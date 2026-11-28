//! `startTlsDkgNode`: the reference MUTUAL-TLS channel for the FROST DKG (feature `mpc-net-driver`, which brings rustls).
//!
//! One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly the other participants'
//! certificates, and the peer's SHA-256 certificate fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the
//! handshake and never from message content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext
//! client, a TLS 1.2 client, a second connection for an already linked identity and a connection from a party that should have been dialled are all
//! refused before any DKG byte is read. Frames are a 4-byte big-endian length then the message ([`crate::frost_dkg_tls`]); the length is checked against
//! [`DKG_MAX_MESSAGE_BYTES`] before any allocation.
//!
//! This is a reference: certificate issuance, rotation and revocation are the deployer's.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use serde_json::{json, Value};

use crate::frost_dkg_channel::{encode_dkg_message, DkgChannel, DkgChannelError, DkgInbox, DKG_MAX_MESSAGE_BYTES};
use crate::frost_dkg_tls::{frame_encode, FrameDecoder};
use crate::mpc_net_driver::certs::{cert_der, fingerprint_der, NodeKey};
use crate::mpc_net_driver::mesh::{client_config, server_config};

type CE<T> = Result<T, DkgChannelError>;

/// What [`start_tls_dkg_node`] needs.
pub struct TlsDkgNodeOpts {
    /// This node's participant id (a positive integer).
    pub self_id: i64,
    pub session_id: Vec<u8>,
    /// This node's PEM private key and certificate.
    pub key_pem: String,
    pub cert_pem: String,
    /// Pinned identities of every OTHER participant (certificate only): `(id, PEM)`.
    pub peer_certs: Vec<(i64, String)>,
    /// Port to listen on (0: ephemeral; read [`TlsDkgNode::port`]). Default host 127.0.0.1.
    pub listen_port: u16,
    pub listen_host: Option<String>,
}

enum Conn {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl Conn {
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Client(s) => s.write_all(b).and_then(|_| s.flush()),
            Conn::Server(s) => s.write_all(b).and_then(|_| s.flush()),
        }
    }
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Client(s) => s.read(b),
            Conn::Server(s) => s.read(b),
        }
    }
    fn shutdown(&mut self) {
        let tcp = match self {
            Conn::Client(s) => &s.sock,
            Conn::Server(s) => &s.sock,
        };
        let _ = tcp.shutdown(std::net::Shutdown::Both);
    }
}

struct Shared {
    self_id: i64,
    session_id: Vec<u8>,
    inbox: DkgInbox,
    peers: Vec<i64>,
    pinned: HashMap<[u8; 32], i64>,
    links: Mutex<HashMap<i64, Arc<Mutex<Conn>>>>,
    linked: Condvar,
    closed: AtomicBool,
}

impl Shared {
    fn attach(self: &Arc<Self>, id: i64, conn: Conn) -> bool {
        let link = Arc::new(Mutex::new(conn));
        {
            let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
            if links.contains_key(&id) {
                return false;
            }
            links.insert(id, link.clone());
            self.linked.notify_all();
        }
        let me = self.clone();
        std::thread::spawn(move || me.read_loop(id, link));
        true
    }

    fn read_loop(&self, id: i64, link: Arc<Mutex<Conn>>) {
        let who = json!(id);
        let mut dec = FrameDecoder::default();
        let mut buf = vec![0u8; 16 * 1024];
        'outer: while !self.closed.load(Ordering::SeqCst) {
            // the socket has a short read timeout, so a writer waits at most that long for the lock
            let got = link.lock().unwrap_or_else(|e| e.into_inner()).read(&mut buf);
            match got {
                Ok(0) => break,
                Ok(n) => {
                    for payload in dec.feed(&buf[..n]) {
                        self.inbox.accept(&who, Some(&payload));
                    }
                    if dec.error.is_some() {
                        self.inbox.fail(&who, &DkgChannelError::new("oversize", Some(who.clone()), &format!("frame exceeds the {DKG_MAX_MESSAGE_BYTES} byte cap")));
                        break 'outer;
                    }
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
        link.lock().unwrap_or_else(|e| e.into_inner()).shutdown();
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        if links.get(&id).is_some_and(|l| Arc::ptr_eq(l, &link)) {
            links.remove(&id);
        }
        drop(links);
        self.inbox.peer_gone(&who);
    }
}

fn peer_id(shared: &Shared, certs: Option<&[rustls::pki_types::CertificateDer<'static>]>) -> Option<i64> {
    certs.and_then(|c| c.first()).and_then(|d| shared.pinned.get(&fingerprint_der(d.as_ref()))).copied()
}

/// A running node: its listening port, and the means to link up with the other participants.
pub struct TlsDkgNode {
    pub port: u16,
    shared: Arc<Shared>,
    client_cfg: Arc<rustls::ClientConfig>,
    peer_ids: Vec<i64>,
}

/// `startTlsDkgNode`: pin the peers, listen, and answer (but do not yet dial) until [`TlsDkgNode::connect`].
pub fn start_tls_dkg_node(opts: TlsDkgNodeOpts) -> Result<TlsDkgNode, String> {
    let key = NodeKey::from_pem(&opts.key_pem)?;
    let cert = cert_der(&opts.cert_pem)?;
    let mut pinned: HashMap<[u8; 32], i64> = HashMap::new();
    for (id, pem) in &opts.peer_certs {
        pinned.insert(fingerprint_der(&cert_der(pem)?), *id);
    }
    if pinned.len() != opts.peer_certs.len() || opts.peer_certs.iter().any(|(id, _)| *id == opts.self_id) {
        return Err("startTlsDkgNode: peer certificates must be distinct and none may be this node".into());
    }
    let mut peers: Vec<i64> = opts.peer_certs.iter().map(|(id, _)| *id).collect();
    peers.sort_unstable();
    let pins: HashSet<[u8; 32]> = pinned.keys().copied().collect();
    let server_cfg = server_config(&key, &cert, pins.clone())?;
    let client_cfg = client_config(&key, &cert, pins)?;
    let peer_values: Vec<Value> = peers.iter().map(|p| json!(p)).collect();
    let shared = Arc::new(Shared {
        self_id: opts.self_id,
        inbox: DkgInbox::new(&opts.session_id, &peer_values),
        session_id: opts.session_id,
        peers: peers.clone(),
        pinned,
        links: Mutex::new(HashMap::new()),
        linked: Condvar::new(),
        closed: AtomicBool::new(false),
    });
    let host = opts.listen_host.unwrap_or_else(|| "127.0.0.1".to_string());
    let listener = TcpListener::bind((host.as_str(), opts.listen_port)).map_err(|e| format!("startTlsDkgNode: {e}"))?;
    let port = listener.local_addr().map_err(|_| "startTlsDkgNode: no listening address".to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let sh = shared.clone();
    std::thread::spawn(move || {
        while !sh.closed.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((tcp, _)) => {
                    let (sh, cfg) = (sh.clone(), server_cfg.clone());
                    // one thread per handshake: a stalled client must not block the others
                    std::thread::spawn(move || accept_one(&sh, cfg, tcp));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    Ok(TlsDkgNode { port, shared, client_cfg, peer_ids: peers })
}

fn prepare(tcp: &TcpStream) -> std::io::Result<()> {
    tcp.set_nonblocking(false)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
}

fn accept_one(sh: &Arc<Shared>, cfg: Arc<rustls::ServerConfig>, mut tcp: TcpStream) {
    if prepare(&tcp).is_err() {
        return;
    }
    let Ok(mut conn) = ServerConnection::new(cfg) else { return };
    while conn.is_handshaking() {
        if conn.complete_io(&mut tcp).is_err() {
            return; // plaintext, TLS 1.2, an unpinned certificate: refused before any DKG byte is read
        }
    }
    let Some(id) = peer_id(sh, conn.peer_certificates()) else { return };
    // only a pinned peer that is supposed to dial us (higher id), once
    if id < sh.self_id || !sh.peers.contains(&id) {
        return;
    }
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(20)));
    sh.attach(id, Conn::Server(StreamOwned::new(conn, tcp)));
}

fn dial(sh: &Arc<Shared>, cfg: &Arc<rustls::ClientConfig>, id: i64, addr: std::net::SocketAddr) -> bool {
    let Ok(mut tcp) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else { return false };
    if prepare(&tcp).is_err() {
        return false;
    }
    let Ok(name) = ServerName::try_from("pca-dkg-node") else { return false };
    let Ok(mut conn) = ClientConnection::new(cfg.clone(), name) else { return false };
    while conn.is_handshaking() {
        if conn.complete_io(&mut tcp).is_err() {
            return false;
        }
    }
    if peer_id(sh, conn.peer_certificates()) != Some(id) {
        return false;
    }
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(20)));
    sh.attach(id, Conn::Client(StreamOwned::new(conn, tcp)))
}

impl TlsDkgNode {
    /// Dial the lower-numbered peers (at `addresses`: `(id, host, port)`), wait for the higher-numbered ones, and return the channel once every link is
    /// authenticated. `Err` with code `identity` for an address of a participant that is not a pinned peer, `timeout` naming the lowest missing peer.
    pub fn connect(&self, addresses: &[(i64, String, u16)], connect_timeout_ms: Option<u64>) -> CE<TlsDkgChannel> {
        let sh = &self.shared;
        let stop = Arc::new(AtomicBool::new(false));
        for (id, host, port) in addresses {
            if !self.peer_ids.contains(id) {
                return Err(DkgChannelError::new("identity", Some(json!(id)), "address for a participant that is not a pinned peer"));
            }
            if *id < sh.self_id {
                let addr = (host.as_str(), *port).to_socket_addrs().ok().and_then(|mut a| a.next());
                let (sh, cfg, stop, id) = (sh.clone(), self.client_cfg.clone(), stop.clone(), *id);
                std::thread::spawn(move || {
                    while let Some(a) = addr {
                        if stop.load(Ordering::SeqCst) || sh.closed.load(Ordering::SeqCst) || dial(&sh, &cfg, id, a) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                });
            }
        }
        let deadline = Instant::now() + Duration::from_millis(connect_timeout_ms.unwrap_or(15_000));
        let mut links = sh.links.lock().unwrap_or_else(|e| e.into_inner());
        while links.len() < sh.peers.len() {
            let now = Instant::now();
            if now >= deadline {
                stop.store(true, Ordering::SeqCst);
                let missing = sh.peers.iter().find(|p| !links.contains_key(p)).copied();
                drop(links);
                self.close();
                let list: Vec<String> = self.peer_ids.iter().map(i64::to_string).collect();
                return Err(DkgChannelError::new("timeout", missing.map(|m| json!(m)), &format!("no authenticated link to {}", list.join(","))));
            }
            links = sh.linked.wait_timeout(links, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
        drop(links);
        stop.store(true, Ordering::SeqCst);
        Ok(TlsDkgChannel { shared: sh.clone() })
    }

    /// Stop listening and dialling, close every link and wake every pending `collect`.
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.inbox.close();
        for link in self.shared.links.lock().unwrap_or_else(|e| e.into_inner()).values() {
            link.lock().unwrap_or_else(|e| e.into_inner()).shutdown();
        }
    }
}

/// The [`DkgChannel`] of a connected node.
pub struct TlsDkgChannel {
    shared: Arc<Shared>,
}

impl TlsDkgChannel {
    fn write(&self, to: i64, kind: &str, body: &Value) -> CE<()> {
        let peer = Some(json!(to));
        let link = self.shared.links.lock().unwrap_or_else(|e| e.into_inner()).get(&to).cloned();
        let link = link.ok_or_else(|| DkgChannelError::new("closed", peer.clone(), "no authenticated link"))?;
        let payload = encode_dkg_message(&self.shared.session_id, &json!(kind), body)?;
        let frame = frame_encode(&payload).map_err(|e| DkgChannelError::new("oversize", peer.clone(), &e))?;
        let r = link.lock().unwrap_or_else(|e| e.into_inner()).write_all(&frame);
        r.map_err(|_| DkgChannelError::new("closed", peer, "write failed"))
    }
}

impl DkgChannel for TlsDkgChannel {
    fn self_id(&self) -> Value {
        json!(self.shared.self_id)
    }
    fn peers(&self) -> Vec<Value> {
        self.shared.peers.iter().map(|p| json!(p)).collect()
    }
    fn broadcast(&self, kind: &str, body: &Value) -> CE<()> {
        self.shared.peers.iter().try_for_each(|p| self.write(*p, kind, body))
    }
    fn send(&self, to: &Value, kind: &str, body: &Value) -> CE<()> {
        match to.as_i64().filter(|t| self.shared.peers.contains(t)) {
            Some(t) => self.write(t, kind, body),
            None => Err(DkgChannelError::new("identity", Some(to.clone()), "not a connected peer")),
        }
    }
    fn collect(&self, kind: &str, from_ids: &[Value], timeout_ms: f64) -> CE<Vec<(Value, Value)>> {
        self.shared.inbox.collect(kind, from_ids, timeout_ms)
    }
    fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.inbox.close();
        for link in self.shared.links.lock().unwrap_or_else(|e| e.into_inner()).values() {
            link.lock().unwrap_or_else(|e| e.into_inner()).shutdown();
        }
    }
}
