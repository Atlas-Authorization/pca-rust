//! Authenticated, confidential, fail-closed point-to-point mesh over mutual TLS 1.3.
//!
//! - MUTUAL TLS with PINNED self-signed certificates ([`super::certs`]): a peer is identified by the SHA-256 of its certificate, never
//!   by anything it claims, and the id in its hello frame must agree with the pin. Both verifiers accept a pinned certificate only
//!   (no chain, no name, no clock).
//! - Strict framing and per-link sequence numbers. A malformed frame, a duplicate or replayed frame, a skipped (out-of-order) frame,
//!   a frame for the wrong round or session, or an oversize length prefix aborts the run with an ATTRIBUTABLE [`NetAbort`] naming
//!   the sender.
//! - A deadline on every receive (no hangs); a silent peer is blamed after the receive timeout.
//! - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an `abort` frame to every
//!   peer (except the one that just told us) and closes the sockets. Once failed nothing further is sent as protocol data.
//! - Dial the lower ids, accept the higher ids; a second connection claiming an already linked identity is refused.
//! - Per-link inbox caps with back-pressure: a reader stops reading at half the cap and the sender is blamed (`flood`) past it.
use super::certs::{cert_der, fingerprint_der, verify as verify_sig, Identity, NodeKey};
use super::clock::{MeshClock, WallClock};
use super::{local, nab};
use crate::mpc_net::{encode_frame, parse_frame, version_mismatch, FrameSplitter, NetAbort, NetAbortOpts, ABORT_KINDS, WIRE_VERSION};
use rustls::client::danger::{HandshakeSignatureValid as ClientSigOk, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Most non-fatal observations kept in [`Mesh::events`]; further ones are only counted.
pub const MAX_MESH_EVENTS: usize = 64;

/// A node of the session: its id, where it listens and its PUBLIC certificate (pinned trust anchor and identity).
#[derive(Debug, Clone)]
pub struct NodeAddr {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub cert_pem: String,
}

/// TEST HOOK input: a (malicious) sender rewriting its own outgoing frames.
#[derive(Debug, Clone)]
pub struct TamperEvent {
    pub to: i64,
    pub frame: Value,
    /// The honest encoding of the frame.
    pub raw: Vec<u8>,
}

/// The bytes actually written for a frame (none = dropped).
pub type Tamper = Arc<dyn Fn(&TamperEvent) -> Vec<Vec<u8>> + Send + Sync>;

#[derive(Clone)]
pub struct MeshConfig {
    /// Time source for deadlines (default: the wall clock).
    pub clock: Option<Arc<dyn MeshClock>>,
    pub self_id: i64,
    /// Every node in the session, self included. Only nodes in `link_to` get a connection.
    pub nodes: Vec<NodeAddr>,
    /// Node ids this node maintains a link to (default: all others).
    pub link_to: Option<Vec<i64>>,
    pub key_pem: String,
    pub cert_pem: String,
    pub session_id: String,
    pub listen_host: Option<String>,
    pub connect_timeout_ms: Option<u64>,
    pub recv_timeout_ms: Option<u64>,
    /// TEST HOOK: refused unless `unsafe_test_hooks` is also true; the node entry point only sets that from an explicit test environment.
    pub tamper: Option<Tamper>,
    pub unsafe_test_hooks: bool,
    /// Most unread frames queued per link before the sender is blamed with `flood` (default 1024).
    pub max_inbox_frames: Option<usize>,
    /// Most unread frame bytes queued per link before the sender is blamed with `flood` (default 32 MiB).
    pub max_inbox_bytes: Option<usize>,
}

impl MeshConfig {
    /// A configuration with every optional member at its default.
    pub fn new(self_id: i64, nodes: Vec<NodeAddr>, identity: &Identity, session_id: &str) -> Self {
        MeshConfig {
            clock: None,
            self_id,
            nodes,
            link_to: None,
            key_pem: identity.key_pem.clone(),
            cert_pem: identity.cert_pem.clone(),
            session_id: session_id.to_string(),
            listen_host: None,
            connect_timeout_ms: None,
            recv_timeout_ms: None,
            tamper: None,
            unsafe_test_hooks: false,
            max_inbox_frames: None,
            max_inbox_bytes: None,
        }
    }
}

/// Per-link traffic counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStats {
    pub peer: i64,
    pub app_bytes_out: u64,
    pub app_bytes_in: u64,
    pub frames_out: u64,
    pub frames_in: u64,
}

// ---- pin-only certificate verifiers -------------------------------------------------------------------------------------------

/// Accepts a certificate if and only if its SHA-256 is one of the pins; handshake signatures are checked against its key (TLS 1.3 only).
struct PinVerifier {
    pins: HashSet<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinVerifier({} pins)", self.pins.len())
    }
}

impl PinVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if self.pins.contains(&fingerprint_der(end_entity.as_ref())) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }
    }

    fn tls13(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<ClientSigOk, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<ClientSigOk, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not accepted".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<ClientSigOk, rustls::Error> {
        self.tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<ClientSigOk, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not accepted".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<ClientSigOk, rustls::Error> {
        self.tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn client_config(key: &NodeKey, cert: &[u8], pins: HashSet<[u8; 32]>) -> Result<Arc<ClientConfig>, String> {
    let p = provider();
    let verifier = Arc::new(PinVerifier { pins, provider: p.clone() });
    let cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![CertificateDer::from(cert.to_vec())], key.der())
        .map_err(|e| format!("tls client identity: {e}"))?;
    Ok(Arc::new(cfg))
}

pub(crate) fn server_config(key: &NodeKey, cert: &[u8], pins: HashSet<[u8; 32]>) -> Result<Arc<ServerConfig>, String> {
    let p = provider();
    let verifier = Arc::new(PinVerifier { pins, provider: p.clone() });
    let cfg = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(cert.to_vec())], key.der())
        .map_err(|e| format!("tls server identity: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Open a raw mutual-TLS connection to `host:port` as `identity`, trusting only `peer_cert_pem`. For tests that play a malicious peer
/// (hand-written frames); the mesh itself never uses it.
pub async fn dial_raw(identity: &Identity, peer_cert_pem: &str, host: &str, port: u16) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let key = NodeKey::from_pem(&identity.key_pem)?;
    let cfg = client_config(&key, &cert_der(&identity.cert_pem)?, HashSet::from([super::certs::fingerprint_of(peer_cert_pem)?]))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let name = ServerName::try_from("pca-mpc-node").map_err(|e| format!("server name: {e}"))?;
    TlsConnector::from(cfg).connect(name, tcp).await.map_err(|e| format!("tls handshake: {e}"))
}

// ---- links -------------------------------------------------------------------------------------------------------------------------

type Writer = Box<dyn AsyncWrite + Unpin + Send>;

struct InboxItem {
    rd: String,
    d: Value,
    size: usize,
    /// A peer's abort claim deferred behind its earlier frames (see [`Mesh::set_defer_aborts`]).
    abort: Option<NetAbort>,
}

#[derive(Default)]
struct LinkState {
    inbox: VecDeque<InboxItem>,
    inbox_bytes: usize,
    paused: bool,
    recv_seq: i64,
    closed: bool,
    hello_seen: bool,
    attached: bool,
    bytes_in: u64,
    frames_in: u64,
}

struct SendState {
    seq: i64,
    writer: Option<Writer>,
    bytes_out: u64,
    frames_out: u64,
}

struct Link {
    id: i64,
    st: Mutex<LinkState>,
    tx: tokio::sync::Mutex<SendState>,
    resume: Notify,
}

#[derive(Default)]
struct Shared {
    failure: Option<NetAbort>,
    finished: bool,
    defer_aborts: bool,
    events: Vec<String>,
    events_dropped: u64,
}

struct Inner {
    self_id: i64,
    nodes: Vec<NodeAddr>,
    session_id: String,
    key: NodeKey,
    pins: HashMap<[u8; 32], i64>,
    peer_certs: HashMap<i64, Vec<u8>>,
    links: BTreeMap<i64, Link>,
    shared: Mutex<Shared>,
    wake: watch::Sender<u64>,
    clock: Arc<dyn MeshClock>,
    recv_timeout_ms: u64,
    connect_timeout_ms: u64,
    max_frames: usize,
    max_bytes: usize,
    tamper: Option<Tamper>,
    listen_host: String,
    max_id: i64,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging); one `?` per UTF-16 unit.
fn sanitize(x: &str, max: usize) -> String {
    x.encode_utf16().take(max).map(|u| if (0x20..=0x7e).contains(&u) { u as u8 as char } else { '?' }).collect()
}

fn first_fingerprint(c: Option<&[CertificateDer<'static>]>) -> Option<[u8; 32]> {
    c.and_then(|l| l.first()).map(|d| fingerprint_der(d.as_ref()))
}

impl Inner {
    fn failed(&self) -> Option<NetAbort> {
        self.shared.lock().expect("mesh lock").failure.clone()
    }

    fn note(&self, msg: String) {
        let mut s = self.shared.lock().expect("mesh lock");
        if s.events.len() < MAX_MESH_EVENTS {
            s.events.push(msg);
        } else {
            s.events_dropped += 1;
        }
    }

    fn wake(&self) {
        self.wake.send_modify(|v| *v += 1);
    }

    fn link(&self, id: i64) -> Result<&Link, NetAbort> {
        self.links.get(&id).ok_or_else(|| local(self.self_id, &format!("mesh: no link to {id}")))
    }

    /// Write one frame. `with_tamper` routes a `msg` frame through the test hook.
    async fn write_frame(&self, l: &Link, ty: &str, rd: &str, d: Value, with_tamper: bool) -> Result<(), NetAbort> {
        let mut tx = l.tx.lock().await;
        let seq = tx.seq;
        tx.seq += 1;
        let frame = json!({"v": WIRE_VERSION, "ty": ty, "sid": self.session_id, "seq": seq, "rd": rd, "d": d});
        let raw = encode_frame(&frame).map_err(|e| local(self.self_id, &format!("mesh: {e}")))?;
        let outs = match (&self.tamper, with_tamper) {
            (Some(t), true) => t(&TamperEvent { to: l.id, frame, raw }),
            _ => vec![raw],
        };
        for b in outs {
            let Some(w) = tx.writer.as_mut() else { break };
            if w.write_all(&b).await.is_err() || w.flush().await.is_err() {
                tx.writer = None;
                break;
            }
            tx.bytes_out += b.len() as u64;
        }
        tx.frames_out += 1;
        Ok(())
    }

    /// Poison the mesh with `err`: tell every peer except `skip` (forwarding a peer's accusation as a claim, never as our own), then close.
    async fn fail(self: &Arc<Self>, err: NetAbort, skip: Option<i64>) {
        {
            let mut s = self.shared.lock().expect("mesh lock");
            if s.failure.is_some() {
                return;
            }
            s.failure = Some(err.clone());
        }
        let relayed = err.kind == "peer-abort";
        let (kind, blamed) =
            if relayed { (err.claimed_kind.clone().unwrap_or_else(|| "peer-abort".to_string()), err.claimed_blame) } else { (err.kind.clone(), err.blamed) };
        let mut d = json!({"kind": kind, "blamed": blamed, "detail": sanitize(&err.message, 200)});
        if relayed {
            d["relayed"] = json!(true);
        }
        for l in self.links.values() {
            if Some(l.id) == skip {
                continue;
            }
            let live = {
                let st = l.st.lock().expect("link lock");
                st.attached && !st.closed
            };
            if live {
                let _ = tokio::time::timeout(Duration::from_millis(1000), self.write_frame(l, "abort", "abort", d.clone(), false)).await;
            }
        }
        self.wake();
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            me.close_all().await;
        });
    }

    async fn close_all(self: &Arc<Self>) {
        for l in self.links.values() {
            if let Ok(mut tx) = tokio::time::timeout(Duration::from_millis(200), l.tx.lock()).await {
                if let Some(w) = tx.writer.as_mut() {
                    let _ = tokio::time::timeout(Duration::from_millis(200), w.shutdown()).await;
                }
            }
        }
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for l in me.links.values() {
                if let Ok(mut tx) = l.tx.try_lock() {
                    tx.writer = None;
                }
            }
            let hs: Vec<JoinHandle<()>> = me.tasks.lock().expect("task lock").drain(..).collect();
            for h in hs {
                h.abort();
            }
        });
    }

    // ---- connect ----------------------------------------------------------------------------------------------------------------

    async fn attach<S>(self: &Arc<Self>, id: i64, stream: S) -> Result<(), NetAbort>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let l = self.link(id)?;
        let (r, w) = tokio::io::split(stream);
        l.tx.lock().await.writer = Some(Box::new(w));
        let me = self.clone();
        let reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(r);
        let h = tokio::spawn(async move { me.read_loop(id, reader).await });
        self.tasks.lock().expect("task lock").push(h);
        // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin
        self.write_frame(l, "hello", "hello", json!({"id": self.self_id}), false).await
    }

    fn claim_link(&self, id: i64) -> bool {
        let Some(l) = self.links.get(&id) else { return false };
        let mut st = l.st.lock().expect("link lock");
        if st.attached {
            return false;
        }
        st.attached = true;
        true
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        let acceptor = TlsAcceptor::from(self.server_cfg.clone());
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    let (me, acc) = (self.clone(), acceptor.clone());
                    tokio::spawn(async move { me.on_incoming(tcp, acc).await });
                }
                Err(e) => {
                    self.note(format!("server error: {}", sanitize(&e.to_string(), 120)));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    async fn on_incoming(self: Arc<Self>, tcp: TcpStream, acceptor: TlsAcceptor) {
        let _ = tcp.set_nodelay(true);
        let tls = match tokio::time::timeout(Duration::from_secs(20), acceptor.accept(tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return self.note(format!("tlsClientError: {}", sanitize(&e.to_string(), 120))),
            Err(_) => return self.note("tlsClientError: handshake timed out".to_string()),
        };
        let fp = first_fingerprint(tls.get_ref().1.peer_certificates());
        let id = fp.and_then(|f| self.pins.get(&f).copied());
        let Some(id) = id.filter(|i| self.links.contains_key(i) && *i >= self.self_id) else {
            return self.note("rejected incoming connection".to_string());
        };
        if !self.claim_link(id) {
            return self.note(format!("duplicate connection from node {id}"));
        }
        if let Err(e) = self.attach(id, tls).await {
            self.fail(e, None).await;
        }
    }

    async fn dial(self: Arc<Self>, id: i64, deadline: u64) {
        let Some(node) = self.nodes.iter().find(|n| n.id == id).cloned() else { return };
        while self.failed().is_none() && self.clock.now() < deadline {
            if self.dial_once(id, &node).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(150)).await; // retry pacing, not a decision: real time
        }
    }

    /// One dial attempt; true when the attempt is over for good (linked, or failed on an identity mismatch).
    async fn dial_once(self: &Arc<Self>, id: i64, node: &NodeAddr) -> bool {
        let tcp = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((node.host.as_str(), node.port))).await {
            Ok(Ok(t)) => t,
            _ => return false,
        };
        let _ = tcp.set_nodelay(true);
        let Ok(name) = ServerName::try_from("pca-mpc-node") else { return false };
        let tls = match tokio::time::timeout(Duration::from_secs(20), TlsConnector::from(self.client_cfg.clone()).connect(name, tcp)).await {
            Ok(Ok(t)) => t,
            _ => return false,
        };
        let fp = first_fingerprint(tls.get_ref().1.peer_certificates());
        if fp.and_then(|f| self.pins.get(&f).copied()) != Some(id) {
            self.fail(nab("identity", Some(id), self.self_id, &format!("dial: peer certificate is not the pinned identity of node {id}")), None).await;
            return true;
        }
        if !self.claim_link(id) {
            return true;
        }
        if let Err(e) = self.attach(id, tls).await {
            self.fail(e, None).await;
        }
        true
    }

    // ---- receive path -----------------------------------------------------------------------------------------------------------

    async fn read_loop(self: Arc<Self>, id: i64, mut r: Box<dyn AsyncRead + Unpin + Send>) {
        let Some(l) = self.links.get(&id) else { return };
        let mut splitter = FrameSplitter::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            // back-pressure: not reading is how a full inbox slows the sender down
            while l.st.lock().expect("link lock").paused {
                l.resume.notified().await;
            }
            let n = match r.read(&mut buf).await {
                Ok(0) => return self.on_closed(l, "peer ended"),
                Ok(n) => n,
                Err(e) => return self.on_closed(l, &format!("socket error: {}", sanitize(&e.to_string(), 80))),
            };
            if let Some((e, skip)) = self.on_data(l, &mut splitter, &buf[..n]) {
                self.fail(e, skip).await;
                return;
            }
            self.wake();
        }
    }

    fn on_closed(&self, l: &Link, why: &str) {
        let (first, hello) = {
            let mut st = l.st.lock().expect("link lock");
            let first = !st.closed;
            st.closed = true;
            (first, st.hello_seen)
        };
        if first {
            let (finished, failed) = {
                let s = self.shared.lock().expect("mesh lock");
                (s.finished, s.failure.is_some())
            };
            if !finished && !failed && !hello {
                self.note(format!("link {} closed before hello: {why}", l.id));
            }
        }
        self.wake();
    }

    /// Process received bytes; `Some((abort, skip))` is a failure to raise.
    fn on_data(&self, l: &Link, sp: &mut FrameSplitter, chunk: &[u8]) -> Option<(NetAbort, Option<i64>)> {
        if self.failed().is_some() {
            return None;
        }
        let me = self.self_id;
        l.st.lock().expect("link lock").bytes_in += chunk.len() as u64;
        let bodies = match sp.push(chunk) {
            Ok(b) => b,
            Err(_) => return Some((nab("oversize", Some(l.id), me, "length prefix above MAX_FRAME_BYTES"), None)),
        };
        for b in bodies {
            let Some(f) = parse_frame(&b) else {
                if let Some(pv) = version_mismatch(&b) {
                    return Some((
                        nab("version", Some(l.id), me, &format!("peer {} speaks wire version {pv}, this node speaks {WIRE_VERSION}; upgrade both peers", l.id)),
                        None,
                    ));
                }
                return Some((nab("malformed", Some(l.id), me, "undecodable or ill-shaped frame"), None));
            };
            if f["sid"].as_str() != Some(self.session_id.as_str()) {
                return Some((nab("wrong-session", Some(l.id), me, "frame from another session"), None));
            }
            let ty = f["ty"].as_str().unwrap_or("");
            let seq = f["seq"].as_f64().unwrap_or(-1.0) as i64;
            let rd = f["rd"].as_str().unwrap_or("").to_string();
            let d = f["d"].clone();
            if ty == "abort" {
                // An abort frame is only a CLAIM by the peer that sent it: blame that peer (the authenticated sender), never the party it names.
                let relayed = d.get("relayed") == Some(&Value::Bool(true));
                let claimed_kind = d.get("kind").and_then(Value::as_str).filter(|k| ABORT_KINDS.contains(k));
                let claimed_blame = d
                    .get("blamed")
                    .and_then(Value::as_f64)
                    .filter(|x| x.fract() == 0.0 && !(*x == 0.0 && x.is_sign_negative()) && *x >= 0.0 && *x <= self.max_id as f64)
                    .map(|x| x as i64);
                let detail = d.get("detail").and_then(Value::as_str).map(|s| sanitize(s, 120)).unwrap_or_default();
                let opts = if relayed {
                    NetAbortOpts {
                        reason: Some("relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence".to_string()),
                        ..Default::default()
                    }
                } else {
                    NetAbortOpts::default()
                };
                let claim = NetAbort::new(
                    "peer-abort",
                    if relayed { None } else { Some(l.id) },
                    me,
                    &format!(
                        "peer {} {} an abort ({}, accuses {}, unverified) {}",
                        l.id,
                        if relayed { "relayed" } else { "reported" },
                        claimed_kind.unwrap_or("unspecified"),
                        claimed_blame.map_or("no one".to_string(), |x| x.to_string()),
                        detail
                    ),
                    claimed_kind,
                    claimed_blame,
                    opts,
                );
                if self.shared.lock().expect("mesh lock").defer_aborts {
                    // Order-preserving: the claim takes effect when it is READ, after every frame this peer sent before it.
                    l.st.lock().expect("link lock").inbox.push_back(InboxItem { rd, d, size: b.len(), abort: Some(claim) });
                    continue;
                }
                return Some((claim, Some(l.id)));
            }
            let mut st = l.st.lock().expect("link lock");
            if seq != st.recv_seq {
                let kind = if seq < st.recv_seq { "duplicate" } else { "out-of-order" };
                return Some((nab(kind, Some(l.id), me, &format!("expected seq {}, got {seq} (round {rd})", st.recv_seq)), None));
            }
            st.recv_seq += 1;
            st.frames_in += 1;
            if ty == "hello" {
                if st.hello_seen || d.get("id").and_then(Value::as_f64) != Some(l.id as f64) {
                    let claimed = d.get("id").map_or("undefined".to_string(), |v| v.to_string());
                    return Some((nab("identity", Some(l.id), me, &format!("hello claims id {claimed} on the link pinned to {}", l.id)), None));
                }
                st.hello_seen = true;
            } else {
                if !st.hello_seen {
                    return Some((nab("malformed", Some(l.id), me, "data before hello"), None));
                }
                st.inbox.push_back(InboxItem { rd, d, size: b.len(), abort: None });
                st.inbox_bytes += b.len();
                if st.inbox.len() > self.max_frames || st.inbox_bytes > self.max_bytes {
                    return Some((nab("flood", Some(l.id), me, &format!("peer {} queued more than the inbox cap allows", l.id)), None));
                }
                if !st.paused && (st.inbox.len() > self.max_frames / 2 || st.inbox_bytes > self.max_bytes / 2) {
                    st.paused = true;
                }
            }
        }
        None
    }

    async fn recv_until(self: &Arc<Self>, from: i64, round: &str, deadline: u64, timeout_ms: u64) -> Result<Value, NetAbort> {
        let l = self.link(from)?;
        let me = self.self_id;
        loop {
            let mut rx = self.wake.subscribe();
            if let Some(f) = self.failed() {
                return Err(f);
            }
            let item = {
                let mut st = l.st.lock().expect("link lock");
                let it = st.inbox.pop_front();
                if let Some(i) = &it {
                    if i.abort.is_none() {
                        st.inbox_bytes = st.inbox_bytes.saturating_sub(i.size);
                        if st.paused && st.inbox.len() <= self.max_frames / 2 && st.inbox_bytes <= self.max_bytes / 2 {
                            st.paused = false;
                            l.resume.notify_one();
                        }
                    }
                }
                it
            };
            if let Some(it) = item {
                if let Some(a) = it.abort {
                    self.fail(a.clone(), Some(from)).await;
                    return Err(a);
                }
                if it.rd != round {
                    let e = nab("wrong-round", Some(from), me, &format!("expected round '{round}', got '{}'", it.rd));
                    self.fail(e.clone(), None).await;
                    return Err(e);
                }
                return Ok(it.d);
            }
            if l.st.lock().expect("link lock").closed {
                let e = nab("disconnect", Some(from), me, &format!("link to {from} closed while awaiting '{round}'"));
                self.fail(e.clone(), None).await;
                return Err(e);
            }
            let now = self.clock.now();
            if now >= deadline {
                let e = NetAbort::new(
                    "timeout",
                    Some(from),
                    me,
                    &format!("no '{round}' message from {from} within {timeout_ms}ms (deadline {timeout_ms}ms; a silent peer is blamed on this local observation only)"),
                    None,
                    None,
                    NetAbortOpts { deadline_ms: Some(timeout_ms as i64), ..Default::default() },
                );
                self.fail(e.clone(), None).await;
                return Err(e);
            }
            tokio::select! {
                _ = rx.changed() => {}
                _ = self.clock.sleep(deadline - now) => {}
            }
        }
    }
}

/// The mesh: cheap to clone (a shared handle).
#[derive(Clone)]
pub struct Mesh {
    inner: Arc<Inner>,
}

impl Mesh {
    pub fn new(cfg: MeshConfig) -> Result<Mesh, String> {
        if cfg.tamper.is_some() && !cfg.unsafe_test_hooks {
            return Err("mesh: the tamper test hook requires unsafe_test_hooks: true (test-only)".to_string());
        }
        let key = NodeKey::from_pem(&cfg.key_pem)?;
        let own = cert_der(&cfg.cert_pem)?;
        let mut pins = HashMap::new();
        let mut peer_certs = HashMap::new();
        for n in cfg.nodes.iter().filter(|n| n.id != cfg.self_id) {
            let der = cert_der(&n.cert_pem)?;
            pins.insert(fingerprint_der(&der), n.id);
            peer_certs.insert(n.id, der);
        }
        let want = cfg.link_to.clone().unwrap_or_else(|| cfg.nodes.iter().map(|n| n.id).filter(|i| *i != cfg.self_id).collect());
        let mut links = BTreeMap::new();
        for id in want {
            if !cfg.nodes.iter().any(|n| n.id == id) {
                return Err(format!("mesh: unknown link target {id}"));
            }
            links.insert(
                id,
                Link {
                    id,
                    st: Mutex::new(LinkState::default()),
                    tx: tokio::sync::Mutex::new(SendState { seq: 0, writer: None, bytes_out: 0, frames_out: 0 }),
                    resume: Notify::new(),
                },
            );
        }
        let pin_set: HashSet<[u8; 32]> = pins.keys().copied().collect();
        let (wake, _) = watch::channel(0u64);
        let inner = Inner {
            self_id: cfg.self_id,
            max_id: cfg.nodes.iter().map(|n| n.id).max().unwrap_or(0),
            nodes: cfg.nodes.clone(),
            session_id: cfg.session_id.clone(),
            server_cfg: server_config(&key, &own, pin_set.clone())?,
            client_cfg: client_config(&key, &own, pin_set)?,
            key,
            pins,
            peer_certs,
            links,
            shared: Mutex::new(Shared::default()),
            wake,
            clock: cfg.clock.clone().unwrap_or_else(|| Arc::new(WallClock)),
            recv_timeout_ms: cfg.recv_timeout_ms.unwrap_or(20_000),
            connect_timeout_ms: cfg.connect_timeout_ms.unwrap_or(30_000),
            max_frames: cfg.max_inbox_frames.unwrap_or(1024),
            max_bytes: cfg.max_inbox_bytes.unwrap_or(32 * 1024 * 1024),
            tamper: cfg.tamper.clone(),
            listen_host: cfg.listen_host.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
            tasks: Mutex::new(vec![]),
        };
        Ok(Mesh { inner: Arc::new(inner) })
    }

    pub fn self_id(&self) -> i64 {
        self.inner.self_id
    }

    /// The session id every frame on this mesh carries (used to bind sub-protocols to this session).
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn peers(&self) -> Vec<i64> {
        self.inner.links.keys().copied().collect()
    }

    pub fn failed(&self) -> Option<NetAbort> {
        self.inner.failed()
    }

    /// Non-fatal observations (a TLS client rejected at the door, ...) and how many further ones were only counted.
    pub fn events(&self) -> (Vec<String>, u64) {
        let s = self.inner.shared.lock().expect("mesh lock");
        (s.events.clone(), s.events_dropped)
    }

    /// Listen, dial every lower-numbered link target, and wait until all links completed the authenticated hello exchange.
    pub async fn connect(&self) -> Result<(), NetAbort> {
        let inner = &self.inner;
        let me = inner.self_id;
        let me_addr = inner.nodes.iter().find(|n| n.id == me).ok_or_else(|| local(me, "mesh: self not in nodes"))?;
        let listener = TcpListener::bind((inner.listen_host.as_str(), me_addr.port))
            .await
            .map_err(|e| local(me, &format!("mesh: listen on port {}: {e}", me_addr.port)))?;
        let accept = tokio::spawn(inner.clone().accept_loop(listener));
        inner.tasks.lock().expect("task lock").push(accept);
        let deadline = inner.clock.now() + inner.connect_timeout_ms;
        for id in self.peers() {
            if id < me {
                let task = tokio::spawn(inner.clone().dial(id, deadline));
                inner.tasks.lock().expect("task lock").push(task);
            }
        }
        // wait for all links to complete the authenticated hello exchange (poll; bounded by the deadline)
        loop {
            if let Some(f) = inner.failed() {
                return Err(f);
            }
            let missing: Vec<i64> = inner.links.values().filter(|l| !l.st.lock().expect("link lock").hello_seen).map(|l| l.id).collect();
            let Some(first) = missing.first() else { return Ok(()) };
            if inner.clock.now() > deadline {
                let list = missing.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
                let e = nab("timeout", Some(*first), me, &format!("connect: no authenticated link from {list}"));
                inner.fail(e.clone(), None).await;
                return Err(e);
            }
            tokio::time::sleep(Duration::from_millis(20)).await; // a poll interval, not a decision: real time
        }
    }

    /// Send a protocol message to one peer. Fails with the mesh failure if already aborted (fail closed).
    pub async fn send(&self, to: i64, round: &str, payload: Value) -> Result<(), NetAbort> {
        if let Some(f) = self.inner.failed() {
            return Err(f);
        }
        let l = self.inner.link(to)?;
        self.inner.write_frame(l, "msg", round, payload, true).await
    }

    pub async fn broadcast(&self, round: &str, payload: &Value, to: &[i64]) -> Result<(), NetAbort> {
        for p in to {
            self.send(*p, round, payload.clone()).await?;
        }
        Ok(())
    }

    /// ECDSA-P256 / SHA-256 signature over `data` with this node's TLS identity key (verifiable against the pinned certificate).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, NetAbort> {
        self.inner.key.sign(data).map_err(|e| local(self.inner.self_id, &e))
    }

    /// Verify `sig` over `data` against the PINNED certificate of node `peer`. False on any failure.
    pub fn verify(&self, peer: i64, data: &[u8], sig: &[u8]) -> bool {
        peer != self.inner.self_id && self.inner.peer_certs.get(&peer).is_some_and(|c| verify_sig(c, data, sig))
    }

    /// Receive the next message from `from`, which must belong to `round`. Times out (default: the configured receive timeout); never hangs.
    pub async fn recv(&self, from: i64, round: &str, timeout_ms: Option<u64>) -> Result<Value, NetAbort> {
        let t = timeout_ms.unwrap_or(self.inner.recv_timeout_ms);
        let deadline = self.inner.clock.now() + t;
        self.inner.recv_until(from, round, deadline, t).await
    }

    /// While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and takes
    /// effect only when a receive from that peer reaches it. Used for the blame round, where an honest party sends its blame data
    /// before any abort, so a cheater's own fast abort cannot pre-empt an honest party still collecting the data it needs.
    pub fn set_defer_aborts(&self, on: bool) {
        self.inner.shared.lock().expect("mesh lock").defer_aborts = on;
    }

    /// Receive `round` from every peer in `from`, all against one shared deadline. A failure on any link fails the whole call.
    pub async fn collect(&self, round: &str, from: &[i64], timeout_ms: Option<u64>) -> Result<BTreeMap<i64, Value>, NetAbort> {
        let t = timeout_ms.unwrap_or(self.inner.recv_timeout_ms);
        let deadline = self.inner.clock.now() + t;
        let mut out = BTreeMap::new();
        for p in from {
            out.insert(*p, self.inner.recv_until(*p, round, deadline, t).await?);
        }
        Ok(out)
    }

    /// Poison the mesh with `err` (see the module docs); `skip` is the peer that just told us.
    pub async fn fail(&self, err: NetAbort, skip: Option<i64>) {
        self.inner.fail(err, skip).await;
    }

    /// Fail the mesh with `err` and hand it back, for `return Err(mesh.abort(e).await)`.
    pub async fn abort(&self, err: NetAbort) -> NetAbort {
        self.inner.fail(err.clone(), None).await;
        err
    }

    /// Normal completion: flush and close. Peers still reading see EOF only after our data.
    pub async fn finish(&self) {
        self.inner.shared.lock().expect("mesh lock").finished = true;
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.inner.close_all().await;
    }

    pub fn stats(&self) -> Vec<LinkStats> {
        let mut out = vec![];
        for l in self.inner.links.values() {
            let (bin, fin) = {
                let st = l.st.lock().expect("link lock");
                (st.bytes_in, st.frames_in)
            };
            let (bout, fout) = match l.tx.try_lock() {
                Ok(tx) => (tx.bytes_out, tx.frames_out),
                Err(_) => (0, 0),
            };
            out.push(LinkStats { peer: l.id, app_bytes_out: bout, app_bytes_in: bin, frames_out: fout, frames_in: fin });
        }
        out
    }
}
