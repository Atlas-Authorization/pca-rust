//! The TLS mesh, the pinned identities, the virtual clock, the fault injectors and the base-OT demo of the networked MPC driver.
//! Identities are generated per run in memory (nothing is committed); every node runs on loopback in this process.
#![cfg(feature = "mpc-net-driver")]
use atlas_pca::mpc_net::{encode_frame, parse_frame, NetAbort, WIRE_VERSION};
use atlas_pca::mpc_net_driver::certs::{cert_der, fingerprint_of, generate_identity, verify, Identity, NodeKey};
use atlas_pca::mpc_net_driver::clock::ManualClock;
use atlas_pca::mpc_net_driver::faults::{tamper_for, Dir, FaultProxy, FrameFault, FrameFaultKind, WireFault, WireFaultKind};
use atlas_pca::mpc_net_driver::mesh::{dial_raw, Mesh, MeshConfig, NodeAddr, TamperEvent};
use atlas_pca::mpc_net_driver::ot_net::{run_ot_receiver, run_ot_sender};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SID: &str = "test-session-0001";

struct Net {
    ids: Vec<Identity>,
    nodes: Vec<NodeAddr>,
    /// Every node's listener, bound to port 0 by the node's own side and held for the whole test (the port in `nodes` is the one it holds).
    listeners: Vec<Arc<std::net::TcpListener>>,
}

fn net(n: usize) -> Net {
    let listeners: Vec<Arc<std::net::TcpListener>> = (0..n).map(|_| Arc::new(std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind"))).collect();
    let ports: Vec<u16> = listeners.iter().map(|l| l.local_addr().expect("addr").port()).collect();
    let ids: Vec<Identity> = (0..n).map(|i| generate_identity(&format!("mpc-node-{i}")).expect("identity")).collect();
    let nodes = (0..n).map(|i| NodeAddr { id: i as i64, host: "127.0.0.1".to_string(), port: ports[i], cert_pem: ids[i].cert_pem.clone() }).collect();
    Net { ids, nodes, listeners }
}

#[test]
fn every_advertised_port_is_a_held_port() {
    let n = net(3);
    for (node, l) in n.nodes.iter().zip(&n.listeners) {
        assert_eq!(l.local_addr().unwrap().port(), node.port);
        assert!(std::net::TcpListener::bind(("127.0.0.1", node.port)).is_err(), "the port is still held");
    }
    let mut p: Vec<u16> = n.nodes.iter().map(|x| x.port).collect();
    p.sort();
    p.dedup();
    assert_eq!(p.len(), 3);
}

fn cfg(net: &Net, id: i64) -> MeshConfig {
    let mut c = MeshConfig::new(id, net.nodes.clone(), &net.ids[id as usize], SID);
    c.listen_host = Some("127.0.0.1".to_string());
    c.listener = Some(net.listeners[id as usize].clone());
    c.recv_timeout_ms = Some(5_000);
    c.connect_timeout_ms = Some(15_000);
    c
}

fn mesh(net: &Net, id: i64) -> Mesh {
    Mesh::new(cfg(net, id)).expect("mesh")
}

fn frame(sid: &str, ty: &str, seq: i64, rd: &str, d: Value) -> Vec<u8> {
    encode_frame(&json!({"v": WIRE_VERSION, "ty": ty, "sid": sid, "seq": seq, "rd": rd, "d": d})).expect("frame")
}

/// A mutual-TLS client with node `from`'s identity, retrying until node `to` listens.
async fn raw_to(net: &Net, from: usize, to: usize) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    for _ in 0..100 {
        if let Ok(s) = dial_raw(&net.ids[from], &net.ids[to].cert_pem, "127.0.0.1", net.nodes[to].port).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not reach node {to}");
}

async fn pause(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ---- identities ---------------------------------------------------------------------------------------------------------------

#[test]
fn an_identity_signs_and_the_pinned_certificate_verifies() {
    let (a, b) = (generate_identity("a").unwrap(), generate_identity("b").unwrap());
    let ka = NodeKey::from_pem(&a.key_pem).unwrap();
    let sig = ka.sign(b"statement").unwrap();
    let ca = cert_der(&a.cert_pem).unwrap();
    assert!(verify(&ca, b"statement", &sig));
    assert!(!verify(&ca, b"another statement", &sig));
    assert!(!verify(&cert_der(&b.cert_pem).unwrap(), b"statement", &sig), "another node's pin must not verify it");
    assert!(!verify(&ca, b"statement", &sig[..sig.len() - 1]));
    assert_ne!(fingerprint_of(&a.cert_pem).unwrap(), fingerprint_of(&b.cert_pem).unwrap());
}

#[test]
fn the_tamper_hook_needs_the_explicit_test_opt_in() {
    let n = net(2);
    let mut c = cfg(&n, 0);
    c.tamper = Some(tamper_for(FrameFault::new(FrameFaultKind::Drop, "x")));
    assert!(Mesh::new(c.clone()).is_err());
    c.unsafe_test_hooks = true;
    assert!(Mesh::new(c).is_ok());
}

// ---- the mesh ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn three_nodes_connect_exchange_and_finish() {
    let n = net(3);
    let run = |id: i64| {
        let m = mesh(&n, id);
        async move {
            m.connect().await.expect("connect");
            let peers = m.peers();
            m.broadcast("r1", &json!({"from": id}), &peers).await.expect("broadcast");
            let got = m.collect("r1", &peers, None).await.expect("collect");
            m.finish().await;
            (id, got, m.sign(b"x").is_ok())
        }
    };
    let (a, b, c) = tokio::join!(run(0), run(1), run(2));
    for (id, got, signed) in [a, b, c] {
        assert!(signed);
        assert_eq!(got.len(), 2);
        for (peer, v) in got {
            assert_eq!(v, json!({"from": peer}), "node {id} must read exactly what {peer} sent");
        }
    }
}

#[tokio::test]
async fn a_wrong_round_aborts_the_receiver_and_the_abort_reaches_the_peer() {
    let n = net(2);
    let (m0, m1) = (mesh(&n, 0), mesh(&n, 1));
    let (r0, r1) = tokio::join!(
        async {
            m0.connect().await?;
            m0.send(1, "a", json!(1)).await?;
            m0.recv(1, "never", Some(5_000)).await
        },
        async {
            m1.connect().await?;
            m1.recv(0, "b", None).await
        }
    );
    let e1: NetAbort = r1.unwrap_err();
    assert_eq!((e1.kind.as_str(), e1.blamed), ("wrong-round", Some(0)));
    let e0 = r0.unwrap_err();
    assert_eq!((e0.kind.as_str(), e0.blamed), ("peer-abort", Some(1)), "an abort frame is a claim: the sender of it is blamed");
    assert_eq!(e0.claimed_kind.as_deref(), Some("wrong-round"));
    assert_eq!(e0.claimed_blame, Some(0));
}

#[tokio::test]
async fn a_peer_with_the_wrong_certificate_never_links() {
    let n = net(2);
    let stranger = generate_identity("stranger").unwrap();
    // node 1 believes node 0 has another certificate: the real node 0 is not in its pins
    let mut c1 = cfg(&n, 1);
    c1.nodes[0].cert_pem = stranger.cert_pem.clone();
    c1.connect_timeout_ms = Some(1_500);
    let mut c0 = cfg(&n, 0);
    c0.connect_timeout_ms = Some(1_500);
    let (m0, m1) = (Mesh::new(c0).unwrap(), Mesh::new(c1).unwrap());
    let (r0, r1) = tokio::join!(m0.connect(), m1.connect());
    let e1 = r1.unwrap_err();
    assert_eq!((e1.kind.as_str(), e1.blamed), ("timeout", Some(0)));
    assert!(r0.is_err());
}

#[tokio::test]
async fn a_client_whose_certificate_is_not_pinned_is_refused_at_the_door() {
    let n = net(2);
    let stranger = generate_identity("stranger").unwrap();
    let mut c0 = cfg(&n, 0);
    c0.connect_timeout_ms = Some(2_000);
    let m0 = Mesh::new(c0).unwrap();
    let (r0, seen) = tokio::join!(m0.connect(), async {
        for _ in 0..100 {
            if let Ok(mut s) = dial_raw(&stranger, &n.ids[0].cert_pem, "127.0.0.1", n.nodes[0].port).await {
                let _ = s.write_all(&frame(SID, "hello", 0, "hello", json!({"id": 1}))).await;
                break;
            }
            pause(50).await;
        }
        pause(500).await;
        m0.events().0
    });
    assert!(r0.is_err(), "no authenticated link can exist");
    assert!(seen.iter().any(|e| e.starts_with("tlsClientError") || e.starts_with("rejected")), "the door must note the refusal: {seen:?}");
    assert!(m0.failed().map_or(true, |f| f.kind == "timeout"));
}

/// Node 0 connected to a hand-written node 1; then `then` runs against node 0.
async fn against_raw<F, Fut>(defer: bool, frames: Vec<Vec<u8>>, then: F) -> (Result<Value, NetAbort>, Vec<String>)
where
    F: FnOnce(Mesh) -> Fut,
    Fut: std::future::Future<Output = Result<Value, NetAbort>>,
{
    let n = net(2);
    let mut c0 = cfg(&n, 0);
    c0.connect_timeout_ms = Some(2_500);
    let m0 = Mesh::new(c0).unwrap();
    m0.set_defer_aborts(defer);
    let probe = m0.clone();
    let (r, _) = tokio::join!(
        async {
            m0.connect().await?;
            then(m0.clone()).await
        },
        async {
            let mut s = raw_to(&n, 1, 0).await;
            for f in frames {
                let _ = s.write_all(&f).await;
            }
            pause(1_500).await;
        }
    );
    (r, probe.events().0)
}

#[tokio::test]
async fn a_hello_naming_another_id_is_an_identity_abort() {
    let (r, _) = against_raw(false, vec![frame(SID, "hello", 0, "hello", json!({"id": 0}))], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("identity", Some(1)));
}

#[tokio::test]
async fn an_oversize_length_prefix_is_refused_before_the_body_arrives() {
    let (r, _) = against_raw(false, vec![0x7fff_ffffu32.to_be_bytes().to_vec()], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("oversize", Some(1)));
}

#[tokio::test]
async fn a_peer_that_closes_before_its_hello_never_links() {
    let (r, events) = against_raw(false, vec![], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("timeout", Some(1)));
    assert!(events.iter().any(|x| x.contains("closed before hello")), "{events:?}");
}

#[tokio::test]
async fn a_replayed_frame_is_a_duplicate_and_a_skipped_one_is_out_of_order() {
    let hello = frame(SID, "hello", 0, "hello", json!({"id": 1}));
    let (r, _) = against_raw(false, vec![hello.clone(), frame(SID, "msg", 1, "x", json!(1)), frame(SID, "msg", 1, "x", json!(1))], |m| async move {
        m.recv(1, "x", Some(2_000)).await?;
        m.recv(1, "x", Some(2_000)).await
    })
    .await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("duplicate", Some(1)));
    let (r, _) = against_raw(false, vec![hello, frame(SID, "msg", 2, "x", json!(1))], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("out-of-order", Some(1)));
}

#[tokio::test]
async fn a_foreign_session_and_data_before_hello_are_refused_and_silence_times_out() {
    let (r, _) =
        against_raw(false, vec![frame("another-session", "hello", 0, "hello", json!({"id": 1}))], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    assert_eq!(r.unwrap_err().kind, "wrong-session");
    let (r, _) = against_raw(false, vec![frame(SID, "msg", 0, "x", json!(1))], |m| async move { m.recv(1, "x", Some(2_000)).await }).await;
    assert_eq!(r.unwrap_err().kind, "malformed");
    let hello = frame(SID, "hello", 0, "hello", json!({"id": 1}));
    let (r, _) = against_raw(false, vec![hello], |m| async move { m.recv(1, "x", Some(300)).await }).await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed, e.deadline_ms), ("timeout", Some(1), Some(300)));
}

#[tokio::test]
async fn a_relayed_abort_names_no_one_and_a_deferred_abort_waits_behind_earlier_frames() {
    let hello = frame(SID, "hello", 0, "hello", json!({"id": 1}));
    let (r, _) = against_raw(
        false,
        vec![hello.clone(), frame(SID, "abort", 1, "abort", json!({"kind": "timeout", "blamed": 1, "detail": "x", "relayed": true}))],
        |m| async move { m.recv(1, "x", Some(2_000)).await },
    )
    .await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed), ("peer-abort", None));
    assert!(e.reason.is_some());
    // with the abort deferred, the data frame sent before it is still delivered first
    let (r, _) = against_raw(
        true,
        vec![hello, frame(SID, "msg", 1, "x", json!("first")), frame(SID, "abort", 2, "abort", json!({"kind": "timeout", "blamed": 0}))],
        |m| async move {
            let first = m.recv(1, "x", Some(2_000)).await?;
            assert_eq!(first, json!("first"));
            m.recv(1, "y", Some(2_000)).await
        },
    )
    .await;
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed, e.claimed_blame), ("peer-abort", Some(1), Some(0)));
}

// ---- the injectable clock ------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_virtual_clock_fires_timers_in_due_order_only_when_advanced() {
    use atlas_pca::mpc_net_driver::clock::MeshClock;
    let clock = ManualClock::new();
    let (a, b) = (clock.sleep(30), clock.sleep(10));
    assert_eq!(clock.pending(), 2);
    tokio::pin!(a, b);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut b).await.is_err(), "nothing fires before time moves");
    clock.advance(10);
    assert!(tokio::time::timeout(Duration::from_millis(500), &mut b).await.is_ok());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut a).await.is_err());
    clock.advance(25);
    assert!(tokio::time::timeout(Duration::from_millis(500), &mut a).await.is_ok());
    assert_eq!(clock.now(), 35);
    assert_eq!(clock.pending(), 0);
}

#[tokio::test]
async fn a_receive_times_out_exactly_when_the_virtual_clock_reaches_its_deadline() {
    let n = net(2);
    let clock = Arc::new(ManualClock::new());
    let mut c0 = cfg(&n, 0);
    c0.clock = Some(clock.clone());
    let (m0, m1) = (Mesh::new(c0).unwrap(), mesh(&n, 1));
    let (r, _) = tokio::join!(
        async {
            m0.connect().await.expect("connect");
            let recv = m0.recv(1, "never", Some(5_000));
            tokio::pin!(recv);
            assert!(tokio::time::timeout(Duration::from_millis(200), &mut recv).await.is_err());
            clock.advance(4_999);
            assert!(tokio::time::timeout(Duration::from_millis(200), &mut recv).await.is_err(), "one millisecond early");
            clock.advance(1);
            recv.await
        },
        async {
            m1.connect().await.expect("connect");
            pause(3_000).await;
        }
    );
    let e = r.unwrap_err();
    assert_eq!((e.kind.as_str(), e.blamed, e.deadline_ms), ("timeout", Some(1), Some(5_000)));
}

// ---- fault injectors ----------------------------------------------------------------------------------------------------------------

fn event(rd: &str, to: i64, seq: i64) -> TamperEvent {
    let f = json!({"v": WIRE_VERSION, "ty": "msg", "sid": SID, "seq": seq, "rd": rd, "d": [1, 2, 3]});
    TamperEvent { to, raw: encode_frame(&f).unwrap(), frame: f }
}

#[test]
fn the_frame_faults_rewrite_only_the_attacked_round() {
    let ev = event("mul0", 1, 4);
    let apply = |kind: FrameFaultKind| tamper_for(FrameFault::new(kind, "mul0"))(&ev);
    assert_eq!(apply(FrameFaultKind::Duplicate), vec![ev.raw.clone(), ev.raw.clone()]);
    assert!(apply(FrameFaultKind::Drop).is_empty());
    assert_eq!(apply(FrameFaultKind::Oversize), vec![vec![0x7f, 0xff, 0xff, 0xff]]);
    let skipped = apply(FrameFaultKind::SkipSeq).remove(0);
    assert_eq!(parse_frame(&skipped[4..]).unwrap()["seq"], json!(5));
    let wrong = apply(FrameFaultKind::WrongRound).remove(0);
    assert_eq!(parse_frame(&wrong[4..]).unwrap()["rd"], json!("zzz-mul0"));
    let session = apply(FrameFaultKind::WrongSession).remove(0);
    assert_eq!(parse_frame(&session[4..]).unwrap()["sid"], json!("not-this-session"));
    let garbage = apply(FrameFaultKind::Garbage).remove(0);
    assert_eq!((garbage.len(), u32::from_be_bytes(garbage[0..4].try_into().unwrap()) as usize), (ev.raw.len(), ev.raw.len() - 4));
    assert!(parse_frame(&garbage[4..]).is_none());
    assert_eq!(apply(FrameFaultKind::Truncate).remove(0).len(), ev.raw.len() / 2);
    let flipped = apply(FrameFaultKind::Bitflip).remove(0);
    assert_eq!(flipped.iter().zip(&ev.raw).filter(|(a, b)| a != b).count(), 1);
    let accuse = tamper_for(FrameFault { accuse: Some(2), ..FrameFault::new(FrameFaultKind::FalseAccuse, "mul0") })(&ev).remove(0);
    let f = parse_frame(&accuse[4..]).unwrap();
    assert_eq!((f["ty"].clone(), f["d"]["blamed"].clone()), (json!("abort"), json!(2)));
    assert!(parse_frame(&apply(FrameFaultKind::ExtraField).remove(0)[4..]).is_none(), "an extra member is an ill-shaped frame");
    // another round, another recipient: untouched
    let other = event("mul1", 1, 4);
    assert_eq!(tamper_for(FrameFault::new(FrameFaultKind::Drop, "mul0"))(&other), vec![other.raw.clone()]);
    let mut to2 = FrameFault::new(FrameFaultKind::Drop, "mul0");
    to2.to = Some(2);
    assert_eq!(tamper_for(to2)(&ev), vec![ev.raw.clone()]);
}

#[test]
fn reorder_holds_one_frame_back_and_silent_from_goes_quiet() {
    let t = tamper_for(FrameFault::new(FrameFaultKind::Reorder, "a"));
    let (first, second) = (event("a", 1, 1), event("b", 1, 2));
    assert!(t(&first).is_empty());
    assert_eq!(t(&second), vec![second.raw.clone(), first.raw.clone()]);
    assert_eq!(t(&event("c", 1, 3)), vec![event("c", 1, 3).raw]);
    let s = tamper_for(FrameFault::new(FrameFaultKind::SilentFrom, "a"));
    assert_eq!(s(&event("z", 1, 0)), vec![event("z", 1, 0).raw]);
    assert!(s(&event("a", 1, 1)).is_empty());
    assert!(s(&event("z", 1, 2)).is_empty(), "silent for good after the first hit");
}

/// An echo server, a proxy in front of it with `fault`, and a client connected through the proxy.
async fn through_proxy(fault: WireFault) -> (tokio::net::TcpStream, Arc<std::sync::Mutex<Vec<String>>>, tokio::sync::oneshot::Sender<()>) {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(k) = s.read(&mut buf).await {
                    if k == 0 || s.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = l.local_addr().unwrap().port();
    let proxy = FaultProxy::new(l, "127.0.0.1", echo_port, fault);
    let log = proxy.log.clone();
    let (stop, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(proxy.serve(rx));
    (tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap(), log, stop)
}

#[tokio::test]
async fn the_proxy_relays_both_ways_without_a_fault() {
    let (mut c, log, _stop) = through_proxy(WireFault { kind: WireFaultKind::None, dir: Dir::C2s, after_bytes: 0, ms: None }).await;
    c.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"hello");
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_drop_fault_passes_the_first_bytes_then_black_holes_and_logs_once() {
    let (mut c, log, _stop) = through_proxy(WireFault { kind: WireFaultKind::Drop, dir: Dir::C2s, after_bytes: 3, ms: None }).await;
    c.write_all(b"ab").await.unwrap();
    let mut two = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut two)).await.unwrap().unwrap();
    assert_eq!(&two, b"ab");
    c.write_all(b"cdef").await.unwrap();
    let mut more = [0u8; 1];
    assert!(tokio::time::timeout(Duration::from_millis(500), c.read_exact(&mut more)).await.is_err(), "the black hole delivers nothing more");
    assert_eq!(log.lock().unwrap().len(), 1);
    assert!(log.lock().unwrap()[0].contains("fault drop"));
}

#[tokio::test]
async fn a_bitflip_fault_flips_one_bit_of_the_middle_byte_once() {
    let (mut c, _log, _stop) = through_proxy(WireFault { kind: WireFaultKind::Bitflip, dir: Dir::C2s, after_bytes: 0, ms: None }).await;
    c.write_all(&[0u8; 8]).await.unwrap();
    let mut buf = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(buf, [0, 0, 0, 0, 1, 0, 0, 0]);
}

// ---- the base-OT demonstration ------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_base_ot_over_the_mesh_hands_the_receiver_the_pad_at_its_choice() {
    let n = net(2);
    let (m0, m1) = (mesh(&n, 0), mesh(&n, 1));
    let (s, r) = tokio::join!(
        async {
            m0.connect().await?;
            run_ot_sender(&m0, 1, "ec", 16).await
        },
        async {
            m1.connect().await?;
            run_ot_receiver(&m1, 0, "ec", 16).await
        }
    );
    let (s, r) = (s.unwrap(), r.unwrap());
    assert!(s.matched && r.matched, "the sender must find every received pad equal to its pad at the choice");
    assert_eq!((s.role, r.role, s.count), ("sender", "receiver", 16));
    assert_ne!(s.pad_digest, r.pad_digest, "the sender holds both pads, the receiver one per index");
}

#[cfg(feature = "mpc-endemic")]
#[tokio::test]
async fn the_endemic_lwe_base_ot_over_the_mesh_hands_the_receiver_the_pad_at_its_choice() {
    let n = net(2);
    let (m0, m1) = (mesh(&n, 0), mesh(&n, 1));
    let (s, r) = tokio::join!(
        async {
            m0.connect().await?;
            run_ot_sender(&m0, 1, "lwe", 8).await
        },
        async {
            m1.connect().await?;
            run_ot_receiver(&m1, 0, "lwe", 8).await
        }
    );
    let (s, r) = (s.unwrap(), r.unwrap());
    assert!(s.matched && r.matched);
    assert_eq!((s.kind.as_str(), s.count), ("lwe", 8));
}

#[cfg(not(feature = "mpc-endemic"))]
#[tokio::test]
async fn the_lwe_kind_is_refused_without_the_endemic_feature() {
    let n = net(2);
    let m0 = mesh(&n, 0);
    let e = run_ot_sender(&m0, 1, "lwe", 8).await.unwrap_err();
    assert_eq!(e.kind, "local");
}
