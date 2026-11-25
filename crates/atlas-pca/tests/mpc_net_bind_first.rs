//! Bind first: a node binds its own port (0 = the OS picks), reports the port it really holds, and takes every peer's real port from one
//! line before anyone dials. No port is probed and released.
#![cfg(feature = "mpc-net-driver")]
use atlas_pca::mpc_net_driver::party_main::{bind_first, NodeConfig, NodeSpec};
use serde_json::Value;

fn cfg() -> NodeConfig {
    let spec = |id: i64| NodeSpec { id, host: "127.0.0.1".to_string(), port: 0, cert_path: String::new() };
    let mut c = NodeConfig::new("party", 1, 2, "s", "k", "c", vec![spec(0), spec(1)]);
    c.listen_host = Some("127.0.0.1".to_string());
    c.bind_first = true;
    c
}

#[test]
fn the_reported_port_is_the_held_port_and_the_map_is_applied() {
    let mut c = cfg();
    let mut out: Vec<u8> = vec![];
    let mut input = std::io::Cursor::new(b"{\"ports\":{\"0\":4321,\"1\":1}}\n".to_vec());
    bind_first(&mut c, &mut input, &mut out).expect("bind first");
    let reported: Value = serde_json::from_slice(&out).expect("one json line");
    let port = reported["listening"].as_u64().expect("listening") as u16;
    assert_ne!(port, 0);
    assert_eq!(reported["id"], 1);
    assert_eq!(c.nodes[1].port, port, "the node's own address is the bound port");
    assert_eq!(c.nodes[0].port, 4321, "a peer's address is the port it reported");
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err(), "the node still holds its port");
    assert_eq!(c.listener.as_ref().expect("held listener").local_addr().expect("addr").port(), port);
}

#[test]
fn a_closed_stdin_or_a_missing_peer_port_fails_closed() {
    let mut out: Vec<u8> = vec![];
    assert!(bind_first(&mut cfg(), &mut std::io::Cursor::new(Vec::<u8>::new()), &mut out).is_err());
    assert!(bind_first(&mut cfg(), &mut std::io::Cursor::new(b"{\"ports\":{}}\n".to_vec()), &mut out).is_err());
}
