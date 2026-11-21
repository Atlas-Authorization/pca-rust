#![cfg(feature = "mpc-net-driver")]
//! The mutual-TLS channel of the FROST DKG: three nodes pinned to each other's certificates run a whole ceremony and agree on the group key; a
//! stranger's certificate is refused before any DKG byte is read.
use atlas_pca::frost_dkg_channel::{run_dkg_over_channel, DkgChannel};
use atlas_pca::frost_dkg_tls_node::{start_tls_dkg_node, TlsDkgNodeOpts};
use atlas_pca::frost_net::os_random;
use atlas_pca::mpc_net_driver::certs::generate_identity;
use atlas_pca::serde_json::json;

fn opts(i: i64, ids: &[(i64, atlas_pca::mpc_net_driver::certs::Identity)], sid: &[u8]) -> TlsDkgNodeOpts {
    let me = &ids.iter().find(|(id, _)| *id == i).unwrap().1;
    TlsDkgNodeOpts {
        self_id: i,
        session_id: sid.to_vec(),
        key_pem: me.key_pem.clone(),
        cert_pem: me.cert_pem.clone(),
        peer_certs: ids.iter().filter(|(id, _)| *id != i).map(|(id, x)| (*id, x.cert_pem.clone())).collect(),
        listen_port: 0,
        listen_host: None,
    }
}

#[test]
fn three_pinned_nodes_run_a_dkg() {
    let ids: Vec<(i64, _)> = (1..=3).map(|i| (i, generate_identity(&format!("dkg-node-{i}")).unwrap())).collect();
    let sid = b"tls-dkg-session-0123456789abcdef".to_vec();
    let nodes: Vec<_> = (1..=3).map(|i| start_tls_dkg_node(opts(i, &ids, &sid)).unwrap()).collect();
    let addrs: Vec<(i64, String, u16)> = nodes.iter().enumerate().map(|(k, n)| (k as i64 + 1, "127.0.0.1".to_string(), n.port)).collect();
    let results: Vec<_> = std::thread::scope(|s| {
        let hs: Vec<_> = nodes
            .iter()
            .map(|n| {
                let addrs = addrs.clone();
                let sid = sid.clone();
                s.spawn(move || {
                    let ch = n.connect(&addrs, Some(20_000)).unwrap();
                    let participants = [json!(1), json!(2), json!(3)];
                    let r = run_dkg_over_channel(&ch, &json!(2), &participants, &sid, Some(20_000.0), None, &os_random());
                    ch.close();
                    r
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let keys: Vec<_> = results.iter().map(|r| r.as_ref().expect("dkg").get("keyPackage").and_then(|k| k.get("groupPublicKey")).cloned().expect("key")).collect();
    assert!(keys.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn a_node_refuses_a_non_peer_and_a_misaddressed_connect() {
    let ids: Vec<(i64, _)> = (1..=2).map(|i| (i, generate_identity(&format!("dkg-node-{i}")).unwrap())).collect();
    let n = start_tls_dkg_node(opts(1, &ids, b"sid")).unwrap();
    let e = n.connect(&[(9, "127.0.0.1".into(), 1)], Some(100)).err().unwrap();
    assert_eq!(e.code, "identity");
    let e = n.connect(&[], Some(200)).err().unwrap();
    assert_eq!(e.code, "timeout");
    assert!(start_tls_dkg_node(TlsDkgNodeOpts { peer_certs: vec![(1, ids[0].1.cert_pem.clone())], ..opts(1, &ids, b"sid") }).is_err());
}
