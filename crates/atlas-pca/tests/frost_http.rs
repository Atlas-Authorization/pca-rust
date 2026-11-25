//! The HTTP transport of networked FROST over loopback: the pure request handler, a real server and the coordinator-side transport.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use atlas_pca::attest::allowlist::JsNum;
use atlas_pca::frost::frost_trusted_dealer_keygen;
use atlas_pca::frost_http::{http_signer_transport, respond, start_signer_http_server};
use atlas_pca::frost_net::{os_random, GuardianSignerService, SignerConfig, SignerTransport};
use atlas_pca::serde_json::{json, Value};

fn service() -> Arc<GuardianSignerService> {
    let k = frost_trusted_dealer_keygen(2, 3, None, &[], None).unwrap();
    let p = &k.participant_shares[0];
    Arc::new(
        GuardianSignerService::new(SignerConfig {
            identifier: &json!(p.identifier),
            share: Some(&p.share),
            group_public_key: Some(&k.group_public_key),
            threshold: &json!(2),
            policy_authority_public_key: Some(&[7u8; 32]),
            session_ttl_ms: JsNum::Undefined,
            now: Arc::new(|| 1_000_000.0),
            nonce_store: None,
            random: os_random(),
            canonical: None,
        })
        .unwrap(),
    )
}

#[test]
fn the_handler_answers_by_method_path_and_body() {
    let s = service();
    assert_eq!(respond(&s, "GET", "/round1", b"").0, 405);
    assert_eq!(respond(&s, "POST", "/nope", b"").0, 404);
    let (status, body) = respond(&s, "POST", "/round1", b"{not json");
    assert_eq!((status, body["refused"].clone(), body["ok"].clone()), (400, json!(true), json!(false)));
    assert_eq!(body["identifier"], 1);
    let (status, body) = respond(&s, "POST", "/round2", b"{}");
    assert_eq!((status, body["ok"].clone()), (200, json!(false))); // a malformed round request is the service's own refusal value
}

#[test]
fn a_server_and_its_transport_talk_over_loopback() {
    let s = service();
    let server = start_signer_http_server(s, None, None).unwrap();
    assert!(server.url.starts_with("http://127.0.0.1:") && server.port > 0);
    let t = http_signer_transport(&server.url, 1, Some(5_000));
    assert_eq!(t.identifier(), 1);
    let r = t.round1(&json!({})).unwrap();
    assert_eq!((r["ok"].clone(), r["reason"].clone()), (json!(false), json!("malformed round-1 request")));
    // a raw GET is refused with 405 and the connection closes
    let mut c = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    c.write_all(b"GET /round1 HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 405 Method Not Allowed\r\n") && out.contains("method not allowed"));
    server.close();
    // the port is closed: an unreachable signer is an Err
    assert!(http_signer_transport("http://127.0.0.1:1", 1, Some(500)).round1(&Value::Null).is_err());
}
