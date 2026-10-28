//! `protect()`: secure defaults over the shared authorize fixtures, and the `doc` member of refusal bodies.
#![cfg(feature = "axum")]

use std::sync::Arc;

use atlas_pca::middleware::authorize_request;
use atlas_pca::protect::{protect, ProtectOptions};
use atlas_pca::{canonicalize_strict, explain_refusal, Operation};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

struct Case {
    grant: Value,
    op: Operation,
    header: String,
    now: i64,
    aud: String,
}

fn case() -> Case {
    let d = fixtures();
    let (grant, s) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    Case {
        grant,
        op: Operation::from_json(&s["operation"]).unwrap(),
        header: URL_SAFE_NO_PAD.encode(canonicalize_strict(&s["pcactn"]).unwrap().as_bytes()),
        now: d["now"].as_i64().unwrap(),
        aud: d["audience"].as_str().unwrap().to_string(),
    }
}

fn opts(c: &Case, grants: Vec<Value>) -> ProtectOptions {
    let (op, now) = (c.op.clone(), c.now);
    ProtectOptions::new(c.aud.clone(), grants, move |_, _| Some(op.clone())).clock(move || now)
}

#[test]
fn allows_once_then_refuses_the_replay_with_a_doc_link() {
    let c = case();
    let p = protect(opts(&c, vec![c.grant.clone()]));
    let first = authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config);
    assert!(first.allow, "{}", first.description);
    assert!(first.json_body().get("doc").is_none(), "an allow carries no doc");
    let second = authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config);
    assert!(!second.allow);
    assert_eq!(second.authorization.as_ref().unwrap().failed_checks(), vec!["replay"]);
    assert_eq!(second.json_body()["doc"], "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay");
}

#[test]
fn revoking_a_grant_refuses_it() {
    let c = case();
    let p = protect(opts(&c, vec![c.grant.clone()]));
    p.revoker.revoke(c.grant["id"].as_str().unwrap());
    let r = authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config);
    assert!(!r.allow);
    assert_eq!(r.authorization.as_ref().unwrap().failed_checks(), vec!["revocation"]);
    assert_eq!(r.json_body()["doc"], explain_refusal(&r.description).docs);
}

#[test]
fn the_grant_comes_from_the_list_never_the_request() {
    let c = case();
    let p = protect(opts(&c, vec![]));
    let r = authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config);
    assert!(!r.allow);
}

#[test]
fn caller_options_win() {
    let c = case();
    let p = protect(opts(&c, vec![c.grant.clone()]).is_revoked(|_, _| Ok(true)));
    assert!(!authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config).allow);
    // a store the caller supplies is the one used: a pre-claimed counter makes the first request a replay
    let store = Arc::new(atlas_pca::MemoryStateStore::new());
    let p = protect(opts(&c, vec![c.grant.clone()]).state_store(store.clone()));
    assert!(authorize_request(Some(&c.header), None, Some(c.op.clone()), &p.config).allow);
    let again = protect(opts(&c, vec![c.grant.clone()]).state_store(store));
    assert!(!authorize_request(Some(&c.header), None, Some(c.op.clone()), &again.config).allow);
}

#[test]
fn a_missing_proof_is_401_with_the_generic_doc() {
    let c = case();
    let p = protect(opts(&c, vec![c.grant.clone()]));
    let r = authorize_request(None, None, Some(c.op.clone()), &p.config);
    assert_eq!(r.status, 401);
    assert_eq!(r.json_body()["doc"], "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md");
}
