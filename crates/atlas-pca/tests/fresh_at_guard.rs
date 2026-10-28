//! `fresh_at` through the guard and `authorize`: ok, stale => escalate, no policy => refused, side-carried header.
#![cfg(feature = "axum")]
use std::sync::Arc;

use atlas_pca::fresh_at::FreshAtPolicy;
use atlas_pca::middleware::{verify_request_side, GuardConfig};
use atlas_pca::{authorize, canonicalize_strict, AuthorizeInput, CheckStatus, MemoryStateStore, Operation, StateStore};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

fn vector(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/fresh-at-vectors.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("read fresh-at-vectors.json")).unwrap();
    doc["vectors"].as_array().unwrap().iter().find(|v| v["name"] == name).unwrap_or_else(|| panic!("no vector {name}")).clone()
}

fn policy(v: &Value) -> Option<FreshAtPolicy> {
    v["context"].get("fresh_at").map(|p| FreshAtPolicy::from_json(p).unwrap())
}

/// Signature-only guard over a vector; `side` is the raw `pca-fresh-at` header. The policy's own side_carried is
/// moved into a header (`header_from_policy`) the way a client would send it.
fn guard(name: &str, with_policy: bool, header_from_policy: bool, raw_side: Option<&str>) -> (bool, String) {
    let v = vector(name);
    let (grant, aud, now) = (v["grant"].clone(), v["context"]["aud"].as_str().unwrap().to_string(), v["context"]["now"].as_i64().unwrap());
    let mut side = raw_side.map(str::to_string);
    let mut cfg = GuardConfig::new(aud, move |r: &str| (r == grant["id"].as_str().unwrap()).then(|| grant.clone()))
        .with_signature_only()
        .with_clock(move || now);
    if with_policy {
        let mut p = policy(&v).expect("vector has a policy");
        if header_from_policy {
            side = p.side_carried.take().map(|t| t.to_string());
        }
        cfg = cfg.with_fresh_at(p);
    }
    let h = URL_SAFE_NO_PAD.encode(canonicalize_strict(&v["pcactn"]).unwrap().as_bytes());
    let r = verify_request_side(Some(&h), None, &cfg, side.as_deref());
    (r.allow, r.json_body().to_string())
}

#[test]
fn guard_member_ok() {
    assert!(guard("member-equal-state", true, false, None).0);
}

#[test]
fn guard_stale_is_refused_as_escalate() {
    let (allow, body) = guard("member-stale-revocation_epoch", true, false, None);
    assert!(!allow);
    assert!(body.contains("fresh_at") && body.contains("escalate"), "{body}");
}

#[test]
fn guard_member_without_policy_is_refused() {
    let (allow, body) = guard("member-without-policy", false, false, None);
    assert!(!allow, "{body}");
}

#[test]
fn guard_side_carried_header() {
    assert!(guard("side-carried-ok", true, true, None).0);
    assert!(!guard("side-carried-stale", true, true, None).0);
    // an unparseable header is a bad token, never a missing one
    let (allow, body) = guard("side-carried-ok", true, true, None);
    assert!(allow, "{body}");
    let v = vector("side-carried-ok");
    let mut p = policy(&v).unwrap();
    p.side_carried = None;
    let (grant, now) = (v["grant"].clone(), v["context"]["now"].as_i64().unwrap());
    let cfg = GuardConfig::new(v["context"]["aud"].as_str().unwrap().to_string(), move |_: &str| Some(grant.clone()))
        .with_signature_only()
        .with_clock(move || now)
        .with_fresh_at(p);
    let h = URL_SAFE_NO_PAD.encode(canonicalize_strict(&v["pcactn"]).unwrap().as_bytes());
    assert!(!verify_request_side(Some(&h), None, &cfg, Some("{not json")).allow);
}

fn run_authorize(name: &str, with_policy: bool) -> atlas_pca::AuthorizeResult {
    let v = vector(name);
    let g = v["grant"].clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let op = Operation::new("noop", "none", serde_json::json!({}));
    let p = if with_policy { policy(&v) } else { None };
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: v["context"]["aud"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(store.as_ref()),
        is_revoked: Some(&revoked),
        now: v["context"]["now"].as_i64(),
        plan: Some("single-step"),
        fresh_at: p.as_ref(),
        ..Default::default()
    };
    authorize(Some(&v["pcactn"]), &input)
}

#[test]
fn authorize_forwards_the_policy() {
    // the vectors are not bound to an operation, so only the fresh_at check itself is asserted
    assert_eq!(run_authorize("member-equal-state", true).check("fresh_at"), Some(CheckStatus::Pass));
    let stale = run_authorize("member-stale-revocation_epoch", true);
    assert_eq!(stale.check("fresh_at"), Some(CheckStatus::Fail));
    assert!(stale.reasons.iter().any(|r| r.contains("escalate: stale_state")), "{:?}", stale.reasons);
    let none = run_authorize("member-without-policy", false);
    assert!(!none.allow);
    assert_eq!(none.check("fresh_at"), Some(CheckStatus::Fail));
}
