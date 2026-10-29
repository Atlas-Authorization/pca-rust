//! Revocation staleness wired into `authorize`: the boolean `is_revoked` hook keeps working unchanged, and a configured
//! gate fails the same `revocation` check when the revocation state is stale, unsigned for an irreversible action, or absent.
mod common;

use atlas_pca::*;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    strict_parse(&text).unwrap()
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn guardian() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn epoch(grant_ref: &str, issued_at: i64) -> Value {
    let mut e = json!({"instance_id": "i", "grant_ref": grant_ref, "epoch": 0, "set_size": 0, "root": "r", "issued_at": issued_at, "not_after": issued_at + 600_000});
    let mut msg = b"atlas-pca/revepoch/v1\0".to_vec();
    msg.extend_from_slice(canonicalize(&e).as_bytes());
    e["guardian"] = json!(b64(guardian().verifying_key().as_bytes()));
    e["sig"] = json!(b64(&guardian().sign(&msg).to_bytes()));
    e
}

/// Run the first fixture step with `gate` and the given server class; returns (allow, revocation reason).
fn run(gate: Option<&RevocationStaleness>, server_class: Option<&'static str>) -> (bool, Option<String>) {
    let d = fixtures();
    let (grant, s) = (&d["cases"][0]["grant"], &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let ctx = move |_: &Value| Ok::<_, String>(server_class.map(|c| json!({"reversibility_class": c})));
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        revocation_staleness: gate,
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        context: Some(&ctx),
        provenance_mediators: &common::harness_pins(),
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    let r = authorize(Some(&s["pcactn"]), &input);
    let why = r.reasons.iter().find(|x| x.starts_with("revocation")).cloned();
    (r.allow, why)
}

fn gate_for(issued_ago_ms: i64, policy: RevocationStalenessPolicy) -> RevocationStaleness {
    let d = fixtures();
    let (now, gref) = (d["now"].as_i64().unwrap(), d["cases"][0]["steps"][0]["pcactn"]["grant_ref"].as_str().unwrap().to_string());
    let ep = epoch(&gref, now - issued_ago_ms);
    RevocationStaleness::new(policy, move |_, _| Ok(Some(RevocationState { epoch: Some(ep.clone()), ..Default::default() })))
        .unwrap()
        .with_guardian(b64(guardian().verifying_key().as_bytes()))
        .with_ids(|_| Vec::new()) // these tests exercise freshness only; proofs have their own tests below
}

#[test]
fn no_gate_is_the_unchanged_boolean_hook() {
    assert_eq!(run(None, None), (true, None));
}

#[test]
fn a_fresh_signed_epoch_passes_and_a_stale_one_is_denied() {
    let policy = RevocationStalenessPolicy { max_revocation_age_ms: Some(100_000.0), ..Default::default() };
    let (allow, why) = run(Some(&gate_for(1_000, policy)), Some("reversible"));
    assert!(allow, "{why:?}");
    let (allow, why) = run(Some(&gate_for(250_000, policy)), Some("reversible"));
    assert!(!allow);
    assert!(why.unwrap().contains("250000 ms old, over the verifier's maximum of 100000 ms (stale revocation state)"));
}

#[test]
fn the_server_class_tightens_the_window() {
    let policy = RevocationStalenessPolicy { max_revocation_age_ms: Some(300_000.0), ..Default::default() };
    let (allow, why) = run(Some(&gate_for(130_000, policy)), Some("irreversible"));
    assert!(!allow);
    assert!(why.unwrap().contains("over the verifier's maximum of 120000 ms"));
}

#[test]
fn unavailable_or_unsigned_state_is_denied() {
    let none = RevocationStaleness::new(RevocationStalenessPolicy::default(), |_, _| Ok(None)).unwrap();
    assert!(run(Some(&none), None).1.unwrap().contains("no signed revocation epoch"));
    let failing = RevocationStaleness::new(RevocationStalenessPolicy::default(), |_, _| Err("store down".into())).unwrap();
    assert!(!run(Some(&failing), None).0);
    let bare = RevocationStaleness::new(RevocationStalenessPolicy { max_revocation_age_ms: Some(300_000.0), ..Default::default() }, |_, _| {
        Ok(Some(RevocationState { epoch: None, root: Some("r".into()), root_issued_at: Some(0.0) }))
    })
    .unwrap();
    assert!(run(Some(&bare), Some("irreversible")).1.unwrap().contains("unsigned revocation root refused for an irreversible action"));
}

#[test]
fn a_revoked_grant_stays_revoked_under_a_fresh_gate() {
    let d = fixtures();
    let (grant, s) = (&d["cases"][0]["grant"], &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(true);
    let store = MemoryStateStore::new();
    let gate = gate_for(1_000, RevocationStalenessPolicy::default());
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&revoked),
        revocation_staleness: Some(&gate),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        ..Default::default()
    };
    let r = authorize(Some(&s["pcactn"]), &input);
    assert!(!r.allow && r.reasons.iter().any(|x| x.contains("the grant is revoked")));
}

#[test]
fn every_chain_capability_needs_a_non_membership_proof() {
    // Default ids = the PCActn's cap_chain: with no proof source the request is denied, fail closed.
    let policy = RevocationStalenessPolicy::default();
    let (now, d) = (fixtures()["now"].as_i64().unwrap(), fixtures());
    let gref = d["cases"][0]["steps"][0]["pcactn"]["grant_ref"].as_str().unwrap().to_string();
    let root = revset_root(&[]).unwrap();
    let mut ep = epoch(&gref, now - 1_000);
    ep["root"] = json!(root);
    // re-sign over the empty-set root
    let mut body = ep.clone();
    body.as_object_mut().unwrap().remove("guardian");
    body.as_object_mut().unwrap().remove("sig");
    let mut msg = b"atlas-pca/revepoch/v1\0".to_vec();
    msg.extend_from_slice(canonicalize(&body).as_bytes());
    ep["sig"] = json!(b64(&guardian().sign(&msg).to_bytes()));
    let mk = |proofs: bool| {
        let ep = ep.clone();
        let g = RevocationStaleness::new(policy, move |_, _| Ok(Some(RevocationState { epoch: Some(ep.clone()), ..Default::default() })))
            .unwrap()
            .with_guardian(b64(guardian().verifying_key().as_bytes()));
        if proofs { g.with_proofs(|_, _| Some(json!({"size": 0}))) } else { g }
    };
    let (allow, why) = run(Some(&mk(false)), None);
    assert!(!allow);
    assert!(why.unwrap().contains("no non-membership proof for"));
    let (allow, why) = run(Some(&mk(true)), None);
    assert!(allow, "{why:?}");
}
