//! Dead-man liveness beacons v2 (the reference's beacons.ts): issuing, verification (every refusal text), monotonic and durable
//! acceptance, the verified decision, and the `beacon` check of `authorize` end to end with a real signed PCActn.
mod common;

use std::sync::Arc;

use atlas_pca::agent::*;
use atlas_pca::beacon::*;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use common::*;

const INST: &str = "inst-1";

fn issuer() -> KeyPair {
    KeyPair::from_seed(&[5u8; 32])
}

fn issuers() -> Vec<String> {
    vec![issuer().public]
}

fn mk(seq: i64, issued_at: i64, scope: &str) -> Value {
    issue_liveness_beacon(&issuer(), INST, Some(scope), seq, issued_at, None, &Suite::default()).unwrap()
}

fn verdict(b: &Value, now: i64, scope: Option<&str>) -> Result<(), String> {
    verify_liveness_beacon(b, &issuers(), now, INST, scope, None)
}

#[test]
fn issuing_checks_its_arguments_and_fixes_the_window() {
    let b = mk(3, 125_000, "*");
    assert_eq!((b["v"].clone(), b["epoch"].clone(), b["not_after"].clone(), b["scope"].clone()), (json!(2), json!(2), json!(125_000 + 300_000), json!("*")));
    let e = |seq, at, v| issue_liveness_beacon(&issuer(), INST, None, seq, at, v, &Suite::default()).unwrap_err();
    assert_eq!(e(-1, 0, None), "issueLivenessBeacon: seq must be a non-negative integer");
    assert_eq!(e(0, -1, None), "issueLivenessBeacon: issuedAt must be an integer");
    assert_eq!(e(0, 0, Some(0)), "issueLivenessBeacon: validity must be in (0, 3600000] ms");
    assert_eq!(e(0, 0, Some(3_600_001)), "issueLivenessBeacon: validity must be in (0, 3600000] ms");
    assert!(issue_liveness_beacon(&issuer(), INST, None, 0, 0, Some(3_600_000), &Suite::default()).is_ok());
    let d = issue_liveness_beacon(&issuer(), INST, None, 0, 0, None, &Suite::default()).unwrap();
    assert_eq!(d["scope"], "*", "no scope is the global scope");
}

#[test]
fn verification_refuses_every_way_a_beacon_can_be_wrong() {
    let b = mk(1, 120_000, "g1");
    assert_eq!(verdict(&b, 130_000, Some("g1")), Ok(()));
    assert_eq!(verdict(&b, 120_000 + 300_000, Some("g1")), Ok(()), "valid through not_after");
    assert_eq!(verdict(&b, 120_000 + 300_001, Some("g1")), Err("expired".into()));
    assert_eq!(verdict(&b, 120_000 - 30_000, Some("g1")), Ok(()), "30 s of clock skew is tolerated");
    assert_eq!(verdict(&b, 120_000 - 30_001, Some("g1")), Err("not yet valid".into()));
    assert_eq!(verdict(&b, 130_000, Some("g2")), Err("scope not covered".into()));
    assert_eq!(verdict(&mk(1, 120_000, "*"), 130_000, Some("g2")), Ok(()), "a global beacon covers every grant");
    assert_eq!(verdict(&b, 130_000, None), Ok(()), "no scope asked, none checked");
    assert_eq!(verify_liveness_beacon(&b, &issuers(), 130_000, "other", Some("g1"), None), Err("wrong instance".into()));
    assert_eq!(verify_liveness_beacon(&b, &[KeyPair::from_seed(&[6u8; 32]).public], 130_000, INST, Some("g1"), None), Err("issuer not pinned".into()));
    for junk in [json!(null), json!("b"), json!([]), json!({}), json!({"v": 1})] {
        assert_eq!(verdict(&junk, 0, None), Err("malformed beacon".into()));
    }
    let mut unknown_alg = b.clone();
    unknown_alg["alg"] = json!("nonsense");
    assert_eq!(verdict(&unknown_alg, 130_000, Some("g1")), Err("malformed beacon".into()));
    // any signed member changed: the signature fails
    for (k, v) in [("seq", json!(2)), ("scope", json!("g9")), ("not_after", json!(120_000 + 300_001)), ("epoch", json!(3))] {
        let mut t = b.clone();
        t[k] = v;
        let r = verdict(&t, 130_000, None);
        assert_eq!(r, Err("bad signature".into()), "{k}");
    }
    let mut t = b.clone();
    t["sig"] = json!("AAAA");
    assert_eq!(verdict(&t, 130_000, None), Err("bad signature".into()));
}

fn forged(f: impl FnOnce(&mut Value)) -> Value {
    // a beacon its issuer really signed, but with a window the reference refuses
    let mut body = json!({"v": 2, "instance": INST, "scope": "*", "epoch": 2, "seq": 1, "issued_at": 120_000, "not_after": 420_000, "issuer": issuer().public});
    f(&mut body);
    sign_artifact(LIVENESS_DOMAIN, &body, &issuer(), &Suite::default()).unwrap()
}

#[test]
fn the_window_rules_are_checked_after_the_signature() {
    assert_eq!(verdict(&forged(|_| {}), 130_000, None), Ok(()));
    assert_eq!(verdict(&forged(|b| b["not_after"] = json!(120_000 + 3_600_001)), 130_000, None), Err("validity exceeds the hard maximum".into()));
    assert_eq!(verdict(&forged(|b| b["not_after"] = json!(120_000)), 130_000, None), Err("validity exceeds the hard maximum".into()));
    assert_eq!(verdict(&forged(|b| b["not_after"] = json!(120_000 + 3_600_000)), 130_000, None), Ok(()), "exactly the maximum is allowed");
    assert_eq!(verdict(&forged(|b| b["epoch"] = json!(1)), 130_000, None), Err("epoch does not match issued_at".into()));
    assert_eq!(verdict(&forged(|b| b["seq"] = json!(-1)), 130_000, None), Err("malformed window".into()));
    assert_eq!(verdict(&forged(|b| b["seq"] = json!(1.5)), 130_000, None), Err("malformed window".into()));
    assert_eq!(verdict(&forged(|b| b["issued_at"] = json!("x")), 130_000, None), Err("malformed window".into()));
}

#[test]
fn acceptance_is_strictly_monotonic_and_a_frozen_grant_needs_one_live_beacon() {
    let b = mk(5, 120_000, "*");
    assert_eq!(accept_beacon(None, &b), Ok(()));
    assert_eq!(accept_beacon(Some(4), &b), Ok(()));
    assert_eq!(accept_beacon(Some(5), &b), Err("replayed beacon: seq 5 <= 5".into()));
    assert_eq!(accept_beacon(Some(9), &b), Err("replayed beacon: seq 5 <= 9".into()));
    for junk in [json!(null), json!({}), json!({"seq": -1}), json!({"seq": 1.5}), json!({"seq": "1"}), json!({"seq": 9_007_199_254_740_992u64})] {
        assert_eq!(accept_beacon(None, &junk), Err("malformed beacon".into()), "{junk}");
    }
    assert!(is_frozen_liveness(&[], &issuers(), 130_000, INST, None, None), "absence is a freeze");
    assert!(is_frozen_liveness(&[mk(1, 120_000, "*")], &issuers(), 999_999_999, INST, None, None), "an expired beacon freezes");
    assert!(!is_frozen_liveness(&[mk(1, 0, "*"), mk(2, 120_000, "*")], &issuers(), 130_000, INST, None, None), "one live beacon is enough");
    assert_eq!(beacon_decision(false, true, false, true), "not-enforced");
    assert_eq!(beacon_decision(true, false, false, true), "rejected");
    assert_eq!(beacon_decision(true, true, true, true), "replayed");
    assert_eq!(beacon_decision(true, true, false, false), "unbound");
    assert_eq!(beacon_decision(true, true, false, true), "pass");
}

#[test]
fn the_durable_acceptor_remembers_the_highest_seq_across_handles() {
    let kv = Arc::new(MemoryAtomicKv::new());
    let acc = |kv: &Arc<MemoryAtomicKv>| BeaconAcceptor::new(kv.clone());
    let a = |acc: &BeaconAcceptor, b: &Value| acc.accept(b, &issuers(), 130_000, INST, None, None);
    assert_eq!(a(&acc(&kv), &mk(5, 120_000, "g1")), Ok(()));
    // a restarted verifier (a new acceptor on the same store) still refuses the captured older beacon
    assert_eq!(a(&acc(&kv), &mk(4, 120_000, "g1")), Err("replayed beacon: seq 4 <= 5".into()));
    assert_eq!(a(&acc(&kv), &mk(5, 120_000, "g1")), Err("replayed beacon: seq 5 <= 5".into()));
    assert_eq!(a(&acc(&kv), &mk(6, 120_000, "g1")), Ok(()));
    assert_eq!(a(&acc(&kv), &mk(1, 120_000, "g2")), Ok(()), "another scope has its own sequence");
    // a beacon that fails verification is refused with that reason and records nothing
    assert_eq!(acc(&kv).accept(&mk(7, 120_000, "g1"), &issuers(), 130_000, "other", None, None), Err("wrong instance".into()));
    assert_eq!(a(&acc(&kv), &mk(7, 120_000, "g1")), Ok(()));
    // junk on disk or a failing store is "unavailable", never an accept
    let junk = Arc::new(MemoryAtomicKv::new());
    let key = format!("beacon-seq/v1/{}", json!([INST, "g1", issuer().public]));
    junk.update(&key, &mut |_| Some(json!("nope"))).unwrap();
    assert_eq!(a(&BeaconAcceptor::new(junk), &mk(1, 120_000, "g1")), Err("beacon state unavailable".into()));
}

// ---- the `beacon` check of authorize, end to end

const AUD: &str = "rs-beacon";

fn fixture(freshness: Option<Value>) -> (Value, Value, Operation) {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    let mut extra = Map::new();
    if let Some(f) = freshness {
        extra.insert("freshness".into(), f);
    }
    let a = agent.act("refund", "orders/1", Some(&params), extra, &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    (grant, a.pcactn, op)
}

fn fresh_for(b: &Value) -> Value {
    json!({"beacon_ref": beacon_ref(b).unwrap(), "epoch": 0, "accumulator_witness": "w"})
}

fn calm(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"semanticDistance": 0, "reversibility": 1, "blastRadius": 0, "taint": 0, "confidence": 1, "age": 0}).as_object().cloned().unwrap())
}

fn run(grant: &Value, p: &Value, op: &Operation, store: &dyn StateStore, src: Option<&BeaconFn>) -> AuthorizeResult {
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let input = AuthorizeInput {
        risk: Some(&calm as &RiskFn),
        operation: Some(op),
        audience: AUD,
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&not_revoked),
        now: p["iat"].as_i64(),
        plan: Some("single-step"),
        beacon: src,
        provenance_mediators: &harness_pins(),
        provenance_bundle: Some(&principal_direct),
        ..Default::default()
    };
    authorize(Some(p), &input)
}

fn ctx_of(b: Value, last: Option<i64>) -> BeaconCtx {
    BeaconCtx { beacon: b, issuers: issuers(), instance: INST.into(), pq_pins: None, last_accepted_seq: last }
}

#[test]
fn a_beacon_scoped_to_another_grant_is_refused_and_consumes_nothing() {
    let (_, p0, _) = fixture(None);
    let b = issue_liveness_beacon(&issuer(), INST, Some("some-other-grant"), 5, p0["iat"].as_i64().unwrap() - 1_000, None, &Suite::default()).unwrap();
    let (grant, p, op) = fixture(Some(fresh_for(&b)));
    let store = MemoryStateStore::new();
    let bc = b.clone();
    let src = move |_: &str, _: &Value| Some(ctx_of(bc.clone(), None));
    let r = run(&grant, &p, &op, &store, Some(&src));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "beacon: scope not covered"), "{:?}", r.reasons);
    let stream = format!("{}:{}", grant["id"].as_str().unwrap(), p["cap_chain"][0]["holder"].as_str().unwrap());
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
}

#[test]
fn the_beacon_check_is_required_binds_the_ref_and_pins_the_sequence() {
    // a global beacon covers whichever grant the fixture mints
    let (_, p0, _) = fixture(None);
    let iat = p0["iat"].as_i64().unwrap();
    let live = |seq: i64| issue_liveness_beacon(&issuer(), INST, None, seq, iat - 1_000, None, &Suite::default()).unwrap();
    let b5 = live(5);
    let (grant, p, op) = fixture(Some(fresh_for(&b5)));
    let store = MemoryStateStore::new();
    let b5c = b5.clone();
    let src5 = move |_: &str, _: &Value| Some(ctx_of(b5c.clone(), None));
    let r = run(&grant, &p, &op, &store, Some(&src5));
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(r.checks.get("beacon"), Some(&CheckStatus::Pass));
    assert_eq!(store.pin(&format!("{}:beacon", grant["id"].as_str().unwrap())), Ok(Some(5)), "the admitted beacon's seq is pinned");

    // a PCActn that names no beacon: unbound
    let (grant, p, op) = fixture(None);
    let r = run(&grant, &p, &op, &MemoryStateStore::new(), Some(&src5));
    assert!(!r.allow && r.reasons.iter().any(|x| x == "beacon: PCActn freshness.beacon_ref does not bind the presented beacon"), "{:?}", r.reasons);

    // an older beacon than the host already accepted: a replay, nothing pinned
    let (grant, p, op) = fixture(Some(fresh_for(&b5)));
    let store = MemoryStateStore::new();
    let b5s = b5.clone();
    let stale = move |_: &str, _: &Value| Some(ctx_of(b5s.clone(), Some(9)));
    let r = run(&grant, &p, &op, &store, Some(&stale));
    assert!(!r.allow && r.reasons.iter().any(|x| x == "beacon: beacon seq 5 is older than the last accepted 9 (replay)"), "{:?}", r.reasons);
    assert_eq!(store.pin(&format!("{}:beacon", grant["id"].as_str().unwrap())), Ok(None));

    // no beacon at all: the required check is not enforced, so the call is refused
    let (grant, p, op) = fixture(Some(fresh_for(&b5)));
    let none = |_: &str, _: &Value| None;
    let r = run(&grant, &p, &op, &MemoryStateStore::new(), Some(&none));
    assert!(!r.allow && r.reasons.iter().any(|x| x.starts_with("beacon: required check is not-enforced")), "{:?}", r.reasons);

    // an expired beacon is rejected with the verifier's reason
    let old = issue_liveness_beacon(&issuer(), INST, None, 7, iat - 2_000_000, None, &Suite::default()).unwrap();
    let (grant, p, op) = fixture(Some(fresh_for(&old)));
    let oldc = old.clone();
    let src_old = move |_: &str, _: &Value| Some(ctx_of(oldc.clone(), None));
    let r = run(&grant, &p, &op, &MemoryStateStore::new(), Some(&src_old));
    assert!(!r.allow && r.reasons.iter().any(|x| x == "beacon: expired"), "{:?}", r.reasons);
}

/// A store with no pins cannot protect a beacon from replay: configuration refused before anything is decided.
struct NoPins(MemoryStateStore);
impl StateStore for NoPins {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
}

#[test]
fn a_beacon_needs_a_store_with_pins() {
    let (grant, p, op) = fixture(None);
    let src = |_: &str, _: &Value| None;
    let r = run(&grant, &p, &op, &NoPins(MemoryStateStore::new()), Some(&src));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "authorize_config: beacon needs a state store that implements pins (replay protection)"), "{:?}", r.reasons);
}
