//! Kill tests from the 0.5 full mutation run: plan-registry behaviour the shared vectors never pin (the wall clock, the
//! store key, an empty node id, the approval expiry boundary, unhashable operation params) and operation-state parsing.
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use atlas_pca::*;
use serde_json::{json, Value};

fn node(id: &str) -> Value {
    json!({"id": id, "verb": "orders.read", "resource": "/orders/1"})
}

fn root_of(t: PlanTransition) -> String {
    match t {
        PlanTransition::Ok(r) => r.root,
        other => panic!("{other:?}"),
    }
}

fn authorized(reg: &PlanRegistry, g: &str, nodes: &[Value], expires_at: Option<f64>) -> String {
    let root = root_of(reg.draft(g, nodes));
    assert!(reg.validate(g, &root).is_ok() && reg.commit(g, &root).is_ok());
    assert!(reg.authorize(g, &root, Some(&PlanApproval { by: "principal".into(), expires_at })).is_ok());
    root
}

#[test]
fn every_operation_state_parses_back() {
    use OperationState::*;
    for s in [Pending, Executing, Committed, Failed, Aborted, Uncertain] {
        assert_eq!(OperationState::parse(s.as_str()), Some(s));
    }
    assert_eq!(OperationState::parse("done"), None);
}

#[test]
fn a_registry_without_a_clock_reads_the_wall_clock() {
    let reg = PlanRegistry::new();
    let root = authorized(&reg, "g1", &[node("n1")], Some(1_000.0));
    let s = reg.status("g1", &root, None);
    assert!(!s.executable, "{s:?}");
    assert!(s.reason.as_deref().unwrap_or("").contains("approval expired at 1000"), "{s:?}");
}

#[test]
fn the_store_key_is_the_prefix_and_the_uri_encoded_grant() {
    let kv = Arc::new(MemoryAtomicKv::new());
    let reg = PlanRegistry::new().with_kv(kv.clone()).with_prefix("p:");
    let root = root_of(reg.draft("a-_.!~*'()/ z", &[node("n1")]));
    assert!(kv.get(&format!("p:a-_.!~*'()%2F%20z:{root}")).unwrap().is_some());
}

#[test]
fn an_empty_node_id_is_invalid() {
    let reg = PlanRegistry::new();
    let root = root_of(reg.draft("g1", &[json!({"id": "", "verb": "orders.read", "resource": "/orders/1"})]));
    match reg.validate("g1", &root) {
        PlanTransition::Refused { reason, .. } => assert!(reason.contains("every node needs an id"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_approval_lapses_at_its_expiry_instant() {
    let clock = Arc::new(AtomicI64::new(0));
    let c = clock.clone();
    let reg = PlanRegistry::new().with_clock(move || c.load(Ordering::SeqCst));
    let root = authorized(&reg, "g1", &[node("n1")], Some(500.0));
    assert!(reg.status("g1", &root, Some(499)).executable);
    assert!(!reg.status("g1", &root, Some(500)).executable);
}

#[test]
fn unhashable_operation_params_are_refused_even_when_a_node_names_their_loose_digest() {
    let reg = PlanRegistry::new();
    // outside the strict profile (an integer past 2^53-1); the loose digest still exists
    let bad = json!({"n": 9_007_199_254_740_993u64});
    let mut n = node("n1");
    n["params_digest"] = json!(params_digest(Some(&bad)));
    let root = authorized(&reg, "g1", &[n], None);
    let op = Operation { verb: "orders.read".into(), resource: "/orders/1".into(), params: bad };
    let s = reg.check("g1", &root, &PlanCheckOptions { node_id: None, operation: Some(op), now: Some(0) });
    assert!(!s.executable, "{s:?}");
    assert!(s.reason.as_deref().unwrap_or("").contains("cannot be hashed"), "{s:?}");
}
