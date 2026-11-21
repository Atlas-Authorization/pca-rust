//! L4 information-flow taint and the `enforce.taint` gate (the reference's taint.ts): the lattice, the independent classification of
//! every declared ref, the fail-closed handling, and the gate's texts.
use std::sync::Arc;

use atlas_pca::taint::*;
use serde_json::json;

struct Graph;
impl ResourceGraphNodes for Graph {
    fn node(&self, id: &str) -> bool {
        id == "node-1"
    }
}

fn gate(reg: &Arc<InMemoryTrustedInputRegistry>, max: f64) -> TaintGate {
    TaintGate { registry: reg.clone(), resource_graph: Some(Arc::new(Graph)), max_taint: max }
}

#[test]
fn the_lattice_ranks_joins_and_collapses_like_the_reference() {
    let l = |k: &str| TaintLabel::new(k);
    assert_eq!(TAINT_LEVELS, ["trusted", "first_party", "tool", "web", "agent"]);
    assert_eq!([0.0, 0.25, 0.5, 0.75, 1.0], ["trusted", "first_party", "tool", "web", "agent"].map(|k| taint_value(&l(k))));
    assert_eq!(label_rank(&l("nonsense")), 4, "an unknown kind is the worst rank");
    assert!(is_taint_level("web") && !is_taint_level("constructor") && !is_taint_level(""));
    assert_eq!(join_label(&l("web"), &l("tool")).kind, "web");
    assert_eq!(join_label(&l("tool"), &l("web")).kind, "web");
    // equal rank: the id is kept only when both agree
    let (a, b) = (TaintLabel { kind: "tool".into(), id: Some("x".into()) }, TaintLabel { kind: "tool".into(), id: Some("y".into()) });
    assert_eq!(join_label(&a, &a), a);
    assert_eq!(join_label(&a, &b), l("tool"));
    assert_eq!(join_labels(&[]), l("agent"), "no lineage is the worst case");
    assert_eq!(join_labels(&[l("trusted"), l("first_party"), l("trusted")]), l("first_party"));
}

#[test]
fn refs_are_classified_from_server_facts_never_from_the_agent() {
    let reg = Arc::new(InMemoryTrustedInputRegistry::new());
    reg.record_trusted("t").record_first_party("f").record_tool("tl", "search").record_web("w");
    reg.record("", TaintLabel::new("trusted")).record("bogus", TaintLabel::new("constructor"));
    assert_eq!(reg.size(), 4, "an empty digest and an unknown level are not recorded");
    let g: Option<&dyn ResourceGraphNodes> = Some(&Graph);
    let c = |v: serde_json::Value| classify_ref(&v, reg.as_ref(), g);
    assert_eq!(c(json!("t")).kind, "trusted");
    assert_eq!(c(json!("tl")), TaintLabel { kind: "tool".into(), id: Some("search".into()) });
    assert_eq!(c(json!("node-1")).kind, "first_party");
    assert_eq!(c(json!("unknown")), TaintLabel { kind: "agent".into(), id: Some("unknown".into()) });
    assert_eq!(c(json!("x".repeat(129))), TaintLabel::new("agent"), "a long id is dropped");
    assert_eq!(c(json!("x".repeat(128))).id.as_deref().map(str::len), Some(128));
    for bad in [json!(""), json!(7), json!(null), json!(["t"])] {
        assert_eq!(c(bad), TaintLabel::new("agent"));
    }
    assert_eq!(classify_ref(&json!("node-1"), reg.as_ref(), None).kind, "agent", "no graph, no first-party");
}

#[test]
fn compute_taint_fails_closed_and_joins_the_lineage() {
    let reg = Arc::new(InMemoryTrustedInputRegistry::new());
    reg.record_trusted("t").record_first_party("f").record_web("w");
    let ct = |p: serde_json::Value| compute_taint(&p, reg.as_ref(), None);
    assert_eq!(ct(json!({"trusted_refs": ["t"]})).unwrap().0, 0.0);
    assert_eq!(ct(json!({"trusted_refs": ["t", "f"]})).unwrap().0, 0.25);
    assert_eq!(ct(json!({"trusted_refs": ["t", "w"]})).unwrap().0, 0.75);
    assert_eq!(ct(json!({"trusted_refs": ["t", "zzz"]})).unwrap().0, 1.0);
    assert_eq!(ct(json!({"trusted_refs": []})).unwrap().0, 1.0, "an empty lineage is the worst case");
    assert_eq!(ct(json!({})).unwrap().0, 1.0, "no declared refs is the worst case");
    assert_eq!(ct(json!({"trusted_refs": "t"})).unwrap_err(), "taint: trusted_refs must be an array");
    assert_eq!(ct(json!({"trusted_refs": ["t", ""]})).unwrap_err(), "taint: trusted_refs must be non-empty strings");
    assert_eq!(ct(json!({"trusted_refs": ["t", 3]})).unwrap_err(), "taint: trusted_refs must be non-empty strings");
    for absent in [json!(null), json!("p"), json!([])] {
        assert_eq!(ct(absent).unwrap_err(), "taint: provenance is absent or malformed");
    }
}

struct Panics;
impl TrustedInputRegistry for Panics {
    fn lookup(&self, _: &str) -> Option<TaintLabel> {
        panic!("registry down")
    }
}

#[test]
fn the_gate_decides_on_the_label_rank_with_the_reference_texts() {
    let reg = Arc::new(InMemoryTrustedInputRegistry::new());
    reg.record_trusted("t").record_first_party("f").record_web("w");
    let p = |refs: serde_json::Value| json!({"trusted_refs": refs});
    assert_eq!(taint_gate_check(&p(json!(["t"])), &gate(&reg, 0.0)), Ok(()));
    assert_eq!(taint_gate_check(&p(json!(["t", "f"])), &gate(&reg, 0.25)), Ok(()));
    assert_eq!(taint_gate_check(&p(json!(["t", "f"])), &gate(&reg, 0.0)), Err("information-flow taint 0.25 exceeds policy max 0".into()));
    assert_eq!(taint_gate_check(&p(json!(["w"])), &gate(&reg, 0.5)), Err("information-flow taint 0.75 exceeds policy max 0.5".into()));
    assert_eq!(taint_gate_check(&p(json!(["w"])), &gate(&reg, 0.75)), Ok(()));
    // between two ranks the lower one is the bound: 0.6 accepts tool (0.5) and refuses web (0.75)
    assert_eq!(taint_gate_check(&p(json!(["w"])), &gate(&reg, 0.6)), Err("information-flow taint 0.75 exceeds policy max 0.6".into()));
    assert_eq!(taint_gate_check(&p(json!(["unknown"])), &gate(&reg, 0.99)), Err("information-flow taint 1 exceeds policy max 0.99".into()));
    assert_eq!(taint_gate_check(&p(json!(["unknown"])), &gate(&reg, 1.0)), Ok(()));
    assert_eq!(taint_gate_check(&p(json!([])), &gate(&reg, 0.5)), Err("information-flow taint 1 exceeds policy max 0.5".into()));
    // a stub or absent lineage never passes, whatever the bound
    assert_eq!(taint_gate_check(&json!(null), &gate(&reg, 1.0)), Err("taint: provenance is absent or malformed".into()));
    // a negative or non-finite bound is a misconfiguration
    for bad in [-0.1, f64::NAN, f64::INFINITY] {
        assert_eq!(taint_gate_check(&p(json!(["t"])), &gate(&reg, bad)), Err("taint gate misconfigured: maxTaint must be a non-negative number (fail closed)".into()));
    }
}

#[test]
fn a_panicking_registry_fails_closed() {
    let g = TaintGate { registry: Arc::new(Panics), resource_graph: None, max_taint: 1.0 };
    let r = taint_gate_check(&json!({"trusted_refs": ["t"]}), &g);
    assert_eq!(r, Err("taint: evaluation error (fail closed): registry down".into()));
    // a panic with a non-string payload is `unknown`, as a non-Error throw is in the reference
    struct Odd;
    impl TrustedInputRegistry for Odd {
        fn lookup(&self, _: &str) -> Option<TaintLabel> {
            std::panic::panic_any(7u32)
        }
    }
    let g = TaintGate { registry: Arc::new(Odd), resource_graph: None, max_taint: 1.0 };
    assert_eq!(taint_gate_check(&json!({"trusted_refs": ["t"]}), &g), Err("taint: evaluation error (fail closed): unknown".into()));
}

#[test]
fn a_registry_label_that_is_not_a_taint_level_is_never_taken_at_its_word() {
    struct Lying;
    impl TrustedInputRegistry for Lying {
        fn lookup(&self, _digest: &str) -> Option<TaintLabel> {
            Some(TaintLabel::new("constructor"))
        }
    }
    // it falls through to the server's own graph, else to the agent level with the ref as its id
    assert_eq!(classify_ref(&json!("node-1"), &Lying, Some(&Graph)), TaintLabel::new("first_party"));
    assert_eq!(classify_ref(&json!("zzz"), &Lying, None), TaintLabel { kind: "agent".into(), id: Some("zzz".into()) });
}
