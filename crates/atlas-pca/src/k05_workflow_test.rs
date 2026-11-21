//! k05 differential oracle for K5 workflow (DAG) admission: tests/data/k05-workflow.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/workflow-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file). Admission
//! results are compared in full ({decision, code, step, at, pending}); `ancestors` as {id: sorted ids} or null.
use super::*;
use crate::k042_support::{k05_run, K05};

fn digest(r: Option<String>) -> K05 {
    r.map_or(K05::Throw(None), |s| K05::Val(json!(s)))
}

fn input(a: &[Value]) -> AdmitInput<'_> {
    AdmitInput { workflow: &a[0], principal: &a[1], rs_signer: &a[2], receipts: &a[3], now: &a[4], request: &a[5] }
}

#[test]
fn k05_workflow_matches_the_reference() {
    k05_run("workflow", 14000, |case, f, a| match f {
        "admit" => K05::Val(admit_step(&input(a)).to_json()),
        "bind" => K05::Val(bind_promises(&input(a)).to_json()),
        "validBody" => K05::Val(json!(parse_body(&a[0]).is_some())),
        // dag / ancestors cases are generated only for bodies the reference accepts as valid
        "dag" => match parse_body(&a[0]) {
            Some(b) => K05::Val(json!(dag_error(&b))),
            None => K05::Match(false),
        },
        "ancestors" => match parse_body(&a[0]) {
            // the reference throws on a dependency that names no step (outside its precondition); the total Rust port answers None
            Some(b) if case["out"].get("$throws").is_some() => K05::Match(ancestors(&b).is_none()),
            Some(b) => K05::Val(ancestors(&b).map_or(Value::Null, |m| json!(m))),
            None => K05::Match(false),
        },
        "planRoot" => match (a[1].as_str(), a[2].as_i64(), a[3].as_str()) {
            (Some(p), Some(now), Some(root)) => K05::Val(json!(plan_root_authorized(&a[0], p, now, root))),
            (None, _, _) => K05::Skip("non-string principal pin (the Rust signature takes &str)"),
            (_, None, _) => K05::Skip("non-integer now (the Rust signature takes i64)"),
            (_, _, None) => K05::Skip("null plan root (the Rust signature takes &str)"),
        },
        "valueDigest" => digest(value_digest(&a[0])),
        "workflowDigest" => digest(workflow_digest(&a[0])),
        "receiptRef" => digest(receipt_ref(&a[0])),
        _ => K05::Skip("fn not in this module"),
    });
}

// Each clause of the validity chains alone, with every other member valid. Bad values are strings wherever the parser would
// otherwise stop at a later `?` on the same value, so the chain is the only thing that can refuse. All limits per workflow.ts.
fn b32() -> Value {
    json!("A".repeat(43))
}

fn set(base: &Value, ptr: &str, x: Value) -> Value {
    let mut v = base.clone();
    *v.pointer_mut(ptr).unwrap() = x;
    v
}

fn step(id: &str, deps: &[&str]) -> Value {
    json!({"id": id, "verb": "v", "resource": "r", "params_digest": null, "deps": deps, "sink": null, "deny_labels": [], "escalate_labels": [], "fresh_ms": null, "cost": {}})
}

fn edge(from: &str, to: &str) -> Value {
    json!({"from": {"step": from, "field": "f"}, "to": {"step": to, "param": "p"}, "op": "le", "unit": null, "deny_labels": [], "promise": null})
}

fn body(steps: Vec<Value>, edges: Vec<Value>) -> Value {
    json!({"v": 1, "id": "wf", "principal": b32(), "goal_digest": null, "plan_root": null, "issued_at": 1, "expires_at": 2, "steps": steps, "edges": edges, "budget": {"max_steps": 8, "caps": {}}})
}

#[test]
fn parse_edge_refuses_each_clause_alone() {
    let e = edge("a", "b");
    assert!(parse_edge(&e).is_some());
    assert!(parse_edge(&set(&set(&e, "/unit", json!("USD")), "/promise", json!("p1"))).is_some());
    assert!(parse_edge(&set(&e, "/from/step", json!("a".repeat(64)))).is_some());
    for (p, x) in [
        ("/from/step", json!("a b")),
        ("/from/step", json!("a".repeat(65))),
        ("/from/field", json!("a:b")), // a colon is an id character, not a name character
        ("/to/step", json!("a b")),
        ("/to/param", json!("a:b")),
        ("/unit", json!("a b")),
        ("/unit", json!("a".repeat(17))),
        ("/unit", json!(5)),
        ("/promise", json!("a b")),
        ("/promise", json!(5)),
    ] {
        assert!(parse_edge(&set(&e, p, x.clone())).is_none(), "{p} {x}");
    }
}

#[test]
fn parse_body_refuses_each_clause_alone() {
    let b = body(vec![step("a", &[])], vec![]);
    assert!(parse_body(&b).is_some());
    for (p, x) in [
        ("/id", json!("a b")),
        ("/principal", json!("x")),
        ("/goal_digest", json!("x")),
        ("/goal_digest", json!(5)),
        ("/plan_root", json!("x")),
        ("/plan_root", json!(5)),
        ("/issued_at", json!(-1)),
        ("/expires_at", json!(-1)),
    ] {
        assert!(parse_body(&set(&b, p, x.clone())).is_none(), "{p} {x}");
    }
}

#[test]
fn parse_body_steps_are_one_to_64() {
    let many = |n: usize| body(vec![step("a", &[]); n], vec![]);
    assert!(parse_body(&many(0)).is_none());
    assert!(parse_body(&many(1)).is_some());
    assert!(parse_body(&many(64)).is_some());
    assert!(parse_body(&many(65)).is_none());
}

#[test]
fn dag_error_reasons_as_the_reference() {
    let err = |steps: Vec<Value>, edges: Vec<Value>| dag_error(&parse_body(&body(steps, edges)).unwrap());
    const EDGE: Option<&str> = Some("edge does not follow a dependency");
    let ab = || vec![step("a", &[]), step("b", &["a"])];
    assert_eq!(err(ab(), vec![edge("a", "b")]), None);
    assert_eq!(err(vec![step("a", &[]), step("b", &["a"]), step("c", &["b"])], vec![edge("a", "c")]), None);
    assert_eq!(err(vec![step("a", &[]), step("a", &[])], vec![]), Some("duplicate step id"));
    // both refuse as "cycle" further down if this clause is lost
    assert_eq!(err(vec![step("a", &["a"])], vec![]), Some("bad dependency"));
    assert_eq!(err(vec![step("a", &["z"])], vec![]), Some("bad dependency"));
    assert_eq!(err(vec![step("a", &["b"]), step("b", &["a"])], vec![]), Some("cycle"));
    assert_eq!(err(ab(), vec![edge("z", "b")]), EDGE);
    assert_eq!(err(ab(), vec![edge("a", "z")]), EDGE);
    assert_eq!(err(ab(), vec![edge("y", "z")]), EDGE);
    assert_eq!(err(ab(), vec![edge("b", "a")]), EDGE);
    assert_eq!(err(ab(), vec![edge("a", "a")]), EDGE);
}

#[test]
fn parse_out_refuses_each_clause_alone() {
    let o = json!({"digest": b32(), "num": 1, "unit": "USD", "labels": []});
    assert!(parse_out(&o).is_some());
    assert!(parse_out(&set(&set(&o, "/num", json!(null)), "/unit", json!(null))).is_some());
    for (p, x) in [("/digest", json!("x")), ("/num", json!(-1)), ("/num", json!("1")), ("/unit", json!("a b")), ("/unit", json!(5))] {
        assert!(parse_out(&set(&o, p, x.clone())).is_none(), "{p} {x}");
    }
}

#[test]
fn parse_receipt_refuses_each_clause_alone() {
    let r = json!({"v": 1, "wf": b32(), "step": "a", "seq": 1, "prev": b32(), "outcome": "ok", "params_digest": b32(), "outputs": {}, "issued_at": 5, "signer": b32(), "sig": "s"});
    assert!(parse_receipt(&r).is_some());
    assert!(parse_receipt(&set(&r, "/outcome", json!("failed"))).is_some());
    assert!(parse_receipt(&set(&set(&r, "/seq", json!(0)), "/prev", json!(null))).is_some());
    for (p, x) in [
        ("/wf", json!("x")),
        ("/step", json!("a b")),
        ("/prev", json!("x")),
        ("/prev", json!(null)), // seq 1 must name a previous receipt
        ("/seq", json!(0)),     // seq 0 must not
        ("/outcome", json!("pending")),
        ("/params_digest", json!("x")),
        ("/issued_at", json!(-1)),
        ("/signer", json!("x")),
        ("/sig", json!(5)),
    ] {
        assert!(parse_receipt(&set(&r, p, x.clone())).is_none(), "{p} {x}");
    }
}

#[test]
fn parse_request_units_need_a_name_key_and_a_unit_value() {
    let r = json!({"step": "a", "verb": "v", "resource": "r", "params": {}, "units": {}, "goal_digest": null, "plan_root": null});
    assert!(parse_request(&r).is_some());
    assert!(parse_request(&set(&r, "/units", json!({"amt": "USD"}))).is_some());
    for x in [json!({"a b": "USD"}), json!({"a:b": "USD"}), json!({"amt": "a b"}), json!({"amt": 5}), json!({"amt": "a".repeat(17)})] {
        assert!(parse_request(&set(&r, "/units", x.clone())).is_none(), "{x}");
    }
}

// Per workflow.ts: ID_RE, LABEL_RE and NAME_RE refuse "__proto__", UNIT_RE does not; isStr counts UTF-16 units; isUint refuses -0.
#[test]
fn id_label_and_unit_classes_match_the_reference_regexes() {
    for ok in ["a", "Z", "0", "_", ".", ":", "-", "aZ0_.:-"] {
        assert!(is_id_str(ok), "{ok}");
    }
    for ok in ["a", "z", "0", "9", "_", ".", ":", "-", "a0_.:-"] {
        assert!(is_label_str(ok), "{ok}");
    }
    assert!(is_id_str(&"a".repeat(64)) && is_label_str(&"a".repeat(64)));
    for bad in [String::new(), "a b".into(), "\u{e9}".into(), "a".repeat(65), "__proto__".into()] {
        assert!(!is_id_str(&bad) && !is_label_str(&bad), "{bad}");
    }
    assert!(!is_label_str("A"));
    for ok in ["a".to_string(), "aZ0_.:-".into(), "a".repeat(16), "__proto__".into()] {
        assert!(is_unit_str(&ok), "{ok}");
    }
    for bad in [String::new(), "a b".into(), "\u{e9}".into(), "a".repeat(17)] {
        assert!(!is_unit_str(&bad), "{bad}");
    }
}

#[test]
fn is_str_and_is_uint_boundaries() {
    assert!(is_str(Some(&json!("ab")), 2));
    assert!(is_str(Some(&json!("\u{1F600}")), 2));
    for bad in [json!(""), json!("abc"), json!("\u{1F600}a"), json!(5)] {
        assert!(!is_str(Some(&bad), 2), "{bad}");
    }
    assert!(!is_str(None, 2));
    assert!(is_uint(Some(&json!(0))));
    assert!(is_uint(Some(&json!(9_007_199_254_740_991i64))));
    for bad in [json!(-1), json!(1.5), json!(-0.0), json!("1"), json!(9_007_199_254_740_992i64), json!(null)] {
        assert!(!is_uint(Some(&bad)), "{bad}");
    }
    assert!(!is_uint(None));
}

#[test]
fn parse_step_refuses_each_clause_alone() {
    let s = step("a", &[]);
    assert!(parse_step(&s).is_some());
    let full = set(&set(&set(&s, "/params_digest", b32()), "/sink", json!("s")), "/fresh_ms", json!(0));
    assert!(parse_step(&full).is_some());
    assert!(parse_step(&set(&s, "/verb", json!("v".repeat(128)))).is_some());
    assert!(parse_step(&set(&s, "/resource", json!("r".repeat(512)))).is_some());
    for (p, x) in [
        ("/id", json!("a b")),
        ("/verb", json!("")),
        ("/verb", json!("v".repeat(129))),
        ("/resource", json!("")),
        ("/resource", json!("r".repeat(513))),
        ("/params_digest", json!("x")),
        ("/params_digest", json!(5)),
        ("/sink", json!("a b")),
        ("/sink", json!(5)),
        ("/fresh_ms", json!(-1)),
        ("/fresh_ms", json!("1")),
        ("/fresh_ms", json!(1.5)),
    ] {
        assert!(parse_step(&set(&s, p, x.clone())).is_none(), "{p} {x}");
    }
}

// ---- signed admission: receipt time, pipelined receipts and edge relations (workflow.ts lines 311, 334, 389) ----

use crate::agent::KeyPair;

fn signed(k: &KeyPair, domain: &str, body: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(k.sign(&crate::fresh_at::domain_bytes(domain, body).unwrap()))
}

/// A signed workflow of the principal (seed 1), valid from 1 up to 1000.
fn wf(steps: Vec<Value>, edges: Vec<Value>) -> Value {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let b = set(&set(&body(steps, edges), "/principal", json!(k.public)), "/expires_at", json!(1000));
    json!({"sig": signed(&k, WORKFLOW_DOMAIN, &b), "body": b})
}

/// The first receipt (seq 0), by the resource server (seed 2), for `step`; output `f` = 10 when `step` is a.
fn first_receipt(w: &Value, step: &str, issued_at: i64) -> Value {
    let rs = KeyPair::from_seed(&[2u8; 32]);
    let outputs = json!({"f": {"digest": value_digest(&json!(10)).unwrap(), "num": 10, "unit": null, "labels": []}});
    let mut r = json!({"v": 1, "wf": workflow_digest(&w["body"]).unwrap(), "step": step, "seq": 0, "prev": null, "outcome": "ok", "params_digest": b32(), "outputs": outputs, "issued_at": issued_at, "signer": rs.public});
    let sig = signed(&rs, WF_RECEIPT_DOMAIN, &r);
    r["sig"] = json!(sig);
    r
}

fn admit(w: &Value, receipts: &[Value], now: i64, step: &str, params: Value) -> WfResult {
    let (principal, rs) = (json!(KeyPair::from_seed(&[1u8; 32]).public), json!(KeyPair::from_seed(&[2u8; 32]).public));
    let request = json!({"step": step, "verb": "v", "resource": "r", "params": params, "units": {}, "goal_digest": null, "plan_root": null});
    let (receipts, now) = (Value::Array(receipts.to_vec()), json!(now));
    admit_step(&AdmitInput { workflow: w, principal: &principal, rs_signer: &rs, receipts: &receipts, now: &now, request: &request })
}

#[test]
fn a_workflow_and_a_receipt_are_good_from_their_issue_time() {
    let w = wf(vec![step("a", &[]), step("b", &["a"])], vec![]);
    assert_eq!(admit(&w, &[], 1, "a", json!({})).decision, Decision::Allow);
    assert_eq!(admit(&w, &[], 0, "a", json!({})).code, Some("not_yet"));
    let r = first_receipt(&w, "a", 5);
    assert_eq!(admit(&w, std::slice::from_ref(&r), 5, "b", json!({})).decision, Decision::Allow);
    let late = admit(&w, std::slice::from_ref(&r), 4, "b", json!({}));
    assert_eq!((late.code, late.at), (Some("bad_receipt"), Some(0)));
}

#[test]
fn a_receipt_may_precede_its_dependency_only_through_promised_edges() {
    let steps = || vec![step("a", &[]), step("b", &["a"]), step("c", &[])];
    let promised = set(&edge("a", "b"), "/promise", json!("p1"));
    for (edges, ok) in [(vec![], false), (vec![edge("a", "b")], false), (vec![promised.clone()], true), (vec![promised, set(&edge("a", "b"), "/to/param", json!("q"))], false)] {
        let w = wf(steps(), edges);
        let r = first_receipt(&w, "b", 5);
        let got = admit(&w, std::slice::from_ref(&r), 5, "c", json!({}));
        let want = if ok { (Decision::Allow, None, None) } else { (Decision::Deny, Some("bad_receipt"), Some(0)) };
        assert_eq!((got.decision, got.code, got.at), want, "{}", w["body"]["edges"]);
    }
}

#[test]
fn edge_relations_hold_exactly_at_their_boundaries() {
    // workflow.ts: le <=, ge >=, lt <, gt > of the request param against the output (10)
    for (op, below, equal, above) in [("le", true, true, false), ("ge", false, true, true), ("lt", true, false, false), ("gt", false, false, true)] {
        let w = wf(vec![step("a", &[]), step("b", &["a"])], vec![set(&edge("a", "b"), "/op", json!(op))]);
        let r = first_receipt(&w, "a", 5);
        for (v, want) in [(9, below), (10, equal), (11, above)] {
            let got = admit(&w, std::slice::from_ref(&r), 5, "b", json!({"p": v}));
            let expect = if want { (Decision::Allow, None) } else { (Decision::Deny, Some("edge_relation")) };
            assert_eq!((got.decision, got.code), expect, "{op} {v}");
        }
    }
}
