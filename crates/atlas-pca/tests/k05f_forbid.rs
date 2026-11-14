//! F3 forbid: the forbid-wins clause decision, its certificate and the check of a presented certificate, replayed over the shared
//! vectors (forbid-certificate-vectors.json `decide`, prohibition-vectors.json `clauses` and `check`), plus the veto-polarity trigger.
use atlas_pca::forbid::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::agent::*;
use atlas_pca::*;
use std::sync::Arc;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

fn load(name: &str) -> Value {
    strict_parse(&std::fs::read_to_string(format!("{DIR}{name}")).unwrap()).unwrap()
}

fn opts(o: Option<&Value>) -> ClauseOptions {
    let strs = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>());
    match o {
        None => ClauseOptions::default(),
        Some(o) => ClauseOptions { precedence: strs(&o["precedence"]).unwrap_or_default(), permit_signers: strs(&o["permitSigners"]) },
    }
}

#[test]
fn the_decide_vectors_are_reproduced_with_their_certificate_digest() {
    let d = load("forbid-certificate-vectors.json");
    for v in d["decide"].as_array().unwrap() {
        let o = opts(v.get("options"));
        let got = decide_clauses(&v["clauses"], &v["action"], &o).to_json();
        let want = &v["expect"];
        for k in ["decision", "winner", "shadowed", "values"] {
            assert_eq!(got[k], want[k], "{} {k}", v["name"]);
        }
        let cert = certify(&v["clauses"], &v["action"], &o).unwrap();
        assert_eq!(hash_canonical_strict(&cert).as_deref(), want["certificate_digest"].as_str(), "{} digest", v["name"]);
    }
}

#[test]
fn the_clause_list_rules_and_the_decision_they_force_are_reproduced() {
    for v in load("prohibition-vectors.json")["clauses"].as_array().unwrap() {
        let want = &v["expect"];
        let err = clauses_error(&v["clauses"]);
        assert_eq!(err.as_deref(), want["error"].as_str(), "{} error", v["name"]);
        let got = decide_clauses(&v["clauses"], &v["action"], &ClauseOptions::default()).to_json();
        for k in ["decision", "winner", "shadowed", "values"] {
            assert_eq!(got[k], want[k], "{} {k}", v["name"]);
        }
    }
}

#[test]
fn the_certificate_check_reasons_are_reproduced() {
    for v in load("prohibition-vectors.json")["check"].as_array().unwrap() {
        let r = check_forbid_certificate(&v["certificate"], &v["clauses"], &v["action"], &opts(v.get("options")));
        let want = &v["expect"];
        match (want["ok"].as_bool().unwrap(), r) {
            (true, Ok(())) => {}
            (false, Err(why)) => assert_eq!(Some(why.as_str()), want["reason"].as_str(), "{}", v["name"]),
            (w, r) => panic!("{}: expected ok={w}, got {r:?}", v["name"]),
        }
    }
}

#[test]
fn a_trigger_that_cannot_be_decided_vetoes_and_a_malformed_one_always_matches() {
    let ctx = json!({"action": {"verb": "pay.send", "resource": "/acct/1", "params": {"amount": 10}}});
    assert!(when_matches(&json!({"verb": "pay.send"}), &ctx));
    assert!(!when_matches(&json!({"verb": "other"}), &ctx));
    assert!(!when_matches(&json!({"verb": "pay.send", "resource": "/blocked/*"}), &ctx));
    // a missing field cannot be decided: the veto applies; a provably false condition does not
    assert!(when_matches(&json!({"verb": "pay.send", "where": [{"field": "action.params.nope", "op": "gt", "value": 1}]}), &ctx));
    assert!(!when_matches(&json!({"verb": "pay.send", "where": [{"field": "action.params.amount", "op": "gt", "value": 100}]}), &ctx));
    // malformed triggers and contexts match
    for bad in [json!(null), json!({}), json!({"verb": ""}), json!({"verb": "pay.send", "resource": 3}), json!({"verb": "pay.send", "where": "x"}),
        json!({"verb": "pay.send", "where": [{"field": "a", "op": "bogus"}]}), json!({"verb": "pay.send", "resource": "re:(a|(b))*"})] {
        assert!(when_matches(&bad, &ctx), "{bad}");
    }
    assert!(when_matches(&json!({"verb": "pay.send"}), &json!({})), "a context without an action");
    assert_eq!(validate_when(&json!({"verb": "v", "where": [{"field": "a", "op": "bogus"}]}), "when").as_deref(), Some("when: unknown condition op bogus"));
    assert_eq!(validate_when(&json!({"verb": "v", "where": [{"field": "a"}]}), "when").as_deref(), Some("when: unknown condition op undefined"));
    assert_eq!(validate_when(&json!({"verb": ["a", ""]}), "when").as_deref(), Some("when: bad verb"));
    assert_eq!(validate_when(&json!({"verb": "v", "resource": "re:(a|(b))*"}), "when").as_deref(), Some("when: unsafe regex resource"));
}

// ---- the `forbid` gate of authorize

fn gate(clauses: Value, require_certificate: bool) -> ForbidGate {
    ForbidGate { clauses: Arc::new(move |_, _| clauses.clone()), context: None, options: ClauseOptions::default(), require_certificate }
}

struct Call {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn call() -> Call {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), "rs-forbid", 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Default::default(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    Call { grant, pcactn: a.pcactn, op }
}

fn run(c: &Call, store: &MemoryStateStore, g: &ForbidGate, cert: Option<&Value>) -> AuthorizeResult {
    let gr = c.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(gr.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let pins = vec![arg_provenance::ProvenanceRecorder::new("conformance-harness", "k1", Some([1u8; 32])).unwrap().pin()];
    let bundle = |op: &Operation| arg_provenance::principal_direct_provenance(&mut arg_provenance::ProvenanceRecorder::new("conformance-harness", "k1", Some([1u8; 32])).unwrap(), op).map(Some);
    let input = AuthorizeInput {
        risk: Some(&insecure_calm_risk as &RiskFn),
        forbid: Some(g),
        forbid_certificate: cert,
        operation: Some(&c.op),
        audience: "rs-forbid",
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&not_revoked),
        now: c.pcactn["iat"].as_i64(),
        plan: Some("single-step"),
        provenance_mediators: &pins,
        provenance_bundle: Some(&bundle),
        ..Default::default()
    };
    authorize(Some(&c.pcactn), &input)
}

fn clause(id: &str, kind: &str, verb: &str) -> Value {
    json!({"id": id, "kind": kind, "signer": "org", "when": {"verb": verb}})
}

#[test]
fn the_forbid_gate_refuses_a_matching_veto_before_the_counter_is_spent() {
    let c = call();
    let stream = format!("{}:{}", c.grant["id"].as_str().unwrap(), c.pcactn["cap_chain"][0]["holder"].as_str().unwrap());
    let store = MemoryStateStore::new();
    let r = run(&c, &store, &gate(json!([clause("p", "permit", "refund"), clause("f-refunds", "forbid", "refund")]), false), None);
    assert!(!r.allow && r.status == 403);
    assert!(r.reasons.iter().any(|x| x == "forbid: deny by forbid f-refunds"), "{:?}", r.reasons);
    let r = run(&c, &store, &gate(json!([clause("p", "permit", "other")]), false), None);
    assert!(r.reasons.iter().any(|x| x == "forbid: deny by none"), "{:?}", r.reasons);
    let r = run(&c, &store, &gate(json!([clause("p", "permit", "refund"), clause("e1", "escalate", "refund")]), false), None);
    assert!(r.reasons.iter().any(|x| x == "forbid: escalate by escalate e1"), "{:?}", r.reasons);
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
}

#[test]
fn a_required_certificate_is_recomputed_never_trusted() {
    let c = call();
    let clauses = json!([clause("p", "permit", "refund"), clause("f-other", "forbid", "delete")]);
    let g = gate(clauses.clone(), true);
    let r = run(&c, &MemoryStateStore::new(), &g, None);
    assert!(r.reasons.iter().any(|x| x == "forbid: the call carries no certificate (fail closed)"), "{:?}", r.reasons);
    let ctx = json!({"action": {"verb": "refund", "resource": "orders/1", "params": c.op.params}});
    let cert = certify(&clauses, &ctx, &ClauseOptions::default()).unwrap();
    let r = run(&c, &MemoryStateStore::new(), &g, Some(&cert));
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(r.forbid.as_ref(), Some(&cert), "the allow carries the recomputed certificate");
    // a gate that does not require a certificate still returns the one it computed; a refusal carries none
    let r = run(&c, &MemoryStateStore::new(), &gate(clauses.clone(), false), None);
    assert_eq!(r.forbid.as_ref(), Some(&cert));
    let r = run(&c, &MemoryStateStore::new(), &gate(json!([clause("f", "forbid", "refund")]), false), None);
    assert!(!r.allow && r.forbid.is_none());
    // a certificate for another policy is refused with the reference's reason
    let other = certify(&json!([clause("p", "permit", "refund")]), &ctx, &ClauseOptions::default()).unwrap();
    let r = run(&c, &MemoryStateStore::new(), &g, Some(&other));
    assert!(r.reasons.iter().any(|x| x == "forbid: certificate refused (certificate does not match the recomputed decision)"), "{:?}", r.reasons);
}

#[test]
fn the_options_builder_carries_the_gate_and_the_presented_certificate() {
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let cert = json!({"v": 1});
    let _opts = AuthorizeOptions::new(store, |_, _| Ok(false)).with_forbid(gate(json!([]), true)).with_forbid_certificate(cert);
}

fn nested_not(n: usize) -> Value {
    let mut c = json!({"field": "a", "op": "eq", "value": 1});
    for _ in 0..n {
        c = json!({"not": c});
    }
    c
}

fn where_err(c: Value) -> Option<String> {
    validate_when(&json!({"verb": "v", "where": [c]}), "w")
}

#[test]
fn condition_depth_boundary_and_combinator_shapes_are_exact() {
    assert_eq!(where_err(nested_not(32)), None);
    assert_eq!(where_err(nested_not(33)).as_deref(), Some("w: condition nesting too deep"));
    let mut c = json!({"field": "a", "op": "eq", "value": 1});
    for i in 0..33 {
        c = if i % 2 == 0 { json!({"all_of": [c]}) } else { json!({"any_of": [c]}) };
    }
    assert_eq!(where_err(c).as_deref(), Some("w: condition nesting too deep"));
    let leaf = json!({"field": "a", "op": "eq", "value": 1});
    for c in [json!({"all_of": [leaf.clone()]}), json!({"any_of": [leaf.clone()]}), json!({"not": leaf.clone()})] {
        assert_eq!(where_err(c.clone()), None, "{c}");
    }
    assert_eq!(where_err(json!({"all_of": []})).as_deref(), Some("w: condition.all_of must be a non-empty array"));
    assert_eq!(where_err(json!({"any_of": []})).as_deref(), Some("w: condition.any_of must be a non-empty array"));
    assert_eq!(where_err(json!({"all_of": "x"})).as_deref(), Some("w: condition.all_of must be a non-empty array"));
    assert_eq!(where_err(json!({"all_of": [leaf.clone(), {"field": "a"}]})).as_deref(), Some("w: unknown condition op undefined"));
    // ref and collection checks
    assert_eq!(where_err(json!({"field": "a", "op": "eq", "ref": "x"})), None);
    assert_eq!(where_err(json!({"field": "a", "op": "eq", "ref": ""})).as_deref(), Some("w: bad condition.ref"));
    assert_eq!(where_err(json!({"field": "a", "op": "eq", "ref": 5})).as_deref(), Some("w: bad condition.ref"));
    assert_eq!(where_err(json!({"field": "a", "op": "eq", "collection": ""})), None);
    assert_eq!(where_err(json!({"field": "a", "op": "member_of", "collection": ""})).as_deref(), Some("w: bad condition.collection"));
    assert_eq!(where_err(json!({"field": "a", "op": "member_of", "collection": "c"})), None);
}

#[test]
fn verb_shapes_and_regex_resource_length_boundary_are_exact() {
    assert_eq!(validate_when(&json!({"verb": ["a", "b"]}), "w"), None);
    assert_eq!(validate_when(&json!({"verb": []}), "w").as_deref(), Some("w: bad verb"));
    assert_eq!(validate_when(&json!({"verb": ["a", ""]}), "w").as_deref(), Some("w: bad verb"));
    assert_eq!(validate_when(&json!({"verb": ["a", 1]}), "w").as_deref(), Some("w: bad verb"));
    assert_eq!(validate_when(&json!({"verb": "v", "resource": format!("re:{}", "a".repeat(200))}), "w"), None);
    assert_eq!(validate_when(&json!({"verb": "v", "resource": format!("re:{}", "a".repeat(201))}), "w").as_deref(), Some("w: unsafe regex resource"));
    // a subject over the regex length cap cannot be decided: the veto applies; at the cap it is decided (no match)
    let ctx = |n: usize| json!({"action": {"verb": "v", "resource": "a".repeat(n)}});
    let re = json!({"verb": "v", "resource": "re:b"});
    assert!(!when_matches(&re, &ctx(512)));
    assert!(when_matches(&re, &ctx(513)));
    // a non-regex resource is never "oversized"
    assert!(!when_matches(&json!({"verb": "v", "resource": "exact"}), &ctx(513)));
}

#[test]
fn the_context_callback_feeds_the_clause_conditions() {
    let c = call();
    let clauses = json!([
        clause("p", "permit", "refund"),
        {"id": "f-intern", "kind": "forbid", "signer": "org", "when": {"verb": "refund", "where": [{"field": "subject.role", "op": "eq", "value": "intern"}]}}
    ]);
    let with_role = |role: &'static str| {
        let cl = clauses.clone();
        ForbidGate {
            clauses: Arc::new(move |_, _| cl.clone()),
            context: Some(Arc::new(move |_: &Operation| json!({"subject": {"role": role}}))),
            options: ClauseOptions::default(),
            require_certificate: false,
        }
    };
    // a decided false condition lets the permit stand
    let r = run(&c, &MemoryStateStore::new(), &with_role("admin"), None);
    assert!(r.allow, "{:?}", r.reasons);
    // a decided true condition vetoes
    let r = run(&c, &MemoryStateStore::new(), &with_role("intern"), None);
    assert!(r.reasons.iter().any(|x| x == "forbid: deny by forbid f-intern"), "{:?}", r.reasons);
    // without the context the field cannot be decided: the veto applies
    let r = run(&c, &MemoryStateStore::new(), &gate(clauses.clone(), false), None);
    assert!(r.reasons.iter().any(|x| x == "forbid: deny by forbid f-intern"), "{:?}", r.reasons);
}
