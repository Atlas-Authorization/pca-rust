//! Intent Layer v2 W-B in the guest (rules 16, 17, 18 and `decideIntentWB`): the guest ports must reproduce the TS
//! reference verdicts exactly.
//! * `primitives.intent_world` / `intent_provenance` / `intent_classifier` of the shared conformance corpus
//!   (packages/pca/conformance/vectors.json): every entry, compared as the corpus README prescribes.
//! * `fixtures/ts_v2_wb.json` (tests/gen_ts_v2_wb.ts, output of the TS reference): extra cases per step of rules 16-18,
//!   boundaries, malformed shapes, and the W-B composition (first failing check ends W-B; a provenance question goes on).
//! No case needs a post-quantum suite: the W-B artifacts are closed member sets without `alg` / `pq_*` members.
use pca_zkvm_core::intent_classifier::decide_classifier_dimensions;
use pca_zkvm_core::oracle_facts::{decide_intent_wb, decide_intent_world, intent_wb_active, intent_wb_context_error};
use pca_zkvm_core::param_provenance::{decide_param_provenance, ProvOutcome};
use pca_zkvm_core::pq_suites::suite_supported;
use serde_json::{json, Value};

/// One `primitives.<name>` block of the corpus (one entry per line; the file also holds 100000-deep cases that exceed
/// serde_json's recursion limit, so only this block is parsed).
fn corpus_block(name: &str) -> Vec<Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conformance/vectors.json");
    let text = std::fs::read_to_string(p).expect("conformance vectors.json");
    let head = format!("\"{name}\": [");
    let mut lines = text.lines().skip_while(|l| l.trim() != head).skip(1);
    let body: Vec<&str> = lines.by_ref().take_while(|l| !l.trim().starts_with(']')).collect();
    assert!(!body.is_empty(), "primitives.{name} block not found");
    serde_json::from_str(&format!("[{}]", body.join("\n"))).unwrap_or_else(|e| panic!("primitives.{name} parses: {e}"))
}

fn fixture() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ts_v2_wb.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("fixtures/ts_v2_wb.json")).expect("ts_v2_wb.json parses")
}

/// The case must fail in the guest with `unsupported_suite`: the fixture marks it (`guest_unsupported`: a LESS
/// artifact, which the TS implements and the guest does not) or the corpus vector `requires_suite` names such a suite.
fn guest_unsupported(c: &Value) -> bool {
    c["guest_unsupported"] == json!(true) || c["requires_suite"].as_str().map_or(false, |a| !suite_supported(Some(a)))
}

/// The reason substring the case demands (`expect.reason_contains`, or `unsupported_suite` for a guest-unsupported case).
fn must_contain(c: &Value) -> Option<String> {
    if guest_unsupported(c) {
        return Some("unsupported_suite".into());
    }
    c["expect"]["reason_contains"].as_str().map(str::to_string)
}

fn reason_ok(c: &Value, reason: &Option<String>) -> bool {
    must_contain(c).map_or(true, |m| reason.as_deref().map_or(false, |r| r.contains(&m)))
}

fn outcome_str(o: ProvOutcome) -> &'static str {
    match o {
        ProvOutcome::Pass => "pass",
        ProvOutcome::Question => "question",
        ProvOutcome::Deny => "deny",
    }
}

/// Rule 16: `ok`, and when ok `world` (as a set of keys) and `single_source` exactly.
fn check_world(c: &Value, bad: &mut Vec<String>) {
    let r = decide_intent_world(&c["input"]);
    let e = &c["expect"];
    let ok = if guest_unsupported(c) {
        !r.ok && reason_ok(c, &r.reason)
    } else {
        r.ok == e["ok"].as_bool().unwrap()
            && (!r.ok || (Value::Object(r.world.clone()) == e["world"] && json!(r.single_source) == e["single_source"]))
            && reason_ok(c, &r.reason)
    };
    if !ok {
        bad.push(format!("{}: guest {:?} differ from TS {}", c["name"], r, e));
    }
}

/// Rule 17: `outcome`, and unless deny `labels`, `classes`, `friction` (question) and, where the fixture has it, `env`.
fn check_prov(c: &Value, bad: &mut Vec<String>) {
    let r = decide_param_provenance(&c["input"]);
    let e = &c["expect"];
    if guest_unsupported(c) {
        if !(r.outcome == ProvOutcome::Deny && reason_ok(c, &r.reason)) {
            bad.push(format!("{}: guest {:?} is not an unsupported_suite deny", c["name"], r));
        }
        return;
    }
    let mut ok = outcome_str(r.outcome) == e["outcome"].as_str().unwrap() && reason_ok(c, &r.reason);
    if ok && r.outcome != ProvOutcome::Deny {
        ok = Value::Object(r.labels.clone()) == e["labels"] && Value::Object(r.classes.clone()) == e["classes"];
        if r.outcome == ProvOutcome::Question || !e["friction"].is_null() {
            ok &= r.friction.as_deref().map(|f| json!(f)).unwrap_or(Value::Null) == e["friction"];
        }
        if let Some(env) = e.get("env") {
            ok &= &r.env == env;
        }
    }
    if !ok {
        bad.push(format!("{}: guest {:?} differ from TS {}", c["name"], r, e));
    }
}

/// Rule 18: `ok`, and when ok `classes` exactly.
fn check_cls(c: &Value, bad: &mut Vec<String>) {
    let r = decide_classifier_dimensions(&c["input"]);
    let e = &c["expect"];
    let ok = if guest_unsupported(c) {
        !r.ok && reason_ok(c, &r.reason)
    } else {
        r.ok == e["ok"].as_bool().unwrap() && (!r.ok || Value::Object(r.classes.clone()) == e["classes"]) && reason_ok(c, &r.reason)
    };
    if !ok {
        bad.push(format!("{}: guest {:?} differ from TS {}", c["name"], r, e));
    }
}

#[test]
fn conformance_intent_world_vectors_match() {
    let cases = corpus_block("intent_world");
    assert!(cases.len() >= 95, "intent_world: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_world(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} intent_world vectors differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn conformance_intent_provenance_vectors_match() {
    let cases = corpus_block("intent_provenance");
    assert!(cases.len() >= 72, "intent_provenance: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_prov(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} intent_provenance vectors differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn conformance_intent_classifier_vectors_match() {
    let cases = corpus_block("intent_classifier");
    assert!(cases.len() >= 41, "intent_classifier: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_cls(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} intent_classifier vectors differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn ts_extra_world_cases_match() {
    let f = fixture();
    let cases = f["world"].as_array().unwrap();
    assert!(cases.len() >= 180, "world: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_world(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} world cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn ts_extra_provenance_cases_match() {
    let f = fixture();
    let cases = f["prov"].as_array().unwrap();
    assert!(cases.len() >= 90, "prov: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_prov(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} prov cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn ts_extra_classifier_cases_match() {
    let f = fixture();
    let cases = f["cls"].as_array().unwrap();
    assert!(cases.len() >= 57, "cls: {} cases", cases.len());
    let mut bad = Vec::new();
    cases.iter().for_each(|c| check_cls(c, &mut bad));
    assert!(bad.is_empty(), "{} of {} cls cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn ts_wb_composition_cases_match() {
    let f = fixture();
    let cases = f["wb"].as_array().unwrap();
    assert!(cases.len() >= 35, "wb: {} cases", cases.len());
    let mut bad = Vec::new();
    for c in cases {
        let r = decide_intent_wb(&c["input"]);
        let e = &c["expect"];
        let checks: Vec<Value> = r.checks.iter().map(|(k, v)| json!([k, v])).collect();
        if guest_unsupported(c) {
            if !(r.outcome == "deny" && reason_ok(c, &r.reason) && r.checks.last().map_or(false, |(_, v)| v == "fail")) {
                bad.push(format!("{}: guest {:?} is not an unsupported_suite deny", c["name"], r));
            }
            continue;
        }
        let ok = json!(r.outcome) == e["outcome"]
            && Value::Array(checks) == e["checks"]
            && Value::Object(r.env.clone()) == e["env"]
            && r.friction.as_deref().map(|f| json!(f)).unwrap_or(Value::Null) == e["friction"];
        if !ok {
            bad.push(format!("{}: guest {:?} differ from TS {}", c["name"], r, e));
        }
    }
    assert!(bad.is_empty(), "{} of {} wb cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// `primitives.intent_wb_active`: the activity rule, through `intent_wb_active` and through `decide_intent_wb` (every
/// reported check is active, and the first active check is reported: W-B starts there and reports pass, question or fail;
/// a malformed W-B context instead reports only `facts` as failed).
#[test]
fn conformance_intent_wb_active_vectors_match() {
    let cases = corpus_block("intent_wb_active");
    assert!(cases.len() >= 24, "intent_wb_active: {} cases", cases.len());
    let mut bad = Vec::new();
    for c in &cases {
        let a = intent_wb_active(&c["input"]);
        let e = &c["expect"];
        let want = [("facts", e["facts"].as_bool().unwrap()), ("provenance", e["provenance"].as_bool().unwrap()), ("classes", e["classes"].as_bool().unwrap())];
        let got = [a.facts, a.provenance, a.classes];
        if want.iter().zip(got).any(|((_, w), g)| *w != g) {
            bad.push(format!("{}: intent_wb_active {:?} differ from TS {}", c["name"], a, e));
        }
        let r = decide_intent_wb(&c["input"]);
        let reported: Vec<&str> = r.checks.iter().map(|(k, _)| k.as_str()).collect();
        let first_active = want.iter().find(|(_, w)| *w).map(|(k, _)| *k);
        // a malformed W-B context fails `facts` before activity is considered (`intentWBContextError`)
        let consistent = if intent_wb_context_error(&c["input"]).is_some() {
            reported == ["facts"] && r.outcome == "deny"
        } else {
            reported.iter().all(|k| want.iter().any(|(n, w)| n == k && *w)) && reported.first().copied() == first_active
        };
        if !consistent {
            bad.push(format!("{}: decide_intent_wb reported {:?}, TS activity {}", c["name"], reported, e));
        }
    }
    assert!(bad.is_empty(), "{} of {} intent_wb_active vectors differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// Totality: hostile shapes never panic.
#[test]
fn hostile_shapes_never_panic() {
    for v in [json!(null), json!(5), json!("x"), json!([]), json!({}), json!({"policy": {"worlds": [{}]}, "committed": {"facts": [1]}}), json!({"intent_session": 5, "policy": 5})] {
        let _ = decide_intent_world(&v);
        let _ = decide_param_provenance(&v);
        let _ = decide_classifier_dimensions(&v);
        let _ = decide_intent_wb(&v);
    }
}
