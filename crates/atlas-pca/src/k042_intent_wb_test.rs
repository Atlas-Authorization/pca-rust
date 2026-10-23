//! 0.4.2 mutation kills for intent_wb.rs (rules 16-18 and the W-B unit): differential tests against the TS reference
//! (oracleprov: oracle-facts.ts / offer-set.ts / label-receipts.ts / param-provenance.ts; mapartcls: the classifier cases;
//! wbmisc: decideIntentWB). The corpora are written by tools/pca-audit/java-mutate/k042-{oracleprov,mapartcls,wbmisc}-oracle.mjs
//! and the Java suite runs the same files. Decisions, outcomes, checks, env members, friction and every list are compared
//! exactly; a validator this crate keeps as a boolean is compared by verdict (null <=> true). A refusal reason TEXT is the
//! reference's, character for character (same_text). A case with a lone surrogate
//! (not representable in serde_json) is skipped.
use super::*;
use crate::k042_support::{corpus_cases, doc_cases, has_lone, same_text};
use serde_json::json;

fn report(bad: Vec<String>) {
    assert!(bad.is_empty(), "{} divergent case(s):\n{}", bad.len(), bad.iter().take(400).cloned().collect::<Vec<_>>().join("\n"));
}

fn skip(c: &Value) -> bool {
    has_lone(c)
}

fn opt(s: Option<String>) -> Option<String> {
    s
}

// ---- mapartcls: the classifier (rule 18) ----------------------------------------------------------------------------

#[test]
fn classifier_verdict_wire_and_policy() {
    let mut bad = Vec::new();
    for c in corpus_cases("k042-mapartcls.json.gz", "verdictwire") {
        if skip(&c) {
            continue;
        }
        let ok = validate_verdict_wire(&c["args"][0]);
        if ok != c["out"].is_null() {
            bad.push(format!("{}: want {} got valid={ok}", c["name"], c["out"]));
        }
    }
    for (i, c) in corpus_cases("k042-mapartcls.json.gz", "policy").iter().enumerate() {
        if skip(c) {
            continue;
        }
        let got = opt(validate_classifier_policy(&c["args"][0]));
        if !same_text(&format!("{}#{i}", c["name"]), c["out"].as_str(), got.as_deref()) {
            bad.push(format!("{}\n  want: {}\n  got:  {got:?}", c["name"], c["out"]));
        }
    }
    report(bad);
}

#[test]
fn classifier_decisions() {
    let mut bad = Vec::new();
    for (i, c) in corpus_cases("k042-mapartcls.json.gz", "classify").iter().enumerate() {
        if skip(c) {
            continue;
        }
        let r = decide_classifier_dimensions(&c["args"][0]);
        let o = &c["out"];
        let ok = o["ok"] == Value::Bool(true);
        let classes_ok = !ok || o["classes"] == Value::Object(r.classes.clone());
        let reason_ok = if ok { r.reason.is_empty() } else { same_text(&format!("{}#{i}", c["name"]), o["reason"].as_str(), Some(&r.reason)) };
        if r.ok != ok || !classes_ok || !reason_ok {
            bad.push(format!("{}\n  want: {o}\n  got:  ok={} {:?} {}", c["name"], r.ok, r.classes, r.reason));
        }
    }
    report(bad);
}

// ---- oracleprov: rules 16 and 17 -------------------------------------------------------------------------------------

/// The reason (or verdict) a validator gives for `arg`: boolean validators give "invalid" for a refusal.
fn validator(name: &str, arg: &Value) -> Option<String> {
    let flag = |ok: bool| if ok { None } else { Some("invalid".to_string()) };
    match name {
        "validateFactWire" => flag(validate_fact_wire(arg)),
        "validateWorldPolicy" => validate_world_policy(arg),
        "validateOfferPolicy" => validate_offer_policy(arg),
        "validateOfferSetWire" => validate_offer_set_wire(arg),
        "validateLabelsWire" => flag(validate_labels_wire(arg)),
        "validateFlowRules" => validate_flow_rules(arg),
        "validateProvenancePolicy" => validate_provenance_policy(arg),
        "validateProvWire" => validate_prov_wire(arg),
        other => panic!("unknown validator {other}"),
    }
}

#[test]
fn oracleprov_reference() {
    let cases = doc_cases("k042-oracleprov.json.gz");
    assert!(cases.len() > 1900, "only {} cases", cases.len());
    let mut bad = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        if skip(c) {
            continue;
        }
        let key = format!("{}#{i}", c["name"].as_str().unwrap());
        let (mut got, mut want): (Value, Value) = (Value::Null, Value::Null);
        let mut reasons: Option<(Option<String>, Option<String>)> = None;
        match c["kind"].as_str().unwrap() {
            "fn" => {
                let f = c["fn"].as_str().unwrap();
                let g = validator(f, &c["arg"]);
                let w = if matches!(f, "validateFactWire" | "validateLabelsWire") { c["want"].as_str().map(|_| "invalid".to_string()) } else { c["want"].as_str().map(String::from) };
                if matches!(f, "validateFactWire" | "validateLabelsWire") {
                    (got, want) = (json!(g.is_some()), json!(w.is_some()));
                } else {
                    (got, want) = (json!(g.is_some()), json!(w.is_some()));
                    reasons = Some((w, g));
                }
            }
            "ratio" => (got, want) = (ratio_ppm(c["a"].as_i64().unwrap(), c["b"].as_i64().unwrap()).map_or(Value::Null, |n| json!(n)), c["want"].clone()),
            "flowRule" => (got, want) = (flow_rule_for(c["rules"].as_object().unwrap(), c["cls"].as_str().unwrap()).map_or(Value::Null, |r| json!(r)), c["want"].clone()),
            "flowAllowed" => {
                (got, want) = (
                    json!(flow_allowed(c["rules"].as_object().unwrap(), c["cls"].as_str().unwrap(), c["origin"].as_str().unwrap(), c["aud"].as_str().unwrap())),
                    c["want"].clone(),
                )
            }
            "active" => {
                let (cm, pol) = (&c["committed"], &c["policy"]);
                (got, want) = (json!(intent_world_active(cm.get("facts"), cm.get("offer_set"), Some(pol))), c["expect"].clone());
            }
            "read" => {
                let r = decide_read_purpose(&c["input"]);
                let e = &c["expect"];
                (got, want) = (json!({"outcome": r.outcome, "minimise": r.minimise, "uncovered": r.uncovered}), json!({"outcome": e["outcome"], "minimise": e["minimise"], "uncovered": e["uncovered"]}));
            }
            "world" => {
                let r = decide_intent_world(&c["input"]);
                let e = &c["expect"];
                if e["ok"] == Value::Bool(true) {
                    (got, want) = (json!({"ok": r.ok, "world": r.world, "single_source": r.single_source}), json!({"ok": true, "world": e["world"], "single_source": e["single_source"]}));
                } else {
                    (got, want) = (json!({"ok": r.ok}), json!({"ok": false}));
                    reasons = Some((e["reason"].as_str().map(String::from), Some(r.reason)));
                }
            }
            "prov" => {
                let r = decide_param_provenance(&c["input"]);
                let e = &c["expect"];
                (got, want) = (
                    json!({"outcome": r.outcome, "friction": r.friction, "labels": r.labels, "classes": r.classes, "env": r.env, "has_reason": !r.reason.is_empty()}),
                    json!({"outcome": e["outcome"], "friction": e["friction"], "labels": e["labels"], "classes": e["classes"], "env": e["env"], "has_reason": !e["reason"].is_null()}),
                );
                reasons = Some((e["reason"].as_str().map(String::from), (!r.reason.is_empty()).then_some(r.reason)));
            }
            k => panic!("unknown kind {k}"),
        }
        let reason_ok = match &reasons {
            Some((w, g)) => same_text(&key, w.as_deref(), g.as_deref()),
            None => true,
        };
        if got != want || !reason_ok {
            bad.push(format!("{key}\n    got  {got} {:?}\n    want {want}", reasons.as_ref().map(|r| &r.1)));
        }
    }
    report(bad);
}

// ---- wbmisc: decideIntentWB -----------------------------------------------------------------------------------------

#[test]
fn decide_intent_wb_reference() {
    let cases = doc_cases("k042-wbmisc.json.gz");
    assert_eq!(cases.len(), 942);
    let mut bad = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        if skip(c) {
            continue;
        }
        let r = decide_intent_wb(&c["input"]);
        let checks: Vec<Value> = r.checks.iter().map(|(n, v)| json!([n, match v { WbCheck::Pass => "pass", WbCheck::Question => "question", WbCheck::Fail => "fail" }])).collect();
        let got = json!({
            "outcome": r.outcome,
            "checks": checks,
            "friction": r.friction,
            "world": r.env.get("world"),
            "prov": r.env.get("prov"),
            "class": r.env.get("class"),
            "single_source": (!r.single_source.is_empty()).then(|| r.single_source.clone()),
        });
        let e = &c["expect"];
        let want = json!({
            "outcome": e["outcome"], "checks": e["checks"], "friction": e["friction"],
            "world": e["world"], "prov": e["prov"], "class": e["class"],
            "single_source": if e["single_source"].as_array().is_some_and(|a| a.is_empty()) { Value::Null } else { e["single_source"].clone() },
        });
        let got_reason = (!r.reason.is_empty()).then_some(r.reason.clone());
        let reason_ok = same_text(&format!("{}#{i}", c["name"]), e["reason"].as_str(), got_reason.as_deref());
        if got != want || !reason_ok {
            bad.push(format!("{}\n   want {want} {}\n   got  {got} {got_reason:?}", c["name"], e["reason"]));
        }
    }
    report(bad);
}

// ---- boundary tests of the W-B wire validators ------------------------------------------------------------------------

const D: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn fact() -> Value {
    json!({"v": 1, "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": 5, "t_obs": 7, "oracle": "o1", "sig": "AAAA"})
}

fn with(mut v: Value, k: &str, x: Value) -> Value {
    v[k] = x;
    v
}

#[test]
fn fact_wire_boundaries() {
    assert!(validate_fact_wire(&fact()));
    assert!(!validate_fact_wire(&json!([])));
    assert!(!validate_fact_wire(&json!(null)));
    // each member alone
    assert!(!validate_fact_wire(&with(fact(), "v", json!(2))));
    assert!(!validate_fact_wire(&with(fact(), "kind", json!("x"))));
    assert!(!validate_fact_wire(&with(fact(), "name", json!("Fare"))));
    assert!(!validate_fact_wire(&with(fact(), "subject", json!(""))));
    assert!(validate_fact_wire(&with(fact(), "subject", json!("s".repeat(256)))));
    assert!(!validate_fact_wire(&with(fact(), "subject", json!("s".repeat(257)))));
    assert!(validate_fact_wire(&with(fact(), "value", json!("v"))));
    assert!(validate_fact_wire(&with(fact(), "value", json!("v".repeat(256)))));
    assert!(!validate_fact_wire(&with(fact(), "value", json!("v".repeat(257)))));
    assert!(!validate_fact_wire(&with(fact(), "value", json!(""))));
    assert!(!validate_fact_wire(&with(fact(), "value", json!(1.5))));
    assert!(!validate_fact_wire(&with(fact(), "value", json!(null))));
    assert!(validate_fact_wire(&with(fact(), "value", json!(-3))));
    assert!(validate_fact_wire(&with(fact(), "t_obs", json!(0))));
    assert!(!validate_fact_wire(&with(fact(), "t_obs", json!(-1))));
    assert!(!validate_fact_wire(&with(fact(), "oracle", json!(""))));
    assert!(validate_fact_wire(&with(fact(), "oracle", json!("o".repeat(64)))));
    assert!(!validate_fact_wire(&with(fact(), "oracle", json!("o".repeat(65)))));
    assert!(!validate_fact_wire(&with(fact(), "sig", json!(5))));
    // closed set: unknown member refused, a missing one refused, the suite members allowed
    assert!(!validate_fact_wire(&with(fact(), "zz", json!(1))));
    let mut m = fact();
    m.as_object_mut().unwrap().remove("sig");
    assert!(!validate_fact_wire(&m));
    assert!(validate_fact_wire(&with(with(fact(), "alg", json!("ml-dsa-65")), "pq_pk", json!("k"))));
}

fn verdict() -> Value {
    json!({"v": 1, "kind": "pca-intent-classification", "classifier": "tone", "session": D, "content_digest": D, "label": "calm", "measurement": "m-1", "judge": D, "sig": "AAAA"})
}

#[test]
fn verdict_wire_boundaries() {
    assert!(validate_verdict_wire(&verdict()));
    assert!(!validate_verdict_wire(&json!(1)));
    for (k, bad) in [
        ("v", json!(2)),
        ("kind", json!("x")),
        ("classifier", json!("Tone")),
        ("session", json!("x")),
        ("content_digest", json!("x")),
        ("label", json!("")),
        ("measurement", json!("")),
        ("judge", json!("x")),
        ("sig", json!(5)),
    ] {
        assert!(!validate_verdict_wire(&with(verdict(), k, bad.clone())), "{k}={bad}");
    }
    assert!(validate_verdict_wire(&with(verdict(), "label", json!("l".repeat(64)))));
    assert!(!validate_verdict_wire(&with(verdict(), "label", json!("l".repeat(65)))));
    assert!(validate_verdict_wire(&with(verdict(), "measurement", json!("m".repeat(256)))));
    assert!(!validate_verdict_wire(&with(verdict(), "measurement", json!("m".repeat(257)))));
    assert!(!validate_verdict_wire(&with(verdict(), "zz", json!(1))));
    let mut m = verdict();
    m.as_object_mut().unwrap().remove("measurement");
    assert!(!validate_verdict_wire(&m));
}

fn clf() -> Value {
    json!({"id": "tone", "param": "action.params.text", "labels": ["calm", "angry"], "keys": [D, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"], "k": 2})
}

fn pol(c: Value) -> Value {
    json!({"classifiers": [c]})
}

#[test]
fn classifier_policy_boundaries() {
    assert_eq!(validate_classifier_policy(&pol(clf())), None);
    assert!(validate_classifier_policy(&json!({"classifiers": []})).is_none());
    // k in [1, |keys|]
    assert_eq!(validate_classifier_policy(&pol(with(clf(), "k", json!(1)))), None);
    assert!(validate_classifier_policy(&pol(with(clf(), "k", json!(0)))).unwrap().contains("k must be an integer in [1, 2]"));
    assert!(validate_classifier_policy(&pol(with(clf(), "k", json!(3)))).unwrap().contains("k must be an integer in [1, 2]"));
    assert!(validate_classifier_policy(&pol(with(clf(), "k", json!("2")))).is_some());
    // labels: 1..MAX distinct non-empty strings of at most 64 bytes
    assert!(validate_classifier_policy(&pol(with(clf(), "labels", json!([])))).unwrap().contains("labels must hold"));
    assert!(validate_classifier_policy(&pol(with(clf(), "labels", json!(["a", "a"])))).unwrap().contains("distinct"));
    assert!(validate_classifier_policy(&pol(with(clf(), "labels", json!(["", "b"])))).unwrap().contains("distinct"));
    assert!(validate_classifier_policy(&pol(with(clf(), "labels", json!(["l".repeat(65), "b"])))).unwrap().contains("distinct"));
    assert_eq!(validate_classifier_policy(&pol(with(clf(), "labels", json!(["l".repeat(64), "b"])))), None);
    assert!(validate_classifier_policy(&pol(with(clf(), "labels", json!([1, 2])))).is_some());
    // keys: non-empty, 32-byte, distinct
    assert!(validate_classifier_policy(&pol(with(clf(), "keys", json!([])))).unwrap().contains("keys must be"));
    assert!(validate_classifier_policy(&pol(with(clf(), "keys", json!([D, D])))).unwrap().contains("keys must be"));
    assert!(validate_classifier_policy(&pol(with(clf(), "keys", json!([D, "x"])))).unwrap().contains("keys must be"));
    // param, id
    assert!(validate_classifier_policy(&pol(with(clf(), "param", json!("params.x")))).unwrap().contains("param must be"));
    assert!(validate_classifier_policy(&pol(with(clf(), "id", json!("Tone")))).unwrap().contains("unique id"));
    assert!(validate_classifier_policy(&json!({"classifiers": [clf(), clf()]})).unwrap().contains("unique id"));
    // measurements: a list of strings
    assert_eq!(validate_classifier_policy(&pol(with(clf(), "measurements", json!(["m"])))), None);
    assert_eq!(validate_classifier_policy(&pol(with(clf(), "measurements", json!([])))), None);
    assert!(validate_classifier_policy(&pol(with(clf(), "measurements", json!([1])))).unwrap().contains("measurements"));
    assert!(validate_classifier_policy(&pol(with(clf(), "measurements", json!("m")))).unwrap().contains("measurements"));
    // pq_keys: allowlisted key -> non-empty PQ key
    assert_eq!(validate_classifier_policy(&pol(with(clf(), "pq_keys", json!({ D: "pk" })))), None);
    assert!(validate_classifier_policy(&pol(with(clf(), "pq_keys", json!({ D: "" })))).unwrap().contains("pq_keys"));
    assert!(validate_classifier_policy(&pol(with(clf(), "pq_keys", json!({ "zz": "pk" })))).unwrap().contains("pq_keys"));
    assert!(validate_classifier_policy(&pol(with(clf(), "pq_keys", json!([])))).unwrap().contains("pq_keys"));
    // closed policy
    assert!(validate_classifier_policy(&json!({"classifiers": [clf()], "x": 1})).is_some());
}
