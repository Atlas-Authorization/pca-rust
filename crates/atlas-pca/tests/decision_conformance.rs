//! Shared vectors for rules 20, 21 and the ternary decision: packages/pca/conformance/decision-vectors.json.
use atlas_pca::serde_json::Value;
use atlas_pca::{
    build_escalation_request, decide_tighten, decide_units, decision_of, escalation_reasons_wire, fold_v2_reasons, meet,
    pep_decision, tighten,
    V2CheckResult,
};

/// `input_text` is raw JSON text each runner parses itself: key order is part of the input (the crate keeps insertion order).
fn input_of(e: &Value) -> Value {
    match e["input_text"].as_str() {
        Some(t) => atlas_pca::serde_json::from_str(t).unwrap(),
        None => e["input"].clone(),
    }
}

fn table(name: &str) -> Vec<Value> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/decision-vectors.json"
    );
    let v: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["primitives"][name].as_array().unwrap().clone()
}

#[test]
fn units_vectors() {
    for e in table("intent_units") {
        let got = decide_units(&input_of(&e));
        let x = &e["expect"];
        assert_eq!(
            got.is_ok(),
            x["ok"].as_bool().unwrap(),
            "{}: {:?}",
            e["name"],
            got
        );
        // the reason is part of the contract, byte for byte
        if let Some(want) = x["reason"].as_str() {
            assert_eq!(got.unwrap_err(), want, "{}", e["name"]);
        }
    }
}

#[test]
fn tighten_vectors() {
    for e in table("intent_tighten") {
        let r = decide_tighten(&input_of(&e));
        let x = &e["expect"];
        assert_eq!(r.outcome, x["outcome"].as_str().unwrap(), "{}", e["name"]);
        assert_eq!(r.legacy, x["legacy"].as_bool().unwrap(), "{}", e["name"]);
        let want: Vec<&str> = x["offending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(r.offending, want, "{}", e["name"]);
        assert_eq!(r.reason.as_deref(), x["reason"].as_str(), "{}", e["name"]);
    }
}

/// The ordered reason list and the decision of a verdict whose intent-v2 pipeline reported several failing checks.
#[test]
fn escalation_fold_vectors() {
    for e in table("escalation_fold") {
        let i = &e["input"];
        let base: Vec<String> = i["core_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        let v2: Vec<V2CheckResult> = i["v2"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| V2CheckResult {
                name: c["name"].as_str().unwrap().to_string(),
                ok: c["ok"].as_bool().unwrap(),
                reason: c["reason"].as_str().map(String::from),
            })
            .collect();
        let got = fold_v2_reasons(&base, &v2);
        let want: Vec<String> = e["expect"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want, "{}", e["name"]);
        let allow = !i["checks"]
            .as_object()
            .unwrap()
            .values()
            .any(|s| s == "fail");
        let verdict =
            atlas_pca::serde_json::json!({"allow": allow, "checks": i["checks"], "reasons": got});
        assert_eq!(
            decision_of(&verdict),
            e["expect"]["decision"].as_str().unwrap(),
            "{}",
            e["name"]
        );
    }
}

#[test]
fn decision_of_vectors() {
    for e in table("decision_of") {
        assert_eq!(
            decision_of(&e["input"]),
            e["expect"]["decision"].as_str().unwrap(),
            "{}",
            e["name"]
        );
    }
}

#[test]
fn lattice_vectors() {
    for e in table("decision_lattice") {
        let n = e["name"].as_str().unwrap();
        let i = &e["input"];
        let got = if n.starts_with("meet-") {
            meet(i["a"].as_str().unwrap(), i["b"].as_str().unwrap())
        } else if n.starts_with("pep-") {
            pep_decision(
                i["decision"].as_str().unwrap(),
                i["answered"].as_bool() == Some(true),
            )
        } else {
            tighten(i["decision"].as_str().unwrap(), &i["signal"])
        };
        assert_eq!(got, e["expect"]["decision"].as_str().unwrap(), "{n}");
    }
}

/// Request reasons are cut at 512 UTF-16 units like `String(r).slice(0, 512)`; a cut inside a surrogate pair keeps the lone
/// high surrogate, which the wire text writes as `\udXXXX`.
#[test]
fn escalation_truncate_vectors() {
    for e in table("escalation_truncate") {
        let reasons: Vec<String> = e["input"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        let req = build_escalation_request(
            "a",
            &atlas_pca::serde_json::json!({"id": "g"}),
            &atlas_pca::serde_json::json!({"action": {"verb": "v", "resource": "r"}}),
            None,
            &reasons,
            1,
            None,
        )
        .unwrap();
        assert_eq!(
            escalation_reasons_wire(&req),
            e["expect"]["wire"].as_str().unwrap(),
            "{}",
            e["name"]
        );
    }
}
