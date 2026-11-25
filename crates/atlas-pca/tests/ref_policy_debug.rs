//! Differential replay of test-data/ref-policy-debug.json.gz (written by the TypeScript reference): the risk decomposition, the
//! decision explanation, the counterfactual edits and the full audit of a PCActn. A case the reference refuses must be refused here.
mod common;
use atlas_pca::policy_debug::*;
use atlas_pca::serde_json::Value;
use common::replay::{replay, thrown};

/// A number argument: a JSON number, `{"$num": "NaN" | "Infinity" | "-Infinity"}`, and anything else (null included) is NaN
/// (an omitted floor defaults to 0 in the reference, and a non-finite one is read as 0 as well).
fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        _ => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "explainRisk" => explain_risk(&a[0], &a[1], double(&a[2])),
        "explainDecision" => explain_decision(&a[0]).unwrap_or_else(thrown),
        "applyDelta" => apply_delta(&a[0], &a[1]).unwrap_or_else(thrown),
        "counterfactual" => counterfactual(&a[0], a[1].as_array().expect("deltas")).unwrap_or_else(thrown),
        "auditPCActn" => audit_pcactn(&a[0], &a[1], &a[2]).unwrap_or_else(thrown),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn policy_debug_replay() {
    replay("policy-debug", 553, 0, run);
}
