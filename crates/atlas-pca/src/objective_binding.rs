//! `resolveObjectiveRisk`: the binding of the objective-risk functional to the live decision path, without touching the signed PCActn. The facts
//! live in the grant's signed envelope (`objective_risk`, see [`crate::core_small::read_objective_commitment`]); the registry, the resource graph
//! and the calibration set are instance-held configuration whose digests must equal the committed ones.

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Value};

use crate::core_small::read_objective_commitment;
use crate::objective_risk::{calibration_digest, native_hash_embedder, objective_risk, Embedder, InMemoryInverseRegistry, ObjectiveRiskContext, ResourceGraph};

fn mismatch(reasons: Vec<String>, on_mismatch: &str) -> Value {
    json!({"mode": "mismatch", "reasons": reasons, "onMismatch": on_mismatch})
}

/// The objective risk inputs for `action` under `grant`. Total (never panics, never throws).
///  - nothing committed: `{mode: "none"}` (the heuristic, unchanged)
///  - committed and reproduced: `{mode: "objective", inputs: {reversibility, blastRadius, semanticDistance}, r, evidenceDigest}`
///  - committed but not reproducible or invalid: `{mode: "mismatch", reasons, onMismatch: "deny" | "heuristic"}` (default `deny`)
///
/// `instance` is the instance-held config `{registry?: {trusted_verifiers?, entries?: [{verb, inverse_kind, fidelity, verification?:
/// {verifier_id, evidence_digest}}]}, graph?: {nodes?, edges?}, calibration?: number[], allow_heuristic_fallback?}`; `taint` and `age` are
/// verifier-supplied (they only feed `r`; default 1). A grant cannot downgrade the verifier's objective risk to the heuristic on its own say-so:
/// `on_mismatch: "heuristic"` counts only when the instance sets `allow_heuristic_fallback`.
pub fn resolve_objective_risk(grant: &Value, action: &Value, instance: Option<&Value>, taint: Option<f64>, age: Option<f64>) -> Value {
    let read = read_objective_commitment(grant);
    if let Some(m) = read.get("malformed").and_then(Value::as_str) {
        return mismatch(vec![m.to_string()], "deny");
    }
    let Some(c) = read.get("commitment") else { return json!({"mode": "none"}) };
    let requested = c.get("on_mismatch").and_then(Value::as_str).unwrap_or("deny");
    let on_mismatch = if requested == "heuristic" && instance.and_then(|i| i.get("allow_heuristic_fallback")) == Some(&Value::Bool(true)) { "heuristic" } else { "deny" };
    let run = || -> Result<Value, Vec<String>> {
        let env = crate::read_envelope(grant).ok_or_else(|| vec!["grant carries no valid envelope".to_string()])?;
        let Some(inst) = instance.filter(|i| !i.is_null()) else {
            return Err(vec!["the grant commits objective-risk facts but the instance holds no objective-risk config".to_string()]);
        };
        let one = |e: String| vec![e];
        let trusted: Vec<String> = inst["registry"]["trusted_verifiers"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let mut registry = InMemoryInverseRegistry::new(&trusted);
        for e in inst["registry"]["entries"].as_array().into_iter().flatten() {
            let mut entry = json!({"inverseKind": e["inverse_kind"], "fidelity": e["fidelity"]});
            if let Some(v) = e.get("verification").filter(|v| v.is_object()) {
                entry["verification"] = json!({"verifierId": v["verifier_id"], "evidenceDigest": v["evidence_digest"]});
            }
            registry.register(e.get("verb").and_then(Value::as_str).unwrap_or("undefined"), &entry);
        }
        let mut graph = ResourceGraph::new();
        for n in inst["graph"]["nodes"].as_array().into_iter().flatten() {
            graph.add_node(n).map_err(one)?;
        }
        for e in inst["graph"]["edges"].as_array().into_iter().flatten() {
            graph.add_edge(e).map_err(one)?;
        }
        let emb = &c["embedder"];
        let embedder = native_hash_embedder(&emb["config"]).map_err(one)?;
        if Some(embedder.model_id().as_str()) != emb["model_id"].as_str() {
            return Err(vec!["embedder model_id does not match the committed one".to_string()]);
        }
        let calibration: Option<Vec<f64>> = inst.get("calibration").and_then(Value::as_array).map(|a| a.iter().map(|v| v.as_f64().unwrap_or(f64::NAN)).collect());
        let committed_cal = c.get("calibration_digest").and_then(Value::as_str);
        if let Some(d) = committed_cal {
            if calibration.as_deref().map(calibration_digest).transpose().map_err(one)?.as_deref() != Some(d) {
                return Err(vec!["calibration set does not match the committed digest".to_string()]);
            }
        }
        let mut commitments = json!({"registryDigest": c["registry_digest"], "graphDigest": c["graph_digest"]});
        if let Some(d) = committed_cal {
            commitments["calibrationDigest"] = json!(d);
        }
        let kinds: BTreeSet<String> = c["authorized_kinds"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(String::from)).collect();
        let denominations: Vec<Value> = c["denominations"].as_array().cloned().unwrap_or_default();
        let weights = env.get("risk_policy").and_then(|r| r.get("weights")).ok_or_else(|| vec!["Cannot read properties of undefined (reading 'weights')".to_string()])?;
        let scope = c.get("scope").filter(|s| s.is_object());
        let res = objective_risk(
            action,
            &ObjectiveRiskContext {
                registry: &registry,
                authorized_kinds: &kinds,
                graph: &graph,
                scope,
                embedder: &embedder,
                goal: &c["goal"],
                commitments: &commitments,
                denominations: &denominations,
                weights,
                taint: taint.unwrap_or(1.0),
                age: age.unwrap_or(1.0),
                attested_uncertainty: None,
                calibration: committed_cal.and(calibration.as_deref()),
            },
        )
        .map_err(one)?;
        if res["valid"] != Value::Bool(true) {
            return Err(res["reasons"].as_array().into_iter().flatten().map(crate::intent_v2::js_value_string).collect());
        }
        let i = &res["inputs"];
        Ok(json!({"mode": "objective", "inputs": {"reversibility": i["reversibility"], "blastRadius": i["blastRadius"], "semanticDistance": i["semanticDistance"]}, "r": res["r"], "evidenceDigest": res["evidenceDigest"]}))
    };
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(v)) => v,
        Ok(Err(reasons)) => mismatch(reasons, on_mismatch),
        Err(e) => mismatch(vec![format!("objective risk evaluation error (fail closed): {}", crate::taint::panic_message(e.as_ref()))], on_mismatch),
    }
}
