//! `resolve_objective_risk`: nothing committed is the heuristic, a malformed or unreproducible commitment is a (deny by default) mismatch, and
//! a grant cannot opt itself out of the objective risk.
use atlas_pca::objective_binding::resolve_objective_risk;
use atlas_pca::serde_json::{json, Value};

fn grant(objective: Option<Value>) -> Value {
    let mut env = json!({
        "type": "envelope", "goal_commit": "g", "predicates": [], "caveats": [], "agent_binding": {},
        "risk_policy": {"theta1": 0.25, "theta2": 0.6, "kappa": 1, "lambda": 0, "rho": 0.5, "bMax": 1,
            "weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05}},
    });
    if let Some(o) = objective {
        env["objective_risk"] = o;
    }
    json!({"id": "x", "caveats": [env]})
}

fn commitment(on_mismatch: Option<&str>) -> Value {
    let mut c = json!({
        "v": 1, "embedder": {"scheme": "native", "model_id": "m", "config": {}}, "goal": {"commit": "c"},
        "registry_digest": "r", "graph_digest": "g", "authorized_kinds": [],
    });
    if let Some(m) = on_mismatch {
        c["on_mismatch"] = json!(m);
    }
    c
}

#[test]
fn nothing_committed_is_the_heuristic() {
    assert_eq!(resolve_objective_risk(&grant(None), &json!({}), None, None, None), json!({"mode": "none"}));
}

#[test]
fn a_malformed_commitment_is_a_denied_mismatch() {
    let r = resolve_objective_risk(&grant(Some(json!({"v": 2}))), &json!({}), None, None, None);
    assert_eq!(r, json!({"mode": "mismatch", "reasons": ["objective_risk: unsupported shape/version"], "onMismatch": "deny"}));
}

#[test]
fn a_commitment_without_instance_config_is_a_mismatch_and_the_grant_cannot_downgrade_it() {
    let g = grant(Some(commitment(Some("heuristic"))));
    let r = resolve_objective_risk(&g, &json!({}), None, None, None);
    assert_eq!(r["mode"], "mismatch");
    assert_eq!(r["onMismatch"], "deny");
    assert_eq!(r["reasons"], json!(["the grant commits objective-risk facts but the instance holds no objective-risk config"]));
    // the instance opts in to the fallback; its (bad) native config is still a mismatch, now answered with the heuristic
    let r = resolve_objective_risk(&g, &json!({}), Some(&json!({"allow_heuristic_fallback": true})), None, None);
    assert_eq!((r["mode"].as_str(), r["onMismatch"].as_str()), (Some("mismatch"), Some("heuristic")));
}
