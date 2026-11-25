//! The budget forecaster and the policy recommender (port of `budget-forecast.ts`). Given a planned sequence of actions and a
//! compiled policy, [`forecast`] says how the trust budget drains, when the first co-sign is forced and how many the whole plan
//! needs; [`recommend_policy`] goes the other way and derives kappa / bMax for a target level of autonomy. Pure: it composes the
//! simulator and the budget algebra.
use serde_json::{json, Value};

use crate::facade::CompiledPolicy;
use crate::policy_sim::{sim_num, simulate, SimOptions};

/// `forecast(policy, plan, {start, catalog})`: `{steps: [{verb, resource, outcome, r, budgetAfter}], firstStepUpAt?,
/// autonomousRisk, forcesCosign, cosignsNeeded, endBudget}` of a plan of `{verb, resource, params?, at?}` actions. A verb the
/// given catalog does not know is priced and classed at the worst case.
pub fn forecast(policy: &CompiledPolicy, plan: &[Value], opts: SimOptions) -> Result<Value, String> {
    let rep = simulate(policy, plan, SimOptions { start: Some(opts.start.unwrap_or(0.0)), ..opts })?;
    let mut steps = Vec::new();
    for r in rep["results"].as_array().into_iter().flatten() {
        let mut step = serde_json::Map::new();
        for k in ["verb", "resource"] {
            if let Some(v) = r["action"].get(k) {
                step.insert(k.into(), v.clone());
            }
        }
        for k in ["outcome", "r", "budgetAfter"] {
            step.insert(k.into(), r[k].clone());
        }
        steps.push(Value::Object(step));
    }
    let first_step_up = steps.iter().position(|s| s["outcome"] == "step_up");
    let mut out = json!({ "steps": steps });
    if let Some(i) = first_step_up {
        out["firstStepUpAt"] = json!(i);
    }
    out["autonomousRisk"] = rep["autonomousRisk"].clone();
    out["forcesCosign"] = json!(rep["stepUp"].as_u64().is_some_and(|n| n > 0));
    out["cosignsNeeded"] = rep["stepUp"].clone();
    out["endBudget"] = rep["endBudget"].clone();
    Ok(out)
}

/// `recommendPolicy(targetActions, perActionRisk, {kappa})`: `{kappa, bMax, autonomousBound, rationale}` so that an agent can
/// take `target_actions` autonomous actions of typical risk `per_action_risk` (clamped to [1e-6, 1]) between human co-signs. By
/// the safety theorem the total machine-only risk is at most bMax / kappa, so bMax = target * risk * kappa (kappa defaults to 1).
/// `Err` for a kappa that is not positive and finite, or a non-finite target or risk.
pub fn recommend_policy(target_actions: f64, per_action_risk: f64, kappa: Option<f64>) -> Result<Value, String> {
    let kappa = kappa.unwrap_or(1.0);
    if !kappa.is_finite() || kappa <= 0.0 {
        return Err("recommendPolicy: kappa must be a positive finite number".into());
    }
    if !target_actions.is_finite() || !per_action_risk.is_finite() {
        return Err("recommendPolicy: targetActions and perActionRisk must be finite numbers".into());
    }
    let r = if per_action_risk > 1.0 { 1.0 } else if per_action_risk < 1e-6 { 1e-6 } else { per_action_risk };
    let n = if target_actions > 0.0 { target_actions } else { 0.0 };
    let b_max = n * r * kappa;
    let bound = b_max / kappa;
    // `toFixed(3)`: from 1e21 up it is the plain number-to-string conversion
    let fixed = |x: f64| if x >= 1e21 { crate::intent_v2::js_number_string(x) } else { crate::risk::js_to_fixed3(x) };
    Ok(json!({
        "kappa": sim_num(kappa),
        "bMax": sim_num(b_max),
        "autonomousBound": sim_num(bound),
        "rationale": format!("\u{3a3}r \u{2264} bMax/\u{3ba} = {} \u{2265} {}\u{d7}{} actions before a human co-sign", fixed(bound), crate::intent_v2::js_number_string(n), fixed(r)),
    }))
}

/// `autonomyBoundOf(policy)`: the proven autonomous bound `bMax / kappa` of a risk policy `{bMax, kappa}` (0 when kappa is not a
/// positive number; NaN when bMax is not a number).
pub fn autonomy_bound_of(policy: &Value) -> f64 {
    let n = |k: &str| policy.get(k).filter(|v| v.is_number()).and_then(Value::as_f64).unwrap_or(f64::NAN);
    crate::risk::safety_bound(n("bMax"), n("kappa"))
}
