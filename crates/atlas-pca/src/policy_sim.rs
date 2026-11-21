//! Static lints over a COMPILED policy (`lintPolicy` of `packages/pca/src/policy-sim.ts`). `error` = almost certainly a mistake
//! (a limit that matches no granted action); `warn` = a real risk worth a second look; `info` = a notable but intentional
//! property. Pure. (The facade-level `policy_ci::lint_policy` lints the policy INPUT; this one lints what `compile_policy` produced.)
use crate::facade::{ActionSpec, CompiledPolicy};
use serde_json::{json, Value};

const REVERSIBILITY_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

fn sev(c: &str) -> i64 {
    REVERSIBILITY_ORDER.iter().position(|r| *r == c).map_or(-1, |i| i as i64)
}

fn lint(level: &str, code: &str, message: String) -> Value {
    json!({ "level": level, "code": code, "message": message })
}

/// `lintPolicy(policy, {catalog})`: `[{level, code, message}]`, in the reference's order.
pub fn lint_compiled_policy(policy: &CompiledPolicy, catalog: &[ActionSpec]) -> Vec<Value> {
    let mut lints = Vec::new();
    let granted: Vec<&str> =
        policy.actions.iter().flat_map(|s| [s.verb.as_str(), s.action.as_str()].into_iter().chain(s.aliases.iter().map(String::as_str))).collect();
    for key in policy.input_limits.as_object().into_iter().flat_map(|m| m.keys()) {
        if !granted.contains(&key.as_str()) {
            lints.push(lint("error", "limit-unmatched", format!("limit for '{key}' matches no granted action")));
        }
    }
    for spec in &policy.actions {
        let pred = policy.predicates.iter().find(|p| p.get("verb").and_then(Value::as_str) == Some(spec.verb.as_str()));
        let resource = pred.and_then(|p| p.get("resource")).and_then(Value::as_str).unwrap_or("");
        let broad = resource.is_empty() || resource == "*";
        if spec.amount_field.is_some() && !policy.limits.iter().any(|(v, _)| *v == spec.verb) {
            lints.push(lint(
                "warn",
                "money-unbounded",
                format!("money action '{}' has no per-call limit \u{2014} spend is bounded only by the trust budget", spec.verb),
            ));
        }
        if broad && sev(&spec.reversibility) >= sev("rate_limited") {
            lints.push(lint(
                "warn",
                "broad-resource",
                format!("'{}' ({}) matches ANY resource \u{2014} consider a resource prefix", spec.verb, spec.reversibility),
            ));
        }
        if !catalog.iter().any(|c| c.verb == spec.verb) {
            lints.push(lint(
                "info",
                "uncatalogued",
                format!("'{}' is not in the catalog \u{2014} treated conservatively (irreversible, high blast radius)", spec.verb),
            ));
        }
    }
    let f = |k: &str| policy.risk_policy.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN);
    let (theta2, b_max, kappa) = (f("theta2"), f("bMax"), f("kappa"));
    if theta2 >= 1.0 {
        let has_irrev = policy.actions.iter().any(|s| sev(&s.reversibility) >= sev("irreversible"));
        let tail = if has_irrev { " \u{2014} including irreversible actions" } else { "" };
        lints.push(lint(
            if has_irrev { "warn" } else { "info" },
            "no-step-up-band",
            format!("theta2 \u{2265} 1: no action triggers a human step-up until the budget is exhausted{tail}"),
        ));
    }
    if kappa > 0.0 && b_max / kappa > 100.0 {
        lints.push(lint(
            "warn",
            "large-autonomy",
            format!("autonomous bound is {}\u{d7} a max-risk action between human co-signs", (b_max / kappa + 0.5).floor()),
        ));
    }
    lints
}

// ---- simulation ---------------------------------------------------------------------------------------------------------------

/// Options of [`simulate`]: the catalog that prices and classes each verb (default: the built-in one) and the time base (an
/// action without an `at` happens at `start` plus its index; default 0).
#[derive(Clone, Copy, Default)]
pub struct SimOptions<'a> {
    pub catalog: Option<&'a crate::catalog::Catalog>,
    pub start: Option<f64>,
}

/// `Math.max(0, Math.min(1, x))`.
fn clamp_unit(x: f64) -> f64 {
    if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// A double as the reference's JSON carries it (a non-finite value is `null`).
pub(crate) fn sim_num(x: f64) -> Value {
    if x.is_finite() {
        crate::prohibitions::num_value(x)
    } else {
        Value::Null
    }
}

fn risk_of(policy: &CompiledPolicy, kappa: f64, spec: Option<&Value>, params: Option<&Value>) -> f64 {
    let field = spec.and_then(|s| s.get("amountField")).and_then(Value::as_str).filter(|f| !f.is_empty());
    if let (true, Some(field)) = (policy.budget_model == "dollars", field) {
        let amount = crate::actions::js_to_number(params.and_then(Value::as_object).and_then(|p| p.get(field)));
        if amount.is_finite() && kappa > 0.0 {
            return clamp_unit(amount / kappa);
        }
    }
    clamp_unit(spec.map_or(0.8, |s| s.get("blastRadius").and_then(Value::as_f64).unwrap_or(f64::NAN)))
}

/// `simulate(policy, actions, {catalog, start})`: replays `actions` (`{verb, resource, params?, at?}`) in time order against the
/// compiled policy, threading the trust budget as the server would (leak between actions, a debit of kappa * r on every machine
/// admit, a step-up when the tier or the budget asks for one). Returns `{results: [{action, outcome, t?, r, reason?,
/// budgetAfter}], auto, stepUp, deny, endBudget, peakRisk, autonomousRisk}`. An action without a usable time is reported as
/// denied, first. Pure and offline: a planning view, the resource server's verifier stays the authority. `Err` only for a policy
/// whose risk policy is invalid.
pub fn simulate(policy: &CompiledPolicy, actions: &[Value], opts: SimOptions) -> Result<Value, String> {
    let rp = crate::risk::RiskPolicy::from_value(&policy.risk_policy)?;
    let builtin: &crate::catalog::Catalog = &crate::catalog::DEFAULT_CATALOG;
    let catalog = opts.catalog.unwrap_or(builtin);
    let start = opts.start.unwrap_or(0.0);
    let timed: Vec<(&Value, f64)> = actions
        .iter()
        .enumerate()
        .map(|(i, a)| match a.get("at") {
            None | Some(Value::Null) => (a, start + i as f64),
            Some(at) => (a, at.as_f64().filter(|_| at.is_number()).unwrap_or(f64::NAN)),
        })
        .collect();
    let mut ordered: Vec<(&Value, f64)> = timed.iter().copied().filter(|x| x.1.is_finite()).collect();
    ordered.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut budget = crate::risk::TrustBudget { b: rp.b_max, tau: start, as_of: Some(start) };
    let mut recent: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    let (mut peak, mut autonomous) = (0.0f64, 0.0f64);
    let (mut auto, mut step_up, mut deny) = (0u64, 0u64, 0u64);
    for (a, _) in timed.iter().filter(|x| !x.1.is_finite()) {
        deny += 1;
        results.push(json!({"action": a, "outcome": "deny", "r": 1, "reason": "action has no finite time", "budgetAfter": sim_num(budget.b)}));
    }
    for (a, at) in ordered {
        let spec = a.get("verb").and_then(Value::as_str).and_then(|v| catalog.get(v));
        let class = spec.and_then(|s| s.get("reversibility")).filter(|c| !c.is_null()).cloned().unwrap_or_else(|| json!("irreversible"));
        let blast = spec.and_then(|s| s.get("blastRadius")).filter(|b| !b.is_null()).cloned().unwrap_or_else(|| json!(1));
        let params = a.get("params").filter(|p| !p.is_null());
        let mut action = serde_json::Map::new();
        for k in ["verb", "resource"] {
            if let Some(v) = a.get(k) {
                action.insert(k.into(), v.clone());
            }
        }
        action.insert("params".into(), params.cloned().unwrap_or_else(|| json!({})));
        action.insert("reversibility_class".into(), class.clone());
        let ctx = json!({ "action": action });
        let r = risk_of(policy, rp.kappa, spec, params);
        peak = if peak.is_nan() || r.is_nan() { f64::NAN } else if r > peak { r } else { peak };

        let denial = crate::safe_regex::with_regex_budget(|| crate::authorize::envelope_predicates_denial(&policy.predicates, &ctx));
        let failed = match denial {
            None => crate::evaluate_caveats(&json!(policy.caveats), &json!({"now": at, "blast_radius": blast, "reversibility_class": class, "recent_action_times": recent})).1,
            Some(_) => Vec::new(),
        };
        budget = crate::risk::leak(&budget, at, rp.lambda);
        if let Some(reason) = denial {
            deny += 1;
            results.push(json!({"action": a, "outcome": "deny", "r": sim_num(r), "reason": reason, "budgetAfter": sim_num(budget.b)}));
            continue;
        }
        if !failed.is_empty() {
            deny += 1;
            results.push(json!({"action": a, "outcome": "deny", "r": sim_num(r), "reason": format!("caveat(s) failed: {}", failed.join(", ")), "budgetAfter": sim_num(budget.b)}));
            continue;
        }
        let adm = crate::risk::admit(r, &budget, &rp);
        if adm.t == 1 && adm.admit {
            budget.b -= crate::risk::cost(r, rp.kappa);
            autonomous += r;
            recent.push(json!(at));
            auto += 1;
            results.push(json!({"action": a, "outcome": "auto", "t": 1, "r": sim_num(r), "budgetAfter": sim_num(budget.b)}));
        } else {
            // tier 2 (the guardian co-signs) and tier 3 (a human) are both a step-up in the planning view
            step_up += 1;
            let mut row = json!({"action": a, "outcome": "step_up", "t": adm.t, "r": sim_num(r)});
            if adm.need_step_up {
                row["reason"] = json!(format!("requires tier {}", adm.t));
            }
            row["budgetAfter"] = sim_num(budget.b);
            results.push(row);
        }
    }
    Ok(json!({"results": results, "auto": auto, "stepUp": step_up, "deny": deny, "endBudget": sim_num(budget.b), "peakRisk": sim_num(peak),
        "autonomousRisk": sim_num(autonomous)}))
}
