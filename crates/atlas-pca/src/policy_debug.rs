//! The replayable policy debugger (port of `policy-debug.ts`): the decision core is pure and total, so a "why" is a re-run of it,
//! not a logged guess. `explain_risk` decomposes the risk functional into its six weighted terms, `explain_decision` explains a
//! decide input (the same object [`crate::policy_vm::decide`] takes), `apply_delta` / `counterfactual` re-run the core under
//! single hypothetical edits and report which one flips the outcome or moves the threshold, and `audit_pcactn` re-verifies a
//! proof-carrying action and attaches the explanation.
//!
//! JSON-valued (`&Value` in, the reference's member names out; a number that is not finite is the `{"$num": "NaN"}` marker the
//! reference's JSON uses). A reference throw is an `Err`. This `explain_decision` explains the Policy VM; it is not the one of
//! the explain package.
use serde_json::{json, Map, Value};

use crate::authorize::read_envelope;
use crate::intent_v2::{js_number_string, js_value_string};
use crate::policy_vm::decide;
use crate::prohibitions::num_value;
use crate::risk::{age_since_touch, cost, leak, plan_geodesic, recharge, recharge_full, safety_bound, RiskPolicy, TrustBudget, DEFAULT_AGE_HORIZON_MS, DEFAULT_RISK_POLICY};

/// The six terms in the fixed order of the risk functional: (term, weight member, inverted, worst-case input).
const TERMS: [(&str, &str, bool, f64); 6] = [
    ("semanticDistance", "alpha", false, 1.0),
    ("reversibility", "beta", true, 0.0),
    ("blastRadius", "gamma", false, 1.0),
    ("taint", "delta", false, 1.0),
    ("confidence", "epsilon", true, 0.0),
    ("age", "zeta", false, 1.0),
];

/// A number argument; a missing or non-number value is NaN (`Number.isFinite` of it is false), the `{"$num"}` marker is its value.
fn jsnum(v: Option<&Value>) -> f64 {
    match v {
        Some(n) if n.is_number() => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::Object(m)) => match m.get("$num").and_then(Value::as_str) {
            Some("Infinity") => f64::INFINITY,
            Some("-Infinity") => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
        _ => f64::NAN,
    }
}

fn nv(f: f64) -> Value {
    if f.is_finite() {
        num_value(f)
    } else {
        json!({ "$num": js_number_string(f) })
    }
}

fn clamp01(x: f64) -> f64 {
    if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

fn wt(x: f64) -> f64 {
    if x.is_finite() && x > 0.0 {
        x
    } else {
        0.0
    }
}

/// `Math.max` (NaN wins).
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// Decomposes the risk score into its six additive terms: `{inputs, weights, terms[6], rawSum, rScore, rFloor, r}`. A non-finite
/// input is the worst case for its term, never the safe end of an inverted one; `r = max(rScore, rFloor)` with the floor clamped to
/// [0, 1] (a non-finite floor is 0).
pub fn explain_risk(inputs: &Value, weights: &Value, r_floor: f64) -> Value {
    let r_floor = if r_floor.is_finite() { r_floor } else { 0.0 };
    let mut raw_sum = 0.0;
    let terms: Vec<Value> = TERMS
        .iter()
        .map(|&(name, w, inverted, worst)| {
            let weight = wt(jsnum(weights.get(w)));
            let x = jsnum(inputs.get(name));
            let input = if x.is_finite() { clamp01(x) } else { worst };
            let effective = if inverted { 1.0 - input } else { input };
            let contribution = weight * effective;
            raw_sum += contribution;
            json!({ "term": name, "weight": nv(weight), "input": nv(input), "effective": nv(effective), "contribution": nv(contribution), "inverted": inverted })
        })
        .collect();
    let r_score = clamp01(raw_sum);
    let floor = clamp01(r_floor);
    json!({ "inputs": inputs, "weights": weights, "terms": terms, "rawSum": nv(raw_sum), "rScore": nv(r_score), "rFloor": nv(floor), "r": nv(js_max(r_score, floor)) })
}

fn budget_of(v: Option<&Value>) -> TrustBudget {
    let v = v.unwrap_or(&Value::Null);
    let as_of = v.get("asOf").filter(|x| x.is_number()).map(|x| jsnum(Some(x)));
    TrustBudget { b: jsnum(v.get("B")), tau: jsnum(v.get("tau")), as_of }
}

fn budget_value(b: &TrustBudget) -> Value {
    json!({ "B": nv(b.b), "tau": nv(b.tau), "asOf": nv(b.as_of.unwrap_or(b.tau)) })
}

fn policy_of(grant: &Value) -> RiskPolicy {
    read_envelope(grant)
        .and_then(|e| RiskPolicy::from_value(e.get("risk_policy").unwrap_or(&Value::Null)).ok())
        .unwrap_or(DEFAULT_RISK_POLICY)
}

fn weights_value(p: &RiskPolicy) -> Value {
    let w = &p.weights;
    json!({ "alpha": nv(w.alpha), "beta": nv(w.beta), "gamma": nv(w.gamma), "delta": nv(w.delta), "epsilon": nv(w.epsilon), "zeta": nv(w.zeta) })
}

/// Explains one decision: replays [`decide`] and decomposes it into `{decision, risk, requiredThreshold, t, autoAllow, needStepUp,
/// releaseGuardianShare, budget: {before, leaked, after, cost, safetyBound}, reasons, envelopeValid}`. `Err` when the input has
/// no readable trust budget.
pub fn explain_decision(input: &Value) -> Result<Value, String> {
    let decision = decide(input);
    let grant = input.get("grant").unwrap_or(&Value::Null);
    let env = read_envelope(grant);
    let pol = policy_of(grant);
    let before = input.get("budget");
    let r = jsnum(decision.get("r"));
    let (risk, leaked) = match &env {
        Some(env) => {
            let rp = RiskPolicy::from_value(env.get("risk_policy").unwrap_or(&Value::Null))?;
            let now = jsnum(input.get("now"));
            let before = before.ok_or("Cannot read properties of undefined (reading 'asOf')")?;
            let leaked = leak(&budget_of(Some(before)), now, rp.lambda);
            let risk_in = input.get("risk").filter(|r| r.is_object());
            let mut inputs = Map::new();
            for &(name, _, _, worst) in &TERMS {
                let x = risk_in.map_or(f64::NAN, |o| jsnum(o.get(name)));
                inputs.insert(name.into(), nv(if x.is_finite() { x } else { worst }));
            }
            let absent = |k: &str| risk_in.is_none_or(|o| o.get(k).is_none());
            if absent("semanticDistance") {
                if let Some(plan) = input.get("plan").and_then(Value::as_array) {
                    let goal = input.get("goalNodeId").filter(|g| !g.is_null()).and_then(Value::as_str).or_else(|| plan.last().and_then(|n| n.get("id")).and_then(Value::as_str));
                    let node = input.get("nodeId").and_then(Value::as_str);
                    inputs.insert("semanticDistance".into(), nv(match (node, goal) {
                        (Some(n), Some(g)) => plan_geodesic(plan, n, g),
                        _ => 1.0,
                    }));
                }
            }
            if absent("age") {
                let horizon = input.get("ageHorizonMs").filter(|h| h.is_number()).map_or(DEFAULT_AGE_HORIZON_MS, |h| jsnum(Some(h)));
                inputs.insert("age".into(), nv(age_since_touch(&leaked, now, horizon)));
            }
            let floor = input.get("rFloor").filter(|f| f.is_number()).map(|f| jsnum(Some(f))).filter(|f| f.is_finite()).map_or(0.0, |f| f.clamp(0.0, 1.0));
            (explain_risk(&Value::Object(inputs), &weights_value(&rp), floor), budget_value(&leaked))
        }
        // fail-closed denial (no envelope): decide returned r = 1; keep the shape coherent
        None => {
            let worst: Map<String, Value> = TERMS.iter().map(|&(n, _, _, w)| (n.to_string(), nv(w))).collect();
            let zero: Map<String, Value> = TERMS.iter().map(|&(_, w, _, _)| (w.to_string(), json!(0))).collect();
            (
                json!({ "inputs": worst, "weights": zero, "terms": [], "rawSum": nv(r), "rScore": nv(r), "rFloor": 0, "r": nv(r) }),
                before.cloned().unwrap_or(Value::Null),
            )
        }
    };
    let rt = decision.get("requiredThreshold").cloned().unwrap_or(Value::Null);
    let flag = |k: &str| decision.get(k).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "decision": decision,
        "risk": risk,
        "requiredThreshold": rt,
        "t": rt.get("t").cloned().unwrap_or(Value::Null),
        "autoAllow": flag("admit"),
        "needStepUp": flag("needStepUp"),
        "releaseGuardianShare": flag("releaseGuardianShare"),
        "budget": {
            "before": before,
            "leaked": leaked,
            "after": flag("budget"),
            "cost": nv(cost(r, pol.kappa)),
            "safetyBound": nv(safety_bound(pol.b_max, pol.kappa)),
        },
        "reasons": flag("reasons"),
        "envelopeValid": env.is_some(),
    }))
}

// ---- counterfactuals -----------------------------------------------------------------------------------------------------------

/// An object's members as a map (anything else spreads to nothing).
fn spread(v: Option<&Value>) -> Map<String, Value> {
    v.and_then(Value::as_object).cloned().unwrap_or_default()
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// The hypothetical decide input a delta `{label?, risk?, budget?, rFloor?, now?, caveatContext?, humanCosign?}` denotes
/// (`humanCosign` recharges the budget first, `{full: true}` to the maximum). Pure: `input` is not changed.
pub fn apply_delta(input: &Value, d: &Value) -> Result<Value, String> {
    let now_v = d.get("now").filter(|n| !n.is_null()).or_else(|| input.get("now")).cloned().unwrap_or(Value::Null);
    let now = jsnum(Some(&now_v));
    let mut merged = spread(input.get("budget"));
    merged.extend(spread(d.get("budget")));
    let mut budget = Value::Object(merged);
    if truthy(d.get("humanCosign")) {
        let pol = policy_of(input.get("grant").unwrap_or(&Value::Null));
        let full = d.get("humanCosign").and_then(|h| h.get("full")) == Some(&Value::Bool(true));
        budget = budget_value(&if full { recharge_full(pol.b_max, now) } else { recharge(&budget_of(Some(&budget)), pol.rho, pol.b_max, now) });
    }
    let mut next = input.as_object().cloned().ok_or("Cannot read properties of null (reading 'grant')")?;
    next.insert("now".into(), now_v);
    next.insert("budget".into(), budget);
    let mut risk = spread(input.get("risk"));
    risk.extend(spread(d.get("risk")));
    next.insert("risk".into(), Value::Object(risk));
    let mut ctx = spread(input.get("caveatContext"));
    ctx.extend(spread(d.get("caveatContext")));
    next.insert("caveatContext".into(), Value::Object(ctx));
    if let Some(f) = d.get("rFloor") {
        next.insert("rFloor".into(), f.clone());
    }
    Ok(Value::Object(next))
}

/// `String(v)`; a non-finite number travels as the `{"$num": "NaN" | "Infinity" | "-Infinity"}` marker and reads as that text.
fn jsv(v: &Value) -> String {
    match v.as_object().filter(|m| m.len() == 1).and_then(|m| m.get("$num")).and_then(Value::as_str) {
        Some(t @ ("NaN" | "Infinity" | "-Infinity")) => t.to_string(),
        _ => js_value_string(v),
    }
}

fn describe(d: &Value) -> String {
    if let Some(l) = d.get("label").filter(|l| truthy(Some(l))) {
        return js_value_string(l);
    }
    let mut parts: Vec<String> = Vec::new();
    let hc = d.get("humanCosign");
    if truthy(hc) {
        parts.push(if truthy(hc.and_then(|h| h.get("full"))) { "human re-confirms goal (B\u{2190}Bmax)" } else { "human co-signs (B+\u{3c1})" }.into());
    }
    for (member, prefix) in [("risk", ""), ("budget", "budget.")] {
        for (k, v) in spread(d.get(member)) {
            parts.push(format!("{prefix}{k}={}", jsv(&v)));
        }
    }
    if let Some(f) = d.get("rFloor") {
        parts.push(format!("caution={}", jsv(f)));
    }
    if let Some(n) = d.get("now") {
        parts.push(format!("now={}", jsv(n)));
    }
    for (k, v) in spread(d.get("caveatContext")) {
        parts.push(format!("ctx.{k}={}", serde_json::to_string(&v).unwrap_or_default()));
    }
    if parts.is_empty() {
        "no-op".into()
    } else {
        parts.join(", ")
    }
}

/// Replays the decision under each single change and reports `{baseline, outcomes: [{label, delta, explanation, flipsAllow, allow,
/// thresholdDirection, changesThreshold, t, rDelta}], flipping, thresholdChanging}`.
pub fn counterfactual(input: &Value, deltas: &[Value]) -> Result<Value, String> {
    let baseline = explain_decision(input)?;
    let t_of = |e: &Value| jsnum(e.get("t"));
    let r_of = |e: &Value| jsnum(e["risk"].get("r"));
    let mut outcomes: Vec<Value> = Vec::new();
    for d in deltas {
        let explanation = explain_decision(&apply_delta(input, d)?)?;
        let (t, bt) = (t_of(&explanation), t_of(&baseline));
        let direction = if t > bt { "raised" } else if t < bt { "lowered" } else { "same" };
        outcomes.push(json!({
            "label": describe(d),
            "delta": d,
            "flipsAllow": explanation["autoAllow"] != baseline["autoAllow"],
            "allow": explanation["autoAllow"],
            "thresholdDirection": direction,
            "changesThreshold": direction != "same",
            "t": explanation["t"],
            "rDelta": nv(r_of(&explanation) - r_of(&baseline)),
            "explanation": explanation,
        }));
    }
    let labels = |key: &str| outcomes.iter().filter(|o| o[key] == true).map(|o| o["label"].clone()).collect::<Vec<_>>();
    let (flipping, changing) = (labels("flipsAllow"), labels("changesThreshold"));
    Ok(json!({ "baseline": baseline, "outcomes": outcomes, "flipping": flipping, "thresholdChanging": changing }))
}

// ---- the full audit ------------------------------------------------------------------------------------------------------------

const ABSENT_AUDIENCE: &str = "audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)";

/// The full audit of a PCActn: `{verify: {allow, checks, reason?}, explanation}`, the verifier's per-check table (the core without
/// hooks, so `taint_gate`, `attestation`, `threshold` and `revocation` are `not-enforced`) plus the decision decomposition of the same
/// action. `opts`: `{grant, nowEpoch?, audience?, authorizedPlanRoots?, insecureSkipPlanRootCheck?}`; `audience` null accepts any
/// audience (`not-enforced`), absent while the PCActn carries one fails closed.
pub fn audit_pcactn(p: &Value, input: &Value, opts: &Value) -> Result<Value, String> {
    let grant = opts.get("grant").filter(|g| g.is_object()).ok_or("Cannot read properties of undefined (reading 'caveats')")?;
    let now = opts.get("nowEpoch").filter(|n| n.is_number()).and_then(Value::as_i64).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
    });
    let roots: Option<Vec<String>> = opts.get("authorizedPlanRoots").and_then(Value::as_array).map(|a| a.iter().filter_map(|r| r.as_str().map(String::from)).collect());
    let skip = opts.get("insecureSkipPlanRootCheck") == Some(&Value::Bool(true));
    let aud_of = |p: &Value| p.get("aud").and_then(Value::as_str).unwrap_or("").to_string();
    let (audience, opt_out) = match opts.get("audience") {
        Some(Value::String(a)) => (a.clone(), false),
        Some(Value::Null) => (aud_of(p), true),
        _ => (String::new(), false),
    };
    let vopts = crate::VerifyOptions { authorized_plan_roots: roots.as_deref(), insecure_skip_plan_root_check: skip, ..crate::VerifyOptions::default() };
    let v = crate::verify_pcactn_core_with(p, grant, now, &audience, &vopts);
    let wire_ok = v.checks.get("wire") == Some(&true);
    let mut checks = Map::new();
    for (k, ok) in &v.checks {
        let status = if k == "audience" && opt_out { "not-enforced" } else if *ok { "pass" } else { "fail" };
        checks.insert(if k == "chain" { "cap_chain".to_string() } else { k.clone() }, json!(status));
    }
    if wire_ok {
        if roots.is_none() && skip {
            checks.insert("plan_root_authorized".into(), json!("not-enforced"));
        }
        for k in ["taint_gate", "attestation", "threshold", "revocation"] {
            checks.insert(k.into(), json!("not-enforced"));
        }
    }
    let mut verify = json!({ "allow": v.allow, "checks": checks });
    if !v.allow {
        let absent = opts.get("audience").is_none() && v.reason == "audience: aud does not match this resource server / instance";
        verify["reason"] = json!(if absent { ABSENT_AUDIENCE } else { v.reason.as_str() });
    }
    Ok(json!({ "verify": verify, "explanation": explain_decision(input)? }))
}
