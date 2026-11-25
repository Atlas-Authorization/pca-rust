//! Approval and step-up model (`approvals.ts`): the HEADLESS core an approval inbox renders. Given an intended action it decides
//! whether it auto-admits, is a hard deny or needs a human, and if so produces a step-up request carrying goal lineage, the risk tier
//! and a stable id; plus batching, "approve this class for N hours" standing approvals and the human co-sign budget recharge.
//!
//! Pure and offline: it composes the agent handle's non-authoritative [`AgentHandle::dry_run`] and the budget algebra, and signs
//! nothing except where a grant is time-boxed ([`time_box`]). The resource server stays the authority at run time. Records are
//! `serde_json::Value`s with the reference's member names (`goalCommit`, `requestedAt`, `renderDigest`, ...).
use crate::adapters::{js_json, js_string};
use crate::agent::{attenuate, verify_goal_commit, KeyPair, Suite};
use crate::approval::approval_render_digest;
use crate::authorize::read_envelope;
use crate::facade::{AgentHandle, ParsedLimit};
use crate::risk::{recharge, recharge_full, RiskPolicy, TrustBudget};
use crate::{hash_canonical, intent_v2::js_number_string};
use serde_json::{json, Map, Value};

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A JSON number as JavaScript writes it: an integral value within the safe range is an integer.
fn num(x: f64) -> Value {
    if x.is_finite() && x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_991.0 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn format_limit(limit: &ParsedLimit) -> String {
    let base = if limit.unit == "usd" { format!("${}", js_number_string(limit.amount)) } else { js_number_string(limit.amount) };
    let Some(period) = limit.period_ms else { return base };
    let hours = period as f64 / 3_600_000.0;
    let p = if hours % 24.0 == 0.0 && hours >= 24.0 {
        format!("{}d", js_number_string(hours / 24.0))
    } else if hours >= 1.0 {
        format!("{}h", js_number_string(hours))
    } else {
        format!("{}m", js_number_string((period as f64 / 60_000.0).round()))
    };
    format!("{base}/{p}")
}

/// `String(v)` for a primitive and `JSON.stringify(v)` for an object, array or null, as the reference prints a param value.
fn show(v: &Value) -> String {
    if v.is_object() || v.is_array() || v.is_null() {
        js_json(v)
    } else {
        js_string(v)
    }
}

fn summarize_params(params: Option<&Value>, amount_field: Option<&str>) -> Option<String> {
    let m = params.and_then(Value::as_object)?;
    if let Some(f) = amount_field {
        if let Some(v) = m.get(f) {
            return Some(format!("{f}={}", js_string(v)));
        }
    }
    if m.is_empty() {
        return None;
    }
    Some(m.iter().take(4).map(|(k, v)| format!("{k}={}", show(v))).collect::<Vec<_>>().join(", "))
}

/// The goal lineage of one intended action ("you approved X because you asked to Y"), derived from the grant envelope's `goal_commit`,
/// the compiled policy and the optional revealed goal, which is checked against the commitment with the agent's goal salt
/// (`goalVerified`). Pure; signs nothing.
pub fn build_goal_lineage(agent: &AgentHandle, verb: &str, resource: &str, params: Option<&Value>, goal: Option<&str>) -> Value {
    let env = read_envelope(&agent.grant);
    let goal_commit = env.as_ref().and_then(|e| e.get("goal_commit")).and_then(Value::as_str).unwrap_or("").to_string();
    let verified = goal.is_some_and(|g| !goal_commit.is_empty() && !agent.goal_salt.is_empty() && verify_goal_commit(&goal_commit, g, &agent.goal_salt));
    let spec = agent.policy.actions.iter().find(|s| s.verb == verb);
    let limit = agent.policy.limits.iter().find(|(v, _)| v == verb).map(|(_, l)| l);

    let goal_label = match goal {
        Some(g) => format!("Pursue the goal: \u{201c}{g}\u{201d}"),
        None => "Pursue the grant\u{2019}s committed goal".to_string(),
    };
    let goal_detail = match goal {
        Some(_) if verified => Some("verified: this goal opens the signed grant commitment".to_string()),
        Some(_) => Some("unverified: the revealed goal does not open the grant commitment".to_string()),
        None if !goal_commit.is_empty() => Some(format!("committed as {goal_commit}")),
        None => None,
    };
    let authority = format!("Delegated authority to {verb}{}", limit.map_or(String::new(), |l| format!(" (up to {})", format_limit(l))));
    let action_detail = summarize_params(params, spec.and_then(|s| s.amount_field.as_deref()));

    let mut g = json!({"kind": "goal", "label": goal_label});
    if let Some(d) = goal_detail {
        g["detail"] = json!(d);
    }
    let mut a = json!({"kind": "authority", "label": authority});
    if let Some(s) = spec.filter(|s| !s.description.is_empty()) {
        a["detail"] = json!(s.description);
    }
    let mut c = json!({"kind": "action", "label": format!("{verb} {resource}")});
    if let Some(d) = action_detail {
        c["detail"] = json!(d);
    }
    let because = match goal {
        Some(g) => format!("Approving {verb} on {resource} because you asked to \u{201c}{g}\u{201d}."),
        None => format!("Approving {verb} on {resource}, authorized under the grant\u{2019}s committed goal."),
    };
    let mut out = Map::new();
    if let Some(g) = goal {
        out.insert("goal".into(), json!(g));
    }
    out.insert("goalCommit".into(), json!(goal_commit));
    out.insert("goalVerified".into(), json!(verified));
    out.insert("chain".into(), json!([g, a, c]));
    out.insert("because".into(), json!(because));
    Value::Object(out)
}

/// `describeGoalLineage` with the reference's own JavaScript semantics, one JSON value per chain node: `lineage.chain.map(n => n.detail ?
/// `${n.label} \u{2014} ${n.detail}` : n.label)`. A null lineage or node, a missing or null chain, and a chain without `map` are the
/// TypeErrors it throws; a node without a string label yields that label as it is (`null` for undefined, a number as a number).
pub fn describe_goal_lineage_values(lineage: &Value) -> Result<Vec<Value>, String> {
    use crate::intent_v2::js_value_string;
    if lineage.is_null() {
        return Err("Cannot read properties of null (reading 'chain')".into());
    }
    let chain = match lineage.get("chain") {
        None => return Err("Cannot read properties of undefined (reading 'map')".into()),
        Some(Value::Null) => return Err("Cannot read properties of null (reading 'map')".into()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err("lineage.chain.map is not a function".into()),
    };
    let mut out = Vec::with_capacity(chain.len());
    for n in chain {
        if n.is_null() {
            return Err("Cannot read properties of null (reading 'detail')".into());
        }
        let (label, detail) = (n.get("label"), n.get("detail"));
        out.push(if crate::oauth::truthy(detail) {
            let shown = |v: Option<&Value>| v.map_or_else(|| "undefined".to_string(), js_value_string);
            Value::String(format!("{} \u{2014} {}", shown(label), shown(detail)))
        } else {
            label.cloned().unwrap_or(Value::Null)
        });
    }
    Ok(out)
}

/// Flatten a lineage to plain text lines (SMS, plain email, Slack fallback).
pub fn describe_goal_lineage(lineage: &Value) -> Result<Vec<String>, String> {
    Ok(describe_goal_lineage_values(lineage)?
        .iter()
        .map(|v| match v {
            Value::Null => "undefined".to_string(),
            other => crate::intent_v2::js_value_string(other),
        })
        .collect())
}

fn risk_for_review(agent: &AgentHandle, verb: &str, params: Option<&Value>) -> f64 {
    let spec = agent.policy.actions.iter().find(|s| s.verb == verb);
    let kappa = agent.policy.risk_policy.get("kappa").and_then(Value::as_f64).unwrap_or(0.0);
    if agent.policy.budget_model == "dollars" {
        if let Some(f) = spec.and_then(|s| s.amount_field.as_deref()) {
            let amt = crate::actions::js_to_number(params.and_then(|p| p.get(f)));
            if amt.is_finite() && kappa > 0.0 {
                return (amt / kappa).clamp(0.0, 1.0);
            }
        }
    }
    spec.map_or(0.8, |s| s.blast_radius).clamp(0.0, 1.0)
}

/// Builds the canonical approval render of an action: `(verb, resource, params)`. An `Err` makes the review a deny.
pub type Renderer<'a> = &'a dyn Fn(&str, &str, Option<&Value>) -> Result<Value, String>;

/// Options of [`review_action`] / [`batch_review`].
#[derive(Default)]
pub struct ReviewOptions<'a> {
    pub now: Option<i64>,
    /// Plaintext goal to carry on any step-up request (shown to the approver).
    pub goal: Option<&'a str>,
    /// Standing "approve class for N hours" grants that can downgrade a step-up to auto.
    pub standing: &'a [Value],
    /// A step-up request is created only together with its canonical approval render: what the approver sees is what is signed.
    /// A renderer that fails makes the review a deny (an action that cannot be shown completely is never put to a human).
    pub renderer: Option<Renderer<'a>>,
    /// DOCUMENTED INSECURE opt-out: without a `renderer` the review is a deny unless this is `true`, which keeps an unbound request.
    pub insecure_unbound_approval: bool,
}

/// Review an intended action against the agent's grant: `{"kind": "auto"}` (no human needed), `{"kind": "deny", "reason"}` (the grant
/// forbids it; no approval fixes that offline) or `{"kind": "step_up", "request"}` (admissible but needs a tier-2/3 co-sign, unless a
/// standing class approval covers it).
pub fn review_action(agent: &AgentHandle, verb: &str, resource: &str, params: Option<&Value>, opts: &ReviewOptions) -> Value {
    review_action_checked(agent, verb, resource, params, opts)
        .unwrap_or_else(|e| json!({"kind": "deny", "reason": format!("approval request could not be built (fail closed): {e}")}))
}

/// [`review_action`] as the reference runs it: a request that cannot be put in the strict canonical form (an out-of-profile parameter)
/// THROWS; `Err` carries that message ([`review_action`] turns it into a deny).
pub fn review_action_checked(agent: &AgentHandle, verb: &str, resource: &str, params: Option<&Value>, opts: &ReviewOptions) -> Result<Value, String> {
    let at = opts.now.unwrap_or_else(now_ms);
    let dr = agent.dry_run(verb, resource, params, Some(at));
    if !dr.allowed {
        return Ok(json!({"kind": "deny", "reason": dr.reason.unwrap_or_else(|| "denied by policy".to_string())}));
    }
    let tier = match dr.t {
        None | Some(1) => return Ok(json!({"kind": "auto"})),
        Some(t) => t,
    };
    if covered_by_any(opts.standing, verb, resource, at) {
        return Ok(json!({"kind": "auto"}));
    }
    let Some(renderer) = opts.renderer else {
        if !opts.insecure_unbound_approval {
            return Ok(json!({"kind": "deny", "reason": "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true"}));
        }
        return step_up(agent, verb, resource, params, opts, at, tier, dr.reason, None);
    };
    let rendered = renderer(verb, resource, params).and_then(|r| approval_render_digest(&r).map(|d| (r, d)));
    match rendered {
        Ok(rd) => step_up(agent, verb, resource, params, opts, at, tier, dr.reason, Some(rd)),
        Err(e) => Ok(json!({"kind": "deny", "reason": format!("approval render failed (fail closed): {}", if e.is_empty() { "unknown" } else { &e })})),
    }
}

#[allow(clippy::too_many_arguments)]
fn step_up(
    agent: &AgentHandle,
    verb: &str,
    resource: &str,
    params: Option<&Value>,
    opts: &ReviewOptions,
    at: i64,
    tier: u8,
    reason: Option<String>,
    render: Option<(Value, String)>,
) -> Result<Value, String> {
    let goal_commit = read_envelope(&agent.grant).and_then(|e| e.get("goal_commit").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
    let mut req = Map::new();
    let idv = json!({"d": "atlas-pca/stepup/v1", "verb": verb, "resource": resource, "params": params.cloned().unwrap_or(Value::Null), "at": at});
    let id = crate::hash_canonical_strict(&idv).ok_or_else(|| crate::canonicalize_strict(&idv).err().unwrap_or_else(|| "canonicalize failed".into()))?;
    req.insert("id".into(), json!(id));
    req.insert("verb".into(), json!(verb));
    req.insert("resource".into(), json!(resource));
    if let Some(p) = params {
        req.insert("params".into(), p.clone());
    }
    req.insert("tier".into(), json!(tier));
    req.insert("reason".into(), json!(reason.unwrap_or_else(|| format!("requires tier {tier} co-sign"))));
    req.insert("goalCommit".into(), json!(goal_commit));
    if let Some(g) = opts.goal {
        req.insert("goal".into(), json!(g));
    }
    req.insert("lineage".into(), build_goal_lineage(agent, verb, resource, params, opts.goal));
    req.insert("r".into(), num(risk_for_review(agent, verb, params)));
    req.insert("requestedAt".into(), json!(at));
    if let Some((r, d)) = render {
        req.insert("render".into(), r);
        req.insert("renderDigest".into(), json!(d));
    }
    Ok(json!({"kind": "step_up", "request": Value::Object(req)}))
}

/// Review a batch of intended actions `{"verb", "resource", "params"?}` (the inbox's "N actions waiting").
pub fn batch_review(agent: &AgentHandle, calls: &[Value], opts: &ReviewOptions) -> Vec<Value> {
    calls
        .iter()
        .map(|c| {
            review_action(
                agent,
                c.get("verb").and_then(Value::as_str).unwrap_or(""),
                c.get("resource").and_then(Value::as_str).unwrap_or(""),
                c.get("params"),
                opts,
            )
        })
        .collect()
}

/// Just the step-up requests from a batch of reviews (what the approver actually sees).
pub fn pending_requests(reviews: &[Value]) -> Vec<Value> {
    reviews.iter().filter(|r| r.get("kind").and_then(Value::as_str) == Some("step_up")).filter_map(|r| r.get("request").cloned()).collect()
}

/// Mint a standing class approval ("approve stripe.refund + gmail.send for the next 4 hours").
pub fn approve_class(verbs: &[&str], ttl_ms: i64, by: &str, now: Option<i64>, resource: Option<&str>) -> Value {
    let granted = now.unwrap_or_else(now_ms);
    let mut sorted: Vec<&str> = verbs.to_vec();
    sorted.sort_unstable(); // byte order of the UTF-8 text, the reference's compareUtf8
    let id = hash_canonical(&json!({"d": "atlas-pca/class-approval/v1", "verbs": sorted, "resource": resource, "grantedAt": granted, "by": by}));
    let mut out = Map::new();
    out.insert("id".into(), json!(id));
    out.insert("verbs".into(), json!(verbs));
    if let Some(r) = resource {
        out.insert("resource".into(), json!(r));
    }
    out.insert("grantedAt".into(), json!(granted));
    out.insert("ttlMs".into(), json!(ttl_ms));
    out.insert("by".into(), json!(by));
    Value::Object(out)
}

fn resource_matches(pattern: Option<&str>, resource: &str) -> bool {
    match pattern {
        None | Some("*") => true,
        Some(p) => match p.strip_suffix('*') {
            Some(prefix) => resource.starts_with(prefix),
            None => p == resource,
        },
    }
}

/// Does this standing approval still cover (verb, resource) at `now`?
pub fn class_approval_covers(a: &Value, verb: &str, resource: &str, now: i64) -> bool {
    let (Some(granted), Some(ttl)) = (a.get("grantedAt").and_then(Value::as_i64), a.get("ttlMs").and_then(Value::as_i64)) else { return false };
    if now < granted || now >= granted.saturating_add(ttl) {
        return false;
    }
    let in_verbs = a.get("verbs").and_then(Value::as_array).is_some_and(|vs| vs.iter().any(|v| v.as_str() == Some(verb)));
    in_verbs && resource_matches(a.get("resource").and_then(Value::as_str), resource)
}

/// Is (verb, resource) covered by ANY active standing approval?
pub fn covered_by_any(approvals: &[Value], verb: &str, resource: &str, now: i64) -> bool {
    approvals.iter().any(|a| class_approval_covers(a, verb, resource, now))
}

/// Record a human's decision (`approve` | `deny`) on a request (pure data for the audit trail).
pub fn record_decision(request: &Value, decision: &str, by: &str, at: Option<i64>) -> Value {
    json!({"requestId": request.get("id").cloned().unwrap_or(Value::Null), "decision": decision, "by": by, "at": at.unwrap_or_else(now_ms)})
}

/// Apply a human co-sign to the trust budget: a partial recharge (rho per co-sign), or a full recharge to bMax with `full`. The ONLY
/// thing that raises the budget, so the safety bound holds between two co-signs.
pub fn apply_cosign(budget: &TrustBudget, policy: &RiskPolicy, now: f64, full: bool) -> TrustBudget {
    if full {
        recharge_full(policy.b_max, now)
    } else {
        recharge(budget, policy.rho, policy.b_max, now)
    }
}

/// Narrow a capability to expire `ttl_ms` from `now` by appending an `expires` caveat signed by the holder. Caveats are conjunctive and
/// append-only, so this only ever restricts.
pub fn time_box(parent: &Value, holder: &KeyPair, ttl_ms: f64, now: Option<f64>) -> Result<Value, String> {
    // JavaScript number arithmetic: a fractional or huge ttl is added as written, and the strict canonical form decides what it accepts
    let at = now.unwrap_or_else(|| now_ms() as f64) + ttl_ms;
    if !at.is_finite() {
        return Err("canonicalize: expires at is not a finite number".into()); // a NaN or infinite instant is never written as null
    }
    let at = if at.fract() == 0.0 && at.abs() <= 9_007_199_254_740_991.0 { json!(at as i64) } else { json!(at) };
    attenuate(parent, &json!([{"type": "expires", "at": at}]), holder, &Suite::default())
}

#[cfg(test)]
mod time_box_tests {
    use super::*;

    #[test]
    fn the_expiry_is_javascript_arithmetic_and_a_non_finite_one_is_refused() {
        let principal = KeyPair::generate().unwrap();
        let holder = KeyPair::generate().unwrap();
        let root = crate::agent::mint_root(&principal, &holder.public, &json!([]), None, &Suite::default()).unwrap();
        let at = |ttl: f64, now: f64| time_box(&root, &holder, ttl, Some(now)).map(|g| g["caveats"][0]["at"].clone());
        assert_eq!(at(10.0, 5.0), Ok(json!(15)));
        assert_eq!(at(1.5, 10.0), Ok(json!(11.5)));
        assert_eq!(at(-5.0, 5.0), Ok(json!(0)));
        assert_eq!(at(1e300, 1e300), Err("canonicalize: integer outside the safe range (|n| > 2^53-1)".to_string()));
        assert!(at(f64::NAN, 1.0).is_err());
        assert!(at(f64::INFINITY, 1.0).is_err());
    }
}
