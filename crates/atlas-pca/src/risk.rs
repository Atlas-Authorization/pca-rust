//! Risk functional, threshold map and decaying trust budget (spec section 10; port of packages/pca/src/risk.ts) plus the policy VM's
//! release decision over them (policy-vm.ts steps 3-5, the Dafny kernels `ReqThr`, `AdmitOf`, `DecideCore`).
//! Pure and deterministic. Time is epoch milliseconds; `lambda` is budget drained PER SECOND. Numbers are JavaScript doubles: every
//! operation keeps the reference's order and NaN behaviour (`js_max` / `js_min` propagate NaN like `Math.max` / `Math.min`), so the
//! results are bit-identical to the reference. Non-finite inputs fail closed (treated as worst case).
use crate::intent_v2::js_number_string;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// `Math.max`: NaN if either side is NaN.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a > b {
        a
    } else {
        b
    }
}

/// `Math.min`: NaN if either side is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a < b {
        a
    } else {
        b
    }
}

/// `x < 0 ? 0 : x > 1 ? 1 : x` (a NaN stays NaN).
fn clamp01(x: f64) -> f64 {
    if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// Non-finite => worst; else clamp to [0,1].
fn unit(x: f64, worst: f64) -> f64 {
    if x.is_finite() { clamp01(x) } else { worst }
}

/// A weight: only a finite positive value counts.
fn wt(x: f64) -> f64 {
    if x.is_finite() && x > 0.0 { x } else { 0.0 }
}

/// A non-negative finite amount, else 0.
fn nz(x: f64) -> f64 {
    if x.is_finite() && x > 0.0 { x } else { 0.0 }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskWeights {
    /// semantic distance
    pub alpha: f64,
    /// irreversibility
    pub beta: f64,
    /// blast radius
    pub gamma: f64,
    /// taint
    pub delta: f64,
    /// agent uncertainty
    pub epsilon: f64,
    /// age since human touch
    pub zeta: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskPolicy {
    pub weights: RiskWeights,
    pub theta1: f64,
    pub theta2: f64,
    /// cost scale: c(A) = kappa * r(A)
    pub kappa: f64,
    /// passive leak, budget units per second
    pub lambda: f64,
    /// recharge per human co-sign
    pub rho: f64,
    pub b_max: f64,
}

/// All normalized to [0,1].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskInputs {
    pub semantic_distance: f64,
    pub reversibility: f64,
    pub blast_radius: f64,
    pub taint: f64,
    pub confidence: f64,
    pub age: f64,
}

/// The worst case for every input (policy-vm.ts `WORST`).
pub const WORST: RiskInputs = RiskInputs { semantic_distance: 1.0, reversibility: 0.0, blast_radius: 1.0, taint: 1.0, confidence: 0.0, age: 1.0 };

pub const DEFAULT_RISK_POLICY: RiskPolicy = RiskPolicy {
    weights: RiskWeights { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 },
    theta1: 0.25,
    theta2: 0.6,
    kappa: 1.0,
    lambda: 0.0005,
    rho: 0.5,
    b_max: 1.0,
};

/// A JSON number as JavaScript's `Number.isFinite` sees it (a string, null or missing member is not finite).
fn finite(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| if v.is_number() { v.as_f64() } else { None }).filter(|f| f.is_finite())
}

/// `Some(error)` if the policy is not well-formed (risk.ts `validateRiskPolicy`, same texts).
pub fn validate_risk_policy(p: &Value) -> Option<String> {
    if !(p.is_object() || p.is_array()) {
        return Some("risk_policy must be an object".into());
    }
    let w = p.get("weights").filter(|w| w.is_object() || w.is_array());
    let Some(w) = w else { return Some("risk_policy.weights missing".into()) };
    for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        if !finite(w.get(k)).is_some_and(|x| x >= 0.0) {
            return Some(format!("risk_policy.weights.{k} must be finite and >= 0"));
        }
    }
    for k in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"] {
        if finite(p.get(k)).is_none() {
            return Some(format!("risk_policy.{k} must be finite"));
        }
    }
    let g = |k: &str| finite(p.get(k)).unwrap_or(f64::NAN);
    if g("theta1") < 0.0 || g("theta2") < g("theta1") {
        return Some("risk_policy requires 0 <= theta1 <= theta2".into());
    }
    if g("kappa") <= 0.0 {
        return Some("risk_policy.kappa must be > 0".into());
    }
    if g("lambda") < 0.0 || g("rho") < 0.0 || g("bMax") < 0.0 {
        return Some("risk_policy lambda/rho/bMax must be >= 0".into());
    }
    None
}

impl RiskPolicy {
    /// A validated policy from its wire form (`Err` carries the [`validate_risk_policy`] text).
    pub fn from_value(p: &Value) -> Result<RiskPolicy, String> {
        if let Some(e) = validate_risk_policy(p) {
            return Err(e);
        }
        let g = |o: &Value, k: &str| finite(o.get(k)).unwrap_or(0.0);
        let w = &p["weights"];
        Ok(RiskPolicy {
            weights: RiskWeights { alpha: g(w, "alpha"), beta: g(w, "beta"), gamma: g(w, "gamma"), delta: g(w, "delta"), epsilon: g(w, "epsilon"), zeta: g(w, "zeta") },
            theta1: g(p, "theta1"),
            theta2: g(p, "theta2"),
            kappa: g(p, "kappa"),
            lambda: g(p, "lambda"),
            rho: g(p, "rho"),
            b_max: g(p, "bMax"),
        })
    }
}

/// r = clamp( a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1 ). Monotone non-decreasing in d, bl, taint, age and
/// non-increasing in rev, conf (weights are clamped to >= 0).
pub fn risk_score(i: &RiskInputs, w: &RiskWeights) -> f64 {
    let r = wt(w.alpha) * unit(i.semantic_distance, 1.0)
        + wt(w.beta) * (1.0 - unit(i.reversibility, 0.0))
        + wt(w.gamma) * unit(i.blast_radius, 1.0)
        + wt(w.delta) * unit(i.taint, 1.0)
        + wt(w.epsilon) * (1.0 - unit(i.confidence, 0.0))
        + wt(w.zeta) * unit(i.age, 1.0);
    clamp01(r)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredThreshold {
    pub t: u8,
    /// 0 claim, 1 standard, 2 strong
    pub proof: u8,
    pub optimistic_allowed: bool,
}

impl RequiredThreshold {
    pub fn proof_name(&self) -> &'static str {
        match self.proof {
            0 => "claim",
            1 => "standard",
            _ => "strong",
        }
    }
}

/// Section 10 piecewise map (the Dafny `ReqThr`). r <= theta1 -> t=1 (claim, optimistic ok unless irreversible); theta1 < r <= theta2 ->
/// t=2 (standard); r > theta2 -> t=3 (strong). A non-finite r is the worst case (r = 1).
pub fn required_threshold(r: f64, theta1: f64, theta2: f64, irreversible: bool) -> RequiredThreshold {
    let x = if r.is_finite() { r } else { 1.0 };
    if x <= theta1 {
        RequiredThreshold { t: 1, proof: 0, optimistic_allowed: !irreversible }
    } else if x <= theta2 {
        RequiredThreshold { t: 2, proof: 1, optimistic_allowed: false }
    } else {
        RequiredThreshold { t: 3, proof: 2, optimistic_allowed: false }
    }
}

/// Raise a threshold to at least `min_t` and keep it coherent; never lowers anything (the Dafny `Escalate`).
pub fn escalate_threshold(rt: RequiredThreshold, min_t: u8) -> RequiredThreshold {
    let t = if min_t > rt.t { min_t } else { rt.t };
    let floor = t - 1;
    RequiredThreshold { t, proof: if rt.proof >= floor { rt.proof } else { floor }, optimistic_allowed: if t > 1 { false } else { rt.optimistic_allowed } }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrustBudget {
    /// current budget in [0, b_max]
    pub b: f64,
    /// last human-touch time (ms)
    pub tau: f64,
    /// time (ms) the budget was last brought up to date by `leak`; defaults to tau. Prevents double-leaking.
    pub as_of: Option<f64>,
}

/// c(A) = kappa*r(A). A non-finite r costs r = 1.
pub fn cost(r: f64, kappa: f64) -> f64 {
    nz(kappa) * clamp01(if r.is_finite() { r } else { 1.0 })
}

/// Passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same `now`.
pub fn leak(b: &TrustBudget, now: f64, lambda: f64) -> TrustBudget {
    let from = b.as_of.unwrap_or(b.tau);
    let dt = if now.is_finite() && from.is_finite() { js_max(0.0, now - from) } else { 0.0 };
    let bb = js_max(0.0, b.b - nz(lambda) * (dt / 1000.0));
    TrustBudget { b: bb, tau: b.tau, as_of: Some(if now.is_finite() { js_max(now, from) } else { from }) }
}

/// B <- max(0, B - cost). Callers must check B >= cost first ([`admit`] does).
pub fn debit(b: &TrustBudget, c: f64) -> TrustBudget {
    TrustBudget { b: js_max(0.0, b.b - nz(c)), ..*b }
}

/// Human co-sign recharge: B <- min(b_max, B + rho), tau <- now. The ONLY way budget increases.
pub fn recharge(b: &TrustBudget, rho: f64, b_max: f64, now: f64) -> TrustBudget {
    TrustBudget { b: js_min(nz(b_max), b.b + nz(rho)), tau: now, as_of: Some(now) }
}

/// Full goal re-confirmation: B <- b_max, tau <- now.
pub fn recharge_full(b_max: f64, now: f64) -> TrustBudget {
    TrustBudget { b: nz(b_max), tau: now, as_of: Some(now) }
}

/// Default horizon of [`age_since_touch`]: one hour.
pub const DEFAULT_AGE_HORIZON_MS: f64 = 3_600_000.0;

/// Normalized age since the last human touch: clamp((now - tau)/horizon, 0, 1).
pub fn age_since_touch(b: &TrustBudget, now: f64, horizon_ms: f64) -> f64 {
    if !now.is_finite() || !b.tau.is_finite() || !(horizon_ms > 0.0) {
        return 1.0;
    }
    clamp01((now - b.tau) / horizon_ms)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// t=1 auto path: no human, no co-signer needed.
    pub admit: bool,
    pub need_step_up: bool,
    pub t: u8,
    /// The action proceeds WITHOUT a human co-signature (t=1 auto-admit, or t=2 where the guardian auto-cosigns) and so MUST be
    /// debited kappa*r. Only t=3 (a human step-up) is unmetered.
    pub metered: bool,
}

/// The Dafny `AdmitOf`: `t` is the required threshold of r, `budget_covers_cost` is `B >= cost(r)` computed on doubles (false for NaN).
pub fn admit_of(t: u8, budget_covers_cost: bool) -> Admission {
    if t < 3 && !budget_covers_cost {
        Admission { admit: false, need_step_up: true, t: 3, metered: false }
    } else if t == 1 {
        Admission { admit: true, need_step_up: false, t: 1, metered: true }
    } else if t == 2 {
        Admission { admit: false, need_step_up: true, t: 2, metered: true }
    } else {
        Admission { admit: false, need_step_up: true, t: 3, metered: false }
    }
}

/// The machine-only band is t=1 AND t=2, so both are metered: an action at t<3 proceeds only if B >= c(A) and is then debited
/// kappa*r; when the budget cannot cover it the action escalates to t=3. The budget must already be leaked up to the decision time.
pub fn admit(r: f64, b: &TrustBudget, p: &RiskPolicy) -> Admission {
    let t = required_threshold(r, p.theta1, p.theta2, false).t;
    admit_of(t, b.b >= cost(r, p.kappa))
}

/// Between two consecutive human recharges the total risk of machine-only actions is at most b_max/kappa.
pub fn safety_bound(b_max: f64, kappa: f64) -> f64 {
    if kappa > 0.0 { js_max(0.0, b_max) / kappa } else { 0.0 }
}

/// Allocate a sub-agent budget B_sub = alloc, guarded by 0 <= alloc <= parent.B.
pub fn sub_budget(parent: &TrustBudget, alloc: f64) -> Result<TrustBudget, String> {
    if !alloc.is_finite() || alloc < 0.0 {
        return Err("allocation must be finite and >= 0".into());
    }
    if alloc > parent.b {
        return Err("allocation exceeds parent remaining budget".into());
    }
    Ok(TrustBudget { b: alloc, tau: parent.tau, as_of: Some(parent.as_of.unwrap_or(parent.tau)) })
}

/// Consolidated debit: a sub-agent's debit ALSO debits the parent. Fails (no state change) if either cannot cover `c`.
pub fn debit_consolidated(parent: &TrustBudget, sub: &TrustBudget, c: f64) -> Result<(TrustBudget, TrustBudget), String> {
    let x = nz(c);
    if sub.b < x {
        return Err("sub-agent budget insufficient".into());
    }
    if parent.b < x {
        return Err("parent budget insufficient".into());
    }
    Ok((debit(parent, x), debit(sub, x)))
}

/// Consolidated debit along a root-to-leaf budget-subtree PATH: every node must cover `c` or nothing is debited.
pub fn debit_consolidated_path(path: &[TrustBudget], c: f64) -> Result<Vec<TrustBudget>, String> {
    let x = nz(c);
    for (i, n) in path.iter().enumerate() {
        if !(n.b >= x) {
            return Err(format!("budget node at depth {i} insufficient (need {}, have {})", js_number_string(x), js_number_string(n.b)));
        }
    }
    Ok(path.iter().map(|n| debit(n, x)).collect())
}

// ---- plan geodesic -------------------------------------------------------------------------------------------------------------

const PRE_KEYS: [&str; 4] = ["after", "depends_on", "requires", "nodes"];
const POST_KEYS: [&str; 4] = ["before", "enables", "then", "next"];

/// The node ids a `pre` / `post` member names: a bare id or array, or the same under the given keys.
fn refs_of(x: Option<&Value>, keys: &[&str]) -> Vec<String> {
    fn add(v: Option<&Value>, out: &mut Vec<String>) {
        match v {
            Some(Value::String(s)) => out.push(s.clone()),
            Some(Value::Array(a)) => out.extend(a.iter().filter_map(|s| s.as_str().map(str::to_string))),
            _ => {}
        }
    }
    let mut out = Vec::new();
    add(x, &mut out);
    if let Some(Value::Object(m)) = x {
        for k in keys {
            add(m.get(*k), &mut out);
        }
    }
    out
}

/// Normalized geodesic distance in the committed plan DAG, in [0,1] (risk.ts `planGeodesic`): BFS hop count over the UNDIRECTED graph
/// of the nodes' `pre` / `post` references divided by (n-1), unreachable = 1, index distance when the plan declares no edges, an
/// unknown node = 1, the same node = 0.
pub fn plan_geodesic(plan: &[Value], from_node_id: &str, to_goal_node_id: &str) -> f64 {
    let mut idx: HashMap<&str, usize> = HashMap::new();
    for (i, n) in plan.iter().enumerate() {
        if let Some(id) = n.get("id").and_then(Value::as_str) {
            idx.insert(id, i);
        }
    }
    let (Some(&a), Some(&b)) = (idx.get(from_node_id), idx.get(to_goal_node_id)) else { return 1.0 };
    if a == b {
        return 0.0;
    }
    let n = plan.len();
    let mut adj: Vec<std::collections::BTreeSet<usize>> = vec![Default::default(); n];
    let mut edges = 0usize;
    let mut link = |i: usize, j: usize, adj: &mut Vec<std::collections::BTreeSet<usize>>| {
        if i == j {
            return;
        }
        if !adj[i].contains(&j) {
            edges += 1;
        }
        adj[i].insert(j);
        adj[j].insert(i);
    };
    for (i, node) in plan.iter().enumerate() {
        for id in refs_of(node.get("pre"), &PRE_KEYS) {
            if let Some(&j) = idx.get(id.as_str()) {
                link(j, i, &mut adj);
            }
        }
        for id in refs_of(node.get("post"), &POST_KEYS) {
            if let Some(&j) = idx.get(id.as_str()) {
                link(i, j, &mut adj);
            }
        }
    }
    if edges == 0 {
        return clamp01(a.abs_diff(b) as f64 / (n - 1) as f64);
    }
    let mut dist = vec![-1i64; n];
    dist[a] = 0;
    let mut q = vec![a];
    let mut h = 0;
    while h < q.len() {
        let u = q[h];
        h += 1;
        for &v in &adj[u] {
            if dist[v] == -1 {
                dist[v] = dist[u] + 1;
                q.push(v);
            }
        }
    }
    if dist[b] < 0 { 1.0 } else { clamp01(dist[b] as f64 / (n - 1) as f64) }
}

// ---- the policy VM's release decision (steps 3-5) -------------------------------------------------------------------------------

/// `Number.prototype.toFixed(3)` of a double in [0, 1]: ties pick the larger integer (Rust's `{:.3}` rounds half to even).
pub fn js_to_fixed3(x: f64) -> String {
    if !x.is_finite() || x < 0.0 {
        return format!("{x:.3}");
    }
    let bits = x.to_bits();
    let (exp, frac) = (((bits >> 52) & 0x7ff) as i32, bits & ((1u64 << 52) - 1));
    // x = m * 2^e exactly
    let (m, e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let n: u128 = if e >= 0 {
        (m as u128).checked_shl(e as u32).and_then(|v| v.checked_mul(1000)).unwrap_or(u128::MAX)
    } else if -e > 120 {
        0
    } else {
        let denom = 1u128 << (-e) as u32;
        ((m as u128) * 1000 + denom / 2) / denom
    };
    format!("{}.{:03}", n / 1000, n % 1000)
}

/// The Dafny `DecideCore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDecision {
    pub release: bool,
    pub admit: bool,
    pub need_step_up: bool,
    pub threshold: RequiredThreshold,
    pub debit: bool,
}

pub fn decide_core(pr_ok: bool, cv_ok: bool, dcv_ok: bool, chain_ok: bool, rt: RequiredThreshold, adm: Admission) -> CoreDecision {
    let release = pr_ok && cv_ok && dcv_ok && chain_ok;
    CoreDecision { release, admit: release && adm.admit, need_step_up: if release { adm.need_step_up } else { true }, threshold: escalate_threshold(rt, adm.t), debit: release && adm.metered }
}

/// Reversibility classes eligible for the optimistic fast path (policy-vm.ts `FAST_PATH_ELIGIBLE_CLASSES`); anything else, a missing
/// class included, is treated as irreversible.
pub fn fast_path_eligible(class: Option<&str>) -> bool {
    matches!(class, Some("reversible" | "rate_limited" | "costly"))
}

pub struct RiskStep<'a> {
    pub policy: &'a RiskPolicy,
    /// The RS-supplied risk inputs by camelCase name (`semanticDistance`, `reversibility`, `blastRadius`, `taint`, `confidence`, `age`);
    /// only a finite number counts, everything else is the worst case.
    pub risk: &'a Map<String, Value>,
    pub plan: Option<&'a [Value]>,
    pub node_id: Option<&'a str>,
    pub goal_node_id: Option<&'a str>,
    pub budget: TrustBudget,
    pub now: f64,
    pub age_horizon_ms: Option<f64>,
    /// The signed `caution`: a monotone floor on r (clamped to [0, 1]).
    pub r_floor: Option<f64>,
    pub reversibility_class: Option<&'a str>,
    /// The caller's verdicts for the predicates, the envelope/root caveats, the delegated caveats and the chain.
    pub pr_ok: bool,
    pub cv_ok: bool,
    pub dcv_ok: bool,
    pub chain_ok: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RiskDecision {
    pub release_guardian_share: bool,
    pub required_threshold: RequiredThreshold,
    pub r: f64,
    pub admit: bool,
    pub need_step_up: bool,
    pub reasons: Vec<String>,
    pub budget: TrustBudget,
    /// The release was metered: the caller stores `budget` (the cost was debited).
    pub debit: bool,
}

const RISK_KEYS: [&str; 6] = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"];

/// Steps 3-5 of the policy VM's `decide`: the risk r, the threshold band, the budget admission, the escalation and the release / admit /
/// debit decision. `reasons` are the informational ones in reference order.
pub fn decide_risk(s: &RiskStep<'_>) -> RiskDecision {
    let p = s.policy;
    let leaked = leak(&s.budget, s.now, p.lambda);
    let mut reasons: Vec<String> = Vec::new();
    let num = |k: &str| finite(s.risk.get(k));
    let mut inputs = WORST;
    if let Some(v) = num("semanticDistance") {
        inputs.semantic_distance = v;
    }
    if let Some(v) = num("reversibility") {
        inputs.reversibility = v;
    }
    if let Some(v) = num("blastRadius") {
        inputs.blast_radius = v;
    }
    if let Some(v) = num("taint") {
        inputs.taint = v;
    }
    if let Some(v) = num("confidence") {
        inputs.confidence = v;
    }
    if let Some(v) = num("age") {
        inputs.age = v;
    }
    // the inputs the server did not supply (age is derived below, never "missing")
    let mut missing: Vec<&str> = RISK_KEYS.iter().copied().filter(|k| *k != "age" && num(k).is_none()).collect();
    if let (Some(plan), false) = (s.plan, s.risk.contains_key("semanticDistance")) {
        let goal = s.goal_node_id.or_else(|| plan.last().and_then(|n| n.get("id")).and_then(Value::as_str));
        inputs.semantic_distance = match (s.node_id, goal) {
            (Some(n), Some(g)) => plan_geodesic(plan, n, g),
            _ => 1.0,
        };
        missing.retain(|k| *k != "semanticDistance");
    }
    if !s.risk.contains_key("age") {
        inputs.age = age_since_touch(&leaked, s.now, s.age_horizon_ms.unwrap_or(DEFAULT_AGE_HORIZON_MS));
    }
    if !missing.is_empty() {
        reasons.push(format!("risk input(s) missing, assumed worst case: {}", missing.join(", ")));
    }
    let r_floor = match s.r_floor {
        Some(f) if f.is_finite() => js_min(1.0, js_max(0.0, f)),
        _ => 0.0,
    };
    let r = js_max(risk_score(&inputs, &p.weights), r_floor);

    // only a RECOGNIZED non-irreversible class is fast-path eligible
    let irreversible = !fast_path_eligible(s.reversibility_class);
    let rt = required_threshold(r, p.theta1, p.theta2, irreversible);
    let adm = admit_of(required_threshold(r, p.theta1, p.theta2, false).t, leaked.b >= cost(r, p.kappa));
    if adm.need_step_up {
        reasons.push(if rt.t < 3 && adm.t == 3 { "trust budget depleted: human recharge required".to_string() } else { format!("risk {} exceeds auto threshold: step-up to t={}", js_to_fixed3(r), adm.t) });
    }
    let dec = decide_core(s.pr_ok, s.cv_ok, s.dcv_ok, s.chain_ok, rt, adm);
    let budget = if dec.debit { debit(&leaked, cost(r, p.kappa)) } else { leaked };
    RiskDecision { release_guardian_share: dec.release, required_threshold: dec.threshold, r, admit: dec.admit, need_step_up: dec.need_step_up, reasons, budget, debit: dec.debit }
}

#[cfg(test)]
#[path = "k05f_risk_test.rs"]
mod k05f_risk_test;
