//! The behavioral immune system: "authorization that gets more paranoid when something is off". It learns each principal's NORMAL risk
//! distribution from the stream of their agents' actions, detects drift, volatility and violation bursts, and under suspicion PROPOSES a
//! tightened risk policy for the next epoch (lower thetas so more actions need a human, higher kappa so each costs more budget). When
//! behaviour returns to baseline the proposal relaxes back to the base policy exactly. It never mutates a signed grant.
//!
//! Guaranteed (deterministic, enforced in code): the adapted policy is a pure function of (base policy, state); it never widens the base
//! (kappa' >= kappa, theta' <= theta, everything else equal, see [`no_widen_violation`]); score 0 restores the base exactly; a malformed
//! state or score fails CLOSED to the most restrictive level; a tightening proposal is guardian-signed, bound to the base policy and state
//! digests, and applies only with a strictly higher epoch. NOT guaranteed: the anomaly score itself is a heuristic (EWMA and z-score over
//! one principal's history); a slow attacker who drifts the baseline can game it, and it is no proof an agent is compromised or benign.
//!
//! JSON-valued like the reference (policies, assessments, proposals); numbers follow JavaScript coercion where the reference coerces.
//! A state is `{baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}`; an observation `{r, at, stepUp?, denied?}`.
use crate::actions::js_to_number;
use crate::actions_kit_import::common::{hash_canonical_lenient, lenient};
use crate::agent::KeyPair;
use crate::intent_v2::js_number_string;
use crate::kv::AtomicKv;
use crate::oauth::{js_str, truthy};
use crate::risk::validate_risk_policy;
use serde_json::{json, Map, Value};

const MAX_COUNT: f64 = 1e9;
const MAX_SAFE: f64 = 9007199254740991.0;
const ALPHA: f64 = 0.3;
const HALF_LIFE_MS: f64 = 3_600_000.0;
const DRIFT_Z_SAT: f64 = 3.0;
const STEP_UP_SAT: f64 = 5.0;
const DENY_SAT: f64 = 3.0;

/// Domain prefix of the signed tightening message.
pub const TIGHTENING_DOMAIN: &str = "atlas-pca/immune-tightening/v1\0";

fn num(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

/// `v.k`: a TypeError on null, `undefined` (None) on anything that has no such member.
fn prop<'a>(v: &'a Value, k: &str) -> Result<Option<&'a Value>, String> {
    match v {
        Value::Null => Err(format!("Cannot read properties of null (reading '{k}')")),
        _ => Ok(v.get(k)),
    }
}

/// `Number.isFinite(x)`: a number type only (a string, null or missing member is not finite).
fn finite_num(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| if v.is_number() { v.as_f64() } else { None }).filter(|f| f.is_finite())
}

/// `Number.isSafeInteger(x)`.
fn safe_int(v: Option<&Value>) -> Option<f64> {
    finite_num(v).filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE)
}

/// `Math.max(0, Math.min(1, x))` (a NaN stays NaN).
fn clamp01(x: f64) -> f64 {
    if x.is_nan() {
        f64::NAN
    } else {
        x.min(1.0).max(0.0)
    }
}

/// `a === b` for JSON members (objects and arrays are never identical).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// `Number.prototype.toFixed(d)` for d >= 1: ties pick the larger integer (exact decimal expansion of the double).
pub fn to_fixed(x: f64, d: u32) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x < 0.0 {
        return format!("-{}", to_fixed(-x, d));
    }
    if !x.is_finite() || x >= 1e21 {
        return js_number_string(x);
    }
    let scale = 10u128.pow(d);
    let bits = x.to_bits();
    let (exp, frac) = (((bits >> 52) & 0x7ff) as i32, bits & ((1u64 << 52) - 1));
    let (m, e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let n: u128 = if e >= 0 {
        ((m as u128) << e as u32) * scale
    } else if -e > 120 {
        0
    } else {
        let denom = 1u128 << (-e) as u32;
        ((m as u128) * scale + denom / 2) / denom
    };
    format!("{}.{:0width$}", n / scale, n % scale, width = d as usize)
}

// ---- state --------------------------------------------------------------------------------------------------------------------

/// A validated immune state.
#[derive(Debug, Clone, PartialEq)]
pub struct ImmuneState {
    /// Baseline sample count (Welford).
    pub n: f64,
    pub mean: f64,
    /// Sum of squared deviations (Welford M2).
    pub m2: f64,
    /// EWMA of recent risk.
    pub ewma: f64,
    /// Decayed count of recent step-ups.
    pub step_ups: f64,
    /// Decayed count of recent denies.
    pub denies: f64,
    pub last_at: f64,
    pub seeded: bool,
}

impl ImmuneState {
    /// The state of a principal with no history.
    pub fn initial() -> ImmuneState {
        ImmuneState { n: 0.0, mean: 0.0, m2: 0.0, ewma: 0.0, step_ups: 0.0, denies: 0.0, last_at: 0.0, seeded: false }
    }

    /// The state's wire form.
    pub fn to_value(&self) -> Value {
        json!({
            "baseline": { "n": num(self.n), "mean": num(self.mean), "m2": num(self.m2) },
            "ewma": num(self.ewma), "stepUps": num(self.step_ups), "denies": num(self.denies), "lastAt": num(self.last_at), "seeded": self.seeded,
        })
    }

    /// A state from its wire form; `Err` carries the [`validate_immune_state`] reason.
    pub fn from_value(v: &Value) -> Result<ImmuneState, String> {
        if let Some(bad) = validate_immune_state(v) {
            return Err(bad);
        }
        let f = |x: Option<&Value>| x.and_then(Value::as_f64).unwrap_or(0.0);
        let b = &v["baseline"];
        Ok(ImmuneState {
            n: f(b.get("n")),
            mean: f(b.get("mean")),
            m2: f(b.get("m2")),
            ewma: f(v.get("ewma")),
            step_ups: f(v.get("stepUps")),
            denies: f(v.get("denies")),
            last_at: f(v.get("lastAt")),
            seeded: v.get("seeded").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

/// The elapsed time of a decay is counted in 1/1024ths of a half-life.
const DECAY_STEPS_PER_HALF_LIFE: f64 = 1024.0;
/// 2^(-1/1024) rounded to the nearest double.
const DECAY_STEP: f64 = 0.9993233275026507;

fn decay(count: f64, dt_ms: f64, half_life_ms: f64) -> f64 {
    if dt_ms <= 0.0 || count == 0.0 {
        return count;
    }
    // quantized down to whole 1/1024ths of a half-life; 0.5 and 2^(-1/1024) applied by repeated multiplication (no pow, exp or log,
    // which differ in the last digit between libm implementations), one IEEE multiplication at a time and never fused
    let u = ((dt_ms * DECAY_STEPS_PER_HALF_LIFE) / half_life_ms).floor();
    if u.is_nan() {
        return f64::NAN;
    }
    if u >= DECAY_STEPS_PER_HALF_LIFE * 1100.0 {
        return count * 0.0; // 0.5^1100 underflows
    }
    let k = (u / DECAY_STEPS_PER_HALF_LIFE).floor();
    let m = u - k * DECAY_STEPS_PER_HALF_LIFE;
    let mut f = 1.0f64;
    for _ in 0..k as u64 {
        f *= 0.5;
    }
    for _ in 0..m as u64 {
        f *= DECAY_STEP;
    }
    count * f
}

/// Fold one observation into the state (baseline, recent EWMA, decayed step-up and deny counters). A non-finite risk counts as 0; a
/// non-finite timestamp advances no clock (it pins to the last good one), so the counters can never turn NaN.
pub fn observe(state: &ImmuneState, r: f64, at: f64, step_up: bool, denied: bool) -> ImmuneState {
    observe_cfg(state, r, at, step_up, denied, &ImmuneConfig::default())
}

/// The tunables of the immune system (the reference's `ImmuneConfig`); the default is [`ImmuneConfig::default`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImmuneConfig {
    pub alpha: f64,
    pub half_life_ms: f64,
    pub drift_z_sat: f64,
    pub step_up_sat: f64,
    pub deny_sat: f64,
}

impl Default for ImmuneConfig {
    fn default() -> Self {
        ImmuneConfig { alpha: ALPHA, half_life_ms: HALF_LIFE_MS, drift_z_sat: DRIFT_Z_SAT, step_up_sat: STEP_UP_SAT, deny_sat: DENY_SAT }
    }
}

/// [`observe`] under an explicit configuration.
pub fn observe_cfg(state: &ImmuneState, r: f64, at: f64, step_up: bool, denied: bool, cfg: &ImmuneConfig) -> ImmuneState {
    let r = clamp01(if r.is_finite() { r } else { 0.0 });
    let at = if at.is_finite() { at } else { state.last_at };
    let dt = if state.seeded { (at - state.last_at).max(0.0) } else { 0.0 };
    let n = state.n + 1.0;
    let delta = r - state.mean;
    let mean = state.mean + delta / n;
    let m2 = state.m2 + delta * (r - mean);
    let ewma = if state.seeded { cfg.alpha * r + (1.0 - cfg.alpha) * state.ewma } else { r };
    let step_ups = decay(state.step_ups, dt, cfg.half_life_ms) + if step_up { 1.0 } else { 0.0 };
    let denies = decay(state.denies, dt, cfg.half_life_ms) + if denied { 1.0 } else { 0.0 };
    ImmuneState { n, mean, m2, ewma, step_ups, denies, last_at: at, seeded: true }
}

/// [`observe`] over an observation object `{r, at, stepUp?, denied?}` (null is refused as the reference's TypeError).
pub fn observe_value(state: &ImmuneState, obs: &Value) -> Result<ImmuneState, String> {
    let r = finite_num(prop(obs, "r")?).unwrap_or(0.0);
    let at = finite_num(prop(obs, "at")?).unwrap_or(f64::NAN);
    Ok(observe(state, r, at, truthy(prop(obs, "stepUp")?), truthy(prop(obs, "denied")?)))
}

fn in_range(x: Option<&Value>, lo: f64, hi: f64) -> bool {
    finite_num(x).is_some_and(|f| f >= lo && f <= hi)
}

/// The reason a state is malformed (non-finite, negative, out of bound), or `None`.
pub fn validate_immune_state(s: &Value) -> Option<String> {
    if !(s.is_object() || s.is_array()) {
        return Some("state must be an object".into());
    }
    let Some(b) = s.get("baseline").filter(|b| b.is_object() || b.is_array()) else { return Some("baseline missing".into()) };
    let n = b.get("n");
    let neg_zero = finite_num(n).is_some_and(|f| f == 0.0 && f.is_sign_negative());
    if !in_range(n, 0.0, MAX_COUNT) || finite_num(n).is_some_and(|f| f.fract() != 0.0) || neg_zero {
        return Some("baseline.n must be an integer in [0, 1e9]".into());
    }
    if !in_range(b.get("mean"), 0.0, 1.0) {
        return Some("baseline.mean must be in [0, 1]".into());
    }
    if !in_range(b.get("m2"), 0.0, MAX_COUNT) {
        return Some("baseline.m2 must be finite and >= 0".into());
    }
    if !in_range(s.get("ewma"), 0.0, 1.0) {
        return Some("ewma must be in [0, 1]".into());
    }
    if !in_range(s.get("stepUps"), 0.0, MAX_COUNT) {
        return Some("stepUps must be finite and >= 0".into());
    }
    if !in_range(s.get("denies"), 0.0, MAX_COUNT) {
        return Some("denies must be finite and >= 0".into());
    }
    if !in_range(s.get("lastAt"), 0.0, MAX_SAFE) {
        return Some("lastAt must be a finite non-negative time".into());
    }
    if !s.get("seeded").is_some_and(Value::is_boolean) {
        return Some("seeded must be a boolean".into());
    }
    None
}

// ---- threat assessment --------------------------------------------------------------------------------------------------------

/// The current threat: the maximum of the drift, step-up volatility and violation signals; levels switch at 0.33 and 0.66.
#[derive(Debug, Clone, PartialEq)]
pub struct Threat {
    /// "calm", "elevated" or "high".
    pub level: &'static str,
    pub score: f64,
    pub signals: Vec<String>,
    pub drift: f64,
    pub volatility: f64,
    pub violation: f64,
}

impl Threat {
    /// `{level, score, signals, components: {drift, volatility, violation}}`.
    pub fn to_value(&self) -> Value {
        json!({
            "level": self.level, "score": num(self.score), "signals": self.signals,
            "components": { "drift": num(self.drift), "volatility": num(self.volatility), "violation": num(self.violation) },
        })
    }
}

/// Assess the threat from the state (as its wire form). A malformed state is the maximal threat.
pub fn assess(state: &Value) -> Threat {
    assess_cfg(state, &ImmuneConfig::default())
}

/// [`assess`] under an explicit configuration.
pub fn assess_cfg(state: &Value, cfg: &ImmuneConfig) -> Threat {
    let worst =
        |why: String| Threat { level: "high", score: 1.0, signals: vec![format!("invalid immune state: {why}")], drift: 1.0, volatility: 1.0, violation: 1.0 };
    let s = match ImmuneState::from_value(state) {
        Ok(s) => s,
        Err(bad) => return worst(bad),
    };
    let std = if s.n >= 2.0 { (s.m2 / s.n).sqrt() } else { 0.0 };
    let mut signals = Vec::new();
    // only ABOVE-baseline movement is threatening, and it needs a settled baseline
    let mut drift = 0.0;
    if s.n >= 5.0 && std > 1e-9 {
        let z = (s.ewma - s.mean) / std;
        drift = clamp01(z / cfg.drift_z_sat);
        if drift > 0.33 {
            signals.push(format!("risk drifted {}\u{3c3} above baseline", to_fixed(z, 1)));
        }
    }
    let volatility = clamp01(s.step_ups / cfg.step_up_sat);
    if volatility > 0.33 {
        signals.push(format!("elevated step-up rate ({})", to_fixed(s.step_ups, 1)));
    }
    let violation = clamp01(s.denies / cfg.deny_sat);
    if violation > 0.33 {
        signals.push(format!("repeated policy violations ({})", to_fixed(s.denies, 1)));
    }
    let score = drift.max(volatility).max(violation);
    let level = if score >= 0.66 {
        "high"
    } else if score >= 0.33 {
        "elevated"
    } else {
        "calm"
    };
    Threat { level, score, signals, drift, volatility, violation }
}

// ---- adaptation ---------------------------------------------------------------------------------------------------------------

fn adaptation(policy: Value, changed: bool, rationale: String) -> Value {
    json!({ "policy": policy, "changed": changed, "rationale": rationale })
}

/// The adapted policy for a threat assessment, derived from the BASE policy (never compounded): `{policy, changed, rationale}`. Kappa is
/// raised up to 3x and the thetas lowered down to 0.4x at score 1; a score of 0 returns the base. The result is re-validated and checked
/// against [`no_widen_violation`]; a failure keeps the base.
pub fn adapt(base: &Value, assessment: &Value) -> Result<Value, String> {
    adapt_with(base, assessment, 3.0, 0.4)
}

pub fn adapt_with(base: &Value, assessment: &Value, max_kappa_mult: f64, min_theta_mult: f64) -> Result<Value, String> {
    // a non-finite score is untrusted input: the worst case, never calm
    let s = finite_num(prop(assessment, "score")?).map_or(1.0, clamp01);
    if s == 0.0 {
        return Ok(adaptation(base.clone(), false, "calm \u{2014} baseline policy".into()));
    }
    let kappa_mult = 1.0 + (max_kappa_mult - 1.0) * s;
    let theta_mult = 1.0 - (1.0 - min_theta_mult) * s;
    if base.is_null() {
        return Err("Cannot read properties of null (reading 'weights')".into());
    }
    let mut policy = base.as_object().cloned().unwrap_or_default();
    let weights = match base.get("weights") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        _ => Value::Object(Map::new()),
    };
    policy.insert("weights".into(), weights);
    policy.insert("kappa".into(), num(js_to_number(base.get("kappa")) * kappa_mult));
    policy.insert("theta1".into(), num(clamp01(js_to_number(base.get("theta1")) * theta_mult)));
    policy.insert("theta2".into(), num(clamp01(js_to_number(base.get("theta2")) * theta_mult)));
    let policy = Value::Object(policy);
    let bad = match validate_risk_policy(&policy) {
        Some(b) => Some(b),
        None => no_widen_violation(base, &policy)?,
    };
    if let Some(bad) = bad {
        return Ok(adaptation(base.clone(), false, format!("adaptation rejected ({bad}) \u{2014} kept baseline")));
    }
    let signals = match prop(assessment, "signals")? {
        Some(Value::Array(a)) => a.clone(),
        _ => return Err("assessment.signals is not an array".into()),
    };
    let why = if signals.is_empty() {
        format!("threat score {}", to_fixed(s, 2))
    } else {
        signals.iter().map(|x| if x.is_null() { String::new() } else { js_str(x) }).collect::<Vec<_>>().join("; ")
    };
    let level = prop(assessment, "level")?.map_or_else(|| "undefined".to_string(), js_str);
    let rationale = format!("{}: {} \u{2192} \u{3ba} \u{d7}{}, \u{3b8} \u{d7}{}", level, why, to_fixed(kappa_mult, 2), to_fixed(theta_mult, 2));
    Ok(adaptation(policy, true, rationale))
}

/// Why `adapted` is looser than `base`, or `None` when it only tightens (kappa up, thetas down, the rest identical). A non-number reads as
/// looser. `Err` where the reference throws (a missing or null `weights`).
pub fn no_widen_violation(base: &Value, adapted: &Value) -> Result<Option<String>, String> {
    // null and booleans coerce to numbers in a relational comparison: a value that is not a number is a violation before any comparison
    for k in ["kappa", "theta1", "theta2"] {
        if !matches!(prop(adapted, k)?, Some(Value::Number(_))) {
            return Ok(Some("kappa and theta must be numbers".into()));
        }
    }
    if !(js_to_number(prop(adapted, "kappa")?) >= js_to_number(prop(base, "kappa")?)) {
        return Ok(Some("kappa decreased".into()));
    }
    if !(js_to_number(prop(adapted, "theta1")?) <= js_to_number(prop(base, "theta1")?)) {
        return Ok(Some("theta1 increased".into()));
    }
    if !(js_to_number(prop(adapted, "theta2")?) <= js_to_number(prop(base, "theta2")?)) {
        return Ok(Some("theta2 increased".into()));
    }
    for k in ["lambda", "rho", "bMax"] {
        if !strict_eq(prop(adapted, k)?, prop(base, k)?) {
            return Ok(Some(format!("{k} changed")));
        }
    }
    let keys: Vec<String> = match prop(base, "weights")? {
        None | Some(Value::Null) => return Err("Cannot convert undefined or null to object".into()),
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        _ => Vec::new(),
    };
    for k in keys {
        let aw = match prop(adapted, "weights")? {
            None | Some(Value::Null) => return Err(format!("Cannot read properties of undefined (reading '{k}')")),
            Some(w) => w,
        };
        if !strict_eq(aw.get(&k), prop(base, "weights")?.and_then(|w| w.get(&k))) {
            return Ok(Some(format!("weights.{k} changed")));
        }
    }
    Ok(None)
}

/// `Err` unless `adapted` only tightens `base`.
pub fn assert_no_widen(base: &Value, adapted: &Value) -> Result<(), String> {
    match no_widen_violation(base, adapted)? {
        Some(v) => Err(format!("immune: adaptation widens the policy ({v})")),
        None => Ok(()),
    }
}

// ---- signed tightening proposals ----------------------------------------------------------------------------------------------

fn tightening_message(claim: &Value) -> Vec<u8> {
    let mut m = TIGHTENING_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(lenient(claim).as_bytes());
    m
}

/// base64url(sha256(lenient canonical JSON)) of a risk policy.
pub fn policy_digest(p: &Value) -> String {
    hash_canonical_lenient(p)
}

/// base64url(sha256(lenient canonical JSON)) of an immune state.
pub fn immune_state_digest(s: &Value) -> String {
    hash_canonical_lenient(s)
}

/// Derive and sign the tightening for `state` with the guardian's Ed25519 seed. `Err` on a malformed base, an epoch that is not a safe
/// integer >= 1 or a non-finite `now` (never an unsigned loosening); a malformed state tightens to the maximum.
pub fn issue_tightening_proposal(base: &Value, state: &Value, epoch: &Value, now: &Value, guardian_seed: &[u8; 32]) -> Result<Value, String> {
    if let Some(bad) = validate_risk_policy(base) {
        return Err(format!("issueTighteningProposal: {bad}"));
    }
    if !safe_int(Some(epoch)).is_some_and(|e| e >= 1.0) {
        return Err("issueTighteningProposal: epoch must be an integer >= 1".into());
    }
    if finite_num(Some(now)).is_none() {
        return Err("issueTighteningProposal: now must be finite".into());
    }
    let ad = adapt(base, &assess(state).to_value())?;
    let key = KeyPair::from_seed(guardian_seed);
    let mut claim = Map::new();
    claim.insert("v".into(), json!(1));
    claim.insert("base_digest".into(), Value::String(policy_digest(base)));
    claim.insert("state_digest".into(), Value::String(hash_canonical_lenient(state)));
    claim.insert("epoch".into(), epoch.clone());
    claim.insert("issued_at".into(), now.clone());
    claim.insert("policy".into(), ad["policy"].clone());
    claim.insert("rationale".into(), ad["rationale"].clone());
    claim.insert("guardian".into(), Value::String(key.public.clone()));
    let sig = crate::b64_encode(&key.sign(&tightening_message(&Value::Object(claim.clone()))));
    claim.insert("sig".into(), Value::String(sig));
    Ok(Value::Object(claim))
}

fn refused(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

/// Verify a proposal and return `{ok: true, policy, epoch}` or `{ok: false, reason}`; never fails. `o` holds the pinned `guardian`
/// (base64url, required: an unpinned proposal is refused), `lastEpoch`, `now`, `maxAgeMs` and optionally `state` (a recompute check).
/// Reasons: malformed, guardian, signature, invalid-policy, base, stale, replayed-epoch, widens, state-mismatch.
pub fn apply_tightening(base: &Value, p: &Value, o: &Value) -> Value {
    apply_tightening_inner(base, p, o).unwrap_or_else(|_| refused("malformed"))
}

fn apply_tightening_inner(base: &Value, p: &Value, o: &Value) -> Result<Value, String> {
    let Some(pm) = p.as_object() else { return Ok(refused("malformed")) };
    if pm.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Ok(refused("malformed"));
    }
    let (Some(sig), Some(guardian)) = (pm.get("sig").and_then(Value::as_str), pm.get("guardian").and_then(Value::as_str)) else {
        return Ok(refused("malformed"));
    };
    if o.get("guardian").and_then(Value::as_str) != Some(guardian) {
        prop(o, "guardian")?; // a null `o` throws in the reference (reported malformed)
        return Ok(refused("guardian"));
    }
    let mut claim = pm.clone();
    claim.remove("sig");
    if !crate::verify_b64u(guardian, &tightening_message(&Value::Object(claim)), sig) {
        return Ok(refused("signature"));
    }
    let policy = pm.get("policy").unwrap_or(&Value::Null);
    if validate_risk_policy(base).is_some() || validate_risk_policy(policy).is_some() {
        return Ok(refused("invalid-policy"));
    }
    if pm.get("base_digest").and_then(Value::as_str) != Some(policy_digest(base).as_str()) {
        return Ok(refused("base"));
    }
    let (now, issued) = (finite_num(o.get("now")), finite_num(pm.get("issued_at")));
    let (Some(now), Some(issued)) = (now, issued) else { return Ok(refused("stale")) };
    if !(issued <= now && now - issued <= js_to_number(o.get("maxAgeMs"))) {
        return Ok(refused("stale"));
    }
    let epoch = pm.get("epoch");
    let e = safe_int(epoch);
    if !e.is_some_and(|e| !(e == 0.0 && e.is_sign_negative()) && e > js_to_number(o.get("lastEpoch"))) {
        return Ok(refused("replayed-epoch"));
    }
    if no_widen_violation(base, policy)?.is_some() {
        return Ok(refused("widens"));
    }
    if truthy(o.get("state")) {
        let st = o.get("state").unwrap_or(&Value::Null);
        let derived = adapt(base, &assess(st).to_value())?;
        if pm.get("state_digest").and_then(Value::as_str) != Some(hash_canonical_lenient(st).as_str())
            || policy_digest(&derived["policy"]) != policy_digest(policy)
        {
            return Ok(refused("state-mismatch"));
        }
    }
    Ok(json!({ "ok": true, "policy": policy, "epoch": epoch }))
}

// ---- durable state ------------------------------------------------------------------------------------------------------------

/// Immune state and applied epoch for one subject over an atomic key/value store, so a restart keeps the history and the replay floor.
pub struct ImmuneStore<'a> {
    kv: &'a dyn AtomicKv,
    s_key: String,
    e_key: String,
}

impl<'a> ImmuneStore<'a> {
    pub fn new(kv: &'a dyn AtomicKv, subject: &str) -> ImmuneStore<'a> {
        ImmuneStore { kv, s_key: format!("immune/state/{subject}"), e_key: format!("immune/epoch/{subject}") }
    }

    /// The stored state (as stored), or the initial one.
    pub fn get(&self) -> Result<Value, String> {
        Ok(self.kv.get(&self.s_key).map_err(|e| e.0)?.unwrap_or_else(|| ImmuneState::initial().to_value()))
    }

    /// Folds one observation atomically. `Err` when the stored state is malformed (it is never silently reset to calm) or `obs` is null.
    pub fn observe(&self, obs: &Value) -> Result<Value, String> {
        let mut err: Option<String> = None;
        let stored = self
            .kv
            .update(&self.s_key, &mut |prev: Option<&Value>| {
                let cur = prev.cloned().unwrap_or_else(|| ImmuneState::initial().to_value());
                let st = match ImmuneState::from_value(&cur) {
                    Ok(s) => s,
                    Err(bad) => {
                        err = Some(format!("immune store: stored state invalid ({bad})"));
                        return None;
                    }
                };
                match observe_value(&st, obs) {
                    Ok(next) => Some(next.to_value()),
                    Err(e) => {
                        err = Some(e);
                        None
                    }
                }
            })
            .map_err(|e| e.0)?;
        if let Some(e) = err {
            return Err(e);
        }
        stored.ok_or_else(|| "immune store: nothing stored".to_string())
    }

    /// The highest epoch applied so far (0 when none).
    pub fn last_epoch(&self) -> Result<f64, String> {
        Ok(self.kv.get(&self.e_key).map_err(|e| e.0)?.and_then(|v| if v.is_number() { v.as_f64() } else { None }).unwrap_or(0.0))
    }

    /// Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. `o` is as for
    /// [`apply_tightening`] without `lastEpoch`.
    pub fn apply(&self, base: &Value, p: &Value, o: &Value) -> Result<Value, String> {
        let mut out = refused("malformed");
        self.kv
            .update(&self.e_key, &mut |prev: Option<&Value>| {
                let last = prev.filter(|v| v.is_number()).cloned().unwrap_or_else(|| json!(0));
                let mut oo = o.as_object().cloned().unwrap_or_default();
                oo.insert("lastEpoch".into(), last);
                out = apply_tightening(base, p, &Value::Object(oo));
                if out["ok"] == Value::Bool(true) {
                    Some(out["epoch"].clone())
                } else {
                    None
                }
            })
            .map_err(|e| e.0)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryAtomicKv;

    #[test]
    fn decay_is_whole_half_life_steps_of_exact_multiplications() {
        let h = 3_600_000.0;
        assert_eq!(decay(8.0, h, h), 4.0); // 1024 steps: 0.5 once
        assert_eq!(decay(8.0, 3.0 * h, h), 1.0); // 0.5 three times, exact
        assert_eq!(decay(1.0, h / 1024.0, h), 0.9993233275026507); // one step
        assert_eq!(decay(1.0, h / 1024.0 - 1.0, h), 1.0); // quantized down to zero steps
        let two_steps = 0.9993233275026507f64 * 0.9993233275026507;
        assert_eq!(decay(1.0, 2.0 * h / 1024.0, h), 1.0 * two_steps);
        assert_eq!(decay(5.0, 1e30, h), 0.0); // underflows
        assert!(decay(5.0, f64::NAN, h).is_nan());
        assert_eq!(decay(5.0, -1.0, h), 5.0);
    }

    #[test]
    fn an_adaptation_whose_kappa_or_theta_is_not_a_number_is_a_violation() {
        let b = base();
        for k in ["kappa", "theta1", "theta2"] {
            for bad in [json!(null), json!(true), json!("1")] {
                let mut a = b.clone();
                a[k] = bad.clone();
                assert_eq!(no_widen_violation(&b, &a).unwrap().as_deref(), Some("kappa and theta must be numbers"), "{k} {bad}");
            }
        }
    }

    fn base() -> Value {
        json!({ "weights": { "alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05 },
                "theta1": 1, "theta2": 1, "kappa": 500, "lambda": 0.0005, "rho": 0.5, "bMax": 1000 })
    }

    fn hot() -> Value {
        let mut s = ImmuneState::initial();
        for _ in 0..3 {
            s = observe(&s, 1.0, 0.0, false, true);
        }
        s.to_value()
    }

    #[test]
    fn assess_adapt_and_no_widen() {
        assert_eq!(assess(&ImmuneState::initial().to_value()).level, "calm");
        let a = assess(&hot());
        assert_eq!((a.level, a.score), ("high", 1.0));
        let adapted = adapt(&base(), &a.to_value()).unwrap()["policy"].clone();
        assert_eq!(adapted["kappa"].as_f64(), Some(1500.0));
        assert_eq!(no_widen_violation(&base(), &adapted).unwrap(), None);
        assert_eq!(no_widen_violation(&adapted, &base()).unwrap(), Some("kappa decreased".into()));
        // calm restores the base exactly
        let calm = adapt(&base(), &assess(&ImmuneState::initial().to_value()).to_value()).unwrap();
        assert_eq!(calm["changed"], false);
        assert_eq!(calm["policy"], base());
        // a malformed state fails closed, a non-finite timestamp advances no clock
        let mut bad = ImmuneState::initial().to_value();
        bad["ewma"] = json!(2);
        assert_eq!(assess(&bad).level, "high");
        let t = observe(&observe(&ImmuneState::initial(), 0.5, 100.0, false, false), 0.5, f64::NAN, false, false);
        assert_eq!(t.last_at, 100.0);
    }

    #[test]
    fn to_fixed_rounds_like_javascript() {
        assert_eq!(to_fixed(0.125, 2), "0.13"); // an exact tie takes the larger value
        assert_eq!(to_fixed(1.005, 2), "1.00"); // 1.005 is below the tie in binary
        assert_eq!(to_fixed(9.995, 2), "9.99");
        assert_eq!(to_fixed(99.999, 2), "100.00");
        assert_eq!(to_fixed(2.0, 1), "2.0");
        assert_eq!(to_fixed(0.0, 2), "0.00");
        assert_eq!(to_fixed(-0.001, 2), "-0.00");
    }

    #[test]
    fn signed_proposal_round_trip_and_store_floor() {
        let seed = [7u8; 32];
        let guardian = KeyPair::from_seed(&seed).public.clone();
        let now = 1_800_000_000_000i64;
        let p = issue_tightening_proposal(&base(), &hot(), &json!(5), &json!(now), &seed).unwrap();
        let opts = json!({ "guardian": guardian, "now": now + 1000, "maxAgeMs": 60000, "state": hot() });
        let kv = MemoryAtomicKv::new();
        let st = ImmuneStore::new(&kv, "alice");
        assert_eq!(st.last_epoch().unwrap(), 0.0);
        let ok = st.apply(&base(), &p, &opts).unwrap();
        assert_eq!(ok["ok"], true);
        assert_eq!(st.last_epoch().unwrap(), 5.0);
        // a replay of the same epoch is refused
        assert_eq!(st.apply(&base(), &p, &opts).unwrap()["reason"], "replayed-epoch");
        // a proposal for another guardian is refused
        let other = json!({ "guardian": "x", "now": now + 1000, "maxAgeMs": 60000 });
        assert_eq!(apply_tightening(&base(), &p, &other)["reason"], "guardian");
        // the store folds observations and refuses a malformed stored state
        let s1 = st.observe(&json!({ "r": 0.5, "at": now })).unwrap();
        assert_eq!(s1["baseline"]["n"].as_f64(), Some(1.0));
        let kv2 = MemoryAtomicKv::new();
        kv2.update("immune/state/bob", &mut |_| Some(Value::Null)).unwrap();
        assert!(ImmuneStore::new(&kv2, "bob").observe(&json!({ "r": 0.5, "at": now })).is_err());
    }
}

// ---- the baseline on its own --------------------------------------------------------------------------------------------------

/// `updateBaseline(b, r)`: one Welford step of the running baseline `{n, mean, m2}` with the sample `r` (a non-finite sample
/// counts as 0; the sample is not clamped here).
pub fn update_baseline(b: &Value, r: f64) -> Value {
    let f = |k: &str| b.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN);
    let x = if r.is_finite() { r } else { 0.0 };
    let n = f("n") + 1.0;
    let delta = x - f("mean");
    let mean = f("mean") + delta / n;
    json!({ "n": num(n), "mean": num(mean), "m2": num(f("m2") + delta * (x - mean)) })
}

/// `baselineStd(b)`: the population standard deviation of the baseline `{n, mean, m2}` (0 until it holds two samples).
pub fn baseline_std(b: &Value) -> f64 {
    let f = |k: &str| b.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN);
    if f("n") >= 2.0 {
        (f("m2") / f("n")).sqrt()
    } else {
        0.0
    }
}
