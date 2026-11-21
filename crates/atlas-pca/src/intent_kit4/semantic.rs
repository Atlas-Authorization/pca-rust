//! Bond sizing (`optimistic` bondAmount) and the semantic judge panel (`semantic-threshold.ts`): signed verdicts, split-conformal
//! calibration and the k-of-n threshold over trusted judges.
use super::{dbl, finite, js_num, R};
use crate::intent_kit::{js_max, js_round, truthy};
use crate::agent::{sign_with_suite, KeyPair, Suite};
use crate::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::Arc;

pub const SEMANTIC_JUDGE_DOMAIN: &str = "atlas-pca/semantic-judge/v1\0";
pub const SCORE_SCALE: f64 = 1_000_000.0;
const MICROS: f64 = 1_000_000.0;
const MAX_SAFE_MICROS: f64 = 1e15;

// ---- bond sizing -------------------------------------------------------------------------------------------------------------

/// `DEFAULT_BOND_POLICY` (maxOpenAmount is Infinity, which has no JSON form: it is carried as the string "Infinity").
pub fn default_bond_policy() -> Value {
    json!({"floor": 1, "k": 1, "maxOpenClaims": 100, "maxOpenAmount": "Infinity"})
}

/// Snap a computed amount UP onto the micro grid; float noise below 1e-3 micro-units is absorbed.
pub fn quantize_up(x: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
        return x;
    }
    let scaled = x * MICROS;
    if scaled > MAX_SAFE_MICROS {
        return x;
    }
    let r = js_round(scaled);
    let m = if r / MICROS == x || (scaled - r).abs() <= 1e-3 { r } else { scaled.ceil() };
    m / MICROS
}

fn curve_component(curve: Option<&Value>, k: f64, e: f64) -> R<f64> {
    if !truthy(curve) || curve.and_then(|c| c.get("kind")) == Some(&json!("linear")) {
        return Ok(k * e);
    }
    let c = curve.expect("truthy curve");
    if c.get("kind") == Some(&json!("power")) {
        return match finite(c.get("gamma")) {
            Some(g) if g >= 1.0 => Ok(k * e.powf(g)),
            _ => Err("bondAmount: power curve requires finite gamma >= 1".into()),
        };
    }
    let tiers = match c.get("tiers").and_then(Value::as_array) {
        Some(t) if !t.is_empty() => t,
        _ => return Err("bondAmount: piecewise curve requires at least one tier".into()),
    };
    let (mut acc, mut prev_up, mut prev_marginal) = (0.0f64, 0.0f64, 0.0f64);
    for t in tiers {
        let (up, mk) = (dbl(t.get("upTo")), dbl(t.get("marginalK")));
        if !(up.is_finite() && up > prev_up) && up != f64::INFINITY {
            return Err("bondAmount: piecewise tier `upTo` must be strictly increasing".into());
        }
        if !(mk.is_finite() && mk >= 0.0) {
            return Err("bondAmount: piecewise `marginalK` must be a finite number >= 0".into());
        }
        if mk < prev_marginal {
            return Err("bondAmount: piecewise marginal rates must be non-decreasing (convex)".into());
        }
        let width = e.min(up) - prev_up;
        if width > 0.0 {
            acc += width * mk;
        }
        prev_up = up;
        prev_marginal = mk;
        if e <= up {
            break;
        }
    }
    if e > prev_up {
        acc += (e - prev_up) * prev_marginal;
    }
    Ok(k * acc)
}

/// `max(floor, curve(k, exposure))` snapped up onto the micro grid; a non-finite or non-positive exposure gives the floor.
pub fn bond_amount(policy: &Value, exposure: f64) -> R<f64> {
    let e = if exposure.is_finite() && exposure > 0.0 { exposure } else { 0.0 };
    let c = curve_component(policy.get("curve"), dbl(policy.get("k")), e)?;
    Ok(quantize_up(js_max(dbl(policy.get("floor")), c)))
}

// ---- the judge verdict -------------------------------------------------------------------------------------------------------

/// A judge score on the integer ppm grid, clamped to [0, 1e6]; non-finite is 0.
pub fn quantize_score(score: f64) -> f64 {
    if !score.is_finite() {
        return 0.0;
    }
    let q = js_round(score * SCORE_SCALE) + 0.0;
    if q < 0.0 {
        0.0
    } else if q > SCORE_SCALE {
        SCORE_SCALE
    } else {
        q
    }
}

/// Verify ONE verdict against the action digest and goal commitment it must be bound to. Total; a PQ-suite verdict needs its key
/// pinned (`pins` = `{pqPins: {judge: pq_pk}}`). A verdict the reference cannot even encode (a PQ suite without `pq_pk`) is refused.
pub fn verify_judge_verdict(v: &Value, expected: &Value, pins: &Value) -> bool {
    let Some(m) = v.as_object() else { return false };
    let Some(judge) = m.get("judge").and_then(Value::as_str) else { return false };
    if crate::decode_b64u_strict(judge, Some(32)).is_none() {
        return false;
    }
    let (Some(ad), Some(gc)) = (m.get("actionDigest").and_then(Value::as_str), m.get("goalCommitment").and_then(Value::as_str)) else { return false };
    if expected.get("actionDigest").and_then(Value::as_str) != Some(ad) || expected.get("goalCommitment").and_then(Value::as_str) != Some(gc) {
        return false;
    }
    if !m.get("faithful").is_some_and(Value::is_boolean) {
        return false;
    }
    match finite(m.get("score")) {
        Some(s) if (0.0..=1.0).contains(&s) => {}
        _ => return false,
    }
    let Some(meas) = m.get("judgeMeasurement").and_then(Value::as_str) else { return false };
    if !m.get("sig").is_some_and(Value::is_string) {
        return false;
    }
    if suite_of(m.get("alg")).is_err() {
        return false;
    }
    let mut base = Map::new();
    base.insert("v".into(), json!(1));
    base.insert("actionDigest".into(), json!(ad));
    base.insert("goalCommitment".into(), json!(gc));
    base.insert("faithful".into(), json!(m["faithful"] == json!(true)));
    base.insert("score_ppm".into(), Value::from(quantize_score(dbl(m.get("score"))) as i64));
    base.insert("judgeMeasurement".into(), json!(meas));
    match bind_suite_fields(&mut base, m.get("alg"), m.get("pq_pk")) {
        Ok(true) => {}
        _ => return false,
    }
    let Some(msg) = domain_message(SEMANTIC_JUDGE_DOMAIN, base) else { return false };
    let pin = pins.get("pqPins").and_then(Value::as_object).and_then(|p| p.get(judge)).map(|x| (judge, x));
    verify_pinned_suite(m.get("alg"), judge, m.get("pq_pk"), &msg, m.get("sig"), m.get("pq_sig"), pin).unwrap_or(false)
}

// ---- split-conformal calibration ---------------------------------------------------------------------------------------------

fn clamp_alpha(a: Option<&Value>) -> f64 {
    match finite(a) {
        None => 1.0,
        Some(x) if x <= 0.0 => f64::from_bits(1), // Number.MIN_VALUE
        Some(x) if x > 1.0 => 1.0,
        Some(x) => x,
    }
}

/// The scores of the unfaithful samples with a finite numeric score.
fn unfaithful_scores(samples: Option<&Value>) -> Vec<f64> {
    samples
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|s| s.get("faithful") == Some(&json!(false)))
        .filter_map(|s| finite(s.get("score")))
        .collect()
}

/// The split-conformal cutoff over the unfaithful calibration scores (`+Infinity`: not enough negatives to certify alpha).
pub fn conformal_threshold(cal: &Value) -> f64 {
    let alpha = clamp_alpha(cal.get("alpha"));
    let mut un = unfaithful_scores(cal.get("samples"));
    let m = un.len();
    if m == 0 {
        return f64::INFINITY;
    }
    let rank = ((m as f64 + 1.0) * (1.0 - alpha)).ceil();
    if rank > m as f64 {
        return f64::INFINITY;
    }
    un.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    un[(rank.max(1.0) as usize) - 1]
}

/// The share of unfaithful calibration scores above `cutoff`.
pub fn empirical_false_allow_rate(samples: &Value, cutoff: f64) -> f64 {
    let un = unfaithful_scores(Some(samples));
    if un.is_empty() {
        return 0.0;
    }
    un.iter().filter(|s| **s > cutoff).count() as f64 / un.len() as f64
}

// ---- the k-of-n threshold ----------------------------------------------------------------------------------------------------

/// `SemanticThresholdResult`.
#[derive(Clone, Debug)]
pub struct Threshold {
    pub ok: bool,
    pub agree_count: usize,
    pub aggregate_score: f64,
    pub cutoff: Option<f64>,
    pub reason: Option<String>,
}

impl Threshold {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("ok".into(), json!(self.ok));
        m.insert("agreeCount".into(), json!(self.agree_count));
        m.insert("aggregateScore".into(), crate::intent_kit::jn(self.aggregate_score));
        if let Some(c) = self.cutoff {
            m.insert("cutoff".into(), crate::intent_kit::jn(c));
        }
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        Value::Object(m)
    }
}

fn fail(reason: String) -> Threshold {
    Threshold { ok: false, agree_count: 0, aggregate_score: 0.0, cutoff: None, reason: Some(reason) }
}

/// k distinct trusted judges must agree (unanimous `faithful`, one score); with a calibration their mean score must exceed the cutoff.
/// `opts`: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?.
pub fn verify_semantic_threshold(verdicts: &Value, opts: &Value) -> Threshold {
    let k = opts.get("k");
    let allow: HashSet<&str> = opts
        .get("judgeKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|key| crate::decode_b64u_strict(key, Some(32)).is_some())
        .collect();
    let (Some(ad), Some(gc)) = (opts.get("actionDigest").and_then(Value::as_str), opts.get("goalCommitment").and_then(Value::as_str)) else {
        return fail("missing action/goal binding".into());
    };
    let kn = match finite(k) {
        Some(x) if x.fract() == 0.0 && x >= 1.0 => x,
        _ => return fail(format!("invalid quorum k={}", crate::intent_kit3::js_str(k))),
    };
    let expected = json!({"actionDigest": ad, "goalCommitment": gc});
    // judge -> (faithful votes seen, distinct quantized scores), in first-seen order
    let mut by: Vec<(String, (bool, bool), Vec<f64>)> = vec![];
    for v in verdicts.as_array().into_iter().flatten() {
        let Some(judge) = v.get("judge").and_then(Value::as_str) else { continue };
        if !allow.contains(judge) || !verify_judge_verdict(v, &expected, opts) {
            continue;
        }
        // the attested-judge gate: with `require` a judge not bound to an approved measured TEE does not count
        if let Some(att) = opts.get("attestation").filter(|a| truthy(Some(*a))) {
            if att.get("require") == Some(&json!(true)) {
                let attestation = att.get("byJudge").and_then(|b| b.get(judge)).unwrap_or(&Value::Null);
                if verify_judge_attestation(v.get("judgeMeasurement").unwrap_or(&Value::Null), attestation, att.get("approved").unwrap_or(&Value::Null))["ok"]
                    != json!(true)
                {
                    continue;
                }
            }
        }
        let i = match by.iter().position(|(j, _, _)| j == judge) {
            Some(i) => i,
            None => {
                by.push((judge.to_string(), (false, false), vec![]));
                by.len() - 1
            }
        };
        if v.get("faithful") == Some(&json!(true)) {
            by[i].1 .0 = true;
        } else {
            by[i].1 .1 = true;
        }
        let q = quantize_score(dbl(v.get("score")));
        if !by[i].2.contains(&q) {
            by[i].2.push(q);
        }
    }
    let mut agreeing: Vec<(&str, f64)> = by.iter().filter(|(_, f, q)| f.0 && !f.1 && q.len() == 1).map(|(j, _, q)| (j.as_str(), q[0])).collect();
    agreeing.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let n = agreeing.len();
    let score = if n == 0 { 0.0 } else { agreeing.iter().fold(0.0, |acc, a| acc + a.1 / SCORE_SCALE) / n as f64 };
    if (n as f64) < kn {
        return Threshold {
            ok: false,
            agree_count: n,
            aggregate_score: score,
            cutoff: None,
            reason: Some(format!("only {n} distinct trusted judge(s) agree, need {}", js_num(kn))),
        };
    }
    if truthy(opts.get("calibration")) {
        let cutoff = conformal_threshold(opts.get("calibration").expect("calibration"));
        if !(score > cutoff) {
            let reason = format!("aggregateScore {} does not exceed calibrated cutoff {}", js_num(score), js_num(cutoff));
            return Threshold { ok: false, agree_count: n, aggregate_score: score, cutoff: Some(cutoff), reason: Some(reason) };
        }
        return Threshold { ok: true, agree_count: n, aggregate_score: score, cutoff: Some(cutoff), reason: None };
    }
    Threshold { ok: true, agree_count: n, aggregate_score: score, cutoff: None, reason: None }
}

// ---- the signed statement, signing, the attested-judge binding and the hook -------------------------------------------------------

/// `String(x ?? '')`.
fn text_of(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        other => crate::intent_kit3::js_str(other),
    }
}

/// The canonical statement a verdict's signature covers: `{v: 1, actionDigest, goalCommitment, faithful (=== true), score_ppm,
/// judgeMeasurement}` plus `alg` and `pq_pk` bound for a post-quantum suite (an unknown suite binds nothing).
pub fn statement_of(v: &Value) -> Value {
    let mut base = Map::new();
    base.insert("v".into(), json!(1));
    for k in ["actionDigest", "goalCommitment"] {
        if let Some(x) = v.get(k) {
            base.insert(k.into(), x.clone());
        }
    }
    base.insert("faithful".into(), json!(v.get("faithful") == Some(&json!(true))));
    base.insert("score_ppm".into(), Value::from(quantize_score(dbl(v.get("score"))) as i64));
    base.insert("judgeMeasurement".into(), json!(text_of(v.get("judgeMeasurement"))));
    let _ = bind_suite_fields(&mut base, v.get("alg"), v.get("pq_pk")); // an unknown suite is left unbound; a missing pq_pk is left out
    Value::Object(base)
}

/// The exact bytes a judge signs: the domain, then the strict canonical statement. `Err` for a non-integer, negative-zero or non-finite
/// member.
pub fn semantic_judge_message(statement: &Value) -> R<Vec<u8>> {
    let mut m = SEMANTIC_JUDGE_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize_strict(statement)?.as_bytes());
    Ok(m)
}

/// The digest of a whole verdict for ledger anchoring or challenge: the strict canonical hash.
pub fn verdict_digest(v: &Value) -> R<String> {
    let c = crate::canonicalize_strict(v)?;
    Ok(crate::b64_encode(&crate::sha(c.as_bytes())))
}

/// Sign a verdict `{actionDigest, goalCommitment, faithful, score, judgeMeasurement?}` as `secret`'s judge under `suite` (default
/// ed25519; a post-quantum or hybrid suite needs its key pair). The result verifies as is. `Err` for an unknown suite or a statement that
/// has no canonical form.
pub fn sign_judge_verdict(secret: &KeyPair, v: &Value, suite: &Suite) -> R<Value> {
    let jm = text_of(v.get("judgeMeasurement"));
    let alg = suite.alg.map(|a| json!(a));
    let resolved = suite_of(alg.as_ref()).map_err(|_| format!("signJudgeVerdict: unknown signature alg '{}'", suite.alg.unwrap_or("undefined")))?;
    let mut sv = v.as_object().cloned().unwrap_or_default();
    sv.insert("judgeMeasurement".into(), json!(jm));
    sv.remove("alg");
    sv.remove("pq_pk");
    if resolved.alg != "ed25519" {
        sv.insert("alg".into(), json!(resolved.alg));
        if let Some(p) = suite.pq {
            sv.insert("pq_pk".into(), json!(p.public));
        }
    }
    let msg = semantic_judge_message(&statement_of(&Value::Object(sv)))?;
    let (sig, pq_sig) = sign_with_suite(suite, Some(secret), &msg)?;
    let mut out = Map::new();
    out.insert("judge".into(), json!(secret.public));
    for k in ["actionDigest", "goalCommitment"] {
        if let Some(x) = v.get(k) {
            out.insert(k.into(), x.clone());
        }
    }
    out.insert("faithful".into(), json!(v.get("faithful") == Some(&json!(true))));
    if let Some(sc) = v.get("score") {
        out.insert("score".into(), sc.clone());
    }
    out.insert("judgeMeasurement".into(), json!(jm));
    out.insert("sig".into(), json!(sig));
    if resolved.alg != "ed25519" {
        out.insert("alg".into(), json!(resolved.alg));
        if let Some(p) = suite.pq {
            out.insert("pq_pk".into(), json!(p.public));
        }
    }
    if let Some(p) = pq_sig {
        out.insert("pq_sig".into(), json!(p));
    }
    Ok(Value::Object(out))
}

/// Bind a judge's SIGNED `judgeMeasurement` to a verified measured TEE, as the agent is bound: the attestation must be verified and
/// bound (`ok` and `bound` true) with a measured identity, the identity's `runtime_measurement` must equal the signed label, and the
/// identity must satisfy `approved` (an `agent_binding`, matched like the agent's). Total: `{ok, reason?, measured?}`.
pub fn verify_judge_attestation(judge_measurement: &Value, attestation: &Value, approved: &Value) -> Value {
    let no = |reason: Value| json!({"ok": false, "reason": reason});
    if !truthy(Some(attestation)) || attestation.get("ok") != Some(&json!(true)) {
        let why = attestation.get("reason").filter(|r| !r.is_null()).cloned().unwrap_or_else(|| json!("no verified attestation for this judge (fail-closed)"));
        return no(why);
    }
    if attestation.get("bound") != Some(&json!(true)) {
        return no(json!("judge attestation not bound to a TEE report (report_data binding unconfirmed)"));
    }
    let Some(measured) = attestation.get("measured").filter(|m| m.is_object() || m.is_array()) else {
        return no(json!("judge attestation carries no measured identity"));
    };
    let Some(label) = judge_measurement.as_str().filter(|l| !l.is_empty()) else {
        return no(json!("verdict carries no judgeMeasurement to bind to the attested identity"));
    };
    if measured.get("runtime_measurement").and_then(Value::as_str) != Some(label) {
        return no(json!("attested enclave measurement does not match the signed judgeMeasurement"));
    }
    match crate::attestation::match_agent_binding(measured, approved) {
        Ok(Some(reason)) => no(json!(reason)),
        Ok(None) => json!({"ok": true, "measured": measured}),
        Err(e) => no(json!(e)),
    }
}

/// The hosts a semantic verifier hook is wired to: where the ensemble's verdicts and the goal commitment come from for an action (they
/// are not on the core PCActn wire), an optional action-digest override and an optional attested-judge gate
/// (`{require, approved?, byJudge: {judge: HardwareAttestationResult}}`).
pub struct SemanticHooks {
    pub verdicts: Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>,
    pub goal_commitment: Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>,
    /// Default: the strict hash of `ctx.pcactn.action`.
    pub action_digest: Option<Arc<dyn Fn(&Value) -> R<String> + Send + Sync>>,
    pub attestation: Option<Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>>,
}

/// A semantic verifier hook (`(ctx) -> HookResult` shaped): `{enforced: true, ok}` or `{enforced: true, ok: false, reason}`; with
/// `optionalWhenAbsent` an absent ensemble is `{enforced: false}`, else it is a denial. `opts`: `{judgeKeys, k, calibration?,
/// optionalWhenAbsent?}`. `Err` where the reference throws (the default digest of an action with no canonical form).
pub fn create_semantic_verifier(opts: &Value, hooks: SemanticHooks) -> Arc<dyn Fn(&Value) -> R<Value> + Send + Sync> {
    let opts = opts.clone();
    Arc::new(move |ctx: &Value| {
        let goal = (hooks.goal_commitment)(ctx);
        let verdicts = (hooks.verdicts)(ctx);
        let Some((goal, verdicts)) = goal.filter(Value::is_string).zip(verdicts) else {
            if truthy(opts.get("optionalWhenAbsent")) {
                return Ok(json!({"enforced": false}));
            }
            return Ok(json!({"enforced": true, "ok": false, "reason": "no semantic ensemble available for this action (fail-closed)"}));
        };
        let attestation = hooks.attestation.as_ref().and_then(|a| a(ctx));
        let digest = match &hooks.action_digest {
            Some(f) => f(ctx)?,
            None => {
                let action = ctx.get("pcactn").and_then(|p| p.get("action")).ok_or("canonicalize: unsupported type undefined")?;
                let c = crate::canonicalize_strict(action)?;
                crate::b64_encode(&crate::sha(c.as_bytes()))
            }
        };
        let mut o = Map::new();
        for k in ["judgeKeys", "k", "calibration"] {
            if let Some(v) = opts.get(k) {
                o.insert(k.into(), v.clone());
            }
        }
        o.insert("goalCommitment".into(), goal);
        o.insert("actionDigest".into(), json!(digest));
        if let Some(a) = attestation.filter(|a| truthy(Some(a))) {
            o.insert("attestation".into(), a);
        }
        let res = verify_semantic_threshold(&verdicts, &Value::Object(o));
        Ok(if res.ok {
            json!({"enforced": true, "ok": true})
        } else {
            json!({"enforced": true, "ok": false, "reason": res.reason.unwrap_or_else(|| "semantic threshold not met".to_string())})
        })
    })
}
