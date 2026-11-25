//! Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities in ppm,
//! money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-SIGNED configuration;
//! anything missing, out of range or unsigned means ASK. The only learned component is a per-principal multiplier that scales P(bad) UP,
//! so it can only add asks; asking less needs a principal-signed autonomy raise. A port of the reference (@atlasauth/pca-wallet,
//! escalation-pricing). Signing takes the principal's 32-byte Ed25519 seed. Values are plain JSON; a reference throw is an `Err(String)`.
//!
//! API: [`sign_pricing_config`], [`pricing_config_error`], [`fresh_calibration`], [`decide_escalation`], [`sign_answer`],
//! [`update_calibration`], [`sign_autonomy_raise`], [`apply_autonomy_raise`].
use crate::wallet::{ed_sign, PPM};
use crate::wallet_omega::{is_safe_int, num, u16len};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub use crate::wallet::MAX_MULTIPLIER_PPM;

fn is_minor(v: Option<&Value>) -> bool {
    v.is_some_and(|v| is_safe_int(v) && num(v).is_some_and(|f| f >= 0.0))
}

fn neg_zero(v: Option<&Value>) -> bool {
    v.and_then(num).is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

fn is_one(v: Option<&Value>) -> bool {
    v.and_then(num) == Some(1.0)
}

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn f(v: Option<&Value>) -> f64 {
    v.and_then(num).unwrap_or(f64::NAN)
}

/// The signed message: the strict content hash of `{kind, body}`, as text.
fn msg(kind: &str, body: &Value) -> Result<Vec<u8>, String> {
    crate::hash_canonical_strict(&json!({ "kind": kind, "body": body }))
        .map(String::into_bytes)
        .ok_or_else(|| "canonicalize: value outside the strict profile".to_string())
}

fn sign(seed: &[u8; 32], kind: &str, body: &Value) -> Result<String, String> {
    Ok(ed_sign(seed, &msg(kind, body)?))
}

/// The reference's `verify(decodeKey(principal), msg, decodeKey(sig))`: a decoding failure throws (`Err`), a wrong length or a bad
/// signature is `Ok(false)`.
fn verify(principal: &str, kind: &str, body: &Value, sig: &str) -> Result<bool, String> {
    let pk = crate::decode_b64u_strict(principal, None).ok_or("bad base64url")?;
    let m = msg(kind, body)?;
    let sg = crate::decode_b64u_strict(sig, None).ok_or("bad base64url")?;
    match (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sg)) {
        (Ok(pk), Ok(sg)) => Ok(crate::verify_ed25519_strict(&pk, &m, &sg)),
        _ => Ok(false),
    }
}

fn without_sig(o: &Map<String, Value>) -> Value {
    Value::Object(o.iter().filter(|(k, _)| k.as_str() != "sig").map(|(k, v)| (k.clone(), v.clone())).collect())
}

fn with_sig(body: &Value, sig: String) -> Value {
    let mut out = body.as_object().cloned().unwrap_or_default();
    out.insert("sig".into(), json!(sig));
    Value::Object(out)
}

/// Sign a pricing configuration body (`{v: 1, principal, currency, interruptionCost, maxInterruptionCost, hardCeilingLoss,
/// tightenStepPpm, epoch}`) with the principal's seed.
pub fn sign_pricing_config(body: &Value, principal_seed: &[u8; 32]) -> Result<Value, String> {
    Ok(with_sig(body, sign(principal_seed, "pca.escalation_pricing", body)?))
}

/// Why a signed pricing configuration is refused, or `None` (a pure function of its content).
pub fn pricing_config_error(c: &Value) -> Option<String> {
    let bad = |r: &str| Some(r.to_string());
    let Some(x) = c.as_object() else { return bad("config_malformed") };
    if !is_one(x.get("v")) || s(x.get("principal")).is_none() || s(x.get("currency")).is_none() || s(x.get("sig")).is_none() {
        return bad("config_malformed");
    }
    if !(is_minor(x.get("interruptionCost")) && is_minor(x.get("maxInterruptionCost")) && is_minor(x.get("hardCeilingLoss")) && is_minor(x.get("epoch"))) {
        return bad("config_amounts_invalid");
    }
    if f(x.get("interruptionCost")) > f(x.get("maxInterruptionCost")) {
        return bad("config_cost_above_max");
    }
    let step = x.get("tightenStepPpm");
    if !step.is_some_and(is_safe_int) || f(step) < 0.0 || f(step) > MAX_MULTIPLIER_PPM as f64 {
        return bad("config_step_invalid");
    }
    match verify(s(x.get("principal"))?, "pca.escalation_pricing", &without_sig(x), s(x.get("sig"))?) {
        Ok(true) => None,
        Ok(false) => bad("config_signature_invalid"),
        Err(_) => bad("config_malformed"),
    }
}

pub fn fresh_calibration() -> Value {
    json!({ "multiplierPpm": PPM, "seen": [] })
}

/// `{ask, reason}`. Pure and total: anything unverifiable or out of range asks.
pub fn decide_escalation(config: &Value, cal: &Value, a: &Value) -> Value {
    let ask = |reason: &str| json!({ "ask": true, "reason": reason });
    if let Some(e) = pricing_config_error(config) {
        return ask(&e);
    }
    let cfg = config.as_object().cloned().unwrap_or_default();
    let Some(a) = a.as_object().filter(|a| a.get("currency") == cfg.get("currency")) else { return ask("currency_mismatch") };
    let (loss, p) = (a.get("loss"), a.get("pBadUpperPpm"));
    if !is_minor(loss) || neg_zero(loss) || !p.is_some_and(is_safe_int) || f(p) < 0.0 || neg_zero(p) || f(p) > PPM as f64 {
        return ask("risk_input_invalid");
    }
    let mult = cal.as_object().and_then(|c| c.get("multiplierPpm"));
    if !(mult.is_some_and(is_safe_int) && f(mult) >= PPM as f64 && f(mult) <= MAX_MULTIPLIER_PPM as f64) {
        return ask("calibration_invalid");
    }
    if f(loss) > f(cfg.get("hardCeilingLoss")) {
        return ask("above_hard_ceiling");
    }
    // effective P(bad) = min(1, p * mult), in units of 1e-12: p_ppm * mult_ppm. Compare p * mult * loss > cost * 1e12.
    let ppm2 = (PPM as u128) * (PPM as u128);
    let pe = (f(p) as u128) * (f(mult) as u128);
    let capped = pe.min(ppm2);
    let lhs = capped * (f(loss) as u128);
    let rhs = (f(cfg.get("interruptionCost")) as u128) * ppm2;
    if lhs > rhs {
        ask("expected_loss_exceeds_interruption_cost")
    } else {
        json!({ "ask": false, "reason": "expected_loss_within_interruption_cost" })
    }
}

/// Sign an answer body (`{v: 1, principal, nonce, action_digest, answer: "approve" | "deny"}`).
pub fn sign_answer(body: &Value, principal_seed: &[u8; 32]) -> Result<Value, String> {
    Ok(with_sig(body, sign(principal_seed, "pca.escalation_answer", body)?))
}

fn answer_ok(a: &Value, principal: &str) -> bool {
    let Some(o) = a.as_object() else { return false };
    if !is_one(o.get("v")) || s(o.get("principal")) != Some(principal) {
        return false;
    }
    if !s(o.get("nonce")).is_some_and(|n| u16len(n) >= 8)
        || s(o.get("action_digest")).is_none()
        || !matches!(s(o.get("answer")), Some("approve") | Some("deny"))
    {
        return false;
    }
    match s(o.get("sig")) {
        Some(sig) => verify(principal, "pca.escalation_answer", &without_sig(o), sig).unwrap_or(false),
        None => false,
    }
}

/// Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have auto-approved
/// is a miss and adds `tightenStepPpm` (capped); anything else changes nothing. The multiplier never decreases. `risks` maps an action
/// digest to its `{currency, loss, pBadUpperPpm}`.
pub fn update_calibration(config: &Value, cal: &Value, answers: &[Value], risks: &Value) -> Result<Value, String> {
    if pricing_config_error(config).is_some() {
        return Ok(cal.clone());
    }
    let cfg = config.as_object().ok_or("config")?;
    let principal = s(cfg.get("principal")).ok_or("principal")?;
    let step = f(cfg.get("tightenStepPpm"));
    let mut mult = f(cal.get("multiplierPpm"));
    let mut order: Vec<String> = vec![];
    for x in cal.get("seen").and_then(Value::as_array).ok_or("cal.seen is not iterable")? {
        order.push(x.as_str().ok_or("seen entry")?.to_string());
    }
    let mut seen: HashSet<String> = order.iter().cloned().collect();
    for a in answers {
        if !answer_ok(a, principal) {
            continue;
        }
        let nonce = s(a.get("nonce")).unwrap_or("");
        if seen.contains(nonce) {
            continue;
        }
        seen.insert(nonce.to_string());
        order.push(nonce.to_string());
        let risk = risks.get(s(a.get("action_digest")).unwrap_or(""));
        let Some(risk) = risk else { continue };
        if s(a.get("answer")) != Some("deny") {
            continue;
        }
        let probe = json!({ "multiplierPpm": mult, "seen": [] });
        if decide_escalation(config, &probe, risk)["ask"] == json!(false) {
            let up = mult + step;
            mult = if up < MAX_MULTIPLIER_PPM as f64 { up } else { MAX_MULTIPLIER_PPM as f64 };
        }
    }
    let base = f(cal.get("multiplierPpm"));
    Ok(json!({ "multiplierPpm": if mult.is_nan() || base.is_nan() { f64::NAN } else { mult.max(base) }, "seen": order }))
}

/// Sign an autonomy raise body (`{v: 1, principal, epoch, newInterruptionCost}`).
pub fn sign_autonomy_raise(b: &Value, seed: &[u8; 32]) -> Result<Value, String> {
    Ok(with_sig(b, sign(seed, "pca.autonomy_raise", b)?))
}

/// A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within
/// `maxInterruptionCost`; `Err` otherwise. Returns the new signed configuration.
pub fn apply_autonomy_raise(config: &Value, raise: &Value, principal_seed: &[u8; 32]) -> Result<Value, String> {
    let r = raise.as_object().ok_or("Cannot destructure a non-object raise")?;
    let cfg = config.as_object().ok_or("Cannot read properties of null")?;
    let ok = (|| -> Result<bool, String> {
        let principal = s(cfg.get("principal")).ok_or("principal")?;
        if !is_one(r.get("v")) || s(r.get("principal")) != Some(principal) {
            return Ok(false);
        }
        verify(principal, "pca.autonomy_raise", &without_sig(r), s(r.get("sig")).ok_or("sig")?)
    })()
    .unwrap_or(false);
    if !ok {
        return Err("applyAutonomyRaise: signature or principal invalid".into());
    }
    if !(f(r.get("epoch")) > f(cfg.get("epoch"))) {
        return Err("applyAutonomyRaise: epoch must advance".into());
    }
    let cost = r.get("newInterruptionCost");
    if !is_minor(cost) || f(cost) > f(cfg.get("maxInterruptionCost")) {
        return Err("applyAutonomyRaise: above the configured maximum".into());
    }
    let mut body = without_sig(cfg).as_object().cloned().unwrap_or_default();
    body.insert("interruptionCost".into(), cost.cloned().unwrap_or(Value::Null));
    body.insert("epoch".into(), r.get("epoch").cloned().unwrap_or(Value::Null));
    sign_pricing_config(&Value::Object(body), principal_seed)
}
