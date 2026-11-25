//! Payments for PCA: a payment mandate as a Root Intent Grant, the charge decision, the charge PCActn, Shared Payment Token
//! limits, spend rails (card limits, settlement reconciliation), the Stripe Issuing adapter and agent network tokens.
//!
//! Values are the reference's JSON shapes (camelCase members). Inputs follow JavaScript semantics where the reference does
//! (missing members, truthiness, coercing arithmetic), so a hostile mandate or charge is refused or priced exactly as the
//! reference does; a JavaScript runtime TypeError is an `Err` with the reference's message. This package carries no policy
//! engine: the charge decision takes the PCA decision function as an injected closure. Secrets are raw Ed25519 seeds passed
//! beside the options (the reference takes them as bytes inside the options).
use crate::actions::{js_str_to_number, js_to_number};
use crate::agent::{build_pcactn, mint_grant, KeyPair, PcactnInput, Suite};
use crate::intent_v2::js_number_string;
use crate::oauth::{js_str, spread, truthy};
use crate::{decode_b64u_strict, hash_canonical_strict, js_stringify};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

pub const CHARGE_REVERSIBILITY_CLASS: &str = "reversible";
pub const CHARGE_VERB: &str = "charge";
pub const AMOUNT_NOT_MINOR_UNITS: &str = "amount_not_integer_minor_units";
pub const MERCHANT_INVALID: &str = "merchant_invalid";
pub const STRIPE_WEBHOOK_TOLERANCE_SEC: f64 = 300.0;
pub const STRIPE_API_VERSION: &str = "2025-03-31.basil";
pub const NETWORK_TOKEN_BINDING_KIND: &str = "pca.network_token_binding";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A refusal of the charge decision: `code` is set for the reference's `MandateGrantError`
/// (`verified_grant_required`, `mandate_grant_mismatch`, `mandate_terms_mismatch`).
#[derive(Debug, Clone, PartialEq)]
pub struct PayError {
    pub code: Option<&'static str>,
    pub message: String,
}

impl From<String> for PayError {
    fn from(message: String) -> Self {
        PayError { code: None, message }
    }
}

impl From<&str> for PayError {
    fn from(message: &str) -> Self {
        PayError { code: None, message: message.to_string() }
    }
}

impl std::fmt::Display for PayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn grant_err(code: &'static str, message: &str) -> PayError {
    PayError { code: Some(code), message: message.to_string() }
}

// ---- JavaScript value semantics (None = `undefined`) ----------------------------------------------------------------------

pub(crate) type V<'a> = Option<&'a Value>;

/// `o.k`: a TypeError for null / undefined, `undefined` for a missing member or a primitive.
pub(crate) fn prop<'a>(o: V<'a>, k: &str) -> Result<V<'a>, String> {
    match o {
        None => Err(format!("Cannot read properties of undefined (reading '{k}')")),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{k}')")),
        Some(Value::Object(m)) => Ok(m.get(k)),
        Some(_) => Ok(None),
    }
}

/// `o?.k`.
pub(crate) fn optprop<'a>(o: V<'a>, k: &str) -> Result<V<'a>, String> {
    if nullish(o) {
        Ok(None)
    } else {
        prop(o, k)
    }
}

pub(crate) fn nullish(v: V) -> bool {
    matches!(v, None | Some(Value::Null))
}

pub(crate) fn num_of(v: V) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

pub(crate) fn isfinite(v: V) -> bool {
    num_of(v).is_some_and(f64::is_finite)
}

pub(crate) fn safe_f(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE
}

pub(crate) fn safe_int(v: V) -> bool {
    num_of(v).is_some_and(safe_f)
}

/// `Number.isInteger`.
pub(crate) fn is_integer(v: V) -> bool {
    num_of(v).is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

/// A JS number as JSON: a whole number is an integer, NaN / Infinity (not JSON) become null.
pub(crate) fn num(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

/// `String(v)` as a template literal renders it.
pub(crate) fn tostr(v: V) -> String {
    v.map_or_else(|| "undefined".to_string(), js_str)
}

/// `a === b` for JSON values (an object or array is never identical to another).
pub(crate) fn seq(a: V, b: V) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::Object(_) | Value::Array(_)), _) | (_, Some(Value::Object(_) | Value::Array(_))) => false,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// `v.length`: a TypeError for null / undefined; a string's UTF-16 length, an array's length, an object's `length` member.
pub(crate) fn length(v: V) -> Result<Option<Value>, String> {
    match v {
        None | Some(Value::Null) => Err("Cannot read properties of undefined (reading 'length')".into()),
        Some(Value::String(s)) => Ok(Some(json!(s.encode_utf16().count()))),
        Some(Value::Array(a)) => Ok(Some(json!(a.len()))),
        Some(Value::Object(m)) => Ok(m.get("length").cloned()),
        Some(_) => Ok(None),
    }
}

pub(crate) fn gt0(v: V) -> bool {
    js_to_number(v) > 0.0
}

fn length_is_zero(v: V) -> Result<bool, String> {
    Ok(matches!(length(v)?, Some(Value::Number(n)) if n.as_f64() == Some(0.0)))
}

pub(crate) fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

pub(crate) fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `Math.round`.
pub(crate) fn js_round(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let r = x.floor();
    if x - r >= 0.5 {
        r + 1.0
    } else {
        r
    }
}

/// `a > b` for two JSON values (strings compare by UTF-16 code unit, anything else as numbers).
pub(crate) fn js_gt(a: V, b: V) -> bool {
    if let (Some(Value::String(x)), Some(Value::String(y))) = (a, b) {
        return x.encode_utf16().cmp(y.encode_utf16()) == std::cmp::Ordering::Greater;
    }
    js_to_number(a) > js_to_number(b)
}

/// `{...v}` members.
pub(crate) fn spread_obj(v: V) -> Map<String, Value> {
    match v {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Some(Value::String(s)) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            units.iter().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[*u])))).collect()
        }
        _ => Map::new(),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// base64url(sha256(strict canonical(v))); an `undefined` or out-of-profile value is a TypeError.
pub(crate) fn hash_strict(v: V) -> Result<String, String> {
    match v {
        None => Err("canonicalize: unsupported type undefined".into()),
        Some(x) => hash_canonical_strict(x).ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string()),
    }
}

pub(crate) fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn keypair(seed: &[u8]) -> Result<KeyPair, String> {
    let s: [u8; 32] = seed.try_into().map_err(|_| "an Ed25519 seed is 32 bytes".to_string())?;
    Ok(KeyPair::from_seed(&s))
}

/// STRICT RFC 8032 verification (canonical encodings, canonical S, no small-order or torsion components, `verify_strict`).
pub(crate) fn ed25519_verify(pk: &[u8], msg: &[u8], sg: &[u8]) -> bool {
    let (Ok(pk), Ok(sg)): (Result<[u8; 32], _>, Result<[u8; 64], _>) = (pk.try_into(), sg.try_into()) else { return false };
    let Some(a) = CompressedEdwardsY(pk).decompress() else { return false };
    if a.compress().to_bytes() != pk {
        return false;
    }
    let mut rb = [0u8; 32];
    rb.copy_from_slice(&sg[..32]);
    let Some(r) = CompressedEdwardsY(rb).decompress() else { return false };
    if r.compress().to_bytes() != rb {
        return false;
    }
    if a.is_small_order() || r.is_small_order() || !a.is_torsion_free() || !r.is_torsion_free() {
        return false;
    }
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sg[32..]);
    if !bool::from(Scalar::from_canonical_bytes(sb).is_some()) {
        return false;
    }
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sg)).is_ok()
}

// ---- mandate --------------------------------------------------------------------------------------------------------------

/// A merchant id that cannot act as a resource pattern: a non-empty string with no `*` and no control characters.
pub fn is_plain_id(x: &Value) -> bool {
    x.as_str().is_some_and(|s| !s.is_empty() && !s.chars().any(|c| c == '*' || (c as u32) < 0x20 || c == '\u{7f}'))
}

/// A non-negative safe integer (amounts are integer minor units); `-0` is not one.
pub fn is_minor_units(x: &Value) -> bool {
    num_of(Some(x)).is_some_and(|f| safe_f(f) && f >= 0.0 && !(f == 0.0 && f.is_sign_negative()))
}

fn validate(p: &Value) -> Result<(), String> {
    let p = Some(p);
    let g = |k: &str| prop(p, k);
    // -0 is a number the strict canonicalizer refuses (grantDigestOf, hashCanonical): refuse it here too instead of signing it
    for k in ["perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now"] {
        if let Some(Value::Number(n)) = g(k)? {
            if n.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative()) {
                return Err(format!("buildPaymentMandate: {k} must not be negative zero"));
            }
        }
    }
    let strict = !matches!(g("strictMinorUnits")?, Some(Value::Bool(false)));
    if strict {
        let rep = g("replenishPerCosign")?;
        let zero = json!(0);
        let reps = if nullish(rep) { Some(&zero) } else { rep };
        for (k, v) in [
            ("perTransactionCap", g("perTransactionCap")?),
            ("autoApproveThreshold", g("autoApproveThreshold")?),
            ("cumulativeCap", g("cumulativeCap")?),
            ("replenishPerCosign", reps),
        ] {
            if !safe_int(v) {
                return Err(format!("buildPaymentMandate: {k} must be a safe integer in minor units (strictMinorUnits)"));
            }
        }
    }
    let Some(Value::Array(ms)) = g("merchants")? else {
        return Err("buildPaymentMandate: at least one allowlisted merchant is required".into());
    };
    if ms.is_empty() {
        return Err("buildPaymentMandate: at least one allowlisted merchant is required".into());
    }
    if ms.iter().any(|m| m.as_str().map_or(true, str::is_empty)) {
        return Err("buildPaymentMandate: merchant ids must be non-empty strings".into());
    }
    if ms.iter().any(|m| !is_plain_id(m)) {
        return Err("buildPaymentMandate: merchant ids must not contain `*` or control characters".into());
    }
    if g("currency")?.and_then(Value::as_str).map_or(true, str::is_empty) {
        return Err("buildPaymentMandate: currency is required".into());
    }
    let fin = |v: V| num_of(v).filter(|f| f.is_finite());
    let xf = fin(g("perTransactionCap")?);
    if xf.map_or(true, |f| f <= 0.0) {
        return Err("buildPaymentMandate: perTransactionCap (X) must be a finite number > 0".into());
    }
    let xf = xf.unwrap_or(0.0);
    if fin(g("autoApproveThreshold")?).map_or(true, |y| y < 0.0 || y > xf) {
        return Err("buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 \u{2264} Y \u{2264} X".into());
    }
    if fin(g("cumulativeCap")?).map_or(true, |c| c < xf) {
        return Err("buildPaymentMandate: cumulativeCap must be a finite number \u{2265} perTransactionCap (X)".into());
    }
    if let Some(pm) = g("periodMs")? {
        if fin(Some(pm)).map_or(true, |f| f <= 0.0) {
            return Err("buildPaymentMandate: periodMs must be a finite number > 0 when given".into());
        }
    }
    if let Some(mx) = g("maxTransactionsPerPeriod")? {
        if !is_integer(Some(mx)) || num_of(Some(mx)).map_or(true, |f| f <= 0.0) {
            return Err("buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given".into());
        }
    }
    if let Some(r) = g("replenishPerCosign")? {
        if fin(Some(r)).map_or(true, |f| f < 0.0) {
            return Err("buildPaymentMandate: replenishPerCosign must be a finite number \u{2265} 0 when given".into());
        }
    }
    Ok(())
}

fn cond(field: &str, op: &str, value: V) -> Value {
    let mut m = Map::new();
    m.insert("field".into(), json!(field));
    m.insert("op".into(), json!(op));
    if let Some(v) = value {
        m.insert("value".into(), v.clone());
    }
    Value::Object(m)
}

/// The predicates plus whether the reference's objects carry an `undefined` member (a hash of them is a TypeError there).
fn predicates_raw(terms: &Value) -> Result<(Vec<Value>, bool), String> {
    let t = Some(terms);
    let Some(Value::Array(ms)) = prop(t, "merchants")? else {
        return Err("terms.merchants.map is not a function".into());
    };
    let (cap, cur) = (prop(t, "perTransactionCap")?, prop(t, "currency")?);
    let (mut out, mut undef) = (Vec::new(), false);
    for m in ms {
        let cats = prop(t, "categories")?;
        let n = length(cats)?;
        let zero = json!(0);
        let mut conds =
            vec![cond("action.params.amount", "lte", cap), cond("action.params.currency", "eq", cur), cond("action.params.amount", "gte", Some(&zero))];
        if gt0(n.as_ref()) {
            conds.push(cond("action.params.category", "in", cats));
        }
        undef |= cap.is_none() || cur.is_none();
        out.push(json!({"verb": "charge", "resource": format!("merchant:{}", js_str(m)), "where": conds}));
    }
    Ok((out, undef))
}

/// One predicate per merchant, each carrying the currency, category and hard-ceiling guards.
pub fn mandate_predicates(terms: &Value) -> Result<Value, String> {
    predicates_raw(terms).map(|(p, _)| Value::Array(p))
}

/// The envelope caveats: period window, velocity cap, and the bonded / refundable reversibility floor.
pub fn mandate_caveats(terms: &Value) -> Result<Value, String> {
    let t = Some(terms);
    let mut cv = Vec::new();
    let ps = prop(t, "periodStart")?;
    if gt0(ps) {
        cv.push(json!({"type": "not_before", "at": ps}));
    }
    let pe = prop(t, "periodEnd")?;
    if let Some(pe) = pe {
        cv.push(json!({"type": "expires", "at": pe}));
    }
    if let (Some(mx), Some(pe)) = (prop(t, "maxTransactionsPerPeriod")?, pe) {
        let per = js_max(1.0, js_round((js_to_number(Some(pe)) - js_to_number(ps)) / 1000.0));
        cv.push(json!({"type": "rate", "max": mx, "per_secs": num(per)}));
    }
    cv.push(json!({"type": "reversibility_max", "class": "reversible"}));
    Ok(Value::Array(cv))
}

/// The risk policy that makes "spend = risk" exact: only blast radius weighs, theta1 = theta2 = Y/X, kappa = X, bMax = the cap.
pub fn mandate_risk_policy(terms: &Value, replenish_per_cosign: &Value) -> Result<Value, String> {
    let t = Some(terms);
    let (a, x) = (prop(t, "autoApproveThreshold")?, prop(t, "perTransactionCap")?);
    let th = num(js_to_number(a) / js_to_number(x));
    let mut m = Map::new();
    m.insert("weights".into(), json!({"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0}));
    m.insert("theta1".into(), th.clone());
    m.insert("theta2".into(), th);
    if let Some(x) = x {
        m.insert("kappa".into(), x.clone());
    }
    m.insert("lambda".into(), json!(0));
    m.insert("rho".into(), replenish_per_cosign.clone());
    if let Some(c) = prop(t, "cumulativeCap")? {
        m.insert("bMax".into(), c.clone());
    }
    Ok(Value::Object(m))
}

/// The most an agent can spend autonomously between two human co-signs: `safetyBound * kappa` (equals the cumulative cap).
pub fn auto_spend_bound(mandate: &Value) -> Result<Value, String> {
    let p = prop(Some(mandate), "policy")?;
    let (kappa, b_max) = (prop(p, "kappa")?, prop(p, "bMax")?);
    let k = js_to_number(kappa);
    let bound = if k > 0.0 { js_max(0.0, js_to_number(b_max)) / k } else { 0.0 };
    Ok(num(bound * k))
}

/// Encode the params as a PCA Root Intent Grant envelope plus the initial trust budget. `principal_seed` is the 32-byte Ed25519
/// seed that signs the grant (the reference's `principalSecret`); `principalPublic` must be its public key (stricter: the
/// reference signs with the seed and names whatever public key it was given).
pub fn build_payment_mandate(params: &Value, principal_seed: &[u8]) -> Result<Value, String> {
    validate(params)?;
    let p = Some(params);
    let g = |k: &str| prop(p, k);
    let now_v = if isfinite(g("now")?) { g("now")?.cloned().unwrap_or(Value::Null) } else { json!(now_ms()) };
    let ps_v = if isfinite(g("periodStart")?) { g("periodStart")?.cloned().unwrap_or(Value::Null) } else { now_v.clone() };
    let cats = g("categories")?;
    let mut terms = Map::new();
    terms.insert("merchants".into(), g("merchants")?.cloned().unwrap_or(Value::Null));
    terms.insert("categories".into(), if truthy(cats) { Value::Array(spread(cats.unwrap_or(&Value::Null), "object")?) } else { json!([]) });
    for k in ["currency", "perTransactionCap", "autoApproveThreshold", "cumulativeCap"] {
        terms.insert(k.into(), g(k)?.cloned().unwrap_or(Value::Null));
    }
    terms.insert("periodStart".into(), ps_v.clone());
    if let Some(pm) = g("periodMs")? {
        terms.insert("periodEnd".into(), num(js_to_number(Some(&ps_v)) + js_to_number(Some(pm))));
    }
    if let Some(mx) = g("maxTransactionsPerPeriod")? {
        terms.insert("maxTransactionsPerPeriod".into(), mx.clone());
    }
    let terms = Value::Object(terms);
    let rep = g("replenishPerCosign")?;
    let cap = &terms["cumulativeCap"];
    let policy = mandate_risk_policy(&terms, if nullish(rep) { cap } else { rep.unwrap_or(cap) })?;
    let goal = match g("goal")? {
        None | Some(Value::Null) => {
            let ms: Vec<&str> = terms["merchants"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            format!(
                "spend \u{2264} {} {} autonomously / \u{2264} {} with co-sign, \u{2264} {} cumulative, at [{}]",
                tostr(terms.get("autoApproveThreshold")),
                terms["currency"].as_str().unwrap_or(""),
                tostr(terms.get("perTransactionCap")),
                tostr(terms.get("cumulativeCap")),
                ms.join(", ")
            )
        }
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => return Err("mintGrant: goal required".into()),
    };
    let principal = keypair(principal_seed)?;
    if g("principalPublic")?.and_then(Value::as_str) != Some(principal.public.as_str()) {
        return Err("buildPaymentMandate: principalPublic is not the public key of principalSecret".into());
    }
    let salt = match g("goalSalt")? {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("mintGrant: salt must be a string".into()),
    };
    let holder = g("agentPublic")?.and_then(Value::as_str).ok_or("mintGrant: holder must be a string")?;
    let envelope = json!({"predicates": mandate_predicates(&terms)?, "caveats": mandate_caveats(&terms)?, "agent_binding": {}, "risk_policy": policy});
    let minted = mint_grant(&principal, holder, &envelope, &goal, salt, None, &Suite::default())?;
    Ok(json!({"grant": minted.grant, "policy": policy, "budget": {"B": cap, "tau": now_v, "asOf": now_v}, "terms": terms,
        "goalCommit": minted.goal_commit, "goalSalt": minted.goal_salt}))
}

// ---- charge decision ------------------------------------------------------------------------------------------------------

/// The charge params (and whether the reference's object would carry an `undefined` member): the amount, the currency (only an
/// ABSENT currency defaults to the mandate's) and the category when present.
fn charge_params_raw(mandate: &Value, charge: &Value) -> Result<(Map<String, Value>, bool), String> {
    let c = Some(charge);
    let amount = prop(c, "amount")?;
    let cur = prop(c, "currency")?;
    let cur = if cur.is_none() { prop(prop(Some(mandate), "terms")?, "currency")? } else { cur };
    let mut p = Map::new();
    if let Some(a) = amount {
        p.insert("amount".into(), a.clone());
    }
    if let Some(cu) = cur {
        p.insert("currency".into(), cu.clone());
    }
    if let Some(cat) = prop(c, "category")? {
        p.insert("category".into(), cat.clone());
    }
    Ok((p, amount.is_none() || cur.is_none()))
}

/// The charge params committed in both the plan node and the PCActn action (they must reconcile).
pub fn charge_params(mandate: &Value, charge: &Value) -> Result<Value, String> {
    charge_params_raw(mandate, charge).map(|(p, _)| Value::Object(p))
}

/// The action a charge denotes: the verb / resource / params the predicates and risk read.
pub fn charge_action_context(mandate: &Value, charge: &Value) -> Result<Value, String> {
    let params = charge_params(mandate, charge)?;
    Ok(json!({"action": {"verb": CHARGE_VERB, "resource": format!("merchant:{}", tostr(prop(Some(charge), "merchant")?)),
        "params": params, "reversibility_class": CHARGE_REVERSIBILITY_CLASS}}))
}

fn same(a: &Value, b: &Value) -> Result<bool, String> {
    Ok(hash_strict(Some(a))? == hash_strict(Some(b))?)
}

fn bind_to_verified_grant(mandate: &Value, verified_grant: &Value) -> Result<Value, PayError> {
    if !matches!(verified_grant, Value::Object(_) | Value::Array(_)) {
        return Err(grant_err("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority"));
    }
    let m = Some(mandate);
    if !matches!(mandate, Value::Object(_) | Value::Array(_)) || hash_strict(prop(m, "grant")?)? != hash_strict(Some(verified_grant))? {
        return Err(grant_err("mandate_grant_mismatch", "the mandate grant is not the verified grant"));
    }
    let env = crate::authorize::read_envelope(verified_grant);
    let (terms, policy) = (prop(m, "terms")?, prop(m, "policy")?);
    let mismatch = || grant_err("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant");
    let Some(env) = env else { return Err(mismatch()) };
    if !truthy(terms) || !truthy(policy) {
        return Err(mismatch());
    }
    let (terms, policy) = (terms.unwrap_or(&Value::Null), policy.unwrap_or(&Value::Null));
    let (preds, undef) = predicates_raw(terms)?;
    if undef {
        return Err("canonicalize: unsupported type undefined".to_string().into());
    }
    let null = Value::Null;
    if !same(env.get("predicates").unwrap_or(&null), &Value::Array(preds))?
        || !same(env.get("caveats").unwrap_or(&null), &mandate_caveats(terms)?)?
        || !same(env.get("risk_policy").unwrap_or(&null), policy)?
    {
        return Err(mismatch());
    }
    let b_max = env.get("risk_policy").and_then(|r| r.get("bMax")).and_then(Value::as_f64).unwrap_or(f64::NAN);
    let budget = prop(m, "budget")?;
    let b = optprop(budget, "B")?;
    let bb = if isfinite(b) { js_max(0.0, js_min(js_to_number(b), b_max)) } else { 0.0 };
    let mut out = spread_obj(m);
    out.insert("grant".into(), verified_grant.clone());
    let mut nb = spread_obj(budget);
    nb.insert("B".into(), num(bb));
    out.insert("budget".into(), Value::Object(nb));
    Ok(Value::Object(out))
}

/// The decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate whose grant, terms or policy
/// differ from `verified_grant` is refused (`MandateGrantError`).
pub fn charge_decide_input(mandate0: &Value, charge: &Value, now: &Value, verified_grant: &Value) -> Result<Value, PayError> {
    let mandate = bind_to_verified_grant(mandate0, verified_grant)?;
    let x = prop(prop(Some(&mandate), "terms")?, "perTransactionCap")?;
    let amount = prop(Some(charge), "amount")?;
    let amount = if isfinite(amount) { js_to_number(amount) } else { f64::INFINITY };
    let xf = js_to_number(x);
    let blast = if xf > 0.0 { amount / xf } else { 1.0 };
    let mut ctx = Map::new();
    ctx.insert("reversibilityClass".into(), json!(CHARGE_REVERSIBILITY_CLASS));
    if let Some(r) = prop(Some(charge), "recentChargeTimes")? {
        ctx.insert("recentActionTimes".into(), r.clone());
    }
    Ok(json!({"grant": verified_grant, "action": charge_action_context(&mandate, charge)?,
        "risk": {"semanticDistance": 0, "reversibility": 1, "blastRadius": num(blast), "taint": 0, "confidence": 1, "age": 0},
        "budget": mandate["budget"], "now": now, "caveatContext": ctx}))
}

/// Run a charge through the PCA decision against the grant you VERIFIED (or loaded from your own store). Pure: reads the mandate
/// budget (clamped to the signed bMax) and returns the next one in `budgetAfter`. `decide` is the PCA policy engine.
pub fn authorize_charge(mandate0: &Value, charge: &Value, verified_grant: &Value, decide: &dyn Fn(&Value) -> Result<Value, String>) -> Result<Value, PayError> {
    let mandate = bind_to_verified_grant(mandate0, verified_grant)?;
    let now = prop(Some(charge), "now")?;
    let now_v = if isfinite(now) { now.cloned().unwrap_or(Value::Null) } else { json!(now_ms()) };
    let raw = decide(&charge_decide_input(&mandate, charge, &now_v, verified_grant)?)?;
    let (amount, merchant) = (prop(Some(charge), "amount")?, prop(Some(charge), "merchant")?);
    let refusal = if !amount.is_some_and(is_minor_units) {
        Some(AMOUNT_NOT_MINOR_UNITS)
    } else if !merchant.is_some_and(is_plain_id) {
        Some(MERCHANT_INVALID)
    } else {
        None
    };
    let decision = match refusal {
        None => raw.clone(),
        Some(r) => {
            let mut d = raw.as_object().cloned().ok_or("Cannot read properties of undefined (reading 'reasons')")?;
            let mut reasons = vec![json!(r)];
            reasons.extend(raw.get("reasons").and_then(Value::as_array).ok_or("raw.reasons is not iterable")?.iter().cloned());
            d.insert("admit".into(), json!(false));
            d.insert("releaseGuardianShare".into(), json!(false));
            d.insert("reasons".into(), Value::Array(reasons));
            d.insert("budget".into(), mandate["budget"].clone());
            Value::Object(d)
        }
    };
    let outcome = if !truthy(decision.get("releaseGuardianShare")) {
        "deny"
    } else if truthy(decision.get("admit")) {
        "auto"
    } else {
        "step_up"
    };
    let (policy, terms, budget) = (Some(&mandate["policy"]), Some(&mandate["terms"]), &mandate["budget"]);
    let kappa = prop(policy, "kappa")?;
    let exact = outcome == "auto" && amount.is_some_and(is_minor_units) && seq(kappa, prop(terms, "perTransactionCap")?) && safe_int(budget.get("B"));
    let required = decision.get("requiredThreshold").ok_or("Cannot read properties of undefined (reading 't')")?;
    let r = decision.get("r");
    let cost = if outcome != "auto" {
        json!(0)
    } else if exact {
        amount.cloned().unwrap_or(Value::Null)
    } else {
        num(crate::risk::cost(num_of(r).unwrap_or(f64::NAN), js_to_number(kappa)))
    };
    let after = if exact {
        let mut b = spread_obj(decision.get("budget"));
        b.insert("B".into(), num(js_to_number(budget.get("B")) - js_to_number(amount)));
        Value::Object(b)
    } else {
        decision.get("budget").cloned().unwrap_or(Value::Null)
    };
    Ok(json!({"outcome": outcome, "t": required.get("t"), "r": r, "requiredThreshold": required, "cost": cost, "budgetBefore": budget,
        "budgetAfter": after, "reasons": decision.get("reasons"), "decision": decision}))
}

/// Advance the mandate's budget after a decision (functional).
pub fn settle_charge(mandate: &Value, decision: &Value) -> Result<Value, String> {
    let mut m = spread_obj(Some(mandate));
    match prop(Some(decision), "budgetAfter")? {
        Some(b) => m.insert("budget".into(), b.clone()),
        None => m.remove("budget"),
    };
    Ok(Value::Object(m))
}

fn nz(v: V) -> f64 {
    num_of(v).filter(|f| f.is_finite() && *f > 0.0).unwrap_or(0.0)
}

fn recharge(b: V, rho: V, b_max: V, now: &Value) -> Result<Value, String> {
    let bb = prop(b, "B")?;
    let rho = nz(rho);
    let total = match bb {
        // `B + nz(rho)` concatenates when B is a string, an array or an object
        Some(Value::String(_) | Value::Array(_) | Value::Object(_)) => js_str_to_number(&format!("{}{}", tostr(bb), js_number_string(rho))),
        _ => js_to_number(bb) + rho,
    };
    Ok(json!({"B": num(js_min(nz(b_max), total)), "tau": now, "asOf": now}))
}

/// Apply a human co-sign: restore autonomous budget by `rho`, or fully re-confirm to `bMax` with `{"full": true}`. The only way
/// the budget goes up. `opts` None is `undefined` (defaults to `{}`); `Some(null)` is a TypeError, as in the reference.
pub fn apply_human_cosign(mandate: &Value, now: &Value, opts: Option<&Value>) -> Result<Value, String> {
    let empty = json!({});
    let full = truthy(prop(Some(opts.unwrap_or(&empty)), "full")?);
    let m = Some(mandate);
    let budget = if full {
        json!({"B": num(nz(prop(prop(m, "policy")?, "bMax")?)), "tau": now, "asOf": now})
    } else {
        let policy = prop(m, "policy")?;
        recharge(prop(m, "budget")?, prop(policy, "rho")?, prop(policy, "bMax")?, now)?
    };
    let mut out = spread_obj(m);
    out.insert("budget".into(), budget);
    Ok(Value::Object(out))
}

/// Durable cumulative-budget state with an atomic compare-and-set (the reference's `ChargeBudgetStore`).
pub trait ChargeBudgetStore {
    /// The record of `key`: `{budget, version}`, or `None` when there is none yet.
    fn get(&self, key: &str) -> Result<Option<Value>, String>;
    /// Commit `budget` only while the stored version still equals `expected` (`None` = no record yet).
    fn compare_and_set(&self, key: &str, expected: Option<i64>, budget: &Value) -> Result<bool, String>;
}

const MAX_CAS_ATTEMPTS: usize = 8;

fn valid_record(r: &Value) -> bool {
    let v = r.get("version");
    let b = r.get("budget");
    safe_int(v)
        && !num_of(v).is_some_and(|f| f == 0.0 && f.is_sign_negative())
        && b.is_some_and(Value::is_object)
        && ["B", "tau", "asOf"].iter().all(|k| isfinite(b.and_then(|b| b.get(*k))))
}

fn record_of(store: &dyn ChargeBudgetStore, key: &str) -> Result<Option<Value>, String> {
    let rec = store.get(key)?;
    if rec.as_ref().is_some_and(|r| !valid_record(r)) {
        return Err("the store returned a malformed budget record".into());
    }
    Ok(rec)
}

/// [`authorize_charge`] against the DURABLE cumulative budget in `store`. An auto debit is committed with a compare-and-set before
/// it is returned; losing the race re-reads and re-decides; persistent contention returns a deny.
pub fn authorize_charge_atomic(
    mandate: &Value,
    charge: &Value,
    verified_grant: &Value,
    store: &dyn ChargeBudgetStore,
    decide: &dyn Fn(&Value) -> Result<Value, String>,
    key: Option<&str>,
) -> Result<Value, PayError> {
    let key = match key {
        Some(k) => k.to_string(),
        None => hash_strict(Some(verified_grant))?,
    };
    for _ in 0..MAX_CAS_ATTEMPTS {
        let rec = record_of(store, &key)?;
        let m = match &rec {
            Some(r) => {
                let mut o = spread_obj(Some(mandate));
                o.insert("budget".into(), r["budget"].clone());
                Value::Object(o)
            }
            None => mandate.clone(),
        };
        let d = authorize_charge(&m, charge, verified_grant, decide)?;
        if d["outcome"] != "auto" {
            return Ok(d);
        }
        if store.compare_and_set(&key, rec.as_ref().and_then(|r| r["version"].as_i64()), &d["budgetAfter"])? {
            return Ok(d);
        }
    }
    let d = authorize_charge(mandate, charge, verified_grant, decide)?;
    let mut o = d.as_object().cloned().unwrap_or_default();
    let mut reasons = vec![json!("budget_store_conflict")];
    reasons.extend(d["reasons"].as_array().cloned().unwrap_or_default());
    o.insert("outcome".into(), json!("deny"));
    o.insert("t".into(), json!(3));
    o.insert("cost".into(), json!(0));
    o.insert("budgetAfter".into(), d["budgetBefore"].clone());
    o.insert("reasons".into(), Value::Array(reasons));
    Ok(Value::Object(o))
}

/// [`apply_human_cosign`] against the DURABLE budget, committed with a compare-and-set so a co-sign racing a charge is never lost or
/// applied twice. Call it only after verifying the human co-sign; persistent contention is an error.
pub fn apply_human_cosign_atomic(
    mandate: &Value,
    verified_grant: &Value,
    store: &dyn ChargeBudgetStore,
    now: &Value,
    full: bool,
    key: Option<&str>,
) -> Result<Value, PayError> {
    let key = match key {
        Some(k) => k.to_string(),
        None => hash_strict(Some(verified_grant))?,
    };
    for _ in 0..MAX_CAS_ATTEMPTS {
        let rec = record_of(store, &key)?;
        let base = match &rec {
            Some(r) => {
                let mut o = spread_obj(Some(mandate));
                o.insert("budget".into(), r["budget"].clone());
                Value::Object(o)
            }
            None => mandate.clone(),
        };
        let bound = bind_to_verified_grant(&base, verified_grant)?;
        let next = apply_human_cosign(&bound, now, Some(&json!({"full": full})))?["budget"].clone();
        if store.compare_and_set(&key, rec.as_ref().and_then(|r| r["version"].as_i64()), &next)? {
            return Ok(next);
        }
    }
    Err("could not commit the co-sign: the budget record kept changing".to_string().into())
}

// ---- charge as a proof-carrying action ------------------------------------------------------------------------------------

/// The committed plan node for a charge; `params_digest` is pinned to the charge params so the leaf reconciles with the PCActn.
pub fn charge_plan_node(mandate: &Value, charge: &Value, id: &str) -> Result<Value, String> {
    let (params, undef) = charge_params_raw(mandate, charge)?;
    if undef {
        return Err("canonicalize: unsupported type undefined".into());
    }
    Ok(json!({"id": id, "verb": CHARGE_VERB, "resource": format!("merchant:{}", tostr(prop(Some(charge), "merchant")?)),
        "reversibility_class": CHARGE_REVERSIBILITY_CLASS, "params_digest": hash_strict(Some(&Value::Object(params)))?}))
}

/// A signed PCActn for a charge: `{pcactn, node}`. `opts`: `aud`, `counter`, optional `chain`, `nodeId`, `now`. `signer_seed` is the
/// 32-byte Ed25519 seed of the leaf holder (the reference's `opts.signerSecret`).
pub fn charge_to_pcactn(mandate: &Value, charge: &Value, opts: &Value, signer_seed: &[u8]) -> Result<Value, String> {
    let (c, o) = (Some(charge), Some(opts));
    if !prop(c, "amount")?.is_some_and(is_minor_units) {
        return Err("chargeToPCActn: amount must be a non-negative integer in minor units".into());
    }
    let counter = prop(o, "counter")?;
    let node_id = match prop(o, "nodeId")? {
        None | Some(Value::Null) => format!("charge:{}:{}", tostr(prop(c, "merchant")?), tostr(counter)),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("chargeToPCActn: nodeId must be a string".into()),
    };
    let node = charge_plan_node(mandate, charge, &node_id)?;
    let x = prop(prop(Some(mandate), "terms")?, "perTransactionCap")?;
    let amount = prop(c, "amount")?;
    let amount = js_to_number(if isfinite(amount) { amount } else { x });
    let xf = js_to_number(x);
    let r = if xf > 0.0 { amount / xf } else { 1.0 };
    let r = if r < 0.0 {
        0.0
    } else if r > 1.0 {
        1.0
    } else {
        r
    };
    let params = charge_params(mandate, charge)?;
    let chain: Vec<Value> = match prop(o, "chain")? {
        None | Some(Value::Null) => vec![prop(Some(mandate), "grant")?.cloned().unwrap_or(Value::Null)],
        Some(Value::Array(a)) if !a.is_empty() => a.clone(),
        Some(_) => return Err("chain[0] is not a capability".into()),
    };
    let counter = num_of(counter).filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE).ok_or("build_pcactn: counter must be an integer")? as i64;
    let aud = prop(o, "aud")?.and_then(Value::as_str).unwrap_or("");
    let iat = match prop(o, "now")? {
        Some(n) if isfinite(Some(n)) => num_of(Some(n)).unwrap_or(0.0) as i64,
        _ => now_ms(),
    };
    let mut risk_inputs = params.as_object().cloned().unwrap_or_default();
    risk_inputs.insert("blastRadius".into(), num(r));
    let mut extra = Map::new();
    extra.insert("risk_claim".into(), json!({"r": num(r), "inputs": risk_inputs}));
    let signer = keypair(signer_seed)?;
    let pcactn = build_pcactn(&PcactnInput {
        grant: &chain[0],
        chain: &chain,
        plan: std::slice::from_ref(&node),
        node_id: &node_id,
        params: Some(&params),
        counter,
        signer: &signer,
        aud,
        iat,
        exp: None,
        extra,
        suite: Suite::default(),
    })?;
    Ok(json!({"pcactn": pcactn, "node": node}))
}

// ---- Shared Payment Token limits, rails -----------------------------------------------------------------------------------

/// The `usage_limits` of a Stripe Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a co-sign: at most
/// the auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the mandate period.
pub fn shared_payment_token_limits(mandate: &Value, now: &Value) -> Result<Value, String> {
    if !isfinite(Some(now)) {
        return Err("sharedPaymentTokenLimits: now must be an epoch-ms time".into());
    }
    let t = prop(Some(mandate), "terms")?;
    let budget = js_to_number(prop(prop(Some(mandate), "budget")?, "B")?).floor();
    let mx = js_min(js_to_number(prop(t, "autoApproveThreshold")?), budget);
    if !safe_f(mx) || mx <= 0.0 {
        return Err("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed".into());
    }
    let pe = prop(t, "periodEnd")?;
    if pe.is_some() && !isfinite(pe) {
        return Err("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time".into());
    }
    if pe.is_some() && !(js_to_number(Some(now)) < js_to_number(pe)) {
        return Err("sharedPaymentTokenLimits: the mandate period has ended".into());
    }
    let cur = prop(t, "currency")?.and_then(Value::as_str).ok_or("t.currency.toLowerCase is not a function")?;
    let mut out = Map::new();
    out.insert("currency".into(), json!(cur.to_lowercase()));
    out.insert("max_amount".into(), num(mx));
    if pe.is_some() {
        out.insert("expires_at".into(), num((js_to_number(pe) / 1000.0).floor()));
    }
    Ok(Value::Object(out))
}

fn iter_values(v: &Value) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        _ => Err("traits is not iterable".into()),
    }
}

/// Action-kit convention: a trait `mcc.c5734` says the verb may spend in MCC 5734. Traits only narrow.
pub fn categories_from_traits(traits: &Value) -> Result<Value, String> {
    let mut out = std::collections::BTreeSet::new();
    for t in iter_values(traits)? {
        if let Some(d) = t.as_str().and_then(|s| s.strip_prefix("mcc.c")) {
            if d.len() == 4 && d.bytes().all(|b| b.is_ascii_digit()) {
                out.insert(d.to_string());
            }
        }
    }
    Ok(Value::Array(out.into_iter().map(Value::String).collect()))
}

fn js_sorted(mut v: Vec<Value>) -> Vec<Value> {
    v.sort_by(|a, b| tostr(Some(a)).encode_utf16().cmp(tostr(Some(b)).encode_utf16()));
    v
}

/// The limits an instrument for this mandate may carry (amounts from [`shared_payment_token_limits`]; categories are the
/// mandate's allowlist narrowed by the action's mcc traits). `opts`: `actionTraits`, `allowAnyCategory`.
pub fn rail_limits(mandate: &Value, now: &Value, opts: Option<&Value>) -> Result<Value, String> {
    let empty = json!({});
    let o = Some(opts.unwrap_or(&empty));
    let spt = shared_payment_token_limits(mandate, now)?;
    let total = num(js_to_number(prop(prop(Some(mandate), "budget")?, "B")?).floor());
    let t = prop(Some(mandate), "terms")?;
    let from_mandate = spread(prop(t, "categories")?.unwrap_or(&Value::Null), "object")?;
    let traits = prop(o, "actionTraits")?;
    let from_traits: Vec<Value> = match categories_from_traits(&if nullish(traits) { json!([]) } else { traits.cloned().unwrap_or(Value::Null) })? {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    let cats = if !from_mandate.is_empty() && !from_traits.is_empty() {
        let c = js_sorted(from_mandate.into_iter().filter(|c| from_traits.contains(c)).collect());
        if c.is_empty() {
            return Err("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent".into());
        }
        c
    } else if !from_mandate.is_empty() {
        js_sorted(from_mandate)
    } else {
        js_sorted(from_traits)
    };
    if cats.is_empty() && !matches!(prop(o, "allowAnyCategory")?, Some(Value::Bool(true))) {
        return Err("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category".into());
    }
    let cur = prop(t, "currency")?.and_then(Value::as_str).ok_or("t.currency.toUpperCase is not a function")?;
    let mut out = Map::new();
    out.insert("currency".into(), json!(cur.to_uppercase()));
    out.insert("perAuthorizationMax".into(), spt["max_amount"].clone());
    out.insert("totalMax".into(), total);
    out.insert("categories".into(), Value::Array(cats));
    out.insert("merchants".into(), Value::Array(spread(prop(t, "merchants")?.unwrap_or(&Value::Null), "object")?));
    if let Some(e) = spt.get("expires_at") {
        out.insert("expiresAt".into(), num(js_to_number(Some(e)) * 1000.0));
    }
    Ok(Value::Object(out))
}

/// Compare what settled with what PCA approved: commit only on an exact fit; anything else says freeze the grant.
pub fn reconcile_settlement(approved: &Value, s: &Value) -> Result<Value, String> {
    let (a, s) = (Some(approved), Some(s));
    let mut reasons = Vec::new();
    if !seq(prop(s, "authorizationId")?, prop(a, "id")?) {
        reasons.push("authorization_id_mismatch");
    }
    if js_gt(prop(s, "amount")?, prop(a, "amount")?) {
        reasons.push("settled_more_than_approved");
    }
    let sc = prop(s, "currency")?.and_then(Value::as_str).ok_or("s.currency.toUpperCase is not a function")?;
    let ac = prop(a, "currency")?.and_then(Value::as_str).ok_or("approved.currency.toUpperCase is not a function")?;
    if sc.to_uppercase() != ac.to_uppercase() {
        reasons.push("currency_mismatch");
    }
    if !seq(prop(s, "merchantId")?, prop(a, "merchantId")?) {
        reasons.push("merchant_mismatch");
    }
    if js_gt(prop(s, "captures")?, Some(&json!(1))) {
        reasons.push("second_capture");
    }
    Ok(if reasons.is_empty() { json!({"ok": true}) } else { json!({"ok": false, "reasons": reasons, "action": "freeze_grant"}) })
}

// ---- Stripe Issuing adapter -----------------------------------------------------------------------------------------------

/// The form parameters for `POST /v1/issuing/cards` (virtual, active) that carry the rail limits. Fails when an MCC has no Stripe
/// category name. `metadata` is the optional `{k: v}` object.
pub fn stripe_card_params(limits: &Value, category_names: &Value, cardholder: &Value, metadata: Option<&Value>) -> Result<Value, String> {
    let l = Some(limits);
    let cur = prop(l, "currency")?.and_then(Value::as_str).ok_or("limits.currency.toLowerCase is not a function")?;
    let mut p = Map::new();
    p.insert("cardholder".into(), cardholder.clone());
    p.insert("type".into(), json!("virtual"));
    p.insert("status".into(), json!("active"));
    p.insert("currency".into(), json!(cur.to_lowercase()));
    p.insert("spending_controls[spending_limits][0][amount]".into(), json!(tostr(prop(l, "perAuthorizationMax")?)));
    p.insert("spending_controls[spending_limits][0][interval]".into(), json!("per_authorization"));
    p.insert("spending_controls[spending_limits][1][amount]".into(), json!(tostr(prop(l, "totalMax")?)));
    p.insert("spending_controls[spending_limits][1][interval]".into(), json!("all_time"));
    let cats = prop(l, "categories")?;
    let Some(Value::Array(cats)) = cats else { return Err("limits.categories.forEach is not a function".into()) };
    for (i, mcc) in cats.iter().enumerate() {
        let name = prop(Some(category_names), &js_str(mcc))?.ok_or_else(|| format!("stripeCardParams: no Stripe category name for MCC {}", js_str(mcc)))?;
        p.insert(format!("spending_controls[allowed_categories][{i}]"), name.clone());
    }
    if let Some(Value::Object(md)) = metadata {
        for (k, v) in md {
            p.insert(format!("metadata[{k}]"), v.clone());
        }
    }
    Ok(Value::Object(p))
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_stripe(secret: &str, t: &str, raw_body: &str) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC takes a key of any length");
    m.update(format!("{t}.{raw_body}").as_bytes());
    m
}

/// `t=<t>,v1=<hex>` over `<t>.<rawBody>` with the endpoint secret.
pub fn sign_stripe_payload(raw_body: &str, secret: &str, t_sec: f64) -> String {
    let t = js_number_string(t_sec);
    let tag = hmac_stripe(secret, &t, raw_body).finalize().into_bytes();
    format!("t={t},v1={}", tag.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Verify a `Stripe-Signature` header over the RAW body. Total: false on anything malformed, stale or mismatched.
pub fn verify_stripe_signature(raw_body: &str, header: Option<&str>, secret: Option<&str>, now_sec: f64, tolerance_sec: f64) -> bool {
    let (Some(header), Some(secret)) = (header, secret) else { return false };
    if secret.is_empty() || !(tolerance_sec.is_finite() && tolerance_sec > 0.0) {
        return false;
    }
    let (mut t, mut v1): (Option<&str>, Vec<&str>) = (None, Vec::new());
    for part in header.split(',') {
        let Some(i) = part.find('=') else { continue };
        let (k, v) = (part[..i].trim_matches(crate::action_schema::is_js_ws), part[i + 1..].trim_matches(crate::action_schema::is_js_ws));
        if k == "t" {
            t = Some(v);
        } else if k == "v1" {
            v1.push(v);
        }
    }
    let Some(t) = t else { return false };
    if t.is_empty() || t.len() > 12 || !t.bytes().all(|b| b.is_ascii_digit()) || v1.is_empty() {
        return false;
    }
    let tv: f64 = t.parse().unwrap_or(f64::NAN);
    if !((now_sec - tv).abs() <= tolerance_sec) {
        return false;
    }
    let mac = hmac_stripe(secret, t, raw_body);
    v1.iter().any(|sig| {
        sig.len() == 64
            && sig.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (0..32)
                .map(|i| u8::from_str_radix(&sig[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .is_ok_and(|bytes| mac.clone().verify_slice(&bytes).is_ok())
    })
}

fn obj(v: V) -> Option<&Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// Normalise an `issuing_authorization.request` event; `None` when it is not a well-formed request with a pending amount.
pub fn stripe_authorization_from_event(event: &Value) -> Option<Value> {
    let e = obj(Some(event))?;
    if e.get("type").and_then(Value::as_str) != Some("issuing_authorization.request") {
        return None;
    }
    let a = obj(obj(e.get("data")).and_then(|d| d.get("object")))?;
    let pending = obj(a.get("pending_request"))?;
    let card = obj(a.get("card"));
    let merchant = obj(a.get("merchant_data"));
    let (id, card_id) = (a.get("id").and_then(Value::as_str)?, card.and_then(|c| c.get("id")).and_then(Value::as_str)?);
    let amount = pending.get("amount").filter(|v| v.is_number())?;
    let currency = pending.get("currency").and_then(Value::as_str)?;
    let mut out = Map::new();
    out.insert("id".into(), json!(id));
    out.insert("instrumentId".into(), json!(card_id));
    out.insert("amount".into(), amount.clone());
    out.insert("currency".into(), json!(currency));
    if let Some(n) = merchant.and_then(|m| m.get("network_id")).and_then(Value::as_str).filter(|s| !s.is_empty()) {
        out.insert("merchantId".into(), json!(n));
    }
    if let Some(c) = merchant.and_then(|m| m.get("category_code")).and_then(Value::as_str) {
        out.insert("mcc".into(), json!(c));
    }
    Some(Value::Object(out))
}

fn reply(status: u16, body: &Value, version: &str) -> Value {
    json!({"status": status, "headers": {"Stripe-Version": version, "Content-Type": "application/json"}, "body": js_stringify(body)})
}

/// The HTTP handler body for the `issuing_authorization.request` endpoint. A bad signature is 400 (nothing is decided); a request
/// event gets 200 `{approved}` from the PCA decision; any other event type gets 200 `{}`. `amount` is never sent. `authorize` is the
/// verdict function (`{approved, reasons}`). REQUIRED OPERATOR SETTING: set the Issuing authorization timeout response to DECLINE
/// and turn Autopilot off.
pub fn stripe_issuing_webhook(
    raw_body: &str,
    signature: Option<&str>,
    secret: Option<&str>,
    now_sec: f64,
    tolerance_sec: Option<f64>,
    stripe_version: Option<&str>,
    authorize: &dyn Fn(&Value) -> Value,
) -> Value {
    let version = stripe_version.unwrap_or(STRIPE_API_VERSION);
    if !verify_stripe_signature(raw_body, signature, secret, now_sec, tolerance_sec.unwrap_or(STRIPE_WEBHOOK_TOLERANCE_SEC)) {
        return reply(400, &json!({"error": "bad_signature"}), version);
    }
    // a duplicate member is refused (the last would win under JSON.parse); numbers stay as written
    let Ok(event) = crate::ap2::parse_no_duplicates(raw_body) else { return reply(400, &json!({"error": "bad_json"}), version) };
    if obj(Some(&event)).and_then(|e| e.get("type")).and_then(Value::as_str) != Some("issuing_authorization.request") {
        return reply(200, &json!({}), version);
    }
    let Some(auth) = stripe_authorization_from_event(&event) else { return reply(200, &json!({"approved": false}), version) };
    let v = authorize(&auth);
    reply(200, &json!({"approved": v.get("approved") == Some(&Value::Bool(true))}), version)
}

/// Normalise an `issuing_transaction.created` capture into a settlement (a capture's amount is negative in Stripe's ledger).
pub fn stripe_settlement_from_transaction(txn: &Value) -> Option<Value> {
    let t = obj(Some(txn))?;
    let m = obj(t.get("merchant_data"));
    if t.get("type").and_then(Value::as_str) != Some("capture") {
        return None;
    }
    let auth = t.get("authorization").and_then(Value::as_str)?;
    let amount = t.get("amount").and_then(Value::as_f64).filter(|_| t["amount"].is_number())?;
    let currency = t.get("currency").and_then(Value::as_str)?;
    let mut out = Map::new();
    out.insert("authorizationId".into(), json!(auth));
    out.insert("amount".into(), num(-amount));
    out.insert("currency".into(), json!(currency));
    if let Some(n) = m.and_then(|m| m.get("network_id")).and_then(Value::as_str) {
        out.insert("merchantId".into(), json!(n));
    }
    out.insert("captures".into(), json!(1));
    Some(Value::Object(out))
}

// ---- agent network tokens -------------------------------------------------------------------------------------------------

fn luhn(d: &str) -> bool {
    let (mut total, mut dbl) = (0u32, false);
    for c in d.bytes().rev() {
        let mut n = u32::from(c - b'0');
        if dbl {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        total += n;
        dbl = !dbl;
    }
    total % 10 == 0
}

/// True when a maximal digit run (whitespace and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only.
pub fn looks_like_pan(s: &str) -> bool {
    let stripped: String = s.chars().filter(|c| !crate::action_schema::is_js_ws(*c) && *c != '-').collect();
    stripped.split(|c: char| !c.is_ascii_digit()).any(|r| (13..=19).contains(&r.len()) && luhn(r))
}

/// Why a token reference is refused (`token_ref_malformed`, `token_ref_looks_like_pan`), or `None`.
pub fn token_ref_error(r: &Value) -> Option<&'static str> {
    let ok = r.as_str().is_some_and(|s| (8..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')));
    if !ok {
        return Some("token_ref_malformed");
    }
    if r.as_str().is_some_and(looks_like_pan) {
        return Some("token_ref_looks_like_pan");
    }
    None
}

fn body_of(b: &Value) -> Result<Value, String> {
    let m = Some(b);
    let mut body = Map::new();
    body.insert("kind".into(), json!(NETWORK_TOKEN_BINDING_KIND));
    body.insert("v".into(), json!(1));
    for k in ["provider", "token_ref", "grant_digest", "issuer_nonce", "holder"] {
        body.insert(k.into(), prop(m, k)?.cloned().ok_or("canonicalize: unsupported type undefined")?);
    }
    Ok(Value::Object(body))
}

/// The exact bytes the holder signs: UTF-8 of the canonical-JSON digest of the binding body.
pub fn binding_message(b: &Value) -> Result<Vec<u8>, String> {
    Ok(hash_strict(Some(&body_of(b)?))?.into_bytes())
}

/// Tie a grant holder to an OPAQUE network-token reference (never a PAN). `opts`: `provider`, `tokenRef`, `grant`, `issuerNonce`.
/// `holder_seed` is the 32-byte Ed25519 seed (the reference's `holderSecret`); `holder_public` its public key bytes.
pub fn bind_network_token(opts: &Value, holder_seed: &[u8], holder_public: &[u8]) -> Result<Value, String> {
    let o = Some(opts);
    if let Some(e) = token_ref_error(prop(o, "tokenRef")?.unwrap_or(&Value::Null)) {
        return Err(format!("bindNetworkToken: {e}"));
    }
    let nonce = prop(o, "issuerNonce")?;
    if length(nonce)?.is_some_and(|n| js_to_number(Some(&n)) < 16.0) {
        return Err("bindNetworkToken: issuer nonce must be at least 16 chars".into());
    }
    let mut core = Map::new();
    if let Some(p) = prop(o, "provider")? {
        core.insert("provider".into(), p.clone());
    }
    core.insert("token_ref".into(), prop(o, "tokenRef")?.cloned().unwrap_or(Value::Null));
    core.insert("grant_digest".into(), json!(hash_strict(prop(o, "grant")?)?));
    core.insert("issuer_nonce".into(), nonce.cloned().unwrap_or(Value::Null));
    core.insert("holder".into(), json!(b64u(holder_public)));
    let proof = keypair(holder_seed)?.sign(&binding_message(&Value::Object(core.clone()))?);
    let mut out = Map::new();
    out.insert("kind".into(), json!(NETWORK_TOKEN_BINDING_KIND));
    out.extend(core);
    out.insert("binding_proof".into(), json!(b64u(&proof)));
    Ok(Value::Object(out))
}

fn verify_binding(b: &Value, expect: &Value) -> Result<Option<&'static str>, String> {
    let (x, e) = (Some(b), Some(expect));
    if !matches!(b, Value::Object(_) | Value::Array(_)) || prop(x, "kind")?.and_then(Value::as_str) != Some(NETWORK_TOKEN_BINDING_KIND) {
        return Ok(Some("binding_malformed"));
    }
    if let Some(err) = token_ref_error(prop(x, "token_ref")?.unwrap_or(&Value::Null)) {
        return Ok(Some(err));
    }
    let (prov, exp_prov) = (prop(x, "provider")?, prop(e, "provider")?);
    if prov.and_then(Value::as_str).map_or(true, str::is_empty) || (exp_prov.is_some() && !seq(prov, exp_prov)) {
        return Ok(Some("provider_mismatch"));
    }
    if !seq(prop(x, "grant_digest")?, Some(&json!(hash_strict(prop(e, "grant")?)?))) {
        return Ok(Some("grant_digest_mismatch"));
    }
    if !seq(prop(x, "holder")?, prop(e, "holder")?) {
        return Ok(Some("holder_mismatch"));
    }
    if !seq(prop(x, "issuer_nonce")?, prop(e, "issuerNonce")?) {
        return Ok(Some("issuer_nonce_mismatch"));
    }
    let key = |k: &str| -> Result<Option<Vec<u8>>, String> { Ok(prop(x, k)?.and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, None))) };
    let (pk, sg) = (key("holder")?, key("binding_proof")?);
    let (Some(pk), Some(sg)) = (pk, sg) else { return Ok(Some("binding_malformed")) };
    Ok(if ed25519_verify(&pk, &binding_message(b)?, &sg) { None } else { Some("binding_proof_invalid") })
}

/// Total. `None` = valid, else the refusal reason. `expect`: `grant` (the one the caller verified), `holder` (b64u), `issuerNonce`,
/// optional `provider`.
pub fn verify_network_token_binding(b: &Value, expect: &Value) -> Option<&'static str> {
    verify_binding(b, expect).unwrap_or(Some("binding_malformed"))
}

/// The network-side controls: always an upper-bounded copy of the rail limits.
pub fn controls_from_limits(limits: &Value, grant: &Value) -> Result<Value, String> {
    let l = Some(limits);
    let mut c = Map::new();
    for k in ["currency", "perAuthorizationMax", "totalMax"] {
        if let Some(v) = prop(l, k)? {
            c.insert(k.into(), v.clone());
        }
    }
    c.insert("categories".into(), Value::Array(spread(prop(l, "categories")?.unwrap_or(&Value::Null), "object")?));
    c.insert("merchants".into(), Value::Array(spread(prop(l, "merchants")?.unwrap_or(&Value::Null), "object")?));
    if let Some(e) = prop(l, "expiresAt")? {
        c.insert("expiresAt".into(), e.clone());
    }
    c.insert("metadata".into(), json!({"grant_digest": hash_strict(Some(grant))?}));
    Ok(Value::Object(c))
}

/// The metadata echoed on the network settlement.
pub fn settlement_metadata(b: &Value, pcactn_digest: &Value) -> Result<Value, String> {
    let mut m = Map::new();
    if let Some(g) = prop(Some(b), "grant_digest")? {
        m.insert("pca_grant".into(), g.clone());
    }
    m.insert("pca_pcactn".into(), pcactn_digest.clone());
    if let Some(r) = prop(Some(b), "token_ref")? {
        m.insert("pca_token_ref".into(), r.clone());
    }
    Ok(Value::Object(m))
}

/// A network settlement record joins the ledger entry only if all three echoed values match exactly.
pub fn reconcile_network_settlement(expected: &Value, record: &Value) -> Result<Value, String> {
    let md = optprop(Some(record), "metadata")?;
    let empty = json!({});
    let m = if nullish(md) { Some(&empty) } else { md };
    let ex = Some(expected);
    let mut reasons = Vec::new();
    let ped = prop(m, "pca_pcactn")?;
    let missing = match ped {
        Some(Value::String(s)) if !s.is_empty() => length_is_zero(prop(ex, "pcactnDigest")?)?,
        _ => true,
    };
    if missing {
        reasons.push("pcactn_digest_missing");
    }
    if !seq(prop(m, "pca_grant")?, prop(ex, "grantDigest")?) {
        reasons.push("grant_digest_mismatch");
    }
    if !seq(ped, prop(ex, "pcactnDigest")?) {
        reasons.push("pcactn_digest_mismatch");
    }
    if !seq(prop(m, "pca_token_ref")?, prop(ex, "tokenRef")?) {
        reasons.push("token_ref_mismatch");
    }
    Ok(if reasons.is_empty() { json!({"ok": true}) } else { json!({"ok": false, "reasons": reasons}) })
}

/// Build the PCActn for the charge and return the metadata for the network request, derived from THAT PCActn's digest: there is
/// no way to carry a digest that is not of a PCActn this call built.
pub fn charge_with_network_token(binding: &Value, mandate: &Value, charge: &Value, opts: &Value, signer_seed: &[u8]) -> Result<Value, String> {
    if token_ref_error(prop(Some(binding), "token_ref")?.unwrap_or(&Value::Null)).is_some() {
        return Err("chargeWithNetworkToken: bad binding".into());
    }
    if !seq(prop(Some(binding), "grant_digest")?, Some(&json!(hash_strict(prop(Some(mandate), "grant")?)?))) {
        return Err("chargeWithNetworkToken: binding is for another grant".into());
    }
    let built = charge_to_pcactn(mandate, charge, opts, signer_seed)?;
    let digest = hash_strict(Some(&built["pcactn"]))?;
    Ok(json!({"pcactn": built["pcactn"], "node": built["node"], "metadata": settlement_metadata(binding, &json!(digest))?, "pcactnDigest": digest}))
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::*;

    const SECRET: &str = "whsec_test";

    fn send(raw: &str) -> Value {
        let sig = sign_stripe_payload(raw, SECRET, 1000.0);
        stripe_issuing_webhook(raw, Some(&sig), Some(SECRET), 1000.0, None, None, &|_| json!({"approved": true}))
    }

    #[test]
    fn a_duplicate_member_in_the_webhook_body_is_bad_json_and_other_number_spellings_are_accepted() {
        let dup = send(r#"{"type":"x","type":"issuing_authorization.request"}"#);
        assert_eq!(dup["status"], json!(400));
        assert!(dup["body"].as_str().unwrap().contains("bad_json"));
        assert_eq!(send(r#"{"type":"other","amount":8.0,"n":1e3}"#)["status"], json!(200));
    }
}
