//! The wallet side of the PCA Intent Layer v2: the principal-signed answer (wire), friction tiers scaled by harm, cell coordinates over
//! the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue model. A port
//! of the reference (@atlasauth/pca-wallet), part 1: the trusted question card, clarification planning, population priors and the
//! question channel build on this API (they live in other modules). Risk-priced escalation is [`crate::wallet_pricing`]; the outcome
//! space ([`crate::wallet_omega`]) carries the cell and harm helpers and the fdlibm doubles.
//!
//! Values are plain JSON (`&serde_json::Value`, the reference's camelCase member names); a reference refusal (a thrown Error) is an
//! `Err(String)` with the reference message, a refusal that is a verdict is a `Value`. Floats follow the reference operation by operation.
//!
//! API a second module can call: constants ([`INTENT_ANSWER_SIG_DOMAIN`], [`CARD_DOMAIN`], [`MAX_CANDIDATES`], [`POPULATION_VOTE_DOMAIN`],
//! [`BETA_MAX`], [`reason_labels`], [`default_fatigue`], [`empty_noise`]); friction ([`friction_for`], [`friction_rank`], [`tier_rank`],
//! [`max_friction`], [`satisfies_tier`], [`is_friction_tier`], [`worst_provenance`]); the action ([`pca_action_digest`],
//! [`action_values_of`]); the signed answer ([`answer_shape_error`], [`sign_intent_answer`], [`verify_intent_answer`], [`answer_ref`],
//! [`typed_digest`], [`device_challenge`]); cells ([`resolve_coords`], [`BoxResult`], [`coords_of_box`], [`coords_of_cell`], [`cell_in_box`],
//! [`box_cells`], [`box_size`], [`cell_of_action`], [`flat_index`], [`coord_key_of`], [`cat_label`], [`cell_key`]); statistics
//! ([`ln_gamma`], [`beta_inc`], [`beta_quantile`], [`bin_ent`], [`crate::wallet_omega::clopper_pearson_upper`]); noise ([`record_canary`],
//! [`estimate_noise`], [`NoiseEstimate`], [`noise_state`], [`admission_policy`], [`eta_under_load`]); canaries ([`pick_canary`],
//! [`PickCtx`], [`CellAt`], [`CanaryChoice`], [`boundary_neighbours`]); [`SlidingWindowCounter`]; [`double_confirmed`].
//!
//! shortcut: `y` of [`device_challenge`] is an integer (the reference types it 0 | 1).
use crate::wallet_omega::{cell_count, cell_of, fdlibm, is_int, js_entries, num, num_cells, truthy, u16len};
use ed25519_dalek::Signer;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::f64::consts::PI;
use std::sync::OnceLock;

pub const INTENT_ANSWER_SIG_DOMAIN: &str = "atlas-pca/intent-obs/v2\0";
pub const INTENT_ANSWER_REF_DOMAIN: &str = "atlas-pca/intent-answer-ref/v1";
pub const INTENT_TYPED_DOMAIN: &str = "atlas-pca/intent-typed/v1";
pub const INTENT_DEVICE_CHALLENGE_DOMAIN: &str = "atlas-pca/intent-device/v1";
pub const INTENT_ACTION_DOMAIN: &str = "atlas-pca/intent-action/v1";
pub const CARD_DOMAIN: &str = "atlas-pca/intent-card/v2";
pub const POPULATION_VOTE_DOMAIN: &str = "atlas-pca/intent-population-cell/v1";
pub const MIN_HOLD_MS: i64 = 2000;
pub const MAX_CANDIDATES: i64 = 8;
pub const BETA_MAX: f64 = 0.9;
pub const FRICTION_ORDER: [&str; 4] = ["tap", "hold", "typed", "device"];
pub const PROVENANCE_ORDER: [&str; 5] = ["trusted", "first_party", "tool", "web", "agent"];
pub const CLARIFY_REASONS: [&str; 6] = ["ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other"];
pub const H_TAP: f64 = 5.0;
pub const H_DEVICE: f64 = 100_000.0;
pub const PPM: i64 = 1_000_000;
pub const MAX_MULTIPLIER_PPM: i64 = 100_000_000;
const NOISE_PRIOR_A: f64 = 1.0;
const NOISE_PRIOR_B: f64 = 9.0;
const BELOW_HALF: f64 = 0.5 - 1e-9;

/// The card's one-line reason for each clarification reason.
pub fn reason_labels() -> Value {
    json!({
        "ambiguous_parameter": "Your agent found a detail your request did not settle.",
        "multiple_options": "Your agent found several options that match.",
        "price_changed": "Your agent found that a price changed.",
        "constraint_conflict": "Your agent found that two parts of your request conflict.",
        "missing_value": "Your agent needs a value your request did not give.",
        "other": "Your agent needs a decision before it continues."
    })
}

pub fn empty_noise() -> Value {
    json!({ "falseYes": 0, "correctNo": 0, "falseNo": 0, "correctYes": 0 })
}

pub fn default_fatigue() -> Value {
    json!({ "betaF": 0.005, "etaStop": 0.15, "deltaC": 0.05, "freezeOn": "mean", "assumeNoiseFree": false, "delta": 0.05 })
}

/// The exported constants of the reference as one object.
pub fn constants() -> Value {
    json!({
        "FRICTION_ORDER": FRICTION_ORDER, "INTENT_ANSWER_SIG_DOMAIN": INTENT_ANSWER_SIG_DOMAIN, "INTENT_ANSWER_REF_DOMAIN": INTENT_ANSWER_REF_DOMAIN,
        "INTENT_TYPED_DOMAIN": INTENT_TYPED_DOMAIN, "INTENT_DEVICE_CHALLENGE_DOMAIN": INTENT_DEVICE_CHALLENGE_DOMAIN, "MIN_HOLD_MS": MIN_HOLD_MS,
        "PROVENANCE_ORDER": PROVENANCE_ORDER, "DEFAULT_FRICTION_THRESHOLDS": { "hTap": 5, "hDevice": 100000 }, "CARD_DOMAIN": CARD_DOMAIN,
        "CLARIFY_REASONS": CLARIFY_REASONS, "REASON_LABELS": reason_labels(), "MAX_CANDIDATES": MAX_CANDIDATES, "EMPTY_NOISE": empty_noise(),
        "NOISE_PRIOR": { "a": 1, "b": 9 }, "DEFAULT_FATIGUE": default_fatigue(), "PPM": PPM, "MAX_MULTIPLIER_PPM": MAX_MULTIPLIER_PPM,
        "POPULATION_VOTE_DOMAIN": POPULATION_VOTE_DOMAIN, "BETA_MAX": BETA_MAX
    })
}

fn nan_of(v: Option<&Value>) -> f64 {
    v.and_then(num).unwrap_or(f64::NAN)
}

/// `Math.min` (NaN poisons).
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

fn str_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn is_num_eq(v: Option<&Value>, n: f64) -> bool {
    v.and_then(num) == Some(n)
}

// ---- friction (wire.ts, friction.ts) ---------------------------------------------------------------------------------------------------

pub fn is_friction_tier(x: &Value) -> bool {
    x.as_str().is_some_and(|s| FRICTION_ORDER.contains(&s))
}

/// Index in the tier order, -1 when `t` is no tier.
pub fn tier_rank(t: &str) -> i64 {
    FRICTION_ORDER.iter().position(|x| *x == t).map_or(-1, |i| i as i64)
}

pub fn friction_rank(t: &Value) -> i64 {
    t.as_str().map_or(-1, tier_rank)
}

/// The highest tier of the arguments ("tap" for none; an unknown tier never wins).
pub fn max_friction(ts: &[Value]) -> Value {
    let mut best = Value::String("tap".into());
    for t in ts {
        if friction_rank(t) > friction_rank(&best) {
            best = t.clone();
        }
    }
    best
}

pub fn satisfies_tier(given: &Value, required: &Value) -> bool {
    friction_rank(given) >= friction_rank(required)
}

pub fn is_provenance_level(x: &Value) -> bool {
    x.as_str().is_some_and(|s| PROVENANCE_ORDER.contains(&s))
}

/// The least trusted level of a set; "agent" for an empty or unknown set (fail closed). A value `for...of` cannot iterate is a refusal.
pub fn worst_provenance(levels: &Value) -> Result<&'static str, String> {
    match levels {
        Value::String(_) => Ok("agent"), // every character of a string is no level
        Value::Array(a) => {
            let mut best: i64 = -1;
            for l in a {
                let Some(i) = l.as_str().and_then(|s| PROVENANCE_ORDER.iter().position(|x| *x == s)) else { return Ok("agent") };
                best = best.max(i as i64);
            }
            Ok(if best < 0 { "agent" } else { PROVENANCE_ORDER[best as usize] })
        }
        _ => Err("levels is not iterable".into()),
    }
}

/// `{tier, rules}` of the friction a question needs. `th` is `{hTap, hDevice}` (default 5 and 100000).
pub fn friction_for(inp: &Value, th: Option<&Value>) -> Result<Value, String> {
    let (h_tap, h_dev) = match th {
        None => (H_TAP, H_DEVICE),
        Some(t) => (nan_of(get(t, "hTap")), nan_of(get(t, "hDevice"))),
    };
    if inp.is_null() {
        return Err("Cannot read properties of null".into());
    }
    let harm = match get(inp, "expectedHarm").and_then(num).filter(|h| h.is_finite() && *h >= 0.0) {
        Some(h) => h,
        None => return Ok(json!({ "tier": "device", "rules": ["harm-unknown"] })),
    };
    let mut rules: Vec<String> = vec![];
    let mut tier = "tap".to_string();
    fn raise(tier: &mut String, rules: &mut Vec<String>, t: &Value, why: &str) {
        if friction_rank(t) >= tier_rank(tier) {
            rules.push(why.to_string());
        }
        if friction_rank(t) > tier_rank(tier) {
            *tier = t.as_str().unwrap_or("tap").to_string();
        }
    }
    let rev = str_of(get(inp, "reversibility"));
    if rev == Some("rate_limited") {
        raise(&mut tier, &mut rules, &json!("hold"), "rate-limited");
    }
    if harm >= h_tap {
        raise(&mut tier, &mut rules, &json!("hold"), "harm>=h_tap");
    }
    if rev == Some("irreversible") {
        raise(&mut tier, &mut rules, &json!("typed"), "irreversible");
    }
    let mut tainted_critical = false;
    match get(inp, "provenance") {
        None | Some(Value::Null) => {}
        Some(Value::Array(ps)) => {
            for p in ps {
                if p.is_null() {
                    return Err("Cannot read properties of null (reading 'sensitivity')".into());
                }
                if str_of(get(p, "sensitivity")) == Some("critical") {
                    let w = worst_provenance(get(p, "levels").ok_or("levels is not iterable")?)?;
                    if w == "web" || w == "agent" {
                        tainted_critical = true;
                        break;
                    }
                }
            }
        }
        Some(_) => return Err("(inp.provenance ?? []).some is not a function".into()),
    }
    if tainted_critical {
        raise(&mut tier, &mut rules, &json!("typed"), "tainted-critical");
    }
    if get(inp, "widensCriticalIdentity").is_some_and(truthy) && rev == Some("irreversible") {
        raise(&mut tier, &mut rules, &json!("device"), "critical-irreversible");
    }
    if harm >= h_dev {
        raise(&mut tier, &mut rules, &json!("device"), "harm>=h_device");
    }
    if get(inp, "singleSource").is_some_and(truthy) {
        let up = FRICTION_ORDER[((FRICTION_ORDER.len() - 1) as i64).min(tier_rank(&tier) + 1) as usize];
        raise(&mut tier, &mut rules, &json!(up), "single-source");
    }
    if let Some(site_min) = get(inp, "siteMin") {
        raise(&mut tier, &mut rules, site_min, "site-minimum");
    }
    Ok(json!({ "tier": tier, "rules": rules }))
}

// ---- helpers (wire.ts) ------------------------------------------------------------------------------------------------------------------

pub fn is_obj(v: &Value) -> bool {
    v.is_object()
}

pub fn is_b64u32(v: &Value) -> bool {
    v.as_str().is_some_and(|s| crate::decode_b64u_strict(s, Some(32)).is_some())
}

fn is_b64u32_opt(v: Option<&Value>) -> bool {
    v.is_some_and(is_b64u32)
}

/// Cell coordinates as the core validates them: dimension path -> `[lo, hi]` index range or a distinct value set.
pub fn coords_error(c: &Value) -> Option<String> {
    let Some(m) = c.as_object().filter(|m| !m.is_empty() && m.len() <= 64) else { return Some("coords must be an object of 1..64 dimensions".into()) };
    for k in crate::missing_context::js_keys(m) {
        let v = &m[k.as_str()];
        if !(1..=256).contains(&u16len(&k)) {
            return Some("a coordinate path must be 1..256 characters".into());
        }
        let a = v.as_array();
        if let Some([lo, hi]) = a.filter(|r| r.iter().all(is_int)).map(Vec::as_slice) {
            let (lo, hi) = (num(lo), num(hi));
            if !(lo >= Some(0.0) && lo <= hi) {
                return Some(format!("coords '{k}': need 0 <= lo <= hi"));
            }
        } else if let Some(set) = a.filter(|s| (1..=256).contains(&s.len()) && s.iter().all(Value::is_string)) {
            let distinct: HashSet<&str> = set.iter().filter_map(Value::as_str).collect();
            if distinct.len() != set.len() {
                return Some(format!("coords '{k}': values must be distinct"));
            }
        } else {
            return Some(format!("coords '{k}': an index range [lo, hi] or a value set"));
        }
    }
    None
}

fn strict_hash(v: &Value) -> Result<String, String> {
    crate::hash_canonical_strict(v).ok_or_else(|| "canonicalize: value outside the strict profile".to_string())
}

/// The action digest of an attempted action (what `intent_required.action_digest` and a JIT consent bind to).
pub fn pca_action_digest(a: &Value) -> Result<String, String> {
    let o = a.as_object().ok_or("canonicalize: undefined")?;
    let field = |k: &str| o.get(k).cloned().ok_or_else(|| "canonicalize: undefined".to_string());
    let (verb, resource) = (field("verb")?, field("resource")?);
    let params = o.get("params").filter(|p| !p.is_null()).cloned().unwrap_or_else(|| json!({}));
    let params_digest = strict_hash(&params)?;
    let rev = field("reversibility_class")?;
    strict_hash(
        &json!({ "d": INTENT_ACTION_DOMAIN, "action": { "verb": verb, "resource": resource, "params_digest": params_digest, "reversibility_class": rev } }),
    )
}

/// The default projection of an attempted action onto Omega paths: the resource and every scalar param.
pub fn action_values_of(a: &Value) -> Result<Value, String> {
    let o = a.as_object().ok_or("Cannot convert undefined or null to object")?;
    let mut values = Map::new();
    if let Some(r) = o.get("resource") {
        values.insert("action.resource".into(), r.clone());
    }
    for (k, v) in js_entries(o.get("params").ok_or("Cannot convert undefined or null to object")?)? {
        if v.is_string() || v.is_number() {
            values.insert(format!("action.params.{k}"), v);
        }
    }
    let mut out = Map::new();
    out.insert("values".into(), Value::Object(values));
    if let Some(v) = o.get("verb") {
        out.insert("verb".into(), v.clone());
    }
    Ok(Value::Object(out))
}

// ---- M6: the signed answer ----------------------------------------------------------------------------------------------------------------

const ANS_KEYS: [&str; 15] =
    ["v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig"];
const UX_KEYS: [&str; 8] = ["tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action"];
const WA_KEYS: [&str; 4] = ["credential_id", "authenticator_data", "client_data_json", "signature"];

fn only_keys(o: &Map<String, Value>, allowed: &[&str]) -> Option<String> {
    crate::missing_context::js_keys(o).into_iter().find(|k| !allowed.contains(&k.as_str())).map(|k| format!("unknown member \"{k}\""))
}

fn partial_error(p: &Value) -> Option<String> {
    let Some(o) = p.as_object().filter(|o| o.get("path").and_then(Value::as_str).is_some_and(|s| !s.is_empty())) else {
        return Some("partial.path must be a non-empty string".into());
    };
    let keys: Vec<String> = crate::missing_context::js_keys(o).into_iter().filter(|k| k != "path").collect();
    if keys.len() != 1 {
        return Some("partial must carry exactly one of upTo / from / except / notFor".into());
    }
    let k = keys[0].as_str();
    let v = &o[k];
    if (k == "upTo" || k == "from") && !is_int(v) {
        return Some(format!("partial.{k} must be an integer"));
    }
    if k == "except" && !v.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(is_int)) {
        return Some("partial.except must be a non-empty integer array".into());
    }
    if k == "notFor" && !v.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty()))) {
        return Some("partial.notFor must be a non-empty string array".into());
    }
    if !["upTo", "from", "except", "notFor"].contains(&k) {
        return Some(format!("unknown partial member \"{k}\""));
    }
    None
}

fn qid_ok(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Why a (signed or unsigned) answer is malformed, or `None`.
pub fn answer_shape_error(a: &Value) -> Option<String> {
    let Some(o) = a.as_object() else { return Some("not an object".into()) };
    if let Some(e) = only_keys(o, &ANS_KEYS) {
        return Some(e);
    }
    if !is_num_eq(o.get("v"), 2.0) || str_of(o.get("kind")) != Some("pca-intent-observation") {
        return Some("not a pca-intent-observation v2".into());
    }
    for k in ["map_digest", "session", "signer"] {
        if !is_b64u32_opt(o.get(k)) {
            return Some(format!("{k} is not canonical base64url (32 bytes)"));
        }
    }
    if !str_of(o.get("question_id")).is_some_and(qid_ok) {
        return Some("question_id must match [A-Za-z0-9_-]{1,64}".into());
    }
    if !str_of(o.get("verb")).is_some_and(|s| !s.is_empty()) {
        return Some("verb must be a non-empty string".into());
    }
    if let Some(ce) = coords_error(o.get("cell").unwrap_or(&crate::wallet_omega::NULL)) {
        // an absent cell is `undefined` in the reference: also "not an object"
        return Some(format!("cell: {ce}"));
    }
    if !(is_num_eq(o.get("y"), 0.0) || is_num_eq(o.get("y"), 1.0)) {
        return Some("y must be 0 or 1".into());
    }
    let y1 = is_num_eq(o.get("y"), 1.0);
    if let Some(p) = o.get("partial") {
        if let Some(pe) = partial_error(p) {
            return Some(pe);
        }
        if !y1 {
            return Some("a partial answer carries y = 1 (yes for the part)".into());
        }
    }
    if !matches!(str_of(o.get("source")), Some("elicitation") | Some("clarification")) {
        return Some("source must be elicitation or clarification".into());
    }
    if !o.get("observed_at").is_some_and(|v| is_int(v) && num(v).is_some_and(|f| f >= 0.0)) {
        return Some("observed_at must be a non-negative safe integer".into());
    }
    if str_of(o.get("alg")) != Some("ed25519") {
        return Some("alg must be ed25519".into());
    }
    let Some(ux) = o.get("ux").and_then(Value::as_object) else { return Some("ux must be an object".into()) };
    if let Some(ue) = only_keys(ux, &UX_KEYS) {
        return Some(format!("ux: {ue}"));
    }
    if !ux.get("tier").is_some_and(is_friction_tier) {
        return Some("ux.tier is not a friction tier".into());
    }
    if !is_b64u32_opt(ux.get("rendered_digest")) {
        return Some("ux.rendered_digest is not canonical base64url (32 bytes)".into());
    }
    let Some(canary) = ux.get("canary").and_then(Value::as_bool) else { return Some("ux.canary must be a boolean".into()) };
    if ux.contains_key("typed_digest") && !is_b64u32_opt(ux.get("typed_digest")) {
        return Some("ux.typed_digest is not canonical base64url (32 bytes)".into());
    }
    if let Some(h) = ux.get("hold_ms") {
        if !(is_int(h) && num(h).is_some_and(|f| f >= 0.0)) {
            return Some("ux.hold_ms must be a non-negative integer".into());
        }
    }
    if ux.contains_key("action_digest") && !is_b64u32_opt(ux.get("action_digest")) {
        return Some("ux.action_digest is not canonical base64url (32 bytes)".into());
    }
    if ux.get("consent_for_action").is_some_and(|c| !c.is_boolean()) {
        return Some("ux.consent_for_action must be a boolean".into());
    }
    let consent = ux.get("consent_for_action").and_then(Value::as_bool) == Some(true);
    if consent && (!ux.contains_key("action_digest") || !y1 || o.contains_key("partial")) {
        return Some("consent_for_action needs action_digest and a plain yes".into());
    }
    if consent && canary {
        return Some("a canary never consents to an action".into());
    }
    if let Some(wa) = ux.get("webauthn") {
        let ok = wa.as_object().is_some_and(|w| only_keys(w, &WA_KEYS).is_none() && WA_KEYS.iter().all(|k| w.get(*k).is_some_and(Value::is_string)));
        if !ok {
            return Some("ux.webauthn is malformed".into());
        }
    }
    if y1 && !canary {
        match str_of(ux.get("tier")) {
            Some("hold") if !ux.get("hold_ms").is_some_and(|h| is_int(h) && num(h).is_some_and(|f| f >= MIN_HOLD_MS as f64)) => {
                return Some(format!("hold tier needs hold_ms >= {MIN_HOLD_MS}"));
            }
            Some("typed") if !ux.contains_key("typed_digest") => return Some("typed tier needs typed_digest".into()),
            Some("device") if !ux.contains_key("webauthn") => return Some("device tier needs a WebAuthn assertion".into()),
            _ => {}
        }
    }
    None
}

/// JSON.parse(JSON.stringify(v)): -0 becomes 0.
fn plain(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), plain(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(plain).collect()),
        Value::Number(_) if num(v) == Some(0.0) => json!(0),
        _ => v.clone(),
    }
}

fn answer_body(a: &Map<String, Value>) -> Value {
    let mut body = Map::new();
    for k in ANS_KEYS.iter().filter(|k| **k != "sig") {
        if let Some(x) = a.get(*k) {
            body.insert((*k).to_string(), x.clone());
        }
    }
    plain(&Value::Object(body))
}

fn domain_message(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    let mut out = domain.as_bytes().to_vec();
    out.extend_from_slice(crate::canonicalize_strict(body)?.as_bytes());
    Ok(out)
}

pub(crate) fn ed_sign(seed: &[u8; 32], msg: &[u8]) -> String {
    crate::b64_encode(&ed25519_dalek::SigningKey::from_bytes(seed).sign(msg).to_bytes())
}

pub(crate) fn ed_public_b64u(seed: &[u8; 32]) -> String {
    crate::b64_encode(&ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body).
pub fn sign_intent_answer(a: &Value, principal_seed: &[u8; 32]) -> Result<Value, String> {
    let mut base = a.as_object().cloned().unwrap_or_default();
    base.insert("v".into(), json!(2));
    base.insert("kind".into(), json!("pca-intent-observation"));
    base.insert("signer".into(), json!(ed_public_b64u(principal_seed)));
    base.insert("alg".into(), json!("ed25519"));
    let body = answer_body(&base);
    if let Some(bad) = answer_shape_error(&body) {
        return Err(format!("signIntentAnswer: {bad}"));
    }
    let sig = ed_sign(principal_seed, &domain_message(INTENT_ANSWER_SIG_DOMAIN, &body)?);
    let mut out = body.as_object().cloned().unwrap_or_default();
    out.insert("sig".into(), json!(sig));
    Ok(Value::Object(out))
}

/// Verify a signed answer: `{ok: true}` or `{ok: false, reason}`. `principals` (the keys named in the session root) restricts the
/// signer; given but not an array it restricts to nobody. Never errs.
pub fn verify_intent_answer(a: &Value, principals: Option<&Value>) -> Value {
    let run = || -> Result<Value, String> {
        if let Some(bad) = answer_shape_error(a) {
            return Ok(json!({ "ok": false, "reason": bad }));
        }
        let o = a.as_object().ok_or("not an object")?;
        let signer = str_of(o.get("signer")).ok_or("signer")?;
        if let Some(p) = principals {
            if !p.as_array().is_some_and(|arr| arr.iter().any(|x| x.as_str() == Some(signer))) {
                return Ok(json!({ "ok": false, "reason": "signer is not a principal of the session" }));
            }
        }
        let Some(sig) = str_of(o.get("sig")) else { return Ok(json!({ "ok": false, "reason": "bad signature" })) };
        let msg = domain_message(INTENT_ANSWER_SIG_DOMAIN, &answer_body(o))?;
        if crate::verify_b64u(signer, &msg, sig) {
            Ok(json!({ "ok": true }))
        } else {
            Ok(json!({ "ok": false, "reason": "bad signature" }))
        }
    };
    run().unwrap_or_else(|e| json!({ "ok": false, "reason": format!("malformed answer: {e}") }))
}

/// Content address of a signed answer (evidence bundles and delta grants refer to it).
pub fn answer_ref(a: &Value) -> Result<String, String> {
    strict_hash(&json!({ "d": INTENT_ANSWER_REF_DOMAIN, "a": a }))
}

pub fn typed_digest(question_id: &str, normalized_value: &str) -> Result<String, String> {
    strict_hash(&json!({ "d": INTENT_TYPED_DOMAIN, "q": question_id, "v": normalized_value }))
}

/// The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action.
pub fn device_challenge(question_id: &str, rendered_digest: &str, y: i64, action_digest: Option<&str>) -> Result<String, String> {
    strict_hash(&json!({ "d": INTENT_DEVICE_CHALLENGE_DOMAIN, "q": question_id, "r": rendered_digest, "y": y, "a": action_digest }))
}

// ---- cell coordinates <-> the wallet's own Omega (box.ts) ---------------------------------------------------------------------------------------

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}

/// A coordinate key of a dimension path: the spec's short aliases of lifted dimensions.
pub fn coord_key_of(path: &str) -> String {
    static ACC: OnceLock<Regex> = OnceLock::new();
    static MON: OnceLock<Regex> = OnceLock::new();
    static PROV: OnceLock<Regex> = OnceLock::new();
    static WORLD: OnceLock<Regex> = OnceLock::new();
    if let Some(c) = re(&ACC, r"^env\.acc\.([A-Za-z0-9_.-]+)\.post$").captures(path) {
        return c[1].to_string();
    }
    if let Some(c) = re(&MON, r"^env\.mon\.([A-Za-z0-9_.-]+)\.state$").captures(path) {
        return format!("mon:{}", &c[1]);
    }
    if let Some(c) = re(&PROV, "^env\\.prov\\.([^\n\r\u{2028}\u{2029}]+)$").captures(path) {
        return format!("prov:{}", &c[1]);
    }
    if let Some(c) = re(&WORLD, r"^env\.world\.([A-Za-z0-9_.-]+)$").captures(path) {
        return c[1].to_string();
    }
    path.to_string()
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

/// The label of categorical value `i` of a dimension, as used in coordinates (`⊥` for "any other").
pub fn cat_label(d: &Value, i: usize) -> String {
    d["values"][i]["value"].as_str().unwrap_or("").to_string()
}

pub enum BoxResult<'a> {
    /// `box_[k]` holds the allowed cell indices of dimension `k` (sorted, de-duplicated).
    Ok {
        vs: &'a Value,
        box_: Vec<Vec<usize>>,
    },
    Refused(String),
}

fn look<'a>(coords: &'a Value, key: &str) -> Option<&'a Value> {
    coords.as_object().and_then(|m| m.get(key))
}

fn is_integral(x: f64) -> bool {
    x.is_finite() && x.fract() == 0.0
}

/// Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once; anything the wallet cannot
/// resolve exactly is refused (`BoxResult::Refused`); `Err` is a reference throw.
pub fn resolve_coords<'a>(omega: &'a Value, verb: &str, coords: &Value) -> Result<BoxResult<'a>, String> {
    let Some(vs) = arr(&omega["verbs"]).iter().find(|v| v["verb"].as_str() == Some(verb)) else {
        return Ok(BoxResult::Refused(format!("verb {verb} is not in the wallet's outcome space")));
    };
    let dims = arr(&vs["dims"]);
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for (k, d) in dims.iter().enumerate() {
        let path = d["path"].as_str().unwrap_or("");
        by_key.insert(path.to_string(), k);
        by_key.insert(coord_key_of(path), k);
    }
    let mut named: HashSet<usize> = HashSet::new();
    for (key, _) in js_entries(coords)? {
        let Some(&k) = by_key.get(&key) else { return Ok(BoxResult::Refused(format!("unknown dimension {key}"))) };
        if !named.insert(k) {
            return Ok(BoxResult::Refused(format!("dimension {} is named twice", dims[k]["path"].as_str().unwrap_or(""))));
        }
    }
    let mut box_: Vec<Vec<usize>> = vec![];
    for d in dims {
        let path = d["path"].as_str().unwrap_or("");
        let c = match look(coords, path) {
            Some(x) if !x.is_null() => Some(x),
            _ => look(coords, &coord_key_of(path)),
        };
        let Some(c) = c else { return Ok(BoxResult::Refused(format!("coordinates leave out dimension {path}"))) };
        if c.is_null() {
            return Err("Cannot read properties of null".into());
        }
        if d["kind"].as_str() == Some("num") {
            let r = c.as_array().filter(|a| a.len() == 2 && a[0].is_number() && a[1].is_number());
            let Some(r) = r else { return Ok(BoxResult::Refused(format!("dimension {path} is numeric: expected an index range"))) };
            let (lo, hi) = (num(&r[0]).unwrap_or(f64::NAN), num(&r[1]).unwrap_or(f64::NAN));
            let neg0 = |x: f64| x == 0.0 && x.is_sign_negative();
            if !(is_integral(lo) && is_integral(hi) && !neg0(lo) && !neg0(hi) && lo >= 0.0 && lo <= hi && hi < num_cells(d).len() as f64) {
                return Ok(BoxResult::Refused(format!("index range of {path} is out of range")));
            }
            box_.push((lo as usize..=hi as usize).collect());
        } else {
            let Some(labels) = c.as_array() else { return Err("c.every is not a function".into()) };
            if !labels.iter().all(Value::is_string) {
                return Ok(BoxResult::Refused(format!("dimension {path} is categorical: expected a value set")));
            }
            let mut ids: Vec<usize> = vec![];
            for l in labels {
                let label = l.as_str().unwrap_or("");
                let hits: Vec<usize> = arr(&d["values"]).iter().enumerate().filter(|(_, v)| v["value"].as_str() == Some(label)).map(|(j, _)| j).collect();
                let quoted = || Value::String(label.to_string()).to_string();
                if hits.is_empty() {
                    return Ok(BoxResult::Refused(format!("unknown value {} for {path}", quoted())));
                }
                if hits.len() > 1 {
                    return Ok(BoxResult::Refused(format!("value {} names two cells of {path}", quoted())));
                }
                ids.push(hits[0]);
            }
            ids.sort_unstable();
            ids.dedup();
            box_.push(ids);
        }
    }
    Ok(BoxResult::Ok { vs, box_ })
}

/// The coordinates of a box (the inverse of [`resolve_coords`]; numeric sides must be contiguous).
pub fn coords_of_box(vs: &Value, box_: &[Vec<usize>]) -> Result<Value, String> {
    let mut out = Map::new();
    for (k, d) in arr(&vs["dims"]).iter().enumerate() {
        let path = d["path"].as_str().unwrap_or("");
        let ids = box_.get(k).ok_or("Cannot read properties of undefined")?;
        if d["kind"].as_str() == Some("num") {
            let (lo, hi) = (ids.iter().min(), ids.iter().max());
            match (lo, hi) {
                (Some(&lo), Some(&hi)) if hi - lo + 1 == ids.len() => out.insert(path.to_string(), json!([lo, hi])),
                _ => return Err(format!("coordsOfBox: numeric side of {path} is not contiguous")),
            };
        } else {
            out.insert(path.to_string(), Value::Array(ids.iter().map(|i| json!(cat_label(d, *i))).collect()));
        }
    }
    Ok(Value::Object(out))
}

/// The coordinates of one cell.
pub fn coords_of_cell(vs: &Value, idx: &[usize]) -> Result<Value, String> {
    let b: Vec<Vec<usize>> = idx.iter().map(|i| vec![*i]).collect();
    coords_of_box(vs, &b)
}

pub fn cell_in_box(box_: &[Vec<usize>], idx: &[usize]) -> bool {
    box_.len() == idx.len() && box_.iter().enumerate().all(|(k, ids)| ids.contains(&idx[k]))
}

/// Every cell (per-dimension indices) of a box, in lexicographic order.
pub fn box_cells(box_: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = vec![vec![]];
    for ids in box_ {
        out = out.iter().flat_map(|pre| ids.iter().map(move |i| pre.iter().copied().chain([*i]).collect())).collect();
    }
    out
}

pub fn box_size(box_: &[Vec<usize>]) -> usize {
    box_.iter().fold(1usize, |n, ids| n.saturating_mul(ids.len()))
}

/// The cell of a concrete action `{verb, values}` in the wallet's Omega (`Ok(None)` when it falls outside it: fail closed).
pub fn cell_of_action<'a>(omega: &'a Value, a: &Value) -> Result<Option<(&'a Value, Vec<usize>)>, String> {
    if a.is_null() {
        return Err("Cannot read properties of null (reading 'verb')".into());
    }
    let Some(vs) = arr(&omega["verbs"]).iter().find(|v| get(a, "verb").is_some_and(|x| &v["verb"] == x)) else { return Ok(None) };
    let values = get(a, "values").ok_or("Cannot use 'in' operator to search for a path in undefined")?;
    match values {
        Value::Object(m) => {
            if !arr(&vs["dims"]).iter().all(|d| m.contains_key(d["path"].as_str().unwrap_or(""))) {
                return Ok(None);
            }
        }
        Value::Array(_) => return Ok(None),
        _ => return Err("Cannot use 'in' operator".into()),
    }
    Ok(cell_of(vs, &json!({ "verb": a["verb"], "values": values })).map(|idx| (vs, idx)))
}

/// Flat lexicographic index of a cell (the tie-breaker "cell index").
pub fn flat_index(vs: &Value, idx: &[usize]) -> usize {
    let mut f = 0usize;
    for (k, d) in arr(&vs["dims"]).iter().enumerate() {
        f = f * cell_count(d) + idx[k];
    }
    f
}

// ---- stats (stats.ts) -----------------------------------------------------------------------------------------------------------------------

const LANCZOS: [f64; 8] = [
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_13,
    -176.615_029_162_140_59,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_571_6e-6,
    1.505_632_735_149_311_6e-7,
];

pub fn ln_gamma(x: f64) -> f64 {
    if x < 0.5 {
        return fdlibm::log(PI / fdlibm::sin(PI * x)) - ln_gamma(1.0 - x);
    }
    let z = x - 1.0;
    let mut a = 0.999_999_999_999_809_93;
    let t = z + 7.5;
    for (i, l) in LANCZOS.iter().enumerate() {
        a += l / (z + i as f64 + 1.0);
    }
    0.5 * fdlibm::log(2.0 * PI) + (z + 0.5) * fdlibm::log(t) - t + fdlibm::log(a)
}

/// The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by).
pub fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const TINY: f64 = 1e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - (qab * x) / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=300 {
        let m = m as f64;
        let m2 = 2.0 * m;
        let mut aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 1e-15 {
            break;
        }
    }
    h
}

/// Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1].
pub fn beta_inc(x: f64, a: f64, b: f64) -> Result<f64, String> {
    if !(a > 0.0 && b > 0.0) {
        return Err("betaInc: a and b must be > 0".into());
    }
    if x <= 0.0 {
        return Ok(0.0);
    }
    if x >= 1.0 {
        return Ok(1.0);
    }
    let lbt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * fdlibm::log(x) + b * fdlibm::log(1.0 - x);
    let bt = fdlibm::exp(lbt);
    if x < (a + 1.0) / (a + b + 2.0) {
        return Ok((bt * betacf(a, b, x)) / a);
    }
    Ok(1.0 - (bt * betacf(b, a, 1.0 - x)) / b)
}

/// The q-quantile of Beta(a, b) by bisection (200 steps).
/// The upper bound q such that the Beta(a, b) posterior puts mass `delta` above it, for POSITIVE INTEGER a and b, exactly:
/// I_x(a, b) = P[Bin(a + b - 1, x) >= a], so the quantile at level 1 - delta is the Clopper-Pearson inversion with k = a - 1 successes in
/// n = a + b - 1 trials (integer arithmetic, rounded outward to 2^-44). The freeze and admission decisions compare this value.
pub fn beta_upper_exact(delta: f64, a: f64, b: f64) -> Result<f64, String> {
    let int = |x: f64| x.is_finite() && x.fract() == 0.0 && x >= 1.0;
    if !(int(a) && int(b)) {
        return Err("betaUpperExact: a and b must be positive integers".into());
    }
    crate::wallet_omega::clopper_pearson_upper(a - 1.0, a + b - 1.0, delta)
}

pub fn beta_quantile(q: f64, a: f64, b: f64) -> Result<f64, String> {
    if !(0.0..=1.0).contains(&q) {
        return Err("betaQuantile: q must be in [0, 1]".into());
    }
    if q == 0.0 {
        return Ok(0.0);
    }
    if q == 1.0 {
        return Ok(1.0);
    }
    let (mut lo, mut hi) = (0.0, 1.0);
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if beta_inc(mid, a, b)? < q {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(hi)
}

/// Binary entropy in bits.
pub fn bin_ent(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    -(p * fdlibm::log2(p) + (1.0 - p) * fdlibm::log2(1.0 - p))
}

// ---- canaries (canary.ts) -------------------------------------------------------------------------------------------------------------------

/// Fold one canary answer into the counts (pure; members the counts carry beyond the four are kept).
pub fn record_canary(n: &Value, expected: &Value, y: &Value) -> Result<Value, String> {
    let mut out = n.as_object().cloned().ok_or("Cannot read properties of null")?;
    let mut bump = |k: &str| {
        let v = nan_of(n.get(k)) + 1.0;
        out.insert(k.into(), json!(v));
    };
    if is_num_eq(Some(expected), 0.0) {
        bump(if is_num_eq(Some(y), 1.0) { "falseYes" } else { "correctNo" });
    } else if is_num_eq(Some(y), 0.0) {
        bump("falseNo");
    } else {
        bump("correctYes");
    }
    Ok(Value::Object(out))
}

#[derive(Clone, Debug, PartialEq)]
pub struct NoiseEstimate {
    pub eta_pos: f64,
    pub eta_neg: f64,
    pub eta_pos_upper: f64,
    pub eta_neg_upper: f64,
    pub eta_pos_cp: f64,
    pub eta_neg_cp: f64,
    pub asked: f64,
}

impl NoiseEstimate {
    pub fn to_value(&self) -> Value {
        json!({
            "etaPos": self.eta_pos, "etaNeg": self.eta_neg, "etaPosUpper": self.eta_pos_upper, "etaNegUpper": self.eta_neg_upper,
            "etaPosCP": self.eta_pos_cp, "etaNegCP": self.eta_neg_cp, "asked": self.asked
        })
    }
}

/// Posterior means and upper bounds of the canary noise rates (`n` = `{falseYes, correctNo, falseNo, correctYes}`; `delta_c` default 0.05).
pub fn estimate_noise(n: &Value, delta_c: f64) -> Result<NoiseEstimate, String> {
    if !(delta_c > 0.0 && delta_c < 1.0) {
        return Err("estimateNoise: deltaC must be in (0, 1)".into());
    }
    let c = |k: &str| nan_of(n.get(k));
    let (false_yes, correct_no, false_no, correct_yes) = (c("falseYes"), c("correctNo"), c("falseNo"), c("correctYes"));
    let ap = NOISE_PRIOR_A + false_yes;
    let bp = NOISE_PRIOR_B + correct_no;
    let an = NOISE_PRIOR_A + false_no;
    let bn = NOISE_PRIOR_B + correct_yes;
    let known_no = false_yes + correct_no;
    let known_yes = false_no + correct_yes;
    Ok(NoiseEstimate {
        eta_pos: ap / (ap + bp),
        eta_neg: an / (an + bn),
        eta_pos_upper: beta_upper_exact(delta_c, ap, bp)?,
        eta_neg_upper: beta_upper_exact(delta_c, an, bn)?,
        eta_pos_cp: if known_no == 0.0 { 1.0 } else { crate::wallet_omega::clopper_pearson_upper(false_yes, known_no, delta_c)? },
        eta_neg_cp: if known_yes == 0.0 { 1.0 } else { crate::wallet_omega::clopper_pearson_upper(false_no, known_yes, delta_c)? },
        asked: known_no + known_yes,
    })
}

/// `verb|i,j,...`
pub fn cell_key(verb: &str, idx: &[usize]) -> String {
    format!("{verb}|{}", idx.iter().map(usize::to_string).collect::<Vec<_>>().join(","))
}

#[derive(Clone, Debug, PartialEq)]
pub struct CellAt {
    pub verb: String,
    pub idx: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanaryChoice {
    pub verb: String,
    pub idx: Vec<usize>,
    /// 0 (a known no) or 1 (a confirmed yes).
    pub expected: u8,
    /// "ceiling" | "veto" | "confirmed-yes"
    pub source: String,
}

/// Cells one step outside the confirmed region in exactly one dimension (deterministic order).
pub fn boundary_neighbours(omega: &Value, confirmed: &[CellAt]) -> Vec<CellAt> {
    let inside: HashSet<String> = confirmed.iter().map(|c| cell_key(&c.verb, &c.idx)).collect();
    let mut out: HashMap<String, CellAt> = HashMap::new();
    for c in confirmed {
        let Some(vs) = arr(&omega["verbs"]).iter().find(|v| v["verb"].as_str() == Some(c.verb.as_str())) else { continue };
        for (k, d) in arr(&vs["dims"]).iter().enumerate() {
            let Some(&here) = c.idx.get(k) else { continue };
            let n = cell_count(d) as i64;
            let alts: Vec<i64> = if d["kind"].as_str() == Some("num") { vec![here as i64 - 1, here as i64 + 1] } else { (0..n).collect() };
            for a in alts {
                if a < 0 || a >= n || a == here as i64 {
                    continue;
                }
                let mut idx = c.idx.clone();
                idx[k] = a as usize;
                let key = cell_key(&c.verb, &idx);
                if !inside.contains(&key) {
                    out.insert(key, CellAt { verb: c.verb.clone(), idx });
                }
            }
        }
    }
    let mut v: Vec<(String, CellAt)> = out.into_iter().collect();
    v.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    v.into_iter().map(|(_, c)| c).collect()
}

/// The inputs of [`pick_canary`].
pub struct PickCtx<'a> {
    pub omega: &'a Value,
    /// Cells inside the confirmed region (in the effective grant).
    pub confirmed: &'a [CellAt],
    /// Why a cell is a known no ("ceiling" | "veto"), or `None`.
    pub known_no: &'a dyn Fn(&str, &[usize]) -> Option<String>,
    /// Cells with an earlier verified high-friction yes in this session.
    pub known_yes: &'a [CellAt],
    /// `verb|i,j,..` keys not to use.
    pub exclude: &'a HashSet<String>,
    /// The randomness source, a draw in [0, 1) (a failing draw ends the call with its error).
    pub rand: &'a mut dyn FnMut() -> Result<f64, String>,
    /// Insertion probability (default 0.1).
    pub rho: Option<f64>,
    pub low_harm_session: bool,
    pub canaries_so_far: u64,
}

/// Decide whether to insert a canary now, and which (`None`: no canary this time).
pub fn pick_canary(ctx: &mut PickCtx) -> Result<Option<CanaryChoice>, String> {
    let rho = ctx.rho.unwrap_or(0.1);
    if !(0.0..=1.0).contains(&rho) {
        return Err("pickCanary: rho must be in [0, 1]".into());
    }
    if ctx.low_harm_session && ctx.canaries_so_far >= 1 {
        return Ok(None);
    }
    if !((ctx.rand)()? < rho) {
        return Ok(None);
    }
    let mut no: Vec<CanaryChoice> = vec![];
    for c in boundary_neighbours(ctx.omega, ctx.confirmed) {
        if ctx.exclude.contains(&cell_key(&c.verb, &c.idx)) {
            continue;
        }
        if let Some(why) = (ctx.known_no)(&c.verb, &c.idx).filter(|w| !w.is_empty()) {
            no.push(CanaryChoice { verb: c.verb, idx: c.idx, expected: 0, source: why });
        }
    }
    let yes: Vec<CanaryChoice> = ctx
        .known_yes
        .iter()
        .filter(|c| !ctx.exclude.contains(&cell_key(&c.verb, &c.idx)))
        .map(|c| CanaryChoice { verb: c.verb.clone(), idx: c.idx.clone(), expected: 1, source: "confirmed-yes".into() })
        .collect();
    if no.is_empty() && yes.is_empty() {
        return Ok(None);
    }
    let pool = if !no.is_empty() && !yes.is_empty() {
        if (ctx.rand)()? < 0.5 {
            no
        } else {
            yes
        }
    } else if !no.is_empty() {
        no
    } else {
        yes
    };
    let at = ((pool.len() - 1) as f64).min(((ctx.rand)()? * pool.len() as f64).floor()) as usize;
    Ok(Some(pool[at].clone()))
}

// ---- approval fatigue (fatigue.ts) ------------------------------------------------------------------------------------------------------

/// eta+ under load: base + beta_f * n_recent, capped at 1/2.
pub fn eta_under_load(base: f64, beta_f: f64, n_recent: f64) -> Result<f64, String> {
    if !(base >= 0.0 && beta_f >= 0.0 && is_integral(n_recent) && n_recent >= 0.0) {
        return Err("etaUnderLoad: bad arguments".into());
    }
    Ok(js_min(0.5, base + beta_f * n_recent))
}

/// `{etaPos, etaPosBar, etaNegBar, frozen}` under load (`model` default [`default_fatigue`]).
pub fn noise_state(counts: &Value, n_recent: f64, model: Option<&Value>) -> Result<Value, String> {
    let dm = default_fatigue();
    let model = model.unwrap_or(&dm);
    let m = |k: &str| nan_of(get(model, k));
    let e = estimate_noise(counts, m("deltaC"))?;
    let eta_pos = eta_under_load(e.eta_pos, m("betaF"), n_recent)?;
    let eta_pos_bar = eta_under_load(e.eta_pos_upper, m("betaF"), n_recent)?;
    let stat = if str_of(get(model, "freezeOn")) == Some("mean") { eta_pos } else { eta_pos_bar };
    Ok(json!({ "etaPos": eta_pos, "etaPosBar": eta_pos_bar, "etaNegBar": js_min(0.5, e.eta_neg_upper), "frozen": stat > m("etaStop") }))
}

/// `{tau, etaPos, etaNeg, doubleConfirmIrreversible, falseAdmitBound}` for a noise state.
pub fn admission_policy(state: &Value, model: Option<&Value>) -> Result<Value, String> {
    let dm = default_fatigue();
    let model = model.unwrap_or(&dm);
    if get(model, "assumeNoiseFree").is_some_and(truthy) {
        return Ok(json!({ "tau": 1, "etaPos": 0, "etaNeg": 0, "doubleConfirmIrreversible": false, "falseAdmitBound": 0 }));
    }
    let delta = nan_of(get(model, "delta"));
    if !(delta > 0.0 && delta < 1.0) {
        return Err("admissionPolicy: delta must be in (0, 1)".into());
    }
    let ep = js_min(BELOW_HALF, nan_of(get(state, "etaPosBar")));
    let en = js_min(BELOW_HALF, nan_of(get(state, "etaNegBar")));
    Ok(json!({ "tau": 1.0 - delta, "etaPos": ep, "etaNeg": en, "doubleConfirmIrreversible": ep > 0.0, "falseAdmitBound": ep * ep }))
}

/// Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split around it by
/// opening sessions). Keeps only timestamps inside the window.
pub struct SlidingWindowCounter {
    pub window_ms: f64,
    times: std::collections::VecDeque<f64>,
}

impl SlidingWindowCounter {
    pub const DEFAULT_WINDOW_MS: f64 = 3_600_000.0;

    pub fn new(window_ms: f64) -> Result<Self, String> {
        if !(is_integral(window_ms) && window_ms > 0.0) {
            return Err("SlidingWindowCounter: windowMs must be a positive integer".into());
        }
        Ok(Self { window_ms, times: Default::default() })
    }

    fn prune(&mut self, now: f64) {
        if !now.is_finite() {
            return; // an infinite clock must never forget a recorded event
        }
        while self.times.front().is_some_and(|t| *t <= now - self.window_ms) {
            self.times.pop_front();
        }
    }

    pub fn count(&mut self, now: f64) -> usize {
        self.prune(now);
        self.times.len()
    }

    /// Record one event at `now` if the count is below `cap`; `Ok(false)` (and nothing recorded) otherwise.
    pub fn try_add(&mut self, now: f64, cap: f64) -> Result<bool, String> {
        if !now.is_finite() {
            return Ok(false);
        }
        self.prune(now);
        if !((self.times.len() as f64) < cap) {
            return Ok(false);
        }
        if self.times.back().is_some_and(|t| !(now >= *t)) {
            return Err("SlidingWindowCounter: time went backwards".into());
        }
        self.times.push_back(now);
        Ok(true)
    }
}

/// One answer on a screen, for [`double_confirmed`].
pub struct Confirmation {
    pub screen: f64,
    pub tier: String,
}

/// Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them.
pub fn double_confirmed(records: &[Confirmation]) -> bool {
    let mut strong: Vec<f64> = records.iter().filter(|r| r.tier == "typed" || r.tier == "device").map(|r| r.screen).collect();
    strong.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    for i in 0..strong.len() {
        for j in i + 1..strong.len() {
            if strong[j] - strong[i] >= 2.0 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod beta_upper_exact_tests {
    use super::beta_upper_exact;

    #[test]
    fn the_beta_upper_bound_is_the_exact_clopper_pearson_inversion() {
        // Beta(1, 1) is uniform: P[Bin(1, x) >= 1] = x, so the level-0.95 bound is 0.95 (rounded outward to 2^-44)
        let u = beta_upper_exact(0.05, 1.0, 1.0).unwrap();
        assert!((u - 0.95).abs() <= 2f64.powi(-43), "{u}");
        // the same value as the inversion it is defined by: k = a - 1 successes in n = a + b - 1 trials
        let (a, b) = (3.0, 5.0);
        assert_eq!(beta_upper_exact(0.05, a, b), crate::wallet_omega::clopper_pearson_upper(a - 1.0, a + b - 1.0, 0.05));
    }

    #[test]
    fn a_non_integer_or_non_positive_parameter_is_refused() {
        for (a, b) in [(0.0, 1.0), (1.0, 0.0), (1.5, 2.0), (2.0, 2.5), (f64::NAN, 1.0), (1.0, f64::INFINITY), (-1.0, 3.0)] {
            assert_eq!(beta_upper_exact(0.05, a, b), Err("betaUpperExact: a and b must be positive integers".to_string()), "{a} {b}");
        }
    }
}
