//! K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
//! binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
//!
//! Signatures are Ed25519 (strict) over the UTF-8 bytes of `hash_canonical({"kind": kind, "body": body})` (the digest string);
//! `body` is the signed object without its `sig`. Escalation is integer-only. Total: no function panics.
use crate::{decode_b64u_strict, hash_canonical_strict, safe_int, verify_b64u};
use serde_json::{json, Map, Value};

pub const PPM: i64 = 1_000_000;
pub const MAX_MULTIPLIER_PPM: i64 = 100 * PPM;
pub const NETWORK_TOKEN_BINDING_KIND: &str = "pca.network_token_binding";

fn minor(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn is_addr(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && is_hex(&s[2..])
}
fn is_qty(s: &str) -> bool {
    s.starts_with("0x") && is_hex(&s[2..]) && (&s[2..] == "0" || !s[2..].starts_with('0'))
}

/// `None` when the key or signature does not decode; else the strict verification result.
fn sig_ok(pubkey: Option<&str>, kind: &str, obj: &Map<String, Value>) -> Option<bool> {
    let mut body = Map::new();
    for (k, v) in obj {
        if k != "sig" {
            body.insert(k.clone(), v.clone());
        }
    }
    let (p, s) = (pubkey?, obj.get("sig")?.as_str()?);
    decode_b64u_strict(p, None)?;
    decode_b64u_strict(s, None)?;
    let h = hash_canonical_strict(&json!({"kind": kind, "body": Value::Object(body)}))?;
    Some(verify_b64u(p, h.as_bytes(), s))
}

// ---- network-token binding ---------------------------------------------------------------------------------------

fn luhn(d: &str) -> bool {
    let (mut sum, mut dbl) = (0u32, false);
    for c in d.bytes().rev() {
        let mut n = u32::from(c - b'0');
        if dbl {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        dbl = !dbl;
    }
    sum % 10 == 0
}

/// A maximal digit run (spaces and hyphens removed) of 13..19 digits that passes Luhn.
pub fn looks_like_pan(s: &str) -> bool {
    let t: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    t.split(|c: char| !c.is_ascii_digit()).any(|r| (13..=19).contains(&r.len()) && luhn(r))
}

pub fn token_ref_error(r: Option<&Value>) -> Option<&'static str> {
    let ok = r.and_then(Value::as_str).is_some_and(|s| (8..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')));
    if !ok {
        return Some("token_ref_malformed");
    }
    if looks_like_pan(r.and_then(Value::as_str).unwrap_or("")) {
        return Some("token_ref_looks_like_pan");
    }
    None
}

/// `None` = valid, else the reason. `provider` None = any.
pub fn verify_network_token_binding(b: &Value, grant: &Value, holder: &str, issuer_nonce: &str, provider: Option<&str>) -> Option<&'static str> {
    let Some(m) = b.as_object().filter(|m| m.get("kind").and_then(Value::as_str) == Some(NETWORK_TOKEN_BINDING_KIND)) else { return Some("binding_malformed") };
    if let Some(e) = token_ref_error(m.get("token_ref")) {
        return Some(e);
    }
    let p = m.get("provider").and_then(Value::as_str).unwrap_or("");
    if p.is_empty() || provider.is_some_and(|x| x != p) {
        return Some("provider_mismatch");
    }
    if hash_canonical_strict(grant).as_deref() != m.get("grant_digest").and_then(Value::as_str) {
        return Some("grant_digest_mismatch");
    }
    if m.get("holder").and_then(Value::as_str) != Some(holder) {
        return Some("holder_mismatch");
    }
    if m.get("issuer_nonce").and_then(Value::as_str) != Some(issuer_nonce) {
        return Some("issuer_nonce_mismatch");
    }
    let body = json!({"kind": NETWORK_TOKEN_BINDING_KIND, "v": 1, "provider": p, "token_ref": m["token_ref"], "grant_digest": m["grant_digest"], "issuer_nonce": m["issuer_nonce"], "holder": m["holder"]});
    let (Some(h), Some(proof)) = (hash_canonical_strict(&body), m.get("binding_proof").and_then(Value::as_str)) else { return Some("binding_malformed") };
    if decode_b64u_strict(holder, None).is_none() || decode_b64u_strict(proof, None).is_none() {
        return Some("binding_malformed");
    }
    if verify_b64u(holder, h.as_bytes(), proof) { None } else { Some("binding_proof_invalid") }
}

// ---- risk-priced escalation --------------------------------------------------------------------------------------

pub fn pricing_config_error(c: &Value) -> Option<&'static str> {
    let Some(m) = c.as_object() else { return Some("config_malformed") };
    if m.get("v").and_then(safe_int) != Some(1) || !["principal", "currency", "sig"].iter().all(|k| m.get(*k).is_some_and(Value::is_string)) {
        return Some("config_malformed");
    }
    let (Some(cost), Some(max), Some(_), Some(_)) = (minor(m.get("interruptionCost")), minor(m.get("maxInterruptionCost")), minor(m.get("hardCeilingLoss")), minor(m.get("epoch"))) else { return Some("config_amounts_invalid") };
    if cost > max {
        return Some("config_cost_above_max");
    }
    if !m.get("tightenStepPpm").and_then(safe_int).is_some_and(|s| (0..=MAX_MULTIPLIER_PPM).contains(&s)) {
        return Some("config_step_invalid");
    }
    match sig_ok(m["principal"].as_str(), "pca.escalation_pricing", m) {
        None => Some("config_malformed"),
        Some(false) => Some("config_signature_invalid"),
        Some(true) => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub ask: bool,
    pub reason: &'static str,
}
const fn ask(reason: &'static str) -> Decision {
    Decision { ask: true, reason }
}

/// Ask a person iff `min(p * multiplier, 1e12) * loss > interruptionCost * 1e12` (u128); anything unexpected asks.
pub fn decide_escalation(config: &Value, cal: &Value, a: &Value) -> Decision {
    if let Some(e) = pricing_config_error(config) {
        return ask(e);
    }
    let cfg = &config;
    let Some(r) = a.as_object().filter(|r| r.get("currency") == cfg.get("currency")) else { return ask("currency_mismatch") };
    let (Some(loss), Some(p)) = (minor(r.get("loss")), r.get("pBadUpperPpm").and_then(safe_int).filter(|p| (0..=PPM).contains(p))) else { return ask("risk_input_invalid") };
    let Some(mult) = cal.get("multiplierPpm").and_then(safe_int).filter(|m| (PPM..=MAX_MULTIPLIER_PPM).contains(m)) else { return ask("calibration_invalid") };
    if loss > minor(cfg.get("hardCeilingLoss")).unwrap_or(0) {
        return ask("above_hard_ceiling");
    }
    let one = (PPM as u128) * (PPM as u128);
    let capped = ((p as u128) * (mult as u128)).min(one);
    if capped * (loss as u128) > (minor(cfg.get("interruptionCost")).unwrap_or(0) as u128) * one {
        return ask("expected_loss_exceeds_interruption_cost");
    }
    Decision { ask: false, reason: "expected_loss_within_interruption_cost" }
}

fn answer_ok(a: &Value, principal: &str) -> bool {
    let Some(m) = a.as_object() else { return false };
    m.get("v").and_then(safe_int) == Some(1)
        && m.get("principal").and_then(Value::as_str) == Some(principal)
        && m.get("nonce").and_then(Value::as_str).is_some_and(|n| n.encode_utf16().count() >= 8)
        && m.get("action_digest").is_some_and(Value::is_string)
        && matches!(m.get("answer").and_then(Value::as_str), Some("approve" | "deny"))
        && sig_ok(Some(principal), "pca.escalation_answer", m) == Some(true)
}

/// Fold principal-signed answers into the calibration; the multiplier can only rise. Returns (multiplierPpm, seen nonces in order).
pub fn update_calibration(config: &Value, cal: &Value, answers: &[Value], risks: &Map<String, Value>) -> (i64, Vec<String>) {
    let start = cal.get("multiplierPpm").and_then(safe_int).unwrap_or(PPM);
    let mut order: Vec<String> = cal.get("seen").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if pricing_config_error(config).is_some() {
        return (start, order);
    }
    let principal = config["principal"].as_str().unwrap_or("");
    let step = config["tightenStepPpm"].as_i64().unwrap_or(0);
    let mut mult = start;
    for a in answers {
        if !answer_ok(a, principal) {
            continue;
        }
        let nonce = a["nonce"].as_str().unwrap_or("");
        if order.iter().any(|n| n == nonce) {
            continue;
        }
        order.push(nonce.to_string());
        let Some(risk) = a["action_digest"].as_str().and_then(|d| risks.get(d)) else { continue };
        if a["answer"] == "deny" && !decide_escalation(config, &json!({"multiplierPpm": mult}), risk).ask {
            mult = (mult + step).min(MAX_MULTIPLIER_PPM);
        }
    }
    (mult.max(start), order)
}

// ---- ERC-7715 granted-permission check ---------------------------------------------------------------------------

fn lower(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).map_or_else(|| "\0".to_string(), str::to_lowercase)
}
/// Numeric compare of two normalised hex quantities (no leading zeros): longer is larger, else lexicographic.
fn hex_gt(a: &str, b: &str) -> bool {
    let (a, b) = (a[2..].to_lowercase(), b[2..].to_lowercase());
    (a.len(), a) > (b.len(), b)
}

/// `None` when what the wallet granted is within the request and the grant. `g` = {grantDigest, expiresAtSec}.
pub fn verify_granted_permission(g: &Value, sent: &Value, got: &Value, allowed_managers: &[String], context_owner: &dyn Fn(&str) -> Option<String>) -> Option<&'static str> {
    let Some(perm) = got.get("permission").and_then(Value::as_object) else { return Some("response_malformed") };
    let Some(ctx) = got.get("context").and_then(Value::as_str).filter(|c| c.starts_with("0x") && is_hex(&c[2..])) else { return Some("context_malformed") };
    if context_owner(ctx).is_some_and(|o| Some(o.as_str()) != g.get("grantDigest").and_then(Value::as_str)) {
        return Some("context_bound_to_other_grant");
    }
    let mgr = got.get("delegationManager").and_then(Value::as_str);
    if !mgr.is_some_and(|m| is_addr(m) && allowed_managers.iter().any(|x| x.eq_ignore_ascii_case(m))) {
        return Some("delegation_manager_not_allowed");
    }
    if lower(got.get("chainId")) != lower(sent.get("chainId")) {
        return Some("chain_mismatch");
    }
    if lower(got.get("to")) != lower(sent.get("to")) {
        return Some("recipient_mismatch");
    }
    if sent.get("from").is_some_and(|f| !f.is_null()) && lower(got.get("from")) != lower(sent.get("from")) {
        return Some("from_mismatch");
    }
    let sperm = &sent["permission"];
    let pt = perm.get("type").and_then(Value::as_str);
    if pt != sperm["type"].as_str() || !matches!(pt, Some("native-token-allowance" | "erc20-token-allowance")) {
        return Some("permission_type_mismatch");
    }
    let Some(d) = perm.get("data").and_then(Value::as_object) else { return Some("response_malformed") };
    let tok = |v: Option<&Value>| v.and_then(Value::as_str).map_or_else(String::new, str::to_lowercase);
    if tok(d.get("tokenAddress")) != tok(sperm["data"].get("tokenAddress")) {
        return Some("token_mismatch");
    }
    let Some(al) = d.get("allowance").and_then(Value::as_str).filter(|a| is_qty(a)) else { return Some("amount_malformed") };
    if hex_gt(al, sperm["data"]["allowance"].as_str().unwrap_or("0x0")) {
        return Some("amount_widened");
    }
    if perm.get("isAdjustmentAllowed") != sperm.get("isAdjustmentAllowed") && perm.get("isAdjustmentAllowed") == Some(&Value::Bool(true)) {
        return Some("adjustment_widened");
    }
    let Some(rules) = got.get("rules").and_then(Value::as_array) else { return Some("expiry_missing") };
    let mut expiry: Option<i64> = None;
    for rule in rules {
        if rule.get("type").and_then(Value::as_str) != Some("expiry") {
            return Some("unknown_rule_type");
        }
        if expiry.is_some() {
            return Some("duplicate_expiry");
        }
        let Some(ts) = rule.get("data").and_then(|d| d.get("timestamp")).and_then(safe_int) else { return Some("expiry_malformed") };
        expiry = Some(ts);
    }
    let Some(e) = expiry else { return Some("expiry_missing") };
    if e > g.get("expiresAtSec").and_then(safe_int).unwrap_or(0) {
        return Some("expiry_extended");
    }
    None
}
