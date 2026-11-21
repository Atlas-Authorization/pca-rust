//! ERC-7715 (`wallet_grantPermissions`) for a PCA grant: the permission request a grant envelope maps to (an allowance capped at
//! the grant's spend cap, an expiry rule at its expiry) and the fail-closed check of what the wallet granted back (never wider:
//! amount, expiry, adjustment, chain, recipient, token, delegation manager, rule types, context binding).
use crate::hash_canonical;
use crate::oauth::js_str;
use rsa::BigUint;
use serde_json::{json, Map, Value};

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn hex_addr(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex_qty(s: &str) -> bool {
    let Some(d) = s.strip_prefix("0x") else { return false };
    d == "0" || (!d.is_empty() && !d.starts_with('0') && d.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn safe_int(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE)
}

fn hex_of(n: &BigUint) -> String {
    format!("0x{}", n.to_str_radix(16))
}

/// The ERC-7715 permission request for a grant envelope `{grantDigest, capMinor, expiresAtSec}` (`grantToPermissionRequest`):
/// allowance = capMinor x baseUnitsPerMinor base units, native or (with `token_address`) ERC-20, plus the expiry rule.
pub fn grant_to_permission_request(
    g: &Value,
    chain_id: u128,
    session_account: &str,
    token_address: Option<&str>,
    base_units_per_minor: &str,
    from: Option<&str>,
    is_adjustment_allowed: Option<bool>,
) -> Result<Value, String> {
    let (cap, exp) = (safe_int(g.get("capMinor")), safe_int(g.get("expiresAtSec")));
    if !cap.is_some_and(|c| c > 0.0) || !exp.is_some_and(|e| e > 0.0) {
        return Err("grantToPermissionRequest: bad envelope".into());
    }
    if !hex_addr(session_account) || from.is_some_and(|f| !hex_addr(f)) || token_address.is_some_and(|t| !hex_addr(t)) {
        return Err("grantToPermissionRequest: bad address".into());
    }
    let dec = base_units_per_minor == "0" || (!base_units_per_minor.is_empty() && !base_units_per_minor.starts_with('0') && base_units_per_minor.bytes().all(|b| b.is_ascii_digit()));
    if !dec || base_units_per_minor == "0" {
        return Err("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string".into());
    }
    if chain_id == 0 {
        return Err("grantToPermissionRequest: bad chain".into());
    }
    let base = BigUint::parse_bytes(base_units_per_minor.as_bytes(), 10).ok_or("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string")?;
    let allowance = hex_of(&(BigUint::from(cap.unwrap() as u64) * base));
    let adj = is_adjustment_allowed.unwrap_or(true);
    let permission = match token_address {
        Some(t) => json!({ "type": "erc20-token-allowance", "isAdjustmentAllowed": adj, "data": { "tokenAddress": t, "allowance": allowance } }),
        None => json!({ "type": "native-token-allowance", "isAdjustmentAllowed": adj, "data": { "allowance": allowance } }),
    };
    let mut r = Map::new();
    r.insert("chainId".into(), json!(format!("0x{chain_id:x}")));
    if let Some(f) = from {
        r.insert("from".into(), json!(f));
    }
    r.insert("to".into(), json!(session_account));
    r.insert("permission".into(), permission);
    r.insert("rules".into(), json!([{ "type": "expiry", "data": { "timestamp": g["expiresAtSec"] } }]));
    Ok(Value::Object(r))
}

/// `Array.prototype.includes` (SameValueZero) over JSON values.
fn includes(list: &[Value], x: &Value) -> bool {
    list.iter().any(|v| match (v, x) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        _ => v == x,
    })
}

/// Does the wallet's `wallet_getSupportedExecutionPermissions` answer cover this request (`supportsRequest`)? Any malformed
/// input is false.
pub fn supports_request(supported: &Value, req: &Value) -> bool {
    let Some(perm) = req.get("permission").filter(|p| !p.is_null()) else { return false };
    let key = perm.get("type").map_or("undefined".to_string(), js_str);
    let s = match supported {
        Value::Object(m) => m.get(&key),
        Value::Array(a) => key.parse::<usize>().ok().filter(|i| i.to_string() == key).and_then(|i| a.get(i)),
        _ => None,
    };
    let Some(s) = s.filter(|s| !s.is_null()) else { return false };
    let Some(ids) = s.get("chainIds").and_then(Value::as_array) else { return false };
    let Some(lowered) = ids.iter().map(|x| x.as_str().map(str::to_lowercase)).collect::<Option<Vec<_>>>() else { return false };
    let Some(chain) = req.get("chainId").and_then(Value::as_str) else { return false };
    if !lowered.contains(&chain.to_lowercase()) {
        return false;
    }
    let rt = s.get("ruleTypes").filter(|x| !x.is_null()).or_else(|| s.get("rulesTypes"));
    let rules = match req.get("rules") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return false,
    };
    rules.iter().all(|r| {
        if r.is_null() {
            return false;
        }
        let t = r.get("type").cloned().unwrap_or(Value::Null);
        rt.and_then(Value::as_array).is_some_and(|l| r.get("type").is_some() && includes(l, &t))
    })
}

/// `wallet_revokePermission` params.
pub fn revoke_params(context: &str) -> Value {
    json!({ "permissionContext": context })
}

fn lower_of(v: Option<&Value>) -> String {
    v.map_or("undefined".to_string(), js_str).to_lowercase()
}

/// `BigInt(text)` for the forms the check meets: `0x` hex or plain decimal (surrounding whitespace allowed, empty = 0).
fn big(text: &str) -> Option<BigUint> {
    let t = text.trim();
    if t.is_empty() {
        return Some(BigUint::from(0u8));
    }
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) => BigUint::parse_bytes(h.as_bytes(), 16),
        Some(_) => None,
        None if t.bytes().all(|b| b.is_ascii_digit()) => BigUint::parse_bytes(t.as_bytes(), 10),
        None => None,
    }
}

/// The refusal code for what the wallet granted (`verifyGrantedPermission`), or `None` when it is no wider than what was sent.
/// `context_owner` answers which grant digest a permission context is already bound to.
pub fn verify_granted_permission(g: &Value, sent: &Value, got: &Value, allowed_managers: &[&str], context_owner: Option<&dyn Fn(&str) -> Option<String>>) -> Option<&'static str> {
    check(g, sent, got, allowed_managers, context_owner).unwrap_or(Some("response_malformed"))
}

/// `None` where the reference would throw (a TypeError inside its try): the caller maps it to `response_malformed`.
fn check(g: &Value, sent: &Value, r: &Value, managers: &[&str], owner_of: Option<&dyn Fn(&str) -> Option<String>>) -> Option<Option<&'static str>> {
    let done = |c: &'static str| Some(Some(c));
    if !(r.is_object() || r.is_array()) || !r.get("permission").is_some_and(|p| p.is_object() || p.is_array()) {
        return done("response_malformed");
    }
    let ctx = match r.get("context").and_then(Value::as_str) {
        Some(c) if c.len() > 2 && c.starts_with("0x") && c[2..].bytes().all(|b| b.is_ascii_hexdigit()) => c,
        _ => return done("context_malformed"),
    };
    if let Some(f) = owner_of {
        if f(ctx).is_some_and(|o| Some(o.as_str()) != g.get("grantDigest").and_then(Value::as_str)) {
            return done("context_bound_to_other_grant");
        }
    }
    let dm = r.get("delegationManager").and_then(Value::as_str);
    if !dm.is_some_and(|d| hex_addr(d) && managers.iter().any(|m| m.to_lowercase() == d.to_lowercase())) {
        return done("delegation_manager_not_allowed");
    }
    let sent_str = |k: &str| sent.get(k).and_then(Value::as_str).map(str::to_lowercase);
    if lower_of(r.get("chainId")) != sent_str("chainId")? {
        return done("chain_mismatch");
    }
    if lower_of(r.get("to")) != sent_str("to")? {
        return done("recipient_mismatch");
    }
    if sent.get("from").is_some() && lower_of(r.get("from")) != sent_str("from")? {
        return done("from_mismatch");
    }
    let (rp, sp) = (&r["permission"], sent.get("permission").filter(|p| !p.is_null())?);
    let t = rp.get("type");
    if t != sp.get("type") || !matches!(t.and_then(Value::as_str), Some("native-token-allowance" | "erc20-token-allowance")) {
        return done("permission_type_mismatch");
    }
    let d = rp.get("data").filter(|d| !d.is_null())?;
    let sd = sp.get("data").filter(|d| !d.is_null())?;
    let tok = |x: &Value| x.get("tokenAddress").filter(|v| !v.is_null()).map_or(String::new(), js_str).to_lowercase();
    if tok(d) != tok(sd) {
        return done("token_mismatch");
    }
    let Some(allow) = d.get("allowance").and_then(Value::as_str).filter(|a| hex_qty(a)) else { return done("amount_malformed") };
    let sent_allow = big(sd.get("allowance")?.as_str()?)?;
    if big(allow)? > sent_allow {
        return done("amount_widened");
    }
    let ra = rp.get("isAdjustmentAllowed");
    if ra != sp.get("isAdjustmentAllowed") && ra == Some(&Value::Bool(true)) {
        return done("adjustment_widened");
    }
    let Some(rules) = r.get("rules").and_then(Value::as_array) else { return done("expiry_missing") };
    let mut expiry: Option<f64> = None;
    for rule in rules {
        if rule.get("type").and_then(Value::as_str) != Some("expiry") {
            return done("unknown_rule_type");
        }
        if expiry.is_some() {
            return done("duplicate_expiry");
        }
        let ts = rule.get("data").filter(|d| !d.is_null())?.get("timestamp");
        let n = ts.and_then(Value::as_f64);
        match n {
            Some(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE && !(f == 0.0 && f.is_sign_negative()) => expiry = Some(f),
            _ => return done("expiry_malformed"),
        }
    }
    let Some(e) = expiry else { return done("expiry_missing") };
    // a grant expiry that is not a safe integer bounds nothing
    if !g.get("expiresAtSec").and_then(Value::as_f64).is_some_and(|x| x.fract() == 0.0 && x.abs() <= MAX_SAFE && e <= x) {
        return done("expiry_extended");
    }
    Some(None)
}

/// The digest a grant envelope names (`grantDigestOf`).
pub fn grant_digest_of(grant: &Value) -> Result<String, String> {
    // the strict canonical form, as the reference: -0, unsafe integers, lone surrogates and tiny magnitudes are refused
    crate::canonicalize_strict(grant)?;
    Ok(hash_canonical(grant))
}
