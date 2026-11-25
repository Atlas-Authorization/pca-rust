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
    is_adjustment_allowed: Option<&Value>,
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
    // `o.isAdjustmentAllowed ?? true`: only null / undefined default; any other value is copied through as given
    let adj = match is_adjustment_allowed {
        None | Some(Value::Null) => json!(true),
        Some(v) => v.clone(),
    };
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

/// `grantToPermissionRequest` over the options object exactly as the reference reads it (`o.chainId`, `o.sessionAccount`,
/// `o.tokenAddress`, `o.baseUnitsPerMinor`, `o.from`, `o.isAdjustmentAllowed`): every member may be any JSON value. An address is
/// tested as the string JavaScript makes of it (a one-element array reads as its element, a missing member as `undefined`), the base
/// units likewise (a number that prints as digits passes), and the members are copied into the request as they were given.
pub fn grant_to_permission_request_value(g: &Value, o: &Value) -> Result<Value, String> {
    let (cap, exp) = (safe_int(g.get("capMinor")), safe_int(g.get("expiresAtSec")));
    if !cap.is_some_and(|c| c > 0.0) || !exp.is_some_and(|e| e > 0.0) {
        return Err("grantToPermissionRequest: bad envelope".into());
    }
    let text = |v: Option<&Value>| v.map_or_else(|| "undefined".to_string(), crate::intent_v2::js_value_string);
    let (session, from, token) = (o.get("sessionAccount"), o.get("from"), o.get("tokenAddress"));
    if !hex_addr(&text(session)) || from.is_some_and(|f| !hex_addr(&text(Some(f)))) || token.is_some_and(|t| !hex_addr(&text(Some(t)))) {
        return Err("grantToPermissionRequest: bad address".into());
    }
    let units = text(o.get("baseUnitsPerMinor"));
    let dec = units == "0" || (!units.is_empty() && !units.starts_with('0') && units.bytes().all(|b| b.is_ascii_digit()));
    if !dec || o.get("baseUnitsPerMinor").and_then(Value::as_str) == Some("0") {
        return Err("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string".into());
    }
    let chain = text(o.get("chainId"));
    let chain_id = if !chain.is_empty() && chain.bytes().all(|b| b.is_ascii_digit()) { BigUint::parse_bytes(chain.as_bytes(), 10) } else { None };
    let Some(chain_id) = chain_id.filter(|c| *c != BigUint::from(0u8)) else { return Err("grantToPermissionRequest: bad chain".into()) };
    let base = BigUint::parse_bytes(units.as_bytes(), 10).ok_or("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string")?;
    let allowance = hex_of(&(BigUint::from(cap.unwrap_or(0.0) as u64) * base));
    // `o.isAdjustmentAllowed ?? true`
    let adj = match o.get("isAdjustmentAllowed") {
        None | Some(Value::Null) => json!(true),
        Some(v) => v.clone(),
    };
    let permission = match token {
        Some(t) => json!({ "type": "erc20-token-allowance", "isAdjustmentAllowed": adj, "data": { "tokenAddress": t, "allowance": allowance } }),
        None => json!({ "type": "native-token-allowance", "isAdjustmentAllowed": adj, "data": { "allowance": allowance } }),
    };
    let mut r = Map::new();
    r.insert("chainId".into(), json!(hex_of(&chain_id)));
    if let Some(f) = from {
        r.insert("from".into(), f.clone());
    }
    r.insert("to".into(), session.cloned().unwrap_or(Value::Null));
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

/// `BigInt(value)` for the sent allowance: a safe integer number, a boolean, or a string in `StringToBigInt` form (trimmed; empty is 0;
/// a decimal may be signed; `0x`, `0o` and `0b` digits are not). The pair is (negative, magnitude); `None` where `BigInt` throws.
fn big_js(v: &Value) -> Option<(bool, BigUint)> {
    match v {
        Value::Bool(b) => Some((false, BigUint::from(u8::from(*b)))),
        Value::Number(n) => {
            let f = n.as_f64()?;
            if !f.is_finite() || f.fract() != 0.0 {
                return None;
            }
            let m = BigUint::parse_bytes(format!("{:.0}", f.abs()).as_bytes(), 10)?;
            Some((f < 0.0 && m != BigUint::from(0u8), m))
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Some((false, BigUint::from(0u8)));
            }
            let radix = |p: &str, r: u32| t.strip_prefix(p).or_else(|| t.strip_prefix(&p.to_uppercase())).map(|d| (d, r));
            if let Some((d, r)) = radix("0x", 16).or_else(|| radix("0o", 8)).or_else(|| radix("0b", 2)) {
                return BigUint::parse_bytes(d.as_bytes(), r).filter(|_| !d.is_empty()).map(|m| (false, m));
            }
            let (neg, d) = match t.as_bytes()[0] {
                b'-' => (true, &t[1..]),
                b'+' => (false, &t[1..]),
                _ => (false, t),
            };
            if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let m = BigUint::parse_bytes(d.as_bytes(), 10)?;
            Some((neg && m != BigUint::from(0u8), m))
        }
        _ => None,
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
        if let Some(o) = f(ctx) {
            // reading `grantDigest` of a null grant is a TypeError
            if g.is_null() {
                return None;
            }
            if Some(o.as_str()) != g.get("grantDigest").and_then(Value::as_str) {
                return done("context_bound_to_other_grant");
            }
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
    let (sent_neg, sent_mag) = big_js(sd.get("allowance")?)?;
    if sent_neg || big(allow)? > sent_mag {
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
    if g.is_null() {
        return None; // `g.expiresAtSec` of a null grant is a TypeError
    }
    // a grant expiry that is not a safe integer bounds nothing
    if !g.get("expiresAtSec").and_then(Value::as_f64).is_some_and(|x| x.fract() == 0.0 && x.abs() <= MAX_SAFE && e <= x) {
        return done("expiry_extended");
    }
    Some(None)
}

/// The digest a grant envelope names (`grantDigestOf`).
pub fn grant_digest_of(grant: &Value) -> Result<String, String> {
    // a Rust string cannot hold a lone surrogate: the crate's stand-in (U+10FFFF) is read as one and refused, as the reference's canonicalize does
    fn lone(v: &Value) -> bool {
        match v {
            Value::String(s) => s.contains('\u{10FFFF}'),
            Value::Array(a) => a.iter().any(lone),
            Value::Object(m) => m.iter().any(|(k, x)| k.contains('\u{10FFFF}') || lone(x)),
            _ => false,
        }
    }
    if lone(grant) {
        return Err("canonicalize: lone surrogate in string".into());
    }
    // the strict canonical form, as the reference: -0, unsafe integers, lone surrogates and tiny magnitudes are refused
    crate::canonicalize_strict(grant)?;
    Ok(hash_canonical(grant))
}

#[cfg(test)]
mod verify_granted_tests {
    use super::*;

    fn request(allowance: Value) -> Value {
        json!({"chainId": "0x1", "to": "0xabababababababababababababababababababab", "permission": {"type": "native-token-allowance", "isAdjustmentAllowed": true, "data": {"allowance": allowance}}, "rules": [{"type": "expiry", "data": {"timestamp": 1800000000}}]})
    }

    fn granted() -> Value {
        let mut r = request(json!("0x1"));
        r["context"] = json!("0x1234abcd");
        r["delegationManager"] = json!("0x9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f");
        r
    }

    fn verdict(g: Value, sent_allowance: Value, owner: Option<&dyn Fn(&str) -> Option<String>>) -> Option<&'static str> {
        verify_granted_permission(&g, &request(sent_allowance), &granted(), &["0x9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"], owner)
    }

    #[test]
    fn the_sent_allowance_reads_as_bigint_does() {
        let g = json!({"grantDigest": "GD", "capMinor": 5000, "expiresAtSec": 1800000000});
        for ok in [json!("5"), json!(5), json!(" 0x10 "), json!("0b11"), json!("0o7"), json!(true), json!("+2")] {
            assert_eq!(verdict(g.clone(), ok.clone(), None), None, "{ok}");
        }
        assert_eq!(verdict(g.clone(), json!(""), None), Some("amount_widened"));
        assert_eq!(verdict(g.clone(), json!("-1"), None), Some("amount_widened"));
        for bad in [json!("1.5"), json!(1.5), json!(null), json!("-0x1"), json!("0x"), json!({}), json!([])] {
            assert_eq!(verdict(g.clone(), bad.clone(), None), Some("response_malformed"), "{bad}");
        }
    }

    #[test]
    fn a_null_grant_is_a_type_error_where_it_is_read() {
        assert_eq!(verdict(Value::Null, json!("5"), None), Some("response_malformed"));
        let owned: &dyn Fn(&str) -> Option<String> = &|_| Some("GD".to_string());
        assert_eq!(verdict(Value::Null, json!("5"), Some(owned)), Some("response_malformed"));
        // a grant that is not an object has no expiry: extended, not malformed
        assert_eq!(verdict(json!(5), json!("5"), None), Some("expiry_extended"));
    }

    #[test]
    fn a_lone_surrogate_stand_in_is_refused_by_the_digest() {
        assert_eq!(grant_digest_of(&json!({"a": "\u{10FFFF}"})), Err("canonicalize: lone surrogate in string".to_string()));
        assert_eq!(grant_digest_of(&json!({"\u{10FFFF}": 1})), Err("canonicalize: lone surrogate in string".to_string()));
        assert!(grant_digest_of(&json!({"a": "b"})).is_ok());
    }
}
