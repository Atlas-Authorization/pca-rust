//! Agentic Commerce Protocol (ACP) and x402 for PCA: delegated one-time payment tokens minted FROM a PCActn (the proof's spend
//! cap, merchant and category allowlists and human-present requirement gate issuance), their settlement-time verification, the
//! x402 v1 challenge and the injectable settle flow, x402 v2 (requirements, headers, negotiation), its HTTP transport and Stripe
//! Shared Payment Granted Tokens. No network is performed: the verifier, settler and single-use store are injected.
//!
//! JSON-valued API (reference member names, JavaScript value semantics: a missing member is `undefined`, reading a member of
//! `null` is a TypeError). `Err` is a refusal / throw with the reference's message. The single-use store is a closure
//! `claim(jti, expiresAtMs) -> Result<Value, String>` whose answer must be exactly `true` to admit a token.
use crate::actions::js_to_number;
use crate::agentcard::iso_string;
use crate::intent_v2::js_number_string;
use crate::jose::{assert_canonical_compact_jws, check_crit_b64, import_public_jwk, sign_ed25519_jws, verify_jws_signature, DEFAULT_MAX_JWS_BYTES};
use crate::oauth::{js_str, truthy};
use crate::payments::{hash_strict, isfinite, nullish, num, num_of, prop, safe_int, spread_obj, tostr};
use crate::{decode_b64u_strict, js_stringify, verify_pcactn_core_with, VerifyOptions};
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde_json::{json, Map, Value};

pub const ACP_DELEGATED_TOKEN_VERSION: i64 = 1;
pub const ACP_DELEGATED_TOKEN_TYPE: &str = "acp-delegated-payment";
pub const SPEND_CAP_CAVEAT: &str = "max_amount";
pub const MERCHANT_ALLOW_CAVEAT: &str = "merchant_allow";
pub const MERCHANT_CATEGORY_CAVEAT: &str = "merchant_category";
pub const HUMAN_PRESENT_CAVEAT: &str = "human_present";
pub const X402_VERSION_1: i64 = 1;
pub const X402_VERSION_2: i64 = 2;
pub const X402_SUPPORTED_VERSIONS: [i64; 2] = [2, 1];
pub const X402_V2_PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
pub const X402_PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";
pub const X402_PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";
pub const STRIPE_SPT_OBJECT: &str = "shared_payment.granted_token";

/// The single-use store's `claim(jti, expiresAtMs)`: the token is admitted only when the answer is exactly `true`.
pub type ClaimFn<'a> = &'a dyn Fn(&str, &Value) -> Result<Value, String>;

type V<'a> = Option<&'a Value>;

/// `X402_HTTP_STATUS` as the reference exports it.
pub fn x402_http_status() -> Value {
    json!({ "payment_required": 402, "malformed": 400, "failed": 402, "internal_error": 500, "settled": 200 })
}

// ---- JavaScript value semantics -------------------------------------------------------------------------------------------

fn is_obj(v: V) -> bool {
    matches!(v, Some(Value::Object(_)))
}

fn is_num(v: V) -> bool {
    matches!(v, Some(Value::Number(_)))
}

fn neg_zero(v: V) -> bool {
    num_of(v).is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

/// Integer minor units: floats, zero, negatives and unsafe integers are refused.
fn is_amount(v: V) -> bool {
    safe_int(v) && num_of(v).is_some_and(|f| f > 0.0)
}

fn is_int(v: V) -> bool {
    safe_int(v) && !neg_zero(v)
}

fn nz(v: V, default: Value) -> Value {
    if nullish(v) {
        default
    } else {
        v.cloned().unwrap_or(Value::Null)
    }
}

fn nonempty_str(v: V) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}

fn js_num(v: V) -> String {
    js_number_string(num_of(v).unwrap_or(f64::NAN))
}

fn jf(f: f64) -> Value {
    num(f)
}

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

/// `[...v]` of an array or string (the iterable cases of the reference).
fn elems(v: V) -> Result<Vec<Value>, String> {
    match v {
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::String(s)) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        _ => Err("value is not iterable".into()),
    }
}

/// `list.includes(v)` / `v in list` for the allowlist members (a string list is a substring test, as in the reference).
fn includes_str(list: &Value, item: &str) -> Result<bool, String> {
    match list {
        Value::Array(a) => Ok(a.iter().any(|x| x.as_str() == Some(item))),
        Value::String(s) => Ok(s.contains(item)),
        _ => Err("allowlist is not an array".into()),
    }
}

// ---- caveat vocabulary ----------------------------------------------------------------------------------------------------

pub fn spend_cap_caveat(max_amount: &Value, currency: V) -> Value {
    let mut o = Map::new();
    o.insert("type".into(), json!(SPEND_CAP_CAVEAT));
    o.insert("max".into(), max_amount.clone());
    if let Some(c) = currency {
        o.insert("currency".into(), c.clone());
    }
    Value::Object(o)
}

pub fn merchant_allow_caveat(merchants: &Value) -> Result<Value, String> {
    Ok(json!({ "type": MERCHANT_ALLOW_CAVEAT, "merchants": elems(Some(merchants))? }))
}

pub fn merchant_category_caveat(categories: &Value) -> Result<Value, String> {
    Ok(json!({ "type": MERCHANT_CATEGORY_CAVEAT, "categories": elems(Some(categories))? }))
}

/// `humanPresentCaveat(required = true)`.
pub fn human_present_caveat(required: Option<&Value>) -> Value {
    json!({ "type": HUMAN_PRESENT_CAVEAT, "required": required.cloned().unwrap_or(Value::Bool(true)) })
}

fn string_array(v: V, label: &str) -> Result<Vec<String>, String> {
    match v {
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => Ok(a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
        _ => Err(format!("malformed {label} caveat: expected a string[] (fail closed)")),
    }
}

fn dedupe(l: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in l {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// Collapse a leaf capability's cumulative caveats into its effective payment authority: the tightest cap, intersected allowlists,
/// a sticky human-present requirement. A malformed PAYMENT caveat is refused (fail closed); other caveat types are ignored.
pub fn extract_payment_authority(caveats: V) -> Result<Value, String> {
    let items = elems(caveats).map_err(|_| "caveats is not iterable".to_string())?;
    let mut max_amount: Option<Value> = None;
    let mut currency: Option<String> = None;
    let mut merchants: Option<Vec<String>> = None;
    let mut categories: Option<Vec<String>> = None;
    let mut human = false;
    for c in &items {
        let typ = prop(Some(c), "type")?.and_then(Value::as_str);
        match typ {
            Some(SPEND_CAP_CAVEAT) => {
                let mx = c.get("max");
                if !is_num(mx) || !safe_int(mx) || num_of(mx).is_some_and(|f| f < 0.0) || neg_zero(mx) {
                    return Err("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)".into());
                }
                let mx = mx.cloned().unwrap_or(Value::Null);
                max_amount = Some(match max_amount {
                    Some(prev) if num_of(Some(&mx)) < num_of(Some(&prev)) => mx,
                    Some(prev) => prev,
                    None => mx,
                });
                if let Some(cur) = c.get("currency") {
                    let Some(cs) = cur.as_str().filter(|s| !s.is_empty()) else {
                        return Err("malformed max_amount caveat: currency must be a non-empty string (fail closed)".into());
                    };
                    if let Some(prev) = &currency {
                        if prev != cs {
                            return Err(format!("conflicting spend-cap currencies \"{prev}\" vs \"{cs}\" (fail closed)"));
                        }
                    }
                    currency = Some(cs.to_string());
                }
            }
            Some(MERCHANT_ALLOW_CAVEAT) => {
                let lst = string_array(c.get("merchants"), "merchant_allow")?;
                merchants = Some(match merchants {
                    None => dedupe(lst),
                    Some(m) => m.into_iter().filter(|x| lst.contains(x)).collect(),
                });
            }
            Some(MERCHANT_CATEGORY_CAVEAT) => {
                let lst = string_array(c.get("categories"), "merchant_category")?;
                categories = Some(match categories {
                    None => dedupe(lst),
                    Some(m) => m.into_iter().filter(|x| lst.contains(x)).collect(),
                });
            }
            Some(HUMAN_PRESENT_CAVEAT) => match c.get("required") {
                Some(Value::Bool(b)) => human = human || *b,
                _ => return Err("malformed human_present caveat: required must be a boolean (fail closed)".into()),
            },
            _ => {}
        }
    }
    let mut out = Map::new();
    if let Some(m) = max_amount {
        out.insert("maxAmount".into(), m);
    }
    if let Some(c) = currency {
        out.insert("currency".into(), Value::String(c));
    }
    out.insert("merchants".into(), merchants.map_or(Value::Null, |m| json!(m)));
    out.insert("categories".into(), categories.map_or(Value::Null, |m| json!(m)));
    out.insert("humanPresentRequired".into(), Value::Bool(human));
    Ok(Value::Object(out))
}

fn refuse(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

/// Check a concrete purchase request against a payment authority. Pure and fail-closed.
pub fn check_payment_authority(authority: &Value, request: &Value) -> Result<Value, String> {
    let (amount, currency, merchant) = (prop(Some(request), "amount")?, prop(Some(request), "currency")?, prop(Some(request), "merchant")?);
    if !is_amount(amount) {
        return Ok(refuse("amount must be a positive integer in minor units"));
    }
    let Some(currency) = currency.and_then(Value::as_str).filter(|s| !s.is_empty()) else { return Ok(refuse("currency must be a non-empty string")) };
    let Some(merchant) = merchant.and_then(Value::as_str).filter(|s| !s.is_empty()) else { return Ok(refuse("merchant must be a non-empty string")) };
    let a_cur = prop(Some(authority), "currency")?;
    if a_cur.is_some() && a_cur.and_then(Value::as_str) != Some(currency) {
        return Ok(refuse(&format!("currency \"{currency}\" is not the authorized currency \"{}\"", tostr(a_cur))));
    }
    let cap = prop(Some(authority), "maxAmount")?;
    if cap.is_some() && !(is_int(cap) && num_of(cap).is_some_and(|f| f >= 0.0)) {
        return Ok(refuse("authorized spend cap is not a non-negative integer (fail closed)"));
    }
    if cap.is_some() && !(num_of(amount).unwrap_or(f64::NAN) <= js_to_number(cap)) {
        return Ok(refuse(&format!("amount {} exceeds the authorized spend cap {}", js_num(amount), tostr(cap))));
    }
    let merchants = prop(Some(authority), "merchants")?.filter(|m| !m.is_null());
    if let Some(m) = merchants {
        if !includes_str(m, merchant)? {
            return Ok(refuse(&format!("merchant \"{merchant}\" is not in the authorized allowlist")));
        }
    }
    let categories = prop(Some(authority), "categories")?.filter(|m| !m.is_null());
    if let Some(cats) = categories {
        let Some(category) = prop(Some(request), "category")? else {
            return Ok(refuse("the proof constrains merchant categories but no category was supplied"));
        };
        if !elems(Some(cats))?.iter().any(|x| matches!((x, category), (Value::String(a), Value::String(b)) if a == b)) {
            return Ok(refuse(&format!("category \"{}\" is not in the authorized allowlist", tostr(Some(category)))));
        }
    }
    if truthy(prop(Some(authority), "humanPresentRequired")?) && prop(Some(request), "humanPresent")? != Some(&Value::Bool(true)) {
        return Ok(refuse("the proof requires a human-present charge but humanPresent was not asserted"));
    }
    Ok(json!({ "ok": true }))
}

// ---- delegated payment token ----------------------------------------------------------------------------------------------

fn leaf_capability(pca: &Value) -> Result<&Value, String> {
    match prop(Some(pca), "cap_chain")? {
        Some(Value::Array(c)) if !c.is_empty() => Ok(&c[c.len() - 1]),
        _ => Err("PCActn carries no capability chain (fail closed)".into()),
    }
}

fn authority_ref(pca: &Value) -> Result<Map<String, Value>, String> {
    let leaf = leaf_capability(pca)?;
    let action = prop(Some(pca), "action")?;
    let digest = hash_strict(Some(pca))?;
    let mut out = Map::new();
    out.insert("digest".into(), Value::String(digest));
    for (k, v) in [
        ("aud", prop(Some(pca), "aud")?),
        ("grant_ref", prop(Some(pca), "grant_ref")?),
        ("leaf_holder", prop(Some(leaf), "holder")?),
        ("verb", prop(action, "verb")?),
        ("resource", prop(action, "resource")?),
        ("params_digest", prop(action, "params_digest")?),
    ] {
        if let Some(v) = v {
            out.insert(k.into(), v.clone());
        }
    }
    Ok(out)
}

fn seed_of_jwk(k: &Value) -> Option<[u8; 32]> {
    let o = k.as_object()?;
    if o.get("kty")?.as_str()? != "OKP" || o.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    decode_b64u_strict(o.get("d")?.as_str()?, Some(32))?.try_into().ok()
}

/// Mint a one-time ACP delegated payment token (a compact EdDSA JWS) FROM a PCActn, bound to session, merchant, amount, currency
/// and expiry, carrying the proof's authority BY REFERENCE (`pca.digest`). The proof's caveats gate issuance; an over-authority
/// request, an expiry in the past or one that would outlive the proof is refused. `opts`: `amount`, `currency`, `merchant`,
/// `session`, `expiresAt`, `paymentMethod`, `signingKey` (a private Ed25519 OKP JWK), `alg`, `category`, `humanPresent`, `issuer`, `kid`,
/// `jti`, `now`. shortcut: only EdDSA over an Ed25519 JWK signs (the reference also signs ES256/384/512 and RSA); other algs are refused.
pub fn mint_delegated_payment_token(pca: &Value, opts: &Value) -> Result<String, String> {
    let now_o = prop(Some(opts), "now")?;
    let now_v = if isfinite(now_o) { now_o.cloned().unwrap_or(Value::Null) } else { jf(now_ms()) };
    let now = num_of(Some(&now_v)).unwrap_or(f64::NAN);
    let authority = extract_payment_authority(prop(Some(leaf_capability(pca)?), "caveats")?)?;
    let mut req = Map::new();
    for k in ["amount", "currency", "merchant"] {
        if let Some(v) = prop(Some(opts), k)? {
            req.insert(k.into(), v.clone());
        }
    }
    for k in ["category", "humanPresent"] {
        if let Some(v) = prop(Some(opts), k)? {
            req.insert(k.into(), v.clone());
        }
    }
    let check = check_payment_authority(&authority, &Value::Object(req))?;
    if check["ok"] != Value::Bool(true) {
        let why = check.get("reason").filter(|r| truthy(Some(*r))).map_or("request exceeds the proof authority".to_string(), js_str);
        return Err(format!("refused: {why}"));
    }
    let exp_at = prop(Some(opts), "expiresAt")?;
    if !isfinite(exp_at) {
        return Err("refused: expiresAt must be a finite epoch-ms timestamp".into());
    }
    let exp_f = num_of(exp_at).unwrap_or(f64::NAN);
    if !(exp_f > now) {
        return Err("refused: expiresAt is not in the future".into());
    }
    let pexp = prop(Some(pca), "exp")?;
    if !(js_to_number(pexp).is_finite() && exp_f <= js_to_number(pexp)) {
        return Err(format!("refused: token expiry {} would outlive the proof's exp {}", js_num(exp_at), tostr(pexp)));
    }
    let session = prop(Some(opts), "session")?;
    if !truthy(session) {
        return Err("refused: a session id is required".into());
    }
    let mut aref = authority_ref(pca)?;
    let jti = match prop(Some(opts), "jti")? {
        Some(j) if !j.is_null() => j.clone(),
        _ => {
            let digest = aref["digest"].as_str().unwrap_or("").to_string();
            let nonce = format!(
                "acp:{}:{}:{}:{}:{}:{}",
                tostr(session),
                tostr(prop(Some(opts), "merchant")?),
                tostr(prop(Some(opts), "amount")?),
                tostr(prop(Some(opts), "currency")?),
                tostr(exp_at),
                digest
            );
            let mut seed = match pca {
                Value::Object(m) => m.clone(),
                _ => Map::new(),
            };
            seed.insert("nonce".into(), Value::String(nonce));
            Value::String(hash_strict(Some(&Value::Object(seed)))?)
        }
    };
    let mut claims = Map::new();
    claims.insert("typ".into(), json!(ACP_DELEGATED_TOKEN_TYPE));
    claims.insert("ver".into(), json!(ACP_DELEGATED_TOKEN_VERSION));
    claims.insert("jti".into(), jti);
    for (k, src) in [("session", "session"), ("merchant", "merchant"), ("amount", "amount"), ("currency", "currency")] {
        if let Some(v) = prop(Some(opts), src)? {
            claims.insert(k.into(), v.clone());
        }
    }
    claims.insert("iat".into(), now_v);
    claims.insert("exp".into(), exp_at.cloned().unwrap_or(Value::Null));
    claims.insert("paymentMethod".into(), Value::Object(spread_obj(prop(Some(opts), "paymentMethod")?)));
    claims.insert("humanPresent".into(), Value::Bool(prop(Some(opts), "humanPresent")? == Some(&Value::Bool(true))));
    if let Some(c) = prop(Some(opts), "category")? {
        claims.insert("category".into(), c.clone());
    }
    if let Some(i) = prop(Some(opts), "issuer")? {
        claims.insert("iss".into(), i.clone());
    }
    claims.insert("pca".into(), Value::Object(std::mem::take(&mut aref)));
    let alg = match prop(Some(opts), "alg")? {
        Some(Value::String(a)) => a.clone(),
        None | Some(Value::Null) => "EdDSA".to_string(),
        Some(_) => return Err("Invalid alg: not a string".into()),
    };
    if alg != "EdDSA" {
        return Err(format!("Unsupported alg \"{alg}\" for this signing key"));
    }
    let seed = prop(Some(opts), "signingKey")?.and_then(seed_of_jwk).ok_or("Invalid key for this operation: EdDSA needs an Ed25519 private key")?;
    let mut header = Map::new();
    header.insert("alg".into(), json!(alg));
    header.insert("typ".into(), json!(ACP_DELEGATED_TOKEN_TYPE));
    if let Some(k) = prop(Some(opts), "kid")? {
        header.insert("kid".into(), k.clone());
    }
    Ok(sign_ed25519_jws(&Value::Object(header), &Value::Object(claims), &seed))
}

fn parse_claims(payload: &Map<String, Value>) -> bool {
    let g = |k: &str| payload.get(k);
    if g("typ").and_then(Value::as_str) != Some(ACP_DELEGATED_TOKEN_TYPE) || !is_num(g("ver")) || num_of(g("ver")) != Some(ACP_DELEGATED_TOKEN_VERSION as f64) {
        return false;
    }
    if !nonempty_str(g("jti"))
        || !nonempty_str(g("session"))
        || !nonempty_str(g("merchant"))
        || !is_amount(g("amount"))
        || !nonempty_str(g("currency"))
        || !isfinite(g("iat"))
        || !isfinite(g("exp"))
        || !matches!(g("humanPresent"), Some(Value::Bool(_)))
    {
        return false;
    }
    if !matches!(g("paymentMethod"), Some(Value::Object(pm)) if pm.get("type").is_some_and(Value::is_string)) {
        return false;
    }
    let Some(Value::Object(p)) = g("pca") else { return false };
    ["digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest"].iter().all(|k| p.get(*k).is_some_and(Value::is_string))
}

/// The key a JWK imports as: private members are dropped (importJWK verifies with the derived public key).
fn verify_key_of(vk: V, alg: &str) -> Result<crate::jose::JwkKey, String> {
    let Some(Value::Object(m)) = vk.filter(|k| k.get("kty").is_some()) else { return Err("Invalid key for this operation".into()) };
    let mut pubm = m.clone();
    for k in ["d", "p", "q", "dp", "dq", "qi"] {
        pubm.remove(k);
    }
    import_public_jwk(&Value::Object(pubm), alg)
}

/// jose `compactVerify` after the canonical gate: header rules, the allowed algorithm, the signature. Returns the claims.
fn compact_verify(token: &Value, opts: &Value, alg: &str) -> Result<Option<Map<String, Value>>, String> {
    let jws = assert_canonical_compact_jws(token, 3, DEFAULT_MAX_JWS_BYTES, true)?;
    let key = verify_key_of(prop(Some(opts), "verifyKey")?, alg);
    let b64 = check_crit_b64(&jws.header)?;
    let halg = jws.header.get("alg").and_then(Value::as_str).filter(|a| !a.is_empty()).ok_or("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")?;
    if halg != alg {
        return Err("\"alg\" (Algorithm) Header Parameter value not allowed".into());
    }
    let key = key?;
    let input = format!("{}.{}", jws.segments[0], jws.segments[1]);
    if !verify_jws_signature(alg, &key, input.as_bytes(), &jws.bytes[2]) {
        return Err("signature verification failed".into());
    }
    // an unencoded payload (RFC 7797) is the raw segment text, which is never a JSON object in the canonical profile
    Ok(if b64 { jws.payload } else { None })
}

fn verify_binding(token: &Value, opts: &Value) -> Result<Value, String> {
    let alg_v = prop(Some(opts), "alg")?;
    let alg = if nullish(alg_v) { Some("EdDSA") } else { alg_v.and_then(Value::as_str) };
    let now_o = prop(Some(opts), "now")?;
    let now = if isfinite(now_o) { num_of(now_o).unwrap_or(0.0) } else { now_ms() };
    let verified = match alg {
        Some(a) => compact_verify(token, opts, a),
        None => Err("\"algorithms\" option must be an array of strings".to_string()),
    };
    let claims = match verified {
        Err(e) => return Ok(refuse(&format!("token signature did not verify: {e}"))),
        Ok(None) => return Ok(refuse("token payload is not a well-formed delegated payment token")),
        Ok(Some(c)) if !parse_claims(&c) => return Ok(refuse("token payload is not a well-formed delegated payment token")),
        Ok(Some(c)) => c,
    };
    let cv = Value::Object(claims.clone());
    let fail = |reason: String| -> Result<Value, String> { Ok(json!({ "ok": false, "reason": reason, "claims": cv })) };
    let cs = |k: &str| claims.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let em = prop(Some(opts), "expectedMerchant")?;
    if em.and_then(Value::as_str) != Some(cs("merchant").as_str()) {
        return fail(format!("token merchant \"{}\" does not match expected \"{}\"", cs("merchant"), tostr(em)));
    }
    let amount = prop(Some(opts), "amount")?;
    if !is_amount(amount) {
        return fail("settlement amount must be a positive integer in minor units".into());
    }
    if !matches!((num_of(amount), num_of(claims.get("amount"))), (Some(a), Some(c)) if a <= c) {
        return fail(format!("settlement amount {} exceeds the token's authorized amount {}", js_num(amount), js_num(claims.get("amount"))));
    }
    if !(now <= num_of(claims.get("exp")).unwrap_or(f64::NAN)) {
        return fail("the delegated payment token has expired".into());
    }
    let es = prop(Some(opts), "expectedSession")?;
    if es.is_some() && es.and_then(Value::as_str) != Some(cs("session").as_str()) {
        return fail(format!("token session \"{}\" does not match expected \"{}\"", cs("session"), tostr(es)));
    }
    let ec = prop(Some(opts), "expectedCurrency")?;
    if ec.is_some() && ec.and_then(Value::as_str) != Some(cs("currency").as_str()) {
        return fail(format!("token currency \"{}\" does not match expected \"{}\"", cs("currency"), tostr(ec)));
    }
    let (grant, pca) = (prop(Some(opts), "grant")?, prop(Some(opts), "pcActn")?);
    if grant.is_some() && pca.is_none() {
        return fail("a grant was supplied without the pcActn to re-verify (fail closed)".into());
    }
    let Some(pca) = pca else { return Ok(json!({ "ok": true, "claims": cv })) };
    let digest = hash_strict(Some(pca))?;
    let want = claims.get("pca").and_then(|p| p.get("digest")).and_then(Value::as_str).unwrap_or("");
    if digest != want {
        return fail("pcactn_digest mismatch: the supplied proof is not the one that minted this token".into());
    }
    let Some(grant) = grant else { return Ok(json!({ "ok": true, "claims": cv })) };
    // shortcut: a missing / non-string audience is refused here (the Rust core always checks `aud`)
    let Some(audience) = prop(Some(opts), "audience")?.and_then(Value::as_str) else {
        return Ok(
            json!({ "ok": false, "reason": "bound proof failed to verify: audience is required (fail closed)", "claims": cv, "pcaResult": { "allow": false } }),
        );
    };
    let roots: Option<Vec<String>> = prop(Some(opts), "authorizedPlanRoots")?.map(|r| match r {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => Vec::new(), // a non-list authorizes nothing: the plan-root check fails
    });
    let vopts = VerifyOptions {
        authorized_plan_roots: roots.as_deref(),
        insecure_skip_plan_root_check: prop(Some(opts), "insecureSkipPlanRootCheck")? == Some(&Value::Bool(true)),
        ..VerifyOptions::default()
    };
    let v = verify_pcactn_core_with(pca, grant, now as i64, audience, &vopts);
    let result = json!({ "allow": v.allow, "checks": v.checks, "reason": v.reason });
    if !v.allow {
        let why = if v.reason.is_empty() { "denied".to_string() } else { v.reason.clone() };
        return Ok(json!({ "ok": false, "reason": format!("bound proof failed to verify: {why}"), "claims": cv, "pcaResult": result }));
    }
    Ok(json!({ "ok": true, "claims": cv, "pcaResult": result }))
}

/// Verify a delegated payment token at settlement: the signature, then merchant, amount, expiry, session and currency bindings and,
/// with a `pcActn`, the proof's digest (end to end with a `grant`). Strict by default: a single-use store and an `expectedCurrency`
/// are required, and after every other check the token's `jti` is claimed once. Fails CLOSED on every mismatch, an already redeemed
/// token or an unavailable store. `store` is the callable `singleUse.claim`; `opts.singleUse`, when present without a store, is a
/// value that is not a store (strict refuses it, non-strict reports the store unavailable).
pub fn verify_delegated_payment_token(token: &Value, opts: &Value, store: Option<ClaimFn>) -> Result<Value, String> {
    let su = prop(Some(opts), "singleUse")?;
    let has_su = su.is_some() || store.is_some();
    if prop(Some(opts), "strict")? != Some(&Value::Bool(false)) {
        if store.is_none() {
            return Ok(refuse("strict settlement requires a singleUse store (fail closed)"));
        }
        if !nonempty_str(prop(Some(opts), "expectedCurrency")?) {
            return Ok(refuse("strict settlement requires expectedCurrency (fail closed)"));
        }
    }
    let res = verify_binding(token, opts)?;
    if res["ok"] != Value::Bool(true) || !has_su {
        return Ok(res);
    }
    let claims = res["claims"].clone();
    let jti = claims["jti"].as_str().unwrap_or("");
    let first = match store.map(|claim| claim(jti, &claims["exp"])) {
        Some(Ok(Value::Bool(true))) => true,
        Some(Ok(_)) => false,
        _ => return Ok(json!({ "ok": false, "reason": "single-use store unavailable (fail closed)", "claims": claims })),
    };
    if first {
        Ok(res)
    } else {
        Ok(json!({ "ok": false, "reason": "the delegated payment token was already redeemed", "claims": claims }))
    }
}

// ---- x402 v1 --------------------------------------------------------------------------------------------------------------

/// The HTTP 402 challenge for a protected resource (x402 v1 `accepts` entry and body). Anything the v1 wire would make invalid is
/// refused (a non-positive-integer amount, no payTo or asset, a bad timeout).
pub fn x402_challenge(resource: &Value, opts: &Value) -> Result<Value, String> {
    let amount = prop(Some(opts), "amount")?;
    if !is_amount(amount) {
        return Err("x402Challenge: amount must be a positive integer in atomic/minor units".into());
    }
    let (pay_to, currency) = (prop(Some(opts), "payTo")?, prop(Some(opts), "currency")?);
    if !nonempty_str(pay_to) {
        return Err("x402Challenge: payTo is required".into());
    }
    if !nonempty_str(currency) {
        return Err("x402Challenge: currency (the x402 asset) is required".into());
    }
    let timeout = nz(prop(Some(opts), "maxTimeoutSeconds")?, json!(60));
    if !safe_int(Some(&timeout)) || num_of(Some(&timeout)).is_some_and(|t| t <= 0.0) {
        return Err("x402Challenge: maxTimeoutSeconds must be a positive integer".into());
    }
    let requirement = json!({
        "maxTimeoutSeconds": timeout,
        "scheme": nz(prop(Some(opts), "scheme")?, json!("exact")),
        "network": nz(prop(Some(opts), "network")?, json!("base-sepolia")),
        "maxAmountRequired": js_num(amount),
        "resource": resource,
        "description": nz(prop(Some(opts), "description")?, Value::String(format!("Payment required for {}", js_str(resource)))),
        "payTo": pay_to,
        "asset": currency,
        "mimeType": nz(prop(Some(opts), "mimeType")?, json!("application/json")),
    });
    Ok(json!({
        "status": 402,
        "headers": { "Content-Type": "application/json" },
        "body": { "x402Version": 1, "error": nz(prop(Some(opts), "error")?, json!("X-PAYMENT header is required")), "accepts": [requirement] },
    }))
}

/// Gate an x402 settlement on a verified, PCActn-bound payment. `verify` (payload -> `{ok, reason?, claims?}`) is required; on a
/// refusal the answer is a fresh 402 (fail closed), otherwise the optional `settle` step (payload, claims -> receipt) runs and its
/// `Some` return value becomes the receipt. A throwing verifier or settler is an `Err`.
pub fn x402_settle(
    payload: &Value,
    verify: &dyn Fn(&Value) -> Result<Value, String>,
    settle: Option<&dyn Fn(&Value, &Value) -> Result<Option<Value>, String>>,
) -> Result<Value, String> {
    let norm = normalize_x402_payload(payload);
    if norm["ok"] != Value::Bool(true) {
        return Ok(json!({ "settled": false, "status": 402, "reason": norm["reason"] }));
    }
    let v = verify(payload)?;
    if !truthy(prop(Some(&v), "ok")?) {
        let mut out = Map::new();
        out.insert("settled".into(), json!(false));
        out.insert("status".into(), json!(402));
        out.insert("reason".into(), nz(v.get("reason"), json!("payment verification failed")));
        if truthy(v.get("claims")) {
            out.insert("claims".into(), v["claims"].clone());
        }
        return Ok(Value::Object(out));
    }
    let Some(claims) = v.get("claims") else {
        return Ok(json!({ "settled": false, "status": 402, "reason": "verifier admitted the payment but returned no claims (fail closed)" }));
    };
    let receipt = match settle {
        Some(s) => s(payload, claims)?,
        None => None,
    };
    let mut out = Map::new();
    out.insert("settled".into(), json!(true));
    out.insert("status".into(), json!(200));
    out.insert("claims".into(), claims.clone());
    if let Some(r) = receipt {
        out.insert("receipt".into(), r);
    }
    Ok(Value::Object(out))
}

/// Adapt [`verify_delegated_payment_token`] into the `verify` step of [`x402_settle`]: it reads the token from the payload of either
/// version and verifies its binding and bound proof. Strict by default: `expectedMerchant` and `amount` must come from the server
/// (the payload's own are never read) and a store and currency are required.
pub fn acp_x402_verify(payload: &Value, opts: &Value, store: Option<ClaimFn>) -> Result<Value, String> {
    let norm = normalize_x402_payload(payload);
    if norm["ok"] != Value::Bool(true) {
        return Ok(json!({ "ok": false, "reason": norm["reason"] }));
    }
    let offered = prop(Some(opts), "offered")?;
    if norm["version"] == json!(2) {
        if let Some(o) = offered {
            if !x402_accepted_matches(o, &norm["accepted"])? {
                return Ok(refuse("x402 v2 payload.accepted is not one of the requirements this server offered"));
            }
        }
    }
    let (em, amt) = (prop(Some(opts), "expectedMerchant")?, prop(Some(opts), "amount")?);
    if prop(Some(opts), "strict")? != Some(&Value::Bool(false)) && (em.is_none() || amt.is_none()) {
        return Ok(refuse("strict settlement requires the server to supply expectedMerchant and amount (fail closed)"));
    }
    let merchant = nz(em, norm.get("merchant").cloned().unwrap_or(Value::Null));
    if !nonempty_str(Some(&merchant)) {
        return Ok(refuse("x402 payload has no merchant to check the token against"));
    }
    let amount = match amt {
        Some(a) if !a.is_null() => a.clone(),
        _ => norm.get("amount").cloned().unwrap_or(Value::Null),
    };
    if !is_amount(Some(&amount)) {
        return Ok(refuse("x402 payload has no amount to check the token against"));
    }
    let mut o2 = Map::new();
    o2.insert("expectedMerchant".into(), merchant);
    o2.insert("amount".into(), amount);
    for k in [
        "verifyKey",
        "alg",
        "now",
        "expectedSession",
        "expectedCurrency",
        "pcActn",
        "grant",
        "audience",
        "authorizedPlanRoots",
        "insecureSkipPlanRootCheck",
        "singleUse",
        "strict",
    ] {
        if let Some(v) = prop(Some(opts), k)? {
            o2.insert(k.into(), v.clone());
        }
    }
    let res = verify_delegated_payment_token(&norm["token"], &Value::Object(o2), store)?;
    let mut out = Map::new();
    out.insert("ok".into(), res["ok"].clone());
    if let Some(r) = res.get("reason").filter(|r| !r.is_null()) {
        out.insert("reason".into(), r.clone());
    }
    if truthy(res.get("claims")) {
        out.insert("claims".into(), res["claims"].clone());
    }
    Ok(Value::Object(out))
}

/// Map VERIFIED token claims to the ACP delegate_payment `allowance`; refused when a claim cannot be expressed in the ACP shape
/// (currency not three letters, merchant over 256 characters, expiry not a date).
pub fn to_acp_allowance(claims: &Value) -> Result<Value, String> {
    if !is_amount(prop(Some(claims), "amount")?) {
        return Err("allowance: amount must be a positive integer in minor units".into());
    }
    let currency = claims.get("currency").and_then(Value::as_str).map(str::to_lowercase).unwrap_or_default();
    if !(currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_lowercase())) {
        return Err("allowance: currency must be a three-letter ISO-4217 code".into());
    }
    let merchant = claims.get("merchant").and_then(Value::as_str).filter(|m| !m.is_empty() && u16len(m) <= 256);
    let Some(merchant) = merchant else { return Err("allowance: merchant_id must be 1 to 256 characters".into()) };
    let Some(session) = claims.get("session").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Err("allowance: checkout_session_id is required".into());
    };
    let exp = claims.get("exp");
    if !isfinite(exp) {
        return Err("allowance: expiry is not a valid time".into());
    }
    let at = iso_string(num_of(exp).unwrap_or(f64::NAN)).ok_or("allowance: expiry is not a valid time")?;
    Ok(
        json!({ "reason": "one_time", "max_amount": claims["amount"], "currency": currency, "checkout_session_id": session, "merchant_id": merchant, "expires_at": at }),
    )
}

// ---- x402 v2 --------------------------------------------------------------------------------------------------------------

fn is_caip2(s: &str) -> bool {
    let Some((ns, r)) = s.split_once(':') else { return false };
    (3..=8).contains(&ns.len())
        && ns.bytes().all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit())
        && (1..=32).contains(&r.len())
        && r.bytes().all(|b| b == b'-' || b == b'_' || b.is_ascii_alphanumeric())
}

fn is_atomic(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn is_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn absolute_http(u: V) -> bool {
    u.and_then(Value::as_str).and_then(|s| url::Url::parse(s).ok()).is_some_and(|p| matches!(p.scheme(), "http" | "https"))
}

fn str_is(v: V) -> bool {
    matches!(v, Some(Value::String(_)))
}

/// Problems with a `ResourceInfo` (empty = valid).
pub fn resource_info_problems(r: V) -> Vec<String> {
    let Some(Value::Object(r)) = r else { return vec!["resource must be an object".into()] };
    let mut p = Vec::new();
    if !absolute_http(r.get("url")) {
        p.push("resource.url must be an absolute http(s) URL".to_string());
    }
    for k in ["description", "mimeType"] {
        if r.contains_key(k) && !str_is(r.get(k)) {
            p.push(format!("resource.{k} must be a string"));
        }
    }
    let printable32 = |v: &Value| v.as_str().is_some_and(|s| u16len(s) <= 32 && is_printable(s));
    if r.get("serviceName").is_some_and(|sn| !printable32(sn)) {
        p.push("resource.serviceName must be printable ASCII up to 32 characters".into());
    }
    if r.get("tags").is_some_and(|t| !matches!(t, Value::Array(a) if a.len() <= 5 && a.iter().all(printable32))) {
        p.push("resource.tags must be up to 5 printable ASCII strings of up to 32 characters".into());
    }
    if let Some(icon) = r.get("iconUrl") {
        if !(absolute_http(Some(icon)) && icon.as_str().is_some_and(|s| u16len(s) <= 2048)) {
            p.push("resource.iconUrl must be an absolute http(s) URL up to 2048 characters".into());
        }
    }
    p
}

/// Problems with one v2 `PaymentRequirements` (empty = valid).
pub fn requirement_v2_problems(q: V) -> Vec<String> {
    let Some(Value::Object(q)) = q else { return vec!["requirements must be an object".into()] };
    let mut p = Vec::new();
    if !nonempty_str(q.get("scheme")) {
        p.push("scheme is required".to_string());
    }
    if !q.get("network").and_then(Value::as_str).is_some_and(is_caip2) {
        p.push("network must be a CAIP-2 identifier".into());
    }
    if !q.get("amount").and_then(Value::as_str).is_some_and(|a| is_atomic(a) && a != "0") {
        p.push("amount must be a positive decimal string of atomic units".into());
    }
    if !nonempty_str(q.get("asset")) {
        p.push("asset is required".into());
    }
    if !nonempty_str(q.get("payTo")) {
        p.push("payTo is required".into());
    }
    let t = q.get("maxTimeoutSeconds");
    if !is_num(t) || !safe_int(t) || num_of(t).is_some_and(|f| f <= 0.0) {
        p.push("maxTimeoutSeconds must be a positive integer".into());
    }
    if q.contains_key("extra") && !is_obj(q.get("extra")) {
        p.push("extra must be an object".into());
    }
    p
}

/// Problems with a v2 `PaymentRequired` (empty = valid).
pub fn payment_required_v2_problems(pr: V) -> Vec<String> {
    let Some(Value::Object(pr)) = pr else { return vec!["PaymentRequired must be an object".into()] };
    let mut p = Vec::new();
    if num_of(pr.get("x402Version")) != Some(2.0) {
        p.push("x402Version must be 2".to_string());
    }
    if pr.contains_key("error") && !str_is(pr.get("error")) {
        p.push("error must be a string".into());
    }
    p.extend(resource_info_problems(pr.get("resource")));
    match pr.get("accepts") {
        Some(Value::Array(acc)) if !acc.is_empty() => {
            for (i, q) in acc.iter().enumerate() {
                p.extend(requirement_v2_problems(Some(q)).into_iter().map(|m| format!("accepts[{i}].{m}")));
            }
        }
        _ => p.push("accepts must be a non-empty array".into()),
    }
    if let Some(ex) = pr.get("extensions") {
        match ex {
            Value::Object(m) => {
                for (k, v) in m {
                    if !is_obj(Some(v)) || !is_obj(v.get("info")) || !is_obj(v.get("schema")) {
                        p.push(format!("extensions.{k} needs info and schema objects"));
                    }
                }
            }
            _ => p.push("extensions must be an object".into()),
        }
    }
    p
}

fn b64_encode(obj: &Value) -> String {
    STANDARD.encode(js_stringify(obj).as_bytes())
}

/// Decode a header value like Node's `Buffer.from(v, 'base64')` behind the shape gate, then `JSON.parse` it.
fn b64_decode(value: V, name: &str) -> Result<Value, String> {
    let gated = value.and_then(Value::as_str).filter(|s| {
        let t = s.trim_end_matches('=');
        s.len() - t.len() <= 2 && !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    });
    let Some(s) = gated else { return Err(format!("x402: {name} is not base64")) };
    let mut t = s.trim_end_matches('=');
    if t.len() % 4 == 1 {
        t = &t[..t.len() - 1];
    }
    let lenient = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let bytes = lenient.decode(t).map_err(|_| format!("x402: {name} is not JSON"))?;
    serde_json::from_str(&String::from_utf8_lossy(&bytes)).map_err(|_| format!("x402: {name} is not JSON"))
}

fn problems_err(p: &[String]) -> String {
    format!("x402: {}", p.join("; "))
}

/// Encode a `PaymentRequired` for the `PAYMENT-REQUIRED` header (validates first).
pub fn encode_payment_required_header(pr: &Value) -> Result<String, String> {
    let p = payment_required_v2_problems(Some(pr));
    if p.is_empty() {
        Ok(b64_encode(pr))
    } else {
        Err(problems_err(&p))
    }
}

/// Decode and validate a `PAYMENT-REQUIRED` header value.
pub fn decode_payment_required_header(value: V) -> Result<Value, String> {
    let doc = b64_decode(value, "PAYMENT-REQUIRED")?;
    let p = payment_required_v2_problems(Some(&doc));
    if p.is_empty() {
        Ok(doc)
    } else {
        Err(problems_err(&p))
    }
}

/// The v2 402 challenge: JSON body plus the base64 `PAYMENT-REQUIRED` header; refuses anything the v2 spec makes invalid.
pub fn x402_challenge_v2(resource: V, opts: &Value) -> Result<Value, String> {
    let amount = prop(Some(opts), "amount")?;
    if !is_num(amount) || !safe_int(amount) || num_of(amount).is_some_and(|a| a <= 0.0) {
        return Err("x402Challenge: amount must be a positive integer in atomic units".into());
    }
    let info = match resource {
        Some(Value::String(u)) => json!({ "url": u }),
        r => Value::Object(spread_obj(r)),
    };
    let mut req = Map::new();
    req.insert("scheme".into(), nz(prop(Some(opts), "scheme")?, json!("exact")));
    if let Some(n) = prop(Some(opts), "network")? {
        req.insert("network".into(), n.clone());
    }
    req.insert("amount".into(), Value::String(js_num(amount)));
    for k in ["asset", "payTo"] {
        if let Some(v) = prop(Some(opts), k)? {
            req.insert(k.into(), v.clone());
        }
    }
    req.insert("maxTimeoutSeconds".into(), nz(prop(Some(opts), "maxTimeoutSeconds")?, json!(60)));
    if let Some(e) = prop(Some(opts), "extra")? {
        req.insert("extra".into(), e.clone());
    }
    let mut body = Map::new();
    body.insert("x402Version".into(), json!(2));
    body.insert("error".into(), nz(prop(Some(opts), "error")?, json!("PAYMENT-SIGNATURE header is required")));
    body.insert("resource".into(), info);
    body.insert("accepts".into(), json!([Value::Object(req)]));
    if let Some(e) = prop(Some(opts), "extensions")? {
        body.insert("extensions".into(), e.clone());
    }
    let body = Value::Object(body);
    let header = encode_payment_required_header(&body)?;
    Ok(json!({ "status": 402, "headers": { "Content-Type": "application/json", "PAYMENT-REQUIRED": header }, "body": body }))
}

/// The highest x402 version both sides speak, or `null` (answer 402 v1 with an error, never guess). `offered` is what the client
/// says it speaks (`None`, i.e. omitted, or empty means `[1]`; a `null` is refused, as the reference throws). `supported` defaults to
/// `[2, 1]`.
pub fn x402_negotiate(offered: V, supported: V) -> Result<Value, String> {
    let sup: Vec<Value> = match supported {
        None => X402_SUPPORTED_VERSIONS.iter().map(|v| json!(v)).collect(),
        s => elems(s)?,
    };
    let mut mine: Vec<i64> = sup.iter().filter_map(|v| num_of(Some(v))).filter(|f| *f == 1.0 || *f == 2.0).map(|f| f as i64).collect();
    if matches!(offered, Some(Value::Null)) {
        return Err("Cannot read properties of null (reading 'length')".into());
    }
    let theirs: Vec<Value> = match offered {
        None => vec![json!(1)],
        Some(o) => {
            let l = elems(Some(o))?;
            if l.is_empty() {
                vec![json!(1)]
            } else {
                l
            }
        }
    };
    mine.sort_unstable_by(|a, b| b.cmp(a));
    Ok(mine.into_iter().find(|v| theirs.iter().any(|x| num_of(Some(x)) == Some(*v as f64))).map_or(Value::Null, |v| json!(v)))
}

fn stable(v: &Value) -> String {
    match v {
        Value::Array(a) => format!("[{}]", a.iter().map(stable).collect::<Vec<_>>().join(",")),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            format!(
                "{{{}}}",
                keys.into_iter().map(|k| format!("{}:{}", js_stringify(&Value::String(k.clone())), stable(&m[k.as_str()]))).collect::<Vec<_>>().join(",")
            )
        }
        s => js_stringify(s),
    }
}

/// True when `accepted` (echoed by the client in its v2 payload) is exactly one of the requirements the server offered.
pub fn x402_accepted_matches(offered: &Value, accepted: &Value) -> Result<bool, String> {
    if !requirement_v2_problems(Some(accepted)).is_empty() {
        return Ok(false);
    }
    let Value::Array(list) = offered else { return Err("offered.some is not a function".into()) };
    let a = stable(accepted);
    Ok(list.iter().any(|o| stable(o) == a))
}

/// Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the token is
/// `payload.token` and the echoed `accepted` must be a valid v2 requirement (the merchant is never read from a v2 payload and the
/// amount only from `accepted.amount`). Never fails: `{ok: false, reason}`.
pub fn normalize_x402_payload(raw: &Value) -> Value {
    let Value::Object(raw) = raw else { return refuse_n("x402 payment payload is not an object") };
    let ver = raw.get("x402Version");
    if num_of(ver) == Some(2.0) {
        let token = raw.get("payload").and_then(|p| p.get("token")).and_then(Value::as_str).filter(|t| !t.is_empty());
        let (Some(Value::Object(_)), Some(token)) = (raw.get("payload"), token) else { return refuse_n("x402 v2 payload is missing payload.token") };
        let problems = requirement_v2_problems(raw.get("accepted"));
        if !problems.is_empty() {
            return refuse_n(&format!("x402 v2 payload.accepted is invalid: {}", problems.join("; ")));
        }
        let accepted = &raw["accepted"];
        let mut out = Map::new();
        out.insert("ok".into(), json!(true));
        out.insert("version".into(), json!(2));
        out.insert("token".into(), json!(token));
        out.insert("accepted".into(), accepted.clone());
        let amount: f64 = accepted["amount"].as_str().and_then(|a| a.parse().ok()).unwrap_or(f64::NAN);
        if amount.is_finite() && amount <= 9_007_199_254_740_991.0 {
            out.insert("amount".into(), json!(amount as i64));
        }
        return Value::Object(out);
    }
    if ver.is_some() && num_of(ver) != Some(1.0) {
        return refuse_n(&format!("unsupported x402Version {}", tostr(ver)));
    }
    let Some(token) = raw.get("token").and_then(Value::as_str) else { return refuse_n("x402 payment payload is missing a token") };
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("version".into(), json!(1));
    out.insert("token".into(), json!(token));
    if let Some(m) = raw.get("merchant").filter(|m| m.is_string()) {
        out.insert("merchant".into(), m.clone());
    }
    if let Some(a) = raw.get("amount").filter(|a| a.is_number()) {
        out.insert("amount".into(), a.clone());
    }
    Value::Object(out)
}

fn refuse_n(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

// ---- x402 v2 HTTP transport -----------------------------------------------------------------------------------------------

/// Problems with a v2 `PaymentPayload` (empty = valid).
pub fn payment_payload_v2_problems(p: V) -> Vec<String> {
    let Some(Value::Object(p)) = p else { return vec!["PaymentPayload must be an object".into()] };
    let mut out = Vec::new();
    if num_of(p.get("x402Version")) != Some(2.0) {
        out.push("x402Version must be 2".to_string());
    }
    if let Some(r) = p.get("resource") {
        out.extend(resource_info_problems(Some(r)));
    }
    out.extend(requirement_v2_problems(p.get("accepted")).into_iter().map(|m| format!("accepted.{m}")));
    if !is_obj(p.get("payload")) {
        out.push("payload must be an object".into());
    }
    if p.contains_key("extensions") && !is_obj(p.get("extensions")) {
        out.push("extensions must be an object".into());
    }
    out
}

/// Problems with a `SettlementResponse` (empty = valid). A success must not carry an `errorReason`; a failure must.
pub fn settlement_response_problems(r: V) -> Vec<String> {
    let Some(Value::Object(r)) = r else { return vec!["SettlementResponse must be an object".into()] };
    let mut out = Vec::new();
    let (success, tx, net, er) = (r.get("success"), r.get("transaction"), r.get("network"), r.get("errorReason"));
    let ok = success == Some(&Value::Bool(true));
    if !matches!(success, Some(Value::Bool(_))) {
        out.push("success must be a boolean".to_string());
    }
    match tx {
        Some(Value::String(t)) => {
            if ok && t.is_empty() {
                out.push("a successful settlement needs a transaction".into());
            }
        }
        _ => out.push("transaction must be a string".into()),
    }
    if !net.and_then(Value::as_str).is_some_and(is_caip2) {
        out.push("network must be a CAIP-2 identifier".into());
    }
    if er.is_some() && !str_is(er) {
        out.push("errorReason must be a string".into());
    }
    if ok && er.is_some() {
        out.push("errorReason must be omitted on success".into());
    }
    if success == Some(&Value::Bool(false)) && !nonempty_str(er) {
        out.push("errorReason is required on failure".into());
    }
    if r.contains_key("payer") && !str_is(r.get("payer")) {
        out.push("payer must be a string".into());
    }
    if r.contains_key("amount") && !r.get("amount").and_then(Value::as_str).is_some_and(is_atomic) {
        out.push("amount must be a decimal string of atomic units".into());
    }
    if r.contains_key("extensions") && !is_obj(r.get("extensions")) {
        out.push("extensions must be an object".into());
    }
    out
}

fn encode_header(obj: &Value, problems: Vec<String>) -> Result<String, String> {
    if problems.is_empty() {
        Ok(b64_encode(obj))
    } else {
        Err(problems_err(&problems))
    }
}

/// Encode a `PaymentPayload` for the `PAYMENT-SIGNATURE` request header (validates first).
pub fn encode_payment_signature_header(p: &Value) -> Result<String, String> {
    encode_header(p, payment_payload_v2_problems(Some(p)))
}

/// Decode and validate a `PAYMENT-SIGNATURE` header value.
pub fn decode_payment_signature_header(value: V) -> Result<Value, String> {
    let doc = b64_decode(value, "PAYMENT-SIGNATURE")?;
    let p = payment_payload_v2_problems(Some(&doc));
    if p.is_empty() {
        Ok(doc)
    } else {
        Err(problems_err(&p))
    }
}

/// Encode a `SettlementResponse` for the `PAYMENT-RESPONSE` response header.
pub fn encode_payment_response_header(r: &Value) -> Result<String, String> {
    encode_header(r, settlement_response_problems(Some(r)))
}

/// Decode and validate a `PAYMENT-RESPONSE` header value.
pub fn decode_payment_response_header(value: V) -> Result<Value, String> {
    let doc = b64_decode(value, "PAYMENT-RESPONSE")?;
    let p = settlement_response_problems(Some(&doc));
    if p.is_empty() {
        Ok(doc)
    } else {
        Err(problems_err(&p))
    }
}

/// Server side: read the client's `PAYMENT-SIGNATURE` header (case-insensitive, first value of a list). A missing header is 402
/// (answer with a `PAYMENT-REQUIRED` challenge); a present but undecodable or invalid one is 400. Only a non-object `headers` fails.
pub fn read_payment_signature(headers: &Value) -> Result<Value, String> {
    let Value::Object(h) = headers else { return Err("headers is not an object".into()) };
    let found = h.iter().find(|(k, _)| k.to_lowercase() == X402_PAYMENT_SIGNATURE_HEADER.to_lowercase()).map(|(_, v)| v);
    let v: Option<&Value> = match found {
        Some(Value::Array(a)) => a.first(),
        other => other,
    };
    if v.is_none() || v == Some(&json!("")) {
        return Ok(json!({ "ok": false, "status": 402, "reason": "PAYMENT-SIGNATURE header is required" }));
    }
    Ok(match decode_payment_signature_header(v) {
        Ok(p) => json!({ "ok": true, "payload": p }),
        Err(e) => json!({ "ok": false, "status": 400, "reason": e }),
    })
}

/// Server side: the status and `PAYMENT-RESPONSE` header for a settlement outcome (a success is 200 and needs the transaction; a
/// failure is 402 with `success: false`, the reason and an empty transaction unless one was broadcast). Refused if the response
/// would be invalid.
pub fn x402_settlement_response(outcome: &Value, network: V) -> Result<Value, String> {
    let Value::Object(o) = outcome else { return Err("outcome is not an object".into()) };
    let settled = truthy(o.get("settled"));
    let mut body = Map::new();
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v {
            body.insert(k.to_string(), v);
        }
    };
    if settled {
        put("success", Some(json!(true)));
        put("transaction", o.get("transaction").cloned());
        put("network", network.cloned());
        for k in ["payer", "amount"] {
            put(k, o.get(k).cloned());
        }
    } else {
        put("success", Some(json!(false)));
        put("errorReason", o.get("reason").cloned());
        put("transaction", Some(if nullish(o.get("transaction")) { json!("") } else { o["transaction"].clone() }));
        put("network", network.cloned());
        put("payer", o.get("payer").cloned());
    }
    let header = encode_payment_response_header(&Value::Object(body))?;
    Ok(json!({ "status": if settled { 200 } else { 402 }, "headers": { "PAYMENT-RESPONSE": header } }))
}

/// Client side: the request header to attach on the retry, from a payload built for an offered requirement.
pub fn x402_payment_signature_headers(p: &Value) -> Result<Value, String> {
    Ok(json!({ "PAYMENT-SIGNATURE": encode_payment_signature_header(p)? }))
}

// ---- Stripe Shared Payment Granted Tokens ---------------------------------------------------------------------------------

fn is_currency(v: V) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_lowercase()))
}

fn is_spt_id(s: &str) -> bool {
    s.strip_prefix("spt_").is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric()))
}

/// Problems with a Shared Payment Granted Token object (empty = well formed).
pub fn stripe_spt_problems(t: V) -> Vec<String> {
    let Some(Value::Object(t)) = t else { return vec!["the token must be an object".into()] };
    let mut p = Vec::new();
    if t.get("object").and_then(Value::as_str) != Some(STRIPE_SPT_OBJECT) {
        p.push(format!("object must be \"{STRIPE_SPT_OBJECT}\""));
    }
    if !t.get("id").and_then(Value::as_str).is_some_and(is_spt_id) {
        p.push("id must be an spt_ identifier".into());
    }
    if !is_int(t.get("created")) {
        p.push("created must be an integer timestamp".into());
    }
    if !matches!(t.get("livemode"), Some(Value::Bool(_))) {
        p.push("livemode must be a boolean".into());
    }
    let da = t.get("deactivated_at");
    if !matches!(da, Some(Value::Null)) && !is_int(da) {
        p.push("deactivated_at must be null or an integer timestamp".into());
    }
    let dr = t.get("deactivated_reason");
    if !matches!(dr, Some(Value::Null)) && !dr.and_then(Value::as_str).is_some_and(|r| ["consumed", "expired", "resolved", "revoked"].contains(&r)) {
        p.push("deactivated_reason must be null or one of consumed, expired, resolved, revoked".into());
    }
    match t.get("usage_limits") {
        Some(Value::Object(u)) => {
            if !is_currency(u.get("currency")) {
                p.push("usage_limits.currency must be a lowercase three-letter code".into());
            }
            if !is_int(u.get("max_amount")) || num_of(u.get("max_amount")).is_some_and(|f| f < 0.0) {
                p.push("usage_limits.max_amount must be a non-negative integer in minor units".into());
            }
            let ea = u.get("expires_at");
            if !nullish(ea) && !is_int(ea) {
                p.push("usage_limits.expires_at must be an integer timestamp".into());
            }
        }
        _ => p.push("usage_limits is required".into()),
    }
    if let Some(ud) = t.get("usage_details").filter(|u| !u.is_null()) {
        let c = ud.get("amount_captured").filter(|_| ud.is_object());
        let ok =
            matches!(c, Some(Value::Object(c)) if is_int(c.get("value")) && num_of(c.get("value")).is_some_and(|f| f >= 0.0) && is_currency(c.get("currency")));
        if !ok {
            p.push("usage_details.amount_captured needs a non-negative integer value and a lowercase currency".into());
        }
    }
    for k in ["payment_method_details", "agent_details", "shared_metadata"] {
        if t.get(k).is_some_and(|v| !v.is_null() && !v.is_object()) {
            p.push(format!("{k} must be null or an object"));
        }
    }
    if let Some(Value::Object(pmd)) = t.get("payment_method_details") {
        if !str_is(pmd.get("type")) {
            p.push("payment_method_details.type must be a string".into());
        }
    }
    p
}

/// Parse a Shared Payment Granted Token; refused with every problem listed.
pub fn parse_stripe_spt(t: &Value) -> Result<Value, String> {
    let p = stripe_spt_problems(Some(t));
    if p.is_empty() {
        Ok(t.clone())
    } else {
        Err(format!("stripe spt: {}", p.join("; ")))
    }
}

/// Can this token still be used for this capture? Refuses a malformed token, a deactivated or expired one, the wrong mode, a
/// different currency, a non-integer amount and one above `max_amount` minus what was already captured.
pub fn stripe_spt_usable(t: &Value, usage: &Value) -> Result<Value, String> {
    let problems = stripe_spt_problems(Some(t));
    if let Some(first) = problems.first() {
        return Ok(refuse(&format!("malformed token: {first}")));
    }
    let (now, amount) = (prop(Some(usage), "now")?, prop(Some(usage), "amount")?);
    if !is_int(now) || !is_int(amount) || num_of(amount).is_some_and(|a| a <= 0.0) {
        return Ok(refuse("now and amount must be integers and the amount positive"));
    }
    let (now, amount) = (num_of(now).unwrap_or(0.0), num_of(amount).unwrap_or(0.0));
    let lm = nz(prop(Some(usage), "livemode")?, json!(true));
    if !lm.is_boolean() || lm != t["livemode"] {
        return Ok(refuse("the token is in the wrong mode"));
    }
    if let Some(r) = t["deactivated_reason"].as_str() {
        return Ok(refuse(&format!("the token is deactivated ({r})")));
    }
    if num_of(t.get("deactivated_at")).is_some_and(|d| !(d > now)) {
        return Ok(refuse("the token is deactivated"));
    }
    let lim = &t["usage_limits"];
    if num_of(lim.get("expires_at")).is_some_and(|e| !(now < e)) {
        return Ok(refuse("the token has expired"));
    }
    let Some(cur) = prop(Some(usage), "currency")?.and_then(Value::as_str) else {
        return Err("Cannot read properties of undefined (reading 'toLowerCase')".into());
    };
    if lim["currency"].as_str() != Some(cur.to_lowercase().as_str()) {
        return Ok(refuse("the capture currency differs from the token currency"));
    }
    let captured = t.get("usage_details").filter(|u| u.is_object()).and_then(|u| u.get("amount_captured")).filter(|c| !c.is_null());
    if let Some(c) = captured {
        if c["currency"] != lim["currency"] {
            return Ok(refuse("the captured amount is in another currency"));
        }
    }
    let remaining = num_of(lim.get("max_amount")).unwrap_or(0.0) - captured.and_then(|c| num_of(c.get("value"))).unwrap_or(0.0);
    if !(remaining.is_finite() && amount <= remaining) {
        return Ok(refuse(&format!("the amount {} exceeds the remaining {}", js_number_string(amount), js_number_string(remaining))));
    }
    Ok(json!({ "ok": true }))
}

/// The `usage_limits` to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds (rounded
/// down). Refused on anything invalid.
pub fn stripe_usage_limits_for(authority: &Value) -> Result<Value, String> {
    let ma = prop(Some(authority), "maxAmount")?;
    if !is_int(ma) || num_of(ma).is_some_and(|m| m <= 0.0) {
        return Err("stripe spt: maxAmount must be a positive integer in minor units".into());
    }
    let cur = prop(Some(authority), "currency")?.and_then(Value::as_str).filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_alphabetic()));
    let Some(cur) = cur else { return Err("stripe spt: currency must be a three-letter code".into()) };
    let exp = prop(Some(authority), "expiresAtMs")?;
    if exp.is_some() && !(isfinite(exp) && num_of(exp).is_some_and(|e| e > 0.0)) {
        return Err("stripe spt: expiresAtMs must be a positive epoch-ms time".into());
    }
    let mut out = Map::new();
    out.insert("currency".into(), Value::String(cur.to_lowercase()));
    out.insert("max_amount".into(), ma.cloned().unwrap_or(Value::Null));
    if let Some(e) = num_of(exp) {
        out.insert("expires_at".into(), jf((e / 1000.0).floor()));
    }
    Ok(Value::Object(out))
}

/// A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
/// `max_amount` not above the delegated amount, and an expiry present and not after the delegated token's.
pub fn stripe_spt_within_claims(t: &Value, claims: &Value) -> Result<Value, String> {
    let problems = stripe_spt_problems(Some(t));
    if let Some(first) = problems.first() {
        return Ok(refuse(&format!("malformed token: {first}")));
    }
    let lim = &t["usage_limits"];
    let (amount, exp) = (prop(Some(claims), "amount")?, prop(Some(claims), "exp")?);
    let Some(cur) = prop(Some(claims), "currency")?.and_then(Value::as_str) else {
        return Err("Cannot read properties of undefined (reading 'toLowerCase')".into());
    };
    if lim["currency"].as_str() != Some(cur.to_lowercase().as_str()) {
        return Ok(refuse("the token currency differs from the delegated currency"));
    }
    let max = num_of(lim.get("max_amount")).unwrap_or(0.0);
    // `Number.isFinite` does not coerce: a string, array or missing claim is not a finite number
    let finite_num = |v: Option<&Value>| v.filter(|x| x.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite());
    if !finite_num(amount).is_some_and(|a| max <= a) {
        return Ok(refuse(&format!("max_amount {} exceeds the delegated amount {}", js_number_string(max), tostr(amount))));
    }
    let Some(ea) = num_of(lim.get("expires_at")) else { return Ok(refuse("the token has no expiry")) };
    if !finite_num(exp).is_some_and(|e| ea * 1000.0 <= e) {
        return Ok(refuse("the token outlives the delegated payment token"));
    }
    Ok(json!({ "ok": true }))
}
