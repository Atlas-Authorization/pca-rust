//! AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant.
//!
//! PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other
//! parties verify. This module carries:
//! - the SD-JWT primitives (RFC 9901): strict compact parsing (duplicate keys, fatal UTF-8, canonical base64url), disclosure
//!   processing, the `sd_hash` / `issuer_jwt_hash` binding digests and ES256 (P-256) signing and verification;
//! - the mandate claim shapes (Intent / Cart / Payment, closed and open), their validators and ISO 4217 minor units;
//! - open-mandate constraint evaluation against a closed mandate or checkout, issuance and presentation of delegation chains, chain
//!   and purchase verification, the single-use redeem ledger, settlement payloads (x402, Stripe shared payment tokens) and the PCA
//!   terms bridge (`open_*_from_pca`, `build_pca_payment_binding`, `verify_pca_binding`).
//!
//! JSON-valued API (reference member names, JavaScript value semantics: a missing member is `undefined`, reading a member of `null`
//! is a TypeError). `Err` is a refusal / throw. Private keys are P-256 private JWKs (`{kty, crv, x, y, d}`) passed where the
//! reference takes a key object; salts come from a caller closure ([`Salt`]; [`new_salt`] is the production source). Time arguments
//! are epoch seconds; where the reference reads the clock the default is the system clock. The PCA policy engine of
//! [`verify_pca_binding`] is an injected `decide` closure.
use crate::actions::js_to_number;
use crate::agent::{build_pcactn, rand_bytes, KeyPair, PcactnInput, Suite};
use crate::oauth::{js_str, truthy};
use crate::payments::{b64u, charge_params, charge_plan_node, isfinite, js_round, nullish, num, num_of, prop, safe_int, seq, spread_obj, tostr};
use crate::{hash_canonical_strict, js_stringify};
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const AP2_COMMIT: &str = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
pub const VCT_CHECKOUT: &str = "mandate.checkout.1";
pub const VCT_CHECKOUT_OPEN: &str = "mandate.checkout.open.1";
pub const VCT_PAYMENT: &str = "mandate.payment.1";
pub const VCT_PAYMENT_OPEN: &str = "mandate.payment.open.1";
pub const PCA_CLAIM: &str = "x_pca";
pub const FREQUENCIES: [&str; 7] = ["ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"];
pub const PCA_BINDING_VERSION: i64 = 1;
pub const TYP_TERMINAL: [&str; 2] = ["kb+sd-jwt", "kb-sd-jwt"];
pub const TYP_INTERMEDIATE: [&str; 2] = ["kb+sd-jwt+kb", "kb-sd-jwt+kb"];
const MAX_HOPS: usize = 8;
const ROOT_TYP: &str = "dc+sd-jwt";
const SD_ALGS: [&str; 3] = ["sha-256", "sha-384", "sha-512"];
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A salt source: each call yields one fresh base64url salt (`Err` only if the OS RNG fails).
pub type Salt<'a> = Box<dyn FnMut() -> Result<String, String> + 'a>;
/// `resolveIssuerKey` / `resolveMerchantKey`: the JWS header -> the public JWK to verify under (`None`: no key).
pub type KeyResolver<'a> = &'a dyn Fn(&Map<String, Value>) -> Result<Option<Value>, String>;

type V<'a> = Option<&'a Value>;

// ---- JavaScript value semantics --------------------------------------------------------------------------------------------

fn is_num(v: V) -> bool {
    matches!(v, Some(Value::Number(_)))
}

fn finite(v: V) -> bool {
    isfinite(v)
}

fn neg0(v: V) -> bool {
    num_of(v).is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

fn is_int(v: V) -> bool {
    safe_int(v) && !neg0(v)
}

fn is_nonneg_int(v: V) -> bool {
    is_int(v) && num_of(v).is_some_and(|f| f >= 0.0)
}

fn is_str(v: V) -> bool {
    matches!(v, Some(Value::String(_)))
}

fn nonempty_str(v: V) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}

fn is_rec(v: V) -> bool {
    matches!(v, Some(Value::Object(_)))
}

fn jnum(f: f64) -> Value {
    num(f)
}

fn jstr(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

fn now_secs() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64)
}

/// `[...x]` of an array (anything else is not iterable).
fn iter_list(x: V) -> Result<&Vec<Value>, String> {
    match x {
        Some(Value::Array(a)) => Ok(a),
        _ => Err("x is not iterable".into()),
    }
}

fn some_str<'a>(v: V<'a>) -> Option<&'a str> {
    v.and_then(Value::as_str)
}

fn clone_or_null(v: V) -> Value {
    v.cloned().unwrap_or(Value::Null)
}

/// JS relational comparison: two strings compare by UTF-16 code unit, anything else as numbers (NaN compares false).
fn rel(a: V, b: V) -> Option<Ordering> {
    if let (Some(Value::String(x)), Some(Value::String(y))) = (a, b) {
        return Some(x.encode_utf16().cmp(y.encode_utf16()));
    }
    js_to_number(a).partial_cmp(&js_to_number(b))
}

fn lt(a: V, b: V) -> bool {
    rel(a, b) == Some(Ordering::Less)
}

fn le(a: V, b: V) -> bool {
    matches!(rel(a, b), Some(Ordering::Less | Ordering::Equal))
}

fn ge(a: V, b: V) -> bool {
    matches!(rel(a, b), Some(Ordering::Greater | Ordering::Equal))
}

fn includes(lst: V, v: V) -> bool {
    match lst {
        Some(Value::Array(a)) => a.iter().any(|x| seq(Some(x), v)),
        Some(Value::String(s)) => matches!(v, Some(Value::String(t)) if s.contains(t.as_str())),
        _ => false,
    }
}

/// `_compact`: the members whose value is defined (what `JSON.stringify` keeps).
fn compact(pairs: Vec<(&str, V)>) -> Value {
    Value::Object(pairs.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v.clone()))).collect())
}

/// `JSON.parse(JSON.stringify(v))`: an `undefined` throws.
fn to_json(v: V) -> Result<Value, String> {
    v.cloned().ok_or_else(|| "JSON.parse: undefined is not valid JSON".to_string())
}

fn hash_canonical(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string())
}

// ---- base64url + JSON helpers ------------------------------------------------------------------------------------------------

pub fn b64u_encode(data: &[u8]) -> String {
    b64u(data)
}

fn lenient() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
}

/// Node's lenient `Buffer.from(s, 'base64url')`: padding and foreign characters dropped, a dangling sextet ignored.
fn node_b64url_decode(s: &str) -> Vec<u8> {
    let mut t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/'))
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    if t.len() % 4 == 1 {
        t.pop();
    }
    lenient().decode(t).unwrap_or_default()
}

/// Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip.
pub fn b64u_decode(s: &str, what: &str) -> Result<Vec<u8>, String> {
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(format!("{what}: not base64url"));
    }
    let buf = lenient().decode(s).map_err(|_| format!("{what}: non-canonical base64url"))?;
    if b64u(&buf) != s {
        return Err(format!("{what}: non-canonical base64url"));
    }
    Ok(buf)
}

/// Reject an object that repeats a key (`JSON.parse` keeps the last): run on text that already parsed.
fn assert_no_duplicate_keys(text: &str, what: &str) -> Result<(), String> {
    let b = text.as_bytes();
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    let mut expect_key = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let mut j = i + 1;
                while b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                if expect_key {
                    if let Some(Some(top)) = stack.last_mut() {
                        let key: String = serde_json::from_str(&text[i..=j]).map_err(|e| e.to_string())?;
                        if top.contains(&key) {
                            return Err(format!("{what}: duplicate key {}", js_stringify(&Value::String(key))));
                        }
                        top.insert(key);
                        expect_key = false;
                    }
                }
                i = j;
            }
            b'{' => {
                stack.push(Some(HashSet::new()));
                expect_key = true;
            }
            b'[' => {
                stack.push(None);
                expect_key = false;
            }
            b'}' | b']' => {
                stack.pop();
                expect_key = false;
            }
            b',' => expect_key = matches!(stack.last(), Some(Some(_))),
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

/// `JSON.parse` that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted).
pub fn parse_json(text: &str, what: &str) -> Result<Value, String> {
    // JSON.parse keeps a lone-surrogate escape (`"\ud800"`) in the string; a Rust string cannot, so the crate's stand-in character
    // takes its place (the crate's lone-surrogate checks read this character as one)
    let text = standin_lone_surrogates(text);
    let text = text.as_ref();
    let v: Value = serde_json::from_str(text).map_err(|e| format!("{what}: invalid JSON ({e})"))?;
    assert_no_duplicate_keys(text, what)?;
    Ok(v)
}

/// The text with every lone-surrogate `\uXXXX` escape inside a string literal replaced by U+10FFFF. A high surrogate escape directly
/// followed by a low surrogate escape is a pair and is left alone.
fn standin_lone_surrogates(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("\\u") {
        return std::borrow::Cow::Borrowed(text);
    }
    let c: Vec<char> = text.chars().collect();
    let hex4 = |at: usize| -> Option<u32> {
        let h: String = c.get(at..at + 4)?.iter().collect();
        if h.len() == 4 && h.bytes().all(|b| b.is_ascii_hexdigit()) { u32::from_str_radix(&h, 16).ok() } else { None }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0usize, false);
    while i < c.len() {
        match c[i] {
            '"' => {
                in_str = !in_str;
                out.push('"');
                i += 1;
            }
            '\\' if in_str => {
                if c.get(i + 1) == Some(&'u') {
                    if let Some(u) = hex4(i + 2) {
                        let low_next = c.get(i + 6) == Some(&'\\') && c.get(i + 7) == Some(&'u') && hex4(i + 8).is_some_and(|l| (0xDC00..=0xDFFF).contains(&l));
                        if (0xD800..=0xDBFF).contains(&u) && low_next {
                            out.extend(&c[i..i + 12]);
                            i += 12;
                            continue;
                        }
                        if (0xD800..=0xDFFF).contains(&u) {
                            out.push('\u{10FFFF}');
                            i += 6;
                            continue;
                        }
                        out.extend(&c[i..i + 6]);
                        i += 6;
                        continue;
                    }
                }
                out.push('\\');
                if let Some(n) = c.get(i + 1) {
                    out.push(*n);
                }
                i += 2;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

fn utf8_text(b: &[u8], what: &str) -> Result<String, String> {
    String::from_utf8(b.to_vec()).map_err(|_| format!("{what}: not valid UTF-8"))
}

fn decode_json_segment(segment: &str, what: &str) -> Result<Map<String, Value>, String> {
    match parse_json(&utf8_text(&b64u_decode(segment, what)?, what)?, what)? {
        Value::Object(m) => Ok(m),
        _ => Err(format!("{what}: must be a JSON object")),
    }
}

// ---- hashing ------------------------------------------------------------------------------------------------------------------

pub fn is_sd_alg(v: V) -> bool {
    matches!(v, Some(Value::String(s)) if SD_ALGS.contains(&s.as_str()))
}

/// base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`.
pub fn sd_digest(value: &str, alg: &str) -> Result<String, String> {
    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err("digest input must be ASCII".into());
    }
    let d = match alg {
        "sha-256" => Sha256::digest(value.as_bytes()).to_vec(),
        "sha-384" => Sha384::digest(value.as_bytes()).to_vec(),
        "sha-512" => Sha512::digest(value.as_bytes()).to_vec(),
        _ => return Err("unsupported hash algorithm".into()),
    };
    Ok(b64u(&d))
}

// ---- ES256 keys (P-256) --------------------------------------------------------------------------------------------------------

/// The 65-byte SEC1 point of a JWK's `x` / `y` (decoded the way Node does), checked to lie on the curve.
fn public_key(jwk: &Value) -> Result<p256::ecdsa::VerifyingKey, String> {
    let pad = |s: Option<&str>| -> Vec<u8> {
        let b = node_b64url_decode(s.unwrap_or(""));
        let mut out = vec![0u8; 32usize.saturating_sub(b.len())];
        out.extend_from_slice(&b);
        out
    };
    let (x, y) = (pad(some_str(jwk.get("x"))), pad(some_str(jwk.get("y"))));
    if x.len() != 32 || y.len() != 32 {
        return Err("invalid P-256 point".into());
    }
    let mut point = vec![4u8];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| "invalid P-256 point".to_string())
}

/// Validate a public JWK against `types/jwk.json` and prove the point is on the curve. Returns the JWK itself.
pub fn assert_p256_jwk(jwk: V, what: &str) -> Result<Value, String> {
    let Some(Value::Object(m)) = jwk else { return Err(format!("{what}: JWK must be an object")) };
    if !seq(m.get("kty"), Some(&json!("EC"))) || !seq(m.get("crv"), Some(&json!("P-256"))) {
        return Err(format!("{what}: JWK must be EC P-256"));
    }
    for c in ["x", "y"] {
        let ok = some_str(m.get(c)).is_some_and(|s| s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        if !ok {
            return Err(format!("{what}: bad JWK {c}"));
        }
    }
    if m.contains_key("d") {
        return Err(format!("{what}: JWK carries private material"));
    }
    if m.get("alg").is_some() && !seq(m.get("alg"), Some(&json!("ES256"))) {
        return Err(format!("{what}: JWK alg must be ES256"));
    }
    public_key(&Value::Object(m.clone())).map_err(|_| format!("{what}: JWK is not a valid P-256 point"))?;
    Ok(Value::Object(m.clone()))
}

fn public_jwk_of(sk: &p256::ecdsa::SigningKey, kid: Option<&str>) -> Value {
    let pt = sk.verifying_key().to_encoded_point(false);
    let mut o = Map::new();
    o.insert("kty".into(), json!("EC"));
    o.insert("crv".into(), json!("P-256"));
    o.insert("x".into(), json!(b64u(pt.x().map_or(&[][..], |x| x.as_slice()))));
    o.insert("y".into(), json!(b64u(pt.y().map_or(&[][..], |y| y.as_slice()))));
    if let Some(k) = kid {
        o.insert("kid".into(), json!(k));
    }
    Value::Object(o)
}

fn signing_key(d_b64u: &str) -> Result<p256::ecdsa::SigningKey, String> {
    let raw = node_b64url_decode(d_b64u);
    let trimmed: Vec<u8> = raw.iter().copied().skip_while(|b| *b == 0).collect();
    if trimmed.len() > 32 {
        return Err("Invalid JWK EC key".into());
    }
    let mut d = vec![0u8; 32 - trimmed.len()];
    d.extend_from_slice(&trimmed);
    p256::ecdsa::SigningKey::from_slice(&d).map_err(|_| "Invalid JWK EC key".to_string())
}

/// A private P-256 JWK (`{kty, crv, x, y, d}`) from a 32-byte scalar (fixtures and tests).
pub fn p256_private_jwk(d: &[u8; 32], kid: Option<&str>) -> Result<Value, String> {
    let sk = signing_key(&b64u(d))?;
    let mut o = public_jwk_of(&sk, kid).as_object().cloned().unwrap_or_default();
    o.insert("d".into(), json!(b64u(d)));
    Ok(Value::Object(o))
}

/// A fresh P-256 key pair: `{publicJwk (never contains d), privateKey (the private JWK)}`.
pub fn generate_ap2_key_pair(kid: Option<&str>) -> Result<Value, String> {
    loop {
        let d = rand_bytes::<32>()?;
        if let Ok(jwk) = p256_private_jwk(&d, kid) {
            let sk = signing_key(&b64u(&d))?;
            return Ok(json!({ "publicJwk": public_jwk_of(&sk, kid), "privateKey": jwk }));
        }
    }
}

/// Rebuild a key pair from a private JWK (`d` present), e.g. for fixtures. A JWK whose x / y do not match `d` is refused.
/// Returns `{privateKey (the JWK), publicJwk}`.
pub fn ap2_key_pair_from_private_jwk(jwk: &Value) -> Result<Value, String> {
    let bad = || "Invalid JWK EC key".to_string();
    let m = jwk.as_object().ok_or_else(bad)?;
    if m.get("kty").and_then(Value::as_str) != Some("EC")
        || m.get("crv").and_then(Value::as_str) != Some("P-256")
        || !["d", "x", "y"].iter().all(|k| m.get(*k).is_some_and(Value::is_string))
    {
        return Err(bad());
    }
    let sk = signing_key(m["d"].as_str().unwrap_or(""))?;
    let publ = public_jwk_of(&sk, None);
    if node_b64url_decode(m["x"].as_str().unwrap_or("")) != node_b64url_decode(publ["x"].as_str().unwrap_or(""))
        || node_b64url_decode(m["y"].as_str().unwrap_or("")) != node_b64url_decode(publ["y"].as_str().unwrap_or(""))
    {
        return Err(bad());
    }
    let kid = m.get("kid").and_then(Value::as_str);
    Ok(json!({ "privateKey": jwk, "publicJwk": public_jwk_of(&sk, kid) }))
}

/// RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key.
pub fn jwk_thumbprint(jwk: V) -> Result<String, String> {
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", tostr(prop(jwk, "x")?), tostr(prop(jwk, "y")?));
    Ok(b64u(&Sha256::digest(canonical.as_bytes())))
}

fn es256_sign(private_jwk: V, signing_input: &str) -> Result<String, String> {
    use p256::ecdsa::signature::Signer;
    let Some(Value::Object(m)) = private_jwk else { return Err("Invalid key for this operation".into()) };
    if m.get("kty").and_then(Value::as_str) != Some("EC") || m.get("crv").and_then(Value::as_str) != Some("P-256") {
        return Err("Invalid key for this operation".into());
    }
    let sk = signing_key(m.get("d").and_then(Value::as_str).ok_or("Invalid key for this operation")?)?;
    let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
    Ok(b64u(&sig.to_bytes()))
}

fn es256_verify(jwk: &Value, signing_input: &str, signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    if signature.len() != 64 {
        return false;
    }
    let Ok(pk) = public_key(jwk) else { return false };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else { return false };
    pk.verify(signing_input.as_bytes(), &sig).is_ok()
}

// ---- compact JWT / SD-JWT parsing --------------------------------------------------------------------------------------------

/// One parsed SD-JWT hop (`jwt~d1~...~dn~`).
#[derive(Debug, Clone)]
pub struct Hop {
    pub raw: String,
    pub jwt: String,
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub disclosures: Vec<String>,
    pub sd_alg: String,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl Hop {
    /// The reference's hop object (`signature` as `{"$bytes": b64url}`).
    pub fn to_value(&self) -> Value {
        json!({ "raw": self.raw, "jwt": self.jwt, "header": self.header, "payload": self.payload, "disclosures": self.disclosures, "sdAlg": self.sd_alg,
                "signingInput": self.signing_input, "signature": { "$bytes": b64u(&self.signature) } })
    }
}

/// The hop's `~`-joined serialisation: what `sd_hash` is computed over.
pub fn hop_sd_jwt(hop: &Hop) -> String {
    format!("{}~{}", hop.jwt, hop.disclosures.iter().map(|d| format!("{d}~")).collect::<String>())
}

/// Parse one SD-JWT (`jwt~d1~...~dn~`; it must end with `~`).
pub fn parse_sd_jwt_hop(token: &str) -> Result<Hop, String> {
    if token.is_empty() {
        return Err("SD-JWT: empty".into());
    }
    if token.starts_with('~') {
        return Err("SD-JWT: empty issuer JWT".into());
    }
    if !token.ends_with('~') {
        return Err("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)".into());
    }
    let parts: Vec<&str> = token[..token.len() - 1].split('~').collect();
    let jwt = parts[0];
    let disclosures: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
    if disclosures.iter().any(String::is_empty) {
        return Err("SD-JWT: empty disclosure segment".into());
    }
    let seg: Vec<&str> = jwt.split('.').collect();
    if seg.len() != 3 || seg.iter().any(|s| s.is_empty()) {
        return Err("SD-JWT: issuer JWT must be header.payload.signature".into());
    }
    let header = decode_json_segment(seg[0], "JWT header")?;
    let payload = decode_json_segment(seg[1], "JWT payload")?;
    let signature = b64u_decode(seg[2], "JWT signature")?;
    let raw_alg = payload.get("_sd_alg");
    if raw_alg.is_some() && !is_sd_alg(raw_alg) {
        return Err(format!("SD-JWT: unsupported _sd_alg {}", js_stringify(raw_alg.unwrap_or(&Value::Null))));
    }
    let sd_alg = some_str(raw_alg).unwrap_or("sha-256").to_string();
    Ok(Hop { raw: token.to_string(), jwt: jwt.to_string(), header, payload, disclosures, sd_alg, signing_input: format!("{}.{}", seg[0], seg[1]), signature })
}

/// `sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop).
pub fn sd_hash_of(hop: &Hop, alg: Option<&str>) -> Result<String, String> {
    sd_digest(&hop_sd_jwt(hop), alg.unwrap_or(&hop.sd_alg))
}

/// `issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone.
pub fn issuer_jwt_hash_of(hop: &Hop, alg: Option<&str>) -> Result<String, String> {
    sd_digest(&hop.jwt, alg.unwrap_or(&hop.sd_alg))
}

/// Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected.
pub fn verify_hop_signature(hop: &Hop, key: V) -> Result<bool, String> {
    if !seq(hop.header.get("alg"), Some(&json!("ES256"))) {
        return Ok(false);
    }
    Ok(es256_verify(&assert_p256_jwk(key, "verification key")?, &hop.signing_input, &hop.signature))
}

/// A parsed compact JWT.
#[derive(Debug, Clone)]
pub struct Jwt {
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl Jwt {
    pub fn to_value(&self) -> Value {
        json!({ "header": self.header, "payload": self.payload, "signingInput": self.signing_input, "signature": { "$bytes": b64u(&self.signature) } })
    }
}

/// Parse a compact JWT.
pub fn parse_jwt(jwt: &str, what: &str) -> Result<Jwt, String> {
    let seg: Vec<&str> = jwt.split('.').collect();
    if seg.len() != 3 || seg.iter().any(|s| s.is_empty()) {
        return Err(format!("{what}: must be header.payload.signature"));
    }
    Ok(Jwt {
        header: decode_json_segment(seg[0], &format!("{what} header"))?,
        payload: decode_json_segment(seg[1], &format!("{what} payload"))?,
        signing_input: format!("{}.{}", seg[0], seg[1]),
        signature: b64u_decode(seg[2], &format!("{what} signature"))?,
    })
}

pub fn verify_jwt_es256(parsed: &Jwt, key: V) -> Result<bool, String> {
    if !seq(parsed.header.get("alg"), Some(&json!("ES256"))) {
        return Ok(false);
    }
    Ok(es256_verify(&assert_p256_jwk(key, "verification key")?, &parsed.signing_input, &parsed.signature))
}

// ---- disclosure processing (RFC 9901 section 7) -----------------------------------------------------------------------------

#[derive(Clone)]
struct Disc {
    property: bool,
    name: String,
    value: Value,
}

fn decode_disclosure(raw: &str) -> Result<Disc, String> {
    let arr = match parse_json(&utf8_text(&b64u_decode(raw, "disclosure")?, "disclosure")?, "disclosure")? {
        Value::Array(a) => a,
        _ => return Err("disclosure: must be a JSON array".into()),
    };
    if !arr.first().is_some_and(|s| s.as_str().is_some_and(|s| !s.is_empty())) {
        return Err("disclosure: salt must be a non-empty string".into());
    }
    match arr.len() {
        3 => {
            let Some(name) = arr[1].as_str() else { return Err("disclosure: claim name must be a string".into()) };
            if name == "_sd" || name == "..." {
                return Err(format!("disclosure: claim name {name} is reserved"));
            }
            Ok(Disc { property: true, name: name.to_string(), value: arr[2].clone() })
        }
        2 => Ok(Disc { property: false, name: String::new(), value: arr[1].clone() }),
        _ => Err("disclosure: array must have 2 or 3 elements".into()),
    }
}

struct Resolver {
    by_digest: HashMap<String, Disc>,
    used: HashSet<String>,
}

impl Resolver {
    fn take(&mut self, digest: &Value, want_property: bool) -> Result<Option<Disc>, String> {
        let Some(d) = digest.as_str().and_then(|s| self.by_digest.get(s)).cloned() else { return Ok(None) };
        let key = digest.as_str().unwrap_or("").to_string();
        if self.used.contains(&key) {
            return Err("SD-JWT: a digest is referenced more than once".into());
        }
        if d.property != want_property {
            let kind = |p: bool| if p { "property" } else { "element" };
            return Err(format!("SD-JWT: a {} disclosure is referenced from a {} position", kind(d.property), kind(want_property)));
        }
        self.used.insert(key);
        Ok(Some(d))
    }

    fn walk(&mut self, node: &Value, depth: usize) -> Result<Value, String> {
        if depth > 32 {
            return Err("SD-JWT: nesting too deep".into());
        }
        match node {
            Value::Array(list) => {
                let mut out = Vec::new();
                for el in list {
                    match el {
                        Value::Object(m) if m.contains_key("...") => {
                            let Some(digest) = m.get("...").filter(|d| m.len() == 1 && d.is_string()) else {
                                return Err("SD-JWT: malformed array digest placeholder".into());
                            };
                            if let Some(d) = self.take(digest, false)? {
                                out.push(self.walk(&d.value, depth + 1)?);
                            }
                        }
                        _ => out.push(self.walk(el, depth + 1)?),
                    }
                }
                Ok(Value::Array(out))
            }
            Value::Object(m) => {
                let mut res = Map::new();
                for (k, v) in m {
                    if k == "_sd" || k == "_sd_alg" {
                        continue;
                    }
                    if k == "..." {
                        return Err("SD-JWT: \"...\" is only valid as the sole key of an array element".into());
                    }
                    res.insert(k.clone(), self.walk(v, depth + 1)?);
                }
                if let Some(sd) = m.get("_sd") {
                    let Some(list) = sd.as_array().filter(|a| a.iter().all(Value::is_string)) else {
                        return Err("SD-JWT: _sd must be an array of strings".into());
                    };
                    for digest in list {
                        let Some(d) = self.take(digest, true)? else { continue };
                        if res.contains_key(&d.name) {
                            return Err(format!("SD-JWT: disclosed claim {} collides with an existing claim", d.name));
                        }
                        res.insert(d.name.clone(), self.walk(&d.value, depth + 1)?);
                    }
                }
                Ok(Value::Object(res))
            }
            other => Ok(other.clone()),
        }
    }
}

/// Resolve every selectively-disclosable claim in `payload` using `disclosures`; `_sd`, `...` markers and `_sd_alg` are removed.
/// Refused if a disclosure is duplicated, not referenced from the payload, collides with an existing claim, or is in the wrong position.
pub fn process_disclosures(payload: &Value, disclosures: &[String], alg: &str) -> Result<Value, String> {
    let mut r = Resolver { by_digest: HashMap::new(), used: HashSet::new() };
    for raw in disclosures {
        let d = decode_disclosure(raw)?;
        let digest = sd_digest(raw, alg)?;
        if r.by_digest.contains_key(&digest) {
            return Err("SD-JWT: duplicate disclosure".into());
        }
        r.by_digest.insert(digest, d);
    }
    let result = r.walk(payload, 0)?;
    if r.used.len() != r.by_digest.len() {
        return Err("SD-JWT: a disclosure is not referenced by the signed payload".into());
    }
    Ok(result)
}

// ---- issuing -----------------------------------------------------------------------------------------------------------------

/// 16 fresh random bytes as a base64url salt.
pub fn new_salt() -> Result<String, String> {
    Ok(b64u(&rand_bytes::<16>()?))
}

pub struct DisclosureBuilder<'a> {
    alg: Value,
    salt: Salt<'a>,
    pub disclosures: Vec<String>,
}

impl DisclosureBuilder<'_> {
    fn digest(&self, raw: &str) -> Result<String, String> {
        match &self.alg {
            a if is_sd_alg(Some(a)) => sd_digest(raw, a.as_str().unwrap_or("")),
            _ => Err("unsupported hash algorithm".into()),
        }
    }

    /// Array-element disclosure for `value`; returns the `{"...": digest}` placeholder.
    pub fn element(&mut self, value: &Value) -> Result<Value, String> {
        let raw = b64u(js_stringify(&json!([(self.salt)()?, value])).as_bytes());
        let d = self.digest(&raw)?;
        self.disclosures.push(raw);
        Ok(json!({ "...": d }))
    }

    /// Property disclosure; returns the digest to put into the parent's `_sd`.
    pub fn property(&mut self, name: &str, value: &Value) -> Result<String, String> {
        let raw = b64u(js_stringify(&json!([(self.salt)()?, name, value])).as_bytes());
        let d = self.digest(&raw)?;
        self.disclosures.push(raw);
        Ok(d)
    }
}

/// `disclosureBuilder(alg?, salt?)`: `alg` defaults to sha-256 (a non-string / unsupported one fails at the first digest).
pub fn disclosure_builder<'a>(alg: V, salt: Option<Salt<'a>>) -> DisclosureBuilder<'a> {
    DisclosureBuilder {
        alg: if nullish(alg) { json!("sha-256") } else { clone_or_null(alg) },
        salt: salt.unwrap_or_else(|| -> Salt<'a> { Box::new(new_salt) }),
        disclosures: Vec::new(),
    }
}

fn header_with_alg(defaults: Vec<(&str, Value)>, given: V) -> Value {
    let mut h = Map::new();
    for (k, v) in defaults {
        h.insert(k.to_string(), v);
    }
    for (k, v) in spread_obj(given) {
        h.insert(k, v);
    }
    Value::Object(h)
}

/// Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. `private_key`: a private P-256 JWK.
pub fn sign_sd_jwt(header: V, payload: &Value, disclosures: &[String], private_key: V) -> Result<String, String> {
    let h = b64u(js_stringify(&header_with_alg(vec![("alg", json!("ES256"))], header)).as_bytes());
    let p = b64u(js_stringify(payload).as_bytes());
    let sig = es256_sign(private_key, &format!("{h}.{p}"))?;
    Ok(format!("{h}.{p}.{sig}~{}", disclosures.iter().map(|d| format!("{d}~")).collect::<String>()))
}

/// Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`).
pub fn sign_jwt_es256(header: V, payload: &Value, private_key: V) -> Result<String, String> {
    let h = b64u(js_stringify(&header_with_alg(vec![("alg", json!("ES256")), ("typ", json!("JWT"))], header)).as_bytes());
    let p = b64u(js_stringify(payload).as_bytes());
    Ok(format!("{h}.{p}.{}", es256_sign(private_key, &format!("{h}.{p}"))?))
}

// ---- currencies and minor units ----------------------------------------------------------------------------------------------

const ZERO_DECIMAL: [&str; 17] = ["BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF"];
const THREE_DECIMAL: [&str; 7] = ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"];
const FOUR_DECIMAL: [&str; 2] = ["CLF", "UYW"];

fn alpha3_upper(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// ISO 4217 minor-unit exponent for `currency` (2 for any code not in the 0/3/4-digit tables).
pub fn currency_exponent(currency: V) -> Result<i32, String> {
    let text = match currency {
        Some(Value::String(s)) => s.clone(),
        c => tostr(c),
    };
    if !alpha3_upper(&text) {
        return Err(format!("currency must be an ISO 4217 alpha-3 code, got {}", currency.map_or("undefined".to_string(), js_stringify)));
    }
    if let Some(Value::String(c)) = currency {
        if ZERO_DECIMAL.contains(&c.as_str()) {
            return Ok(0);
        }
        if THREE_DECIMAL.contains(&c.as_str()) {
            return Ok(3);
        }
        if FOUR_DECIMAL.contains(&c.as_str()) {
            return Ok(4);
        }
    }
    Ok(2)
}

/// A major-unit amount (`120.5` USD) to integer minor units (`12050`). Float drift (`0.1 + 0.2`) is refused rather than rounded away.
pub fn to_minor_units(major: V, currency: V) -> Result<Value, String> {
    let e = currency_exponent(currency)?;
    let m = match major {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite() && *f >= 0.0),
        _ => None,
    };
    let Some(m) = m else { return Err(format!("amount must be a finite non-negative number, got {}", tostr(major))) };
    let fixed = format!("{:.*}", e as usize, m.abs());
    if fixed.parse::<f64>().ok() != Some(m) {
        return Err(format!("amount {} is not exactly representable in {} minor units", tostr(major), tostr(currency)));
    }
    let digits: String = fixed.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_start_matches('0');
    let minor: u64 = if digits.is_empty() { 0 } else { digits.parse().unwrap_or(u64::MAX) };
    if digits.len() > 16 || minor as f64 > MAX_SAFE {
        return Err(format!("amount {} is outside the safe integer range in minor units", tostr(major)));
    }
    Ok(json!(minor))
}

/// Integer minor units to the major-unit number PCA budgets use (exact for any safe integer).
pub fn from_minor_units(minor: V, currency: V) -> Result<Value, String> {
    let e = currency_exponent(currency)?;
    if !safe_int(minor) || num_of(minor).is_some_and(|f| f < 0.0) || neg0(minor) {
        return Err(format!("minor-unit amount must be a non-negative safe integer, got {}", tostr(minor)));
    }
    Ok(jnum(num_of(minor).unwrap_or(0.0) / 10f64.powi(e)))
}

// ---- mandate validators: each returns the list of problems (empty = valid) --------------------------------------------------

type Each = fn(V, &str) -> Vec<String>;

fn merchant_problems(v: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec![format!("{at}: not an object")] };
    let mut p = Vec::new();
    if !nonempty_str(m.get("id")) {
        p.push(format!("{at}.id: required string"));
    }
    if !nonempty_str(m.get("name")) {
        p.push(format!("{at}.name: required string"));
    }
    if m.get("website").is_some() && !is_str(m.get("website")) {
        p.push(format!("{at}.website: must be a string"));
    }
    p
}

fn currency_ok(v: V) -> bool {
    some_str(v).is_some_and(alpha3_upper)
}

fn amount_problems(v: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec![format!("{at}: not an object")] };
    let mut p = Vec::new();
    if !is_nonneg_int(m.get("amount")) {
        p.push(format!("{at}.amount: must be a non-negative integer (minor units)"));
    }
    if !currency_ok(m.get("currency")) {
        p.push(format!("{at}.currency: must be an ISO 4217 alpha-3 code"));
    }
    p
}

fn instrument_problems(v: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec![format!("{at}: not an object")] };
    let mut p = Vec::new();
    if !nonempty_str(m.get("id")) {
        p.push(format!("{at}.id: required string"));
    }
    if !nonempty_str(m.get("type")) {
        p.push(format!("{at}.type: required string"));
    }
    if m.get("description").is_some() && !is_str(m.get("description")) {
        p.push(format!("{at}.description: must be a string"));
    }
    p
}

fn pisp_problems(v: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec![format!("{at}: not an object")] };
    ["legal_name", "brand_name", "domain_name"].iter().filter(|k| !nonempty_str(m.get(**k))).map(|k| format!("{at}.{k}: required string")).collect()
}

fn time_problems(m: &Map<String, Value>) -> Vec<String> {
    ["iat", "exp"].iter().filter(|k| m.get(**k).is_some() && !is_nonneg_int(m.get(**k))).map(|k| format!("{k}: must be an integer epoch-seconds")).collect()
}

fn cnf_problems(v: V) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec!["cnf: must be { jwk }".into()] };
    if !is_rec(m.get("jwk")) {
        return vec!["cnf: must be { jwk }".into()];
    }
    match assert_p256_jwk(m.get("jwk"), "cnf.jwk") {
        Ok(_) => vec![],
        Err(e) => vec![e],
    }
}

fn pca_claim_problems(m: &Map<String, Value>) -> Vec<String> {
    if m.get(PCA_CLAIM).is_some() && !is_rec(m.get(PCA_CLAIM)) {
        vec![format!("{PCA_CLAIM}: must be an object")]
    } else {
        vec![]
    }
}

fn list_problems(v: V, at: &str, each: Each) -> Vec<String> {
    let Some(Value::Array(a)) = v else { return vec![format!("{at}: must be an array")] };
    a.iter().enumerate().flat_map(|(i, x)| each(Some(x), &format!("{at}[{i}]"))).collect()
}

fn payment_constraint_problems(c: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = c.filter(|c| is_str(c.get("type"))) else { return vec![format!("{at}: constraint must be an object with a string type")] };
    let t = m["type"].as_str().unwrap_or("");
    let mut p = Vec::new();
    match t {
        "payment.agent_recurrence" => {
            if !some_str(m.get("frequency")).is_some_and(|f| FREQUENCIES.contains(&f)) {
                p.push(format!("{at}.frequency: not a known frequency"));
            }
            let mo = m.get("max_occurrences");
            if mo.is_some() && !(is_int(mo) && num_of(mo).is_some_and(|f| f > 0.0)) {
                p.push(format!("{at}.max_occurrences: must be a positive integer"));
            }
            p
        }
        "payment.allowed_payees" => list_problems(m.get("allowed"), &format!("{at}.allowed"), merchant_problems),
        "payment.allowed_payment_instruments" => list_problems(m.get("allowed"), &format!("{at}.allowed"), instrument_problems),
        "payment.allowed_pisps" => list_problems(m.get("allowed"), &format!("{at}.allowed"), pisp_problems),
        "payment.amount_range" => {
            if !currency_ok(m.get("currency")) {
                p.push(format!("{at}.currency: must be an ISO 4217 alpha-3 code"));
            }
            if !is_nonneg_int(m.get("max")) {
                p.push(format!("{at}.max: must be a non-negative integer (minor units)"));
            }
            if m.get("min").is_some() && !is_nonneg_int(m.get("min")) {
                p.push(format!("{at}.min: must be a non-negative integer (minor units)"));
            }
            if is_int(m.get("max")) && is_int(m.get("min")) && num_of(m.get("min")) > num_of(m.get("max")) {
                p.push(format!("{at}: min exceeds max"));
            }
            p
        }
        "payment.budget" => {
            if !currency_ok(m.get("currency")) {
                p.push(format!("{at}.currency: must be an ISO 4217 alpha-3 code"));
            }
            let mx = m.get("max");
            if !is_num(mx) || !finite(mx) || num_of(mx).is_some_and(|f| f < 0.0) {
                p.push(format!("{at}.max: must be a non-negative number (major units)"));
            }
            p
        }
        "payment.execution_date" => {
            ["not_before", "not_after"].iter().filter(|k| m.get(**k).is_some() && !is_str(m.get(**k))).map(|k| format!("{at}.{k}: must be a string")).collect()
        }
        "payment.reference" => {
            if nonempty_str(m.get("conditional_transaction_id")) {
                vec![]
            } else {
                vec![format!("{at}.conditional_transaction_id: required string")]
            }
        }
        _ => vec![format!("{at}: unknown constraint type {t}")],
    }
}

fn acceptable_item_problems(x: V, ax: &str) -> Vec<String> {
    let Some(Value::Object(m)) = x else { return vec![format!("{ax}: not an object")] };
    ["id", "title"].iter().filter(|k| !nonempty_str(m.get(**k))).map(|k| format!("{ax}.{k}: required string")).collect()
}

fn checkout_constraint_problems(c: V, at: &str) -> Vec<String> {
    let Some(Value::Object(m)) = c.filter(|c| is_str(c.get("type"))) else { return vec![format!("{at}: constraint must be an object with a string type")] };
    match m["type"].as_str().unwrap_or("") {
        "checkout.allowed_merchants" => list_problems(m.get("allowed"), &format!("{at}.allowed"), merchant_problems),
        "checkout.line_items" => {
            let Some(Value::Array(items)) = m.get("items").filter(|i| i.as_array().is_some_and(|a| !a.is_empty())) else {
                return vec![format!("{at}.items: must be a non-empty array")];
            };
            let mut out = Vec::new();
            for (i, it) in items.iter().enumerate() {
                let a = format!("{at}.items[{i}]");
                let Value::Object(im) = it else {
                    out.push(format!("{a}: not an object"));
                    continue;
                };
                if !nonempty_str(im.get("id")) {
                    out.push(format!("{a}.id: required string"));
                }
                if !is_int(im.get("quantity")) || num_of(im.get("quantity")).is_some_and(|q| q <= 0.0) {
                    out.push(format!("{a}.quantity: must be a positive integer"));
                }
                out.extend(list_problems(im.get("acceptable_items"), &format!("{a}.acceptable_items"), acceptable_item_problems));
            }
            out
        }
        t => vec![format!("{at}: unknown constraint type {t}")],
    }
}

fn vct_problem(m: &Map<String, Value>, want: &str) -> Vec<String> {
    if seq(m.get("vct"), Some(&json!(want))) {
        vec![]
    } else {
        vec![format!("vct: must be {want}")]
    }
}

fn has_type(constraints: V, t: &str) -> bool {
    matches!(constraints, Some(Value::Array(a)) if a.iter().any(|c| is_rec(Some(c)) && seq(c.get("type"), Some(&json!(t)))))
}

pub fn open_payment_mandate_problems(v: V) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec!["mandate: not an object".into()] };
    let mut p = vct_problem(m, VCT_PAYMENT_OPEN);
    p.extend(time_problems(m));
    p.extend(cnf_problems(m.get("cnf")));
    p.extend(pca_claim_problems(m));
    p.extend(list_problems(m.get("constraints"), "constraints", payment_constraint_problems));
    if matches!(m.get("constraints"), Some(Value::Array(_))) && !has_type(m.get("constraints"), "payment.reference") {
        p.push("constraints: must contain a payment.reference constraint".into());
    }
    if m.get("payee").is_some() {
        p.extend(merchant_problems(m.get("payee"), "payee"));
    }
    if m.get("payment_amount").is_some() {
        p.extend(amount_problems(m.get("payment_amount"), "payment_amount"));
    }
    if m.get("payment_instrument").is_some() {
        p.extend(instrument_problems(m.get("payment_instrument"), "payment_instrument"));
    }
    if m.get("pisp").is_some() {
        p.extend(pisp_problems(m.get("pisp"), "pisp"));
    }
    if m.get("execution_date").is_some() && !is_str(m.get("execution_date")) {
        p.push("execution_date: must be a string".into());
    }
    if m.get("risk_data").is_some() && !is_rec(m.get("risk_data")) {
        p.push("risk_data: must be an object".into());
    }
    p
}

pub fn payment_mandate_problems(v: V) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec!["mandate: not an object".into()] };
    let mut p = vct_problem(m, VCT_PAYMENT);
    p.extend(time_problems(m));
    p.extend(pca_claim_problems(m));
    if !nonempty_str(m.get("transaction_id")) {
        p.push("transaction_id: required string".into());
    }
    p.extend(merchant_problems(m.get("payee"), "payee"));
    p.extend(amount_problems(m.get("payment_amount"), "payment_amount"));
    p.extend(instrument_problems(m.get("payment_instrument"), "payment_instrument"));
    if m.get("pisp").is_some() {
        p.extend(pisp_problems(m.get("pisp"), "pisp"));
    }
    if m.get("execution_date").is_some() && !is_str(m.get("execution_date")) {
        p.push("execution_date: must be a string".into());
    }
    if m.get("risk_data").is_some() && !is_rec(m.get("risk_data")) {
        p.push("risk_data: must be an object".into());
    }
    p
}

pub fn open_checkout_mandate_problems(v: V) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec!["mandate: not an object".into()] };
    let mut p = vct_problem(m, VCT_CHECKOUT_OPEN);
    p.extend(time_problems(m));
    p.extend(cnf_problems(m.get("cnf")));
    p.extend(pca_claim_problems(m));
    p.extend(list_problems(m.get("constraints"), "constraints", checkout_constraint_problems));
    if matches!(m.get("constraints"), Some(Value::Array(_))) && !has_type(m.get("constraints"), "checkout.line_items") {
        p.push("constraints: must contain a checkout.line_items constraint".into());
    }
    p
}

pub fn checkout_mandate_problems(v: V) -> Vec<String> {
    let Some(Value::Object(m)) = v else { return vec!["mandate: not an object".into()] };
    let mut p = vct_problem(m, VCT_CHECKOUT);
    p.extend(time_problems(m));
    p.extend(pca_claim_problems(m));
    if !nonempty_str(m.get("checkout_jwt")) {
        p.push("checkout_jwt: required string".into());
    }
    if !nonempty_str(m.get("checkout_hash")) {
        p.push("checkout_hash: required string".into());
    }
    p
}

/// `assertValid(v, problems, what)`: the value itself when it has no problems.
pub fn assert_valid(v: V, problems: fn(V) -> Vec<String>, what: &str) -> Result<Value, String> {
    let p = problems(v);
    if p.is_empty() {
        Ok(clone_or_null(v))
    } else {
        Err(format!("{what}: {}", p.join("; ")))
    }
}

// ---- constraint evaluation ---------------------------------------------------------------------------------------------------

pub fn merchant_matches(candidate: V, target: V) -> Result<bool, String> {
    let (cid, tid) = (prop(candidate, "id")?, prop(target, "id")?);
    if truthy(cid) && truthy(tid) {
        return Ok(seq(cid, tid));
    }
    let (cn, cw) = (prop(candidate, "name")?, prop(candidate, "website")?);
    Ok(truthy(cn) && truthy(cw) && seq(cn, prop(target, "name")?) && seq(cw, prop(target, "website")?))
}

fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(sort_keys).collect()),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            Value::Object(keys.into_iter().map(|k| (k.clone(), sort_keys(&m[k.as_str()]))).collect())
        }
        o => o.clone(),
    }
}

/// `JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b))`; two undefined values are equal.
fn same_json(a: V, b: V) -> bool {
    a.map(|x| js_stringify(&sort_keys(x))) == b.map(|x| js_stringify(&sort_keys(x)))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Epoch ms of an RFC 3339 instant, or `None`. STRICT and independent of the host time zone: `YYYY-MM-DD` (UTC midnight) or
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, with every component in range.
fn parse_instant(s: V) -> Option<i64> {
    let b = some_str(s)?.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = b.get(from..from + n)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    let day = days_from_civil(y, mo, d) * 86_400_000;
    if b.len() == 10 {
        return Some(day);
    }
    if b.len() < 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (h, mi, se) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let mut i = 19;
    let mut ms = 0;
    if b[i] == b'.' {
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let n = j - (i + 1);
        if !(1..=9).contains(&n) {
            return None;
        }
        let mut frac = b[i + 1..j.min(i + 4)].to_vec();
        while frac.len() < 3 {
            frac.push(b'0');
        }
        ms = frac.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0'));
        i = j;
    }
    let offset = match &b[i..] {
        b"Z" => 0,
        r if r.len() == 6 && (r[0] == b'+' || r[0] == b'-') && r[3] == b':' => {
            let (oh, om) = (digits(i + 1, 2)?, digits(i + 4, 2)?);
            if oh > 23 || om > 59 {
                return None;
            }
            (if r[0] == b'+' { 1 } else { -1 }) * (oh * 60 + om) * 60_000
        }
        _ => return None,
    };
    Some(day + ((h * 60 + mi) * 60 + se) * 1000 + ms - offset)
}

/// `Date.UTC`: the years 0..99 mean 1900..1999.
fn date_utc(y: i64, month0: i64, d: i64) -> i64 {
    let y = if (0..=99).contains(&y) { y + 1900 } else { y } + month0.div_euclid(12);
    days_from_civil(y, month0.rem_euclid(12) + 1, d) * 86_400_000
}

/// Start (epoch ms, UTC) of the calendar period of `frequency` that contains `ms`; `None` for an unknown frequency.
fn period_start(ms: f64, frequency: V) -> Option<i64> {
    const DAY: i64 = 86_400_000;
    let t = ms.trunc() as i64;
    let days = t.div_euclid(DAY);
    let (y, mo, d) = civil_from_days(days);
    let day = date_utc(y, mo - 1, d);
    let wd = (days + 4).rem_euclid(7);
    let week_start = day - ((wd + 6) % 7) * DAY;
    match some_str(frequency)? {
        "ON_DEMAND" => Some(0),
        "DAILY" => Some(day),
        "WEEKLY" => Some(week_start),
        "BIWEEKLY" => {
            let (week, epoch_monday) = (7 * DAY, -3 * DAY);
            Some(epoch_monday + (week_start - epoch_monday).div_euclid(2 * week) * 2 * week)
        }
        "MONTHLY" => Some(date_utc(y, mo - 1, 1)),
        "QUARTERLY" => Some(date_utc(y, ((mo - 1) / 3) * 3, 1)),
        "ANNUALLY" => Some(date_utc(y, 0, 1)),
        _ => None,
    }
}

/// A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it.
fn context_problem(c: V) -> Result<Option<String>, String> {
    let last = prop(c, "lastUsedDate")?;
    let ok = |v: V| is_nonneg_int(v);
    if !ok(prop(c, "totalAmount")?) || !ok(prop(c, "totalUses")?) || (last.is_some() && !ok(last)) {
        return Ok(Some("mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate".into()));
    }
    Ok(None)
}

/// The usage state / clock one payment-constraint evaluation reads.
#[derive(Clone, Copy, Default)]
pub struct PayCtx<'a> {
    pub open_checkout_hash: V<'a>,
    pub context: V<'a>,
    pub now: f64,
}

fn evaluate_payment(c: V, closed: V, o: &PayCtx) -> Result<Vec<String>, String> {
    let amt = prop(closed, "payment_amount")?;
    let t = prop(c, "type")?;
    let ctx = o.context;
    let is_t = |s: &str| matches!(t, Some(Value::String(x)) if x == s);
    if is_t("payment.amount_range") {
        let mut v = Vec::new();
        if !seq(prop(amt, "currency")?, prop(c, "currency")?) {
            v.push(format!("currency mismatch: expected {}, got {}", tostr(prop(c, "currency")?), tostr(prop(amt, "currency")?)));
        }
        let mn = prop(c, "min")?;
        if !js_to_number(prop(amt, "amount")?).is_finite() {
            v.push(format!("amount {} is not finite", tostr(prop(amt, "amount")?)));
        }
        if mn.is_some() && !ge(prop(amt, "amount")?, mn) {
            v.push(format!("amount {} below minimum {}", tostr(prop(amt, "amount")?), tostr(mn)));
        }
        if !le(prop(amt, "amount")?, prop(c, "max")?) {
            v.push(format!("amount {} exceeds maximum {}", tostr(prop(amt, "amount")?), tostr(prop(c, "max")?)));
        }
        return Ok(v);
    }
    if is_t("payment.allowed_payees") {
        let payee = prop(closed, "payee")?;
        for m in iter_list(prop(c, "allowed")?)? {
            if merchant_matches(Some(m), payee)? {
                return Ok(vec![]);
            }
        }
        return Ok(vec![format!("payee {} is not in the allowed list", tostr(prop(payee, "name")?))]);
    }
    if is_t("payment.allowed_payment_instruments") {
        let inst = prop(prop(closed, "payment_instrument")?, "id")?;
        for i in iter_list(prop(c, "allowed")?)? {
            if seq(prop(Some(i), "id")?, inst) {
                return Ok(vec![]);
            }
        }
        return Ok(vec![format!("payment instrument {} is not in the allowed list", tostr(inst))]);
    }
    if is_t("payment.allowed_pisps") {
        let p = prop(closed, "pisp")?;
        if !truthy(p) {
            return Ok(vec!["missing PISP in the closed mandate".into()]);
        }
        for a in iter_list(prop(c, "allowed")?)? {
            let a = Some(a);
            if seq(prop(a, "legal_name")?, prop(p, "legal_name")?)
                && seq(prop(a, "brand_name")?, prop(p, "brand_name")?)
                && seq(prop(a, "domain_name")?, prop(p, "domain_name")?)
            {
                return Ok(vec![]);
            }
        }
        return Ok(vec!["PISP is not in the allowed list".into()]);
    }
    if is_t("payment.reference") {
        let h = o.open_checkout_hash;
        if !truthy(h) {
            return Ok(vec!["openCheckoutHash is required to evaluate a payment.reference constraint".into()]);
        }
        return Ok(if seq(h, prop(c, "conditional_transaction_id")?) {
            vec![]
        } else {
            vec!["payment.reference does not match the open checkout mandate hash".into()]
        });
    }
    if is_t("payment.budget") {
        if !seq(prop(amt, "currency")?, prop(c, "currency")?) {
            return Ok(vec![format!("budget currency mismatch: expected {}, got {}", tostr(prop(c, "currency")?), tostr(prop(amt, "currency")?))]);
        }
        if !truthy(ctx) {
            return Ok(vec!["mandate context is required to evaluate a budget".into()]);
        }
        if let Some(bad) = context_problem(ctx)? {
            return Ok(vec![bad]);
        }
        // the official SDK converts the budget with `int(max * 100)` for every currency; this reads it the same way
        let scaled = js_to_number(prop(c, "max")?) * 100.0;
        let max_minor = if scaled.is_finite() { js_round(scaled) } else { f64::NAN };
        if !((scaled - max_minor).abs() <= 1e-6) {
            return Ok(vec!["budget.max is not a whole number of minor units".into()]);
        }
        let past = prop(ctx, "totalAmount")?;
        let spend = js_to_number(past) + js_to_number(prop(amt, "amount")?);
        if !(spend.is_finite() && spend <= max_minor) {
            return Ok(vec![format!("cumulative spend {} exceeds budget {} (past spend {})", jstr(spend), jstr(max_minor), tostr(past))]);
        }
        return Ok(vec![]);
    }
    if is_t("payment.agent_recurrence") {
        let mut v = Vec::new();
        if !some_str(prop(c, "frequency")?).is_some_and(|f| FREQUENCIES.contains(&f)) {
            return Ok(vec!["unknown recurrence frequency".into()]);
        }
        if truthy(ctx) {
            if let Some(bad) = context_problem(ctx)? {
                return Ok(vec![bad]);
            }
        }
        let mo = prop(c, "max_occurrences")?;
        if let Some(mo) = mo {
            if !truthy(ctx) {
                return Ok(vec!["mandate context is required to evaluate recurrence limits".into()]);
            }
            let uses = prop(ctx, "totalUses")?;
            if !lt(uses, Some(mo)) {
                v.push(format!("maximum occurrences exceeded: {} >= {}", tostr(uses), tostr(Some(mo))));
            }
        }
        let freq = prop(c, "frequency")?;
        if !seq(freq, Some(&json!("ON_DEMAND"))) {
            if !truthy(ctx) {
                return Ok(vec!["mandate context is required to evaluate recurrence frequency".into()]);
            }
            if let Some(last) = prop(ctx, "lastUsedDate")? {
                if !o.now.is_finite() {
                    // a non-finite clock has no period: the period reads as already used
                    v.push(format!("already used in the current {} period", tostr(freq)));
                } else if let Some(start) = period_start(o.now * 1000.0, freq) {
                    if !(js_to_number(Some(last)) * 1000.0 < start as f64) {
                        v.push(format!("already used in the current {} period", tostr(freq)));
                    }
                }
            }
        }
        return Ok(v);
    }
    if is_t("payment.execution_date") {
        let ed = prop(closed, "execution_date")?;
        let at = if ed.is_some() { parse_instant(ed).map(|x| x as f64) } else { Some(o.now * 1000.0) };
        let Some(at) = at.filter(|a| a.is_finite()) else { return Ok(vec![format!("execution_date {} is not a valid instant", tostr(ed))]) };
        let mut v = Vec::new();
        for (key, before) in [("not_before", true), ("not_after", false)] {
            let Some(bound) = prop(c, key)? else { continue };
            match parse_instant(Some(bound)) {
                None => v.push(format!("{key} {} is not a valid instant", tostr(Some(bound)))),
                Some(b) => {
                    if if before { !(at >= b as f64) } else { !(at <= b as f64) } {
                        v.push(format!("execution date is {} the allowed window ({key} {})", if before { "before" } else { "after" }, tostr(Some(bound))));
                    }
                }
            }
        }
        return Ok(v);
    }
    Ok(vec![format!("unknown constraint type {}", tostr(t))])
}

/// Violations of the open payment mandate's constraints and pre-set claims by `closed` (empty = satisfied).
pub fn check_payment_constraints(open: V, closed: V, o: &PayCtx) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    if let Some(payee) = prop(open, "payee")? {
        if !merchant_matches(Some(payee), prop(closed, "payee")?)? {
            v.push(format!("pre-set payee mismatch: expected {}, got {}", tostr(prop(Some(payee), "name")?), tostr(prop(prop(closed, "payee")?, "name")?)));
        }
    }
    for (member, label) in [("payment_amount", "payment_amount"), ("payment_instrument", "payment_instrument"), ("pisp", "pisp")] {
        if let Some(x) = prop(open, member)? {
            if !same_json(Some(x), prop(closed, member)?) {
                v.push(format!("pre-set {label} mismatch"));
            }
        }
    }
    if let Some(ed) = prop(open, "execution_date")? {
        if !seq(Some(ed), prop(closed, "execution_date")?) {
            v.push("pre-set execution_date mismatch".into());
        }
    }
    let constraints = iter_list(prop(open, "constraints")?)?;
    let types: Vec<V> = constraints.iter().map(|c| prop(Some(c), "type")).collect::<Result<Vec<V>, String>>()?;
    let has = |t: &str| types.iter().any(|x| matches!(x, Some(Value::String(s)) if s == t));
    if has("payment.agent_recurrence") {
        if !has("payment.amount_range") {
            v.push("payment.agent_recurrence requires a payment.amount_range constraint".into());
        }
        if !has("payment.budget") {
            v.push("payment.agent_recurrence requires a payment.budget constraint".into());
        }
    }
    for c in constraints {
        v.extend(evaluate_payment(Some(c), closed, o)?);
    }
    Ok(v)
}

/// Validate and project the checkout payload (`checkout_jwt`); refused with a descriptive message when malformed.
pub fn project_checkout(payload: V) -> Result<Value, String> {
    let bad = |m: String| -> Result<Value, String> { Err(format!("checkout_jwt payload: {m}")) };
    let (pid, cur, lis, totals) = (prop(payload, "id")?, prop(payload, "currency")?, prop(payload, "line_items")?, prop(payload, "totals")?);
    if !nonempty_str(pid) {
        return bad("id is required".into());
    }
    if !currency_ok(cur) {
        return bad("currency must be ISO 4217".into());
    }
    let Some(Value::Array(lis)) = lis.filter(|l| l.as_array().is_some_and(|a| !a.is_empty())) else {
        return bad("line_items must be a non-empty array".into());
    };
    let Some(Value::Array(totals)) = totals else { return bad("totals must be an array".into()) };
    let mut line_items = Vec::new();
    for (i, li) in lis.iter().enumerate() {
        let Value::Object(lm) = li else { return bad(format!("line_items[{i}] is malformed")) };
        let (Some(lid), Some(Value::Object(item))) = (lm.get("id").filter(|v| v.is_string()), lm.get("item")) else {
            return bad(format!("line_items[{i}] is malformed"));
        };
        let price = item.get("price");
        if !is_str(item.get("id")) || !is_str(item.get("title")) || !safe_int(price) || num_of(price).is_some_and(|p| p < 0.0) || neg0(price) {
            return bad(format!("line_items[{i}].item needs id, title and integer minor-unit price"));
        }
        let qty = lm.get("quantity");
        if !safe_int(qty) || num_of(qty).is_some_and(|q| q < 1.0) {
            return bad(format!("line_items[{i}].quantity must be a positive integer"));
        }
        line_items.push(json!({ "id": lid, "item": { "id": item["id"], "title": item["title"], "price": item["price"] }, "quantity": lm["quantity"] }));
    }
    let mut tt = Vec::new();
    for (i, t) in totals.iter().enumerate() {
        let ok = matches!(t, Value::Object(m) if is_str(m.get("type")) && safe_int(m.get("amount")) && !neg0(m.get("amount")));
        if !ok {
            return bad(format!("totals[{i}] is malformed"));
        }
        tt.push(json!({ "type": t["type"], "amount": t["amount"] }));
    }
    let mut out = Map::new();
    out.insert("id".into(), pid.cloned().unwrap_or(Value::Null));
    out.insert("currency".into(), cur.cloned().unwrap_or(Value::Null));
    out.insert("line_items".into(), Value::Array(line_items));
    out.insert("totals".into(), Value::Array(tt));
    if let Some(m) = prop(payload, "merchant")? {
        let Value::Object(mm) = m else { return bad("merchant needs id and name".into()) };
        if !is_str(mm.get("id")) || !is_str(mm.get("name")) {
            return bad("merchant needs id and name".into());
        }
        let mut merchant = Map::new();
        merchant.insert("id".into(), mm["id"].clone());
        merchant.insert("name".into(), mm["name"].clone());
        if is_str(mm.get("website")) {
            merchant.insert("website".into(), mm["website"].clone());
        }
        out.insert("merchant".into(), Value::Object(merchant));
    }
    Ok(Value::Object(out))
}

/// The checkout's single `total` entry in minor units, or `None` if absent / ambiguous.
pub fn checkout_total(c: V) -> Result<Option<Value>, String> {
    let totals = iter_list(prop(c, "totals")?)?;
    let mut t = Vec::new();
    for x in totals {
        if seq(prop(Some(x), "type")?, Some(&json!("total"))) {
            t.push(x);
        }
    }
    Ok(if t.len() == 1 { Some(prop(Some(t[0]), "amount")?.cloned().unwrap_or(Value::Null)) } else { None })
}

/// Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp): satisfied iff the flow equals both the required
/// and the carted total.
fn line_item_violations(cart: &[Value], reqs: &[Value]) -> Result<Vec<String>, String> {
    let mut skus: Vec<(Value, f64)> = Vec::new();
    for li in cart {
        let k = prop(prop(Some(li), "item")?, "id")?.cloned().unwrap_or(Value::Null);
        let q = js_to_number(prop(Some(li), "quantity")?);
        match skus.iter_mut().find(|(s, _)| seq(Some(s), Some(&k))) {
            Some(e) => e.1 += q,
            None => skus.push((k, q)),
        }
    }
    let (s_node, t_node) = (0usize, 1 + skus.len() + reqs.len());
    let mut cap: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); t_node + 1];
    let mut add = |u: usize, v: usize, c: f64| {
        *cap[u].entry(v).or_insert(0.0) += c;
        cap[v].entry(u).or_insert(0.0);
    };
    for (i, (_, q)) in skus.iter().enumerate() {
        add(s_node, 1 + i, *q);
    }
    for (j, r) in reqs.iter().enumerate() {
        add(1 + skus.len() + j, t_node, js_to_number(prop(Some(r), "quantity")?));
        let ok: Vec<V> = iter_list(prop(Some(r), "acceptable_items")?)?.iter().map(|a| prop(Some(a), "id")).collect::<Result<Vec<V>, String>>()?;
        for (i, (s, _)) in skus.iter().enumerate() {
            if ok.iter().any(|x| seq(Some(s), *x)) {
                add(1 + i, 1 + skus.len() + j, MAX_SAFE);
            }
        }
    }
    let mut flow = 0.0f64;
    loop {
        let mut parent: HashMap<usize, usize> = HashMap::from([(s_node, s_node)]);
        let mut queue = vec![s_node];
        let mut h = 0;
        while h < queue.len() && !parent.contains_key(&t_node) {
            let u = queue[h];
            h += 1;
            for (v, c) in cap[u].clone() {
                if c > 0.0 && !parent.contains_key(&v) {
                    parent.insert(v, u);
                    queue.push(v);
                }
            }
        }
        if !parent.contains_key(&t_node) {
            break;
        }
        let mut push = MAX_SAFE;
        let mut v = t_node;
        while v != s_node {
            push = push.min(cap[parent[&v]][&v]);
            v = parent[&v];
        }
        v = t_node;
        while v != s_node {
            let u = parent[&v];
            *cap[u].entry(v).or_insert(0.0) -= push;
            *cap[v].entry(u).or_insert(0.0) += push;
            v = u;
        }
        flow += push;
    }
    let mut required = 0.0;
    for r in reqs {
        required += js_to_number(prop(Some(r), "quantity")?);
    }
    let carted: f64 = skus.iter().map(|(_, q)| *q).sum();
    if flow == required && flow == carted {
        return Ok(vec![]);
    }
    Ok(vec![format!("line items do not satisfy the constraint: assigned {} of {} required and {} carted units", jstr(flow), jstr(required), jstr(carted))])
}

fn evaluate_checkout(c: V, checkout: &Value) -> Result<Vec<String>, String> {
    let t = prop(c, "type")?;
    if seq(t, Some(&json!("checkout.allowed_merchants"))) {
        let m = prop(Some(checkout), "merchant")?;
        if !truthy(m) {
            return Ok(vec!["missing merchant in the checkout".into()]);
        }
        for a in iter_list(prop(c, "allowed")?)? {
            if merchant_matches(Some(a), m)? {
                return Ok(vec![]);
            }
        }
        return Ok(vec![format!("merchant {} is not in the allowed list", tostr(prop(m, "name")?))]);
    }
    if !seq(t, Some(&json!("checkout.line_items"))) {
        return Ok(vec![format!("unknown constraint type {}", tostr(t))]);
    }
    let items = iter_list(prop(Some(checkout), "line_items")?)?;
    if items.is_empty() {
        return Ok(vec!["empty cart does not satisfy a line_items constraint".into()]);
    }
    line_item_violations(items, iter_list(prop(c, "items")?)?)
}

/// Violations of the open checkout mandate's constraints by `checkout` (empty = satisfied).
pub fn check_checkout_constraints(open: V, checkout: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for c in iter_list(prop(open, "constraints")?)? {
        out.extend(evaluate_checkout(Some(c), checkout)?);
    }
    Ok(out)
}

// ---- issuing open mandates ---------------------------------------------------------------------------------------------------

fn sign_root(c: &Value, mandate: &Value, b: &mut DisclosureBuilder) -> Result<String, String> {
    let element = b.element(mandate)?;
    let issuer = prop(Some(c), "issuer")?;
    let typ = prop(Some(c), "typ")?;
    let mut header = Map::new();
    header.insert("typ".into(), if nullish(typ) { json!(ROOT_TYP) } else { clone_or_null(typ) });
    if let Some(kid) = prop(issuer, "kid")? {
        header.insert("kid".into(), kid.clone());
    }
    if truthy(prop(issuer, "x5c")?) {
        header.insert("x5c".into(), clone_or_null(prop(issuer, "x5c")?));
    }
    let alg = prop(Some(c), "sdAlg")?;
    let payload = json!({ "delegate_payload": [element], "_sd_alg": if nullish(alg) { json!("sha-256") } else { clone_or_null(alg) } });
    sign_sd_jwt(Some(&Value::Object(header)), &payload, &b.disclosures, prop(issuer, "privateKey")?)
}

fn common_claims(c: &Value) -> Result<Map<String, Value>, String> {
    let jwk = assert_p256_jwk(prop(Some(c), "agentJwk")?, "agentJwk")?;
    let (iat, exp) = (prop(Some(c), "iat")?, prop(Some(c), "exp")?);
    if !safe_int(iat) || !safe_int(exp) || num_of(exp) <= num_of(iat) {
        return Err("open mandate: need integer iat < exp (epoch seconds)".into());
    }
    let mut out = Map::new();
    out.insert("cnf".into(), json!({ "jwk": { "crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"] } }));
    out.insert("iat".into(), clone_or_null(iat));
    out.insert("exp".into(), clone_or_null(exp));
    if truthy(prop(Some(c), "pca")?) {
        out.insert(PCA_CLAIM.into(), clone_or_null(prop(Some(c), "pca")?));
    }
    Ok(out)
}

fn sd_allowed(t: V, c: V, b: &mut DisclosureBuilder) -> Result<Value, String> {
    let mut allowed = Vec::new();
    for x in iter_list(prop(c, "allowed")?)? {
        allowed.push(b.element(x)?);
    }
    Ok(json!({ "type": clone_or_null(t), "allowed": allowed }))
}

fn sd_payment_constraint(c: V, b: &mut DisclosureBuilder) -> Result<Value, String> {
    let t = prop(c, "type")?;
    if matches!(some_str(t), Some("payment.allowed_payees" | "payment.allowed_payment_instruments")) {
        return sd_allowed(t, c, b);
    }
    Ok(clone_or_null(c))
}

fn sd_checkout_constraint(c: V, b: &mut DisclosureBuilder) -> Result<Value, String> {
    let t = prop(c, "type")?;
    if seq(t, Some(&json!("checkout.allowed_merchants"))) {
        return sd_allowed(t, c, b);
    }
    let mut items = Vec::new();
    for it in iter_list(prop(c, "items")?)? {
        let it = Some(it);
        let id = prop(it, "id")?;
        let mut acceptable = Vec::new();
        for x in iter_list(prop(it, "acceptable_items")?)? {
            acceptable.push(b.element(x)?);
        }
        items.push(compact(vec![("id", id), ("acceptable_items", Some(&Value::Array(acceptable))), ("quantity", prop(it, "quantity")?)]));
    }
    Ok(compact(vec![("type", t), ("items", Some(&Value::Array(items)))]))
}

fn assert_well_formed(wrapped: &Map<String, Value>, problems: fn(V) -> Vec<String>, what: &str, plain_constraints: V) -> Result<(), String> {
    let mut plain = wrapped.clone();
    plain.insert("constraints".into(), clone_or_null(plain_constraints));
    let p = problems(Some(&Value::Object(plain)));
    if p.is_empty() {
        Ok(())
    } else {
        Err(format!("{what}: {}", p.join("; ")))
    }
}

/// Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. `input`: issuer (`{privateKey (a private P-256
/// JWK), kid?, x5c?}`), agentJwk, iat, exp, constraints, payee?, paymentAmount?, paymentInstrument?, pisp?, executionDate?, pca?,
/// sdAlg?, typ?. `salt`: the salt source (`None`: fresh random salts).
pub fn issue_open_payment_mandate(input: &Value, salt: Option<Salt>) -> Result<String, String> {
    let mut b = disclosure_builder(prop(Some(input), "sdAlg")?, salt);
    let mut sd = Vec::new();
    for c in iter_list(prop(Some(input), "constraints")?)? {
        sd.push(sd_payment_constraint(Some(c), &mut b)?);
    }
    let mut mandate = Map::new();
    mandate.insert("vct".into(), json!(VCT_PAYMENT_OPEN));
    mandate.insert("constraints".into(), Value::Array(sd));
    for (member, key) in [("payee", "payee"), ("payment_amount", "paymentAmount"), ("payment_instrument", "paymentInstrument"), ("pisp", "pisp")] {
        if truthy(prop(Some(input), key)?) {
            mandate.insert(member.into(), clone_or_null(prop(Some(input), key)?));
        }
    }
    if let Some(ed) = prop(Some(input), "executionDate")? {
        mandate.insert("execution_date".into(), ed.clone());
    }
    mandate.extend(common_claims(input)?);
    assert_well_formed(&mandate, open_payment_mandate_problems, "open payment mandate", prop(Some(input), "constraints")?)?;
    sign_root(input, &Value::Object(mandate), &mut b)
}

/// Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT (same `input` as the payment form; `constraints`
/// are checkout constraints).
pub fn issue_open_checkout_mandate(input: &Value, salt: Option<Salt>) -> Result<String, String> {
    let mut b = disclosure_builder(prop(Some(input), "sdAlg")?, salt);
    let mut sd = Vec::new();
    for c in iter_list(prop(Some(input), "constraints")?)? {
        sd.push(sd_checkout_constraint(Some(c), &mut b)?);
    }
    let mut mandate = Map::new();
    mandate.insert("vct".into(), json!(VCT_CHECKOUT_OPEN));
    mandate.insert("constraints".into(), Value::Array(sd));
    mandate.extend(common_claims(input)?);
    assert_well_formed(&mandate, open_checkout_mandate_problems, "open checkout mandate", prop(Some(input), "constraints")?)?;
    sign_root(input, &Value::Object(mandate), &mut b)
}

// ---- presenting closed mandates (KB-SD-JWT hops) -----------------------------------------------------------------------------

fn present_hop(c: &Value, salt: Option<Salt>, build: &mut dyn FnMut(&mut DisclosureBuilder) -> Result<Value, String>) -> Result<String, String> {
    if !truthy(prop(Some(c), "aud")?) || !truthy(prop(Some(c), "nonce")?) {
        return Err("closed mandate: aud and nonce are required".into());
    }
    if !safe_int(prop(Some(c), "iat")?) {
        return Err("closed mandate: iat must be an integer".into());
    }
    let open = some_str(prop(Some(c), "open")?).ok_or("SD-JWT: empty")?;
    let prev = parse_sd_jwt_hop(open)?;
    let mut b = disclosure_builder(Some(&json!(prev.sd_alg)), salt);
    let mandate = build(&mut b)?;
    let element = b.element(&mandate)?;
    let mode = prop(Some(c), "hashMode")?;
    let mode_name = if nullish(mode) { "sd_hash".to_string() } else { js_str(mode.unwrap_or(&Value::Null)) };
    let mut payload = Map::new();
    payload.insert("delegate_payload".into(), json!([element]));
    payload.insert("iat".into(), clone_or_null(prop(Some(c), "iat")?));
    payload.insert("aud".into(), clone_or_null(prop(Some(c), "aud")?));
    payload.insert("nonce".into(), clone_or_null(prop(Some(c), "nonce")?));
    let hash = if mode_name == "sd_hash" { sd_hash_of(&prev, None)? } else { issuer_jwt_hash_of(&prev, None)? };
    payload.insert(mode_name, json!(hash));
    payload.insert("_sd_alg".into(), json!(prev.sd_alg));
    let agent_key = prop(prop(Some(c), "agentKey")?, "privateKey")?;
    let hop = sign_sd_jwt(Some(&json!({ "typ": "kb+sd-jwt" })), &Value::Object(payload), &b.disclosures, agent_key)?;
    Ok(format!("{open}~{hop}")) // hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~"
}

/// Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. `input`: open (the open token),
/// agentKey (`{privateKey (a private P-256 JWK)}`), aud, nonce, iat, transactionId, payee, paymentAmount, paymentInstrument,
/// pisp?, executionDate?, riskData?, exp?, pca?, hashMode?.
pub fn present_closed_payment(input: &Value, salt: Option<Salt>) -> Result<String, String> {
    present_hop(input, salt, &mut |_b| {
        let mut m = Map::new();
        m.insert("vct".into(), json!(VCT_PAYMENT));
        for (member, key) in
            [("transaction_id", "transactionId"), ("payee", "payee"), ("payment_amount", "paymentAmount"), ("payment_instrument", "paymentInstrument")]
        {
            if let Some(v) = prop(Some(input), key)? {
                m.insert(member.into(), v.clone());
            }
        }
        if truthy(prop(Some(input), "pisp")?) {
            m.insert("pisp".into(), clone_or_null(prop(Some(input), "pisp")?));
        }
        if let Some(ed) = prop(Some(input), "executionDate")? {
            m.insert("execution_date".into(), ed.clone());
        }
        if truthy(prop(Some(input), "riskData")?) {
            m.insert("risk_data".into(), clone_or_null(prop(Some(input), "riskData")?));
        }
        if let Some(e) = prop(Some(input), "exp")? {
            m.insert("exp".into(), e.clone());
        }
        if truthy(prop(Some(input), "pca")?) {
            m.insert(PCA_CLAIM.into(), clone_or_null(prop(Some(input), "pca")?));
        }
        let mandate = Value::Object(m);
        let p = payment_mandate_problems(Some(&mandate));
        if !p.is_empty() {
            return Err(format!("closed payment mandate: {}", p.join("; ")));
        }
        Ok(mandate)
    })
}

/// Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate (`input` as above with `checkoutJwt`).
pub fn present_closed_checkout(input: &Value, salt: Option<Salt>) -> Result<String, String> {
    present_hop(input, salt, &mut |b| {
        let prev_alg = parse_sd_jwt_hop(some_str(prop(Some(input), "open")?).ok_or("SD-JWT: empty")?)?.sd_alg;
        let jwt = prop(Some(input), "checkoutJwt")?.ok_or("canonical JSON cannot encode an undefined checkout_jwt")?;
        let sd = b.property("checkout_jwt", jwt)?;
        let hash = sd_digest(jwt.as_str().ok_or("digest input must be ASCII")?, &prev_alg)?;
        let mut mandate = Map::new();
        mandate.insert("_sd".into(), json!([sd]));
        mandate.insert("vct".into(), json!(VCT_CHECKOUT));
        mandate.insert("checkout_hash".into(), json!(hash));
        if let Some(e) = prop(Some(input), "exp")? {
            mandate.insert("exp".into(), e.clone());
        }
        if truthy(prop(Some(input), "pca")?) {
            mandate.insert(PCA_CLAIM.into(), clone_or_null(prop(Some(input), "pca")?));
        }
        let mut check = mandate.clone();
        check.insert("checkout_jwt".into(), jwt.clone());
        let p = checkout_mandate_problems(Some(&Value::Object(check)));
        if !p.is_empty() {
            return Err(format!("closed checkout mandate: {}", p.join("; ")));
        }
        Ok(Value::Object(mandate))
    })
}

// ---- verifying a delegation chain --------------------------------------------------------------------------------------------

/// Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`.
pub fn split_chain(token: &str) -> Result<Vec<String>, String> {
    if token.is_empty() {
        return Err("chain: empty".into());
    }
    let parts: Vec<&str> = token.split("~~").collect();
    if parts.len() > MAX_HOPS {
        return Err(format!("chain: more than {MAX_HOPS} hops"));
    }
    let last = parts.len() - 1;
    Ok(parts.iter().enumerate().map(|(i, p)| if i == last { p.to_string() } else { format!("{p}~") }).collect())
}

fn check_times(label: &str, o: &Value, now: f64, skew: f64) -> Result<(), String> {
    let (exp, iat) = (prop(Some(o), "exp")?, prop(Some(o), "iat")?);
    if exp.is_some() {
        if !safe_int(exp) || neg0(exp) {
            return Err(format!("{label}: exp must be an integer"));
        }
        if !(now.is_finite() && skew.is_finite() && now <= num_of(exp).unwrap_or(f64::NAN) + skew) {
            return Err(format!("{label}: expired at {}", tostr(exp)));
        }
    }
    if iat.is_some() {
        if !safe_int(iat) || neg0(iat) {
            return Err(format!("{label}: iat must be an integer"));
        }
        if !(now.is_finite() && skew.is_finite() && num_of(iat).unwrap_or(f64::NAN) <= now + skew) {
            return Err(format!("{label}: iat is in the future"));
        }
    }
    Ok(())
}

fn delegate_mandate(claims: &Value, label: &str) -> Result<Value, String> {
    let Some(Value::Array(dp)) = prop(Some(claims), "delegate_payload")? else { return Err(format!("{label}: delegate_payload missing")) };
    if dp.len() != 1 || !dp[0].is_object() {
        return Err(format!("{label}: delegate_payload must disclose exactly one mandate (got {})", dp.len()));
    }
    Ok(dp[0].clone())
}

fn cnf_jwk(mandate: &Value, label: &str) -> Result<Value, String> {
    let jwk = mandate.get("cnf").filter(|c| c.is_object()).and_then(|c| c.get("jwk")).filter(|j| j.is_object());
    let Some(jwk) = jwk else { return Err(format!("{label}: no cnf.jwk to delegate to")) };
    assert_p256_jwk(Some(jwk), &format!("{label} cnf.jwk"))
}

/// One verified hop.
#[derive(Debug, Clone)]
pub struct ChainHop {
    pub index: i64,
    pub kind: String,
    pub hop: Hop,
    pub claims: Value,
    pub mandate: Value,
}

impl ChainHop {
    /// The corpus projection `{index, kind, claims, mandate}`.
    pub fn to_value(&self) -> Value {
        json!({ "index": self.index, "kind": self.kind, "claims": self.claims, "mandate": self.mandate })
    }
}

/// What `verify_kb_hop` checks a hop against.
#[derive(Clone, Copy)]
pub struct KbOpts<'a> {
    pub terminal: bool,
    pub expected_audience: V<'a>,
    pub expected_nonce: V<'a>,
    pub now: f64,
    pub skew: f64,
}

/// Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). `prev_hop` / `prev_mandate`
/// are the preceding hop and its verified mandate. The returned hop has `index: -1`.
pub fn verify_kb_hop(hop: &Hop, prev_hop: &Hop, prev_mandate: &Value, o: &KbOpts, label: &str) -> Result<ChainHop, String> {
    let typ = hop.header.get("typ");
    let allowed: &[&str] = if o.terminal { &TYP_TERMINAL } else { &TYP_INTERMEDIATE };
    if !some_str(typ).is_some_and(|t| allowed.contains(&t)) {
        return Err(format!("{label}: typ must be one of {}", allowed.join(", ")));
    }
    if hop.header.contains_key("crit") {
        return Err(format!("{label}: crit headers are not supported"));
    }
    let key = cnf_jwk(prev_mandate, "preceding mandate")?;
    if !verify_hop_signature(hop, Some(&key))? {
        return Err(format!("{label}: signature does not verify under the preceding mandate's cnf.jwk"));
    }
    let claims = process_disclosures(&Value::Object(hop.payload.clone()), &hop.disclosures, &hop.sd_alg)?;
    let (has_sd, has_iss) = (claims.get("sd_hash").is_some(), claims.get("issuer_jwt_hash").is_some());
    if has_sd == has_iss {
        return Err(format!("{label}: exactly one of sd_hash / issuer_jwt_hash is required"));
    }
    let expected = if has_sd { sd_hash_of(prev_hop, None)? } else { issuer_jwt_hash_of(prev_hop, None)? };
    let name = if has_sd { "sd_hash" } else { "issuer_jwt_hash" };
    if !seq(claims.get(name), Some(&json!(expected))) {
        return Err(format!("{label}: {name} does not match the preceding hop"));
    }
    if claims.get("iat").is_none() {
        return Err(format!("{label}: iat is required"));
    }
    check_times(label, &claims, o.now, o.skew)?;
    let mandate = delegate_mandate(&claims, label)?;
    check_times(&format!("{label} mandate"), &mandate, o.now, o.skew)?;
    let has_cnf = mandate.get("cnf").is_some_and(Value::is_object);
    if o.terminal && has_cnf {
        return Err(format!("{label}: a terminal hop must not carry cnf"));
    }
    if !o.terminal && !has_cnf {
        return Err(format!("{label}: an intermediate hop requires cnf"));
    }
    if o.terminal {
        if o.expected_audience.is_none() || !seq(claims.get("aud"), o.expected_audience) {
            return Err(format!("{label}: aud mismatch"));
        }
        if o.expected_nonce.is_none() || !seq(claims.get("nonce"), o.expected_nonce) {
            return Err(format!("{label}: nonce mismatch"));
        }
    }
    Ok(ChainHop { index: -1, kind: if o.terminal { "terminal" } else { "intermediate" }.to_string(), hop: hop.clone(), claims, mandate })
}

/// The options of a chain verification (the reference's `resolveIssuerKey`, `resolveMerchantKey`, `expectedAudience`, ...).
#[derive(Clone, Default)]
pub struct ChainOpts<'a> {
    pub resolve_issuer_key: Option<KeyResolver<'a>>,
    pub resolve_merchant_key: Option<KeyResolver<'a>>,
    pub expected_audience: Option<Value>,
    pub expected_nonce: Option<Value>,
    pub now: Option<f64>,
    pub clock_skew_seconds: Option<f64>,
    pub open_checkout_hash: Option<Value>,
    pub context: Option<Value>,
    pub expected_transaction_id: Option<Value>,
}

/// A verified chain.
#[derive(Debug, Clone, Default)]
pub struct Chain {
    pub hops: Vec<ChainHop>,
    pub open: Option<Value>,
    pub closed: Option<Value>,
    pub checkout_jwt: Option<Value>,
    pub checkout: Option<Value>,
    pub open_hash: Option<String>,
}

impl Chain {
    /// The corpus projection of a verified chain.
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("ok".into(), json!(true));
        out.insert("hops".into(), Value::Array(self.hops.iter().map(ChainHop::to_value).collect()));
        if let (Some(o), Some(c)) = (&self.open, &self.closed) {
            out.insert("open".into(), o.clone());
            out.insert("closed".into(), c.clone());
        }
        if let (Some(j), Some(c)) = (&self.checkout_jwt, &self.checkout) {
            out.insert("checkoutJwt".into(), j.clone());
            out.insert("checkout".into(), c.clone());
        }
        if let Some(h) = &self.open_hash {
            out.insert("openHash".into(), json!(h));
        }
        Value::Object(out)
    }
}

/// A refused chain: the reason and, for constraint failures, the violations.
#[derive(Debug, Clone, Default)]
pub struct Fail {
    pub reason: String,
    pub violations: Vec<String>,
}

impl From<String> for Fail {
    fn from(reason: String) -> Self {
        Fail { reason, violations: Vec::new() }
    }
}

impl From<&str> for Fail {
    fn from(reason: &str) -> Self {
        Fail { reason: reason.to_string(), violations: Vec::new() }
    }
}

impl Fail {
    pub fn to_value(&self) -> Value {
        let mut out = json!({ "ok": false, "reason": self.reason });
        if !self.violations.is_empty() {
            out["violations"] = json!(self.violations);
        }
        out
    }
}

pub type ChainResult = Result<Chain, Fail>;

fn chain_hops(token: &str, o: &ChainOpts) -> Result<Vec<ChainHop>, String> {
    if !truthy(o.expected_audience.as_ref()) || !truthy(o.expected_nonce.as_ref()) {
        return Err("verify: expectedAudience and expectedNonce are required".into());
    }
    let now = o.now.unwrap_or_else(|| now_secs().floor());
    let skew = o.clock_skew_seconds.unwrap_or(60.0);
    let segments: Vec<Hop> = split_chain(token)?.iter().map(|s| parse_sd_jwt_hop(s)).collect::<Result<Vec<Hop>, String>>()?;
    let root = &segments[0];
    if root.header.contains_key("crit") {
        return Err("root: crit headers are not supported".into());
    }
    let resolver = o.resolve_issuer_key.ok_or("resolveIssuerKey is not a function")?;
    let issuer_key = resolver(&root.header)?;
    if !truthy(issuer_key.as_ref()) {
        return Err("root: no issuer key for this header".into());
    }
    if !verify_hop_signature(root, issuer_key.as_ref())? {
        return Err("root: signature does not verify under the issuer key".into());
    }
    let root_claims = process_disclosures(&Value::Object(root.payload.clone()), &root.disclosures, &root.sd_alg)?;
    check_times("root", &root_claims, now, skew)?;
    let root_mandate = delegate_mandate(&root_claims, "root")?;
    check_times("root mandate", &root_mandate, now, skew)?;
    let mut hops = vec![ChainHop { index: 0, kind: "root".into(), hop: root.clone(), claims: root_claims, mandate: root_mandate }];
    for i in 1..segments.len() {
        let kb =
            KbOpts { terminal: i == segments.len() - 1, expected_audience: o.expected_audience.as_ref(), expected_nonce: o.expected_nonce.as_ref(), now, skew };
        let mut v = verify_kb_hop(&segments[i], &hops[i - 1].hop, &hops[i - 1].mandate, &kb, &format!("hop {i}"))?;
        v.index = i as i64;
        hops.push(v);
    }
    Ok(hops)
}

/// Verify a whole chain: root signature, then every hop in order. Reports the reason instead of failing.
pub fn verify_delegation_chain(token: &str, o: &ChainOpts) -> ChainResult {
    Ok(Chain { hops: chain_hops(token, o)?, ..Chain::default() })
}

fn pair(hops: &[ChainHop]) -> Result<(&ChainHop, &ChainHop), String> {
    if hops.len() != 2 {
        return Err(format!("expected an open mandate followed by one closed mandate, got {} hop(s)", hops.len()));
    }
    Ok((&hops[0], &hops[1]))
}

fn require_open_expiry(m: &Value, label: &str) -> Result<(), String> {
    if safe_int(m.get("exp")) {
        Ok(())
    } else {
        Err(format!("{label}: an open mandate must carry exp"))
    }
}

fn problems_err(what: &str, p: Vec<String>) -> Result<(), String> {
    if p.is_empty() {
        Ok(())
    } else {
        Err(format!("{what}: {}", p.join("; ")))
    }
}

/// Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints.
pub fn verify_checkout_chain(token: &str, o: &ChainOpts) -> ChainResult {
    let hops = chain_hops(token, o)?;
    let (open_hop, closed_hop) = pair(&hops)?;
    let (open, closed) = (&open_hop.mandate, &closed_hop.mandate);
    problems_err("open checkout mandate", open_checkout_mandate_problems(Some(open)))?;
    require_open_expiry(open, "open checkout mandate")?;
    problems_err("closed checkout mandate", checkout_mandate_problems(Some(closed)))?;
    let jwt_text = closed["checkout_jwt"].as_str().unwrap_or("");
    if sd_digest(jwt_text, &closed_hop.hop.sd_alg)? != closed["checkout_hash"].as_str().unwrap_or("") {
        return Err("checkout_hash does not match checkout_jwt".to_string().into());
    }
    let jwt = parse_jwt(jwt_text, "checkout_jwt")?;
    let resolver = o.resolve_merchant_key.ok_or("resolveMerchantKey is not a function")?;
    let key = resolver(&jwt.header)?;
    if !truthy(key.as_ref()) {
        return Err("checkout_jwt: no merchant key for this header".to_string().into());
    }
    if !verify_jwt_es256(&jwt, key.as_ref())? {
        return Err("checkout_jwt: merchant signature does not verify".to_string().into());
    }
    let checkout = project_checkout(Some(&Value::Object(jwt.payload.clone())))?;
    let violations = check_checkout_constraints(Some(open), &checkout)?;
    if !violations.is_empty() {
        return Err(Fail { reason: format!("open checkout constraints violated: {}", violations.join("; ")), violations });
    }
    Ok(Chain {
        open: Some(open.clone()),
        closed: Some(closed.clone()),
        checkout_jwt: Some(closed["checkout_jwt"].clone()),
        checkout: Some(checkout),
        open_hash: Some(sd_hash_of(&open_hop.hop, None)?),
        hops: hops.clone(),
    })
}

/// Verify an open+closed payment chain and every open payment constraint. `o` also carries `open_checkout_hash` (the open checkout
/// mandate's `sd_hash`), `context` (usage state) and `expected_transaction_id` (the closed checkout's `checkout_hash`).
pub fn verify_payment_chain(token: &str, o: &ChainOpts) -> ChainResult {
    let hops = chain_hops(token, o)?;
    let (open_hop, closed_hop) = pair(&hops)?;
    let (open, closed) = (&open_hop.mandate, &closed_hop.mandate);
    problems_err("open payment mandate", open_payment_mandate_problems(Some(open)))?;
    require_open_expiry(open, "open payment mandate")?;
    problems_err("closed payment mandate", payment_mandate_problems(Some(closed)))?;
    if let Some(expected) = o.expected_transaction_id.as_ref() {
        if !seq(closed.get("transaction_id"), Some(expected)) {
            return Err("transaction_id does not match the checkout being settled".to_string().into());
        }
    }
    let now = o.now.unwrap_or_else(|| now_secs().floor());
    let ctx = PayCtx { open_checkout_hash: o.open_checkout_hash.as_ref(), context: o.context.as_ref().filter(|c| truthy(Some(*c))), now };
    let violations = check_payment_constraints(Some(open), Some(closed), &ctx)?;
    if !violations.is_empty() {
        return Err(Fail { reason: format!("open payment constraints violated: {}", violations.join("; ")), violations });
    }
    Ok(Chain {
        open: Some(open.clone()),
        closed: Some(closed.clone()),
        open_hash: Some(sd_hash_of(&open_hop.hop, None)?),
        hops: hops.clone(),
        ..Chain::default()
    })
}

/// The options of a whole purchase verification.
#[derive(Clone, Default)]
pub struct PurchaseOpts<'a> {
    pub resolve_issuer_key: Option<KeyResolver<'a>>,
    pub resolve_merchant_key: Option<KeyResolver<'a>>,
    /// `{expectedAudience, expectedNonce}` of the checkout chain.
    pub checkout: Option<Value>,
    /// `{expectedAudience, expectedNonce}` of the payment chain.
    pub payment: Option<Value>,
    pub context: Option<Value>,
    pub now: Option<f64>,
    pub clock_skew_seconds: Option<f64>,
}

/// A verified purchase: the checkout chain and the payment chain bound to it.
#[derive(Debug, Clone)]
pub struct Purchase {
    pub checkout: Chain,
    pub payment: Chain,
}

impl Purchase {
    pub fn to_value(&self) -> Value {
        json!({ "ok": true, "checkout": self.checkout.to_value(), "payment": self.payment.to_value() })
    }
}

fn chain_opts_of<'a>(o: &PurchaseOpts<'a>, sub: Option<&Value>) -> ChainOpts<'a> {
    let spread = spread_obj(sub);
    ChainOpts {
        resolve_issuer_key: o.resolve_issuer_key,
        resolve_merchant_key: o.resolve_merchant_key,
        expected_audience: spread.get("expectedAudience").cloned(),
        expected_nonce: spread.get("expectedNonce").cloned(),
        now: o.now,
        clock_skew_seconds: o.clock_skew_seconds,
        ..ChainOpts::default()
    }
}

/// Verify a complete purchase: the checkout chain, then the payment chain bound to it, and that the payment settles what the merchant
/// quoted (payee, currency, total). `Err` is the reason.
pub fn verify_purchase(checkout_token: &str, payment_token: &str, o: &PurchaseOpts) -> Result<Purchase, String> {
    let co = verify_checkout_chain(checkout_token, &chain_opts_of(o, o.checkout.as_ref())).map_err(|f| format!("checkout: {}", f.reason))?;
    let mut popts = chain_opts_of(o, o.payment.as_ref());
    popts.open_checkout_hash = co.open_hash.as_ref().map(|h| json!(h));
    popts.expected_transaction_id = co.closed.as_ref().and_then(|c| c.get("checkout_hash")).cloned();
    if truthy(o.context.as_ref()) {
        popts.context = o.context.clone();
    }
    let pay = verify_payment_chain(payment_token, &popts).map_err(|f| format!("payment: {}", f.reason))?;
    let checkout = co.checkout.as_ref().ok_or("checkout")?;
    let Some(total) = checkout_total(Some(checkout))? else { return Err("checkout: needs exactly one total entry".into()) };
    let closed = pay.closed.as_ref().ok_or("payment")?;
    let amt = prop(Some(closed), "payment_amount")?;
    if !seq(prop(amt, "currency")?, checkout.get("currency")) {
        return Err("payment currency differs from the checkout currency".into());
    }
    if !seq(prop(amt, "amount")?, Some(&total)) {
        return Err(format!("payment amount {} differs from the checkout total {}", tostr(prop(amt, "amount")?), tostr(Some(&total))));
    }
    let merchant = checkout.get("merchant");
    if !truthy(merchant) {
        return Err("checkout: no merchant to compare the payee with".into());
    }
    if !seq(prop(merchant, "id")?, prop(prop(Some(closed), "payee")?, "id")?) {
        return Err("payee differs from the checkout merchant".into());
    }
    Ok(Purchase { checkout: co, payment: pay })
}

// ---- the redeem ledger -------------------------------------------------------------------------------------------------------

/// The server-owned usage ledger of `redeem_purchase`: `reserve` answers the usage context (or the string `"replayed"`).
pub trait RedeemLedger {
    fn reserve(&self, open_mandate_hash: &str, transaction_id: &Value, amount_minor: &Value) -> Result<Option<Value>, String>;
    fn release(&self, open_mandate_hash: &str, transaction_id: &Value) -> Result<(), String>;
}

/// `verify_purchase` plus single use and server-owned cumulative state. The usage context comes from `ledger`, never from the caller;
/// a missing or failing ledger denies (`ledger_required`, `ledger_unavailable`, `replayed`). `o.context` is ignored.
pub fn redeem_purchase(checkout_token: &str, payment_token: &str, o: &PurchaseOpts, ledger: Option<&dyn RedeemLedger>) -> Result<Purchase, String> {
    let Some(ledger) = ledger else { return Err("ledger_required".into()) };
    // a zero context is the most permissive one for budget and recurrence, so a failure here is final
    let mut first_opts = o.clone();
    first_opts.context = Some(json!({ "totalAmount": 0, "totalUses": 0 }));
    let first = verify_purchase(checkout_token, payment_token, &first_opts)?;
    let open_hash = first.payment.open_hash.clone().unwrap_or_default();
    let closed = first.payment.closed.clone().unwrap_or(Value::Null);
    let tx_id = clone_or_null(prop(Some(&closed), "transaction_id")?);
    let amount = clone_or_null(prop(prop(Some(&closed), "payment_amount")?, "amount")?);
    let ctx = ledger.reserve(&open_hash, &tx_id, &amount).map_err(|_| "ledger_unavailable".to_string())?;
    if ctx.as_ref().and_then(Value::as_str) == Some("replayed") {
        return Err("replayed".into());
    }
    let mut final_opts = o.clone();
    final_opts.context = ctx;
    let result = verify_purchase(checkout_token, payment_token, &final_opts);
    if result.is_err() {
        let _ = ledger.release(&open_hash, &tx_id); // a failed release only ever over-counts spend
    }
    result
}

// ---- PCA terms -> AP2 open mandates ------------------------------------------------------------------------------------------

/// A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused.
fn minor_term(v: V, name: &str) -> Result<f64, String> {
    if !safe_int(v) || num_of(v).is_some_and(|f| f < 0.0) || neg0(v) {
        return Err(format!("PCA term {name} must be a non-negative integer in minor units, got {}", tostr(v)));
    }
    Ok(num_of(v).unwrap_or(0.0))
}

/// The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from.
pub fn pca_open_claim(mandate: V) -> Result<Value, String> {
    Ok(json!({ "v": PCA_BINDING_VERSION, "grant": to_json(prop(mandate, "grant")?)?, "terms": to_json(prop(mandate, "terms")?)? }))
}

fn open_expiry(terms: V, o: &Value) -> Result<Value, String> {
    let pe = prop(terms, "periodEnd")?;
    let period_end = pe.map(|p| (js_to_number(Some(p)) / 1000.0).floor());
    let exp = prop(Some(o), "exp")?.filter(|e| !e.is_null());
    let exp_v = match (exp, period_end) {
        (Some(e), _) => e.clone(),
        (None, Some(p)) => jnum(p),
        (None, None) => return Err("exp is required when the PCA terms have no period end".into()),
    };
    if let Some(p) = period_end {
        if !(js_to_number(Some(&exp_v)) <= p) {
            return Err("exp must not exceed the PCA period end".into());
        }
    }
    Ok(exp_v)
}

fn merchants_for(terms: V, merchants: V) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for mid in iter_list(prop(terms, "merchants")?)? {
        let mut found = None;
        for x in iter_list(merchants)? {
            if seq(prop(Some(x), "id")?, Some(mid)) {
                found = Some(x.clone());
                break;
            }
        }
        out.push(found.ok_or_else(|| format!("no merchant descriptor supplied for PCA merchant {}", tostr(Some(mid))))?);
    }
    Ok(out)
}

fn budget_reads(max: V, currency: V) -> Result<(f64, f64), String> {
    let e = currency_exponent(currency)?;
    if !is_num(max) || !finite(max) || num_of(max).is_some_and(|f| f < 0.0) {
        return Err(format!("budget.max must be a finite non-negative number, got {}", tostr(max)));
    }
    let m = num_of(max).unwrap_or(0.0);
    Ok(((m * 100.0).trunc(), js_round(m * 10f64.powi(e))))
}

/// What the two readers of an AP2 `budget.max` read, in minor units of `currency`: the SDK (`int(max * 100)`) and a major-unit reader.
pub fn ap2_budget_reads(max: V, currency: V) -> Result<Value, String> {
    let (sdk, major) = budget_reads(max, currency)?;
    Ok(json!({ "sdk": jnum(sdk), "major": jnum(major) }))
}

fn next_up(x: f64) -> f64 {
    f64::from_bits(x.to_bits() + 1)
}

/// The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as `int(max * 100)`
/// whatever the currency, a major-unit reader as `max * 10^exponent`: the value emitted never lets EITHER read more than the cap
/// (nudged up by at most a few ulps when `cap / divisor` falls just under the exact decimal). Refused when no exact representation exists.
pub fn ap2_budget_max(cap_minor: V, currency: V) -> Result<Value, String> {
    let cap = minor_term(cap_minor, "cumulativeCap")?;
    let e = currency_exponent(currency)?;
    let sdk_target = if e <= 2 { cap } else { (cap / 10f64.powi(e - 2)).floor() };
    let mut d = cap / 10f64.powi(e.max(2));
    for _ in 0..8 {
        if !(d > 0.0 && (d * 100.0).trunc() < sdk_target) {
            break;
        }
        d = next_up(d);
    }
    if (d * 100.0).trunc() != sdk_target || js_round(d * 10f64.powi(e)) > cap {
        return Err(format!("cumulativeCap {} {} has no exact AP2 budget.max representation", tostr(cap_minor), tostr(currency)));
    }
    Ok(jnum(d))
}

/// The AP2 open payment constraints a set of PCA terms denotes (PCA terms are integer minor units of the mandate currency;
/// `budget.max` is derived by [`ap2_budget_max`]).
pub fn payment_constraints_from_terms(terms: V, merchants: V, checkout_reference: V) -> Result<Vec<Value>, String> {
    let cur = prop(terms, "currency")?;
    let per_tx = minor_term(prop(terms, "perTransactionCap")?, "perTransactionCap")?;
    let budget_max = ap2_budget_max(prop(terms, "cumulativeCap")?, cur)?;
    let mut recurrence = json!({ "type": "payment.agent_recurrence", "frequency": "ON_DEMAND" });
    if let Some(mt) = prop(terms, "maxTransactionsPerPeriod")? {
        recurrence["max_occurrences"] = mt.clone();
    }
    let range = compact(vec![("type", Some(&json!("payment.amount_range"))), ("currency", cur), ("min", Some(&json!(0))), ("max", Some(&jnum(per_tx)))]);
    let budget = compact(vec![("type", Some(&json!("payment.budget"))), ("currency", cur), ("max", Some(&budget_max))]);
    Ok(vec![
        range,
        json!({ "type": "payment.allowed_payees", "allowed": merchants_for(terms, merchants)? }),
        compact(vec![("type", Some(&json!("payment.reference"))), ("conditional_transaction_id", checkout_reference)]),
        budget,
        recurrence,
    ])
}

fn from_pca_input(mandate: V, o: &Value, constraints: Vec<Value>) -> Result<Value, String> {
    let need = |k: &str| -> Result<Value, String> { prop(Some(o), k)?.cloned().ok_or_else(|| format!("{k} is required")) };
    let mut out = Map::new();
    out.insert("issuer".into(), need("issuer")?);
    out.insert("agentJwk".into(), need("agentJwk")?);
    out.insert("iat".into(), need("iat")?);
    out.insert("exp".into(), open_expiry(prop(mandate, "terms")?, o)?);
    out.insert("pca".into(), pca_open_claim(mandate)?);
    out.insert("constraints".into(), Value::Array(constraints));
    Ok(Value::Object(out))
}

/// Issue the open payment mandate for a PCA mandate (grant + terms), chained to `o.checkoutReference`. `o`: issuer, agentJwk,
/// merchants, iat, exp?, checkoutReference.
pub fn open_payment_mandate_from_pca(mandate: V, o: &Value, salt: Option<Salt>) -> Result<String, String> {
    let merchants = prop(Some(o), "merchants")?;
    let constraints = payment_constraints_from_terms(prop(mandate, "terms")?, merchants, prop(Some(o), "checkoutReference")?)?;
    issue_open_payment_mandate(&from_pca_input(mandate, o, constraints)?, salt)
}

/// Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items (`o.lineItems`).
pub fn open_checkout_mandate_from_pca(mandate: V, o: &Value, salt: Option<Salt>) -> Result<String, String> {
    let line_items = clone_or_null(prop(Some(o), "lineItems")?);
    let allowed = merchants_for(prop(mandate, "terms")?, prop(Some(o), "merchants")?)?;
    let constraints = vec![json!({ "type": "checkout.line_items", "items": line_items }), json!({ "type": "checkout.allowed_merchants", "allowed": allowed })];
    issue_open_checkout_mandate(&from_pca_input(mandate, o, constraints)?, salt)
}

// ---- the closed payment: PCActn bound to the AP2 mandate ---------------------------------------------------------------------

/// The value the PCActn's signed `nonce` must equal for these AP2 facts (transactionId, payeeId, amount, currency, instrumentId,
/// openHash, agentJkt).
pub fn pca_binding_nonce(f: V) -> Result<String, String> {
    let mut m = Map::new();
    m.insert("v".into(), json!(PCA_BINDING_VERSION));
    m.extend(spread_obj(f));
    Ok(format!("ap2:{}", hash_canonical(&Value::Object(m))?))
}

/// amount / cap, clamped to [0, 1] and rounded UP to 12 decimals (PCA's canonical encoding refuses numbers with more than 15
/// significant digits; rounding up can only raise the risk the threshold policy sees).
pub fn risk_ratio(amount: V, cap: V) -> Value {
    let (a, c) = (js_to_number(amount), js_to_number(cap));
    let r = if c > 0.0 { a / c } else { 1.0 };
    let up = (r * 1e12 - 1e-6).ceil() / 1e12;
    jnum(crate::payments::js_min(1.0, crate::payments::js_max(0.0, up)))
}

/// Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. `i`: mandate (the PCA mandate:
/// grant + terms), open (the open payment mandate token), agentJwk, audience, counter, transactionId, payee, amount (`{amount,
/// currency}`), instrumentId, category?, now? (epoch ms). `agent_secret` is the grant holder's 32-byte Ed25519 seed; `cosign` is called
/// over the built PCActn and returns the threshold shares.
pub fn build_pca_payment_binding(i: &Value, agent_secret: &[u8], cosign: Option<&dyn Fn(&Value) -> Result<Value, String>>) -> Result<Value, String> {
    let g = |k: &str| -> Result<Value, String> { prop(Some(i), k)?.cloned().ok_or_else(|| format!("{k} is required")) };
    let amount = g("amount")?;
    let major = minor_term(prop(Some(&amount), "amount")?, "amount")?;
    let payee = g("payee")?;
    let category = prop(Some(i), "category")?;
    let mut charge = Map::new();
    // an absent payee id is an `undefined` member in the reference's charge, which the strict canonical encoder refuses
    if prop(Some(&payee), "id")?.is_none() {
        return Err("canonicalize: unsupported type undefined".into());
    }
    charge.insert("merchant".into(), clone_or_null(prop(Some(&payee), "id")?));
    charge.insert("amount".into(), jnum(major));
    charge.insert("currency".into(), clone_or_null(prop(Some(&amount), "currency")?));
    if let Some(c) = category {
        charge.insert("category".into(), c.clone());
    }
    let mandate = g("mandate")?;
    let open_hash = sd_hash_of(&parse_sd_jwt_hop(some_str(prop(Some(i), "open")?).ok_or("SD-JWT: empty")?)?, None)?;
    let mut facts = Map::new();
    for (k, v) in [
        ("transactionId", prop(Some(i), "transactionId")?),
        ("payeeId", prop(Some(&payee), "id")?),
        ("amount", prop(Some(&amount), "amount")?),
        ("currency", prop(Some(&amount), "currency")?),
        ("instrumentId", prop(Some(i), "instrumentId")?),
    ] {
        if let Some(v) = v {
            facts.insert(k.into(), v.clone());
        }
    }
    facts.insert("openHash".into(), json!(open_hash));
    facts.insert("agentJkt".into(), json!(jwk_thumbprint(prop(Some(i), "agentJwk")?)?));
    let terms = prop(Some(&mandate), "terms")?;
    let risk = risk_ratio(Some(&jnum(major)), prop(terms, "perTransactionCap")?);
    let node_id = format!("ap2:{}", tostr(prop(Some(i), "transactionId")?));
    let charge = Value::Object(charge);
    let params = charge_params(&mandate, &charge)?;
    let node = charge_plan_node(&mandate, &charge, &node_id)?;
    let grant = g_of(&mandate, "grant")?;
    let seed: [u8; 32] = agent_secret.try_into().map_err(|_| "an Ed25519 seed is 32 bytes".to_string())?;
    let signer = KeyPair::from_seed(&seed);
    let counter =
        num_of(prop(Some(i), "counter")?).filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE).ok_or("build_pcactn: counter must be an integer")? as i64;
    let aud = some_str(prop(Some(i), "audience")?).unwrap_or("");
    let iat = match prop(Some(i), "now")? {
        Some(n) if finite(Some(n)) => num_of(Some(n)).unwrap_or(0.0) as i64,
        _ => (now_secs() * 1000.0) as i64,
    };
    let mut inputs = params.as_object().cloned().unwrap_or_default();
    inputs.insert("blastRadius".into(), risk.clone());
    let mut extra = Map::new();
    extra.insert("nonce".into(), json!(pca_binding_nonce(Some(&Value::Object(facts)))?));
    extra.insert("risk_claim".into(), json!({ "r": risk, "inputs": inputs }));
    let chain = [grant.clone()];
    let mut built = build_pcactn(&PcactnInput {
        grant: &grant,
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
    if let Some(cosign) = cosign {
        let shares = cosign(&built)?;
        if let Some(m) = built.as_object_mut() {
            m.insert("threshold".into(), shares);
        }
    }
    let mut claim_charge = Map::new();
    claim_charge.insert("amount".into(), jnum(major));
    claim_charge.insert("currency".into(), clone_or_null(prop(Some(&amount), "currency")?));
    if let Some(c) = category {
        claim_charge.insert("category".into(), c.clone());
    }
    Ok(json!({ "v": PCA_BINDING_VERSION, "charge": claim_charge, "pcactn": built }))
}

fn g_of(o: &Value, k: &str) -> Result<Value, String> {
    prop(Some(o), k)?.cloned().ok_or_else(|| format!("{k} is required"))
}

// ---- verification of the PCA side of a verified AP2 chain --------------------------------------------------------------------

/// Raised by [`verify_pca_binding`] when it lacks the server-held state the policy decision needs (`code`: `mandate_required` |
/// `charge_history_required`).
#[derive(Debug, Clone, PartialEq)]
pub struct PcaBindingError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for PcaBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// A verifier hook: `ctx -> {enforced, ok, reason?, t?}`.
pub type HookFn<'a> = &'a dyn Fn(&Value) -> Result<Value, String>;

/// The `hooks` of [`verify_pca_binding`].
#[derive(Clone, Copy, Default)]
pub struct PcaHooks<'a> {
    pub attestation: Option<HookFn<'a>>,
    pub threshold: Option<HookFn<'a>>,
    pub revocation: Option<HookFn<'a>>,
}

fn find_type<'a>(constraints: V<'a>, t: &str) -> Result<V<'a>, String> {
    for c in iter_list(constraints)? {
        if matches!(prop(Some(c), "type")?, Some(Value::String(s)) if s == t) {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

/// Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant).
fn constraints_within_terms(open: V, terms: V) -> Result<Option<String>, String> {
    let cur = prop(terms, "currency")?;
    let per_tx = minor_term(prop(terms, "perTransactionCap")?, "perTransactionCap")?;
    let constraints = prop(open, "constraints")?;
    let Some(rng) = find_type(constraints, "payment.amount_range")? else {
        return Ok(Some("open mandate has no amount_range to compare with the PCA per-transaction cap".into()));
    };
    if !seq(prop(Some(rng), "currency")?, cur) {
        return Ok(Some("amount_range currency differs from the PCA terms".into()));
    }
    if !(js_to_number(prop(Some(rng), "max")?) <= per_tx) {
        return Ok(Some(format!("amount_range.max {} exceeds the PCA per-transaction cap {}", tostr(prop(Some(rng), "max")?), jstr(per_tx))));
    }
    let payees = find_type(constraints, "payment.allowed_payees")?;
    if let Some(p) = payees {
        for m in iter_list(prop(Some(p), "allowed")?)? {
            if !includes(prop(terms, "merchants")?, prop(Some(m), "id")?) {
                return Ok(Some("allowed_payees names a merchant outside the PCA allowlist".into()));
            }
        }
    }
    if payees.is_none() {
        return Ok(Some("open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side".into()));
    }
    let Some(budget) = find_type(constraints, "payment.budget")? else {
        return Ok(Some("open mandate has no budget to compare with the PCA cumulative cap".into()));
    };
    if !seq(prop(Some(budget), "currency")?, cur) {
        return Ok(Some("budget exceeds the PCA cumulative cap".into()));
    }
    let (sdk, major) = budget_reads(prop(Some(budget), "max")?, cur)?;
    let cap_minor = minor_term(prop(terms, "cumulativeCap")?, "cumulativeCap")?;
    if !(sdk <= cap_minor && major <= cap_minor) {
        return Ok(Some("budget exceeds the PCA cumulative cap".into()));
    }
    let rec = find_type(constraints, "payment.agent_recurrence")?;
    let max_tx = prop(terms, "maxTransactionsPerPeriod")?;
    if let Some(mt) = max_tx {
        let mo = match rec {
            Some(r) => prop(Some(r), "max_occurrences")?,
            None => None,
        };
        if mo.is_none() || !le(mo, Some(mt)) {
            return Ok(Some("max_occurrences is missing or exceeds the PCA transaction limit".into()));
        }
    }
    if let Some(pe) = prop(terms, "periodEnd")? {
        let exp = prop(open, "exp")?;
        if exp.is_none() || !(js_to_number(exp) <= (js_to_number(Some(pe)) / 1000.0).floor()) {
            return Ok(Some("open mandate outlives the PCA period".into()));
        }
    }
    Ok(None)
}

fn xpca_ok(c: V, k1: &str, k2: &str) -> bool {
    matches!(c, Some(Value::Object(m)) if seq(m.get("v"), Some(&json!(PCA_BINDING_VERSION))) && is_rec(m.get(k1)) && is_rec(m.get(k2)))
}

fn binding_inner(i: &Value, mandate: &Value, recent: V, hooks: &PcaHooks, decide: &dyn Fn(&Value) -> Result<Value, String>) -> Result<Value, String> {
    let fail = |reason: String| -> Result<Value, String> { Ok(json!({ "ok": false, "reason": reason })) };
    let open = prop(Some(i), "open")?;
    let oc = prop(open, "x_pca")?;
    let Some(oc) = oc.filter(|c| xpca_ok(Some(c), "grant", "terms")) else {
        return fail("open mandate carries no x_pca grant".into());
    };
    let (grant, terms) = (&oc["grant"], &oc["terms"]);
    let Some(principal) = some_str(prop(Some(i), "expectedPrincipal")?) else { return fail("PCA grant: expectedPrincipal is required (fail closed)".into()) };
    let pins: Option<HashMap<String, String>> = match prop(Some(i), "pqPins")? {
        Some(Value::Object(m)) => Some(m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()),
        _ => None,
    };
    if let Err(why) = crate::verify_chain_policy(std::slice::from_ref(grant), Some(principal), None, pins.as_ref(), None) {
        return fail(format!("PCA grant: {why}"));
    }
    let Some(env) = crate::authorize::read_envelope(grant) else { return fail("PCA grant has no envelope".into()) };
    let preds = hash_canonical(env.get("predicates").unwrap_or(&Value::Null))?;
    let cavs = hash_canonical(env.get("caveats").unwrap_or(&Value::Null))?;
    if preds != hash_canonical(&crate::payments::mandate_predicates(terms)?)? || cavs != hash_canonical(&crate::payments::mandate_caveats(terms)?)? {
        return fail("x_pca terms do not match the grant envelope".into());
    }
    let rp = env.get("risk_policy");
    if !seq(prop(rp, "kappa")?, prop(Some(terms), "perTransactionCap")?) || !seq(prop(rp, "bMax")?, prop(Some(terms), "cumulativeCap")?) {
        return fail("x_pca terms do not match the grant risk policy".into());
    }
    if let Some(within) = constraints_within_terms(open, Some(terms))? {
        return fail(within);
    }

    let closed = prop(Some(i), "closed")?;
    let cc = prop(closed, "x_pca")?;
    let Some(cc) = cc.filter(|c| xpca_ok(Some(c), "pcactn", "charge")) else {
        return fail("closed mandate carries no x_pca PCActn".into());
    };
    let (pcactn, charge) = (&cc["pcactn"], &cc["charge"]);
    let (amt, payee) = (prop(closed, "payment_amount")?, prop(closed, "payee")?);
    if !seq(prop(Some(charge), "currency")?, prop(amt, "currency")?) || !seq(prop(Some(charge), "amount")?, prop(amt, "amount")?) {
        return fail("x_pca charge differs from the mandate payment_amount".into());
    }
    let cats = prop(Some(terms), "categories")?;
    let Some(cats) = cats.filter(|c| !c.is_null()) else {
        return Err(format!("Cannot read properties of {} (reading 'length')", if cats.is_none() { "undefined" } else { "null" }));
    };
    let category = prop(Some(charge), "category")?;
    let ncats = match cats {
        Value::Array(a) => a.len(),
        Value::String(s) => s.encode_utf16().count(),
        _ => 0,
    };
    if ncats > 0 && (!is_str(category) || !includes(Some(cats), category)) {
        return fail("x_pca charge lacks an allowed category".into());
    }

    // the t the threshold hook REPORTS it enforced: a hook built for a smaller t cannot satisfy a charge that needs more
    let enforce = prop(Some(i), "enforce")?.and_then(Value::as_object);
    if enforce.is_some_and(|e| e.keys().any(|k| k != "freshness" && k != "taint")) {
        return fail("PCActn: an enforce gate other than freshness and taint is not supported by this verifier (fail closed)".into());
    }
    // shortcut: the taint gate has no native verifier hook yet; it is refused rather than skipped
    if enforce.is_some_and(|e| e.get("taint").is_some_and(|t| !t.is_null())) {
        return fail("PCActn: enforce.taint is not supported by this verifier (fail closed)".into());
    }
    let freshness_gate = match enforce.and_then(|e| e.get("freshness")).filter(|f| !f.is_null()) {
        Some(f) => {
            let opt = |k: &str| f.get(k).filter(|v| !v.is_null()).map(|v| js_to_number(Some(v)));
            Some(crate::FreshnessGate {
                max_age_ms: opt("maxAgeMs").unwrap_or(f64::NAN),
                epoch_ms: opt("epochMs"),
                now: opt("now"),
                clock_skew_ms: opt("clockSkewMs"),
            })
        }
        None => None,
    };
    let now_o = prop(Some(i), "now")?.filter(|n| !n.is_null());
    let now_ms = match now_o {
        Some(n) => js_to_number(Some(n)),
        None => now_secs() * 1000.0,
    };
    let Some(audience) = some_str(prop(Some(i), "audience")?) else { return fail("PCActn: audience is required (fail closed)".into()) };
    let vopts = crate::VerifyOptions { insecure_skip_plan_root_check: true, freshness_gate, ..crate::VerifyOptions::default() };
    let core = crate::verify_pcactn_core_with(pcactn, grant, now_ms as i64, audience, &vopts);
    if !core.allow {
        return fail(format!("PCActn: {}", if core.reason.is_empty() { "rejected".to_string() } else { core.reason.clone() }));
    }
    let mut hook_ctx = json!({ "pcactn": pcactn, "grant": grant });
    if let Some(n) = now_o {
        hook_ctx["nowEpoch"] = n.clone();
    }
    let mut enforced_t: Option<f64> = None;
    for (name, hook) in [("attestation", hooks.attestation), ("threshold", hooks.threshold), ("revocation", hooks.revocation)] {
        let Some(hook) = hook else { continue };
        let res = hook(&hook_ctx)?;
        let r = Some(&res);
        if name == "threshold" && truthy(prop(r, "enforced")?) && truthy(prop(r, "ok")?) && is_num(prop(r, "t")?) {
            enforced_t = num_of(prop(r, "t")?);
        }
        if truthy(prop(r, "enforced")?) && !truthy(prop(r, "ok")?) {
            let why = prop(r, "reason")?;
            return fail(format!("PCActn: {name}: {}", if nullish(why) { "rejected".to_string() } else { tostr(why) }));
        }
    }

    let action = prop(Some(pcactn), "action")?;
    let payee_id = prop(payee, "id")?;
    if !seq(prop(action, "verb")?, Some(&json!("charge"))) || !seq(prop(action, "resource")?, Some(&json!(format!("merchant:{}", tostr(payee_id))))) {
        return fail("PCActn action is not a charge at this payee".into());
    }
    let (c_amount, c_currency) = (prop(Some(charge), "amount")?, prop(Some(charge), "currency")?);
    let (Some(c_amount), Some(c_currency)) = (c_amount, c_currency) else { return Err("canonical JSON cannot encode an undefined charge member".into()) };
    let mut params = Map::new();
    params.insert("amount".into(), c_amount.clone());
    params.insert("currency".into(), c_currency.clone());
    if is_str(category) {
        params.insert("category".into(), clone_or_null(category));
    }
    if !seq(prop(action, "params_digest")?, Some(&json!(crate::params_digest(Some(&Value::Object(params)))))) {
        return fail("PCActn params do not commit to the x_pca charge".into());
    }
    let agent_jwk = prop(prop(open, "cnf")?, "jwk")?;
    let mut facts = Map::new();
    for (k, v) in [
        ("transactionId", prop(closed, "transaction_id")?),
        ("payeeId", payee_id),
        ("amount", prop(amt, "amount")?),
        ("currency", prop(amt, "currency")?),
        ("instrumentId", prop(prop(closed, "payment_instrument")?, "id")?),
        ("openHash", prop(Some(i), "openHash")?),
    ] {
        facts.insert(k.into(), v.cloned().ok_or("canonical JSON cannot encode an undefined binding fact")?);
    }
    facts.insert("agentJkt".into(), json!(jwk_thumbprint(agent_jwk)?));
    if !seq(prop(Some(pcactn), "nonce")?, Some(&json!(pca_binding_nonce(Some(&Value::Object(facts)))?))) {
        return fail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key".into());
    }
    let per_tx = minor_term(prop(Some(terms), "perTransactionCap")?, "perTransactionCap")?;
    if !(js_to_number(prop(amt, "amount")?).is_finite() && js_to_number(prop(amt, "amount")?) <= per_tx) {
        return fail("payment exceeds the PCA per-transaction cap".into());
    }
    // the agent may not understate the risk of its own charge; a charge whose risk needs a human co-sign (t > 1) needs a threshold verifier
    let recomputed = num_of(Some(&risk_ratio(prop(amt, "amount")?, prop(Some(terms), "perTransactionCap")?))).unwrap_or(f64::NAN);
    let claimed = prop(prop(Some(pcactn), "risk_claim")?, "r")?;
    let Some(claimed_f) = num_of(claimed).filter(|c| *c >= recomputed - 1e-9) else { return fail("PCActn understates the risk of this charge".into()) };
    let need =
        crate::risk::required_threshold(claimed_f, num_of(prop(rp, "theta1")?).unwrap_or(f64::NAN), num_of(prop(rp, "theta2")?).unwrap_or(f64::NAN), false);
    let t = need.t as f64;
    if need.t > 1 && hooks.threshold.is_none() {
        return fail(format!("this charge needs a threshold of {} (human co-sign); supply hooks.threshold to verify it", need.t));
    }
    if need.t > 1 && !enforced_t.is_some_and(|e| e >= t) {
        return fail(format!(
            "this charge needs a threshold of {} but the threshold hook enforced t={}; build it with createThresholdVerifier({{ t: {} }})",
            need.t,
            enforced_t.map_or("unreported".to_string(), jstr),
            need.t
        ));
    }
    if !seq(prop(amt, "currency")?, prop(Some(terms), "currency")?) || !includes(prop(Some(terms), "merchants")?, payee_id) {
        return fail("payment currency or payee is outside the PCA terms".into());
    }

    let mandate_grant = mandate.get("grant").cloned().unwrap_or(Value::Null);
    if hash_canonical(&mandate_grant)? != hash_canonical(grant)? {
        return fail("the supplied PCA mandate is not the one in the open mandate".into());
    }
    // `grant` was verified above under the caller-pinned principal; the decision is bound to it
    let mut spend = Map::new();
    spend.insert("merchant".into(), clone_or_null(payee_id));
    spend.insert("amount".into(), clone_or_null(prop(amt, "amount")?));
    spend.insert("currency".into(), clone_or_null(prop(amt, "currency")?));
    if is_str(category) {
        spend.insert("category".into(), clone_or_null(category));
    }
    spend.insert("recentChargeTimes".into(), recent.filter(|r| !r.is_null()).cloned().unwrap_or_else(|| json!([])));
    if let Some(n) = now_o {
        spend.insert("now".into(), n.clone());
    }
    let decision = crate::payments::authorize_charge(mandate, &Value::Object(spend), grant, decide).map_err(|e| e.message)?;
    let outcome = decision.get("outcome").and_then(Value::as_str).unwrap_or("");
    if outcome == "deny" {
        let reasons: Vec<String> = decision.get("reasons").and_then(Value::as_array).map(|a| a.iter().map(|r| tostr(Some(r))).collect()).unwrap_or_default();
        return fail(format!("PCA denies this charge: {}", reasons.join("; ")));
    }
    if outcome == "step_up" && !enforced_t.is_some_and(|e| e >= 2.0) {
        return fail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced".into());
    }
    Ok(json!({ "ok": true, "pcactn": pcactn, "grant": grant, "terms": terms }))
}

/// Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent
/// with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience,
/// committing to exactly this AP2 charge). Run it after [`verify_payment_chain`]. `decide` is the PCA policy engine (the decision runs
/// on the server-held mandate, never skipped). `i`: open (the verified open mandate), closed, openHash, expectedPrincipal (REQUIRED),
/// audience, mandate (REQUIRED), recentChargeTimes (REQUIRED when the mandate limits the charge count), pqPins?, now? (epoch ms),
/// enforce? (`{freshness?}`; any other gate, `taint` included, is refused). Returns `{ok: true, pcactn, grant, terms}` or `{ok: false,
/// reason}`; `Err` when the mandate or history is missing.
pub fn verify_pca_binding(i: &Value, hooks: &PcaHooks, decide: &dyn Fn(&Value) -> Result<Value, String>) -> Result<Value, PcaBindingError> {
    let Some(mandate) = i.get("mandate").filter(|m| m.is_object()) else {
        return Err(PcaBindingError {
            code: "mandate_required",
            message: "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped".into(),
        });
    };
    let max_tx = mandate.get("terms").filter(|t| t.is_object()).and_then(|t| t.get("maxTransactionsPerPeriod"));
    let recent = i.get("recentChargeTimes");
    if max_tx.is_some() && !matches!(recent, Some(Value::Array(a)) if a.iter().all(|t| finite(Some(t)))) {
        return Err(PcaBindingError {
            code: "charge_history_required",
            message: "the mandate limits the charge count: pass recentChargeTimes from your own records".into(),
        });
    }
    Ok(binding_inner(i, mandate, recent, hooks, decide).unwrap_or_else(|e| json!({ "ok": false, "reason": e })))
}

// ---- settlement backends (structural only, no network) ---------------------------------------------------------------------

/// Integer minor units to an integer string of atomic units: scales by `10 ** (decimals - exponent)` exactly; when the asset has fewer
/// decimals than the currency the division must be exact. Refused otherwise (fail closed).
pub fn to_atomic_units(amount: V, decimals: V) -> Result<String, String> {
    let dec = num_of(decimals).filter(|d| is_num(decimals) && d.is_finite() && *d == d.trunc() && (0.0..=18.0).contains(d));
    let Some(dec) = dec else { return Err(format!("x402: decimals must be an integer in 0..18, got {}", tostr(decimals))) };
    let amt = prop(amount, "amount")?;
    if !safe_int(amt) || num_of(amt).is_some_and(|f| f < 0.0) || neg0(amt) {
        return Err(format!("x402: amount {} cannot be expressed in atomic units with {} decimals", tostr(amt), tostr(decimals)));
    }
    let decimals = dec as i32;
    let exp = currency_exponent(prop(amount, "currency")?)?;
    let minor = num_of(amt).unwrap_or(0.0) as u128;
    if decimals >= exp {
        return Ok((minor * 10u128.pow((decimals - exp) as u32)).to_string());
    }
    let div = 10u128.pow((exp - decimals) as u32);
    if minor % div != 0 {
        return Err(format!("x402: amount {} cannot be expressed in atomic units with {} decimals", tostr(amt), tostr(Some(&json!(decimals)))));
    }
    Ok((minor / div).to_string())
}

fn ctx_get<'a>(ctx: V<'a>, k: &str) -> V<'a> {
    match ctx {
        Some(Value::Object(m)) => m.get(k).filter(|v| !v.is_null()),
        _ => None,
    }
}

/// Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request header (standard base64 of
/// the JSON payment payload). The payload is a placeholder envelope, not a signed authorization: the real rail settles on-chain.
/// `ctx`: network?, decimals?, resourceUrl?, payTo?, asset?, maxTimeoutSeconds?.
pub fn x402_settlement(payment: V, ctx: V) -> Result<Value, String> {
    let network = ctx_get(ctx, "network").cloned().unwrap_or_else(|| json!("base-sepolia"));
    let amt = prop(payment, "payment_amount")?;
    let payee_id = prop(prop(payment, "payee")?, "id")?;
    let six = json!(6);
    let atomic = to_atomic_units(amt, Some(ctx_get(ctx, "decimals").unwrap_or(&six)))?;
    let tx = prop(payment, "transaction_id")?;
    let requirement = json!({
        "scheme": "exact",
        "network": network,
        "maxAmountRequired": atomic,
        "resource": ctx_get(ctx, "resourceUrl").cloned().unwrap_or_else(|| json!("")),
        "description": format!("AP2 payment mandate {}", tostr(tx)),
        "payTo": ctx_get(ctx, "payTo").cloned().unwrap_or_else(|| clone_or_null(payee_id)),
        "asset": ctx_get(ctx, "asset").cloned().unwrap_or_else(|| clone_or_null(prop(amt, "currency").ok().flatten())),
        "mimeType": "application/json",
        "maxTimeoutSeconds": ctx_get(ctx, "maxTimeoutSeconds").cloned().unwrap_or_else(|| json!(60)),
    });
    let inner = compact(vec![("transactionId", tx), ("amount", prop(amt, "amount")?), ("currency", prop(amt, "currency")?)]);
    let envelope = json!({ "x402Version": 1, "scheme": "exact", "network": network, "payload": inner });
    let x_payment = STANDARD.encode(js_stringify(&envelope).as_bytes());
    Ok(json!({
        "rail": "x402",
        "amount": clone_or_null(amt),
        "merchant": clone_or_null(payee_id),
        "payload": { "httpStatus": 402, "x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [requirement], "header": { "X-PAYMENT": x_payment } },
    }))
}

/// Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The token is the
/// mandate's payment instrument id, never a raw PAN. `ctx`: payTo? (becomes `on_behalf_of`).
pub fn stripe_spt_settlement(payment: V, ctx: V) -> Result<Value, String> {
    let inst = prop(payment, "payment_instrument")?;
    if !seq(prop(inst, "type")?, Some(&json!("shared_payment_token"))) {
        return Err(format!("stripe-spt: the payment instrument must be of type shared_payment_token, got {}", tostr(prop(inst, "type")?)));
    }
    let pa = prop(payment, "payment_amount")?;
    let currency = some_str(prop(pa, "currency")?).ok_or("currency.lower is not a function")?.to_lowercase();
    let mut payload = Map::new();
    if let Some(id) = prop(inst, "id")? {
        payload.insert("shared_payment_token".into(), id.clone());
    }
    if let Some(a) = prop(pa, "amount")? {
        payload.insert("amount".into(), a.clone());
    }
    payload.insert("currency".into(), json!(currency));
    if truthy(ctx_get(ctx, "payTo")) {
        payload.insert("on_behalf_of".into(), clone_or_null(ctx_get(ctx, "payTo")));
    }
    let payee_id = prop(prop(payment, "payee")?, "id")?;
    Ok(json!({ "rail": "stripe-spt", "amount": clone_or_null(pa), "merchant": clone_or_null(payee_id), "payload": payload }))
}
