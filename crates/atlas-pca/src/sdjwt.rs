//! SD-JWT serialization of a `PCActn` (IETF SD-JWT with selective disclosure of the capability claims and optional holder key
//! binding). A bridge, not a replacement: the PCActn's own signature stays the source of truth and rides as a disclosable claim.
//!
//! - [`issue_pca_sd_jwt`]: PCActn -> `<issuer JWT>~<Disclosure>~...~` (EdDSA over an Ed25519 seed).
//! - [`present`]: the holder keeps only the selected Disclosures and may append a KB-JWT.
//! - [`verify_pca_sd_jwt`]: canonical-spelling gate, issuer signature + claims, `_sd` matching (recursive), key binding.
//! - [`verify_recovered`]: rebuild the byte-identical PCActn from a verified result and run the core verifier on it.
//!
//! Options are JSON objects with the reference's camelCase member names; results are the reference's JSON shapes.
//! Keys: an Ed25519 key is raw bytes; a JWK is a JSON object. Where options take a raw key as JSON (`keyBinding.holderPublicKey`,
//! `keyBindingKey`), it is the base64url string of the 32 raw bytes.
use crate::jose::{
    assert_canonical_compact_jws, check_crit_b64, import_public_jwk, sign_ed25519_jws, verify_jws_signature, CanonicalJws, DEFAULT_MAX_JWS_BYTES,
};
use crate::oauth::truthy;
use crate::{b64_encode, js_stringify, Verdict, VerifyOptions};
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::collections::{HashMap, HashSet};

pub const SD_ALG: &str = "sha-256";
pub const PCA_SD_JWT_TYP: &str = "pca+sd-jwt";
pub const KB_JWT_TYP: &str = "kb+jwt";
pub const DEFAULT_SIGNING_ALG: &str = "EdDSA";
const JWS_ALG_INVALID: &str = "JWS \"alg\" (Algorithm) Header Parameter missing or invalid";

pub const PCA_CAPABILITY_CLAIMS: [&str; 22] = [
    "action",
    "grant_ref",
    "cap_chain",
    "plan",
    "attestation",
    "provenance",
    "freshness",
    "counter",
    "risk_claim",
    "nonce",
    "caution",
    "rationale_commitment",
    "progress_step",
    "prohibition_evidence",
    "tool_binding",
    "alg",
    "pq_pk",
    "sig",
    "pq_sig",
    "threshold",
    "zk_compliance",
    "bond_ref",
];

const STANDARD_MAPPED: [&str; 3] = ["aud", "iat", "exp"];
const CLEAR_DISCRIMINATOR: &str = "ver";
const CRITICAL_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "nbf", "cnf", "status"];
const RESERVED_CLAIMS: [&str; 8] = ["iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf"];
/// The JavaScript `Date` range (ms); a clock outside it is refused.
const MAX_DATE_MS: f64 = 8.64e15;

/// A verification key: a raw Ed25519 public key, or a public JWK (imported for the token's `alg`).
#[derive(Debug, Clone)]
pub enum SdJwtKey {
    Ed25519([u8; 32]),
    Jwk(Value),
}

impl SdJwtKey {
    /// A raw Ed25519 public key (`importEd25519PublicKey`): exactly 32 bytes.
    pub fn ed25519(raw: &[u8]) -> Result<Self, String> {
        Ok(SdJwtKey::Ed25519(raw.try_into().map_err(|_| "pca-sdjwt: Ed25519 public key must be 32 bytes".to_string())?))
    }
}

/// `importEd25519PrivateKey`: a 32-byte Ed25519 seed.
pub fn ed25519_seed(raw: &[u8]) -> Result<[u8; 32], String> {
    raw.try_into().map_err(|_| "pca-sdjwt: Ed25519 private seed must be 32 bytes".to_string())
}

/// `ed25519PublicJwk`: the OKP JWK of a raw 32-byte Ed25519 public key.
pub fn ed25519_public_jwk(raw: &[u8]) -> Result<Value, String> {
    if raw.len() != 32 {
        return Err("pca-sdjwt: Ed25519 public key must be 32 bytes".into());
    }
    Ok(json!({ "kty": "OKP", "crv": "Ed25519", "x": b64_encode(raw) }))
}

/// base64url(SHA-256(ASCII(s))), with Node's `ascii` encoding (the low byte of every UTF-16 unit).
fn sha256b64u(s: &str) -> String {
    let bytes: Vec<u8> = s.encode_utf16().map(|u| u as u8).collect();
    b64_encode(&sha2::Sha256::digest(&bytes))
}

fn is_jwk(v: &Value) -> bool {
    v.get("kty").is_some_and(Value::is_string) && v.is_object()
}

/// A JS number as `JSON.stringify` writes it: integral values as integers.
fn jnum(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9.0e18 {
        Value::from(x as i64)
    } else {
        serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number)
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

// ------------------------------------------------------------------------------------------------- issuance

fn leaf_holder_jwk(pc: &Map<String, Value>) -> Result<Value, String> {
    let holder = pc.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last()).and_then(|l| l.get("holder")).and_then(Value::as_str);
    match holder {
        Some(h) if !h.is_empty() => ed25519_public_jwk(&b64_lenient(h)),
        _ => Err("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing".into()),
    }
}

/// `Buffer.from(s, 'base64url')`: lenient (stops at the first character outside the alphabet, padding ignored).
fn b64_lenient(s: &str) -> Vec<u8> {
    let clean: String = s.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '+' || *c == '/').collect();
    let clean = clean.replace('+', "-").replace('/', "_");
    let usable = clean.len() - if clean.len() % 4 == 1 { 1 } else { 0 };
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean[..usable]).unwrap_or_default()
}

fn to_numeric_date(v: Option<&Value>, label: &str, ceil: bool) -> Result<f64, String> {
    let Some(ms) = v.and_then(Value::as_f64) else { return Err(format!("pca-sdjwt: PCActn.{label} must be a finite number (epoch ms)")) };
    Ok(if ceil { (ms / 1000.0).ceil() } else { (ms / 1000.0).floor() })
}

fn salt() -> Result<String, String> {
    let mut s = [0u8; 16];
    getrandom::getrandom(&mut s).map_err(|e| e.to_string())?;
    Ok(b64_encode(&s))
}

/// `issuePcaSdJwt(pcActn, {issuerKey, ...opts})`. `issuer_seed` is the issuer's 32-byte Ed25519 seed; `opts` members:
/// `disclosable` (claim names, default [`PCA_CAPABILITY_CLAIMS`]), `keyBinding` (`{}` = the chain leaf holder, or
/// `{holderPublicKey: JWK | base64url raw key}`), `iss`, `sub`, `typ`, `signingAlg` (only `EdDSA`).
pub fn issue_pca_sd_jwt(pcactn: &Value, issuer_seed: &[u8], opts: &Value) -> Result<String, String> {
    let seed = ed25519_seed(issuer_seed)?;
    let Some(pc) = pcactn.as_object() else { return Err("pca-sdjwt: pcActn must be an object".into()) };
    let chain = match pc.get("cap_chain") {
        Some(Value::Array(c)) if !c.is_empty() => c,
        _ => return Err("pca-sdjwt: pcActn.cap_chain must be a non-empty array".into()),
    };
    let Some(root_issuer) = chain[0].get("issuer").and_then(Value::as_str) else { return Err("pca-sdjwt: cap_chain root issuer is missing".into()) };
    let Some(leaf_holder) = chain[chain.len() - 1].get("holder").and_then(Value::as_str) else {
        return Err("pca-sdjwt: cap_chain leaf holder is missing".into());
    };
    let aud = match pc.get("aud") {
        Some(Value::String(a)) if !a.is_empty() => a.clone(),
        _ => return Err("pca-sdjwt: pcActn.aud is required".into()),
    };
    let opt = |k: &str| opts.get(k).filter(|v| !v.is_null());
    let iss = opt("iss").cloned().unwrap_or_else(|| json!(root_issuer));
    let sub = opt("sub").cloned().unwrap_or_else(|| json!(leaf_holder));
    let iat = to_numeric_date(pc.get("iat"), "iat", false)?;
    let mut exp = to_numeric_date(pc.get("exp"), "exp", true)?;
    if exp <= iat {
        exp = iat + 1.0; // exp strictly after iat even for sub-second lifetimes
    }
    let disclosable: HashSet<String> = match opt("disclosable") {
        None => PCA_CAPABILITY_CLAIMS.iter().map(|s| s.to_string()).collect(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        Some(Value::String(s)) => s.chars().map(String::from).collect(), // `new Set(string)`: its characters
        Some(_) => return Err("pca-sdjwt: disclosable must be an array of claim names".into()),
    };
    let alg = match opt("signingAlg") {
        None => DEFAULT_SIGNING_ALG,
        Some(Value::String(a)) if a == DEFAULT_SIGNING_ALG => DEFAULT_SIGNING_ALG,
        // jose refuses an alg that is not a non-empty string before the key is looked at
        Some(Value::String(a)) if a.is_empty() => return Err(JWS_ALG_INVALID.into()),
        Some(v) if !v.is_string() => return Err(JWS_ALG_INVALID.into()),
        Some(_) => return Err("pca-sdjwt: an Ed25519 issuer key signs only with EdDSA".into()),
    };
    let typ = opt("typ").cloned().unwrap_or_else(|| json!(PCA_SD_JWT_TYP));

    let mut payload = Map::new();
    payload.insert("iss".into(), iss);
    payload.insert("sub".into(), sub);
    payload.insert("aud".into(), json!(aud));
    payload.insert("iat".into(), jnum(iat));
    payload.insert("exp".into(), jnum(exp));
    if let Some(v) = pc.get(CLEAR_DISCRIMINATOR) {
        payload.insert(CLEAR_DISCRIMINATOR.into(), v.clone());
    }
    payload.insert("iat_ms".into(), pc["iat"].clone());
    payload.insert("exp_ms".into(), pc["exp"].clone());
    payload.insert("_sd_alg".into(), json!(SD_ALG));
    let (mut disclosures, mut sd) = (Vec::new(), Vec::new());
    for (key, value) in pc {
        if STANDARD_MAPPED.contains(&key.as_str()) || key == CLEAR_DISCRIMINATOR {
            continue;
        }
        if disclosable.contains(key) {
            let encoded = b64_encode(js_stringify(&json!([salt()?, key, value])).as_bytes());
            sd.push(json!(sha256b64u(&encoded)));
            disclosures.push(encoded);
        } else {
            payload.insert(key.clone(), value.clone()); // kept in the clear
        }
    }
    if !sd.is_empty() {
        payload.insert("_sd".into(), Value::Array(sd));
    }
    if truthy(opts.get("keyBinding")) {
        let jwk = match opts["keyBinding"].get("holderPublicKey") {
            None => leaf_holder_jwk(pc)?,
            Some(Value::String(raw)) => ed25519_public_jwk(&crate::decode_b64u_strict(raw, None).unwrap_or_default())?,
            Some(j) if is_jwk(j) => j.clone(),
            Some(_) => return Err("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key".into()),
        };
        payload.insert("cnf".into(), json!({ "jwk": jwk }));
    }
    let jwt = sign_ed25519_jws(&json!({ "alg": alg, "typ": typ }), &Value::Object(payload), &seed);
    let mut out = format!("{jwt}~");
    for d in disclosures {
        out.push_str(&d);
        out.push('~');
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------- parsing

struct Parsed {
    jwt: CanonicalJws,
    jwt_text: String,
    disclosures: Vec<String>,
    kb: Option<(CanonicalJws, String)>,
    head: String,
}

fn parse_sd_jwt(sdjwt: &Value) -> Result<Parsed, String> {
    let s = match sdjwt.as_str() {
        Some(s) if !s.is_empty() => s,
        _ => return Err("pca-sdjwt: empty SD-JWT".into()),
    };
    let segs: Vec<&str> = s.split('~').collect();
    if segs.len() < 2 {
        return Err("pca-sdjwt: malformed SD-JWT (missing ~ separator)".into());
    }
    if segs[0].is_empty() {
        return Err("pca-sdjwt: empty issuer JWT".into());
    }
    let last = segs[segs.len() - 1];
    let disclosures: Vec<String> = segs[1..segs.len() - 1].iter().map(|x| x.to_string()).collect();
    if disclosures.iter().any(String::is_empty) {
        return Err("pca-sdjwt: empty disclosure segment".into()); // `a~~b` is an aliasing vector
    }
    let jwt = assert_canonical_compact_jws(&json!(segs[0]), 3, DEFAULT_MAX_JWS_BYTES, true)?;
    let kb = if last.is_empty() { None } else { Some((assert_canonical_compact_jws(&json!(last), 3, DEFAULT_MAX_JWS_BYTES, true)?, last.to_string())) };
    let head = s[..s.len() - last.len()].to_string();
    Ok(Parsed { jwt, jwt_text: segs[0].to_string(), disclosures, kb, head })
}

fn decode_disclosure(encoded: &str) -> Result<Vec<Value>, String> {
    let parsed = crate::attest::jws::decode_canonical_b64url(encoded)
        .and_then(|b| crate::jose::parse_json_bytes(&b))
        .map_err(|_| "pca-sdjwt: disclosure is not canonical base64url strict JSON".to_string())?;
    let parts = match parsed {
        Value::Array(a) if a.len() == 2 || a.len() == 3 => a,
        _ => return Err("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair".into()),
    };
    if !parts[0].is_string() {
        return Err("pca-sdjwt: disclosure salt must be a string".into());
    }
    Ok(parts)
}

fn collect_digests(n: &Value, out: &mut Vec<String>) {
    match n {
        Value::Array(a) => a.iter().for_each(|x| collect_digests(x, out)),
        Value::Object(m) => {
            for (k, v) in m {
                match (k.as_str(), v) {
                    ("_sd", Value::Array(a)) => out.extend(a.iter().filter_map(Value::as_str).map(String::from)),
                    ("...", Value::String(s)) => out.push(s.clone()),
                    _ => collect_digests(v, out),
                }
            }
        }
        _ => {}
    }
}

// ------------------------------------------------------------------------------------------------- presentation

/// `present(sdjwt, selectClaims, {keyBinding})`: keep the Disclosures of the selected claims (and every Disclosure nested in
/// their values). `select` is iterated as a JS `Set` (an array of names; `null` = none; a string = its characters).
/// With `holder_seed`, a KB-JWT is appended: `kb` members `audience`, `nonce`, `iat` (default: now), `alg` (only `EdDSA`).
pub fn present(sdjwt: &Value, select: &Value, holder_seed: Option<&[u8]>, kb: &Value) -> Result<String, String> {
    let parsed = parse_sd_jwt(sdjwt)?;
    let keep: HashSet<String> = match select {
        Value::Null => HashSet::new(),
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        Value::String(s) => s.chars().map(String::from).collect(),
        _ => return Err("selectClaims is not iterable".into()),
    };
    let by_digest: HashMap<String, &String> = parsed.disclosures.iter().map(|e| (sha256b64u(e), e)).collect();
    let mut kept: HashSet<String> = HashSet::new();
    fn include(d: &str, by: &HashMap<String, &String>, kept: &mut HashSet<String>) -> Result<(), String> {
        let Some(enc) = by.get(d) else { return Ok(()) };
        if !kept.insert(d.to_string()) {
            return Ok(());
        }
        let parts = decode_disclosure(enc)?;
        let mut inner = Vec::new();
        collect_digests(&parts[parts.len() - 1], &mut inner);
        inner.iter().try_for_each(|x| include(x, by, kept))
    }
    let payload = parsed.jwt.payload.as_ref().expect("json payload");
    if let Some(Value::Array(sd)) = payload.get("_sd") {
        for d in sd.iter().filter_map(Value::as_str) {
            let Some(enc) = by_digest.get(d) else { continue };
            let parts = decode_disclosure(enc)?;
            if parts.len() == 3 && parts[1].as_str().is_some_and(|n| keep.contains(n)) {
                include(d, &by_digest, &mut kept)?;
            }
        }
    }
    for (k, v) in payload {
        if k != "_sd" && keep.contains(k) {
            let mut ds = Vec::new();
            collect_digests(v, &mut ds);
            ds.iter().try_for_each(|d| include(d, &by_digest, &mut kept))?;
        }
    }
    let mut head = parsed.jwt_text.clone();
    for e in parsed.disclosures.iter().filter(|e| kept.contains(&sha256b64u(e))) {
        head.push('~');
        head.push_str(e);
    }
    head.push('~');
    let Some(seed) = holder_seed else { return Ok(head) };
    let seed = ed25519_seed(seed)?;
    match kb.get("alg") {
        None | Some(Value::Null) => {}
        Some(Value::String(a)) if a == DEFAULT_SIGNING_ALG => {}
        Some(Value::String(a)) if a.is_empty() => return Err(JWS_ALG_INVALID.into()),
        Some(v) if !v.is_string() => return Err(JWS_ALG_INVALID.into()),
        Some(_) => return Err("pca-sdjwt: an Ed25519 holder key signs only with EdDSA".into()),
    }
    let mut p = Map::new();
    p.insert("iat".into(), kb.get("iat").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| jnum((now_ms() / 1000.0).floor())));
    if let Some(a) = kb.get("audience") {
        p.insert("aud".into(), a.clone());
    }
    p.insert("sd_hash".into(), json!(sha256b64u(&head)));
    if let Some(n) = kb.get("nonce") {
        p.insert("nonce".into(), n.clone());
    }
    let kb_jwt = sign_ed25519_jws(&json!({ "alg": DEFAULT_SIGNING_ALG, "typ": KB_JWT_TYP }), &Value::Object(p), &seed);
    Ok(head + &kb_jwt)
}

// ------------------------------------------------------------------------------------------------- JWT verification

/// The JOSE library's `secs()` time-period parser (`"10 seconds"`, `"2h"`, `"5 m ago"`).
fn secs(s: &str) -> Result<f64, String> {
    let bad = || "Invalid time period format".to_string();
    let lower = s.to_lowercase();
    let mut t = lower.as_str();
    let mut sign = 1.0;
    if let Some(r) = t.strip_prefix('+') {
        t = r;
    } else if let Some(r) = t.strip_prefix('-') {
        (sign, t) = (-1.0, r);
    }
    t = t.strip_prefix(' ').unwrap_or(t);
    let (mut t, mut suffix_sign) = (t, 1.0);
    if let Some(r) = t.strip_suffix(" ago") {
        (t, suffix_sign) = (r, -1.0);
    } else if let Some(r) = t.strip_suffix(" from now") {
        t = r;
    }
    let num_end = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let (num, unit) = t.split_at(num_end);
    let valid_num = !num.is_empty() && num.split('.').count() <= 2 && num.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !valid_num {
        return Err(bad());
    }
    let value: f64 = num.parse().map_err(|_| bad())?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit);
    let mult = match unit {
        "sec" | "secs" | "second" | "seconds" | "s" => 1.0,
        "minute" | "minutes" | "min" | "mins" | "m" => 60.0,
        "hour" | "hours" | "hr" | "hrs" | "h" => 3600.0,
        "day" | "days" | "d" => 86400.0,
        "week" | "weeks" | "w" => 604800.0,
        "year" | "years" | "yr" | "yrs" | "y" => 31_557_600.0,
        _ => return Err(bad()),
    };
    let n = (value * mult).round();
    Ok(if sign < 0.0 || suffix_sign < 0.0 { -n } else { n })
}

pub(crate) struct Claims<'a> {
    pub(crate) audience: Option<&'a Value>,
    pub(crate) tolerance: Option<&'a Value>,
    pub(crate) now_sec: f64,
}

pub(crate) fn tolerance_of(t: Option<&Value>) -> Result<f64, String> {
    match t {
        None => Ok(0.0),
        Some(Value::Number(n)) => Ok(n.as_f64().unwrap_or(0.0)),
        Some(Value::String(s)) => secs(s),
        Some(_) => Err("Invalid clockTolerance option type".into()),
    }
}

/// `checkAudiencePresence` with the reference library's JavaScript semantics for an option that is not a string or array.
fn audience_ok(aud: Option<&Value>, opt: &Value) -> Result<bool, String> {
    let eq = |a: &Value, b: &Value| a == b && !a.is_object() && !a.is_array();
    match (aud, opt) {
        (Some(Value::String(a)), Value::String(o)) => Ok(a == o),
        (Some(a @ Value::String(_)), Value::Array(o)) => Ok(o.iter().any(|x| eq(x, a))),
        (Some(Value::Array(a)), Value::String(o)) => Ok(a.iter().any(|x| x.as_str() == Some(o))),
        (Some(Value::Array(a)), Value::Array(o)) => Ok(o.iter().any(|x| a.iter().any(|y| eq(x, y)))),
        (Some(Value::String(_)), _) => Err("audOption.includes is not a function".into()),
        (Some(Value::Array(_)), _) => Err("audOption.some is not a function".into()),
        _ => Ok(false),
    }
}

/// `jwtVerify(token, key, {algorithms, audience, currentDate, clockTolerance})` over an already canonical-gated JWS.
fn jwt_verify(jws: &CanonicalJws, key: &SdJwtKey, algorithms: &Value, c: &Claims) -> Result<(), String> {
    jwt_verify_with(jws, &|_| Ok(key.clone()), algorithms, c)
}

/// [`jwt_verify`] with the key chosen from the protected header after the algorithm gate (the JOSE library's key-function
/// order). The resolver's error text is the refusal.
pub(crate) fn jwt_verify_with(
    jws: &CanonicalJws,
    key_for: &dyn Fn(&Map<String, Value>) -> Result<SdJwtKey, String>,
    algorithms: &Value,
    c: &Claims,
) -> Result<(), String> {
    let h = &jws.header;
    let b64 = check_crit_b64(h)?;
    let alg = h.get("alg").and_then(Value::as_str).filter(|a| !a.is_empty()).ok_or("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")?;
    let Some(algs) = algorithms.as_array().filter(|a| a.iter().all(Value::is_string)) else {
        return Err("\"algorithms\" option must be an array of strings".into());
    };
    if !algs.iter().any(|a| a.as_str() == Some(alg)) {
        return Err("\"alg\" (Algorithm) Header Parameter value not allowed".into());
    }
    let input = format!("{}.{}", jws.segments[0], jws.segments[1]);
    let ok = match &key_for(h)? {
        SdJwtKey::Ed25519(pk) if alg == "EdDSA" => verify_jws_signature(alg, &crate::jose::JwkKey::Ed25519(*pk), input.as_bytes(), &jws.bytes[2]),
        SdJwtKey::Ed25519(_) => return Err(format!("an Ed25519 key cannot verify {alg}")),
        SdJwtKey::Jwk(j) => verify_jws_signature(alg, &import_public_jwk(j, alg)?, input.as_bytes(), &jws.bytes[2]),
    };
    if !ok {
        return Err("signature verification failed".into());
    }
    if !b64 {
        return Err("JWTs MUST NOT use unencoded payload".into());
    }
    let p = jws.payload.as_ref().expect("json payload");
    if let Some(a) = c.audience {
        if !p.contains_key("aud") {
            return Err("missing required \"aud\" claim".into());
        }
        if truthy(Some(a)) && !audience_ok(p.get("aud"), a)? {
            return Err("unexpected \"aud\" claim value".into());
        }
    }
    let tol = tolerance_of(c.tolerance)?;
    let num = |k: &str| -> Result<Option<f64>, String> {
        match p.get(k) {
            None => Ok(None),
            Some(v) => v.as_f64().map(Some).ok_or_else(|| format!("\"{k}\" claim must be a number")),
        }
    };
    num("iat")?;
    if num("nbf")?.is_some_and(|nbf| !(nbf <= c.now_sec + tol)) {
        return Err("\"nbf\" claim timestamp check failed".into());
    }
    if num("exp")?.is_some_and(|exp| !(exp > c.now_sec - tol)) {
        return Err("\"exp\" claim timestamp check failed".into());
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------- verification

struct Decoded {
    parts: Vec<Value>,
    used: bool,
}

fn claim(d: &str, by: &HashMap<String, Decoded>, seen: &mut HashSet<String>) -> Result<Option<Vec<Value>>, String> {
    if !seen.insert(d.to_string()) {
        return Err("a digest appears more than once in the payload".into());
    }
    Ok(by.get(d).map(|x| x.parts.clone()))
}

fn walk(node: &Value, top: bool, by: &mut HashMap<String, Decoded>, seen: &mut HashSet<String>, disclosed: &mut Map<String, Value>) -> Result<Value, String> {
    match node {
        Value::Array(a) => {
            let mut out = Vec::new();
            for el in a {
                match el.as_object() {
                    Some(o) if o.len() == 1 && o.contains_key("...") => {
                        let Some(d) = o["..."].as_str() else { return Err("an array '...' entry must reference a string digest".into()) };
                        let Some(parts) = claim(d, by, seen)? else { continue }; // undisclosed element or decoy
                        if parts.len() != 2 {
                            return Err("an array-element disclosure must be [salt, value]".into());
                        }
                        by.get_mut(d).expect("present").used = true;
                        out.push(walk(&parts[1], false, by, seen, disclosed)?);
                    }
                    _ => out.push(walk(el, false, by, seen, disclosed)?),
                }
            }
            Ok(Value::Array(out))
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                if k != "_sd" {
                    out.insert(k.clone(), walk(v, false, by, seen, disclosed)?);
                }
            }
            if let Some(sd) = m.get("_sd") {
                let Some(list) = sd.as_array().filter(|l| l.iter().all(Value::is_string)) else { return Err("_sd must be an array of strings".into()) };
                for d in list.iter().filter_map(Value::as_str) {
                    let Some(parts) = claim(d, by, seen)? else { continue }; // decoy or undisclosed claim
                    if parts.len() != 3 {
                        return Err("an object-property disclosure must be [salt, name, value]".into());
                    }
                    let Some(name) = parts[1].as_str() else { return Err("disclosure claim name must be a string".into()) };
                    if name == "_sd" || name == "..." {
                        return Err(format!("disclosure claim name '{name}' is reserved"));
                    }
                    if out.contains_key(name) {
                        return Err(format!("disclosure claim '{name}' collides with an existing claim"));
                    }
                    if top && CRITICAL_CLAIMS.contains(&name) {
                        return Err(format!("'{name}' is security-critical and must not be selectively disclosable"));
                    }
                    by.get_mut(d).expect("present").used = true;
                    let value = walk(&parts[2], false, by, seen, disclosed)?;
                    out.insert(name.to_string(), value.clone());
                    if top {
                        disclosed.insert(name.to_string(), value);
                    }
                }
            }
            Ok(Value::Object(out))
        }
        v => Ok(v.clone()),
    }
}

fn fail(reason: impl Into<String>) -> Value {
    json!({ "ok": false, "reason": reason.into() })
}

/// `verifyPcaSdJwt(sdjwt, {issuerKey, ...opts})` -> `{ok: true, payload, processed, protectedHeader, disclosed, claims,
/// keyBinding}` or `{ok: false, reason}`. `opts` members (camelCase, as the reference): `requiredDisclosures`,
/// `expectedAudience`, `keyBindingKey` (JWK or base64url raw Ed25519 key), `expectedKbAudience`, `expectedNonce`,
/// `requireKeyBinding`, `algorithms`, `kbAlgorithms` (default `["EdDSA"]` each), `now` (epoch ms, default the wall clock),
/// `kbMaxAgeSec`, `clockToleranceSec`.
pub fn verify_pca_sd_jwt(sdjwt: &Value, issuer_key: &SdJwtKey, opts: &Value) -> Value {
    verify_inner(sdjwt, issuer_key, opts).unwrap_or_else(fail)
}

fn verify_inner(sdjwt: &Value, issuer_key: &SdJwtKey, opts: &Value) -> Result<Value, String> {
    // a non-finite clock, tolerance or window would slip past the date checks (every comparison with NaN is false, and -Infinity is
    // "before" every expiry): anything that is not a finite number is refused before the token is read
    for k in ["now", "clockToleranceSec", "kbMaxAgeSec"] {
        if let Some(v) = opts.get(k) {
            if !(v.is_number() && v.as_f64().is_some_and(f64::is_finite)) {
                return Err("now, clockToleranceSec and kbMaxAgeSec must be finite".into());
            }
        }
    }
    let parsed = parse_sd_jwt(sdjwt)?;
    let get = |k: &str| opts.get(k);
    let nn = |k: &str| opts.get(k).filter(|v| !v.is_null());
    let default_algs = json!([DEFAULT_SIGNING_ALG]);
    let now = match get("now") {
        None => now_ms(),
        // a clock that is not a finite number, or beyond the Date range (an invalid Date that reads as no clock), is refused
        Some(v) => {
            let n = v.as_f64().filter(|n| n.is_finite()).ok_or("now, clockToleranceSec and kbMaxAgeSec must be finite")?;
            if !(n.abs() <= MAX_DATE_MS) {
                return Err("now is not a representable time".into());
            }
            n
        }
    };
    let now_sec = (now.trunc() / 1000.0).floor();
    let claims = Claims { audience: get("expectedAudience"), tolerance: get("clockToleranceSec"), now_sec };
    jwt_verify(&parsed.jwt, issuer_key, nn("algorithms").unwrap_or(&default_algs), &claims)?;
    let payload = parsed.jwt.payload.clone().expect("json payload");
    if payload.get("_sd_alg").is_some_and(|a| a.as_str() != Some(SD_ALG)) {
        return Ok(fail(format!("unsupported _sd_alg (require \"{SD_ALG}\")")));
    }
    let mut by: HashMap<String, Decoded> = HashMap::new();
    for e in &parsed.disclosures {
        let d = sha256b64u(e);
        if by.contains_key(&d) {
            return Ok(fail("duplicate disclosure"));
        }
        by.insert(d, Decoded { parts: decode_disclosure(e)?, used: false });
    }
    let (mut seen, mut disclosed) = (HashSet::new(), Map::new());
    let processed = walk(&Value::Object(payload.clone()), true, &mut by, &mut seen, &mut disclosed).and_then(|p| {
        if by.values().any(|d| !d.used) {
            return Err("a presented disclosure does not match any _sd digest (tampered)".into());
        }
        Ok(p)
    });
    let mut processed = match processed {
        Ok(Value::Object(p)) => p,
        Ok(_) => return Ok(fail("payload is not an object")),
        Err(e) => return Ok(fail(e)),
    };
    processed.retain(|k, _| k != "_sd_alg");
    if let Some(req) = nn("requiredDisclosures") {
        for r in req.as_array().ok_or("requiredDisclosures must be an array")? {
            let name = crate::oauth::js_str(r);
            if !disclosed.contains_key(&name) {
                return Ok(fail(format!("required disclosure '{name}' was not presented")));
            }
        }
    }

    let cnf_jwk = payload.get("cnf").filter(|c| c.is_object()).and_then(|c| c.get("jwk")).filter(|j| is_jwk(j)).cloned();
    let mut kb_out = json!({ "presented": parsed.kb.is_some(), "verified": false });
    if let Some((kb, _)) = &parsed.kb {
        let Some(cnf) = cnf_jwk else { return Ok(fail("KB-JWT presented but issuer JWT has no cnf key")) };
        if let Some(want) = get("keyBindingKey") {
            let want_x = match want {
                Value::String(s) => Some(s.as_str()),
                j if is_jwk(j) => j.get("x").and_then(Value::as_str),
                _ => None,
            };
            if want_x.is_none() || want_x != cnf.get("x").and_then(Value::as_str) {
                return Ok(fail("cnf key does not match the expected keyBindingKey"));
            }
        }
        let kb_aud = nn("expectedKbAudience").or(get("expectedAudience"));
        let kb_claims = Claims { audience: kb_aud, tolerance: get("clockToleranceSec"), now_sec };
        // shortcut (stricter than the reference): a cnf JWK carrying private members is refused (the reference verifies with it)
        if let Err(e) = jwt_verify(kb, &SdJwtKey::Jwk(cnf), nn("kbAlgorithms").unwrap_or(&default_algs), &kb_claims) {
            return Ok(fail(format!("KB-JWT signature/claims invalid: {e}")));
        }
        let kp = kb.payload.as_ref().expect("json payload");
        if kb.header.get("typ").and_then(Value::as_str) != Some(KB_JWT_TYP) {
            return Ok(fail(format!("KB-JWT typ must be \"{KB_JWT_TYP}\"")));
        }
        let Some(iat) = kp.get("iat").and_then(Value::as_f64) else { return Ok(fail("KB-JWT iat is required")) };
        if let Some(max_age) = get("kbMaxAgeSec") {
            let max_age = if max_age.is_null() { 0.0 } else { max_age.as_f64().ok_or("kbMaxAgeSec must be a number")? };
            let now_floor = (now / 1000.0).floor();
            if !iat.is_finite() {
                return Ok(fail("KB-JWT iat is not a finite number"));
            }
            if !(now_floor - iat <= max_age) {
                return Ok(fail("KB-JWT is older than the accepted window"));
            }
            if !(iat - now_floor <= tolerance_of(nn("clockToleranceSec"))?) {
                return Ok(fail("KB-JWT iat is in the future"));
            }
        }
        let aud = kp.get("aud");
        if !matches!(aud, Some(Value::String(_) | Value::Array(_))) {
            return Ok(fail("KB-JWT aud is required"));
        }
        if kp.get("sd_hash").and_then(Value::as_str) != Some(sha256b64u(&parsed.head).as_str()) {
            return Ok(fail("KB-JWT sd_hash does not cover this presentation"));
        }
        if let Some(n) = get("expectedNonce") {
            if kp.get("nonce") != Some(n) {
                return Ok(fail("KB-JWT nonce does not match"));
            }
        }
        kb_out["verified"] = json!(true);
        if let Some(Value::String(a)) = aud {
            kb_out["aud"] = json!(a);
        }
        if let Some(Value::String(n)) = kp.get("nonce") {
            kb_out["nonce"] = json!(n);
        }
    } else if get("keyBindingKey").is_some() || truthy(get("requireKeyBinding")) {
        return Ok(fail("key binding required but no KB-JWT was presented"));
    }

    let claims: Map<String, Value> = processed.iter().filter(|(k, _)| !RESERVED_CLAIMS.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    Ok(json!({
        "ok": true,
        "payload": payload,
        "processed": processed,
        "protectedHeader": parsed.jwt.header,
        "disclosed": disclosed,
        "claims": claims,
        "keyBinding": kb_out,
    }))
}

fn deny(reason: &str) -> Verdict {
    Verdict { allow: false, checks: Default::default(), reason: reason.to_string(), reasons: Vec::new(), legacy_model_polarity: false }
}

/// `verifyRecovered(res, coreOpts)`: rebuild the PCActn from a verified (`ok: true`) result and run the core verifier on it
/// (`now` epoch ms, the verifier's own `audience`). `insecure_skip_plan_root_check` is the core's explicit opt-out.
pub fn verify_recovered(res: &Value, grant: &Value, audience: &str, now: i64, insecure_skip_plan_root_check: bool) -> Verdict {
    let empty = Map::new();
    let c = res.get("claims").and_then(Value::as_object).unwrap_or(&empty);
    let p = res.get("processed").and_then(Value::as_object).unwrap_or(&empty);
    let (Some(iat_ms), Some(exp_ms)) = (c.get("iat_ms").and_then(Value::as_f64), c.get("exp_ms").and_then(Value::as_f64)) else {
        return deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn");
    };
    let iat_sec = (iat_ms / 1000.0).floor();
    if p.get("iat").and_then(Value::as_f64) != Some(iat_sec) {
        return deny("pca-sdjwt: iat_ms disagrees with iat");
    }
    if p.get("exp").and_then(Value::as_f64) != Some((exp_ms / 1000.0).ceil().max(iat_sec + 1.0)) {
        return deny("pca-sdjwt: exp_ms disagrees with exp");
    }
    for k in ["action", "cap_chain", "plan", "sig", "grant_ref", "counter"] {
        if !c.contains_key(k) {
            return deny(&format!("pca-sdjwt: required claim '{k}' was not disclosed"));
        }
    }
    let Some(aud) = p.get("aud").filter(|a| a.is_string()) else { return deny("pca-sdjwt: aud must be a string") };
    let chain = match c.get("cap_chain") {
        Some(Value::Array(ch)) if !ch.is_empty() => ch,
        _ => return deny("pca-sdjwt: cap_chain is empty"),
    };
    if p.get("iss").is_none() || p.get("iss") != chain[0].get("issuer") {
        return deny("pca-sdjwt: iss does not match the chain root issuer");
    }
    if p.get("sub").is_none() || p.get("sub") != chain[chain.len() - 1].get("holder") {
        return deny("pca-sdjwt: sub does not match the chain leaf holder");
    }
    let mut pc: Map<String, Value> = c.iter().filter(|(k, _)| *k != "iat_ms" && *k != "exp_ms").map(|(k, v)| (k.clone(), v.clone())).collect();
    match p.get("ver") {
        Some(v) => {
            pc.insert("ver".into(), v.clone());
        }
        None => pc.retain(|k, _| k != "ver"),
    }
    pc.insert("aud".into(), aud.clone());
    pc.insert("iat".into(), c["iat_ms"].clone());
    pc.insert("exp".into(), c["exp_ms"].clone());
    let opts = VerifyOptions { insecure_skip_plan_root_check, ..VerifyOptions::default() };
    crate::verify_pcactn_core_with(&Value::Object(pc), grant, now, audience, &opts)
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::*;

    fn sdjwt(payload: &str) -> Value {
        json!(format!("{}.{}.{}~", b64_encode(br#"{"alg":"EdDSA"}"#), b64_encode(payload.as_bytes()), b64_encode(&[1u8; 64])))
    }

    #[test]
    fn a_duplicate_issuer_payload_member_is_refused() {
        assert!(present(&sdjwt(r#"{"_sd":[],"a":1}"#), &json!([]), None, &Value::Null).is_ok());
        let err = present(&sdjwt(r#"{"_sd":[],"_sd":["x"]}"#), &json!([]), None, &Value::Null).unwrap_err();
        assert!(err.contains(r#"duplicate key "_sd""#), "{err}");
    }
}
