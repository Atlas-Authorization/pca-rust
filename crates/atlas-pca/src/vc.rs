//! W3C Verifiable Credential projection of an agent passport, a native port of the reference bridge: did:key (Ed25519,
//! base58btc multibase), the agent-passport SD-JWT VC (the four measurement digests selectively disclosable) and RFC 9421 /
//! Web Bot Auth HTTP message signatures over a request. JSON-valued API: arguments are the reference's JSON values, errors
//! are the reference's messages.
use crate::attest::jws::decode_canonical_b64url;
use crate::jose::{assert_canonical_compact_jws, check_crit_b64, validate_jwt_claims, JwtClaimsCheck, DEFAULT_MAX_JWS_BYTES};
use crate::oauth::js_str;
use crate::{b64_encode, js_stringify};
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::Digest;

pub const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const AGENT_PASSPORT_CONTEXT: &str = "https://atlasauth.net/credentials/agent-passport/v1";
pub const AGENT_PASSPORT_VC_TYPE: &str = "AgentPassportCredential";
const SD_DIGEST_FIELDS: [&str; 4] = ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"];
const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_BASE58_INPUT: usize = 1024;

fn e(m: impl Into<String>) -> String {
    m.into()
}

fn sha256_b64u(ascii: &str) -> String {
    // the disclosures are base64url (ASCII), so Node's 'ascii' encoding is the bytes themselves
    b64_encode(&sha2::Sha256::digest(ascii.as_bytes()))
}

/// base58btc (Bitcoin alphabet), leading zero bytes as `1`s.
pub fn base58btc_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u32> = Vec::new();
    for &b in &bytes[zeros..] {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += *d << 8;
            *d = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
    out
}

/// base58btc decode (at most 1024 characters).
pub fn base58btc_decode(s: &Value) -> Result<Vec<u8>, String> {
    let Some(s) = s.as_str() else { return Err(e("Cannot read properties of a non-string")) };
    if s.encode_utf16().count() > MAX_BASE58_INPUT {
        return Err(e("pca-vc: base58btc input too long"));
    }
    let zeros = s.chars().take_while(|c| *c == '1').count();
    let mut bytes: Vec<u32> = Vec::new();
    for c in s.chars().skip(zeros) {
        let Some(v) = B58.iter().position(|b| *b as char == c) else { return Err(e("pca-vc: invalid base58btc character")) };
        let mut carry = v as u32;
        for b in bytes.iter_mut() {
            carry += *b * 58;
            *b = carry & 0xff;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev().map(|b| *b as u8));
    Ok(out)
}

/// `did:key:z<base58btc(0xed 0x01 || key)>` of a 32-byte Ed25519 public key.
pub fn did_key_from_ed25519(public_key: &[u8]) -> Result<String, String> {
    if public_key.len() != 32 {
        return Err(e("pca-vc: Ed25519 public key must be 32 bytes"));
    }
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(public_key);
    Ok(format!("did:key:z{}", base58btc_encode(&mc)))
}

/// The Ed25519 public key of a `did:key:z6Mk...` identifier.
pub fn ed25519_from_did_key(did: &Value) -> Result<Vec<u8>, String> {
    let Some(d) = did.as_str() else { return Err(e("did.startsWith is not a function")) };
    let prefix = "did:key:z";
    let Some(body) = d.strip_prefix(prefix) else { return Err(e("pca-vc: not a did:key:z… identifier")) };
    if body.encode_utf16().count() > 64 {
        return Err(e("pca-vc: did:key is not an Ed25519 (0xed01) key"));
    }
    let mc = base58btc_decode(&json!(body))?;
    if mc.len() != 34 || mc[0] != 0xed || mc[1] != 0x01 {
        return Err(e("pca-vc: did:key is not an Ed25519 (0xed01) key"));
    }
    Ok(mc[2..].to_vec())
}

/// The agent-passport JSON-LD context document.
pub fn agent_passport_context_doc() -> Value {
    let v = "https://atlasauth.net/credentials/agent-passport/v1#";
    let x = "http://www.w3.org/2001/XMLSchema#";
    let t = |id: &str, ty: &str| json!({ "@id": format!("{v}{id}"), "@type": format!("{x}{ty}") });
    json!({ "@context": { "@protected": true, "AgentPassportCredential": {
        "@id": format!("{v}AgentPassportCredential"),
        "@context": {
            "@protected": true, "id": "@id", "type": "@type",
            "passport_id": t("passportId", "string"), "model_id": t("modelId", "string"), "operator": t("operator", "string"),
            "hardware_rooted": t("hardwareRooted", "boolean"), "weights_measured": t("weightsMeasured", "boolean"),
            "issued_at": t("issuedAt", "integer"), "weights_digest": t("weightsDigest", "string"),
            "system_prompt_digest": t("systemPromptDigest", "string"), "tool_manifest_digest": t("toolManifestDigest", "string"),
            "runtime_measurement": t("runtimeMeasurement", "string"),
            "_sd": { "@id": format!("{v}selectiveDisclosureDigest"), "@container": "@set" },
        },
    } } })
}

/// SHA-256 (hex) of the context document in sorted-key JSON.
pub fn agent_passport_context_digest() -> String {
    fn canonical(v: &Value) -> String {
        match v {
            Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
            Value::Object(o) => {
                let mut ks: Vec<&String> = o.keys().collect();
                ks.sort();
                format!("{{{}}}", ks.iter().map(|k| format!("{}:{}", js_stringify(&json!(k)), canonical(&o[*k]))).collect::<Vec<_>>().join(","))
            }
            s => js_stringify(s),
        }
    }
    sha2::Sha256::digest(canonical(&agent_passport_context_doc()).as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The context document for its IRI, else null.
pub fn resolve_agent_passport_context(iri: &Value) -> Value {
    if iri.as_str() == Some(AGENT_PASSPORT_CONTEXT) {
        agent_passport_context_doc()
    } else {
        Value::Null
    }
}

fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

/// `passportToVC(passport, {issuerKey, issuerDid, subjectDid, ttlSec})`: an SD-JWT VC (`vc+sd-jwt`, EdDSA) whose
/// credentialSubject carries the passport and `_sd` digests of the measurement digests, each disclosure followed by `~`.
/// `issuer_seed` is the issuer's Ed25519 seed; `now_sec` is the issue time (whole seconds).
pub fn passport_to_vc(
    passport: &Value,
    issuer_seed: &[u8; 32],
    issuer_did: Option<&Value>,
    subject_did: Option<&Value>,
    ttl_sec: Option<&Value>,
    now_sec: i64,
) -> Result<String, String> {
    if passport.is_null() {
        return Err(e("Cannot read properties of null (reading 'weights_digest')"));
    }
    let (mut disclosures, mut sd) = (Vec::new(), Vec::new());
    for f in SD_DIGEST_FIELDS {
        let Some(v) = get(passport, f) else { continue };
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|x| x.to_string())?;
        let d = b64_encode(js_stringify(&json!([b64_encode(&salt), f, v])).as_bytes());
        sd.push(json!(sha256_b64u(&d)));
        disclosures.push(d);
    }
    let mut cs = Map::new();
    if let Some(s) = subject_did {
        cs.insert("id".into(), s.clone());
    }
    for (k, src) in [
        ("passport_id", "id"),
        ("model_id", "model_id"),
        ("operator", "operator"),
        ("hardware_rooted", "hardware_rooted"),
        ("issued_at", "issued_at"),
        ("weights_measured", "weights_measured"),
    ] {
        if let Some(v) = get(passport, src) {
            cs.insert(k.into(), v.clone());
        }
    }
    if !sd.is_empty() {
        cs.insert("_sd".into(), Value::Array(sd.clone()));
    }
    let mut p = Map::new();
    p.insert(
        "vc".into(),
        json!({ "@context": [VC_CONTEXT, AGENT_PASSPORT_CONTEXT], "type": ["VerifiableCredential", AGENT_PASSPORT_VC_TYPE], "credentialSubject": cs }),
    );
    if !sd.is_empty() {
        p.insert("_sd_alg".into(), json!("sha-256"));
    }
    if let Some(i) = issuer_did {
        p.insert("iss".into(), i.clone());
    }
    if let Some(s) = subject_did {
        p.insert("sub".into(), s.clone());
    }
    p.insert("iat".into(), json!(now_sec));
    if let Some(t) = ttl_sec {
        // `now + ttlSec`: a number (true is 1, null is 0); a string concatenates and the JOSE library refuses the result
        let exp = match t {
            Value::Null => now_sec as f64,
            Value::Bool(b) => now_sec as f64 + f64::from(u8::from(*b)),
            Value::Number(n) => now_sec as f64 + n.as_f64().unwrap_or(f64::NAN),
            _ => return Err(e("Invalid time period format")),
        };
        p.insert("exp".into(), if exp.fract() == 0.0 { json!(exp as i64) } else { json!(exp) });
    }
    let jwt = crate::jose::sign_ed25519_jws(&json!({ "alg": "EdDSA", "typ": "vc+sd-jwt" }), &Value::Object(p), issuer_seed);
    Ok(std::iter::once(jwt).chain(disclosures).map(|x| format!("{x}~")).collect())
}

fn as_str_l(v: Option<&Value>, label: &str) -> Result<Value, String> {
    v.filter(|x| x.is_string()).cloned().ok_or_else(|| format!("pca-vc: expected string for {label}"))
}

/// `verifyPassportVC(vc, issuerVerifyKey, {expectedIssuerDid})`: the passport, issuer DID and subject DID of a VC signed
/// (EdDSA) by `issuer_public`. Every disclosure must match an `_sd` digest once. `now_sec` is the clock (whole seconds).
pub fn verify_passport_vc(vc: &Value, issuer_public: &[u8; 32], options: Option<&Value>, now_sec: f64) -> Result<Value, String> {
    let Some(vc) = vc.as_str() else { return Err(e("vc.split is not a function")) };
    let parts: Vec<&str> = vc.split('~').collect();
    let jwt = parts[0];
    if jwt.is_empty() {
        return Err(e("pca-vc: empty SD-JWT"));
    }
    let disclosures: Vec<&str> = parts[1..].iter().copied().filter(|p| !p.is_empty()).collect();
    let jws = assert_canonical_compact_jws(&json!(jwt), 3, DEFAULT_MAX_JWS_BYTES, true)?;
    for d in &disclosures {
        decode_canonical_b64url(d)?;
    }
    // the JOSE library's jwtVerify with algorithms ['EdDSA']
    let b64 = check_crit_b64(&jws.header)?;
    let alg = jws.header.get("alg").and_then(Value::as_str).filter(|a| !a.is_empty()).ok_or("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")?;
    if alg != "EdDSA" {
        return Err(e("\"alg\" (Algorithm) Header Parameter value not allowed"));
    }
    let sig: [u8; 64] = jws.bytes[2].as_slice().try_into().map_err(|_| "signature verification failed".to_string())?;
    if !crate::verify_ed25519_strict(issuer_public, format!("{}.{}", jws.segments[0], jws.segments[1]).as_bytes(), &sig) {
        return Err(e("signature verification failed"));
    }
    if !b64 {
        return Err(e("JWTs MUST NOT use unencoded payload"));
    }
    let payload = jws.payload.clone().unwrap_or_default();
    validate_jwt_claims(&jws.header, &payload, &JwtClaimsCheck { now_sec: now_sec.floor(), ..Default::default() })?;
    if jws.header.get("typ") != Some(&json!("vc+sd-jwt")) {
        return Err(e("pca-vc: header typ must be 'vc+sd-jwt'"));
    }
    let Some(vcc @ Value::Object(_)) = payload.get("vc") else { return Err(e("pca-vc: missing vc claim")) };
    let ctx = get(vcc, "@context").and_then(Value::as_array);
    if !ctx.is_some_and(|c| c.first().and_then(Value::as_str) == Some(VC_CONTEXT)) {
        return Err(format!("pca-vc: @context must begin with {VC_CONTEXT}"));
    }
    if !ctx.is_some_and(|c| c.len() == 2 && c[1].as_str() == Some(AGENT_PASSPORT_CONTEXT)) {
        return Err(format!("pca-vc: @context must be exactly [{VC_CONTEXT}, {AGENT_PASSPORT_CONTEXT}]"));
    }
    let types = get(vcc, "type").and_then(Value::as_array);
    if !types.is_some_and(|t| t.iter().any(|x| x == "VerifiableCredential") && t.iter().any(|x| x == AGENT_PASSPORT_VC_TYPE)) {
        return Err(format!("pca-vc: type must include VerifiableCredential and {AGENT_PASSPORT_VC_TYPE}"));
    }
    let Some(cs @ Value::Object(_)) = get(vcc, "credentialSubject") else { return Err(e("pca-vc: missing credentialSubject")) };
    if get(cs, "_sd_alg").is_some() {
        return Err(e("pca-vc: _sd_alg must be a top-level claim"));
    }
    if payload.get("_sd_alg").is_some_and(|a| a != "sha-256") {
        return Err(e("pca-vc: unsupported _sd_alg (require sha-256)"));
    }
    let sd_list: Vec<&str> = get(cs, "_sd").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let mut recovered = Map::new();
    let mut seen = Vec::new();
    for d in &disclosures {
        let digest = sha256_b64u(d);
        if !sd_list.contains(&digest.as_str()) {
            return Err(e("pca-vc: disclosure does not match any _sd digest"));
        }
        if seen.contains(&digest) {
            return Err(e("pca-vc: duplicate disclosure"));
        }
        seen.push(digest);
        // the reference decodes leniently with JSON.parse; the disclosure is already canonical base64url
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(d).map_err(|_| "pca-vc: malformed disclosure".to_string())?;
        // a duplicate member is refused (JSON.parse keeps the last); numbers stay as written
        let malformed = || "pca-vc: malformed disclosure".to_string();
        let decoded: Value = crate::ap2::parse_no_duplicates(std::str::from_utf8(&raw).map_err(|_| malformed())?).map_err(|_| malformed())?;
        let Some(arr) = decoded.as_array().filter(|a| a.len() == 3) else { return Err(e("pca-vc: malformed disclosure")) };
        let name = as_str_l(Some(&arr[1]), "disclosure name")?;
        let name = name.as_str().unwrap_or_default();
        if !SD_DIGEST_FIELDS.contains(&name) {
            return Err(format!("pca-vc: unexpected disclosure claim '{name}'"));
        }
        if recovered.contains_key(name) {
            return Err(format!("pca-vc: disclosure claim '{name}' appears more than once"));
        }
        recovered.insert(name.into(), as_str_l(Some(&arr[2]), "disclosure value")?);
    }
    let mut passport = Map::new();
    passport.insert("id".into(), as_str_l(get(cs, "passport_id"), "passport_id")?);
    passport.insert("model_id".into(), as_str_l(get(cs, "model_id"), "model_id")?);
    passport.insert("operator".into(), as_str_l(get(cs, "operator"), "operator")?);
    passport.insert(
        "hardware_rooted".into(),
        get(cs, "hardware_rooted").filter(|v| v.is_boolean()).cloned().ok_or("pca-vc: expected boolean for hardware_rooted")?,
    );
    passport.insert("issued_at".into(), get(cs, "issued_at").filter(|v| v.is_number()).cloned().ok_or("pca-vc: expected number for issued_at")?);
    if let Some(w) = get(cs, "weights_measured") {
        passport.insert("weights_measured".into(), Some(w).filter(|v| v.is_boolean()).cloned().ok_or("pca-vc: expected boolean for weights_measured")?);
    }
    for f in SD_DIGEST_FIELDS {
        if let Some(v) = recovered.get(f) {
            passport.insert(f.into(), v.clone());
        }
    }
    let issuer_did = as_str_l(payload.get("iss"), "iss")?;
    let subject_did = as_str_l(get(cs, "id"), "credentialSubject.id")?;
    if payload.get("sub") != Some(&subject_did) {
        return Err(e("pca-vc: sub does not match credentialSubject.id"));
    }
    if let Some(want) = options.and_then(|o| get(o, "expectedIssuerDid")) {
        if *want != issuer_did {
            return Err(e("pca-vc: iss does not match expectedIssuerDid"));
        }
    }
    Ok(json!({ "passport": passport, "issuerDid": issuer_did, "subjectDid": subject_did }))
}

// ---- RFC 9421 / Web Bot Auth -------------------------------------------------------------------------------------------------

fn js_trim(s: &str) -> &str {
    s.trim_matches(crate::action_schema::is_js_ws)
}

/// `new URL(url).host`: the host and a non-default port.
fn url_host(u: &str) -> Result<String, String> {
    let p = url::Url::parse(u).map_err(|_| "Invalid URL".to_string())?;
    Ok(format!("{}{}", p.host_str().unwrap_or(""), p.port().map(|n| format!(":{n}")).unwrap_or_default()))
}

/// Lower-cased header names (a later spelling of the same name replaces the value in place).
fn normalize_headers(h: &Value) -> Result<Vec<(String, Value)>, String> {
    let Some(m) = h.as_object() else { return Err(e("Cannot convert undefined or null to object")) };
    let mut out: Vec<(String, Value)> = Vec::new();
    for (k, v) in m {
        let k = k.to_lowercase();
        match out.iter_mut().find(|(x, _)| *x == k) {
            Some(e) => e.1 = v.clone(),
            None => out.push((k, v.clone())),
        }
    }
    Ok(out)
}

fn set_header(h: &mut Vec<(String, Value)>, k: &str, v: Value) {
    match h.iter_mut().find(|(x, _)| x == k) {
        Some(e) => e.1 = v,
        None => h.push((k.to_string(), v)),
    }
}

fn component_value(name: &str, method: &str, url: &str, headers: &[(String, Value)]) -> Result<String, String> {
    match name {
        "@method" => Ok(method.to_uppercase()),
        "@target-uri" => Ok(url.to_string()),
        "@authority" => url_host(url),
        _ => match headers.iter().find(|(k, _)| k == name) {
            None => Err(format!("pca-vc: covered header '{name}' absent from request")),
            Some((_, Value::String(s))) => Ok(js_trim(s).to_string()),
            Some(_) => Err(e("v.trim is not a function")),
        },
    }
}

fn signature_base(components: &[String], params: &str, method: &str, url: &str, headers: &[(String, Value)]) -> Result<String, String> {
    let mut lines = Vec::new();
    for c in components {
        lines.push(format!("\"{c}\": {}", component_value(c, method, url, headers)?));
    }
    lines.push(format!("\"@signature-params\": {params}"));
    Ok(lines.join("\n"))
}

/// `signRequestMessage(args)`: `args` = {method, url, headers, keyid, created?, signatureAgent?}; `seed` is the Ed25519
/// signing seed; `now_sec` stands in for an absent `created`. Covers `@method`, `@target-uri` and every header (sorted).
pub fn sign_request_message(args: &Value, seed: &[u8; 32], now_sec: i64) -> Result<Value, String> {
    use ed25519_dalek::Signer;
    let method = get(args, "method").and_then(Value::as_str).ok_or("method.toUpperCase is not a function")?;
    let url = get(args, "url").and_then(Value::as_str).ok_or("Invalid URL")?;
    let created = get(args, "created").filter(|c| !c.is_null()).cloned().unwrap_or(json!(now_sec));
    let mut headers = normalize_headers(get(args, "headers").unwrap_or(&Value::Null))?;
    if !headers.iter().any(|(k, _)| k == "host") {
        headers.push(("host".into(), json!(url_host(url)?)));
    }
    let agent = get(args, "signatureAgent").map(|a| format!("\"{}\"", js_str(a)));
    if let Some(a) = &agent {
        set_header(&mut headers, "signature-agent", json!(a));
    }
    let mut names: Vec<String> = headers.iter().map(|(k, _)| k.clone()).collect();
    names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let components: Vec<String> = ["@method".to_string(), "@target-uri".to_string()].into_iter().chain(names).collect();
    let inner = format!("({})", components.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" "));
    let keyid = get(args, "keyid").map(js_str).unwrap_or_else(|| "undefined".into());
    let mut params = format!(";created={};keyid=\"{keyid}\";alg=\"ed25519\"", js_str(&created));
    if agent.is_some() {
        params.push_str(";tag=\"web-bot-auth\"");
    }
    let sp = format!("{inner}{params}");
    let base = signature_base(&components, &sp, method, url, &headers)?;
    let sig = ed25519_dalek::SigningKey::from_bytes(seed).sign(base.as_bytes());
    let mut out = Map::new();
    out.insert("signatureInput".into(), json!(format!("sig1={sp}")));
    out.insert("signature".into(), json!(format!("sig1=:{}:", base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))));
    if let Some(a) = agent {
        out.insert("signatureAgent".into(), json!(a));
    }
    Ok(Value::Object(out))
}

/// Node's lenient base64 decode: both alphabets, stops at `=`, other characters skipped.
fn node_b64(s: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        bits = (bits << 6) | v as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn parse_components(sp: &str) -> Result<Vec<String>, String> {
    let close = sp.find(')');
    if !sp.starts_with('(') || close.is_none() {
        return Err(e("pca-vc: malformed @signature-params"));
    }
    let inner = js_trim(&sp[1..close.unwrap_or(1)]);
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(crate::action_schema::is_js_ws)
        .filter(|t| !t.is_empty())
        .map(|t| match t.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
            Some(x) if t.len() >= 2 => Ok(x.to_string()),
            _ => Err(e("pca-vc: malformed component identifier")),
        })
        .collect()
}

/// The first `;<name>=<digits>` / `;<name>="<value>"` parameter.
fn param<'a>(sp: &'a str, name: &str, quoted: bool) -> Option<&'a str> {
    let pat = format!(";{name}={}", if quoted { "\"" } else { "" });
    let mut from = 0;
    while let Some(i) = sp[from..].find(&pat) {
        let rest = &sp[from + i + pat.len()..];
        let end = if quoted { rest.find('"') } else { Some(rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len())) };
        match end {
            Some(n) if quoted || n > 0 => return Some(&rest[..n]),
            _ => from += i + 1,
        }
    }
    None
}

fn verify_inner(a: &Value, public: &[u8; 32]) -> Result<bool, String> {
    let si = get(a, "signatureInput").and_then(Value::as_str).ok_or("not a string")?;
    let Some(eq) = si.find('=') else { return Ok(false) };
    let sp = &si[eq + 1..];
    let components = parse_components(sp)?;
    let needs: Vec<Value> = match get(a, "requiredComponents") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(x)) => x.clone(),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        Some(_) => return Err(e("not iterable")),
    };
    if needs.iter().any(|n| !n.as_str().is_some_and(|n| components.iter().any(|c| c == n))) {
        return Ok(false);
    }
    if param(sp, "alg", true).is_some_and(|x| x != "ed25519") {
        return Ok(false);
    }
    if let Some(max) = get(a, "maxAgeSec") {
        let Some(created) = param(sp, "created", false) else { return Ok(false) };
        let now = match get(a, "nowSec").filter(|v| !v.is_null()) {
            Some(n) => crate::actions::js_to_number(Some(n)),
            None => crate::jose::now_unix_sec(),
        };
        let c: f64 = created.parse().unwrap_or(f64::NAN);
        let max = crate::actions::js_to_number(Some(max));
        if !((now - c).is_finite() && now - c <= max && c - now <= 5.0) {
            return Ok(false);
        }
    }
    let method = get(a, "method").and_then(Value::as_str).ok_or("not a string")?;
    let url = get(a, "url").and_then(Value::as_str).ok_or("Invalid URL")?;
    let mut headers = normalize_headers(get(a, "headers").unwrap_or(&Value::Null))?;
    if !headers.iter().any(|(k, _)| k == "host") {
        headers.push(("host".into(), json!(url_host(url)?)));
    }
    if components.iter().any(|c| c == "signature-agent") && !headers.iter().any(|(k, _)| k == "signature-agent") {
        let Some(sa) = get(a, "signatureAgent") else { return Ok(false) };
        headers.push(("signature-agent".into(), sa.clone()));
    }
    let base = signature_base(&components, sp, method, url, &headers)?;
    let sig = get(a, "signature").and_then(Value::as_str).ok_or("not a string")?;
    let Some(se) = sig.find('=') else { return Ok(false) };
    let wrapped = js_trim(&sig[se + 1..]);
    let Some(inner) = wrapped.strip_prefix(':').and_then(|x| x.strip_suffix(':')).filter(|_| wrapped.len() >= 2) else { return Ok(false) };
    if inner.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return Ok(false);
    }
    let Ok(s) = <[u8; 64]>::try_from(node_b64(inner).as_slice()) else { return Ok(false) };
    Ok(crate::verify_ed25519_strict(public, base.as_bytes(), &s))
}

/// `verifyRequestSignature(args, key)`: `args` = {method, url, headers, signatureInput, signature, signatureAgent?,
/// requiredComponents?, maxAgeSec?, nowSec?}. Any malformed input is `false`.
pub fn verify_request_signature(args: &Value, public: &[u8; 32]) -> bool {
    verify_inner(args, public).unwrap_or(false)
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::*;

    // the issuer key is generated per run and never leaves the test
    fn vc_with(disclosure_text: &str, seed: &[u8; 32]) -> String {
        let disclosure = b64_encode(disclosure_text.as_bytes());
        let payload = json!({
            "iss": "did:example:i", "sub": "did:example:s", "_sd_alg": "sha-256",
            "vc": {
                "@context": [VC_CONTEXT, AGENT_PASSPORT_CONTEXT],
                "type": ["VerifiableCredential", AGENT_PASSPORT_VC_TYPE],
                "credentialSubject": {"id": "did:example:s", "passport_id": "p", "model_id": "m", "operator": "o", "hardware_rooted": true, "issued_at": 1, "_sd": [sha256_b64u(&disclosure)]},
            },
        });
        let jwt = crate::jose::sign_ed25519_jws(&json!({"alg": "EdDSA", "typ": "vc+sd-jwt"}), &payload, seed);
        format!("{jwt}~{disclosure}~")
    }

    #[test]
    fn a_duplicate_member_inside_a_disclosure_is_refused_and_other_number_spellings_are_accepted() {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let verify = |text: &str| verify_passport_vc(&json!(vc_with(text, &seed)), &public, None, 1000.0);
        assert_eq!(verify(r#"["s","weights_digest","dd"]"#).unwrap()["passport"]["weights_digest"], json!("dd"));
        assert_eq!(verify(r#"["s","weights_digest",{"a":1,"a":2}]"#), Err("pca-vc: malformed disclosure".to_string()));
        assert!(verify(r#"[8.0,"weights_digest","dd"]"#).is_ok());
        assert!(verify(r#"[1e3,"weights_digest","dd"]"#).is_ok());
    }
}
