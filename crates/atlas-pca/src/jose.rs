//! The JOSE pieces the protocol bridges share: the canonical compact-JWS reader (`assertCanonicalCompactJws`), RFC 7638 JWK
//! thumbprints, public-JWK import and JWS signature verification (EdDSA over Ed25519, ES256 / ES384 / ES512, RS256 / RS384 /
//! RS512, PS256 / PS384 / PS512, HS256 / HS384 / HS512 over a shared secret), and Ed25519 JWS signing. Verification is
//! fail-closed: an unsupported algorithm or curve (Ed448 without the `ed448` feature, secp256k1) never verifies.
use crate::attest::jws::decode_canonical_b64url;
use crate::attest::x509::{ec_point_valid, rsa_pkcs1_verify, rsa_pss_verify, verify_p1363_sig, EcCurve, Hash, PubKey};
use crate::{b64_encode, decode_b64u_strict, js_stringify, strict_parse};
use serde_json::{Map, Value};
use sha2::Digest;

pub const DEFAULT_MAX_JWS_BYTES: usize = 64 * 1024;

/// A compact JWS read in the canonical profile: every segment canonical base64url, the header (and, when asked, the payload)
/// a strict-JSON object.
#[derive(Debug, Clone)]
pub struct CanonicalJws {
    pub segments: Vec<String>,
    pub header: Map<String, Value>,
    pub payload: Option<Map<String, Value>>,
    /// The decoded bytes of every segment.
    pub bytes: Vec<Vec<u8>>,
}

fn jws_err(reason: &str, detail: Option<String>) -> String {
    match detail {
        Some(d) if !d.is_empty() => format!("non-canonical compact JWS: {reason} ({d})"),
        _ => format!("non-canonical compact JWS: {reason}"),
    }
}

/// UTF-8 JSON bytes of a segment, strict profile (a BOM, invalid UTF-8 or non-strict JSON is refused).
pub fn parse_json_bytes(bytes: &[u8]) -> Result<Value, String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(jws_err("bom", None));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| jws_err("bad-utf8", None))?;
    strict_parse(text).map_err(|e| jws_err("bad-json", Some(e)))
}

/// `isCanonicalCompactJws`: `true` iff `token` is the one canonical spelling of a compact JWS / JWE (see [`assert_canonical_compact_jws`]).
pub fn is_canonical_compact_jws(token: &Value, parts: usize, max_bytes: usize, json_payload: bool) -> bool {
    assert_canonical_compact_jws(token, parts, max_bytes, json_payload).is_ok()
}

/// `assertCanonicalJwsSegments(protected, signature)`: the same canonical profile for a detached JWS (the payload is supplied out of band):
/// both segments non-empty canonical base64url, the protected header a strict-JSON object, which is returned.
pub fn assert_canonical_jws_segments(protected: &Value, signature: &Value, max_bytes: Option<usize>) -> Result<Map<String, Value>, String> {
    let (Some(p), Some(s)) = (protected.as_str(), signature.as_str()) else { return Err(jws_err("not-a-string", None)) };
    if p.encode_utf16().count() + s.encode_utf16().count() > max_bytes.unwrap_or(DEFAULT_MAX_JWS_BYTES) {
        return Err(jws_err("too-long", None));
    }
    if p.is_empty() || s.is_empty() {
        return Err(jws_err("empty-segment", None));
    }
    let header = match parse_json_bytes(&decode_canonical_b64url(p)?)? {
        Value::Object(m) => m,
        _ => return Err(jws_err("not-an-object", None)),
    };
    decode_canonical_b64url(s)?;
    Ok(header)
}

/// `decodeCanonicalJsonSegment`: a canonical unpadded base64url segment holding a strict-JSON document of any type (SD-JWT disclosures).
pub fn decode_canonical_json_segment(seg: &str) -> Result<Value, String> {
    parse_json_bytes(&decode_canonical_b64url(seg)?)
}

/// `assertCanonicalCompactJws(token, {parts, maxBytes, payload})`. `parts` is 3 (JWS) or 5 (JWE: the encrypted-key segment may
/// be empty); `json_payload` parses segment 1 of a JWS as a strict-JSON object.
pub fn assert_canonical_compact_jws(token: &Value, parts: usize, max_bytes: usize, json_payload: bool) -> Result<CanonicalJws, String> {
    let Some(t) = token.as_str() else { return Err(jws_err("not-a-string", None)) };
    if t.encode_utf16().count() > max_bytes {
        return Err(jws_err("too-long", None));
    }
    let segments: Vec<String> = t.split('.').map(String::from).collect();
    if segments.len() != parts {
        return Err(jws_err("bad-segment-count", Some(format!("{} != {parts}", segments.len()))));
    }
    let mut bytes = Vec::with_capacity(parts);
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            if parts == 5 && i == 1 {
                bytes.push(Vec::new());
                continue;
            }
            return Err(jws_err("empty-segment", Some(format!("segment {i}"))));
        }
        bytes.push(decode_canonical_b64url(seg)?);
    }
    let as_obj = |v: Value| match v {
        Value::Object(m) => Ok(m),
        _ => Err(jws_err("not-an-object", None)),
    };
    let header = as_obj(parse_json_bytes(&bytes[0])?)?;
    let payload = if parts == 3 && json_payload { Some(as_obj(parse_json_bytes(&bytes[1])?)?) } else { None };
    Ok(CanonicalJws { segments, header, payload, bytes })
}

/// RFC 7638 JWK thumbprint (`calculateJwkThumbprint`): base64url(hash(JSON of the required members in lexicographic order)).
pub fn jwk_thumbprint(jwk: &Value, hash: &str) -> Result<String, String> {
    let Some(o) = jwk.as_object() else { return Err("JWK must be an object".into()) };
    let members: &[&str] = match o.get("kty").and_then(Value::as_str) {
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        Some("RSA") => &["e", "kty", "n"],
        Some("oct") => &["k", "kty"],
        _ => return Err("\"kty\" (Key Type) Parameter missing or unsupported".into()),
    };
    let mut c = Map::new();
    for m in members {
        match o.get(*m) {
            Some(Value::String(s)) if !s.is_empty() => {
                c.insert((*m).into(), Value::String(s.clone()));
            }
            _ => {
                // jose's own labels, so the text is the reference's
                let label = match (o.get("kty").and_then(Value::as_str), *m) {
                    (Some("EC"), "crv") => "Curve",
                    (Some("OKP"), "crv") => "Subtype of Key Pair",
                    (Some("EC"), "x") => "X Coordinate",
                    (Some("OKP"), "x") => "Public Key",
                    (_, "y") => "Y Coordinate",
                    (_, "e") => "Exponent",
                    (_, "n") => "Modulus",
                    (_, "k") => "Key Value",
                    _ => "Key Type",
                };
                return Err(format!("\"{m}\" ({label}) Parameter missing or invalid"));
            }
        }
    }
    let text = js_stringify(&Value::Object(c));
    let d = match hash {
        "sha256" => sha2::Sha256::digest(text.as_bytes()).to_vec(),
        "sha384" => sha2::Sha384::digest(text.as_bytes()).to_vec(),
        "sha512" => sha2::Sha512::digest(text.as_bytes()).to_vec(),
        _ => return Err("digestAlgorithm must one of \"sha256\", \"sha384\", or \"sha512\"".into()),
    };
    Ok(b64_encode(&d))
}

/// A public key imported from a JWK.
#[derive(Debug, Clone)]
pub enum JwkKey {
    Ed25519([u8; 32]),
    Ec(PubKey),
    Rsa(PubKey),
    /// The 57-byte public key of an Ed448 JWK (feature `ed448`; without it Ed448 is refused).
    #[cfg(feature = "ed448")]
    Ed448(Vec<u8>),
}

/// Ed448 (RFC 8032, empty context) through OpenSSL 3, the vetted implementation (feature `ed448`).
#[cfg(feature = "ed448")]
mod ed448 {
    use openssl::pkey::{Id, PKey};
    use openssl::sign::{Signer, Verifier};

    pub fn valid_public(x: &[u8]) -> bool {
        x.len() == 57 && PKey::public_key_from_raw_bytes(x, Id::ED448).is_ok()
    }

    pub fn verify(x: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if x.len() != 57 || sig.len() != 114 {
            return false;
        }
        let Ok(k) = PKey::public_key_from_raw_bytes(x, Id::ED448) else { return false };
        Verifier::new_without_digest(&k).and_then(|mut v| v.verify_oneshot(sig, msg)).unwrap_or(false)
    }

    pub fn sign(seed: &[u8; 57], msg: &[u8]) -> Result<Vec<u8>, String> {
        let k = PKey::private_key_from_raw_bytes(seed, Id::ED448).map_err(|e| e.to_string())?;
        Signer::new_without_digest(&k).and_then(|mut s| s.sign_oneshot_to_vec(msg)).map_err(|e| e.to_string())
    }

    pub fn public_of(seed: &[u8; 57]) -> Result<Vec<u8>, String> {
        PKey::private_key_from_raw_bytes(seed, Id::ED448).and_then(|k| k.raw_public_key()).map_err(|e| e.to_string())
    }
}

fn b64_member(o: &Map<String, Value>, k: &str) -> Result<Vec<u8>, String> {
    // Node decodes a JWK member with Buffer's base64url reader, which skips whitespace
    o.get(k).and_then(Value::as_str).map(|s| s.chars().filter(|c| !c.is_ascii_whitespace()).collect::<String>()).and_then(|s| decode_b64u_strict(&s, None)).filter(|b| !b.is_empty()).ok_or_else(|| format!("invalid JWK member \"{k}\""))
}

/// Is `point` (SEC1 uncompressed) a valid point of `curve` (P-256, P-384 or P-521)?
pub fn ec_point_on_curve(curve: EcCurve, point: &[u8]) -> bool {
    match curve {
        EcCurve::P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok(),
        c => ec_point_valid(c, point),
    }
}

/// Import a PUBLIC JWK for `alg` (private members refused). Ed448 imports only with the `ed448` feature (refused without it).
pub fn import_public_jwk(jwk: &Value, alg: &str) -> Result<JwkKey, String> {
    let Some(o) = jwk.as_object() else { return Err("JWK must be an object".into()) };
    if ["d", "p", "q", "dp", "dq", "qi", "k"].iter().any(|m| o.contains_key(*m)) {
        return Err("JWK is not a public key".into());
    }
    let kty = o.get("kty").and_then(Value::as_str).unwrap_or("");
    let crv = o.get("crv").and_then(Value::as_str).unwrap_or("");
    match (alg, kty) {
        ("EdDSA", "OKP") if crv == "Ed25519" => {
            let x = b64_member(o, "x")?;
            let pk: [u8; 32] = x.try_into().map_err(|_| "invalid Ed25519 public key length".to_string())?;
            ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| "invalid Ed25519 public key".to_string())?;
            Ok(JwkKey::Ed25519(pk))
        }
        #[cfg(feature = "ed448")]
        ("EdDSA", "OKP") if crv == "Ed448" => {
            let x = b64_member(o, "x")?;
            if !ed448::valid_public(&x) {
                return Err("invalid Ed448 public key".into());
            }
            Ok(JwkKey::Ed448(x))
        }
        ("ES256", "EC") | ("ES384", "EC") | ("ES512", "EC") => {
            let (curve, want) = match (alg, crv) {
                ("ES256", "P-256") => (EcCurve::P256, 32),
                ("ES384", "P-384") => (EcCurve::P384, 48),
                ("ES512", "P-521") => (EcCurve::P521, 66),
                _ => return Err(format!("JWK curve '{crv}' does not match {alg}")),
            };
            let (x, y) = (b64_member(o, "x")?, b64_member(o, "y")?);
            if x.len() != want || y.len() != want {
                return Err("invalid EC JWK coordinate length".into());
            }
            let mut point = vec![4u8];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            if !ec_point_on_curve(curve, &point) {
                return Err("EC JWK point is not on the curve".into());
            }
            Ok(JwkKey::Ec(PubKey::Ec { curve, point }))
        }
        ("PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512", "RSA") => {
            if o.contains_key("oth") {
                return Err("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported".into());
            }
            let (n, e) = (b64_member(o, "n")?, b64_member(o, "e")?);
            let bits = n.iter().skip_while(|b| **b == 0).count() * 8;
            let lead = n.iter().find(|b| **b != 0).map_or(8, |b| b.leading_zeros() as usize);
            if bits.saturating_sub(lead) < 2048 {
                return Err(format!("{alg} requires key modulusLength to be 2048 bits or larger"));
            }
            Ok(JwkKey::Rsa(PubKey::Rsa { n, e }))
        }
        _ => Err(format!("unsupported JWK for {alg}")),
    }
}

/// Verify a JWS signature (`signing_input` = `header.payload` ASCII) under `key` for `alg`. Unsupported pairs are false.
pub fn verify_jws_signature(alg: &str, key: &JwkKey, signing_input: &[u8], sig: &[u8]) -> bool {
    match (alg, key) {
        ("EdDSA", JwkKey::Ed25519(pk)) => match <[u8; 64]>::try_from(sig) {
            Ok(s) => crate::verify_ed25519_strict(pk, signing_input, &s),
            Err(_) => false,
        },
        #[cfg(feature = "ed448")]
        ("EdDSA", JwkKey::Ed448(x)) => ed448::verify(x, signing_input, sig),
        ("ES256", JwkKey::Ec(k @ PubKey::Ec { curve: EcCurve::P256, .. })) => sig.len() == 64 && verify_p1363_sig(k, Hash::Sha256, signing_input, sig),
        ("ES384", JwkKey::Ec(k @ PubKey::Ec { curve: EcCurve::P384, .. })) => sig.len() == 96 && verify_p1363_sig(k, Hash::Sha384, signing_input, sig),
        ("ES512", JwkKey::Ec(PubKey::Ec { curve: EcCurve::P521, point })) => sig.len() == 132 && verify_p521(point, signing_input, sig),
        ("RS256", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pkcs1_verify(n, e, Hash::Sha256, signing_input, sig),
        ("RS384", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pkcs1_verify(n, e, Hash::Sha384, signing_input, sig),
        ("RS512", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pkcs1_verify(n, e, Hash::Sha512, signing_input, sig),
        ("PS256", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pss_verify(n, e, Hash::Sha256, 32, signing_input, sig),
        ("PS384", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pss_verify(n, e, Hash::Sha384, 48, signing_input, sig),
        ("PS512", JwkKey::Rsa(PubKey::Rsa { n, e })) => rsa_pss_verify(n, e, Hash::Sha512, 64, signing_input, sig),
        _ => false,
    }
}

/// ECDSA P-521 / SHA-512 over `msg`, `sig` = `r || s` (66 bytes each).
fn verify_p521(point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p521::ecdsa::signature::Verifier;
    let (Ok(vk), Ok(s)) = (p521::ecdsa::VerifyingKey::from_sec1_bytes(point), p521::ecdsa::Signature::from_slice(sig)) else { return false };
    vk.verify(msg, &s).is_ok()
}

/// HS256 / HS384 / HS512 over a shared secret (constant-time compare). Any other `alg` is false.
pub fn verify_hmac(alg: &str, secret: &[u8], signing_input: &[u8], sig: &[u8]) -> bool {
    macro_rules! hm {
        ($d:ty) => {{
            use hmac::Mac;
            let Ok(mut m) = <hmac::Hmac<$d> as Mac>::new_from_slice(secret) else { return false };
            m.update(signing_input);
            m.verify_slice(sig).is_ok()
        }};
    }
    match alg {
        "HS256" => hm!(sha2::Sha256),
        "HS384" => hm!(sha2::Sha384),
        "HS512" => hm!(sha2::Sha512),
        _ => false,
    }
}

/// The JOSE library's `crit` rules with the one extension it understands (`b64`, RFC 7797): `crit` must be a non-empty array
/// of non-empty strings, every name must be `b64` and present in the header, and `b64` must then be a boolean. Returns the
/// `b64` value (true when not critical). Messages are the reference library's.
pub fn check_crit_b64(header: &Map<String, Value>) -> Result<bool, String> {
    let Some(c) = header.get("crit") else { return Ok(true) };
    let list = c.as_array().filter(|a| !a.is_empty() && a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())));
    let Some(list) = list else { return Err("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present".into()) };
    for p in list.iter().filter_map(Value::as_str) {
        if p != "b64" {
            return Err(format!("Extension Header Parameter \"{p}\" is not recognized"));
        }
        if !header.contains_key(p) {
            return Err(format!("Extension Header Parameter \"{p}\" is missing"));
        }
    }
    header.get("b64").and_then(Value::as_bool).ok_or_else(|| "The \"b64\" (base64url-encode payload) Header Parameter must be a boolean".to_string())
}

/// A compact EdDSA (Ed25519) JWS over `header` and `payload` (serialized as `JSON.stringify` writes them, member order kept),
/// signed with the 32-byte seed.
pub fn sign_ed25519_jws(header: &Value, payload: &Value, seed: &[u8; 32]) -> String {
    use ed25519_dalek::Signer;
    let input = format!("{}.{}", b64_encode(js_stringify(header).as_bytes()), b64_encode(js_stringify(payload).as_bytes()));
    let sig = ed25519_dalek::SigningKey::from_bytes(seed).sign(input.as_bytes());
    format!("{input}.{}", b64_encode(&sig.to_bytes()))
}

/// A compact EdDSA (Ed448) JWS, signed with the 57-byte seed (feature `ed448`).
#[cfg(feature = "ed448")]
pub fn sign_ed448_jws(header: &Value, payload: &Value, seed: &[u8; 57]) -> Result<String, String> {
    let input = format!("{}.{}", b64_encode(js_stringify(header).as_bytes()), b64_encode(js_stringify(payload).as_bytes()));
    Ok(format!("{input}.{}", b64_encode(&ed448::sign(seed, input.as_bytes())?)))
}

/// The OKP public JWK `{kty, crv, x}` of an Ed448 seed (feature `ed448`).
#[cfg(feature = "ed448")]
pub fn ed448_public_jwk(seed: &[u8; 57]) -> Result<Value, String> {
    Ok(serde_json::json!({ "kty": "OKP", "crv": "Ed448", "x": b64_encode(&ed448::public_of(seed)?) }))
}

/// The OKP public JWK `{kty, crv, x}` of an Ed25519 seed.
pub fn ed25519_public_jwk(seed: &[u8; 32]) -> Value {
    let pk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": b64_encode(&pk) })
}

/// The JOSE library's header gate before a signature check: `crit` (no extension is understood here, so any is refused),
/// then `alg` present and in `allowed`. Messages are the reference library's.
pub fn check_jws_header(header: &Map<String, Value>, allowed: &[&str]) -> Result<String, String> {
    if let Some(c) = header.get("crit") {
        let list = c.as_array().filter(|a| !a.is_empty() && a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())));
        let Some(list) = list else { return Err("Extension Header Parameter \"crit\" must be an array of non-empty strings when present".into()) };
        // shortcut: `crit: ["b64"]` (admitted by the reference library with `b64: true`) is refused too; stricter, never looser
        return Err(format!("Extension Header Parameter \"{}\" is not recognized", list[0].as_str().unwrap_or("")));
    }
    let alg = header.get("alg").and_then(Value::as_str).filter(|a| !a.is_empty()).ok_or("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")?;
    if !allowed.contains(&alg) {
        return Err("\"alg\" (Algorithm) Header Parameter value not allowed".into());
    }
    Ok(alg.to_string())
}

/// What the JWT claims set is checked against (the reference library's `jwtVerify` options).
#[derive(Debug, Clone, Default)]
pub struct JwtClaimsCheck<'a> {
    /// Expected `typ` header (compared lower-cased, an `application/` prefix ignored).
    pub typ: Option<&'a str>,
    pub required: &'a [&'a str],
    pub audience: Option<&'a str>,
    pub clock_tolerance: f64,
    /// Unix seconds (whole: the reference floors the clock).
    pub now_sec: f64,
}

fn norm_typ(t: &str) -> String {
    let l = t.to_lowercase();
    l.strip_prefix("application/").map(String::from).unwrap_or(l)
}

/// `validateClaimsSet`: typ, required claims (in the library's order), audience, then `iat` / `nbf` / `exp`.
pub fn validate_jwt_claims(header: &Map<String, Value>, payload: &Map<String, Value>, c: &JwtClaimsCheck) -> Result<(), String> {
    if let Some(t) = c.typ {
        if !header.get("typ").and_then(Value::as_str).is_some_and(|h| norm_typ(h) == norm_typ(t)) {
            return Err("unexpected \"typ\" JWT header value".into());
        }
    }
    let mut presence: Vec<&str> = c.required.to_vec();
    if c.audience.is_some() {
        presence.push("aud");
    }
    presence.reverse();
    let mut seen = Vec::new();
    for k in presence {
        if seen.contains(&k) {
            continue;
        }
        seen.push(k);
        if !payload.contains_key(k) {
            return Err(format!("missing required \"{k}\" claim"));
        }
    }
    if let Some(a) = c.audience {
        let ok = match payload.get("aud") {
            Some(Value::String(s)) => s == a,
            Some(Value::Array(l)) => l.iter().any(|x| x.as_str() == Some(a)),
            _ => false,
        };
        if !ok {
            return Err("unexpected \"aud\" claim value".into());
        }
    }
    let num = |k: &str| -> Result<Option<f64>, String> {
        match payload.get(k) {
            None => Ok(None),
            Some(v) => v.as_f64().map(Some).ok_or_else(|| format!("\"{k}\" claim must be a number")),
        }
    };
    num("iat")?;
    // a non-finite clock or tolerance would make every nbf / exp comparison pass
    if !(c.now_sec.is_finite() && c.clock_tolerance.is_finite() && c.clock_tolerance >= 0.0) {
        return Err("the verifier clock or clockTolerance is not a finite number >= 0".into());
    }
    if let Some(nbf) = num("nbf")? {
        if !(nbf <= c.now_sec + c.clock_tolerance) {
            return Err("\"nbf\" claim timestamp check failed".into());
        }
    }
    if let Some(exp) = num("exp")? {
        if !(exp > c.now_sec - c.clock_tolerance) {
            return Err("\"exp\" claim timestamp check failed".into());
        }
    }
    Ok(())
}

thread_local! {
    static CLOCK_OVERRIDE_SEC: std::cell::Cell<Option<f64>> = const { std::cell::Cell::new(None) };
}

/// Run `f` with [`now_unix_sec`] reading `sec` on this thread: a replay of a reference that ran under a frozen clock injects it
/// here. The override is thread-local and restored when `f` returns, so nothing else observes it.
pub fn with_clock_sec<R>(sec: f64, f: impl FnOnce() -> R) -> R {
    let prev = CLOCK_OVERRIDE_SEC.with(|c| c.replace(Some(sec)));
    let r = f();
    CLOCK_OVERRIDE_SEC.with(|c| c.set(prev));
    r
}

/// The wall clock in whole Unix seconds (the injected clock inside [`with_clock_sec`]).
pub fn now_unix_sec() -> f64 {
    if let Some(s) = CLOCK_OVERRIDE_SEC.with(|c| c.get()) {
        return s;
    }
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64)
}
