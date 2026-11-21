//! WebAuthn step-up binding for PCA: a passkey assertion whose challenge is the action's threshold digest (or the approval
//! challenge over it and a render digest), verified natively (ES256 and Ed25519, strict encodings), plus the Secure Payment
//! Confirmation (`payment.get`) binding of the signed payment details to the canonical render.
//! Byte-identical to the TypeScript reference where the result is defined; refusal texts are the reference's.
use crate::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_AUTHENTICATOR_DATA_BYTES: usize = 4096;
pub const MAX_CLIENT_DATA_BYTES: usize = 8192;
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// COSE maps nest only as ignored values; past this depth the key is refused instead of risking the stack.
const MAX_COSE_DEPTH: usize = 128;
const OOB: &str = "Offset is outside the bounds of the DataView";
/// floor(n / 2) for the P-256 group order: an `s` above it is the high-S twin of a valid signature.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc,
    0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

fn b64u(b: &[u8]) -> String {
    crate::b64_encode(b)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

// ---- CBOR (the COSE_Key subset) ----------------------------------------------------------------------------------------

enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Map(BTreeMap<i64, Cbor>),
}

fn byte_at(d: &[u8], p: usize) -> Result<u8, String> {
    d.get(p).copied().ok_or_else(|| OOB.to_string())
}

fn be_at(d: &[u8], p: usize, n: usize) -> Result<u64, String> {
    let s = d.get(p..p + n).ok_or_else(|| OOB.to_string())?;
    Ok(s.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

fn read_cbor(d: &[u8], offset: usize, depth: usize) -> Result<(Cbor, usize), String> {
    if depth > MAX_COSE_DEPTH {
        return Err("cose: CBOR nesting too deep".into());
    }
    let initial = byte_at(d, offset)?;
    let (major, ai) = (initial >> 5, initial & 0x1f);
    let mut p = offset + 1;
    let arg = match ai {
        0..=23 => u64::from(ai),
        24 | 25 | 26 => {
            let n = 1usize << (ai - 24);
            let v = be_at(d, p, n)?;
            p += n;
            v
        }
        _ => return Err("cose: unsupported CBOR argument encoding (8-byte or indefinite length)".into()),
    };
    match major {
        0 => Ok((Cbor::Int(arg as i64), p)),
        1 => Ok((Cbor::Int(-1 - arg as i64), p)),
        2 => {
            let end = p as u64 + arg;
            if end > d.len() as u64 {
                return Err("cose: byte string length out of range".into());
            }
            Ok((Cbor::Bytes(d[p..end as usize].to_vec()), end as usize))
        }
        5 => {
            let mut m = BTreeMap::new();
            let mut q = p;
            for _ in 0..arg {
                let (k, next) = read_cbor(d, q, depth + 1)?;
                let Cbor::Int(k) = k else { return Err("cose: non-integer map key".into()) };
                let (v, next) = read_cbor(d, next, depth + 1)?;
                m.insert(k, v); // a duplicate label: the later one wins, as with a JS Map
                q = next;
            }
            Ok((Cbor::Map(m), q))
        }
        _ => Err(format!("cose: unsupported CBOR major type {major}")),
    }
}

fn cbor_string(v: Option<&Cbor>) -> String {
    match v {
        None => "undefined".into(),
        Some(Cbor::Int(n)) => n.to_string(),
        Some(Cbor::Bytes(b)) => b.iter().map(u8::to_string).collect::<Vec<_>>().join(","),
        Some(Cbor::Map(_)) => "[object Map]".into(),
    }
}

/// A COSE_Key (EC2 P-256 or OKP Ed25519) as a JWK. Trailing bytes after the key map are ignored, as in the reference.
pub fn cose_key_to_jwk(bytes: &[u8]) -> Result<Value, String> {
    let Cbor::Map(m) = read_cbor(bytes, 0, 0)?.0 else { return Err("coseKeyToJwk: COSE_Key is not a CBOR map".into()) };
    let int = |k: i64| match m.get(&k) {
        Some(Cbor::Int(n)) => Some(*n),
        _ => None,
    };
    let bstr = |k: i64| match m.get(&k) {
        Some(Cbor::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    };
    match int(1) {
        Some(2) => {
            if int(-1) != Some(1) {
                return Err("coseKeyToJwk: EC2 key is not P-256 (crv != 1)".into());
            }
            let (Some(x), Some(y)) = (bstr(-2), bstr(-3)) else { return Err("coseKeyToJwk: EC2 key missing an x/y coordinate".into()) };
            if x.len() != 32 || y.len() != 32 {
                return Err("coseKeyToJwk: EC2 coordinate is not 32 bytes".into());
            }
            Ok(json!({ "kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y), "alg": "ES256" }))
        }
        Some(1) => {
            if int(-1) != Some(6) {
                return Err("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)".into());
            }
            let Some(x) = bstr(-2) else { return Err("coseKeyToJwk: OKP key missing its public key".into()) };
            if x.len() != 32 {
                return Err("coseKeyToJwk: Ed25519 public key is not 32 bytes".into());
            }
            Ok(json!({ "kty": "OKP", "crv": "Ed25519", "x": b64u(x), "alg": "EdDSA" }))
        }
        _ => Err(format!("coseKeyToJwk: unsupported COSE key type (kty={})", cbor_string(m.get(&1)))),
    }
}

/// The credential public key: a COSE_Key as stored at registration, or a JWK.
#[derive(Clone, Copy)]
pub enum CredentialPublicKey<'a> {
    Cose(&'a [u8]),
    Jwk(&'a Value),
}

#[derive(PartialEq)]
enum Alg {
    Es256,
    EdDsa,
}

/// base64url (padding and the standard alphabet tolerated), with canonical trailing bits.
fn b64_any(v: Option<&Value>) -> Option<Vec<u8>> {
    let s = v?.as_str()?.trim_end_matches('=').replace('+', "-").replace('/', "_");
    crate::decode_b64u_strict(&s, None)
}

fn resolve_key(pk: CredentialPublicKey) -> Result<(Alg, Vec<u8>), String> {
    let owned;
    let jwk = match pk {
        CredentialPublicKey::Cose(b) => {
            owned = cose_key_to_jwk(b)?;
            &owned
        }
        CredentialPublicKey::Jwk(Value::Null) => return Err("Cannot read properties of null (reading 'kty')".into()),
        CredentialPublicKey::Jwk(j) => j,
    };
    match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") => {
            if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
                return Err("resolveKey: EC JWK is not P-256".into());
            }
            match (b64_any(jwk.get("x")), b64_any(jwk.get("y"))) {
                (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => Ok((Alg::Es256, [&[0x04u8][..], &x, &y].concat())),
                _ => Err("resolveKey: invalid EC JWK coordinates".into()),
            }
        }
        Some("OKP") => {
            if jwk.get("crv").and_then(Value::as_str) != Some("Ed25519") {
                return Err("resolveKey: OKP JWK is not Ed25519".into());
            }
            match b64_any(jwk.get("x")) {
                Some(x) if x.len() == 32 => Ok((Alg::EdDsa, x)),
                _ => Err("resolveKey: invalid OKP JWK public key".into()),
            }
        }
        _ => Err("resolveKey: unsupported public key".into()),
    }
}

// ---- authenticator data ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorFlags {
    pub up: bool,
    pub uv: bool,
    pub be: bool,
    pub bs: bool,
    pub at: bool,
    pub ed: bool,
}

impl AuthenticatorFlags {
    pub fn to_json(&self) -> Value {
        json!({ "up": self.up, "uv": self.uv, "be": self.be, "bs": self.bs, "at": self.at, "ed": self.ed })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: AuthenticatorFlags,
    pub sign_count: u32,
}

/// rpIdHash (32) || flags (1) || signCount (4, big-endian) || extensions; `None` when shorter than 37 bytes.
pub fn parse_authenticator_data(d: &[u8]) -> Option<ParsedAuthenticatorData> {
    if d.len() < 37 {
        return None;
    }
    let f = d[32];
    Some(ParsedAuthenticatorData {
        rp_id_hash: d[..32].try_into().ok()?,
        flags: AuthenticatorFlags { up: f & 0x01 != 0, uv: f & 0x04 != 0, be: f & 0x08 != 0, bs: f & 0x10 != 0, at: f & 0x40 != 0, ed: f & 0x80 != 0 },
        sign_count: u32::from_be_bytes(d[33..37].try_into().ok()?),
    })
}

// ---- challenges ------------------------------------------------------------------------------------------------------------

/// What a step-up challenge is derived from: the threshold digest (raw or canonical base64url), or the PCActn itself.
#[derive(Clone, Copy)]
pub enum StepUpSource<'a> {
    Digest(&'a [u8]),
    DigestB64u(&'a str),
    Actn(&'a Map<String, Value>),
}

/// The WebAuthn challenge for a step-up: the 32-byte threshold digest of the action.
pub fn build_step_up_challenge(src: StepUpSource) -> Result<Vec<u8>, String> {
    match src {
        StepUpSource::Digest(b) if b.len() == 32 => Ok(b.to_vec()),
        StepUpSource::Digest(_) => Err("buildStepUpChallenge: digest bytes must be 32 bytes".into()),
        StepUpSource::DigestB64u(s) => {
            crate::decode_b64u_strict(s, Some(32)).ok_or_else(|| "buildStepUpChallenge: digest is not a canonical base64url 32-byte value".into())
        }
        StepUpSource::Actn(m) => Ok(sha256(&crate::threshold_message(m)?)),
    }
}

pub fn step_up_challenge_b64u(src: StepUpSource) -> Result<String, String> {
    build_step_up_challenge(src).map(|b| b64u(&b))
}

/// The approval challenge: the step-up digest bound to the digest of what the approver was shown.
pub fn approval_challenge_for_actn(src: StepUpSource, render_digest: &str) -> Result<String, String> {
    crate::approval_challenge(&b64u(&build_step_up_challenge(src)?), render_digest)
}

pub fn build_approval_challenge(src: StepUpSource, render_digest: &str) -> Result<Vec<u8>, String> {
    let c = approval_challenge_for_actn(src, render_digest)?;
    crate::decode_b64u_strict(&c, Some(32)).ok_or_else(|| "approvalChallenge: challenge is not canonical".into())
}

// ---- Secure Payment Confirmation ---------------------------------------------------------------------------------------

/// JavaScript `===` between two JSON members (`None` is undefined; two objects are never the same reference).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// Property read with JavaScript semantics: `Err` is the TypeError of reading from null / undefined.
fn prop<'v>(v: Option<&'v Value>, k: &str) -> Result<Option<&'v Value>, String> {
    match v {
        None => Err(format!("Cannot read properties of undefined (reading '{k}')")),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{k}')")),
        Some(x) => Ok(x.as_object().and_then(|m| m.get(k))),
    }
}

/// Why `clientData.payment` does not bind the expected payment (`Ok(None)` when it does). The expectation must name the payee.
/// `Err` is a malformed expectation (null / missing `total`), which a verifier reports as a fail-closed error.
pub fn spc_payment_error(payment: &Value, e: &Value, rp_id: &str) -> Result<Option<String>, String> {
    let Some(p) = payment.as_object() else { return Ok(Some("clientData.payment is missing".into())) };
    let e = Some(e);
    if prop(e, "payeeName")?.is_none() && prop(e, "payeeOrigin")?.is_none() {
        return Ok(Some("the expectation names no payee (refused: a payment approval must bind the payee)".into()));
    }
    if !strict_eq(p.get("rpId"), Some(&Value::String(rp_id.into()))) {
        return Ok(Some("clientData.payment.rpId is not the verifier rpId".into()));
    }
    if !strict_eq(p.get("topOrigin"), prop(e, "topOrigin")?) {
        return Ok(Some("clientData.payment.topOrigin is not the verifier approval origin".into()));
    }
    let bad_total = Ok(Some("clientData.payment.total does not equal the canonical render".into()));
    let Some(total) = p.get("total").and_then(Value::as_object) else { return bad_total };
    let et = prop(e, "total")?;
    if !strict_eq(total.get("currency"), prop(et, "currency")?) || !strict_eq(total.get("value"), prop(et, "value")?) {
        return bad_total;
    }
    for k in ["payeeName", "payeeOrigin"] {
        let want = prop(e, k)?;
        if want.is_some() && !strict_eq(p.get(k), want) {
            return Ok(Some(format!("clientData.payment.{k} does not equal the canonical render")));
        }
    }
    Ok(None)
}

// ---- assertion verification --------------------------------------------------------------------------------------------

pub struct Assertion<'a> {
    pub authenticator_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature: &'a [u8],
    pub public_key: CredentialPublicKey<'a>,
}

#[derive(Clone, Copy)]
pub enum Challenge<'a> {
    Bytes(&'a [u8]),
    B64u(&'a str),
}

pub struct VerifyExpectations<'a> {
    pub expected_challenge: Option<Challenge<'a>>,
    pub rp_id: &'a str,
    pub origins: &'a [&'a str],
    pub require_uv: bool,
    /// Refuse a high-S ES256 signature (the malleable twin).
    pub require_low_s: bool,
    /// The stored counter (0 for a credential never used); `None` is refused. A non-integer is refused as not a uint32.
    pub stored_sign_count: Option<f64>,
    /// Called with (stored, reported) when a correctly signed assertion's counter did not increase.
    pub on_sign_count_regression: Option<&'a dyn Fn(u32, u32)>,
    /// Default true: a `crossOrigin: true` assertion is refused.
    pub reject_cross_origin: bool,
    /// Set for Secure Payment Confirmation (`payment.get`): the payment expectation, see [`spc_payment_error`].
    pub payment: Option<&'a Value>,
}

impl Default for VerifyExpectations<'_> {
    fn default() -> Self {
        VerifyExpectations {
            expected_challenge: None,
            rp_id: "",
            origins: &[],
            require_uv: false,
            require_low_s: false,
            stored_sign_count: None,
            on_sign_count_regression: None,
            reject_cross_origin: true,
            payment: None,
        }
    }
}

fn fail(reason: impl Into<String>) -> Value {
    json!({ "ok": false, "reason": reason.into() })
}

fn es256_ok(raw_point: &[u8], digest: &[u8], sig: &[u8], low_s: bool) -> bool {
    let rs = if sig.first() == Some(&0x30) && sig.len() != 64 {
        match crate::attest::x509::ecdsa_der_to_raw(sig, 32) {
            Some(rs) => rs,
            None => return false,
        }
    } else if sig.len() == 64 {
        sig.to_vec()
    } else {
        return false;
    };
    if low_s && rs[32..] > P256_HALF_ORDER[..] {
        return false;
    }
    crate::attest::x509::ecdsa_verify_raw(crate::attest::x509::EcCurve::P256, raw_point, digest, &rs)
}

/// Verify a WebAuthn assertion as a step-up: `{ok: true, alg, signCount, flags}` or `{ok: false, reason}`. Fails closed.
pub fn verify_assertion(a: &Assertion, e: &VerifyExpectations) -> Value {
    match verify_inner(a, e) {
        Ok(v) | Err(v) => v,
    }
}

fn verify_inner(a: &Assertion, e: &VerifyExpectations) -> Result<Value, Value> {
    if a.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES {
        return Err(fail("authenticatorData is too large"));
    }
    if a.client_data_json.len() > MAX_CLIENT_DATA_BYTES {
        return Err(fail("clientDataJSON is too large"));
    }
    if a.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(fail("signature is too large"));
    }
    if e.rp_id.is_empty() {
        return Err(fail("rpId is required"));
    }
    if e.origins.is_empty() {
        return Err(fail("origins allowlist is empty"));
    }
    let Some(stored) = e.stored_sign_count else { return Err(fail("storedSignCount is required (use 0 for a credential never used)")) };

    let text = std::str::from_utf8(a.client_data_json).map_err(|_| fail("clientDataJSON is not valid UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text); // TextDecoder drops a leading BOM
    let parsed: Value = crate::serde_json::from_str(text).map_err(|_| fail("clientDataJSON is not valid JSON"))?;
    let client = parsed.as_object().ok_or_else(|| fail("clientDataJSON is not a JSON object"))?;
    let want_type = if e.payment.is_some() { "payment.get" } else { "webauthn.get" };
    let ty = client.get("type");
    if ty.and_then(Value::as_str) != Some(want_type) {
        let shown = ty.map_or("undefined".into(), crate::intent_v2::js_value_string);
        return Err(fail(format!("clientData.type is not \"{want_type}\" ({shown})")));
    }
    if let Some(pe) = e.payment {
        match spc_payment_error(client.get("payment").unwrap_or(&Value::Null), pe, e.rp_id) {
            Ok(None) => {}
            Ok(Some(r)) => return Err(fail(r)),
            Err(x) => return Err(fail(format!("verification error (fail closed): {x}"))),
        }
    }

    let got = client.get("challenge").and_then(Value::as_str).and_then(|s| crate::decode_b64u_strict(s, None));
    let got = got.ok_or_else(|| fail("clientData.challenge is missing or not canonical base64url"))?;
    let exp = match e.expected_challenge {
        Some(Challenge::Bytes(b)) => Some(b.to_vec()),
        Some(Challenge::B64u(s)) => crate::decode_b64u_strict(s, None),
        None => None,
    };
    let exp = exp.ok_or_else(|| fail("expectedChallenge is not decodable"))?;
    if !ct_eq(&got, &exp) {
        return Err(fail("clientData.challenge does not match the step-up challenge"));
    }

    if e.reject_cross_origin {
        match client.get("crossOrigin") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => return Err(fail("clientData.crossOrigin is true")),
            Some(_) => return Err(fail("clientData.crossOrigin is not a boolean")),
        }
    }
    let origin = client.get("origin").and_then(Value::as_str).ok_or_else(|| fail("clientData.origin is missing"))?;
    if !e.origins.contains(&origin) {
        return Err(fail(format!("clientData.origin \"{origin}\" is not in the allowlist")));
    }

    let ad = parse_authenticator_data(a.authenticator_data).ok_or_else(|| fail("authenticatorData is too short (< 37 bytes)"))?;
    if !ct_eq(&ad.rp_id_hash, &sha256(e.rp_id.as_bytes())) {
        return Err(fail("rpIdHash does not match sha256(rpId)"));
    }
    if !ad.flags.up {
        return Err(fail("User Present (UP) flag is not set"));
    }
    if e.require_uv && !ad.flags.uv {
        return Err(fail("User Verified (UV) flag is required but not set"));
    }

    let signed = [a.authenticator_data, &sha256(a.client_data_json)].concat();
    let (alg, raw) = resolve_key(a.public_key).map_err(|x| fail(format!("public key could not be resolved: {x}")))?;
    let valid = match alg {
        Alg::Es256 => es256_ok(&raw, &sha256(&signed), a.signature, e.require_low_s),
        Alg::EdDsa => match (<[u8; 32]>::try_from(raw.as_slice()), <[u8; 64]>::try_from(a.signature)) {
            (Ok(pk), Ok(sg)) => crate::verify_ed25519_strict(&pk, &signed, &sg),
            _ => false,
        },
    };
    if !valid {
        return Err(fail("assertion signature did not verify"));
    }

    if stored.fract() != 0.0 || !stored.is_finite() || stored < 0.0 || (stored == 0.0 && stored.is_sign_negative()) || stored > f64::from(u32::MAX) {
        return Err(fail("storedSignCount is not a uint32"));
    }
    let stored = stored as u32;
    if (ad.sign_count != 0 || stored != 0) && ad.sign_count <= stored {
        if let Some(hook) = e.on_sign_count_regression {
            hook(stored, ad.sign_count);
        }
        return Err(fail("signCount did not increase (possible cloned authenticator)"));
    }
    Ok(json!({ "ok": true, "alg": if alg == Alg::Es256 { "ES256" } else { "EdDSA" }, "signCount": ad.sign_count, "flags": ad.flags.to_json() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_cose_nesting_is_refused_not_a_stack_overflow() {
        let mut b = vec![0xa1u8, 0x18, 0x64]; // {100: {100: ... }}
        for _ in 0..10_000 {
            b.extend_from_slice(&[0xa1, 0x18, 0x64]);
        }
        assert_eq!(cose_key_to_jwk(&b).unwrap_err(), "cose: CBOR nesting too deep");
    }
}
