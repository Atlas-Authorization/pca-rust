//! Compact JWS handling shared by the Azure Attestation and Confidential Space verifiers: the canonical base64url gate,
//! the header / payload / signature split, claim-byte decoding and the binding hash transform.

use super::util::{b64_lenient, b64url_enc, is_hex, sha256, sha512, hex_decode};
use serde_json::{Map, Value};

pub struct Jws {
    pub alg: String,
    pub kid: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub payload: Map<String, Value>,
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
}

/// `decodeCanonicalBase64url`: the one canonical unpadded spelling of a segment.
pub fn decode_canonical_b64url(seg: &str) -> Result<Vec<u8>, String> {
    let e = |reason: &str, detail: Option<&str>| match detail {
        Some(d) => format!("non-canonical compact JWS: {reason} ({d})"),
        None => format!("non-canonical compact JWS: {reason}"),
    };
    if !seg.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(e("bad-character", None));
    }
    if seg.len() % 4 == 1 {
        return Err(e("non-canonical-base64url", Some("impossible length")));
    }
    let bytes = b64_lenient(seg);
    if b64url_enc(&bytes) != seg {
        return Err(e("non-canonical-base64url", None));
    }
    Ok(bytes)
}

/// The text of V8's `JSON.parse` error for `text` (the common shapes: an unexpected token or the end of input).
pub fn js_json_error(text: &str, err: &serde_json::Error) -> String {
    use serde_json::error::Category;
    if err.classify() == Category::Eof || text.is_empty() {
        return "Unexpected end of JSON input".to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    if err.to_string().starts_with("trailing characters") {
        return format!("Unexpected non-whitespace character after JSON at position {}", err.column().saturating_sub(1));
    }
    // serde reports the column after the offending character for some errors; the token is the character at `col - 1`
    let at = err.column().saturating_sub(1).min(chars.len().saturating_sub(1));
    let tok = chars[at];
    let n = chars.len();
    let slice = |a: usize, b: usize| -> String { chars[a..b].iter().collect() };
    if n < 21 {
        format!("Unexpected token '{tok}', \"{text}\" is not valid JSON")
    } else if at < 10 {
        format!("Unexpected token '{tok}', \"{}\"... is not valid JSON", slice(0, at + 10))
    } else if at < n - 10 {
        format!("Unexpected token '{tok}', ...\"{}\"... is not valid JSON", slice(at - 10, at + 10))
    } else {
        format!("Unexpected token '{tok}', ...\"{}\" is not valid JSON", slice(at - 10, n))
    }
}

fn parse_json_segment(bytes: &[u8]) -> Result<Value, String> {
    let text = String::from_utf8_lossy(bytes).to_string();
    serde_json::from_str::<Value>(&text).map_err(|e| js_json_error(&text, &e))
}

/// Parse a compact JWS into its header fields, payload claims, signing input and signature. Verifies nothing.
/// `f` is the TypeScript function name that prefixes every message (`parseMaaJwt` / `parseGcpCsJwt`).
pub fn parse_jws(token: &str, f: &str) -> Result<Jws, String> {
    if token.is_empty() {
        return Err(format!("{f}: empty token"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("{f}: a compact JWS has exactly three dot-separated parts"));
    }
    let (h, p, s) = (parts[0], parts[1], parts[2]);
    if h.is_empty() || p.is_empty() || s.is_empty() {
        return Err(format!("{f}: empty JWS segment"));
    }
    let seg = |x: &str| -> Result<Value, String> {
        let b = decode_canonical_b64url(x)?;
        parse_json_segment(&b)
    };
    let hv = seg(h).map_err(|e| format!("{f}: malformed JSON segment: {e}"))?;
    let pv = seg(p).map_err(|e| format!("{f}: malformed JSON segment: {e}"))?;
    let header = match hv {
        Value::Object(o) => o,
        _ => return Err(format!("{f}: header is not a JSON object")),
    };
    let payload = match pv {
        Value::Object(o) => o,
        _ => return Err(format!("{f}: payload is not a JSON object")),
    };
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => return Err(format!("{f}: header has no alg")),
    };
    let signature = decode_canonical_b64url(s).map_err(|e| format!("{f}: malformed signature segment: {e}"))?;
    if signature.is_empty() {
        return Err(format!("{f}: empty signature"));
    }
    Ok(Jws {
        alg,
        kid: header.get("kid").and_then(Value::as_str).map(|x| x.to_string()),
        x5c: header.get("x5c").and_then(super::util::str_array),
        payload,
        signing_input: format!("{h}.{p}").into_bytes(),
        signature,
    })
}

/// `decodeClaimBytes`: hex (optionally `0x`-prefixed), else base64url / base64. `None` when nothing decodes.
pub fn decode_claim_bytes(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    let hx = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if is_hex(hx) && hx.len() % 2 == 0 {
        return hex_decode(hx);
    }
    let b = b64_lenient(trimmed);
    if b.is_empty() {
        None
    } else {
        Some(b)
    }
}

/// `transformBinding`: the hash applied to the binding before it is compared with a claim.
pub fn transform_binding(binding: &[u8], mode: Option<&str>) -> Vec<u8> {
    match mode {
        Some("sha256") => sha256(binding),
        Some("sha512") => sha512(binding),
        _ => binding.to_vec(),
    }
}

/// `Number.isFinite` claim.
pub fn num_claim(m: &Map<String, Value>, k: &str) -> Option<f64> {
    m.get(k).and_then(Value::as_f64)
}

/// `String(v)` of a possibly absent string claim.
pub fn js_str(v: Option<&str>) -> String {
    match v {
        Some(s) => s.to_string(),
        None => "undefined".to_string(),
    }
}
