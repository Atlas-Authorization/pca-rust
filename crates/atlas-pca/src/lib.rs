//! Reference verifier for the CORE PCActn checks (wire format v2): wire, version, audience, validity,
//! capability chain, grant_ref binding, Merkle plan inclusion, strict Ed25519 leaf signature, counter. Byte-matches
//! `@atlasauth/pca` (the shared conformance corpus defines the normative rules).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY as CompressedEdwards;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write;

pub use serde_json;

/// Ergonomic tower / axum middleware built on top of this verifier (feature `axum`).
#[cfg(feature = "axum")]
pub mod middleware;

const SIG_DOMAIN: &[u8] = b"atlas-pca/actn/v2\x00";
const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\x00";
const SHARE_DOMAIN_PREFIX: &[u8] = b"atlas-pca/share/";
const SIGNERSET_DOMAIN: &[u8] = b"atlas-pca/signerset/v1\x00";
const SHARE_SUITE_TAG: &[u8] = b"\x00atlas-pca/share-suite/v1\x00";
const DEFAULT_REV: &str = "reversible";

/// Wire format version this verifier accepts.
pub const PCACTN_WIRE_VERSION: i64 = 2;
pub const MAX_CHAIN_DEPTH: usize = 16;
/// Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain.
pub const MAX_CAVEATS_PER_HOP: usize = 256;
pub const MAX_CAVEATS_PER_CHAIN: usize = 1024;
/// Shared reason string for the caveat caps (identical across all PCA verifiers).
pub const CAVEAT_LIMIT_REASON: &str = "chain exceeds caveat limit (max 256 per hop, 1024 per chain)";
/// Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing.
pub const MAX_ARTIFACT_BYTES: usize = 524_288;
/// Shared reason string for the raw-size cap (identical across all PCA verifiers).
pub const ARTIFACT_SIZE_REASON: &str = "artifact exceeds size limit (max 524288 bytes)";

/// True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work.
pub fn caveat_limit_exceeded(chain: &[Value]) -> bool {
    let mut total = 0usize;
    for c in chain {
        let n = c.get("caveats").and_then(Value::as_array).map_or(0, Vec::len);
        if n > MAX_CAVEATS_PER_HOP {
            return true;
        }
        total += n;
        if total > MAX_CAVEATS_PER_CHAIN {
            return true;
        }
    }
    false
}
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_CHARS: usize = 1 << 20;
pub const MAX_DECIMAL_DIGITS: usize = 15;
pub const MAX_LIFETIME_MS: i64 = 3_600_000;
pub const MAX_SKEW_MS: i64 = 60_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;
const MAX_AUD_LEN: usize = 256;
const MAX_NONCE_LEN: usize = 128;

fn b64_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// STRICT base64url (RFC 4648 section 5, no padding): only `[A-Za-z0-9_-]`, no whitespace, `len % 4 != 1`,
/// zero trailing bits (re-encoding must reproduce the input). When `len` is given the DECODED length must
/// equal it. Returns `None` on ANY deviation.
pub fn decode_b64u_strict(s: &str, len: Option<usize>) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_') {
        return None;
    }
    if b.len() % 4 == 1 {
        return None;
    }
    if let Some(n) = len {
        // checked: a caller-supplied n > usize::MAX/4 must fail closed, not panic (debug) or wrap (release)
        match n.checked_mul(4) {
            Some(m) if b.len() == m.div_ceil(3) => {}
            _ => return None,
        }
    }
    let bytes = URL_SAFE_NO_PAD.decode(b).ok()?;
    if b64_encode(&bytes) != s {
        return None; // non-canonical trailing bits
    }
    if let Some(n) = len {
        if bytes.len() != n {
            return None;
        }
    }
    Some(bytes)
}

/// Verdict for the core checks. `checks[name]` is true when it passed. A wire failure is terminal and is
/// the ONLY entry (`{wire: false}`); otherwise all of wire, version, audience, validity, chain,
/// plan_inclusion, leaf_signature, counter are present.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub allow: bool,
    pub checks: BTreeMap<String, bool>,
    pub reason: String,
}

fn wire_fail(why: impl Into<String>) -> Verdict {
    let mut checks = BTreeMap::new();
    checks.insert("wire".to_string(), false);
    Verdict { allow: false, checks, reason: format!("wire: {}", why.into()) }
}

// ---- numbers ---------------------------------------------------------------------------

/// Strict-profile check of one JSON number (see README section 3). `None` when acceptable.
fn number_error(n: &Number) -> Option<String> {
    if let Some(i) = n.as_i64() {
        return if i.unsigned_abs() > MAX_SAFE as u64 {
            Some("integer outside the safe range".into())
        } else {
            None
        };
    }
    if let Some(u) = n.as_u64() {
        return if u > MAX_SAFE as u64 { Some("integer outside the safe range".into()) } else { None };
    }
    let f = match n.as_f64() {
        Some(f) if f.is_finite() => f,
        _ => return Some("non-finite number".into()),
    };
    if f == 0.0 && f.is_sign_negative() {
        return Some("negative zero".into());
    }
    if f.fract() == 0.0 {
        return if f.abs() > MAX_SAFE as f64 { Some("integer outside the safe range".into()) } else { None };
    }
    if f.abs() < 1e-6 {
        return Some("non-integer magnitude below 1e-6".into());
    }
    // Rust's Display for f64 is the shortest round-trip decimal and never uses an exponent.
    let s = format!("{}", f.abs());
    let digits: String = s.chars().filter(|c| *c != '.').collect();
    if digits.trim_start_matches('0').len() > MAX_DECIMAL_DIGITS {
        return Some("more than 15 significant digits".into());
    }
    None
}

/// A value that is a strictly-valid number AND integer-valued.
fn safe_int(v: &Value) -> Option<i64> {
    let n = match v {
        Value::Number(n) => n,
        _ => return None,
    };
    if number_error(n).is_some() {
        return None;
    }
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    if let Some(u) = n.as_u64() {
        return i64::try_from(u).ok();
    }
    let f = n.as_f64()?;
    if f.fract() == 0.0 {
        Some(f as i64)
    } else {
        None
    }
}

fn fmt_number(n: &Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f == 0.0 {
        return "0".to_string();
    }
    // Rust's Display for f64 is shortest round-trip and never uses exponent notation.
    format!("{}", f)
}

// ---- canonicalization ------------------------------------------------------------------

/// LENIENT canonical JSON (capability content addressing, Merkle leaves): keys sorted BYTEWISE over UTF-8,
/// compact, escape only `"` `\` and < U+0020, shortest round-trip numbers, `-0` -> `0`.
pub fn canonicalize(v: &Value) -> String {
    let mut s = String::new();
    let _ = ser(&mut s, v, false, 1);
    s
}

/// STRICT canonical form of a signed PCActn body (wire v2): as [`canonicalize`] plus integer-valued numbers
/// must be safe integers (no `-0`), non-integers plain decimal <= 15 significant digits and >= 1e-6, and
/// nesting depth <= 32. Errs on any violation.
pub fn canonicalize_strict(v: &Value) -> Result<String, String> {
    let mut s = String::new();
    ser(&mut s, v, true, 1)?;
    Ok(s)
}

fn js_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ser(out: &mut String, v: &Value, strict: bool, depth: usize) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => js_string(out, s),
        Value::Number(n) => {
            if strict {
                if let Some(e) = number_error(n) {
                    return Err(format!("canonicalize: {e}"));
                }
            }
            out.push_str(&fmt_number(n));
        }
        Value::Array(a) => {
            if strict && depth > MAX_JSON_DEPTH {
                return Err("canonicalize: nesting too deep".into());
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser(out, x, strict, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            if strict && depth > MAX_JSON_DEPTH {
                return Err("canonicalize: nesting too deep".into());
            }
            // String ordering is bytewise over UTF-8 (== code point order).
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                js_string(out, k);
                out.push(':');
                ser(out, &m[k.as_str()], strict, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

/// base64url-nopad(sha256(canonical(v))) (lenient canonical form). Content addressing only: the verifiers never
/// use it for a protocol digest (see [`hash_canonical_strict`]).
pub fn hash_canonical(v: &Value) -> String {
    b64_encode(&sha(canonicalize(v).as_bytes()))
}

/// base64url-nopad(sha256(STRICT canonical(v))), like the reference `hashCanonical` (hash.ts `canonicalBytes` is
/// `canonicalizeStrict`): depth <= [`MAX_JSON_DEPTH`], safe integers only, plain-decimal non-integers. `None` on an
/// out-of-profile value. Every protocol digest the verifiers compute (capability / grant hash, hop body digest,
/// caveat comparison, Merkle leaf) goes through it: a lenient digest would accept a correctly signed out-of-profile hop
/// that the reference refuses, and would recurse without bound on a deep caller-built value.
pub fn hash_canonical_strict(v: &Value) -> Option<String> {
    canonicalize_strict(v).ok().map(|c| b64_encode(&sha(c.as_bytes())))
}

/// `a` and `b` have the same strict digest; `false` when either is out of profile (never equal-by-both-failing).
fn same_strict_hash(a: &Value, b: &Value) -> bool {
    matches!((hash_canonical_strict(a), hash_canonical_strict(b)), (Some(x), Some(y)) if x == y)
}

// ---- strict JSON parser ----------------------------------------------------------------

/// STRICT JSON profile for signed bytes (README section 2): hand-written RFC 8259 parser rejecting comments,
/// trailing commas, a BOM, non-JSON whitespace, duplicate keys (post-unescape), lone surrogates (raw or
/// escaped), raw control chars in strings, unknown escapes, nesting > 32, input > 2^20 UTF-8 bytes, and any
/// number not in the canonical wire form. Returns any JSON value (the PCActn check requires an object).
pub fn strict_parse(text: &str) -> Result<Value, String> {
    strict_parse_depth(text, MAX_JSON_DEPTH)
}

/// R6-01: [`strict_parse`] for an untrusted transport envelope that WRAPS a PCActn one level deep (the middleware body
/// `{"pcactn": ...}`): the same strict profile (duplicate keys refused at ANY depth, strict numbers, no lone surrogates,
/// size cap) with the depth cap `MAX_JSON_DEPTH` applied to the WHOLE envelope, as the reference does (require-pca.ts
/// `defaultExtract` strict-parses the body text): the wrapped PCActn therefore gets one level less than in header mode.
pub fn strict_parse_envelope(text: &str) -> Result<Value, String> {
    strict_parse_depth(text, MAX_JSON_DEPTH)
}

fn strict_parse_depth(text: &str, max_depth: usize) -> Result<Value, String> {
    if text.len() > MAX_JSON_CHARS {
        return Err("strict JSON: input too large".into());
    }
    let mut p = Parser { b: text.as_bytes(), i: 0, max_depth };
    let v = p.value(1)?;
    p.ws();
    if p.i < p.b.len() {
        return Err(p.err("trailing characters after the JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    max_depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, m: &str) -> String {
        format!("strict JSON: {m} (at offset {})", self.i)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    /// `self.i` points at the `u`; reads 4 hex digits and leaves `self.i` on the last one.
    fn hex4(&mut self) -> Result<u32, String> {
        let s = self.b.get(self.i + 1..self.i + 5).ok_or_else(|| self.err("bad \\u escape"))?;
        if !s.iter().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.err("bad \\u escape"));
        }
        let h = std::str::from_utf8(s).map_err(|_| self.err("bad \\u escape"))?;
        let v = u32::from_str_radix(h, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err(self.err("unterminated string")),
            };
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                0..=0x1f => return Err(self.err("raw control character in string")),
                b'\\' => {
                    self.i += 1;
                    let e = match self.peek() {
                        Some(e) => e,
                        None => return Err(self.err("unterminated string")),
                    };
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..=0xDBFF).contains(&hi) {
                                if self.b.get(self.i + 1) == Some(&b'\\') && self.b.get(self.i + 2) == Some(&b'u') {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(self.err("lone surrogate in string"));
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return Err(self.err("lone surrogate in string"));
                                }
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(self.err("lone surrogate in string"));
                            } else {
                                hi
                            };
                            let ch = char::from_u32(cp).ok_or_else(|| self.err("bad code point"))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                    self.i += 1;
                }
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| self.err("invalid UTF-8"))
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("bad number")),
        }
        let mut frac = false;
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("bad number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            frac = true;
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            return Err(self.err("exponent form is not allowed (use a plain decimal)"));
        }
        let lex = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("bad number"))?;
        if lex == "-0" {
            return Err(self.err("negative zero is not allowed"));
        }
        // a leading zero followed by a digit ("01") leaves a digit behind: rejected by the caller's
        // structural check ("expected , or }"), exactly like the reference parser.
        if frac {
            if lex.ends_with('0') {
                return Err(self.err("trailing fractional zero is not canonical"));
            }
            let digits: String = lex.chars().filter(|c| *c != '-' && *c != '.').collect();
            if digits.trim_start_matches('0').len() > MAX_DECIMAL_DIGITS {
                return Err(self.err("more than 15 significant digits"));
            }
            let v: f64 = lex.parse().map_err(|_| self.err("bad number"))?;
            if v != 0.0 && v.abs() < 1e-6 {
                return Err(self.err("non-integer magnitude below 1e-6 is not allowed"));
            }
            let n = Number::from_f64(v).ok_or_else(|| self.err("bad number"))?;
            Ok(Value::Number(n))
        } else {
            let abs = lex.trim_start_matches('-');
            if abs.len() > 16 {
                return Err(self.err("integer outside the safe range"));
            }
            let mag: i64 = abs.parse().map_err(|_| self.err("bad number"))?;
            if mag > MAX_SAFE {
                return Err(self.err("integer outside the safe range"));
            }
            Ok(Value::Number(Number::from(if lex.starts_with('-') { -mag } else { mag })))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        self.ws();
        let ch = match self.peek() {
            Some(c) => c,
            None => return Err(self.err("unexpected end of input")),
        };
        match ch {
            b'{' => {
                if depth > self.max_depth {
                    return Err(self.err("nesting too deep"));
                }
                self.i += 1;
                let mut o = Map::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Object(o));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return Err(self.err("expected a string key"));
                    }
                    let k = self.string()?;
                    if o.contains_key(&k) {
                        return Err(self.err("duplicate key"));
                    }
                    self.ws();
                    if self.peek() != Some(b':') {
                        return Err(self.err("expected \":\""));
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    o.insert(k, v);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(o));
                        }
                        _ => return Err(self.err("expected \",\" or \"}\"")),
                    }
                }
            }
            b'[' => {
                if depth > self.max_depth {
                    return Err(self.err("nesting too deep"));
                }
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(a));
                        }
                        _ => return Err(self.err("expected \",\" or \"]\"")),
                    }
                }
            }
            b'"' => Ok(Value::String(self.string()?)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => {
                let rest = &self.b[self.i..];
                if rest.starts_with(b"true") {
                    self.i += 4;
                    Ok(Value::Bool(true))
                } else if rest.starts_with(b"false") {
                    self.i += 5;
                    Ok(Value::Bool(false))
                } else if rest.starts_with(b"null") {
                    self.i += 4;
                    Ok(Value::Null)
                } else {
                    Err(self.err("unexpected token"))
                }
            }
        }
    }
}

// ---- Merkle ----------------------------------------------------------------------------

/// Merkle leaf hash over the STRICT canonical form (like the reference); `None` on an out-of-profile leaf.
fn leaf_hash(leaf: &Value) -> Option<Vec<u8>> {
    let mut m = vec![0x00u8];
    m.extend_from_slice(canonicalize_strict(leaf).ok()?.as_bytes());
    Some(sha(&m))
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + l.len() + r.len());
    m.push(0x01);
    m.extend_from_slice(l);
    m.extend_from_slice(r);
    sha(&m)
}

fn split(n: u64) -> u64 {
    let mut k = 1u64;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn build(hs: &[Vec<u8>]) -> Vec<u8> {
    if hs.len() == 1 {
        return hs[0].clone();
    }
    let k = split(hs.len() as u64) as usize;
    node_hash(&build(&hs[..k]), &build(&hs[k..]))
}

/// RFC-6962-shaped Merkle root (split at the largest power of two < n).
pub fn merkle_root(leaves: &[Value]) -> Result<String, String> {
    if leaves.is_empty() {
        return Err("empty leaf set".into());
    }
    let hs: Vec<Vec<u8>> = leaves.iter().map(leaf_hash).collect::<Option<_>>().ok_or("leaf is outside the strict JSON profile")?;
    Ok(b64_encode(&build(&hs)))
}

/// Sibling sides (leaf -> root) for leaf `index` in a tree of `size` leaves (RFC 6962 split).
fn path_shape(index: u64, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut idx = index;
    let mut n = size;
    while n > 1 {
        let k = split(n);
        if idx < k {
            out.push(b'R');
            n = k;
        } else {
            out.push(b'L');
            idx -= k;
            n -= k;
        }
    }
    out.reverse();
    out
}

/// Never panics; malformed proofs return false. `index`/`size` are bound to the path shape
/// (`size >= 1`, `0 <= index < size`, path length and every side recomputed from them).
pub fn verify_inclusion(root: &str, proof: Option<&Map<String, Value>>, leaf: &Value) -> bool {
    let proof = match proof {
        Some(p) => p,
        None => return false,
    };
    let path = match proof.get("path").and_then(Value::as_array) {
        Some(p) => p,
        None => return false,
    };
    let (index, size) = match (proof.get("index").and_then(safe_int), proof.get("size").and_then(safe_int)) {
        (Some(i), Some(s)) => (i, s),
        _ => return false,
    };
    if size < 1 || index < 0 || index >= size {
        return false;
    }
    let shape = path_shape(index as u64, size as u64);
    if shape.len() != path.len() {
        return false;
    }
    let mut h = match leaf_hash(leaf) {
        Some(h) => h,
        None => return false,
    };
    for (i, s) in path.iter().enumerate() {
        let step = match s.as_object() {
            Some(s) => s,
            None => return false,
        };
        let side = step.get("side").and_then(Value::as_str).unwrap_or("");
        if side.as_bytes() != [shape[i]] {
            return false;
        }
        let sib = match step.get("hash").and_then(Value::as_str).and_then(|x| decode_b64u_strict(x, Some(32))) {
            Some(b) => b,
            None => return false,
        };
        h = if side == "L" { node_hash(&sib, &h) } else { node_hash(&h, &sib) };
    }
    b64_encode(&h) == root
}

/// hashCanonical(params ?? {}).
pub fn params_digest(params: Option<&Value>) -> String {
    match params {
        Some(p) if !p.is_null() => hash_canonical(p),
        _ => hash_canonical(&Value::Object(Map::new())),
    }
}

fn conditions_digest_default() -> String {
    let mut m = Map::new();
    m.insert("pre".into(), Value::Null);
    m.insert("post".into(), Value::Null);
    hash_canonical(&Value::Object(m))
}

fn plan_leaf(node_id: Option<&Value>, action: Option<&Map<String, Value>>, cond: &str) -> Option<Value> {
    let node_id = match node_id {
        Some(v) if !v.is_null() => v.clone(),
        _ => return None,
    };
    let get = |k: &str| action.and_then(|a| a.get(k)).cloned().unwrap_or(Value::Null);
    let pd = match get("params_digest") {
        Value::Null => Value::String(params_digest(None)),
        v => v,
    };
    let rc = match get("reversibility_class") {
        Value::Null => Value::String(DEFAULT_REV.into()),
        v => v,
    };
    let mut m = Map::new();
    m.insert("node_id".into(), node_id);
    m.insert("verb".into(), get("verb"));
    m.insert("resource".into(), get("resource"));
    m.insert("params_digest".into(), pd);
    m.insert("reversibility_class".into(), rc);
    m.insert("conditions".into(), Value::String(cond.to_string()));
    Some(Value::Object(m))
}

// ---- keys ------------------------------------------------------------------------------

/// STRICT RFC 8032 verification: exact lengths, canonical base64url, canonical point encodings (y < p),
/// canonical S (S < L), rejects small-order AND mixed-order (torsion) public key and R, then
/// `verify_strict` (cofactorless equation, also rejecting weak keys).
fn verify_b64u(pubkey: &str, msg: &[u8], sig: &str) -> bool {
    let pk = match decode_b64u_strict(pubkey, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
        Some(a) => a,
        None => return false,
    };
    let sg = match decode_b64u_strict(sig, Some(64)).and_then(|b| <[u8; 64]>::try_from(b).ok()) {
        Some(a) => a,
        None => return false,
    };
    verify_ed25519_strict(&pk, msg, &sg)
}

fn verify_ed25519_strict(pk: &[u8; 32], msg: &[u8], sg: &[u8; 64]) -> bool {
    let a = match CompressedEdwards(*pk).decompress() {
        Some(p) => p,
        None => return false,
    };
    if a.compress().to_bytes() != *pk {
        return false; // non-canonical encoding of A
    }
    let mut rb = [0u8; 32];
    rb.copy_from_slice(&sg[..32]);
    let r = match CompressedEdwards(rb).decompress() {
        Some(p) => p,
        None => return false,
    };
    if r.compress().to_bytes() != rb {
        return false; // non-canonical encoding of R
    }
    if a.is_small_order() || r.is_small_order() || !a.is_torsion_free() || !r.is_torsion_free() {
        return false;
    }
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sg[32..]);
    if !bool::from(Scalar::from_canonical_bytes(sb).is_some()) {
        return false; // S >= L
    }
    let vk = match VerifyingKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify_strict(msg, &Signature::from_bytes(sg)).is_ok()
}

// ---- B4 post-quantum crypto-agility (ML-DSA-65 / FIPS-204) -----------------------------
//
// An ADDITIVE, backward-compatible algorithm-agility slot for the PCActn leaf signature, mirroring
// the `@atlasauth/pca` and Go implementations. Absent `alg` (or `alg == "ed25519"`) is BYTE-IDENTICAL to
// the pre-B4 wire. Suites:
//   - "ed25519"                     classical 64-byte Ed25519 `sig` (unchanged).
//   - "ml-dsa-65"                   pure PQ: `sig` is an ML-DSA-65 (FIPS-204) signature verified under `pq_pk`.
//   - "hybrid-ed25519-ml-dsa-65"    BOTH Ed25519 `sig` (under the leaf holder) AND ML-DSA-65 `pq_sig`
//                                   (under `pq_pk`) over the same canonical message; both must verify.
// `alg` and `pq_pk` are SIGNED; `sig` and `pq_sig` are the signatures, stripped from the signed body.
// The ML-DSA primitive is `fips204` (FIPS-204, category 3), empty context — matching @noble/post-quantum
// (vectors) and cloudflare/circl (go-pca): public key 1952 bytes, signature 3309 bytes.

/// ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

struct SigSuite {
    alg: &'static str,
    /// Decoded byte length REQUIRED in the primary `sig` field for this suite.
    sig_bytes: usize,
    /// A `pq_pk` (ML-DSA-65 public key) field is REQUIRED (and forbidden otherwise).
    needs_pq_pk: bool,
    /// A `pq_sig` field is REQUIRED — ML-DSA sig separate from `sig` (hybrid). Forbidden otherwise.
    needs_pq_sig: bool,
}

/// The closed algorithm registry.
fn sig_suite(name: &str) -> Option<SigSuite> {
    match name {
        "ed25519" => Some(SigSuite { alg: "ed25519", sig_bytes: 64, needs_pq_pk: false, needs_pq_sig: false }),
        "ml-dsa-65" => Some(SigSuite {
            alg: "ml-dsa-65",
            sig_bytes: ML_DSA_65_SIGNATURE_BYTES,
            needs_pq_pk: true,
            needs_pq_sig: false,
        }),
        "hybrid-ed25519-ml-dsa-65" => Some(SigSuite {
            alg: "hybrid-ed25519-ml-dsa-65",
            sig_bytes: 64,
            needs_pq_pk: true,
            needs_pq_sig: true,
        }),
        _ => None,
    }
}

/// Resolve the suite for a PCActn `alg`: absent => ed25519; a known name => that suite; anything else
/// (unknown name, non-string, null) => `None` (FAIL-CLOSED: the caller rejects it).
fn resolve_sig_alg(alg: Option<&Value>) -> Option<SigSuite> {
    match alg {
        None => sig_suite("ed25519"),
        Some(Value::String(s)) => sig_suite(s),
        Some(_) => None,
    }
}

fn b64_len(v: Option<&Value>, n: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| decode_b64u_strict(s, Some(n)).is_some())
}

/// ML-DSA-65 verify over raw bytes (empty context). A wrong length or malformed input returns false.
fn ml_dsa65_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};
    let pk_arr: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = match pk.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; ML_DSA_65_SIGNATURE_BYTES] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(msg, &sig_arr, &[]) // empty context, matching @noble/post-quantum and cloudflare/circl
}

/// `ml_dsa65_verify` over base64url key and signature; false on any decoding error.
/// Private on purpose: the only caller is [`ml_dsa65_verify_pinned`], which takes a [`pinned::PinnedPq`].
fn ml_dsa65_verify_b64u(pk_b64u: &str, msg: &[u8], sig_b64u: Option<&Value>) -> bool {
    let pk = match decode_b64u_strict(pk_b64u, Some(ML_DSA_65_PUBLIC_KEY_BYTES)) {
        Some(b) => b,
        None => return false,
    };
    let sg = match sig_b64u
        .and_then(Value::as_str)
        .and_then(|s| decode_b64u_strict(s, Some(ML_DSA_65_SIGNATURE_BYTES)))
    {
        Some(b) => b,
        None => return false,
    };
    ml_dsa65_verify(&pk, msg, &sg)
}

/// Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. `Ok(())` when well-formed, else a short reason.
/// Strict + fail-closed: unknown alg, wrong sizes, or a field not used by the suite being present all fail.
fn validate_signature_wire(p: &Map<String, Value>) -> Result<(), String> {
    validate_suite_fields(p, true)
}

/// 0.4.1: a threshold share's signature fields, validated PER SUITE exactly like the leaf's (`alg` absent = ed25519 with a
/// 64-byte `sig` and no `pq_sig`; ml-dsa-65 a 3309-byte `sig`; the hybrid a 64-byte `sig` plus a 3309-byte `pq_sig`), EXCEPT
/// that a share's `pq_pk` is not judged here: it is an optional echo checked against the signer set by the threshold check.
fn validate_share_signature_wire(s: &Map<String, Value>) -> Result<(), String> {
    validate_suite_fields(s, false)
}

fn validate_suite_fields(p: &Map<String, Value>, check_pq_pk: bool) -> Result<(), String> {
    let alg = p.get("alg");
    if let Some(a) = alg {
        if !a.is_string() {
            return Err("'alg' must be a string".into());
        }
    }
    let suite = match resolve_sig_alg(alg) {
        Some(s) => s,
        None => return Err(format!("unknown signature alg '{}'", alg.map(Value::to_string).unwrap_or_default())),
    };
    if !b64_len(p.get("sig"), suite.sig_bytes) {
        return Err(format!("'sig' is not canonical base64url ({} bytes) for alg '{}'", suite.sig_bytes, suite.alg));
    }
    if !check_pq_pk {
        // share: `pq_pk` is an optional echo, judged by verify_threshold_share against the signer set
    } else if suite.needs_pq_pk {
        if !b64_len(p.get("pq_pk"), ML_DSA_65_PUBLIC_KEY_BYTES) {
            return Err(format!("'pq_pk' is not canonical base64url ({ML_DSA_65_PUBLIC_KEY_BYTES} bytes)"));
        }
    } else if p.get("pq_pk").is_some() {
        return Err(format!("'pq_pk' must be absent for alg '{}'", suite.alg));
    }
    if suite.needs_pq_sig {
        if !b64_len(p.get("pq_sig"), ML_DSA_65_SIGNATURE_BYTES) {
            return Err(format!("'pq_sig' is not canonical base64url ({ML_DSA_65_SIGNATURE_BYTES} bytes)"));
        }
    } else if p.get("pq_sig").is_some() {
        return Err(format!("'pq_sig' must be absent for alg '{}'", suite.alg));
    }
    Ok(())
}

/// Verify the leaf signature under the PCActn's suite. FAIL-CLOSED: unknown alg, a missing component, or any
/// invalid component returns false.
///   - ed25519:   Ed25519 `sig` under `holder`.
///   - ml-dsa-65: ML-DSA-65 `sig` under `pq_pk`.
///   - hybrid:    Ed25519 `sig` under `holder` AND ML-DSA-65 `pq_sig` under `pq_pk`; BOTH must verify.
///
/// The PQ half verifies ONLY under `pq` (a [`pinned::PinnedPq`], minted solely by [`pinned::resolve_pq_key`] or the
/// explicitly named caller-vouched constructor), never under a `pq_pk` read off the artifact being verified (R3-01 / R4-01).
fn verify_suite(
    alg: Option<&Value>,
    holder: &str,
    pq: Option<&pinned::PinnedPq>,
    msg: &[u8],
    sig: Option<&Value>,
    pq_sig: Option<&Value>,
) -> bool {
    let suite = match resolve_sig_alg(alg) {
        Some(s) => s,
        None => return false,
    };
    let sig_str = match sig.and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    match suite.alg {
        "ed25519" => verify_b64u(holder, msg, sig_str),
        "ml-dsa-65" => ml_dsa65_verify_pinned(pq, msg, sig),
        "hybrid-ed25519-ml-dsa-65" => {
            verify_b64u(holder, msg, sig_str) && ml_dsa65_verify_pinned(pq, msg, pq_sig)
        }
        _ => false,
    }
}

fn ml_dsa65_verify_pinned(pq: Option<&pinned::PinnedPq>, msg: &[u8], sig_b64u: Option<&Value>) -> bool {
    match pq {
        Some(k) => ml_dsa65_verify_b64u(k.key(), msg, sig_b64u),
        None => false,
    }
}

/// The single key-resolution choke point (R3-01 / R4-01). `PinnedPq` has a private field and no public constructor,
/// so code outside this module can obtain one only from [`resolve_pq_key`] (verifier-side authority) or the explicitly
/// named [`PinnedPq::caller_vouched`].
mod pinned {
    use super::{holder_pq_commitment, Value};
    use std::collections::HashMap;

    /// An opaque PQ verification key.
    pub(super) struct PinnedPq {
        key: String,
    }

    impl PinnedPq {
        pub(super) fn key(&self) -> &str {
            &self.key
        }

        /// The caller asserts the key is authorised by some other mechanism. Named loudly on purpose.
        pub(super) fn caller_vouched(pk: &str) -> Option<PinnedPq> {
            if pk.is_empty() {
                None
            } else {
                Some(PinnedPq { key: pk.to_string() })
            }
        }
    }

    /// Mirrors `resolvePqVerifyKey` in packages/pca/src/pq.ts. Returns the key to verify under, or `None` (REFUSE)
    /// when no verifier-side authority vouches for the artifact's `pq_pk`:
    ///   1. `trusted_pk`: a key the verifier itself holds (the stored grant). Used as is.
    ///   2. `pq_pins[identity]` (own entry only): the artifact's `pq_pk` MUST equal the pin; a differing pin refuses.
    ///   3. `holder_pq`: the artifact's `pq_pk` must hash to the signer's committed `holder_pq` (F-2).
    /// Natives have no `allowUnboundPq`: an artifact's own key is never enough.
    pub(super) fn resolve_pq_key(
        identity: Option<&str>,
        artifact_pk: Option<&Value>,
        holder_pq: Option<&Value>,
        pq_pins: Option<&HashMap<String, String>>,
        trusted_pk: Option<&str>,
    ) -> Option<PinnedPq> {
        if let Some(t) = trusted_pk {
            if !t.is_empty() {
                return Some(PinnedPq { key: t.to_string() });
            }
        }
        let pk = match artifact_pk {
            Some(Value::String(s)) if !s.is_empty() => s.as_str(),
            _ => return None,
        };
        if let (Some(pins), Some(id)) = (pq_pins, identity) {
            if let Some(pinned) = pins.get(id) {
                return if pinned == pk { Some(PinnedPq { key: pk.to_string() }) } else { None };
            }
        }
        match holder_pq {
            Some(Value::String(c)) if holder_pq_commitment(pk) == *c => Some(PinnedPq { key: pk.to_string() }),
            _ => None,
        }
    }
}

// ---- capability chain ------------------------------------------------------------------

/// Hash of the full capability, including its signature.
pub fn cap_hash(c: &Value) -> String {
    hash_canonical(c)
}

/// `true` when `v`, sitting at container depth `at` (the hop object itself is depth 1, its fields' values depth 2),
/// nests deeper than [`MAX_JSON_DEPTH`]. ITERATIVE and stops at the first container past the cap, so a caller-built value
/// of any depth is measured without recursion (a recursive clone / serialisation of it would overflow the stack).
fn deeper_than_cap(v: &Value, at: usize) -> bool {
    let mut st: Vec<(&Value, usize)> = vec![(v, at)];
    while let Some((x, d)) = st.pop() {
        let kids: Box<dyn Iterator<Item = &Value>> = match x {
            Value::Array(a) => Box::new(a.iter()),
            Value::Object(m) => Box::new(m.values()),
            _ => continue,
        };
        if d > MAX_JSON_DEPTH {
            return true;
        }
        st.extend(kids.map(|k| (k, d + 1)));
    }
    false
}

/// The hop BODY (the fields `signable_hop_body` copies) is out of the strict depth profile: the reference cannot hash it
/// (`hop N: malformed body`). Checked before the body is cloned.
fn body_too_deep(c: &Map<String, Value>) -> bool {
    ["issuer", "holder", "caveats", "parent", "holder_pq", "alg", "pq_pk"]
        .iter()
        .any(|k| c.get(*k).is_some_and(|v| deeper_than_cap(v, 2)))
}

fn body_of(c: &Map<String, Value>) -> Value {
    let g = |k: &str| c.get(k).cloned().unwrap_or(Value::Null);
    let mut m = Map::new();
    m.insert("issuer".into(), g("issuer"));
    m.insert("holder".into(), g("holder"));
    m.insert("caveats".into(), g("caveats"));
    m.insert("parent".into(), g("parent"));
    if let Some(hp) = c.get("holder_pq") {
        m.insert("holder_pq".into(), hp.clone());
    }
    Value::Object(m)
}

const HOLDER_PQ_DOMAIN: &[u8] = b"atlas-pca/holder-pq/v1\0";

/// Mirrors holderPqCommitment in capability.ts: b64u(sha256(domain || utf8(pq_pk string))).
fn holder_pq_commitment(pq_pk: &str) -> String {
    let mut m = HOLDER_PQ_DOMAIN.to_vec();
    m.extend_from_slice(pq_pk.as_bytes());
    b64_encode(&sha(&m))
}

fn alg_name(alg: Option<&Value>) -> String {
    match alg {
        None => "ed25519".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => "\u{0}non-string".to_string(),
    }
}

/// Mirrors suitePolicyError: `None` policy allows everything; a present (even empty) list enforces.
fn suite_allowed(alg: Option<&Value>, allowed: Option<&[String]>) -> bool {
    match allowed {
        None => true,
        Some(l) => {
            let n = alg_name(alg);
            l.iter().any(|a| *a == n)
        }
    }
}

/// Mirrors pqBindingError (always strict, no allowUnboundPq): a suite carrying a PQ key is accepted only if
/// `pq_pk` hashes to the signer's committed `holder_pq`.
fn pq_binding_ok(alg: Option<&Value>, pq_pk: Option<&Value>, committed: Option<&Value>) -> bool {
    match resolve_sig_alg(alg) {
        Some(su) if su.needs_pq_pk => matches!(
            (pq_pk, committed),
            (Some(Value::String(pk)), Some(Value::String(c))) if holder_pq_commitment(pk) == *c
        ),
        _ => true,
    }
}

fn str_of<'a>(c: &'a Map<String, Value>, k: &str) -> &'a str {
    c.get(k).and_then(Value::as_str).unwrap_or("")
}

/// body_of + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
/// key-swap breaks the hop digest), byte-identical to body_of for ed25519. Mirrors signableBody in
/// capability.ts. Returns `Err(reason)` for an unknown `alg` (fail-closed).
fn signable_hop_body(c: &Map<String, Value>) -> Result<Value, String> {
    let suite = match resolve_sig_alg(c.get("alg")) {
        Some(s) => s,
        None => {
            return Err(format!("unknown signature alg '{}'", c.get("alg").map(Value::to_string).unwrap_or_default()));
        }
    };
    let mut body = body_of(c);
    if suite.alg != "ed25519" {
        if let Value::Object(ref mut m) = body {
            m.insert("alg".into(), Value::String(suite.alg.to_string()));
            if suite.needs_pq_pk {
                if let Some(pk @ Value::String(_)) = c.get("pq_pk") {
                    m.insert("pq_pk".into(), pk.clone());
                }
            }
        }
    }
    Ok(body)
}

fn check_sig(c: &Map<String, Value>, signer: &str, label: &str, pq: Option<&pinned::PinnedPq>) -> Option<String> {
    // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
    if resolve_sig_alg(c.get("alg")).is_some() && body_too_deep(c) {
        return Some(format!("{label}: malformed body"));
    }
    let body = match signable_hop_body(c) {
        Ok(b) => b,
        Err(e) => return Some(format!("{label}: {e}")),
    };
    let digest = match hash_canonical_strict(&body) {
        Some(d) => d,
        None => return Some(format!("{label}: malformed body")),
    };
    let bd = str_of(c, "body_digest");
    let id = str_of(c, "id");
    if digest != bd || id != bd {
        return Some(format!("{label}: body digest mismatch"));
    }
    let msg = decode_b64u_strict(bd, Some(32)).map(|d| {
        let mut m = CAP_DOMAIN.to_vec();
        m.extend_from_slice(&d);
        m
    });
    // Suite-agile hop verification: ed25519 == verify_b64u(signer, msg, sig); hybrid requires BOTH the
    // Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`); pure ml-dsa-65 verifies `sig`
    // under the RESOLVED `pq` key (never the hop's own `pq_pk`). verify_suite dispatches on the hop's `alg`.
    match msg {
        Some(msg) if verify_suite(c.get("alg"), signer, pq, &msg, c.get("sig"), c.get("pq_sig")) => None,
        _ => Some(format!("{label}: bad signature (not signed by expected key)")),
    }
}

/// Mirrors `wellTyped` in capability.ts: id/issuer/holder/body_digest/sig are strings; alg/pq_pk/pq_sig/holder_pq/parent are
/// absent or strings (JSON null is NOT absent); caveats is an array of objects each carrying a string `type`. A correctly
/// SIGNED but ill-typed hop is refused like in the reference (R6-05).
fn hop_well_typed(c: &Value) -> bool {
    let o = match c.as_object() {
        Some(o) => o,
        None => return false,
    };
    ["id", "issuer", "holder", "body_digest", "sig"].iter().all(|k| is_str(o.get(*k)))
        && ["alg", "pq_pk", "pq_sig", "holder_pq", "parent"].iter().all(|k| o.get(*k).map_or(true, Value::is_string))
        && o.get("caveats").and_then(Value::as_array).is_some_and(|cv| {
            cv.iter().all(|x| x.as_object().is_some_and(|d| is_str(d.get("type"))))
        })
}

/// Mirrors verifyChain in capability.ts. `Ok(())` when valid, else `Err(reason)`. The 16-hop cap is
/// enforced before any signature work.
///
/// No PQ authority is supplied, so a non-ed25519 (pure `ml-dsa-65` or hybrid) ROOT is always refused (R4-01); use
/// [`verify_chain_policy`] with `pq_pins` / `trusted_root` to accept one.
pub fn verify_chain(chain: &[Value], expected_root_issuer: Option<&str>) -> Result<(), String> {
    verify_chain_policy(chain, expected_root_issuer, None, None, None)
}

/// Reason a non-ed25519 root is refused without verifier-side PQ authority (R4-01); exact text is conformance-checked.
fn root_pq_pin_reason(alg: &str) -> String {
    format!("hop 0: root suite '{alg}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)")
}

/// Mirrors `rootPq` in capability.ts. The root has no parent holding a `holder_pq` commitment, so a PQ-carrying root's key
/// must come from a verifier-side authority: the verifier's stored copy of this very grant (`trusted_root`, same content
/// hash) or a pin for `root.issuer`. `Ok(None)` for an ed25519 root (no PQ key needed).
fn resolve_root_pq(
    root: &Map<String, Value>,
    root_val: &Value,
    pq_pins: Option<&std::collections::HashMap<String, String>>,
    trusted_root: Option<&Value>,
) -> Result<Option<pinned::PinnedPq>, String> {
    let suite = match resolve_sig_alg(root.get("alg")) {
        Some(s) => s,
        None => return Ok(None), // unknown suite: check_sig refuses it
    };
    if !suite.needs_pq_pk {
        return Ok(None);
    }
    let pk = root.get("pq_pk");
    let trusted: Option<&str> = match (trusted_root, pk) {
        (Some(t), Some(Value::String(s))) if same_strict_hash(t, root_val) => Some(s.as_str()),
        _ => None,
    };
    match pinned::resolve_pq_key(root.get("issuer").and_then(Value::as_str), pk, None, pq_pins, trusted) {
        Some(k) => Ok(Some(k)),
        None => Err(root_pq_pin_reason(suite.alg)),
    }
}

/// [`verify_chain`] with an optional allowed-suites policy (`None` = none; `Some(&[])` refuses every suite) and the
/// verifier-side PQ authority for a non-ed25519 ROOT (R4-01): `pq_pins` maps the root issuer (Ed25519, base64url) to its
/// ML-DSA public key (a pin that differs from the root's `pq_pk` is a refusal); `trusted_root` is the verifier's own stored
/// root capability (accepted when its content hash equals the presented root's). Ed25519 roots need neither.
pub fn verify_chain_policy(
    chain: &[Value],
    expected_root_issuer: Option<&str>,
    allowed: Option<&[String]>,
    pq_pins: Option<&std::collections::HashMap<String, String>>,
    trusted_root: Option<&Value>,
) -> Result<(), String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"));
    }
    if caveat_limit_exceeded(chain) {
        return Err(CAVEAT_LIMIT_REASON.into());
    }
    for (i, c) in chain.iter().enumerate() {
        if !hop_well_typed(c) {
            return Err(format!("hop {i}: malformed capability"));
        }
    }
    let root = chain[0].as_object().ok_or("hop 0: malformed")?;
    if root.contains_key("parent") {
        return Err("hop 0: root must not have a parent".into());
    }
    if let Some(exp) = expected_root_issuer {
        if root.get("issuer").and_then(Value::as_str) != Some(exp) {
            return Err("hop 0: root issuer is not the expected principal".into());
        }
    }
    if !suite_allowed(root.get("alg"), allowed) {
        return Err(format!("hop 0: signature suite '{}' is not allowed by this verifier's suite policy", alg_name(root.get("alg"))));
    }
    let root_pq = resolve_root_pq(root, &chain[0], pq_pins, trusted_root)?;
    if let Some(e) = check_sig(root, str_of(root, "issuer"), "hop 0", root_pq.as_ref()) {
        return Err(e);
    }
    for i in 1..chain.len() {
        let label = format!("hop {i}");
        let (parent, c) = match (chain[i - 1].as_object(), chain[i].as_object()) {
            (Some(p), Some(c)) => (p, c),
            _ => return Err(format!("{label}: malformed")),
        };
        let ph = hash_canonical_strict(&chain[i - 1]);
        if ph.is_none() || c.get("parent").and_then(Value::as_str) != ph.as_deref() {
            return Err(format!("{label}: broken parent link"));
        }
        if c.get("issuer") != parent.get("holder") {
            return Err(format!("{label}: issuer is not the parent's bound holder"));
        }
        if !suite_allowed(c.get("alg"), allowed) {
            return Err(format!("{label}: signature suite '{}' is not allowed by this verifier's suite policy", alg_name(c.get("alg"))));
        }
        if !pq_binding_ok(c.get("alg"), c.get("pq_pk"), parent.get("holder_pq")) {
            return Err(format!("{label}: pq_pk does not match the signer's committed holder_pq (F-2)"));
        }
        let hop_pq = pinned::resolve_pq_key(parent.get("holder").and_then(Value::as_str), c.get("pq_pk"), parent.get("holder_pq"), None, None);
        if let Some(e) = check_sig(c, str_of(parent, "holder"), &label, hop_pq.as_ref()) {
            return Err(e);
        }
        let empty = Vec::new();
        let pc = parent.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        let cc = c.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        if cc.len() < pc.len() {
            return Err(format!("{label}: drops parent caveat(s)"));
        }
        for j in 0..pc.len() {
            if !same_strict_hash(&cc[j], &pc[j]) {
                return Err(format!("{label}: caveat {j} altered or reordered"));
            }
        }
    }
    Ok(())
}

// ---- wire format v2 --------------------------------------------------------------------

const REQUIRED_FIELDS: [&str; 14] = [
    "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter",
    "risk_claim", "aud", "iat", "exp", "sig",
];
const OPTIONAL_FIELDS: [&str; 12] = [
    "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
    "threshold", "zk_compliance", "bond_ref",
    // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as pre-B4.
    "alg", "pq_pk", "pq_sig",
];

fn b32(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| decode_b64u_strict(s, Some(32)).is_some())
}

fn is_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}

fn is_int(v: Option<&Value>) -> bool {
    v.and_then(safe_int).is_some()
}

fn closed(o: &Map<String, Value>, allowed: &[&str], label: &str) -> Result<(), String> {
    for k in o.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("unknown field '{label}{k}'"));
        }
    }
    Ok(())
}

fn obj<'a>(v: Option<&'a Value>, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.and_then(Value::as_object).ok_or_else(|| format!("'{what}' must be an object"))
}

/// Validate the wire form (README section 1/3/5): closed field sets, presence, JSON types, safe integers,
/// canonical fixed-length base64url, and that the whole signed body admits the strict canonical encoding.
/// `Ok(())` when well-formed, else a short reason.
pub fn validate_wire(pcactn: &Value) -> Result<(), String> {
    let p = pcactn.as_object().ok_or("PCActn is not an object")?;
    for k in p.keys() {
        if !REQUIRED_FIELDS.contains(&k.as_str()) && !OPTIONAL_FIELDS.contains(&k.as_str()) {
            return Err(format!("unknown field '{k}'"));
        }
    }
    for k in REQUIRED_FIELDS {
        if !p.contains_key(k) {
            return Err(format!("missing field '{k}'"));
        }
    }
    // every signed byte must be strict-canonical-encodable (`sig`, `threshold`, `pq_sig` are unsigned)
    let mut body = Map::new();
    for (k, v) in p {
        if k != "sig" && k != "threshold" && k != "pq_sig" {
            body.insert(k.clone(), v.clone());
        }
    }
    canonicalize_strict(&Value::Object(body))?;

    for k in ["ver", "counter", "iat", "exp"] {
        if !is_int(p.get(k)) {
            return Err(format!("'{k}' must be a safe integer"));
        }
    }
    match p.get("aud").and_then(Value::as_str) {
        Some(a) if !a.is_empty() && a.len() <= MAX_AUD_LEN => {}
        _ => return Err("'aud' must be a non-empty string".into()),
    }
    if let Some(n) = p.get("nonce") {
        match n.as_str() {
            Some(s) if !s.is_empty() && s.len() <= MAX_NONCE_LEN => {}
            _ => return Err("'nonce' must be a non-empty string".into()),
        }
    }
    // B4 crypto-agility: the signature fields (`alg`, `sig`, `pq_pk`, `pq_sig`) are validated per suite.
    // With no `alg` this asserts exactly `sig` is 64-byte canonical b64u and `pq_pk`/`pq_sig` are absent —
    // i.e. BYTE-IDENTICAL wire behaviour to the pre-B4 reference. Unknown `alg` fails closed.
    validate_signature_wire(p)?;
    if !b32(p.get("grant_ref")) {
        return Err("'grant_ref' is not canonical base64url (32 bytes)".into());
    }

    let a = obj(p.get("action"), "action")?;
    closed(a, &["verb", "resource", "params_digest", "reversibility_class"], "action.")?;
    if !is_str(a.get("verb")) || !is_str(a.get("resource")) || !is_str(a.get("reversibility_class")) {
        return Err("action.verb/resource/reversibility_class must be strings".into());
    }
    if !b32(a.get("params_digest")) {
        return Err("'action.params_digest' is not canonical base64url (32 bytes)".into());
    }

    let pl = obj(p.get("plan"), "plan")?;
    closed(pl, &["root", "inclusion_proof", "node_id", "conditions_digest"], "plan.")?;
    if !b32(pl.get("root")) {
        return Err("'plan.root' is not canonical base64url (32 bytes)".into());
    }
    if !is_str(pl.get("node_id")) {
        return Err("'plan.node_id' must be a string".into());
    }
    if let Some(cd) = pl.get("conditions_digest") {
        if !b32(Some(cd)) {
            return Err("'plan.conditions_digest' must be a canonical base64url string (32 bytes)".into());
        }
    }
    let ip = obj(pl.get("inclusion_proof"), "plan.inclusion_proof")?;
    closed(ip, &["index", "size", "path"], "plan.inclusion_proof.")?;
    if !is_int(ip.get("index")) {
        return Err("'plan.inclusion_proof.index' must be a safe integer".into());
    }
    if !is_int(ip.get("size")) {
        return Err("'plan.inclusion_proof.size' must be a safe integer".into());
    }
    let path = ip
        .get("path")
        .and_then(Value::as_array)
        .ok_or("'plan.inclusion_proof.path' must be an array")?;
    for (i, st) in path.iter().enumerate() {
        let st = st.as_object().ok_or_else(|| format!("proof step {i} must be an object"))?;
        for k in st.keys() {
            if k != "side" && k != "hash" {
                return Err(format!("unknown field 'path[{i}].{k}'"));
            }
        }
        match st.get("side").and_then(Value::as_str) {
            Some("L") | Some("R") => {}
            _ => return Err(format!("proof step {i}: side must be 'L' or 'R'")),
        }
        if !b32(st.get("hash")) {
            return Err(format!("proof step {i}: hash is not canonical base64url (32 bytes)"));
        }
    }

    let chain = p.get("cap_chain").and_then(Value::as_array).ok_or("'cap_chain' must be an array")?;
    for (i, c) in chain.iter().enumerate() {
        let c = c.as_object().ok_or_else(|| format!("cap_chain[{i}] must be an object"))?;
        closed(
            c,
            &["id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig", "holder_pq"],
            &format!("cap_chain[{i}]."),
        )?;
        for k in ["id", "issuer", "holder", "body_digest"] {
            if !b32(c.get(k)) {
                return Err(format!("cap_chain[{i}].{k} is not canonical base64url (32 bytes)"));
            }
        }
        // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the leaf.
        // Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical pre-B4 hop).
        if let Err(e) = validate_signature_wire(c) {
            return Err(format!("cap_chain[{i}]: {e}"));
        }
        if let Some(par) = c.get("parent") {
            if !b32(Some(par)) {
                return Err(format!("cap_chain[{i}].parent is not canonical base64url (32 bytes)"));
            }
        }
        if let Some(hp) = c.get("holder_pq") {
            if !b32(Some(hp)) {
                return Err(format!("cap_chain[{i}].holder_pq is not canonical base64url (32 bytes)"));
            }
        }
        let ok = c.get("caveats").and_then(Value::as_array).is_some_and(|cv| {
            cv.iter().all(|x| x.as_object().is_some_and(|o| is_str(o.get("type"))))
        });
        if !ok {
            return Err(format!("cap_chain[{i}].caveats must be an array of {{type,...}} objects"));
        }
    }

    let at = p.get("attestation").and_then(Value::as_object);
    match at {
        Some(at) if is_int(at.get("epoch")) => {
            if !(is_str(at.get("quote_digest"))
                && is_str(at.get("model_id"))
                && is_str(at.get("measurement"))
                && is_str(at.get("operator")))
            {
                return Err("attestation string fields must be strings".into());
            }
        }
        _ => return Err("'attestation' must be an object with an integer 'epoch'".into()),
    }
    let pv = p.get("provenance").and_then(Value::as_object);
    let pv_ok = pv.is_some_and(|pv| {
        is_str(pv.get("causal_hash"))
            && matches!(pv.get("taint_level"), Some(Value::Number(_)))
            && pv
                .get("trusted_refs")
                .and_then(Value::as_array)
                .is_some_and(|r| r.iter().all(Value::is_string))
    });
    if !pv_ok {
        return Err("'provenance' is malformed".into());
    }
    let fr_ok = p.get("freshness").and_then(Value::as_object).is_some_and(|fr| {
        is_int(fr.get("epoch")) && is_str(fr.get("beacon_ref")) && is_str(fr.get("accumulator_witness"))
    });
    if !fr_ok {
        return Err("'freshness' is malformed".into());
    }
    let rc_ok = p.get("risk_claim").and_then(Value::as_object).is_some_and(|rc| {
        matches!(rc.get("r"), Some(Value::Number(_))) && matches!(rc.get("inputs"), Some(Value::Object(_)))
    });
    if !rc_ok {
        return Err("'risk_claim' is malformed".into());
    }

    // optional signed slots
    if let Some(c) = p.get("caution") {
        match c.as_f64() {
            Some(f) if c.is_number() && (0.0..=1.0).contains(&f) => {}
            _ => return Err("'caution' must be a number in [0,1]".into()),
        }
    }
    if let Some(v) = p.get("rationale_commitment") {
        if !b32(Some(v)) {
            return Err("'rationale_commitment' is not canonical base64url (32 bytes)".into());
        }
    }
    if let Some(v) = p.get("tool_binding") {
        if !b32(Some(v)) {
            return Err("'tool_binding' is not canonical base64url (32 bytes)".into());
        }
    }
    if let Some(v) = p.get("progress_step") {
        if !v.is_object() {
            return Err("'progress_step' must be an object".into());
        }
    }
    if let Some(v) = p.get("prohibition_evidence") {
        if !v.is_object() && !v.is_array() {
            return Err("'prohibition_evidence' must be an object or array".into());
        }
    }
    if let Some(th) = p.get("threshold") {
        let shares = th
            .as_object()
            .and_then(|t| t.get("shares"))
            .and_then(Value::as_array)
            .ok_or("'threshold' must be {shares:[...]}")?;
        for (i, s) in shares.iter().enumerate() {
            let s = match s.as_object() {
                Some(s) if is_str(s.get("role")) => s,
                _ => return Err(format!("threshold.shares[{i}] is malformed")),
            };
            if !b32(s.get("publicKey")) {
                return Err(format!("threshold.shares[{i}].publicKey is not canonical base64url (32 bytes)"));
            }
            // 0.4.1: per suite (it used to be a fixed 64 bytes, so a pure post-quantum share could never be carried).
            validate_share_signature_wire(s).map_err(|e| format!("threshold.shares[{i}]: {e}"))?;
        }
    }
    Ok(())
}

// ---- PCActn ----------------------------------------------------------------------------

/// SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig`, `threshold`, `pq_sig`)).
pub fn threshold_message(p: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let mut body = Map::new();
    for (k, v) in p {
        if k != "sig" && k != "threshold" && k != "pq_sig" {
            body.insert(k.clone(), v.clone());
        }
    }
    let canon = canonicalize_strict(&Value::Object(body))?;
    let mut m = SIG_DOMAIN.to_vec();
    m.extend_from_slice(&sha(canon.as_bytes()));
    Ok(m)
}

/// Recompute the signer-set hash committed by a threshold share (v2.1):
/// `sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role}]))`.
/// FAIL-CLOSED: `None` on any malformed entry.
fn signer_set_hash(signer_set: &[Value]) -> Option<Vec<u8>> {
    // `pq_pk` is carried ONLY when registered (additive: ed25519-only sets hash as before).
    let mut entries: Vec<(&str, &str, Option<&str>)> = Vec::with_capacity(signer_set.len());
    for e in signer_set {
        let o = e.as_object()?;
        let role = o.get("role")?.as_str()?;
        let pk = o.get("publicKey")?.as_str()?;
        entries.push((role, pk, o.get("pq_pk").and_then(Value::as_str)));
    }
    entries.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));
    let arr = Value::Array(
        entries
            .iter()
            .map(|(role, pk, pq)| {
                let mut m = Map::new();
                if let Some(pq) = pq {
                    m.insert("pq_pk".into(), Value::String((*pq).to_string()));
                }
                m.insert("publicKey".into(), Value::String((*pk).to_string()));
                m.insert("role".into(), Value::String((*role).to_string()));
                Value::Object(m)
            })
            .collect(),
    );
    let canon = canonicalize_strict(&arr).ok()?;
    let mut m = SIGNERSET_DOMAIN.to_vec();
    m.extend_from_slice(canon.as_bytes());
    Some(sha(&m))
}

/// Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1), whether
/// or not this crate implements the suite: a signer set is validated exactly like the reference.
const PQ_PK_LENGTHS: [usize; 7] = [1952, 2592, 32, 64, 897, 1793, 97484];
const SIGNER_ROLES: [&str; 3] = ["agent", "guardian", "principal"];

/// R6-03: validate the WHOLE signer set like the reference (`decideThreshold` BuildReg): every entry an object with a known
/// role (case-sensitive) and a canonical 32-byte `publicKey`; a present `pq_pk` (JSON null is present) is canonical
/// base64url of a registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the same
/// `pq_pk`. Returns `(role, publicKey, pq_pk)` rows (one per role), or `None` when the set is malformed.
fn validate_signer_set(signer_set: &[Value]) -> Option<Vec<(&str, &str, Option<&str>)>> {
    let mut reg: Vec<(&str, &str, Option<&str>)> = Vec::new();
    for e in signer_set {
        let o = e.as_object()?;
        let role = o.get("role")?.as_str().filter(|r| SIGNER_ROLES.contains(r))?;
        let pk = o.get("publicKey")?.as_str()?;
        decode_b64u_strict(pk, Some(32))?;
        let pq = match o.get("pq_pk") {
            None => None,
            Some(v) => {
                let ps = v.as_str()?;
                let b = decode_b64u_strict(ps, None)?;
                if !PQ_PK_LENGTHS.contains(&b.len()) {
                    return None;
                }
                Some(ps)
            }
        };
        if let Some(prev) = reg.iter().find(|r| r.0 == role) {
            if prev.1 != pk || prev.2 != pq {
                return None; // two keys for one role, or a conflicting pq_pk on a duplicate (role, key)
            }
            continue;
        }
        if reg.iter().any(|r| r.1 == pk) {
            return None; // one key under two roles
        }
        reg.push((role, pk, pq));
    }
    Some(reg)
}

/// The signer-set hash as base64url: `None` on a set with a non-object entry or a non-string role / publicKey.
pub fn signer_set_hash_b64u(signer_set: &[Value]) -> Option<String> {
    signer_set_hash(signer_set).map(|h| b64_encode(&h))
}

/// Verify a single threshold share under the v2.1 agent-leaf share binding. FAIL-CLOSED: returns `false`
/// on any malformed input (never panics). The share signature MUST verify over the bound message
/// `"atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)` under
/// `share.publicKey` (or `share.pq_pk` per `share.alg`, routed through the same suite seam as the leaf).
/// Consequently the PRE-v2.1 bare agent share (a `sig` over the bare threshold message) and a cross-signer-set
/// replay (a share bound to a DIFFERENT signer set) both fail — the clean break the v2.1 binding mandates.
/// `entry` is a `{ role, t, signer_set, threshold_message, share{publicKey, sig, alg?, pq_pk?, pq_sig?} }`
/// object (the `primitives.threshold_share[]` shape).
pub fn verify_threshold_share(entry: &Value) -> bool {
    let o = match entry.as_object() {
        Some(o) => o,
        None => return false,
    };
    let role = match o.get("role").and_then(Value::as_str) {
        Some(r) => r,
        None => return false,
    };
    // R6-04: t is exactly 1, 2 or 3 (the reference refuses every other value).
    let t = match o.get("t").and_then(safe_int) {
        Some(t) if (1..=3).contains(&t) => t as u8,
        _ => return false,
    };
    let signer_set = match o.get("signer_set").and_then(Value::as_array) {
        Some(s) => s,
        None => return false,
    };
    let tm = match o.get("threshold_message").and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, None)) {
        Some(b) => b,
        None => return false,
    };
    // R6-03: the WHOLE set is validated before the share is looked at.
    let reg = match validate_signer_set(signer_set) {
        Some(r) => r,
        None => return false,
    };
    let ssh = match signer_set_hash(signer_set) {
        Some(h) => h,
        None => return false,
    };
    let share = match o.get("share").and_then(Value::as_object) {
        Some(s) => s,
        None => return false,
    };
    if share.get("role").and_then(Value::as_str) != Some(role) {
        return false; // share.role is required and must name the verified role
    }
    let pk = match share.get("publicKey").and_then(Value::as_str) {
        Some(p) => p,
        None => return false,
    };
    // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the share's own
    // publicKey / pq_pk never vouch for themselves.
    let (reg_pq, role_has_pq) = match reg.iter().find(|r| r.0 == role) {
        Some(r) if r.1 == pk => (r.2, r.2.is_some()),
        _ => return false,
    };
    let suite = match resolve_sig_alg(share.get("alg")) {
        Some(s) => s,
        None => return false,
    };
    // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering none has
    // nothing it could equal). The key used is always the registered one.
    if let Some(sp) = share.get("pq_pk") {
        match (sp.as_str(), reg_pq) {
            (Some(s), Some(rq)) if s == rq => {}
            _ => return false,
        }
    }
    // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share for it is
    // refused (otherwise an Ed25519 break would still forge the role).
    if role_has_pq && suite.alg == "ed25519" {
        return false;
    }
    let mut tag: Vec<u8> = Vec::new();
    let mut vouched = None;
    if suite.alg != "ed25519" {
        // PQ key = the signer set's registered pq_pk, never the share's own.
        let rq = match reg_pq {
            Some(q) => q,
            None => return false,
        };
        vouched = pinned::PinnedPq::caller_vouched(rq);
        if vouched.is_none() {
            return false;
        }
        tag.extend_from_slice(SHARE_SUITE_TAG);
        tag.extend_from_slice(suite.alg.as_bytes());
    }
    // Bound share message: domain(role) || sha256(thresholdMessage) || signerSetHash || t [|| suite tag].
    let mut msg = Vec::with_capacity(SHARE_DOMAIN_PREFIX.len() + role.len() + 1 + 32 + ssh.len() + 1 + tag.len());
    msg.extend_from_slice(SHARE_DOMAIN_PREFIX);
    msg.extend_from_slice(role.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&sha(&tm));
    msg.extend_from_slice(&ssh);
    msg.push(t);
    msg.extend_from_slice(&tag);
    verify_suite(share.get("alg"), pk, vouched.as_ref(), &msg, share.get("sig"), share.get("pq_sig"))
}

/// Verify a RAW PCActn text: strict-parse it first (a parse failure is a `wire` failure), then
/// [`verify_pcactn_core`].
pub fn verify_pcactn_json(text: &str, grant: &Value, now: i64, audience: &str) -> Verdict {
    verify_pcactn_json_policy(text, grant, now, audience, None)
}

/// [`verify_pcactn_json`] with an optional allowed-suites policy.
pub fn verify_pcactn_json_policy(text: &str, grant: &Value, now: i64, audience: &str, allowed: Option<&[String]>) -> Verdict {
    if text.len() > MAX_ARTIFACT_BYTES {
        // FIRST: before any parsing (str::len is UTF-8 bytes)
        return wire_fail(ARTIFACT_SIZE_REASON.to_string());
    }
    match strict_parse(text) {
        Ok(v) => verify_pcactn_core_policy(&v, grant, now, audience, allowed),
        Err(e) => wire_fail(e),
    }
}

/// Checks, in the normative order: wire (terminal), version, audience, validity, chain, plan_inclusion,
/// leaf_signature, counter. `now` is epoch milliseconds; `audience` is this verifier's own audience id.
/// Later-milestone checks (attestation, threshold, revocation, ...) are out of scope.
pub fn verify_pcactn_core(pcactn: &Value, grant: &Value, now: i64, audience: &str) -> Verdict {
    verify_pcactn_core_policy(pcactn, grant, now, audience, None)
}

/// [`verify_pcactn_core`] with an optional allowed-suites policy (`None` = none; `Some(&[])` refuses every
/// hop and leaf suite; absent `alg` == "ed25519"). Hybrid / pure-PQ keys are always required to be bound
/// to the signer's `holder_pq` (no unbound escape hatch).
pub fn verify_pcactn_core_policy(pcactn: &Value, grant: &Value, now: i64, audience: &str, allowed: Option<&[String]>) -> Verdict {
    if let Err(why) = validate_wire(pcactn) {
        return wire_fail(why);
    }
    let p = match pcactn.as_object() {
        Some(p) => p,
        None => return wire_fail("PCActn is not an object"),
    };

    let mut checks: BTreeMap<String, bool> = BTreeMap::new();
    let mut reason = String::new();
    let mut record = |name: &str, res: Result<(), String>| match res {
        Ok(()) => {
            checks.insert(name.into(), true);
        }
        Err(why) => {
            checks.insert(name.into(), false);
            if reason.is_empty() {
                reason = format!("{name}: {why}");
            }
        }
    };
    record("wire", Ok(()));

    // version
    let ver = p.get("ver").and_then(safe_int);
    record(
        "version",
        if ver == Some(PCACTN_WIRE_VERSION) { Ok(()) } else { Err("unsupported ver".into()) },
    );

    // audience
    record(
        "audience",
        if p.get("aud").and_then(Value::as_str) == Some(audience) {
            Ok(())
        } else {
            Err("aud does not match this resource server / instance".into())
        },
    );

    // validity
    let iat = p.get("iat").and_then(safe_int).unwrap_or(0);
    let exp = p.get("exp").and_then(safe_int).unwrap_or(0);
    record(
        "validity",
        if exp <= iat {
            Err("exp must be greater than iat".into())
        } else if exp - iat > MAX_LIFETIME_MS {
            Err(format!("lifetime exceeds {MAX_LIFETIME_MS} ms"))
        } else if iat > now.saturating_add(MAX_SKEW_MS) {
            Err("iat is in the future (clock skew)".into())
        } else if now > exp {
            Err("the PCActn has expired".into())
        } else {
            Ok(())
        },
    );

    // capability chain, root == grant (16-hop cap is checked before any signature work)
    let empty_vec = Vec::new();
    let chain = p.get("cap_chain").and_then(Value::as_array).unwrap_or(&empty_vec);
    record("chain", {
        if chain.is_empty() {
            Err("empty chain".into())
        } else if chain.len() > MAX_CHAIN_DEPTH {
            Err(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"))
        } else if caveat_limit_exceeded(chain) {
            Err(CAVEAT_LIMIT_REASON.into()) // before any hashing or signature work
        } else if !same_strict_hash(&chain[0], grant) {
            Err("chain root is not the grant".into())
        } else {
            // chain[0] == grant was checked above, so the grant is the verifier's stored root
            verify_chain_policy(chain, grant.get("issuer").and_then(Value::as_str), allowed, None, Some(grant))
        }
    });

    // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
    // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed on
    // an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
    let gref = p.get("grant_ref").and_then(Value::as_str);
    let root_id = chain.first().and_then(|c| c.get("id")).and_then(Value::as_str);
    record(
        "grant_ref_bound",
        match (gref, root_id) {
            (Some(g), Some(r)) if !g.is_empty() && g == r => Ok(()),
            _ => Err("grant_ref is not the id of the root capability in cap_chain".into()),
        },
    );

    // plan inclusion (leaf recomputed from the action itself)
    let empty_map = Map::new();
    let plan = p.get("plan").and_then(Value::as_object).unwrap_or(&empty_map);
    let action = p.get("action").and_then(Value::as_object);
    let cond = plan
        .get("conditions_digest")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(conditions_digest_default);
    let root = plan.get("root").and_then(Value::as_str).unwrap_or("");
    let proof = plan.get("inclusion_proof").and_then(Value::as_object);
    let ok = plan_leaf(plan.get("node_id"), action, &cond)
        .map(|leaf| verify_inclusion(root, proof, &leaf))
        .unwrap_or(false);
    record(
        "plan_inclusion",
        if ok { Ok(()) } else { Err("action is not a node of the committed plan".into()) },
    );

    // leaf signature under the PCActn's B4 suite (ed25519 / ml-dsa-65 / hybrid) over the v2 signed message
    let leaf_msg = "signature does not verify under the leaf holder key";
    let sig_ok = chain.last().is_some_and(|leaf_cap| {
        let holder = leaf_cap.get("holder").and_then(Value::as_str).unwrap_or("");
        if !suite_allowed(p.get("alg"), allowed) || !pq_binding_ok(p.get("alg"), p.get("pq_pk"), leaf_cap.get("holder_pq")) {
            return false;
        }
        match threshold_message(p) {
            Ok(msg) => verify_suite(
                p.get("alg"),
                holder,
                pinned::resolve_pq_key(Some(holder), p.get("pq_pk"), leaf_cap.get("holder_pq"), None, None).as_ref(),
                &msg,
                p.get("sig"),
                p.get("pq_sig"),
            ),
            Err(_) => false,
        }
    });
    record("leaf_signature", if sig_ok { Ok(()) } else { Err(leaf_msg.into()) });

    // counter: safe integer >= 0 (monotonicity vs. stored state is the resource server's job)
    record(
        "counter",
        match p.get("counter").and_then(safe_int) {
            Some(i) if i >= 0 => Ok(()),
            _ => Err("missing or not a non-negative safe integer".into()),
        },
    );

    let allow = checks.values().all(|v| *v);
    Verdict { allow, checks, reason }
}

// ---- PCA-Action header (0.4.1) -----------------------------------------------------------

/// Why [`decode_pca_header`] refused a `PCA-Action` header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcaHeaderError {
    /// The value is empty.
    Empty,
    /// The value is not strict unpadded base64url.
    NotBase64url,
    /// The decoded bytes are not valid UTF-8.
    NotUtf8,
}

impl std::fmt::Display for PcaHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PcaHeaderError::Empty => "PCA-Action header is empty",
            PcaHeaderError::NotBase64url => "PCA-Action header is not strict unpadded base64url",
            PcaHeaderError::NotUtf8 => "PCA-Action header does not decode to UTF-8 text",
        })
    }
}

impl std::error::Error for PcaHeaderError {}

/// Decode a `PCA-Action` header value to the encoded PCActn JSON text (pass it to [`strict_parse`]).
///
/// STRICT (0.4.1), exactly the profile's base64url rule ([`decode_b64u_strict`] with no fixed length): RFC 4648 section 5
/// alphabet only (`A-Z a-z 0-9 - _`), no `=` padding, no whitespace anywhere (nothing is trimmed), `len % 4 != 1`, zero
/// unused trailing bits; then strict UTF-8 (invalid, overlong, surrogate and truncated sequences are refused; a leading
/// BOM is kept, and the strict JSON parser refuses it). Nothing is normalized, so one PCActn has one header spelling.
pub fn decode_pca_header(value: &str) -> Result<String, PcaHeaderError> {
    if value.is_empty() {
        return Err(PcaHeaderError::Empty);
    }
    let bytes = decode_b64u_strict(value, None).ok_or(PcaHeaderError::NotBase64url)?;
    String::from_utf8(bytes).map_err(|_| PcaHeaderError::NotUtf8)
}

// ---- policy-layer caveat helpers (0.4.1) -------------------------------------------------
//
// The core verifier (the nine checks above, and the axum middleware) treats caveats as OPAQUE: it checks that they are
// carried, signed and only ever appended, but it does not evaluate them. A resource server enforcing a grant's caveats
// calls `evaluate_caveats(&policy_caveats(&grant, &chain), &ctx)` with its own action. 0.4.1 (security, mirrors the
// TypeScript policy layer): the caveats on the ROOT grant outside the envelope are part of that list, so they are enforced
// exactly like the caveats delegation hops append.

const ENVELOPE_CAVEAT: &str = "envelope";
const REVERSIBILITY_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

/// Every caveat the policy layer evaluates for an action under `grant` delegated along `chain` (root first): the grant's
/// caveats with its FIRST `envelope` caveat removed (order kept; that one is the policy container read separately), then
/// the caveats the hops appended (`leaf.caveats` beyond the grant's, leaf = the last chain element). Nothing is appended
/// when `chain` is not a non-empty array or either caveat list is not an array. A non-array grant list is returned as is
/// (`Null` when absent), and [`evaluate_caveats`] refuses it (fail closed). Total.
pub fn policy_caveats(grant: &Value, chain: &Value) -> Value {
    let cs = match grant.get("caveats").and_then(Value::as_array) {
        Some(cs) => cs,
        None => return grant.get("caveats").cloned().unwrap_or(Value::Null),
    };
    let mut out: Vec<Value> = cs.clone();
    if let Some(i) = cs.iter().position(|c| c.get("type").and_then(Value::as_str) == Some(ENVELOPE_CAVEAT)) {
        out.remove(i);
    }
    if let Some(leaf_cs) = chain.as_array().and_then(|c| c.last()).and_then(|l| l.get("caveats")).and_then(Value::as_array) {
        out.extend(leaf_cs.get(cs.len()..).unwrap_or(&[]).iter().cloned());
    }
    Value::Array(out)
}

/// Evaluate a caveat list against a policy context; `(ok, failed)` where `ok` iff every caveat is satisfied and `failed`
/// lists the unsatisfied caveats' `type` (`"<malformed>"` when it is not a string) in order. A non-array list is
/// `(false, ["<malformed caveats>"])`. Total: never panics.
///
/// `ctx` is a JSON object: `now` (epoch ms), optional `delegation_depth`, `blast_radius`, `reversibility_class`,
/// `recent_action_times` (epoch ms), and `action` `{verb, resource, reversibility_class?, params}`. A field the caveat
/// needs that is absent (or of the wrong type) leaves it unsatisfied. Implemented types (anything else, including
/// `envelope`, `note`, `resource_prefix`, `predicates`, `tool_schema`, is unsatisfied: fail closed):
///   * `max_spend {usd}`: `usd` finite >= 0; `action.params` is an object with an own finite `amount`, `0 <= amount <= usd`;
///     a `currency` in params, when present, is exactly `"usd"` or `"USD"`. Does not need `now`.
///   * the rest need a finite `now`: `expires {at}` (now < at), `not_before {at}` (now >= at), `rate {max, per_secs}`
///     (admitted times in `(now - per_secs*1000, now]` fewer than `max`), `max_blast_radius {max}`,
///     `reversibility_max {class}` (reads `ctx.reversibility_class`), `delegation_depth {max}`, `budget_alloc {limit}`
///     (limit finite >= 0; metered elsewhere).
pub fn evaluate_caveats(caveats: &Value, ctx: &Value) -> (bool, Vec<String>) {
    let list = match caveats.as_array() {
        Some(l) => l,
        None => return (false, vec!["<malformed caveats>".to_string()]),
    };
    let mut failed = Vec::new();
    for cv in list {
        if !caveat_satisfied(cv, ctx) {
            failed.push(cv.get("type").and_then(Value::as_str).unwrap_or("<malformed>").to_string());
        }
    }
    (failed.is_empty(), failed)
}

/// A finite JSON number (never a bool or a string).
fn fin(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|x| x.is_finite()),
        _ => None,
    }
}

fn caveat_satisfied(cv: &Value, ctx: &Value) -> bool {
    let (c, x) = match (cv.as_object(), ctx.as_object()) {
        (Some(c), Some(x)) => (c, x),
        _ => return false,
    };
    let ty = match c.get("type") {
        Some(Value::String(t)) => t.as_str(),
        _ => return false,
    };
    if ty == "max_spend" {
        let lim = match fin(c.get("usd")) {
            Some(l) if l >= 0.0 => l,
            _ => return false,
        };
        let params = match x.get("action").and_then(Value::as_object).and_then(|a| a.get("params")).and_then(Value::as_object) {
            Some(p) => p,
            None => return false,
        };
        let amount = match fin(params.get("amount")) {
            Some(a) if a >= 0.0 => a,
            _ => return false,
        };
        if let Some(cur) = params.get("currency") {
            if cur.as_str() != Some("usd") && cur.as_str() != Some("USD") {
                return false;
            }
        }
        return amount <= lim;
    }
    let now = match fin(x.get("now")) {
        Some(n) => n,
        None => return false,
    };
    match ty {
        "expires" => fin(c.get("at")).is_some_and(|at| now < at),
        "not_before" => fin(c.get("at")).is_some_and(|at| now >= at),
        "rate" => {
            let (max, per) = match (fin(c.get("max")), fin(c.get("per_secs"))) {
                (Some(m), Some(p)) if p > 0.0 => (m, p),
                _ => return false,
            };
            let times = match x.get("recent_action_times").and_then(Value::as_array) {
                Some(t) => t,
                None => return false,
            };
            let lo = now - per * 1000.0;
            let n = times.iter().filter_map(|t| fin(Some(t))).filter(|t| *t > lo && *t <= now).count();
            (n as f64) < max
        }
        "max_blast_radius" => match (fin(c.get("max")), fin(x.get("blast_radius"))) {
            (Some(m), Some(b)) => b <= m,
            _ => false,
        },
        "reversibility_max" => {
            let (lim, cur) = match (c.get("class").and_then(Value::as_str), x.get("reversibility_class").and_then(Value::as_str)) {
                (Some(l), Some(c)) => (l, c),
                _ => return false,
            };
            match (REVERSIBILITY_ORDER.iter().position(|r| *r == lim), REVERSIBILITY_ORDER.iter().position(|r| *r == cur)) {
                (Some(l), Some(c)) => c <= l,
                _ => false,
            }
        }
        "delegation_depth" => match (fin(c.get("max")), fin(x.get("delegation_depth"))) {
            (Some(m), Some(d)) => d <= m,
            _ => false,
        },
        "budget_alloc" => fin(c.get("limit")).is_some_and(|l| l >= 0.0),
        _ => false,
    }
}
