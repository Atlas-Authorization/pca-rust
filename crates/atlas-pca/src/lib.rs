//! Reference verifier for the CORE PCActn checks (wire format v2): wire, version, audience, validity,
//! capability chain, Merkle plan inclusion, strict Ed25519 leaf signature, counter. Byte-matches
//! `@atlasauth/pca` (see `packages/pca/conformance/README.md` for the normative rules).

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
const DEFAULT_REV: &str = "reversible";

/// Wire format version this verifier accepts.
pub const PCACTN_WIRE_VERSION: i64 = 2;
pub const MAX_CHAIN_DEPTH: usize = 16;
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
        if b.len() != (n * 4 + 2) / 3 {
            return None;
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

/// base64url-nopad(sha256(canonical(v))) (lenient canonical form).
pub fn hash_canonical(v: &Value) -> String {
    b64_encode(&sha(canonicalize(v).as_bytes()))
}

// ---- strict JSON parser ----------------------------------------------------------------

/// STRICT JSON profile for signed bytes (README section 2): hand-written RFC 8259 parser rejecting comments,
/// trailing commas, a BOM, non-JSON whitespace, duplicate keys (post-unescape), lone surrogates (raw or
/// escaped), raw control chars in strings, unknown escapes, nesting > 32, input > 2^20 UTF-8 bytes, and any
/// number not in the canonical wire form. Returns any JSON value (the PCActn check requires an object).
pub fn strict_parse(text: &str) -> Result<Value, String> {
    if text.len() > MAX_JSON_CHARS {
        return Err("strict JSON: input too large".into());
    }
    let mut p = Parser { b: text.as_bytes(), i: 0 };
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
                if depth > MAX_JSON_DEPTH {
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
                if depth > MAX_JSON_DEPTH {
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

fn leaf_hash(leaf: &Value) -> Vec<u8> {
    let mut m = vec![0x00u8];
    m.extend_from_slice(canonicalize(leaf).as_bytes());
    sha(&m)
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
    let hs: Vec<Vec<u8>> = leaves.iter().map(leaf_hash).collect();
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
    let mut h = leaf_hash(leaf);
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
// packages/pca/src/pq.ts and sdks/go-pca/pq.go. Absent `alg` (or `alg == "ed25519"`) is BYTE-IDENTICAL to
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
    v.and_then(Value::as_str).map_or(false, |s| decode_b64u_strict(s, Some(n)).is_some())
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
fn ml_dsa65_verify_b64u(pk_b64u: Option<&Value>, msg: &[u8], sig_b64u: Option<&Value>) -> bool {
    let pk = match pk_b64u
        .and_then(Value::as_str)
        .and_then(|s| decode_b64u_strict(s, Some(ML_DSA_65_PUBLIC_KEY_BYTES)))
    {
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
    if suite.needs_pq_pk {
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
fn verify_leaf_suite(
    alg: Option<&Value>,
    holder: &str,
    pq_pk: Option<&Value>,
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
        "ml-dsa-65" => ml_dsa65_verify_b64u(pq_pk, msg, sig),
        "hybrid-ed25519-ml-dsa-65" => {
            verify_b64u(holder, msg, sig_str) && ml_dsa65_verify_b64u(pq_pk, msg, pq_sig)
        }
        _ => false,
    }
}

// ---- capability chain ------------------------------------------------------------------

/// Hash of the full capability, including its signature.
pub fn cap_hash(c: &Value) -> String {
    hash_canonical(c)
}

fn body_of(c: &Map<String, Value>) -> Value {
    let g = |k: &str| c.get(k).cloned().unwrap_or(Value::Null);
    let mut m = Map::new();
    m.insert("issuer".into(), g("issuer"));
    m.insert("holder".into(), g("holder"));
    m.insert("caveats".into(), g("caveats"));
    m.insert("parent".into(), g("parent"));
    Value::Object(m)
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

fn check_sig(c: &Map<String, Value>, signer: &str, label: &str) -> Option<String> {
    // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
    let body = match signable_hop_body(c) {
        Ok(b) => b,
        Err(e) => return Some(format!("{label}: {e}")),
    };
    let digest = hash_canonical(&body);
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
    // under `pq_pk`. verify_leaf_suite dispatches on the hop's `alg` (signer = the expected Ed25519 key).
    match msg {
        Some(msg) if verify_leaf_suite(c.get("alg"), signer, c.get("pq_pk"), &msg, c.get("sig"), c.get("pq_sig")) => None,
        _ => Some(format!("{label}: bad signature (not signed by expected key)")),
    }
}

/// Mirrors verifyChain in capability.ts. `Ok(())` when valid, else `Err(reason)`. The 16-hop cap is
/// enforced before any signature work.
pub fn verify_chain(chain: &[Value], expected_root_issuer: Option<&str>) -> Result<(), String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"));
    }
    for (i, c) in chain.iter().enumerate() {
        if !c.is_object() {
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
    if let Some(e) = check_sig(root, str_of(root, "issuer"), "hop 0") {
        return Err(e);
    }
    for i in 1..chain.len() {
        let label = format!("hop {i}");
        let (parent, c) = match (chain[i - 1].as_object(), chain[i].as_object()) {
            (Some(p), Some(c)) => (p, c),
            _ => return Err(format!("{label}: malformed")),
        };
        let ph = cap_hash(&chain[i - 1]);
        if c.get("parent").and_then(Value::as_str) != Some(ph.as_str()) {
            return Err(format!("{label}: broken parent link"));
        }
        if c.get("issuer") != parent.get("holder") {
            return Err(format!("{label}: issuer is not the parent's bound holder"));
        }
        if let Some(e) = check_sig(c, str_of(parent, "holder"), &label) {
            return Err(e);
        }
        let empty = Vec::new();
        let pc = parent.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        let cc = c.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        if cc.len() < pc.len() {
            return Err(format!("{label}: drops parent caveat(s)"));
        }
        for j in 0..pc.len() {
            if hash_canonical(&cc[j]) != hash_canonical(&pc[j]) {
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
    v.and_then(Value::as_str).map_or(false, |s| decode_b64u_strict(s, Some(32)).is_some())
}

fn b64sig(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).map_or(false, |s| decode_b64u_strict(s, Some(64)).is_some())
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
            &["id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig"],
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
        let ok = c.get("caveats").and_then(Value::as_array).map_or(false, |cv| {
            cv.iter().all(|x| x.as_object().map_or(false, |o| is_str(o.get("type"))))
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
    let pv_ok = pv.map_or(false, |pv| {
        is_str(pv.get("causal_hash"))
            && matches!(pv.get("taint_level"), Some(Value::Number(_)))
            && pv
                .get("trusted_refs")
                .and_then(Value::as_array)
                .map_or(false, |r| r.iter().all(Value::is_string))
    });
    if !pv_ok {
        return Err("'provenance' is malformed".into());
    }
    let fr_ok = p.get("freshness").and_then(Value::as_object).map_or(false, |fr| {
        is_int(fr.get("epoch")) && is_str(fr.get("beacon_ref")) && is_str(fr.get("accumulator_witness"))
    });
    if !fr_ok {
        return Err("'freshness' is malformed".into());
    }
    let rc_ok = p.get("risk_claim").and_then(Value::as_object).map_or(false, |rc| {
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
            if !b64sig(s.get("sig")) {
                return Err(format!("threshold.shares[{i}].sig is not canonical base64url (64 bytes)"));
            }
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

/// Verify a RAW PCActn text: strict-parse it first (a parse failure is a `wire` failure), then
/// [`verify_pcactn_core`].
pub fn verify_pcactn_json(text: &str, grant: &Value, now: i64, audience: &str) -> Verdict {
    match strict_parse(text) {
        Ok(v) => verify_pcactn_core(&v, grant, now, audience),
        Err(e) => wire_fail(e),
    }
}

/// Checks, in the normative order: wire (terminal), version, audience, validity, chain, plan_inclusion,
/// leaf_signature, counter. `now` is epoch milliseconds; `audience` is this verifier's own audience id.
/// Later-milestone checks (attestation, threshold, revocation, ...) are out of scope.
pub fn verify_pcactn_core(pcactn: &Value, grant: &Value, now: i64, audience: &str) -> Verdict {
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
        } else if cap_hash(&chain[0]) != cap_hash(grant) {
            Err("chain root is not the grant".into())
        } else {
            verify_chain(chain, grant.get("issuer").and_then(Value::as_str))
        }
    });

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
    let sig_ok = chain.last().map_or(false, |leaf_cap| {
        let holder = leaf_cap.get("holder").and_then(Value::as_str).unwrap_or("");
        match threshold_message(p) {
            Ok(msg) => verify_leaf_suite(
                p.get("alg"),
                holder,
                p.get("pq_pk"),
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
