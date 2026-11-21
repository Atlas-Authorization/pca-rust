//! Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests in the `web-bot-auth`
//! profile (Ed25519), RFC 9530 `Content-Digest`, signed key-directory responses, and the PCA proof binding (the `PCA-Action` header is a
//! covered component, so one request is both bot-verified and proof-carrying).
//!
//! Verification FAILS CLOSED: any parse error, missing field, stale window, wrong tag, unknown key or bad signature is a
//! `{"valid": false, "reason": ...}` result, never a panic. JSON-valued API with the reference's member names (`created`, `expiresInSec`,
//! `agentDirectoryUrl`, `signatureInput`, ...), so a request signed here verifies in the TypeScript verifier and the reverse. Times are
//! epoch seconds; where the reference reads the clock the `now` argument defaults to the system clock.
//!
//! Signing keys are JSON members `{"secretKey": "<base64url 32-byte Ed25519 seed>"}`; public keys are base64url strings (`publicKey`).
//! The key resolver, the replay cache and the directory fetch are caller-supplied (closures / a trait), not JSON.
//!
//! Differences from the reference: only special-scheme URLs (http, https, ws, wss, ftp) are signed or verified, and a URL with
//! credentials is refused wherever the serialized URL itself is needed (`@target-uri`, the directory fetch).
use crate::oauth::{js_str, truthy};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

pub const WEB_BOT_AUTH_TAG: &str = "web-bot-auth";
pub const WEB_BOT_AUTH_ALG: &str = "ed25519";
pub const WELL_KNOWN_DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
pub const DIRECTORY_CONTENT_TYPE: &str = "application/http-message-signatures-directory+json";
pub const DEFAULT_SIGNATURE_LABEL: &str = "sig1";
pub const DEFAULT_EXPIRES_SEC: u32 = 300;
pub const SIGNATURE_AGENT_HEADER: &str = "Signature-Agent";
pub const PCA_HEADER: &str = "PCA-Action";
pub const PCA_PROOF_COMPONENT: &str = "pca-action";
pub const CONTENT_DIGEST_ALGS: [&str; 2] = ["sha-256", "sha-512"];
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";
pub const DIRECTORY_SIGNATURE_TAG: &str = "http-message-signatures-directory";

const DIRECTORY_LIFETIME_SEC: f64 = 86400.0;
const MAX_ARTIFACT_BYTES: usize = 524288;
const SPECIAL_SCHEMES: [&str; 5] = ["http", "https", "ws", "wss", "ftp"];
// JS String.prototype.trim / `\s`: WhiteSpace plus LineTerminator
const JS_WS: &[char] = &[
    '\t', '\n', '\u{b}', '\u{c}', '\r', ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
    '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
];

type R<T> = Result<T, String>;

/// What a key resolver returns for a `keyid`: nothing, 32 raw public-key bytes, or a public JWK (`{kty: OKP, crv: Ed25519, x}`).
pub enum ResolvedKey {
    None,
    Raw(Vec<u8>),
    Jwk(Value),
}

/// `keyid` -> the key (an `Err` is a failed resolution and fails the verification closed).
pub type KeyResolver<'a> = &'a dyn Fn(&str) -> Result<ResolvedKey, String>;

/// Single-use store for accepted signatures. `claim` is `true` for a first sighting and `false` for a replay.
pub trait ReplayCache {
    fn claim(&self, key: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String>;
}

/// In-process replay cache. Fails CLOSED (an `Err` from `claim`) when `max_entries` unexpired claims are held.
pub struct MemoryReplayCache {
    max: usize,
    seen: Mutex<HashMap<String, f64>>,
}

pub fn memory_replay_cache(max_entries: Option<usize>) -> MemoryReplayCache {
    MemoryReplayCache { max: max_entries.unwrap_or(100_000), seen: Mutex::new(HashMap::new()) }
}

impl ReplayCache for MemoryReplayCache {
    fn claim(&self, key: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String> {
        if !now_sec.is_finite() || !expires_at_sec.is_finite() {
            return Ok(false);
        }
        let mut seen = self.seen.lock().map_err(|_| "replay cache unavailable".to_string())?;
        if seen.len() >= self.max {
            seen.retain(|_, exp| !(*exp < now_sec));
            if seen.len() >= self.max {
                return Err("replay cache full".into());
            }
        }
        if let Some(existing) = seen.get(key) {
            if !(*existing < now_sec) {
                return Ok(false);
            }
        }
        seen.insert(key.to_string(), expires_at_sec);
        Ok(true)
    }
}

/// A fetched directory response (`headers` keyed by LOWER-CASE name).
pub struct FetchResponse {
    pub status: i64,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// `(url, init)` -> response. `init` is `{redirect: "error", timeout: seconds, headers: {accept}}`; the fetch must NOT follow redirects.
pub type DirectoryFetch<'a> = &'a dyn Fn(&str, &Value) -> Result<FetchResponse, String>;

// ---- small JS-semantics helpers ---------------------------------------------------------------------------------------------

fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| JS_WS.contains(&c))
}

fn num(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9007199254740991.0 {
        json!(f as i64)
    } else {
        Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}

fn pnum(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

fn finite(v: Option<&Value>) -> bool {
    pnum(v).is_some_and(f64::is_finite)
}

fn need_num(v: Option<&Value>, what: &str) -> R<f64> {
    pnum(v).ok_or_else(|| format!("{what} must be a number"))
}

fn need_str<'a>(v: Option<&'a Value>, what: &str) -> R<&'a str> {
    match v {
        Some(Value::String(s)) => Ok(s.as_str()),
        _ => Err(format!("{what} must be a string")),
    }
}

fn list_of<'a>(v: Option<&'a Value>, what: &str) -> R<&'a Vec<Value>> {
    match v {
        Some(Value::Array(a)) => Ok(a),
        _ => Err(format!("{what} must be an array")),
    }
}

/// JS iteration (`for ... of x`) of a JSON value: arrays and strings only.
fn iter_of(v: &Value) -> R<Vec<Value>> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        _ => Err("not iterable".into()),
    }
}

fn str_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    matches!((a, b), (Some(Value::String(x)), Some(Value::String(y))) if x == y)
}

fn now_secs() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0).floor()
}

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Node's `Buffer.from(s, 'base64')`: both alphabets, characters outside the alphabet skipped, decoding stops at `=`.
fn node_b64(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
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
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// The 32-byte seed of a signing key `{"secretKey": base64url seed}`.
fn key_seed(key: Option<&Value>) -> R<Zeroizing<[u8; 32]>> {
    let s = key.and_then(|k| k.get("secretKey")).and_then(Value::as_str).ok_or("the signing key must be {secretKey: base64url seed}")?;
    let b = Zeroizing::new(crate::decode_b64u_strict(s, Some(32)).ok_or("an Ed25519 seed is 32 canonical base64url bytes")?);
    let mut a = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&b);
    Ok(a)
}

fn public_x(seed: &[u8; 32]) -> String {
    b64u(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

/// Ed25519 verify under the base64url `x` of a public key; `false` for any malformed key or signature.
fn ed_verify_x(x: &str, message: &[u8], sig: &[u8]) -> bool {
    let (Ok(sg), Ok(pk)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(node_b64(x).as_slice())) else {
        return false;
    };
    crate::verify_ed25519_strict(&pk, message, &sg)
}

/// RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK).
pub fn jwk_thumbprint(public_key: &[u8]) -> String {
    thumbprint_of_x(&b64u(public_key))
}

fn thumbprint_of_x(x: &str) -> String {
    b64u(Sha256::digest(format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}").as_bytes()).as_slice())
}

// ---- structured-field helpers (targeted to the RFC 9421 Signature-Input / Signature grammars) ------------------------------

fn sf(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn sf_val(v: Option<&Value>, what: &str) -> R<String> {
    Ok(sf(need_str(v, what)?))
}

fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut in_str, mut start) = (0i32, false, 0usize);
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        if in_str {
            if c == '\\' {
                it.next();
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth = (depth - 1).max(0);
        } else if c == sep && depth == 0 {
            out.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    out.push(&s[start..]);
    out
}

fn index_of_top_level(s: &str, ch: char) -> Option<usize> {
    let (mut depth, mut in_str) = (0i32, false);
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        if in_str {
            if c == '\\' {
                it.next();
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth = (depth - 1).max(0);
        } else if c == ch && depth == 0 {
            return Some(i);
        }
    }
    None
}

/// The byte index of the `)` matching the leading `(` of `s`.
fn matching_paren(s: &str) -> Option<usize> {
    if !s.starts_with('(') {
        return None;
    }
    let (mut depth, mut in_str) = (0i32, false);
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        if in_str {
            if c == '\\' {
                it.next();
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// An sf-string at the start of `s`: the unescaped text and the byte index after the closing quote.
fn read_sf_string(s: &str) -> R<(String, usize)> {
    let mut it = s.char_indices();
    if it.next().map(|(_, c)| c) != Some('"') {
        return Err("expected a quoted string".into());
    }
    let mut out = String::new();
    while let Some((i, c)) = it.next() {
        if c == '\\' {
            match it.next() {
                Some((_, n)) if n == '"' || n == '\\' => out.push(n),
                _ => return Err("invalid escape in string".into()),
            }
        } else if c == '"' {
            return Ok((out, i + 1));
        } else {
            out.push(c);
        }
    }
    Err("unterminated string".into())
}

fn is_int(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())
}

fn is_dec(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    match d.split_once('.') {
        Some((a, b)) => !a.is_empty() && !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

fn parse_param_value(raw: &str) -> R<Value> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(Value::Bool(true)); // valueless parameter => boolean true
    }
    if s.starts_with('"') {
        let (v, nxt) = read_sf_string(s)?;
        if nxt != s.len() {
            return Err("trailing characters after string parameter".into());
        }
        return Ok(Value::String(v));
    }
    if s == "?1" {
        return Ok(Value::Bool(true));
    }
    if s == "?0" {
        return Ok(Value::Bool(false));
    }
    if is_int(s) || is_dec(s) {
        let f = s.parse::<f64>().map_err(|e| e.to_string())?;
        if !f.is_finite() {
            return Err("number out of range".into());
        }
        return Ok(num(f));
    }
    Ok(Value::String(s.to_string())) // token
}

fn parse_params(param_str: &str) -> R<HashMap<String, Value>> {
    let mut params = HashMap::new();
    let trimmed = trim(param_str);
    if trimmed.is_empty() {
        return Ok(params);
    }
    if !trimmed.starts_with(';') {
        return Err("expected parameters to start with \";\"".into());
    }
    for part in split_top_level(&trimmed[1..], ';') {
        let seg = trim(part);
        if seg.is_empty() {
            continue;
        }
        match index_of_top_level(seg, '=') {
            None => {
                params.insert(seg.to_string(), Value::Bool(true));
            }
            Some(eq) => {
                let v = parse_param_value(&seg[eq + 1..])?;
                params.insert(trim(&seg[..eq]).to_string(), v);
            }
        }
    }
    Ok(params)
}

/// `"(?:[^"\\]|\\[^\n\r  ])*"` at the start of `s` (a JS `.` does not match a line terminator): the byte length through the closing quote.
fn quoted_loose_len(s: &str) -> Option<usize> {
    let mut it = s.char_indices();
    if it.next().map(|(_, c)| c) != Some('"') {
        return None;
    }
    while let Some((i, c)) = it.next() {
        if c == '"' {
            return Some(i + 1);
        }
        if c == '\\' {
            match it.next() {
                Some((_, n)) if !matches!(n, '\n' | '\r' | '\u{2028}' | '\u{2029}') => {}
                _ => return None,
            }
        }
    }
    None
}

/// `;key=<quoted string>` in full: the quoted string.
fn key_param(rest: &str) -> Option<&str> {
    let r = rest.strip_prefix(";key=")?;
    (quoted_loose_len(r) == Some(r.len())).then_some(r)
}

/// `(;[a-z*][a-z0-9_.*-]*(=("..."|[A-Za-z0-9_.:/*+%-]+))?)*` in full (the canonical compact member-parameter form).
fn member_params_ok(s: &str) -> bool {
    let mut r = s;
    while !r.is_empty() {
        let Some(x) = r.strip_prefix(';') else {
            return false;
        };
        let b = x.as_bytes();
        if b.is_empty() || !(b[0].is_ascii_lowercase() || b[0] == b'*') {
            return false;
        }
        let mut i = 1;
        while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || matches!(b[i], b'_' | b'.' | b'*' | b'-')) {
            i += 1;
        }
        let mut rest = &x[i..];
        if let Some(v) = rest.strip_prefix('=') {
            if v.starts_with('"') {
                match quoted_loose_len(v) {
                    Some(n) => rest = &v[n..],
                    None => return false,
                }
            } else {
                let n = v.bytes().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'/' | b'*' | b'+' | b'%' | b'-')).count();
                if n == 0 {
                    return false;
                }
                rest = &v[n..];
            }
        }
        r = rest;
    }
    true
}

#[derive(Clone)]
struct Comp {
    id: String,
    raw: String,
    key: Option<String>,
}

struct Entry {
    label: String,
    components: Vec<Comp>,
    params_raw: String,
    params: HashMap<String, Value>,
}

fn parse_signature_input(value: &str) -> R<Vec<Entry>> {
    let mut entries = Vec::new();
    for member_raw in split_top_level(value, ',') {
        let member = trim(member_raw);
        if member.is_empty() {
            continue;
        }
        let eq = index_of_top_level(member, '=').ok_or("malformed Signature-Input member")?;
        let label = trim(&member[..eq]);
        let params_raw = trim(&member[eq + 1..]);
        if !params_raw.starts_with('(') {
            return Err("Signature-Input value must be an inner list".into());
        }
        let close = matching_paren(params_raw).ok_or("unterminated inner list")?;
        let inner = &params_raw[1..close];
        let mut components = Vec::new();
        for chunk_raw in split_top_level(inner, ' ') {
            let chunk = trim(chunk_raw);
            if chunk.is_empty() {
                continue;
            }
            let (ident, nxt) = read_sf_string(chunk)?;
            let lowered = ident.to_lowercase();
            let rest = trim(&chunk[nxt..]);
            if rest.is_empty() {
                components.push(Comp { raw: format!("\"{lowered}\""), id: lowered, key: None });
                continue;
            }
            // the only component parameter supported is `key` (dictionary member), on header components
            let group = match key_param(rest) {
                Some(g) if !lowered.starts_with('@') => g,
                _ => return Err(format!("unsupported component parameters on \"{ident}\"")),
            };
            let key = read_sf_string(group)?.0;
            components.push(Comp { raw: format!("\"{lowered}\";key={}", sf(&key)), id: lowered, key: Some(key) });
        }
        let params = parse_params(&params_raw[close + 1..])?;
        entries.push(Entry { label: label.to_string(), components, params_raw: params_raw.to_string(), params });
    }
    Ok(entries)
}

fn parse_signature(value: &str) -> R<HashMap<String, Vec<u8>>> {
    let mut out = HashMap::new();
    for member_raw in split_top_level(value, ',') {
        let member = trim(member_raw);
        if member.is_empty() {
            continue;
        }
        let eq = index_of_top_level(member, '=').ok_or("malformed Signature member")?;
        let label = trim(&member[..eq]);
        let v = trim(&member[eq + 1..]);
        if v.len() < 2 || !v.starts_with(':') || !v.ends_with(':') {
            return Err("Signature value must be a byte sequence (:base64:)".into());
        }
        out.insert(label.to_string(), node_b64(&v[1..v.len() - 1]));
    }
    Ok(out)
}

// ---- signature base (RFC 9421 section 2.5) ----------------------------------------------------------------------------------

fn normalize_headers(h: Option<&Value>) -> R<HashMap<String, String>> {
    let mut m: HashMap<String, String> = HashMap::new();
    if !truthy(h) {
        return Ok(m);
    }
    let entries: Vec<(String, Value)> = match h {
        Some(Value::Object(o)) => o.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
        Some(Value::String(s)) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => Vec::new(),
    };
    for (k, v) in entries {
        let name = k.to_lowercase();
        let value = match &v {
            Value::Array(a) => {
                let mut parts = Vec::new();
                for x in a {
                    parts.push(trim(need_str(Some(x), "a header value")?).to_string());
                }
                parts.join(", ")
            }
            other => trim(need_str(Some(other), "a header value")?).to_string(),
        };
        let merged = match m.get(&name) {
            Some(prev) => format!("{prev}, {value}"),
            None => value,
        };
        m.insert(name, merged);
    }
    Ok(m)
}

/// A special-scheme URL (WHATWG parse); anything else is "Invalid URL".
fn parse_special(url: &str) -> R<Url> {
    let u = Url::parse(url).map_err(|_| "Invalid URL".to_string())?;
    if !SPECIAL_SCHEMES.contains(&u.scheme()) || u.host_str().is_none() {
        return Err("Invalid URL".into());
    }
    Ok(u)
}

fn url_of(v: Option<&Value>) -> R<Url> {
    match v {
        Some(Value::String(s)) => parse_special(s),
        _ => Err("Invalid URL".into()),
    }
}

fn search_of(u: &Url) -> String {
    match u.query() {
        Some(q) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    }
}

/// `host` of the WHATWG URL (with a non-default port), lower-case.
fn authority_of(u: &Url) -> String {
    let host = u.host_str().unwrap_or("").to_lowercase();
    match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// `new URL(url).href`; a URL with credentials is refused.
fn href_of(u: &Url) -> R<String> {
    if !u.username().is_empty() || u.password().is_some() {
        return Err("a URL with credentials is not supported".into());
    }
    Ok(u.as_str().to_string())
}

struct Ctx {
    method: String,
    authority: String,
    path: String,
    url: Url,
    scheme: String,
    query: String,
    request_target: String,
    headers: HashMap<String, String>,
}

fn build_context(method: Option<&Value>, url: Option<&Value>, headers: HashMap<String, String>) -> R<Ctx> {
    let u = url_of(url)?;
    let method = need_str(method, "the method")?.to_uppercase();
    let search = search_of(&u);
    let path = if u.path().is_empty() { "/".to_string() } else { u.path().to_string() };
    Ok(Ctx {
        method,
        authority: authority_of(&u),
        request_target: format!("{path}{search}"),
        query: if search.is_empty() { "?".into() } else { search },
        scheme: u.scheme().to_lowercase(),
        path,
        url: u,
        headers,
    })
}

/// RFC 9421 section 2.1.2: the serialized value of dictionary member `key`; only string members in canonical form.
fn dictionary_member(header: &str, key: &str, header_name: &str) -> R<String> {
    for member_raw in split_top_level(header, ',') {
        let member = trim(member_raw);
        let Some(eq) = index_of_top_level(member, '=') else {
            continue;
        };
        if trim(&member[..eq]) != key {
            continue;
        }
        let value = trim(&member[eq + 1..]);
        let (_v, nxt) = read_sf_string(value)?;
        // parameters are allowed only in compact canonical form, so the verbatim text IS the serialization
        if !member_params_ok(&value[nxt..]) {
            return Err(format!("member \"{key}\" of \"{header_name}\" is not in canonical form"));
        }
        return Ok(value.to_string());
    }
    Err(format!("\"{header_name}\" has no dictionary member \"{key}\""))
}

fn derive_component_value(c: &Comp, ctx: &Ctx) -> R<String> {
    match c.id.as_str() {
        "@method" => return Ok(ctx.method.clone()),
        "@authority" => return Ok(ctx.authority.clone()),
        "@path" => return Ok(ctx.path.clone()),
        "@target-uri" => return href_of(&ctx.url),
        "@scheme" => return Ok(ctx.scheme.clone()),
        "@query" => return Ok(ctx.query.clone()),
        "@request-target" => return Ok(ctx.request_target.clone()),
        id if id.starts_with('@') => return Err(format!("unsupported derived component \"{id}\"")),
        _ => {}
    }
    let v = ctx.headers.get(&c.id).ok_or_else(|| format!("covered header \"{}\" is absent from the request", c.id))?;
    match &c.key {
        Some(k) => dictionary_member(v, k, &c.id),
        None => Ok(v.clone()),
    }
}

fn build_signature_base(components: &[Comp], params_raw: &str, ctx: &Ctx) -> R<String> {
    let mut lines = Vec::new();
    for c in components {
        lines.push(format!("{}: {}", c.raw, derive_component_value(c, ctx)?));
    }
    lines.push(format!("\"@signature-params\": {params_raw}"));
    Ok(lines.join("\n"))
}

// ---- sign_request -----------------------------------------------------------------------------------------------------------

/// Does the URL text have a `?` followed by anything but `#`?
fn has_query(url: &str) -> bool {
    let mut it = url.chars().peekable();
    while let Some(c) = it.next() {
        if c == '?' && it.peek().is_some_and(|n| *n != '#') {
            return true;
        }
    }
    false
}

/// Build the `Signature-Input` / `Signature` header values over the RFC 9421 base (`@authority @method @path`, plus `@query` when the
/// URL has a query string, the `Signature-Agent` component and any `coverHeaders`). `input`: method, url, headers?, key
/// (`{secretKey}`), keyid, created?, expiresInSec?, agentDirectoryUrl?, agentDirectoryKey?, components?, coverHeaders?, nonce?, label?.
/// Returns `{signatureInput, signature, signatureAgent?, covered, headers}`.
pub fn sign_request(input: &Value, now: Option<f64>) -> R<Value> {
    let inp = input.as_object().ok_or("signRequest: input must be an object")?;
    let label = match inp.get("label") {
        None | Some(Value::Null) => Value::String(DEFAULT_SIGNATURE_LABEL.into()),
        Some(v) => v.clone(),
    };
    let created_v = match inp.get("created") {
        None | Some(Value::Null) => num(now.map(f64::floor).unwrap_or_else(now_secs)),
        Some(v) => v.clone(),
    };
    let created = need_num(Some(&created_v), "created")?;
    let ex = match inp.get("expiresInSec") {
        None | Some(Value::Null) => DEFAULT_EXPIRES_SEC as f64,
        Some(v) => need_num(Some(v), "expiresInSec")?,
    };
    let expires = created + ex;

    let mut working = normalize_headers(inp.get("headers"))?;
    let mut emitted = Map::new();

    let comps_in = inp.get("components");
    let mut derived: Vec<Value> = match comps_in {
        None | Some(Value::Null) => vec![json!("@authority"), json!("@method"), json!("@path")],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("components must be an array".into()),
    };
    // by default a URL with a query string also covers @query (the verifier requires it)
    if comps_in.is_none() && has_query(need_str(inp.get("url"), "url")?) {
        derived.push(json!("@query"));
    }
    if !derived.iter().any(|v| v.as_str() == Some("@authority")) {
        return Err("signRequest: the web-bot-auth profile requires @authority to be covered".into());
    }
    let mut components: Vec<Comp> = Vec::new();
    for cid in &derived {
        let lower = need_str(Some(cid), "a component")?.to_lowercase();
        if !lower.starts_with('@') {
            return Err(format!("signRequest: components must be derived components, got \"{}\" (use coverHeaders for headers)", js_str(cid)));
        }
        components.push(Comp { raw: format!("\"{lower}\""), id: lower, key: None });
    }

    let mut signature_agent: Option<String> = None;
    match (inp.get("agentDirectoryUrl"), inp.get("agentDirectoryKey")) {
        (Some(u), k) => {
            let sa = match k {
                None => sf_val(Some(u), "agentDirectoryUrl")?,
                Some(kv) => format!("{}={}", js_str(kv), sf_val(Some(u), "agentDirectoryUrl")?),
            };
            working.insert("signature-agent".into(), sa.clone());
            emitted.insert(SIGNATURE_AGENT_HEADER.into(), Value::String(sa.clone()));
            match k {
                None => components.push(Comp { id: "signature-agent".into(), raw: "\"signature-agent\"".into(), key: None }),
                Some(kv) => {
                    let ks = need_str(Some(kv), "agentDirectoryKey")?;
                    components.push(Comp { id: "signature-agent".into(), raw: format!("\"signature-agent\";key={}", sf(ks)), key: Some(ks.to_string()) });
                }
            }
            signature_agent = Some(sa);
        }
        (None, Some(_)) => return Err("signRequest: agentDirectoryKey requires agentDirectoryUrl".into()),
        (None, None) => {}
    }

    let cover: Vec<Value> = match inp.get("coverHeaders") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => list_of(Some(v), "coverHeaders")?.clone(),
    };
    for name in &cover {
        let lower = need_str(Some(name), "a covered header")?.to_lowercase();
        if !working.contains_key(&lower) {
            return Err(format!("signRequest: covered header \"{}\" is not present in headers", js_str(name)));
        }
        if !components.iter().any(|c| c.id == lower) {
            components.push(Comp { raw: format!("\"{lower}\""), id: lower, key: None });
        }
    }

    let ctx = build_context(inp.get("method"), inp.get("url"), working)?;

    // parameter order follows the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag
    let inner_list = components.iter().map(|c| c.raw.as_str()).collect::<Vec<_>>().join(" ");
    let mut params_raw = format!(
        "({inner_list});created={};keyid={};alg={};expires={}",
        js_str(&created_v),
        sf_val(inp.get("keyid"), "keyid")?,
        sf(WEB_BOT_AUTH_ALG),
        js_str(&num(expires))
    );
    if let Some(n) = inp.get("nonce") {
        params_raw.push_str(&format!(";nonce={}", sf_val(Some(n), "nonce")?));
    }
    params_raw.push_str(&format!(";tag={}", sf(WEB_BOT_AUTH_TAG)));

    let base = build_signature_base(&components, &params_raw, &ctx)?;
    let seed = key_seed(inp.get("key"))?;
    let sig = SigningKey::from_bytes(&seed).sign(base.as_bytes()).to_bytes();

    let signature_input = format!("{}={}", js_str(&label), params_raw);
    let signature = format!("{}=:{}:", js_str(&label), STANDARD.encode(sig));
    emitted.insert("Signature-Input".into(), Value::String(signature_input.clone()));
    emitted.insert("Signature".into(), Value::String(signature.clone()));
    let mut out = Map::new();
    out.insert("signatureInput".into(), Value::String(signature_input));
    out.insert("signature".into(), Value::String(signature));
    out.insert("covered".into(), Value::Array(components.iter().map(|c| Value::String(c.id.clone())).collect()));
    out.insert("headers".into(), Value::Object(emitted));
    if let Some(sa) = signature_agent {
        out.insert("signatureAgent".into(), Value::String(sa));
    }
    Ok(Value::Object(out))
}

// ---- verify_signed_request --------------------------------------------------------------------------------------------------

fn fail(reason: String) -> Value {
    json!({ "valid": false, "reason": reason })
}

fn x_from_resolved(k: &ResolvedKey) -> Option<String> {
    match k {
        ResolvedKey::None => None,
        ResolvedKey::Raw(b) => (b.len() == 32).then(|| b64u(b)),
        ResolvedKey::Jwk(v) => x_of_jwk(v),
    }
}

fn x_of_jwk(v: &Value) -> Option<String> {
    let x = v.get("x").and_then(Value::as_str)?;
    (v.get("crv").and_then(Value::as_str) == Some("Ed25519") && v.get("kty").and_then(Value::as_str) == Some("OKP")).then(|| x.to_string())
}

fn resolve_from_jwks(keyid: &str, jwks: &Value, now: f64, skew: f64) -> R<Option<String>> {
    let keys = jwks.get("keys").and_then(Value::as_array).ok_or("jwks.keys is not an array")?;
    let mut found: Option<&Value> = None;
    for j in keys {
        if j.is_null() {
            return Err("a directory key must not be null".into());
        }
        if j.is_object() && j.get("kid").and_then(Value::as_str) == Some(keyid) {
            found = Some(j);
            break;
        }
    }
    let Some(m) = found else {
        return Ok(None);
    };
    // a published validity window is enforced; a bound that is not a finite number cannot be checked, so the key resolves to nothing
    for b in [m.get("nbf"), m.get("exp")] {
        if b.is_some() && !finite(b) {
            return Ok(None);
        }
    }
    if let Some(nbf) = pnum(m.get("nbf")) {
        if !(now.is_finite() && skew.is_finite() && now + skew >= nbf) {
            return Ok(None);
        }
    }
    if let Some(exp) = pnum(m.get("exp")) {
        if !(now.is_finite() && skew.is_finite() && now - skew <= exp) {
            return Ok(None);
        }
    }
    Ok(x_of_jwk(m))
}

fn verify_core(req: &Value, opts: &Value, resolve: Option<KeyResolver<'_>>, cache: Option<&dyn ReplayCache>) -> R<Value> {
    let empty = Map::new();
    let o = opts.as_object().unwrap_or(&empty);
    let jwks = o.get("jwks");
    if resolve.is_none() && !truthy(jwks) {
        return Ok(fail("verifySignedRequest: provide resolveKey or jwks".into()));
    }
    let headers = normalize_headers(req.get("headers"))?;
    let (Some(sig_input_header), Some(sig_header)) = (headers.get("signature-input"), headers.get("signature")) else {
        return Ok(fail("missing Signature-Input or Signature header".into()));
    };

    let inputs = parse_signature_input(sig_input_header)?;
    let sigs = parse_signature(sig_header)?;
    let default_tag = Value::String(WEB_BOT_AUTH_TAG.into());
    let required_tag: Option<&Value> = match o.get("requiredTag") {
        None => Some(&default_tag),
        Some(Value::Null) => None,
        Some(v) => Some(v),
    };

    let chosen: Option<&Entry> = if let Some(l) = o.get("label") {
        inputs.iter().find(|e| l.as_str() == Some(e.label.as_str()))
    } else if let Some(rt) = required_tag {
        inputs.iter().find(|e| str_eq(e.params.get("tag"), Some(rt))).or_else(|| inputs.first())
    } else {
        inputs.first()
    };
    let Some(chosen) = chosen else {
        return Ok(fail("no matching signature in Signature-Input".into()));
    };

    let Some(sig_bytes) = sigs.get(&chosen.label) else {
        return Ok(fail(format!("no Signature entry for label \"{}\"", chosen.label)));
    };

    let p = &chosen.params;
    let tag: Option<&str> = p.get("tag").and_then(Value::as_str);
    if let Some(rt) = required_tag {
        if !matches!((tag, rt.as_str()), (Some(a), Some(b)) if a == b) {
            return Ok(fail(format!("tag \"{}\" does not match required \"{}\"", tag.unwrap_or("undefined"), js_str(rt))));
        }
    }

    // @authority is required by the profile; @method and @path too, so a signature cannot be replayed on another method or path
    let covered: Vec<&str> = chosen.components.iter().map(|c| c.id.as_str()).collect();
    let req_components = o.get("requiredComponents");
    let required: Vec<Value> = match req_components {
        None | Some(Value::Null) => vec![json!("@authority"), json!("@method"), json!("@path")],
        Some(v) => iter_of(v)?,
    };
    for cid in &required {
        if !cid.as_str().is_some_and(|s| covered.contains(&s)) {
            return Ok(fail(format!("{} is not a covered component", js_str(cid))));
        }
    }
    if req_components.is_none() {
        let url = need_str(req.get("url"), "url")?;
        if let Some(q) = url.find('?') {
            let query = url[q + 1..].split('#').next().unwrap_or("");
            if !query.is_empty() && !covered.contains(&"@query") {
                return Ok(fail("@query is not a covered component".into()));
            }
        }
    }

    if let Some(alg) = p.get("alg") {
        if alg.as_str() != Some(WEB_BOT_AUTH_ALG) {
            return Ok(fail(format!("unsupported alg \"{}\"", js_str(alg))));
        }
    }

    let now = match o.get("now") {
        None | Some(Value::Null) => now_secs(),
        Some(v) => need_num(Some(v), "now")?,
    };
    let skew = match o.get("clockSkewSec") {
        None | Some(Value::Null) => 0.0,
        Some(v) => need_num(Some(v), "clockSkewSec")?,
    };
    let created = pnum(p.get("created"));
    let expires = pnum(p.get("expires"));
    if expires.is_none() && o.get("requireExpires") != Some(&Value::Bool(false)) {
        return Ok(fail("missing expires parameter".into()));
    }
    if let Some(e) = expires {
        if !(now.is_finite() && skew.is_finite() && e.is_finite() && now <= e + skew) {
            return Ok(fail("signature has expired".into()));
        }
    }
    if let Some(c) = created {
        if !(now.is_finite() && skew.is_finite() && c.is_finite() && c <= now + skew) {
            return Ok(fail("signature created-time is in the future".into()));
        }
    }
    if let (Some(v), Some(c)) = (o.get("maxAgeSec"), created) {
        if !(now.is_finite() && skew.is_finite() && now - c <= need_num(Some(v), "maxAgeSec")? + skew) {
            return Ok(fail("signature is older than maxAgeSec".into()));
        }
    }
    // a lifetime bound that is not a finite number (the reference's `Infinity`) disables the check
    let max_lifetime: Option<f64> = match o.get("maxLifetimeSec") {
        None | Some(Value::Null) => Some(300.0),
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        Some(_) => None,
    };
    if let Some(ml) = max_lifetime {
        let Some(c) = created else {
            return Ok(fail("missing created parameter (needed to bound the signature lifetime)".into()));
        };
        if let Some(e) = expires {
            if !(e - c <= ml) {
                return Ok(fail("signature lifetime exceeds maxLifetimeSec".into()));
            }
        }
    }

    let Some(keyid) = p.get("keyid").and_then(Value::as_str) else {
        return Ok(fail("missing keyid parameter".into()));
    };
    let x: Option<String> = if let Some(r) = resolve {
        x_from_resolved(&r(keyid)?)
    } else if let Some(j) = jwks.filter(|j| truthy(Some(*j))) {
        resolve_from_jwks(keyid, j, now, skew)?
    } else {
        None
    };
    let Some(x) = x else {
        return Ok(fail(format!("could not resolve key \"{keyid}\"")));
    };

    let ctx = build_context(req.get("method"), req.get("url"), headers.clone())?;
    let base = build_signature_base(&chosen.components, &chosen.params_raw, &ctx)?;
    if !ed_verify_x(&x, base.as_bytes(), sig_bytes) {
        return Ok(fail("signature does not verify under the resolved key".into()));
    }

    let nonce: Option<&str> = p.get("nonce").and_then(Value::as_str);
    if let Some(c) = cache {
        let until = match (expires, created) {
            (Some(e), _) => e,
            (None, Some(cr)) => cr + max_lifetime.unwrap_or(3600.0),
            (None, None) => now + 3600.0,
        };
        let key = format!("{keyid}|{}", nonce.map(str::to_string).unwrap_or_else(|| b64u(sig_bytes)));
        if !c.claim(&key, until + skew, now)? {
            return Ok(fail("replayed signature".into()));
        }
    }
    let mut out = Map::new();
    out.insert("valid".into(), Value::Bool(true));
    out.insert("label".into(), Value::String(chosen.label.clone()));
    out.insert("keyid".into(), Value::String(keyid.to_string()));
    out.insert("covered".into(), Value::Array(chosen.components.iter().map(|c| Value::String(c.id.clone())).collect()));
    if let Some(c) = created {
        out.insert("created".into(), num(c));
    }
    if let Some(e) = expires {
        out.insert("expires".into(), num(e));
    }
    if let Some(t) = tag {
        out.insert("tag".into(), Value::String(t.to_string()));
    }
    if let Some(n) = nonce {
        out.insert("nonce".into(), Value::String(n.to_string()));
    }
    Ok(Value::Object(out))
}

/// Verify an RFC 9421 signature over `req` = `{method, url, headers}`. `opts`: jwks (`{keys: [...]}`), now?, clockSkewSec?, maxAgeSec?,
/// requireExpires? (default true), requiredTag? (default `web-bot-auth`; null = not enforced), label?, requiredComponents? (default
/// `@authority @method @path`, plus `@query` when the URL has a query string), maxLifetimeSec? (default 300; a non-number disables).
/// `resolve` (keyid -> key) takes the place of the reference's `resolveKey`; `cache` of its `replayCache`. Never panics: any failure is
/// `{valid: false, reason}`.
pub fn verify_signed_request(req: &Value, opts: &Value, resolve: Option<KeyResolver<'_>>, cache: Option<&dyn ReplayCache>) -> Value {
    match verify_core(req, opts, resolve, cache) {
        Ok(v) => v,
        Err(e) => fail(format!("verification failed (fail closed): {e}")),
    }
}

// ---- key directory (JWKS) and handler ---------------------------------------------------------------------------------------

/// JWKS for the agent's public keys: `[{publicKey: base64url, keyid?, use?, nbf?, exp?}]`; `kid` defaults to the thumbprint.
pub fn build_key_directory(keys: &Value) -> R<Value> {
    let mut out = Vec::new();
    for k in list_of(Some(keys), "keys")? {
        let pk = node_b64(need_str(k.get("publicKey"), "publicKey")?);
        let kid = match k.get("keyid") {
            None | Some(Value::Null) => Value::String(jwk_thumbprint(&pk)),
            Some(v) => v.clone(),
        };
        let mut entry = Map::new();
        entry.insert("kty".into(), json!("OKP"));
        entry.insert("crv".into(), json!("Ed25519"));
        entry.insert("x".into(), Value::String(b64u(&pk)));
        entry.insert("kid".into(), kid);
        for f in ["use", "nbf", "exp"] {
            if let Some(v) = k.get(f) {
                entry.insert(f.into(), v.clone());
            }
        }
        out.push(Value::Object(entry));
    }
    Ok(json!({ "keys": out }))
}

/// The directory entry whose `kid` is `keyid`, or `None`.
pub fn resolve_from_directory(directory: &Value, keyid: &str) -> R<Option<Value>> {
    for j in list_of(directory.get("keys"), "directory.keys")? {
        if j.is_null() {
            return Err("a directory key must not be null".into());
        }
        if j.is_object() && j.get("kid").and_then(Value::as_str) == Some(keyid) {
            return Ok(Some(j.clone()));
        }
    }
    Ok(None)
}

/// A framework-agnostic handler: the 200 response when the path is the well-known directory path, else `None`.
pub fn directory_handler(keys: &Value) -> R<Box<dyn Fn(&str) -> Option<Value>>> {
    let body = crate::js_stringify(&build_key_directory(keys)?);
    Ok(Box::new(move |pathname: &str| {
        let path = pathname.split('?').next().unwrap_or("");
        if path != WELL_KNOWN_DIRECTORY_PATH {
            return None;
        }
        Some(json!({
            "status": 200,
            "headers": { "content-type": DIRECTORY_CONTENT_TYPE, "cache-control": "max-age=86400" },
            "body": body.clone(),
        }))
    }))
}

// ---- PCA proof binding ------------------------------------------------------------------------------------------------------

/// The `PCA-Action` header carrying a PCActn (base64url of its canonical wire form): `{"PCA-Action": value}`.
pub fn proof_headers(pcactn: &Value) -> R<Value> {
    let mut m = Map::new();
    m.insert(PCA_HEADER.into(), Value::String(b64u(crate::canonicalize(pcactn).as_bytes())));
    Ok(Value::Object(m))
}

/// Reverse [`proof_headers`]: the `PCA-Action` header value to the PCActn. Errs on a malformed header or PCActn.
pub fn decode_proof_header(value: &str) -> R<Value> {
    let text = crate::decode_pca_header(value).map_err(|e| e.to_string())?;
    if text.len() > MAX_ARTIFACT_BYTES {
        return Err(format!("artifact exceeds size limit (max {MAX_ARTIFACT_BYTES} bytes)"));
    }
    let v = crate::strict_parse(&text)?;
    if !v.is_object() {
        return Err("decodePCActn: not an object".into());
    }
    Ok(v)
}

/// [`sign_request`] plus the PCActn in `PCA-Action` as a covered header. `input` is a `sign_request` input with `pcactn`.
pub fn sign_request_with_proof(input: &Value, now: Option<f64>) -> R<Value> {
    let inp = input.as_object().ok_or("signRequestWithProof: input must be an object")?;
    let proof = proof_headers(inp.get("pcactn").ok_or("canonicalize: unsupported type undefined")?)?;
    let mut headers: Map<String, Value> = match inp.get("headers") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
        Some(Value::String(s)) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        Some(_) => Map::new(),
    };
    let proof_map = proof.as_object().cloned().unwrap_or_default();
    for (k, v) in &proof_map {
        headers.insert(k.clone(), v.clone());
    }
    let mut cover: Vec<Value> = match inp.get("coverHeaders") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => iter_of(v)?,
    };
    cover.push(Value::String(PCA_PROOF_COMPONENT.into()));
    let mut rest: Map<String, Value> = inp.iter().filter(|(k, _)| k.as_str() != "pcactn").map(|(k, v)| (k.clone(), v.clone())).collect();
    rest.insert("headers".into(), Value::Object(headers));
    rest.insert("coverHeaders".into(), Value::Array(cover));
    let mut out = sign_request(&Value::Object(rest), now)?;
    if let Some(Value::Object(h)) = out.get_mut("headers") {
        for (k, v) in &proof_map {
            h.insert(k.clone(), v.clone());
        }
    }
    out["proofHeader"] = proof;
    Ok(out)
}

fn proof_stage(base: Value, req: &Value, opts: &Value) -> R<Value> {
    if base.get("valid") != Some(&Value::Bool(true)) {
        return Ok(base);
    }
    let covered = base.get("covered").and_then(Value::as_array).is_some_and(|a| a.iter().any(|c| c.as_str() == Some(PCA_PROOF_COMPONENT)));
    if !covered {
        return Ok(fail(format!("the {PCA_HEADER} proof header is not covered by the signature")));
    }
    let header_value = normalize_headers(req.get("headers"))?.get(PCA_PROOF_COMPONENT).cloned();
    let Some(header_value) = header_value else {
        return Ok(fail(format!("missing {PCA_HEADER} header")));
    };
    let pcactn = match decode_proof_header(&header_value) {
        Ok(p) => p,
        Err(e) => return Ok(fail(format!("invalid PCActn in {PCA_HEADER}: {e}"))),
    };
    if let Some(expected) = opts.get("expectedPCActn") {
        match (crate::hash_canonical_strict(&pcactn), crate::hash_canonical_strict(expected)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => return Ok(fail("carried PCActn does not match the expected proof".into())),
            _ => return Err("canonicalize: value is outside the strict profile".into()),
        }
    }
    let mut out = base;
    out["pcactn"] = pcactn;
    Ok(out)
}

/// [`verify_signed_request`] AND extract the proof: `PCA-Action` must be a covered component; `opts.expectedPCActn`, when given, must
/// equal the carried PCActn by canonical digest. The returned `pcactn` is bound to the verified signature. An `Err` is an expected
/// proof outside the strict canonical profile.
pub fn verify_signed_request_with_proof(req: &Value, opts: &Value, resolve: Option<KeyResolver<'_>>, cache: Option<&dyn ReplayCache>) -> R<Value> {
    proof_stage(verify_signed_request(req, opts, resolve, cache), req, opts)
}

// ---- Content-Digest (RFC 9530) ----------------------------------------------------------------------------------------------

/// The raw digest bytes of `body` under `alg` ("sha-256" or "sha-512").
pub fn content_digest_bytes(body: &[u8], alg: &str) -> R<Vec<u8>> {
    match alg {
        "sha-256" => Ok(Sha256::digest(body).to_vec()),
        "sha-512" => Ok(Sha512::digest(body).to_vec()),
        _ => Err("unsupported digest algorithm".into()),
    }
}

/// The `Content-Digest` field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, duplicates dropped). `algs` defaults to `["sha-256"]`.
pub fn content_digest_header(body: &[u8], algs: Option<&Value>) -> R<String> {
    let default = Value::Array(vec![json!("sha-256")]);
    let algs = list_of(Some(algs.unwrap_or(&default)), "algs")?;
    if algs.is_empty() {
        return Err("contentDigestHeader: name at least one algorithm".into());
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut parts = Vec::new();
    for alg in algs {
        let a = match alg.as_str() {
            Some(a) if CONTENT_DIGEST_ALGS.contains(&a) => a,
            _ => return Err(format!("contentDigestHeader: unsupported algorithm {}", js_str(alg))),
        };
        if seen.contains(&a) {
            continue;
        }
        seen.push(a);
        parts.push(format!("{a}=:{}:", STANDARD.encode(content_digest_bytes(body, a)?)));
    }
    Ok(parts.join(", "))
}

/// `([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):` in full: the key and the base64 text.
fn digest_member(m: &str) -> Option<(&str, &str)> {
    let b = m.as_bytes();
    if b.is_empty() || !(b[0].is_ascii_lowercase() || b[0] == b'*') {
        return None;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || matches!(b[i], b'_' | b'-' | b'.' | b'*')) {
        i += 1;
    }
    let rest = m[i..].strip_prefix("=:")?.strip_suffix(':')?;
    let core = rest.trim_end_matches('=');
    (rest.len() - core.len() <= 2 && core.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')).then_some((&m[..i], rest))
}

/// Parse the dictionary: key -> byte sequence, in order. Errs on anything that is not `key=:base64:` (parameters refused, repeats refused).
pub fn parse_content_digest(value: &str) -> R<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for raw in value.split(',') {
        let member = trim(raw);
        if member.is_empty() {
            return Err("empty dictionary member".into());
        }
        let Some((key, b64)) = digest_member(member) else {
            return Err(format!("malformed Content-Digest member \"{member}\""));
        };
        if b64.len() % 4 != 0 {
            return Err(format!("member \"{key}\" is not canonical base64"));
        }
        let data = node_b64(b64);
        if STANDARD.encode(&data) != b64 {
            return Err(format!("member \"{key}\" is not canonical base64"));
        }
        if out.iter().any(|(k, _)| k == key) {
            return Err(format!("member \"{key}\" appears twice"));
        }
        out.push((key.to_string(), data));
    }
    Ok(out)
}

/// Check `body` against a `Content-Digest` field value. Every supported member present must match; unsupported members are ignored; at
/// least one supported member must be present; every algorithm in `opts.require` must be among the matched ones.
pub fn verify_content_digest(header: Option<&str>, body: &[u8], opts: Option<&Value>) -> Value {
    let run = || -> R<Value> {
        let Some(header) = header.filter(|h| !trim(h).is_empty()) else {
            return Ok(fail("missing Content-Digest".into()));
        };
        let members = parse_content_digest(header)?;
        let mut matched: Vec<&str> = Vec::new();
        for alg in CONTENT_DIGEST_ALGS {
            let Some((_, got)) = members.iter().find(|(k, _)| k == alg) else {
                continue;
            };
            if !ct_eq(got, &content_digest_bytes(body, alg)?) {
                return Ok(fail(format!("{alg} digest does not match the content")));
            }
            matched.push(alg);
        }
        if matched.is_empty() {
            return Ok(fail("no supported digest algorithm (sha-256 or sha-512)".into()));
        }
        let required = match opts.and_then(|o| o.get("require")) {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => iter_of(v)?,
        };
        for alg in &required {
            if !alg.as_str().is_some_and(|a| matched.contains(&a)) {
                return Ok(fail(format!("required {} digest is absent", js_str(alg))));
            }
        }
        Ok(json!({ "valid": true, "matched": matched }))
    };
    match run() {
        Ok(v) => v,
        Err(e) => fail(format!("malformed Content-Digest: {e}")),
    }
}

// ---- signed key-directory responses -----------------------------------------------------------------------------------------

const MALFORMED_KEY: &str = "directory contains a malformed key";

/// Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string `kid`. Errs otherwise.
pub fn parse_key_directory(text: &str) -> R<Value> {
    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    {
        let keys = match doc.get("keys").and_then(Value::as_array) {
            Some(k) if !k.is_empty() => k,
            _ => return Err("directory has no keys".into()),
        };
        for j in keys {
            let o = j.as_object().ok_or(MALFORMED_KEY)?;
            if o.get("kty").and_then(Value::as_str) != Some("OKP") || o.get("crv").and_then(Value::as_str) != Some("Ed25519") {
                return Err(MALFORMED_KEY.into());
            }
            if !o.get("kid").and_then(Value::as_str).is_some_and(|k| !k.is_empty()) {
                return Err(MALFORMED_KEY.into());
            }
            let x = o.get("x").and_then(Value::as_str).ok_or(MALFORMED_KEY)?;
            if x.len() != 43 || !x.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') || node_b64(x).len() != 32 {
                return Err(MALFORMED_KEY.into());
            }
            for f in ["nbf", "exp"] {
                if o.contains_key(f) && !finite(o.get(f)) {
                    return Err(MALFORMED_KEY.into());
                }
            }
        }
    }
    Ok(doc)
}

/// Sign a directory response (RFC 9421 over `"@authority";req`, one signature per key). `input`: keys (`[{secretKey}]`), directory,
/// authority (lower-case host or host:port), created?, expiresInSec?. Returns the exact `body` to serve and the `headers`.
pub fn sign_directory_response(input: &Value, now: Option<f64>) -> R<Value> {
    let keys = list_of(input.get("keys"), "keys")?;
    if keys.is_empty() {
        return Err("signDirectoryResponse: at least one signing key is required".into());
    }
    let authority = need_str(input.get("authority"), "authority")?;
    if authority.is_empty() || !authority.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-' | b'[' | b']' | b':')) {
        return Err("signDirectoryResponse: authority must be a lower-case host or host:port".into());
    }
    let created_v = match input.get("created") {
        None | Some(Value::Null) => num(now.map(f64::floor).unwrap_or_else(now_secs)),
        Some(v) => v.clone(),
    };
    let created = need_num(Some(&created_v), "created")?;
    let ex = match input.get("expiresInSec") {
        None | Some(Value::Null) => DIRECTORY_LIFETIME_SEC,
        Some(v) => need_num(Some(v), "expiresInSec")?,
    };
    let expires = created + ex;
    let directory = input.get("directory").cloned().unwrap_or(Value::Null);
    let body = crate::js_stringify(&directory);
    let dir_keys = list_of(directory.get("keys"), "directory.keys")?;
    let (mut inputs, mut sigs) = (Vec::new(), Vec::new());
    for (i, k) in keys.iter().enumerate() {
        let seed = key_seed(Some(k))?;
        let x = public_x(&seed);
        if !dir_keys.iter().any(|j| j.is_object() && j.get("x").and_then(Value::as_str) == Some(x.as_str())) {
            return Err("signDirectoryResponse: a signing key is not in the directory".into());
        }
        let keyid = thumbprint_of_x(&x);
        let label = format!("sig{}", i + 1);
        let params = format!(
            "(\"@authority\";req);created={};expires={};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"{DIRECTORY_SIGNATURE_TAG}\"",
            js_str(&created_v),
            js_str(&num(expires))
        );
        let base = format!("\"@authority\";req: {authority}\n\"@signature-params\": {params}");
        inputs.push(format!("{label}={params}"));
        sigs.push(format!("{label}=:{}:", STANDARD.encode(SigningKey::from_bytes(&seed).sign(base.as_bytes()).to_bytes())));
    }
    Ok(json!({
        "body": body,
        "headers": { "content-type": DIRECTORY_CONTENT_TYPE, "signature-input": inputs.join(", "), "signature": sigs.join(", ") },
    }))
}

fn label_len(s: &str) -> usize {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_lowercase() {
        return 0;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || matches!(b[i], b'_' | b'.' | b'*' | b'-')) {
        i += 1;
    }
    i
}

/// `<label>=:<base64>:` in full.
fn dir_sig(part: &str) -> Option<(&str, &str)> {
    let n = label_len(part);
    if n == 0 {
        return None;
    }
    let rest = part[n..].strip_prefix("=:")?.strip_suffix(':')?;
    let core = rest.trim_end_matches('=');
    (!core.is_empty() && rest.len() - core.len() <= 2 && core.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/'))
        .then_some((&part[..n], rest))
}

/// `<label>=("@authority";req)(;[a-z]+=([0-9]+|"[A-Za-z0-9_.-]*"))*` in full: the label and the parameter text.
fn dir_entry(raw: &str) -> Option<(&str, &str)> {
    let n = label_len(raw);
    if n == 0 {
        return None;
    }
    let rest = raw[n..].strip_prefix("=(\"@authority\";req)")?;
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b';' {
            return None;
        }
        i += 1;
        let s = i;
        while i < b.len() && b[i].is_ascii_lowercase() {
            i += 1;
        }
        if i == s || i >= b.len() || b[i] != b'=' {
            return None;
        }
        i += 1;
        if i < b.len() && b[i] == b'"' {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'.' | b'-')) {
                i += 1;
            }
            if i >= b.len() || b[i] != b'"' {
                return None;
            }
            i += 1;
        } else {
            let s2 = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == s2 {
                return None;
            }
        }
    }
    Some((&raw[..n], rest))
}

struct DirCheck<'a> {
    sigs: &'a HashMap<String, Vec<u8>>,
    keys: &'a [Value],
    authority: String,
    t: f64,
    skew: f64,
    max_life: f64,
}

/// One `signature-input` entry: the directory key it validly signs, or the reason it does not.
fn check_dir_entry(raw: &str, c: &DirCheck<'_>) -> Result<(String, Value), String> {
    let (label, ptxt) = dir_entry(raw).ok_or_else(|| "malformed signature-input entry (must cover exactly \"@authority\";req)".to_string())?;
    let mut params: HashMap<&str, &str> = HashMap::new();
    let mut dup = false;
    for p in ptxt.split(';').skip(1) {
        if let Some(eq) = p.find('=') {
            if params.insert(&p[..eq], &p[eq + 1..]).is_some() {
                dup = true;
            }
        }
    }
    if dup {
        return Err("duplicate signature parameter".into());
    }
    let sv = |k: &str| -> Option<String> { params.get(k).and_then(|v| v.strip_prefix('"')).map(|v| v[..v.len() - 1].to_string()) };
    let nv = |k: &str| -> Option<f64> {
        params.get(k).and_then(|v| if !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()) { v.parse::<f64>().ok() } else { None })
    };
    if sv("tag").as_deref() != Some(DIRECTORY_SIGNATURE_TAG) {
        return Err("wrong tag".into());
    }
    if let Some(alg) = params.get("alg") {
        if *alg != "\"ed25519\"" {
            return Err("unsupported alg".into());
        }
    }
    let (Some(created), Some(expires)) = (nv("created"), nv("expires")) else {
        return Err("created and expires are required".into());
    };
    if !(c.t.is_finite() && c.skew.is_finite() && created.is_finite() && created <= c.t + c.skew) {
        return Err("signature created-time is in the future".into());
    }
    if !(c.t.is_finite() && c.skew.is_finite() && expires.is_finite() && c.t <= expires + c.skew) {
        return Err("signature has expired".into());
    }
    if !(expires - created <= c.max_life) {
        return Err("signature lifetime exceeds maxLifetimeSec".into());
    }
    let keyid = sv("keyid").ok_or("missing keyid")?;
    let key = c
        .keys
        .iter()
        .find(|j| j.get("x").and_then(Value::as_str).is_some_and(|x| thumbprint_of_x(x) == keyid))
        .ok_or("keyid is not the thumbprint of any directory key")?;
    if pnum(key.get("nbf")).is_some_and(|nbf| !(c.t.is_finite() && c.skew.is_finite() && c.t + c.skew >= nbf)) || pnum(key.get("exp")).is_some_and(|exp| !(c.t.is_finite() && c.skew.is_finite() && c.t - c.skew <= exp)) {
        return Err("directory key is outside its validity window".into());
    }
    let sig = match c.sigs.get(label) {
        Some(s) if s.len() == 64 => s,
        _ => return Err("no valid signature bytes for the label".into()),
    };
    let base = format!("\"@authority\";req: {}\n\"@signature-params\": {}", c.authority, &raw[label.len() + 1..]);
    let x = key.get("x").and_then(Value::as_str).unwrap_or("");
    if !ed_verify_x(x, base.as_bytes(), sig) {
        return Err("signature does not verify".into());
    }
    let kid = key.get("kid").and_then(Value::as_str).unwrap_or("").to_string();
    Ok((kid, key.clone()))
}

fn dir_fail(reason: String) -> Value {
    json!({ "valid": false, "reason": reason, "keys": [] })
}

fn verify_directory_core(input: &Value, now: Option<f64>) -> R<Value> {
    let headers = input.get("headers").ok_or("'headers'")?;
    let (si, sh) = (headers.get("signature-input"), headers.get("signature"));
    if !truthy(si) || !truthy(sh) {
        return Ok(dir_fail("missing signature-input or signature header".into()));
    }
    let sig_input = need_str(si, "signature-input")?;
    let sig_header = need_str(sh, "signature")?;
    let directory = parse_key_directory(need_str(input.get("body"), "the document")?)?;
    let mut sigs: HashMap<String, Vec<u8>> = HashMap::new();
    for part in sig_header.split(", ") {
        let Some((label, b64)) = dir_sig(part) else {
            return Ok(dir_fail("malformed signature header".into()));
        };
        sigs.insert(label.to_string(), node_b64(b64));
    }
    let t = match input.get("now") {
        None | Some(Value::Null) => now.map(f64::floor).unwrap_or_else(now_secs),
        Some(v) => need_num(Some(v), "now")?,
    };
    let skew = match input.get("clockSkewSec") {
        None | Some(Value::Null) => 0.0,
        Some(v) => need_num(Some(v), "clockSkewSec")?,
    };
    let max_life = match input.get("maxLifetimeSec") {
        None | Some(Value::Null) => DIRECTORY_LIFETIME_SEC,
        Some(v) => need_num(Some(v), "maxLifetimeSec")?,
    };
    let authority = match input.get("authority") {
        None => "undefined".to_string(),
        Some(v) => js_str(v),
    };
    let dir_keys: &[Value] = directory.get("keys").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let check = DirCheck { sigs: &sigs, keys: dir_keys, authority, t, skew, max_life };
    let mut good: Vec<(String, Value)> = Vec::new();
    let mut last_reason = "no signature entry".to_string();
    for raw in sig_input.split(", ") {
        match check_dir_entry(raw, &check) {
            Ok((kid, key)) => match good.iter_mut().find(|(k, _)| *k == kid) {
                Some(slot) => slot.1 = key,
                None => good.push((kid, key)),
            },
            Err(reason) => last_reason = reason,
        }
    }
    if good.is_empty() {
        return Ok(dir_fail(last_reason));
    }
    Ok(json!({ "valid": true, "keys": good.into_iter().map(|(_, k)| k).collect::<Vec<_>>() }))
}

/// Verify a signed directory response: `input` = `{authority, headers (lower-case signature-input, signature), body, now?, clockSkewSec?,
/// maxLifetimeSec?}`. Fail closed: `{valid: false, reason, keys: []}` unless at least one signature is valid; when valid, `keys` holds
/// only the directory keys that carry a valid signature.
pub fn verify_directory_response(input: &Value, now: Option<f64>) -> Value {
    match verify_directory_core(input, now) {
        Ok(v) => v,
        Err(e) => dir_fail(format!("verification failed (fail closed): {e}")),
    }
}

// ---- fetch_key_directory ----------------------------------------------------------------------------------------------------

/// Fetch (through the caller's `fetch`) and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: errs on a non-https URL, a
/// non-200 status, a wrong content type, an oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK. Never
/// returns a partial directory. `options`: maxBytes? (UTF-16 units, default 65536), timeoutMs? (default 5000), allowInsecureHttp?,
/// requireSignature?, now?. The fetch must not follow redirects.
pub fn fetch_key_directory(url: &str, options: &Value, fetch: DirectoryFetch<'_>) -> R<Value> {
    let u = parse_special(url)?;
    let allow_http = options.get("allowInsecureHttp") == Some(&Value::Bool(true));
    if u.scheme() != "https" && !(allow_http && u.scheme() == "http") {
        return Err("directory URL must be https".into());
    }
    let href = href_of(&u)?;
    let timeout_ms = pnum(options.get("timeoutMs")).unwrap_or(5000.0);
    let init = json!({ "redirect": "error", "timeout": timeout_ms / 1000.0, "headers": { "accept": DIRECTORY_CONTENT_TYPE } });
    let res = fetch(&href, &init)?;
    if res.status != 200 {
        return Err(format!("directory fetch returned status {}", res.status));
    }
    let ct = res.headers.get("content-type").map(String::as_str).unwrap_or("");
    if trim(ct.split(';').next().unwrap_or("")).to_lowercase() != DIRECTORY_CONTENT_TYPE {
        return Err("directory has the wrong content type".into());
    }
    let max_bytes = pnum(options.get("maxBytes")).unwrap_or(65536.0);
    if res.body.encode_utf16().count() as f64 > max_bytes {
        return Err("directory response is too large".into());
    }
    let directory = parse_key_directory(&res.body)?;
    if options.get("requireSignature") == Some(&Value::Bool(true)) {
        let mut vin = json!({
            "authority": authority_of(&u),
            "body": res.body.clone(),
            "headers": {
                "signature-input": res.headers.get("signature-input").cloned().unwrap_or_default(),
                "signature": res.headers.get("signature").cloned().unwrap_or_default(),
            },
        });
        if let Some(n) = options.get("now").filter(|n| !n.is_null()) {
            vin["now"] = n.clone();
        }
        let v = verify_directory_response(&vin, None);
        if v.get("valid") != Some(&Value::Bool(true)) {
            return Err(format!("directory signature: {}", v.get("reason").map(js_str).unwrap_or_default()));
        }
        return Ok(json!({ "keys": v.get("keys").cloned().unwrap_or(Value::Null) }));
    }
    Ok(directory)
}
