//! An OUTBOUND connection/token vault for PCA agents: it holds an agent's third-party OAuth tokens and refreshes them, releasing a
//! fresh, least-privilege access token only when a verified Proof-Carrying Action proves authority over the provider and scopes.
//! A port of the TypeScript reference (@atlasauth/pca-connect): `oauth_scope` caveats, token refresh, the proxy-mode request
//! extractor, signed release receipts and the [`TokenVault`]. JSON-valued: connections, PCActns, requests and provider configs are
//! `serde_json::Value`s; transports, stores, clocks and the replay store are closures / traits.
//!
//! The envelope-encrypted store is [`crate::connect_encrypted::EncryptedConnectionStore`] (`strict` mode needs a store whose
//! [`ConnectionStore::encrypted`] is true). A string cut inside a surrogate pair (a refresh error detail) yields U+FFFD (a Rust string cannot hold a lone surrogate).
use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::authorize::StateStore;
use crate::escalation::escalation_action_digest;
use crate::intent_strict::verify_artifact_sig;
use crate::intent_v2::js_value_string;
use crate::{hash_canonical, hash_canonical_strict, strict_parse, verify_pcactn_core_with, VerifyOptions};
use regex::Regex;
use serde_json::{json, Map, Number, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub const OAUTH_SCOPE_CAVEAT: &str = "oauth_scope";
pub const RELEASE_RECEIPT_DOMAIN: &str = "atlas-pca/connect-release-receipt/v1\0";
pub const DEFAULT_PROXY_HEADERS: [&str; 3] = ["content-type", "accept", "idempotency-key"];
const MAX_SAFE: i64 = 9_007_199_254_740_991;

// ---- errors (errors.ts) ----------------------------------------------------------------------------------------------------

/// A typed refusal of the vault (branch on `code`), or a plain host error (`code` is empty, `name` is "Error").
#[derive(Debug, Clone, PartialEq)]
pub struct VaultError {
    pub name: &'static str,
    pub code: &'static str,
    pub message: String,
    pub status: Option<i64>,
    pub missing: Vec<String>,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for VaultError {}

impl VaultError {
    fn typed(name: &'static str, code: &'static str, message: String) -> VaultError {
        VaultError { name, code, message, status: None, missing: vec![] }
    }
    /// A non-typed error (the reference's TypeError / Error).
    pub fn plain(message: impl Into<String>) -> VaultError {
        VaultError { name: "Error", code: "", message: message.into(), status: None, missing: vec![] }
    }
    /// The error as the oracle records it: `{ok:false, name, code, message?, status?, missing?}` (the message of `not_authorized`
    /// is left out: its text carries verifier reasons).
    pub fn to_json(&self) -> Value {
        if self.code.is_empty() {
            return json!({ "ok": false, "name": "Error" });
        }
        let mut m = Map::new();
        m.insert("ok".into(), json!(false));
        m.insert("name".into(), json!(self.name));
        m.insert("code".into(), json!(self.code));
        if self.code != "not_authorized" {
            m.insert("message".into(), json!(self.message));
        }
        if let Some(s) = self.status {
            m.insert("status".into(), json!(s));
        }
        if !self.missing.is_empty() {
            m.insert("missing".into(), json!(self.missing));
        }
        Value::Object(m)
    }
}

pub fn not_authorized(message: impl Into<String>) -> VaultError {
    VaultError::typed("NotAuthorizedError", "not_authorized", message.into())
}
pub fn scope_exceeded(provider: &str, missing: &[String]) -> VaultError {
    let mut e = VaultError::typed(
        "ScopeExceededError",
        "scope_exceeded",
        format!("requested scopes exceed the capability's grant for '{provider}': not granted [{}]", missing.join(", ")),
    );
    e.missing = missing.to_vec();
    e
}
pub fn expired_no_refresh(provider: &str, connection_id: &str) -> VaultError {
    VaultError::typed(
        "ExpiredNoRefreshError",
        "expired_no_refresh",
        format!("connection '{provider}/{connection_id}' token is expired and has no refresh token"),
    )
}
pub fn refresh_failed(provider: &str, detail: &str, status: Option<i64>) -> VaultError {
    let mut e = VaultError::typed("RefreshFailedError", "refresh_failed", format!("refresh for '{provider}' failed: {detail}"));
    e.status = status;
    e
}
pub fn unknown_connection(agent_id: &str, provider: &str, connection_id: &str) -> VaultError {
    VaultError::typed(
        "UnknownConnectionError",
        "unknown_connection",
        format!("no connection for agent '{agent_id}' provider '{provider}' id '{connection_id}'"),
    )
}
pub fn store_error(message: &str) -> VaultError {
    VaultError::typed("StoreError", "store_error", message.to_string())
}
pub fn unknown_action(verb: &str) -> VaultError {
    VaultError::typed("UnknownActionError", "unknown_action", format!("no pinned action definition for verb '{verb}': refusing to release a credential"))
}
pub fn unconfirmed_action(verb: &str) -> VaultError {
    VaultError::typed(
        "UnconfirmedActionError",
        "unconfirmed_action",
        format!("the definition of '{verb}' has no valid signed confirmation: refusing to release a credential"),
    )
}
pub fn request_mismatch(message: impl Into<String>) -> VaultError {
    VaultError::typed("RequestMismatchError", "request_mismatch", message.into())
}
pub fn bearer_release_disabled() -> VaultError {
    VaultError::typed(
        "BearerReleaseDisabledError",
        "bearer_release_disabled",
        "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)".into(),
    )
}
pub fn proxy_failed(message: &str) -> VaultError {
    VaultError::typed("ProxyFailedError", "proxy_failed", message.to_string())
}

// ---- small JS-shaped helpers --------------------------------------------------------------------------------------------------

/// A finite JSON number; an integral value is written as an integer (what `JSON.parse(JSON.stringify(x))` yields).
pub(crate) fn jnum(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64 {
        Value::from(f as i64)
    } else {
        Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

pub(crate) fn finite(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

pub(crate) fn strs(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

pub(crate) fn s_or_undefined(v: Option<&Value>) -> String {
    v.map_or("undefined".to_string(), js_value_string)
}

fn u16_sort(v: &mut [String]) {
    v.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
}

/// `obj.k` of a JSON value: an object member (None = undefined); null / undefined throw a TypeError; other values have none.
fn prop<'a>(v: &'a Value, k: &str) -> Result<Option<&'a Value>, VaultError> {
    match v {
        Value::Null => Err(VaultError::plain(format!("Cannot read properties of null (reading '{k}')"))),
        Value::Object(m) => Ok(m.get(k)),
        _ => Ok(None),
    }
}

/// `Object.entries(v)`: null throws; numbers and booleans have none.
fn entries(v: &Value) -> Result<Vec<(String, Value)>, VaultError> {
    Ok(match v {
        Value::Object(m) => m.iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        Value::Null => return Err(VaultError::plain("Cannot convert undefined or null to object")),
        _ => vec![],
    })
}

// ---- the oauth_scope caveat (authority.ts) ----------------------------------------------------------------------------------

/// An `oauth_scope` caveat granting `scopes` on `provider`; duplicate scopes are collapsed.
pub fn oauth_scope_caveat(provider: &str, scopes: &[String]) -> Value {
    let mut seen: Vec<&String> = vec![];
    for s in scopes {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    json!({ "type": OAUTH_SCOPE_CAVEAT, "provider": provider, "scopes": seen })
}

pub fn is_oauth_scope_caveat(cv: &Value) -> bool {
    let Value::Object(m) = cv else { return false };
    m.get("type").and_then(Value::as_str) == Some(OAUTH_SCOPE_CAVEAT)
        && m.get("provider").is_some_and(Value::is_string)
        && m.get("scopes").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string))
}

/// The INTERSECTION of every `oauth_scope` caveat naming `provider` in the chain's leaf, or `None` when the chain grants nothing for
/// it (the vault tells "not covered" from "covered but too narrow"). Run the chain verifier first. Err = the reference's TypeError
/// (a null leaf). The scope set is returned without duplicates, in first-seen order.
pub fn granted_oauth_scopes(chain: &Value, provider: &str) -> Result<Option<Vec<String>>, VaultError> {
    let Value::Array(c) = chain else { return Ok(None) };
    let Some(leaf) = c.last() else { return Ok(None) };
    let caveats = match prop(leaf, "caveats")? {
        Some(Value::Array(a)) => a,
        _ => return Ok(None),
    };
    let mut effective: Option<Vec<String>> = None;
    for cv in caveats {
        if !is_oauth_scope_caveat(cv) || cv["provider"].as_str() != Some(provider) {
            continue;
        }
        let here = strs(cv.get("scopes"));
        effective = Some(match effective {
            None => {
                let mut d: Vec<String> = vec![];
                for s in here {
                    if !d.contains(&s) {
                        d.push(s);
                    }
                }
                d
            }
            Some(e) => e.into_iter().filter(|s| here.contains(s)).collect(),
        });
    }
    Ok(effective)
}

// ---- stored connections (store.ts) -------------------------------------------------------------------------------------------

/// A copy of a stored connection (the reference's `cloneConnection`).
pub fn clone_connection(c: &Value) -> Value {
    let a = &c["authority"];
    let mut auth = Map::new();
    auth.insert("provider".into(), a["provider"].clone());
    auth.insert("principal".into(), a["principal"].clone());
    auth.insert("scopes".into(), a["scopes"].clone());
    if let Some(x) = a.get("audience") {
        auth.insert("audience".into(), x.clone());
    }
    let mut out = Map::new();
    for k in ["agentId", "provider", "connectionId", "accessToken", "expiresAt", "scopes"] {
        out.insert(k.into(), c[k].clone());
    }
    out.insert("authority".into(), Value::Object(auth));
    out.insert("createdAt".into(), c["createdAt"].clone());
    out.insert("useCount".into(), c["useCount"].clone());
    for k in ["refreshToken", "lastUsedAt"] {
        if let Some(x) = c.get(k) {
            out.insert(k.into(), x.clone());
        }
    }
    Value::Object(out)
}

/// Persistence of the vault's connections. `get` / `set` / `delete` take and return JSON connections
/// (`{agentId, provider, connectionId, accessToken, refreshToken?, expiresAt, scopes, authority, createdAt, useCount, lastUsedAt?}`).
/// A non-typed error is reported to the caller as a bare `store_error` (its text can quote a record).
pub trait ConnectionStore: Send + Sync {
    fn get(&self, key: &Value) -> Result<Option<Value>, VaultError>;
    fn set(&self, connection: &Value) -> Result<(), VaultError>;
    fn delete(&self, key: &Value) -> Result<(), VaultError>;
    /// True for a store that encrypts tokens at rest (a strict vault requires it).
    fn encrypted(&self) -> bool {
        false
    }
}

fn key_string(key: &Value) -> String {
    format!("{}\u{0}{}\u{0}{}", s_or_undefined(key.get("agentId")), s_or_undefined(key.get("provider")), s_or_undefined(key.get("connectionId")))
}

/// Process-local connection store; records are cloned in and out so callers cannot mutate vault state.
#[derive(Default)]
pub struct InMemoryConnectionStore {
    map: Mutex<HashMap<String, Value>>,
}

impl InMemoryConnectionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConnectionStore for InMemoryConnectionStore {
    fn get(&self, key: &Value) -> Result<Option<Value>, VaultError> {
        let m = self.map.lock().map_err(|_| store_error("the connection store failed"))?;
        Ok(m.get(&key_string(key)).map(clone_connection))
    }
    fn set(&self, connection: &Value) -> Result<(), VaultError> {
        let mut m = self.map.lock().map_err(|_| store_error("the connection store failed"))?;
        m.insert(key_string(connection), clone_connection(connection));
        Ok(())
    }
    fn delete(&self, key: &Value) -> Result<(), VaultError> {
        let mut m = self.map.lock().map_err(|_| store_error("the connection store failed"))?;
        m.remove(&key_string(key));
        Ok(())
    }
}

// ---- the proxy-mode request extractor (proxy.ts) ------------------------------------------------------------------------------

/// Maps an outbound request `{method, url, headers?, body?}` back to the action's parameters, or refuses it.
pub type Extractor = Arc<dyn Fn(&Value) -> Result<Value, VaultError> + Send + Sync>;

fn mismatch(m: &str) -> VaultError {
    request_mismatch(format!("outbound request refused: {m}"))
}

fn hexv(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// `decodeURIComponent`: a bad escape or invalid UTF-8 is an error.
fn decode_uri_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = b.get(i + 1..i + 3)?;
            out.push(hexv(h[0])? * 16 + hexv(h[1])?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The extractor of one operation: it refuses anything the pinned spec does not carry (an extra query key, body member, header or
/// redirect target). `Err` on a malformed spec (the reference's TypeError / invalid URL).
pub fn http_extractor(spec: &Value) -> Result<Extractor, VaultError> {
    let spec_url = spec["url"].as_str().ok_or_else(|| VaultError::plain("Invalid URL"))?.to_string();
    let ph = Regex::new(r"\{([A-Za-z0-9_]+)\}").map_err(|e| VaultError::plain(e.to_string()))?;
    let probe = ph.replace_all(&spec_url, "x").to_string();
    let u = url::Url::parse(&probe).map_err(|_| VaultError::plain("Invalid URL"))?;
    if u.scheme() != "https"
        || u.query().is_some_and(|q| !q.is_empty())
        || u.fragment().is_some_and(|f| !f.is_empty())
        || !u.username().is_empty()
        || u.password().is_some_and(|p| !p.is_empty())
    {
        return Err(VaultError::plain("httpExtractor: url must be https without query, fragment or userinfo"));
    }
    let method = spec["method"].as_str().ok_or_else(|| VaultError::plain("httpExtractor: method must be a string"))?.to_string();
    if method != method.to_uppercase() {
        return Err(VaultError::plain("httpExtractor: method must be upper case"));
    }
    let origin = u.origin().ascii_serialization();
    let template: String = spec_url.chars().skip(origin.chars().count()).collect();
    let mut pat = String::from("^(?:");
    let mut names: Vec<String> = vec![];
    let mut last = 0;
    for c in ph.captures_iter(&template) {
        let w = c.get(0).ok_or_else(|| VaultError::plain("Invalid URL"))?;
        pat.push_str(&regex::escape(&template[last..w.start()]));
        pat.push_str("([A-Za-z0-9._~%-]+)");
        names.push(c[1].to_string());
        last = w.end();
    }
    pat.push_str(&regex::escape(&template[last..]));
    pat.push_str(")$");
    let rx = Regex::new(&pat).map_err(|e| VaultError::plain(e.to_string()))?;
    let allowed_query: HashSet<String> = strs(spec.get("query")).into_iter().collect();
    let body_kind: Option<String> = spec.get("body").and_then(Value::as_str).map(String::from);
    let ctype: Option<&'static str> = match body_kind.as_deref() {
        Some("json") => Some("application/json"),
        Some("form") => Some("application/x-www-form-urlencoded"),
        _ => None,
    };
    let fixed0: Vec<(String, Value)> =
        spec.get("fixed").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();

    Ok(Arc::new(move |req: &Value| -> Result<Value, VaultError> {
        let req_method = req.get("method");
        if req_method.and_then(Value::as_str) != Some(method.as_str()) {
            return Err(mismatch(&format!("method {} is not {}", s_or_undefined(req_method), method)));
        }
        let r = match req.get("url").and_then(Value::as_str).and_then(|s| url::Url::parse(s).ok()) {
            Some(r) => r,
            None => return Err(mismatch("the url does not parse")),
        };
        if r.origin().ascii_serialization() != origin
            || !r.username().is_empty()
            || r.password().is_some_and(|p| !p.is_empty())
            || r.fragment().is_some_and(|f| !f.is_empty())
        {
            return Err(mismatch("the url is not on the pinned origin"));
        }
        let caps = rx.captures(r.path()).ok_or_else(|| mismatch("the path does not match the pinned template"))?;
        let mut params: Map<String, Value> = Map::new();
        let put = |params: &mut Map<String, Value>, k: &str, v: Value| -> Result<(), VaultError> {
            if params.contains_key(k) {
                return Err(mismatch(&format!("parameter '{k}' is carried twice")));
            }
            params.insert(k.to_string(), v);
            Ok(())
        };
        for (i, n) in names.iter().enumerate() {
            let raw = caps.get(i + 1).map_or("", |m| m.as_str());
            let v = decode_uri_component(raw).ok_or_else(|| mismatch("a path segment is not valid percent-encoding"))?;
            put(&mut params, n, Value::String(v))?;
        }
        let mut seen: HashSet<String> = HashSet::new();
        for (k, v) in r.query_pairs() {
            if !allowed_query.contains(&*k) {
                return Err(mismatch(&format!("query key '{k}' is not allowed")));
            }
            if !seen.insert(k.to_string()) {
                return Err(mismatch(&format!("query key '{k}' is repeated")));
            }
            put(&mut params, &k, Value::String(v.to_string()))?;
        }
        let ct: Option<Value> = match req.get("headers") {
            None | Some(Value::Null) => None,
            Some(h) => entries(h)?.into_iter().find(|(k, _)| k.to_lowercase() == "content-type").map(|(_, v)| v),
        };
        let body = req.get("body");
        match &body_kind {
            None => {
                if !matches!(body, None | Some(Value::String(_))) || body.and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
                    return Err(mismatch("this operation carries no body"));
                }
            }
            Some(kind) => {
                let text = match body {
                    Some(Value::String(s)) if !s.is_empty() => s.as_str(),
                    _ => return Err(mismatch("the body is missing")),
                };
                let ct_ok = match &ct {
                    None => false,
                    Some(Value::String(c)) => Some(c.split(';').next().unwrap_or("").trim().to_lowercase().as_str()) == ctype,
                    Some(_) => return Err(VaultError::plain("content-type is not a string")),
                };
                if !ct_ok {
                    return Err(mismatch(&format!("content-type must be {}", ctype.unwrap_or("undefined"))));
                }
                let mut fixed = fixed0.clone();
                if kind == "json" {
                    let b = strict_parse(text).map_err(|_| mismatch("the body is not strict JSON"))?;
                    let Value::Object(bm) = b else { return Err(mismatch("the body must be a JSON object")) };
                    for (k, v) in bm {
                        if let Some(pos) = fixed.iter().position(|(fk, _)| *fk == k) {
                            if hash_canonical(&v) != hash_canonical(&fixed[pos].1) {
                                return Err(mismatch(&format!("fixed member '{k}' has another value")));
                            }
                            fixed.remove(pos);
                        } else {
                            put(&mut params, &k, v)?;
                        }
                    }
                } else {
                    let mut keys: HashSet<String> = HashSet::new();
                    let form = text.strip_prefix('?').unwrap_or(text);
                    for (k, v) in url::form_urlencoded::parse(form.as_bytes()) {
                        if !keys.insert(k.to_string()) {
                            return Err(mismatch(&format!("form key '{k}' is repeated")));
                        }
                        if let Some(pos) = fixed.iter().position(|(fk, _)| fk.as_str() == &*k) {
                            if fixed[pos].1.as_str() != Some(&*v) {
                                return Err(mismatch(&format!("fixed member '{k}' has another value")));
                            }
                            fixed.remove(pos);
                        } else {
                            put(&mut params, &k, Value::String(v.to_string()))?;
                        }
                    }
                }
                if !fixed.is_empty() {
                    let names: Vec<&str> = fixed.iter().map(|(k, _)| k.as_str()).collect();
                    return Err(mismatch(&format!("fixed member(s) {} missing", names.join(", "))));
                }
            }
        }
        Ok(Value::Object(params))
    }))
}

/// The request headers the agent may set (the vault sets Authorization itself); anything else is refused. Returns the headers
/// lower-cased. `allow` holds lower-case names.
pub fn check_proxy_headers(headers: Option<&Value>, allow: &[String]) -> Result<Map<String, Value>, VaultError> {
    let mut out = Map::new();
    let list = match headers {
        None | Some(Value::Null) => vec![],
        Some(h) => entries(h)?,
    };
    for (k, v) in list {
        let n = k.to_lowercase();
        if !allow.contains(&n) {
            return Err(mismatch(&format!("header '{k}' is not allowed")));
        }
        if out.contains_key(&n) {
            return Err(mismatch(&format!("header '{k}' is repeated")));
        }
        match &v {
            Value::String(s) if !s.contains(['\r', '\n', '\0']) => {}
            _ => return Err(mismatch(&format!("header '{k}' has an invalid value"))),
        }
        out.insert(n, v);
    }
    Ok(out)
}

// ---- release receipts (proxy.ts) ---------------------------------------------------------------------------------------------

pub fn outbound_request_digest(method: &str, url: &str, headers: &Value, body: Option<&str>) -> Result<String, VaultError> {
    hash_canonical_strict(&json!({ "d": "atlas-pca/connect-request/v1", "method": method, "url": url, "headers": headers, "body": body }))
        .ok_or_else(|| VaultError::plain("outboundRequestDigest: not canonical"))
}

/// The receipt body plus an Ed25519 signature of the vault key (a 32-byte seed) over domain || canonical(body).
pub fn sign_release_receipt(body: &Value, secret_key: &[u8; 32]) -> Result<Value, VaultError> {
    sign_artifact(RELEASE_RECEIPT_DOMAIN, body, &KeyPair::from_seed(secret_key), &Suite::default()).map_err(VaultError::plain)
}

/// True iff the receipt is signed by the pinned vault key.
pub fn verify_release_receipt(r: &Value, vault_pk: &str) -> bool {
    r.as_object().is_some_and(|o| verify_artifact_sig(RELEASE_RECEIPT_DOMAIN, o, vault_pk, None))
}

pub fn receipt_action_digest(pcactn: &Value) -> Result<String, VaultError> {
    escalation_action_digest(pcactn).ok_or_else(|| VaultError::plain("receiptActionDigest: not canonical"))
}

// ---- token refresh (refresh.ts) -----------------------------------------------------------------------------------------------

/// What a transport returns: the status, and the already-read JSON / text bodies (an `Err` is a body that cannot be read).
pub struct FetchResponse {
    pub ok: bool,
    pub status: i64,
    pub json: Result<Value, String>,
    pub text: Result<String, String>,
}

/// `fetch(url, {method, headers, body})`.
pub type FetchFn = Arc<dyn Fn(&str, &Value) -> Result<FetchResponse, String> + Send + Sync>;

pub(crate) fn encode_uri_component(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub(crate) fn redact(text: &str, secrets: &[String]) -> String {
    let mut t = text.to_string();
    for s in secrets {
        if !s.is_empty() {
            t = t.replace(s.as_str(), "[redacted]");
        }
    }
    t
}

/// JavaScript whitespace (`String.prototype.trim` / `\s`).
pub(crate) fn js_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

struct Parsed {
    access_token: String,
    expires_in_secs: Option<f64>,
    refresh_token: Option<String>,
    scopes: Option<Vec<String>>,
}

fn parse_token_response(body: &Value, provider: &str) -> Result<Parsed, VaultError> {
    let Value::Object(m) = body else { return Err(refresh_failed(provider, "token endpoint returned a non-object body", None)) };
    let at = match m.get("access_token") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(refresh_failed(provider, "token endpoint response has no access_token", None)),
    };
    let expires_in_secs = finite(m.get("expires_in")).filter(|x| *x > 0.0);
    let refresh_token = match m.get("refresh_token") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let scopes = match m.get("scope") {
        Some(Value::String(s)) => {
            let t = s.trim_matches(js_ws);
            if t.is_empty() {
                None
            } else {
                Some(t.split(js_ws).filter(|x| !x.is_empty()).map(String::from).collect())
            }
        }
        _ => None,
    };
    Ok(Parsed { access_token: at, expires_in_secs, refresh_token, scopes })
}

/// Epoch-ms expiry claimed by a JWT access token; None for an opaque (non-JWT) token.
fn jwt_expiry_ms(token: &str) -> Option<f64> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    use base64::{alphabet, Engine};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let cleaned: String = parts[1]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/'))
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    let eng = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true),
    );
    let bytes = eng.decode(cleaned.as_bytes()).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let exp = finite(claims.as_object()?.get("exp"))?;
    Some(exp * 1000.0)
}

/// Refresh `connection`'s access token at its provider's token endpoint. Returns the fields to apply to the connection
/// (`accessToken`, `refreshToken`, `expiresAt`, `scopes`); `refresh_failed` on any transport or parse failure. No secret reaches an
/// error.
pub fn refresh_connection(
    connection: &Value,
    config: Option<&Value>,
    refresh_token: &str,
    requested: &[String],
    fetch: Option<&FetchFn>,
    now: f64,
    default_token_lifetime_ms: f64,
) -> Result<Value, VaultError> {
    let provider = connection["provider"].as_str().unwrap_or("").to_string();
    let mut secrets: Vec<String> = vec![refresh_token.to_string(), connection["accessToken"].as_str().unwrap_or("").to_string()];
    if let Some(c) = config {
        if let Some(s) = c.get("clientSecret").and_then(Value::as_str) {
            secrets.push(s.to_string());
        }
        if let Some(Value::Object(x)) = c.get("extraParams") {
            secrets.extend(x.values().filter_map(|v| v.as_str().map(String::from)));
        }
    }
    let Some(config) = config.filter(|c| !c.is_null()) else { return Err(refresh_failed(&provider, "no provider token-endpoint config", None)) };
    let Some(fetch) = fetch else { return Err(refresh_failed(&provider, "no fetch transport configured", None)) };
    let mut params: Map<String, Value> = Map::new();
    params.insert("grant_type".into(), json!("refresh_token"));
    params.insert("refresh_token".into(), json!(refresh_token));
    params.insert("client_id".into(), config["clientId"].clone());
    if let Some(s) = config.get("clientSecret") {
        params.insert("client_secret".into(), s.clone());
    }
    if let Some(Value::Object(x)) = config.get("extraParams") {
        for (k, v) in x {
            params.insert(k.clone(), v.clone());
        }
    }
    let narrowing = config.get("supportsScopeNarrowing") == Some(&Value::Bool(true));
    if narrowing && !requested.is_empty() {
        params.insert("scope".into(), json!(requested.join(" ")));
    }
    let body = params.iter().map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(&js_value_string(v)))).collect::<Vec<_>>().join("&");
    let endpoint = config["tokenEndpoint"].as_str().unwrap_or("");
    let init = json!({ "method": "POST", "headers": { "content-type": "application/x-www-form-urlencoded", "accept": "application/json" }, "body": body });
    let res = match fetch(endpoint, &init) {
        Ok(r) => r,
        Err(e) => return Err(refresh_failed(&provider, &format!("transport error: {}", redact(&e, &secrets)), None)),
    };
    if !res.ok {
        let detail = match &res.text {
            Ok(t) => {
                let u: Vec<u16> = t.encode_utf16().take(256).collect();
                redact(&String::from_utf16_lossy(&u), &secrets)
            }
            Err(_) => "<unreadable body>".to_string(),
        };
        return Err(refresh_failed(&provider, &format!("token endpoint {}: {detail}", res.status), Some(res.status)));
    }
    let j = res.json.map_err(|_| refresh_failed(&provider, "unparseable JSON body", None))?;
    let parsed = parse_token_response(&j, &provider)?;
    let expires_at = match parsed.expires_in_secs {
        Some(secs) => now + secs * 1000.0,
        None => jwt_expiry_ms(&parsed.access_token).unwrap_or(now + default_token_lifetime_ms),
    };
    let scopes: Vec<String> = match parsed.scopes {
        Some(s) => s,
        None if narrowing && !requested.is_empty() => requested.to_vec(),
        None => strs(connection.get("scopes")),
    };
    Ok(json!({
        "accessToken": parsed.access_token,
        "expiresAt": jnum(expires_at),
        "scopes": scopes,
        "refreshToken": parsed.refresh_token.unwrap_or_else(|| refresh_token.to_string()),
    }))
}

// ---- the replay guard (pca replay.ts, the part the vault spends an action with) ------------------------------------------------

fn safe_nonneg_int(v: Option<&Value>) -> Option<i64> {
    let Some(Value::Number(n)) = v else { return None };
    if let Some(i) = n.as_i64() {
        return (0..=MAX_SAFE).contains(&i).then_some(i);
    }
    let f = n.as_f64()?;
    (f.fract() == 0.0 && f >= 0.0 && f <= MAX_SAFE as f64 && !(f == 0.0 && f.is_sign_negative())).then_some(f as i64)
}

/// May the (signature-verified) PCActn be accepted ONCE? `Err(reason)` is a denial; a store that cannot decide denies.
fn guard_pcactn_replay(store: &dyn StateStore, p: &Value, now: i64) -> Result<(), String> {
    const SKEW: i64 = 60_000;
    let Value::Object(po) = p else { return Err("not a PCActn".into()) };
    let aud = match po.get("aud") {
        Some(Value::String(a)) if !a.is_empty() && a.len() <= 256 => a.as_str(),
        _ => return Err("verifier audience is invalid".into()),
    };
    if !(0..=MAX_SAFE).contains(&now.abs()) {
        return Err("verifier clock is not an integer epoch-ms".into());
    }
    let (iat, exp) = match (safe_nonneg_int(po.get("iat")), safe_nonneg_int(po.get("exp"))) {
        (Some(i), Some(e)) if e > i && e - i <= 3_600_000 => (i, e),
        _ => return Err("iat / exp are not a valid bounded window".into()),
    };
    if iat > now + SKEW {
        return Err("iat is in the future beyond the clock-skew allowance".into());
    }
    if now > exp {
        return Err("the PCActn has expired".into());
    }
    let leaf = po.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last());
    let holder = leaf.and_then(|l| l.get("holder")).and_then(Value::as_str);
    let grant = po.get("grant_ref").and_then(Value::as_str);
    let (Some(holder), Some(grant)) = (holder, grant) else { return Err("no leaf holder / grant".into()) };
    if holder.is_empty() || holder.len() > 512 || grant.is_empty() || grant.len() > 512 {
        return Err("grant / holder is not a bounded string".into());
    }
    if safe_nonneg_int(po.get("counter")).is_none() {
        return Err("counter is not a non-negative safe integer".into());
    }
    let nonce = match po.get("nonce") {
        None => return Err("a nonce is required".into()),
        Some(Value::String(n)) if !n.is_empty() && n.len() <= 128 => n.as_str(),
        Some(_) => return Err("nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes".into()),
    };
    let key = crate::events::replay_key("pca-nonce/v1", &[aud, grant, holder, nonce]);
    match store.consume_once(&key, exp + SKEW, now) {
        Ok(true) => Ok(()),
        Ok(false) => Err("nonce already consumed".into()),
        Err(e) => Err(format!("replay store failed closed: {}", e.0)),
    }
}

// ---- the vault (vault.ts) ------------------------------------------------------------------------------------------------------

/// A pinned action definition (K7): `upstream` is `{provider, scopes_min}`; `extract` maps a proxied request to its parameters.
#[derive(Clone)]
pub struct ActionDef {
    pub verb: String,
    pub def_digest: Value,
    pub confirmed: bool,
    pub upstream: Value,
    pub extract: Option<Extractor>,
}

pub type ClockFn = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type ActionsFn = Arc<dyn Fn(&str) -> Option<ActionDef> + Send + Sync>;
/// `(request) -> response`, a JSON `{status, headers, body}`; the request is `{method, url, headers, body?, redirect: "manual"}`.
pub type ProxyFetchFn = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
pub type IsRevokedFn = Arc<dyn Fn(&Value) -> Result<bool, String> + Send + Sync>;
pub type ResourceForFn = Arc<dyn Fn(&str, &str) -> String + Send + Sync>;
pub type ReceiptSinkFn = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

/// Sign a release receipt with this vault key (a 32-byte Ed25519 seed) for every release / proxied call and hand it to `sink`.
#[derive(Clone)]
pub struct ReceiptConfig {
    pub secret_key: [u8; 32],
    pub sink: Option<ReceiptSinkFn>,
}

/// The connection-use verb check of the legacy (non-derived) mode.
#[derive(Clone, Debug, PartialEq)]
pub enum UseVerb {
    /// `use_connection`
    Default,
    /// no verb check
    Skip,
    Verb(String),
}

pub struct VaultOptions {
    pub store: Option<Arc<dyn ConnectionStore>>,
    /// `{provider: {tokenEndpoint, clientId, clientSecret?, extraParams?, supportsScopeNarrowing?}}`
    pub providers: Map<String, Value>,
    pub fetch: Option<FetchFn>,
    pub now: Option<ClockFn>,
    pub audience: Option<String>,
    pub pq_pins: Option<HashMap<String, String>>,
    pub authorized_plan_roots: Option<Vec<String>>,
    pub insecure_skip_plan_root_check: bool,
    pub expiry_leeway_ms: Option<f64>,
    pub default_connection_id: Option<String>,
    pub require_action_binding: Option<bool>,
    pub resource_for: Option<ResourceForFn>,
    pub use_verb: UseVerb,
    pub default_token_lifetime_ms: Option<f64>,
    pub replay: Option<Arc<dyn StateStore>>,
    pub is_revoked: Option<IsRevokedFn>,
    /// default true: requires an encrypting store, `replay`, `is_revoked` and an `audience`
    pub strict: Option<bool>,
    pub actions: Option<ActionsFn>,
    pub insecure_bearer_release: bool,
    pub proxy_fetch: Option<ProxyFetchFn>,
    pub proxy_headers: Option<Vec<String>>,
    pub max_proxy_response_bytes: Option<f64>,
    pub receipts: Option<ReceiptConfig>,
}

impl Default for VaultOptions {
    fn default() -> Self {
        VaultOptions {
            store: None,
            providers: Map::new(),
            fetch: None,
            now: None,
            audience: None,
            pq_pins: None,
            authorized_plan_roots: None,
            insecure_skip_plan_root_check: false,
            expiry_leeway_ms: None,
            default_connection_id: None,
            require_action_binding: None,
            resource_for: None,
            use_verb: UseVerb::Default,
            default_token_lifetime_ms: None,
            replay: None,
            is_revoked: None,
            strict: None,
            actions: None,
            insecure_bearer_release: false,
            proxy_fetch: None,
            proxy_headers: None,
            max_proxy_response_bytes: None,
            receipts: None,
        }
    }
}

struct Auth {
    provider: String,
    connection_id: String,
    connection: Value,
    requested: Vec<String>,
    now: i64,
    action: Option<ActionDef>,
}

/// Holds an agent's third-party OAuth tokens and releases a fresh access token only for a verified PCActn.
pub struct TokenVault {
    store: Arc<dyn ConnectionStore>,
    providers: Map<String, Value>,
    fetch: Option<FetchFn>,
    now: ClockFn,
    audience: Option<String>,
    pq_pins: Option<HashMap<String, String>>,
    plan_roots: Option<Vec<String>>,
    skip_plan_root: bool,
    leeway: f64,
    default_cid: String,
    require_binding: bool,
    resource_for: ResourceForFn,
    use_verb: UseVerb,
    default_lifetime: f64,
    replay: Option<Arc<dyn StateStore>>,
    is_revoked: Option<IsRevokedFn>,
    actions: Option<ActionsFn>,
    bearer: bool,
    proxy_fetch: Option<ProxyFetchFn>,
    proxy_headers: Vec<String>,
    max_proxy: f64,
    receipts: Option<ReceiptConfig>,
}

fn sys_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

impl TokenVault {
    /// `Err` is the reference's constructor throw (strict mode without its requirements, or no store).
    pub fn new(o: VaultOptions) -> Result<TokenVault, VaultError> {
        if o.strict != Some(false) {
            let mut missing: Vec<&str> = vec![];
            if !o.store.as_ref().is_some_and(|s| s.encrypted()) {
                missing.push("an encrypting store");
            }
            if o.replay.is_none() {
                missing.push("replay");
            }
            if o.is_revoked.is_none() {
                missing.push("isRevoked");
            }
            if !matches!(&o.audience, Some(a) if !a.is_empty()) {
                missing.push("audience");
            }
            if !missing.is_empty() {
                return Err(VaultError::plain(format!("TokenVault strict mode requires {}", missing.join(", "))));
            }
        }
        let store = o.store.ok_or_else(|| VaultError::plain("TokenVault requires a store"))?;
        let proxy_headers: Vec<String> =
            o.proxy_headers.unwrap_or_else(|| DEFAULT_PROXY_HEADERS.iter().map(|s| s.to_string()).collect()).into_iter().map(|h| h.to_lowercase()).collect();
        Ok(TokenVault {
            store,
            providers: o.providers,
            fetch: o.fetch,
            now: o.now.unwrap_or_else(|| Arc::new(sys_now) as ClockFn),
            audience: o.audience,
            pq_pins: o.pq_pins,
            plan_roots: o.authorized_plan_roots,
            skip_plan_root: o.insecure_skip_plan_root_check,
            leeway: o.expiry_leeway_ms.unwrap_or(30_000.0),
            default_cid: o.default_connection_id.unwrap_or_else(|| "default".into()),
            require_binding: o.require_action_binding.unwrap_or(true),
            resource_for: o.resource_for.unwrap_or_else(|| Arc::new(|provider: &str, _cid: &str| format!("oauth:{provider}")) as ResourceForFn),
            use_verb: o.use_verb,
            default_lifetime: o.default_token_lifetime_ms.unwrap_or(300_000.0),
            replay: o.replay,
            is_revoked: o.is_revoked,
            actions: o.actions,
            bearer: o.insecure_bearer_release,
            proxy_fetch: o.proxy_fetch,
            proxy_headers,
            max_proxy: o.max_proxy_response_bytes.unwrap_or(4.0 * 1024.0 * 1024.0),
            receipts: o.receipts,
        })
    }

    /// Store (or replace) an agent's connection. `args` is `{agentId, provider, connectionId?, accessToken, refreshToken?, expiresAt,
    /// scopes, authority: {principal, scopes?, audience?}}`; the authority descriptor binds which capability may use it.
    pub fn put_connection(&self, args: &Value) -> Result<Value, VaultError> {
        let cid = match args.get("connectionId") {
            None | Some(Value::Null) => self.default_cid.clone(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => String::new(),
        };
        let authority = args.get("authority");
        let principal = authority.and_then(|a| a.get("principal"));
        let cid_v = Value::String(cid.clone());
        let fields: [(&str, Option<&Value>); 5] = [
            ("agentId", args.get("agentId")),
            ("provider", args.get("provider")),
            ("connectionId", Some(&cid_v)),
            ("accessToken", args.get("accessToken")),
            ("principal", principal),
        ];
        for (k, val) in fields {
            if !matches!(val, Some(Value::String(s)) if !s.is_empty()) {
                return Err(VaultError::plain(format!("putConnection: {k} must be a non-empty string")));
            }
        }
        let Some(expires_at) = finite(args.get("expiresAt")) else { return Err(VaultError::plain("putConnection: expiresAt must be a finite number")) };
        let refresh = match args.get("refreshToken") {
            None => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(_) => return Err(VaultError::plain("putConnection: refreshToken must be a non-empty string when given")),
        };
        let scopes = match args.get("scopes") {
            Some(Value::Array(a)) if a.iter().all(Value::is_string) => a.clone(),
            _ => return Err(VaultError::plain("putConnection: scopes must be a list of strings")),
        };
        let authority = authority.ok_or_else(|| VaultError::plain("putConnection: authority is required"))?;
        let auth_scopes = match authority.get("scopes") {
            None | Some(Value::Null) => scopes.clone(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return Err(VaultError::plain("putConnection: authority.scopes must be a list")),
        };
        let mut auth = Map::new();
        auth.insert("provider".into(), args["provider"].clone());
        auth.insert("principal".into(), authority["principal"].clone());
        auth.insert("scopes".into(), Value::Array(auth_scopes));
        if let Some(a) = authority.get("audience") {
            auth.insert("audience".into(), a.clone());
        }
        let mut conn = Map::new();
        conn.insert("agentId".into(), args["agentId"].clone());
        conn.insert("provider".into(), args["provider"].clone());
        conn.insert("connectionId".into(), json!(cid));
        conn.insert("accessToken".into(), args["accessToken"].clone());
        conn.insert("expiresAt".into(), jnum(expires_at));
        conn.insert("scopes".into(), Value::Array(scopes));
        conn.insert("authority".into(), Value::Object(auth));
        conn.insert("createdAt".into(), json!((self.now)()));
        conn.insert("useCount".into(), json!(0));
        if let Some(r) = refresh {
            conn.insert("refreshToken".into(), json!(r));
        }
        let conn = Value::Object(conn);
        self.store_set(&conn)?;
        Ok(conn)
    }

    /// A FRESH access token iff `pcactn` verifies against the connection's bound principal and the chain's grant covers the requested
    /// provider and scopes. `args` is `{provider, connectionId?, scopes?}`. Disabled unless the vault was built with
    /// `insecure_bearer_release` (prefer [`TokenVault::proxy_call`]).
    pub fn get_connection_token(&self, pcactn: &Value, args: &Value) -> Result<Value, VaultError> {
        if !self.bearer {
            return Err(bearer_release_disabled());
        }
        let (provider, cid, scopes) = call_args(args)?;
        let a = self.authorize(pcactn, &provider, cid.as_deref(), scopes.as_deref(), false, None)?;
        let (token, refreshed) = self.fresh_token(&a)?;
        let done = self.record_use(&a, &token)?;
        let done_scopes = strs(done.get("scopes"));
        self.issue_receipt(pcactn, &a, "bearer", None, None, "released", &done_scopes)?;
        let exp = finite(pcactn.get("exp"));
        let done_exp = done["expiresAt"].as_f64().unwrap_or(f64::NAN);
        let expires_at = match (&a.action, exp) {
            (Some(_), Some(e)) => jnum(done_exp.min(e)),
            _ => done["expiresAt"].clone(),
        };
        Ok(json!({
            "provider": a.provider,
            "connectionId": a.connection_id,
            "accessToken": done["accessToken"],
            "scopes": done_scopes,
            "expiresAt": expires_at,
            "refreshed": refreshed,
        }))
    }

    /// Proxy mode: the vault makes the outbound call itself (the agent never holds the credential). The request must re-derive
    /// exactly the params the PCActn signed; the action is spent first; redirects are not followed; a receipt links release to effect.
    /// `request` is `{method, url, headers?, body?}`; returns `{response: {status, headers, body}, receipt?}`.
    pub fn proxy_call(&self, pcactn: &Value, request: &Value, args: &Value) -> Result<Value, VaultError> {
        if self.actions.is_none() {
            return Err(VaultError::plain("proxyCall requires the vault to be constructed with `actions`"));
        }
        let Some(proxy_fetch) = &self.proxy_fetch else { return Err(VaultError::plain("proxyCall requires the vault to be constructed with `proxyFetch`")) };
        let send_headers = check_proxy_headers(request.get("headers"), &self.proxy_headers)?;
        let (provider, cid, scopes) = call_args(args)?;
        let a = self.authorize(pcactn, &provider, cid.as_deref(), scopes.as_deref(), true, Some(request))?;
        let (token, _refreshed) = self.fresh_token(&a)?;
        let done = self.record_use(&a, &token)?;
        let done_scopes = strs(done.get("scopes"));
        let tok = done["accessToken"].as_str().unwrap_or("").to_string();
        let mut headers = send_headers.clone();
        headers.insert("authorization".into(), json!(format!("Bearer {tok}")));
        let method = request["method"].as_str().ok_or_else(|| VaultError::plain("request.method must be a string"))?;
        let url = request["url"].as_str().ok_or_else(|| VaultError::plain("request.url must be a string"))?;
        let body = request.get("body");
        let req_digest = outbound_request_digest(method, url, &Value::Object(send_headers), body.and_then(Value::as_str))?;
        let mut call = Map::new();
        call.insert("method".into(), json!(method));
        call.insert("url".into(), json!(url));
        call.insert("headers".into(), Value::Object(headers));
        call.insert("redirect".into(), json!("manual"));
        if let Some(b) = body {
            call.insert("body".into(), b.clone());
        }
        let response = match proxy_fetch(&Value::Object(call)) {
            Ok(r) => r,
            Err(_) => {
                self.issue_receipt(pcactn, &a, "proxy", Some(&req_digest), None, "failed", &done_scopes)?;
                return Err(proxy_failed("the outbound call failed before a response"));
            }
        };
        let rbody = response.get("body").and_then(Value::as_str);
        let size = rbody.map_or(f64::INFINITY, |b| b.len() as f64);
        let status = response.get("status");
        let http_status = match status {
            Some(Value::Number(n)) => {
                n.as_i64().filter(|i| i.abs() <= MAX_SAFE).or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64).map(|f| f as i64))
            }
            _ => None,
        };
        let receipt = self.issue_receipt(pcactn, &a, "proxy", Some(&req_digest), http_status, "executed", &done_scopes)?;
        if !(size.is_finite() && size <= self.max_proxy) {
            return Err(proxy_failed("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)"));
        }
        let rb = rbody.unwrap_or("").replace(&tok, "[redacted]");
        let mut rh = Map::new();
        if let Some(h) = response.get("headers") {
            if !h.is_null() {
                for (k, v) in entries(h)? {
                    if k.to_lowercase() != "set-cookie" {
                        rh.insert(k, json!(js_value_string(&v).replace(&tok, "[redacted]")));
                    }
                }
            }
        }
        let mut resp = Map::new();
        if let Some(s) = status {
            resp.insert("status".into(), s.clone());
        }
        resp.insert("headers".into(), Value::Object(rh));
        resp.insert("body".into(), json!(rb));
        let mut out = Map::new();
        out.insert("response".into(), Value::Object(resp));
        if let Some(r) = receipt {
            out.insert("receipt".into(), r);
        }
        Ok(Value::Object(out))
    }

    /// Resolve, anchor and verify, revoke, bind, derive scopes, least-privilege, spend. Shared by both release modes.
    fn authorize(
        &self,
        pcactn: &Value,
        provider: &str,
        connection_id: Option<&str>,
        scopes: Option<&[String]>,
        need_action: bool,
        request: Option<&Value>,
    ) -> Result<Auth, VaultError> {
        let cid = connection_id.unwrap_or(self.default_cid.as_str()).to_string();
        let chain = match pcactn.get("cap_chain") {
            Some(Value::Array(c)) if !c.is_empty() => c,
            _ => return Err(not_authorized("PCActn has no capability chain")),
        };
        let (leaf, root) = (&chain[chain.len() - 1], &chain[0]);
        let holder = prop(leaf, "holder")?;
        let agent_id = s_or_undefined(holder);
        let mut key = Map::new();
        if let Some(h) = holder {
            key.insert("agentId".into(), h.clone());
        }
        key.insert("provider".into(), json!(provider));
        key.insert("connectionId".into(), json!(cid));
        let Some(connection) = self.store_get(&Value::Object(key))? else { return Err(unknown_connection(&agent_id, provider, &cid)) };
        let issuer = prop(root, "issuer")?;
        if issuer.is_none() || issuer != connection["authority"].get("principal") {
            return Err(not_authorized("capability chain is not rooted at the connection's bound principal"));
        }
        let now = (self.now)();
        let audience: Option<String> = connection["authority"].get("audience").and_then(Value::as_str).map(String::from).or_else(|| self.audience.clone());
        // no audience accepts any: the verifier has no opt-out, so it is given the action's own signed `aud`
        let aud = audience.unwrap_or_else(|| pcactn.get("aud").and_then(Value::as_str).unwrap_or("").to_string());
        let opts = VerifyOptions {
            authorized_plan_roots: self.plan_roots.as_deref(),
            insecure_skip_plan_root_check: self.skip_plan_root,
            pq_pins: self.pq_pins.as_ref(),
            ..VerifyOptions::default()
        };
        let v = verify_pcactn_core_with(pcactn, root, now, &aud, &opts);
        if !v.allow {
            let why = if v.reason.is_empty() { "rejected".to_string() } else { v.reason.clone() };
            return Err(not_authorized(format!("PCActn verification failed: {why}")));
        }
        if let Some(rev) = &self.is_revoked {
            match rev(pcactn) {
                Ok(false) => {}
                Ok(true) => return Err(not_authorized("the capability chain is revoked")),
                Err(_) => return Err(not_authorized("revocation source unavailable")),
            }
        }
        let act = &pcactn["action"];
        let verb_v = &act["verb"];
        let mut action: Option<ActionDef> = None;
        if let Some(actions) = &self.actions {
            let verb = js_value_string(verb_v);
            let found = actions(&verb);
            let Some(def) = found.filter(|d| verb_v.as_str() == Some(d.verb.as_str())) else { return Err(unknown_action(&verb)) };
            if !def.confirmed {
                return Err(unconfirmed_action(&verb));
            }
            if def.upstream["provider"].as_str() != Some(provider) {
                return Err(not_authorized(format!("the action '{verb}' is not for provider '{provider}'")));
            }
            if !def.upstream["scopes_min"].as_array().is_some_and(|a| !a.is_empty()) {
                return Err(not_authorized(format!("the action '{verb}' declares no upstream scopes (nothing to release)")));
            }
            action = Some(def);
        } else if need_action {
            return Err(unknown_action(&js_value_string(verb_v)));
        } else if self.require_binding {
            let expected = (self.resource_for)(provider, &cid);
            if act["resource"].as_str() != Some(expected.as_str()) {
                return Err(not_authorized(format!(
                    "PCActn action resource '{}' is not for this connection (expected '{expected}')",
                    js_value_string(&act["resource"])
                )));
            }
            let want = match &self.use_verb {
                UseVerb::Default => Some("use_connection"),
                UseVerb::Skip => None,
                UseVerb::Verb(v) => Some(v.as_str()),
            };
            if let Some(w) = want {
                if verb_v.as_str() != Some(w) {
                    return Err(not_authorized(format!("PCActn action verb '{}' is not a connection-use verb (expected '{w}')", js_value_string(verb_v))));
                }
            }
        }
        let Some(granted) = granted_oauth_scopes(&Value::Array(chain.clone()), provider)? else {
            return Err(not_authorized(format!("capability grants no authority for provider '{provider}'")));
        };
        let conn_scopes = strs(connection.get("scopes"));
        let auth_scopes = strs(connection["authority"].get("scopes"));
        let requested: Vec<String>;
        if let Some(def) = &action {
            let min = strs(def.upstream.get("scopes_min"));
            requested = scopes.map_or_else(|| min.clone(), |s| s.to_vec());
            let beyond: Vec<String> = requested.iter().filter(|s| !min.contains(s)).cloned().collect();
            if !beyond.is_empty() {
                return Err(scope_exceeded(provider, &beyond));
            }
            let unheld: Vec<String> = min.iter().filter(|s| !conn_scopes.contains(s) || !auth_scopes.contains(s)).cloned().collect();
            if !unheld.is_empty() {
                return Err(scope_exceeded(provider, &unheld));
            }
            if !need_action {
                let extra: Vec<String> = conn_scopes.iter().filter(|s| !min.contains(s)).cloned().collect();
                if !extra.is_empty() {
                    return Err(scope_exceeded(provider, &extra));
                }
            }
            let ungranted: Vec<String> = min.iter().filter(|s| !granted.contains(s)).cloned().collect();
            if !ungranted.is_empty() {
                return Err(scope_exceeded(provider, &ungranted));
            }
        } else {
            requested = scopes.map_or_else(|| auth_scopes.clone(), |s| s.to_vec());
        }
        let missing: Vec<String> = requested.iter().filter(|s| !granted.contains(s)).cloned().collect();
        if !missing.is_empty() {
            return Err(scope_exceeded(provider, &missing));
        }
        if need_action {
            if let Some(def) = &action {
                let (Some(req), Some(extract)) = (request, def.extract.as_ref()) else {
                    return Err(request_mismatch("the action has no request extractor: proxy mode cannot bind the outbound request"));
                };
                let params = match extract(req) {
                    Ok(p) => p,
                    Err(e) if e.code == "request_mismatch" => return Err(e),
                    Err(_) => return Err(request_mismatch("the outbound request could not be mapped to the action parameters")),
                };
                let d = hash_canonical_strict(&params).ok_or_else(|| request_mismatch("the outbound request parameters are not canonical"))?;
                if act["params_digest"].as_str() != Some(d.as_str()) {
                    return Err(request_mismatch("the outbound request does not carry the parameters the PCActn signed"));
                }
            }
        }
        if let Some(replay) = &self.replay {
            if let Err(reason) = guard_pcactn_replay(replay.as_ref(), pcactn, now) {
                return Err(not_authorized(format!("replay guard refused the action: {reason}")));
            }
        }
        Ok(Auth { provider: provider.to_string(), connection_id: cid, connection, requested, now, action })
    }

    /// Refresh a stale token, else use it as is. A token whose expiry or clock is not finite can never be shown fresh.
    fn fresh_token(&self, a: &Auth) -> Result<(Value, bool), VaultError> {
        let conn = &a.connection;
        let stale = match conn["expiresAt"].as_f64().filter(|f| f.is_finite()) {
            Some(e) => !(self.leeway.is_finite() && e - a.now as f64 > self.leeway),
            None => true,
        };
        if !stale {
            return Ok((conn.clone(), false));
        }
        let Some(rt) = conn.get("refreshToken").and_then(Value::as_str) else { return Err(expired_no_refresh(&a.provider, &a.connection_id)) };
        let updated = refresh_connection(conn, self.providers.get(&a.provider), rt, &a.requested, self.fetch.as_ref(), a.now as f64, self.default_lifetime)?;
        let mut token = conn.as_object().cloned().unwrap_or_default();
        if let Value::Object(u) = updated {
            for (k, v) in u {
                token.insert(k, v);
            }
        }
        Ok((Value::Object(token), true))
    }

    /// Record usage and persist.
    fn record_use(&self, a: &Auth, token: &Value) -> Result<Value, VaultError> {
        let mut t = token.as_object().cloned().unwrap_or_default();
        t.insert("lastUsedAt".into(), json!(a.now));
        t.insert("useCount".into(), jnum(token["useCount"].as_f64().unwrap_or(0.0) + 1.0));
        let t = Value::Object(t);
        self.store_set(&t)?;
        Ok(t)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_receipt(
        &self,
        pcactn: &Value,
        a: &Auth,
        mode: &str,
        request_digest: Option<&str>,
        http_status: Option<i64>,
        outcome: &str,
        scopes: &[String],
    ) -> Result<Option<Value>, VaultError> {
        let Some(cfg) = &self.receipts else { return Ok(None) };
        let mut sorted = scopes.to_vec();
        u16_sort(&mut sorted);
        let body = json!({
            "v": 1,
            "kind": "pca-release-receipt",
            "action_digest": receipt_action_digest(pcactn)?,
            "provider": a.provider,
            "connection_id": a.connection_id,
            "mode": mode,
            "scopes_released": sorted,
            "request_digest": request_digest,
            "http_status": http_status,
            "outcome": outcome,
            "ts": a.now,
        });
        let receipt = sign_release_receipt(&body, &cfg.secret_key)?;
        if let Some(sink) = &cfg.sink {
            let _ = sink(&receipt); // a failing sink must not turn a made call into an error the caller retries
        }
        Ok(Some(receipt))
    }

    /// Remove a stored connection.
    pub fn delete_connection(&self, agent_id: &str, provider: &str, connection_id: Option<&str>) -> Result<(), VaultError> {
        let key = json!({ "agentId": agent_id, "provider": provider, "connectionId": connection_id.unwrap_or(self.default_cid.as_str()) });
        self.store.delete(&key).map_err(|e| if e.code.is_empty() { store_error("the connection store failed") } else { e })
    }

    // The store's own error text is never passed on: it can quote a connection string or a record.
    fn store_get(&self, key: &Value) -> Result<Option<Value>, VaultError> {
        self.store.get(key).map_err(|e| if e.code.is_empty() { store_error("the connection store failed") } else { e })
    }

    fn store_set(&self, c: &Value) -> Result<(), VaultError> {
        self.store.set(c).map_err(|e| if e.code.is_empty() { store_error("the connection store failed") } else { e })
    }
}

/// `{provider, connectionId?, scopes?}`.
fn call_args(args: &Value) -> Result<(String, Option<String>, Option<Vec<String>>), VaultError> {
    let provider = args.get("provider").and_then(Value::as_str).ok_or_else(|| VaultError::plain("provider must be a string"))?.to_string();
    let cid = args.get("connectionId").and_then(Value::as_str).map(String::from);
    let scopes = match args.get("scopes") {
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => Some(strs(args.get("scopes"))),
        None | Some(Value::Null) => None,
        Some(_) => return Err(VaultError::plain("scopes must be a list of strings")),
    };
    Ok((provider, cid, scopes))
}
