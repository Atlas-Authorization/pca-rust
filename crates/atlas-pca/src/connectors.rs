//! A declarative catalog of outbound OAuth connectors for the token vault: manifest validation and digests, the provider registry,
//! the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and refresh into the vault,
//! and the manifest-to-vault-provider mapping. A port of the TypeScript reference (@atlasauth/pca-connectors); the seeded provider
//! manifests are in [`crate::connectors_providers`]. JSON-valued: manifests and option bags are `serde_json::Value`s with the
//! reference's member names; transports are the closures of [`crate::connect`] and the vault is a [`crate::connect::TokenVault`].
//!
//! shortcut: a string cut inside a surrogate pair yields U+FFFD (a Rust string cannot hold a lone surrogate); the process-wide default
//! registry is a `RwLock` (the reference's module singleton).
use crate::connect::{encode_uri_component, jnum, js_ws, redact, strs, FetchFn, TokenVault, VaultError};
use crate::connectors_providers::builtin_manifests;
use crate::intent_v2::js_value_string;
use crate::{b64_encode, hash_canonical};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

pub const RESERVED_AUTHORIZE_PARAMS: [&str; 7] = ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"];
pub const RESERVED_TOKEN_PARAMS: [&str; 7] = ["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token"];
const ID_SOURCE: &str = "^[a-z0-9][a-z0-9._-]*$";
const FORBIDDEN_HEADERS: [&str; 7] = ["host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie"];
const MIN_STATE_CHARS: usize = 16;
const DEFAULT_TOKEN_LIFETIME_MS: f64 = 3_600_000.0;

// ---- errors (manifest.ts) --------------------------------------------------------------------------------------------------

/// `ConnectorError`, `ManifestValidationError` (with `issues`), `UnknownProviderError`, or a bare host error (name "Error": the
/// reference's TypeError / a vault error).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorError {
    pub name: &'static str,
    pub message: String,
    pub issues: Vec<String>,
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ConnectorError {}

impl From<VaultError> for ConnectorError {
    fn from(e: VaultError) -> Self {
        ConnectorError::plain(e.message)
    }
}

impl ConnectorError {
    pub fn new(message: impl Into<String>) -> ConnectorError {
        ConnectorError { name: "ConnectorError", message: message.into(), issues: vec![] }
    }
    pub fn manifest_validation(issues: Vec<String>) -> ConnectorError {
        ConnectorError { name: "ManifestValidationError", message: format!("invalid provider manifest: {}", issues.join("; ")), issues }
    }
    pub fn unknown_provider(id: &str) -> ConnectorError {
        ConnectorError { name: "UnknownProviderError", message: format!("no connector registered for provider '{id}'"), issues: vec![] }
    }
    pub fn plain(message: impl Into<String>) -> ConnectorError {
        ConnectorError { name: "Error", message: message.into(), issues: vec![] }
    }
    /// The error as the oracle records it: `{ok:false, name, message, issues?}`; a non-connector failure is `{ok:false, name:"Error"}`.
    pub fn to_json(&self) -> Value {
        if self.name == "Error" {
            return json!({ "ok": false, "name": "Error" });
        }
        let mut m = Map::new();
        m.insert("ok".into(), json!(false));
        m.insert("name".into(), json!(self.name));
        m.insert("message".into(), json!(self.message));
        if !self.issues.is_empty() {
            m.insert("issues".into(), json!(self.issues));
        }
        Value::Object(m)
    }
}

fn cerr<T>(m: impl Into<String>) -> Result<T, ConnectorError> {
    Err(ConnectorError::new(m))
}

// ---- regexes ------------------------------------------------------------------------------------------------------------------

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}
fn var_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"\{([A-Za-z0-9_]+)\}")
}
fn id_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z0-9][a-z0-9._-]*$")
}
fn header_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9][A-Za-z0-9-]*$")
}
fn query_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z_][A-Za-z0-9_.-]*$")
}
fn label_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
}
fn pkce_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9._~-]{43,128}$")
}
fn host_var_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^\{[A-Za-z0-9_]+\}(:[0-9]+)?$")
}

// ---- manifest validation (manifest.ts) ----------------------------------------------------------------------------------------

fn non_empty(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}
fn str_array(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Array(a)) if a.iter().all(Value::is_string))
}
fn str_record(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(m)) if m.values().all(Value::is_string))
}
fn has_ws_or_comma(s: &str) -> bool {
    s.chars().any(|c| js_ws(c) || c == ',')
}

fn is_https_url(v: Option<&Value>) -> bool {
    let Some(Value::String(s)) = v else { return false };
    if !s.starts_with("https://") {
        return false;
    }
    let probe = var_re().replace_all(s, "x").to_string();
    let Ok(u) = url::Url::parse(&probe) else { return false };
    if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some_and(|p| !p.is_empty()) || u.fragment().is_some_and(|f| !f.is_empty()) {
        return false;
    }
    let raw_host = s["https://".len()..].split(['/', '?', '#']).next().unwrap_or("");
    !host_var_re().is_match(raw_host)
}

fn url_vars(u: &str) -> Vec<String> {
    var_re().captures_iter(u).map(|c| c[1].to_string()).collect()
}

fn dedupe(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for s in v {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn one_of(items: &[&str]) -> String {
    items.join(" | ")
}

/// `{ok: true, manifest}` or `{ok: false, issues}`: every problem of a provider manifest, no partial acceptance.
pub fn validate_manifest(inp: &Value) -> Value {
    let Value::Object(m) = inp else { return json!({ "ok": false, "issues": ["manifest must be an object"] }) };
    let g = |k: &str| m.get(k);
    let mut issues: Vec<String> = vec![];
    match g("id") {
        Some(Value::String(id)) if !id.is_empty() => {
            if !id_re().is_match(id) {
                issues.push(format!("id '{id}' must be lowercase and match {ID_SOURCE}"));
            }
        }
        _ => issues.push("id must be a non-empty string".into()),
    }
    if !non_empty(g("displayName")) {
        issues.push("displayName must be a non-empty string".into());
    }
    let authorize_url = g("authorizeUrl");
    if !is_https_url(authorize_url) {
        issues.push("authorizeUrl must be an https:// URL".into());
    }
    let token_url = g("tokenUrl");
    if !is_https_url(token_url) {
        issues.push("tokenUrl must be an https:// URL".into());
    }
    let scopes_available = g("scopesAvailable");
    if !str_array(scopes_available) {
        issues.push("scopesAvailable must be an array of strings".into());
    }
    let default_scopes = g("defaultScopes");
    if !str_array(default_scopes) {
        issues.push("defaultScopes must be an array of strings".into());
    }
    for (name, lst) in [("scopesAvailable", scopes_available), ("defaultScopes", default_scopes)] {
        if str_array(lst) {
            let l = strs(lst);
            if l.iter().any(|s| s.is_empty() || has_ws_or_comma(s)) {
                issues.push(format!(
                    "{name} entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)"
                ));
            }
            if dedupe(l.clone()).len() != l.len() {
                issues.push(format!("{name} must not contain duplicates"));
            }
        }
    }
    if str_array(scopes_available) && str_array(default_scopes) {
        let avail = strs(scopes_available);
        if !avail.is_empty() {
            let missing: Vec<String> = strs(default_scopes).into_iter().filter(|s| !avail.contains(s)).collect();
            if !missing.is_empty() {
                issues.push(format!("defaultScopes must be a subset of scopesAvailable (unknown: {})", missing.join(", ")));
            }
        }
    }
    let refresh = g("refresh");
    match refresh {
        Some(Value::Object(r)) => {
            if !matches!(r.get("mode"), Some(Value::String(s)) if s == "refresh_token" || s == "none") {
                issues.push(format!("refresh.mode must be one of {}", one_of(&["refresh_token", "none"])));
            }
            if let Some(te) = r.get("tokenEndpoint") {
                if !is_https_url(Some(te)) {
                    issues.push("refresh.tokenEndpoint, when present, must be an https:// URL".into());
                }
            }
            if let Some(sn) = r.get("supportsScopeNarrowing") {
                if !sn.is_boolean() {
                    issues.push("refresh.supportsScopeNarrowing must be a boolean".into());
                }
            }
            match r.get("extraParams") {
                Some(ep) if !str_record(Some(ep)) => issues.push("refresh.extraParams must be a string→string map".into()),
                Some(Value::Object(ep)) => {
                    for k in ep.keys() {
                        if RESERVED_TOKEN_PARAMS.contains(&k.as_str()) {
                            issues.push(format!("refresh.extraParams may not set '{k}': the request builder owns it"));
                        }
                    }
                }
                _ => {}
            }
        }
        _ => issues.push("refresh must be an object".into()),
    }
    let placement = g("tokenPlacement");
    match placement {
        Some(Value::String(p)) if p == "bearer" || p == "header" || p == "query" => {
            if p == "header" && !non_empty(g("headerName")) {
                issues.push("tokenPlacement 'header' requires a non-empty headerName".into());
            } else if p == "query" && !non_empty(g("queryParam")) {
                issues.push("tokenPlacement 'query' requires a non-empty queryParam".into());
            }
        }
        _ => issues.push(format!("tokenPlacement must be one of {}", one_of(&["bearer", "header", "query"]))),
    }
    if let Some(Value::String(h)) = g("headerName") {
        if !header_re().is_match(h) || FORBIDDEN_HEADERS.contains(&h.to_lowercase().as_str()) {
            issues.push(format!("headerName '{h}' must be an HTTP token and not a protocol header"));
        }
    }
    if let Some(Value::String(q)) = g("queryParam") {
        if !query_re().is_match(q) {
            issues.push(format!("queryParam '{q}' must be a plain parameter name"));
        }
    }
    if matches!(g("scopeSeparator"), Some(Value::String(s)) if s.is_empty()) {
        issues.push("scopeSeparator must not be empty".into());
    }
    if let Some(p) = g("pkce") {
        if !p.is_boolean() {
            issues.push("pkce must be a boolean".into());
        }
    }
    if let Some(s) = g("scopeSeparator") {
        if !s.is_string() {
            issues.push("scopeSeparator must be a string".into());
        }
    }
    match g("authParams") {
        Some(ap) if !str_record(Some(ap)) => issues.push("authParams must be a string→string map".into()),
        Some(Value::Object(ap)) => {
            for k in ap.keys() {
                if RESERVED_AUTHORIZE_PARAMS.contains(&k.as_str()) {
                    issues.push(format!("authParams may not set '{k}': the request builder owns it"));
                }
            }
        }
        _ => {}
    }
    if let Some(ca) = g("clientAuth") {
        if !matches!(ca, Value::String(s) if s == "post" || s == "basic") {
            issues.push(format!("clientAuth must be one of {}", one_of(&["post", "basic"])));
        }
    }
    let required_vars = g("requiredVars");
    if let Some(rv) = required_vars {
        if !str_array(Some(rv)) {
            issues.push("requiredVars must be an array of strings".into());
        }
    }
    if is_https_url(authorize_url) && is_https_url(token_url) {
        let declared = dedupe(if str_array(required_vars) { strs(required_vars) } else { vec![] });
        let mut all = url_vars(authorize_url.and_then(Value::as_str).unwrap_or(""));
        all.extend(url_vars(token_url.and_then(Value::as_str).unwrap_or("")));
        let used = dedupe(all);
        for v in &used {
            if !declared.contains(v) {
                issues.push(format!("url uses '{{{v}}}' but requiredVars does not declare it"));
            }
        }
        for v in &declared {
            if !used.contains(v) {
                issues.push(format!("requiredVars declares '{v}' but no URL uses '{{{v}}}'"));
            }
        }
    }
    if let Some(d) = g("docsUrl") {
        if !d.is_string() {
            issues.push("docsUrl must be a string".into());
        }
    }
    if !issues.is_empty() {
        return json!({ "ok": false, "issues": issues });
    }
    json!({ "ok": true, "manifest": freeze_manifest(m) })
}

fn freeze_manifest(inp: &Map<String, Value>) -> Value {
    let mut refresh = Map::new();
    let rr = inp.get("refresh").and_then(Value::as_object);
    let rget = |k: &str| rr.and_then(|r| r.get(k));
    refresh.insert("mode".into(), json!(if rget("mode").and_then(Value::as_str) == Some("none") { "none" } else { "refresh_token" }));
    if let Some(Value::String(te)) = rget("tokenEndpoint") {
        refresh.insert("tokenEndpoint".into(), json!(te));
    }
    if let Some(Value::Bool(sn)) = rget("supportsScopeNarrowing") {
        refresh.insert("supportsScopeNarrowing".into(), json!(sn));
    }
    if str_record(rget("extraParams")) {
        refresh.insert("extraParams".into(), rget("extraParams").cloned().unwrap_or(Value::Null));
    }
    let s_or = |k: &str| inp.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let mut m = Map::new();
    m.insert("id".into(), json!(s_or("id")));
    m.insert("displayName".into(), json!(s_or("displayName")));
    m.insert("authorizeUrl".into(), json!(s_or("authorizeUrl")));
    m.insert("tokenUrl".into(), json!(s_or("tokenUrl")));
    m.insert("scopesAvailable".into(), json!(if str_array(inp.get("scopesAvailable")) { strs(inp.get("scopesAvailable")) } else { vec![] }));
    m.insert("defaultScopes".into(), json!(if str_array(inp.get("defaultScopes")) { strs(inp.get("defaultScopes")) } else { vec![] }));
    m.insert("refresh".into(), Value::Object(refresh));
    let tp = match inp.get("tokenPlacement").and_then(Value::as_str) {
        Some("header") => "header",
        Some("query") => "query",
        _ => "bearer",
    };
    m.insert("tokenPlacement".into(), json!(tp));
    if let Some(Value::Bool(p)) = inp.get("pkce") {
        m.insert("pkce".into(), json!(p));
    }
    if let Some(Value::String(s)) = inp.get("scopeSeparator") {
        m.insert("scopeSeparator".into(), json!(s));
    }
    if str_record(inp.get("authParams")) {
        m.insert("authParams".into(), inp.get("authParams").cloned().unwrap_or(Value::Null));
    }
    if let Some(Value::String(c)) = inp.get("clientAuth") {
        if c == "post" || c == "basic" {
            m.insert("clientAuth".into(), json!(c));
        }
    }
    for k in ["headerName", "queryParam"] {
        if let Some(Value::String(s)) = inp.get(k) {
            m.insert(k.into(), json!(s));
        }
    }
    if str_array(inp.get("requiredVars")) {
        m.insert("requiredVars".into(), json!(strs(inp.get("requiredVars"))));
    }
    if let Some(Value::String(s)) = inp.get("docsUrl") {
        m.insert("docsUrl".into(), json!(s));
    }
    Value::Object(m)
}

/// The validated manifest, or a [`ConnectorError`] (`ManifestValidationError`) carrying every issue.
pub fn assert_manifest(inp: &Value) -> Result<Value, ConnectorError> {
    let r = validate_manifest(inp);
    if r["ok"] == json!(true) {
        return Ok(r["manifest"].clone());
    }
    Err(ConnectorError::manifest_validation(strs(r.get("issues"))))
}

/// The content address of a validated manifest: a pinned digest detects a swapped endpoint.
pub fn manifest_digest(manifest: &Value) -> String {
    hash_canonical(manifest)
}

// ---- registry (registry.ts) ---------------------------------------------------------------------------------------------------

/// Validated manifests by provider id.
#[derive(Debug, Default, Clone)]
pub struct ProviderRegistry {
    by_id: BTreeMap<String, Value>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate and register a manifest; `opts.expectedDigest` pins it, a duplicate id needs `opts.replace == true`.
    pub fn register(&mut self, manifest: &Value, opts: Option<&Value>) -> Result<Value, ConnectorError> {
        let valid = assert_manifest(manifest)?;
        let id = valid["id"].as_str().unwrap_or("").to_string();
        if let Some(d) = opts.and_then(|o| o.get("expectedDigest")).filter(|d| !d.is_null()) {
            if d.as_str() != Some(manifest_digest(&valid).as_str()) {
                return cerr(format!("manifest '{id}' does not match the pinned digest"));
            }
        }
        if self.by_id.contains_key(&id) && opts.and_then(|o| o.get("replace")) != Some(&Value::Bool(true)) {
            return cerr(format!("provider '{id}' is already registered; pass {{ replace: true }} to replace it deliberately"));
        }
        self.by_id.insert(id, valid.clone());
        Ok(valid)
    }

    pub fn get(&self, id: &str) -> Option<Value> {
        self.by_id.get(id).cloned()
    }

    pub fn require(&self, id: &str) -> Result<Value, ConnectorError> {
        self.get(id).ok_or_else(|| ConnectorError::unknown_provider(id))
    }

    pub fn has(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// Every manifest, sorted by id (ids are ASCII, so byte order is the reference's UTF-16 order).
    pub fn list(&self) -> Vec<Value> {
        self.by_id.values().cloned().collect()
    }

    pub fn ids(&self) -> Vec<String> {
        self.by_id.keys().cloned().collect()
    }

    /// One digest over the whole catalog (id and manifest digest, in id order).
    pub fn catalog_digest(&self) -> String {
        let pairs: Vec<Value> = self.by_id.iter().map(|(id, m)| json!([id, manifest_digest(m)])).collect();
        hash_canonical(&Value::Array(pairs))
    }
}

/// A registry seeded with the built-in catalog.
pub fn create_default_registry() -> ProviderRegistry {
    let mut r = ProviderRegistry::new();
    for m in builtin_manifests() {
        let _ = r.register(&m, None);
    }
    r
}

/// The process-wide default registry (the reference's `defaultRegistry`).
pub fn default_registry() -> &'static RwLock<ProviderRegistry> {
    static R: OnceLock<RwLock<ProviderRegistry>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(create_default_registry()))
}

fn with_registry<T>(registry: Option<&ProviderRegistry>, f: impl FnOnce(&ProviderRegistry) -> T) -> T {
    match registry {
        Some(r) => f(r),
        None => f(&default_registry().read().unwrap_or_else(|p| p.into_inner())),
    }
}

pub fn register_provider(manifest: &Value, opts: Option<&Value>) -> Result<Value, ConnectorError> {
    default_registry().write().unwrap_or_else(|p| p.into_inner()).register(manifest, opts)
}

pub fn get_provider(id: &str) -> Option<Value> {
    with_registry(None, |r| r.get(id))
}

pub fn list_providers() -> Vec<Value> {
    with_registry(None, |r| r.list())
}

pub fn catalog_digest(registry: Option<&ProviderRegistry>) -> String {
    with_registry(registry, |r| r.catalog_digest())
}

fn require_provider(registry: Option<&ProviderRegistry>, id: &Value) -> Result<Value, ConnectorError> {
    let id = id.as_str().map_or_else(|| js_value_string(id), String::from);
    with_registry(registry, |r| r.require(&id))
}

// ---- authorize URL, PKCE, URL variables and token placement (authorize.ts) --------------------------------------------------------

fn random_token() -> Result<String, ConnectorError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| ConnectorError::plain(e.to_string()))?;
    Ok(b64_encode(&b))
}

/// The PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain".
pub fn pkce_challenge(verifier: &str, method: &str) -> String {
    if method == "plain" {
        verifier.to_string()
    } else {
        b64_encode(&Sha256::digest(verifier.as_bytes()))
    }
}

/// Fill `{name}` placeholders from `vars` (`None` = undefined); each value must be a single DNS label so a value can never change
/// the host. A null `vars` is the reference's TypeError.
pub fn substitute_vars(url: &str, vars: Option<&Value>) -> Result<String, ConnectorError> {
    let mut out = String::new();
    let mut last = 0;
    for c in var_re().captures_iter(url) {
        let w = c.get(0).ok_or_else(|| ConnectorError::plain("regex"))?;
        out.push_str(&url[last..w.start()]);
        last = w.end();
        let name = &c[1];
        let v = match vars {
            Some(Value::Null) => return Err(ConnectorError::plain("Cannot convert undefined or null to object")),
            Some(Value::Object(m)) => m.get(name),
            _ => None,
        };
        let Some(v) = v else { return cerr(format!("missing URL variable '{{{name}}}'")) };
        match v {
            Value::String(s) if label_re().is_match(s) => out.push_str(s),
            _ => return cerr(format!("URL variable '{{{name}}}' must be a single DNS label (letters, digits and hyphens)")),
        }
    }
    out.push_str(&url[last..]);
    Ok(out)
}

fn encode_form(params: &[(String, String)]) -> String {
    params.iter().map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(v))).collect::<Vec<_>>().join("&")
}

fn check_redirect_uri(uri: Option<&Value>) -> Result<(), ConnectorError> {
    let text = uri.map_or("undefined".to_string(), js_value_string);
    let Ok(u) = url::Url::parse(&text) else { return cerr("buildAuthorizeUrl: redirectUri must be an absolute URL") };
    if u.fragment().is_some_and(|f| !f.is_empty()) {
        return cerr("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)");
    }
    if !u.username().is_empty() || u.password().is_some_and(|p| !p.is_empty()) {
        return cerr("buildAuthorizeUrl: redirectUri must not carry credentials");
    }
    let host = u.host_str().unwrap_or("");
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if u.scheme() != "https" && !(u.scheme() == "http" && local) {
        return cerr("buildAuthorizeUrl: redirectUri must be https (http only for localhost)");
    }
    Ok(())
}

fn check_scopes(manifest: &Value, scopes: &Value, allow_unlisted: bool) -> Result<(), ConnectorError> {
    let Value::Array(list) = scopes else { return cerr("buildAuthorizeUrl: scopes must be a list") };
    let sep = manifest.get("scopeSeparator").and_then(Value::as_str).unwrap_or(" ");
    let available = strs(manifest.get("scopesAvailable"));
    let mut seen: Vec<&str> = vec![];
    for s in list {
        let ok = matches!(s, Value::String(t) if !t.is_empty() && !has_ws_or_comma(t) && !t.contains(sep));
        let Some(s) = s.as_str().filter(|_| ok) else {
            return cerr("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator");
        };
        if seen.contains(&s) {
            return cerr(format!("buildAuthorizeUrl: scope '{s}' is listed twice"));
        }
        seen.push(s);
        if !allow_unlisted && !available.is_empty() && !available.iter().any(|a| a == s) {
            return cerr(format!("buildAuthorizeUrl: scope '{s}' is not offered by provider '{}'", manifest["id"].as_str().unwrap_or("")));
        }
    }
    Ok(())
}

/// The authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider: `{url, state, pkce?}`. `options` carries clientId,
/// redirectUri, scopes, state, pkce (`false`, `true` or `{verifier, method}`), vars, extraParams, allowUnlistedScopes and
/// allowPlainPkce; `registry` defaults to the process-wide one. A random state / PKCE verifier is generated when none is given.
pub fn build_authorize_url(provider_id: &str, options: &Value, registry: Option<&ProviderRegistry>) -> Result<Value, ConnectorError> {
    let manifest = with_registry(registry, |r| r.require(provider_id))?;
    let scopes: Value = match options.get("scopes") {
        None | Some(Value::Null) => manifest["defaultScopes"].clone(),
        Some(s) => s.clone(),
    };
    let separator = manifest.get("scopeSeparator").and_then(Value::as_str).unwrap_or(" ").to_string();
    let state_v: Value = match options.get("state") {
        None | Some(Value::Null) => Value::String(random_token()?),
        Some(s) => s.clone(),
    };
    let client_id = match options.get("clientId") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return cerr("buildAuthorizeUrl: clientId must be a non-empty string"),
    };
    let redirect = options.get("redirectUri");
    check_redirect_uri(redirect)?;
    let state = match &state_v {
        Value::String(s) if s.encode_utf16().count() >= MIN_STATE_CHARS => s.clone(),
        _ => return cerr(format!("buildAuthorizeUrl: state must be at least {MIN_STATE_CHARS} characters (omit it to get a random one)")),
    };
    check_scopes(&manifest, &scopes, options.get("allowUnlistedScopes") == Some(&Value::Bool(true)))?;
    // Object.entries: an object's members, an array's elements by index, a string's characters by index (a number or boolean has none)
    let extra: Vec<(String, Value)> = match options.get("extraParams") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
        Some(Value::String(t)) => t.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => Vec::new(),
    };
    for (k, _) in &extra {
        if RESERVED_AUTHORIZE_PARAMS.contains(&k.as_str()) {
            return cerr(format!("buildAuthorizeUrl: extraParams may not set '{k}'"));
        }
    }
    let scope_list = strs(Some(&scopes));
    let mut params: Vec<(String, String)> = vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), client_id),
        ("redirect_uri".into(), redirect.map_or("undefined".to_string(), js_value_string)),
    ];
    if !scope_list.is_empty() {
        params.push(("scope".into(), scope_list.join(&separator)));
    }
    params.push(("state".into(), state.clone()));
    let pk = options.get("pkce");
    let want = match pk {
        Some(Value::Bool(false)) => false,
        Some(_) => true,
        None => manifest.get("pkce") == Some(&Value::Bool(true)),
    };
    let mut pkce_out: Option<Value> = None;
    if want {
        let (verifier, method): (String, Value) = match pk {
            Some(Value::Object(o)) => {
                let v = o.get("verifier").map_or("undefined".to_string(), js_value_string);
                let m = match o.get("method") {
                    None | Some(Value::Null) => json!("S256"),
                    Some(m) => m.clone(),
                };
                (v, m)
            }
            Some(Value::Null) => return Err(ConnectorError::plain("Cannot read properties of null (reading 'verifier')")),
            _ => (random_token()?, json!("S256")),
        };
        if !pkce_re().is_match(&verifier) {
            return cerr("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)");
        }
        let method_s = match method.as_str() {
            Some("S256") => "S256",
            Some("plain") if options.get("allowPlainPkce") == Some(&Value::Bool(true)) => "plain",
            _ => return cerr("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')"),
        };
        let challenge = pkce_challenge(&verifier, method_s);
        params.push(("code_challenge".into(), challenge.clone()));
        params.push(("code_challenge_method".into(), method_s.into()));
        pkce_out = Some(json!({ "verifier": verifier, "challenge": challenge, "method": method_s }));
    }
    if let Some(Value::Object(ap)) = manifest.get("authParams") {
        for (k, v) in ap {
            params.push((k.clone(), js_value_string(v)));
        }
    }
    for (k, v) in &extra {
        params.push((k.clone(), js_value_string(v)));
    }
    let base = substitute_vars(manifest["authorizeUrl"].as_str().unwrap_or(""), options.get("vars"))?;
    let mut out = Map::new();
    out.insert("url".into(), json!(format!("{base}{}{}", if base.contains('?') { "&" } else { "?" }, encode_form(&params))));
    out.insert("state".into(), json!(state));
    if let Some(p) = pkce_out {
        out.insert("pkce".into(), p);
    }
    Ok(Value::Object(out))
}

/// How to present an access token: `{kind: "header" | "query", name, value}`. The token must be printable ASCII without spaces. The
/// manifest is used as is (an unknown placement yields `null`).
pub fn apply_access_token(manifest: &Value, access_token: &Value) -> Result<Value, ConnectorError> {
    let tok = match access_token {
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b)) => s.as_str(),
        _ => return cerr("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces"),
    };
    let id = manifest.get("id").map_or("undefined".to_string(), js_value_string);
    Ok(match manifest.get("tokenPlacement").and_then(Value::as_str) {
        Some("bearer") => json!({ "kind": "header", "name": "Authorization", "value": format!("Bearer {tok}") }),
        Some("header") => match manifest.get("headerName") {
            Some(n) => json!({ "kind": "header", "name": n, "value": tok }),
            None => return cerr(format!("manifest '{id}' is header-placed but has no headerName")),
        },
        Some("query") => match manifest.get("queryParam") {
            Some(n) => json!({ "kind": "query", "name": n, "value": tok }),
            None => return cerr(format!("manifest '{id}' is query-placed but has no queryParam")),
        },
        _ => Value::Null,
    })
}

// ---- code exchange, refresh and the vault bridge (exchange.ts) -------------------------------------------------------------------------

struct Parsed {
    access_token: String,
    expires_in_secs: Option<f64>,
    refresh_token: Option<String>,
    scopes: Option<Vec<String>>,
}

fn parse_token_response(body: &Value, provider: &str) -> Result<Parsed, ConnectorError> {
    let Value::Object(m) = body else { return cerr(format!("[{provider}] token endpoint returned a non-object body")) };
    let at = match m.get("access_token") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return cerr(format!("[{provider}] token endpoint response has no access_token")),
    };
    let expires_in_secs = crate::connect::finite(m.get("expires_in")).filter(|x| *x > 0.0);
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
                // `t.split(/[\s,]+/)`: runs of separators split, a leading / trailing run leaves an empty piece
                let (mut out, mut cur, mut in_sep) = (vec![], String::new(), false);
                for c in t.chars() {
                    if js_ws(c) || c == ',' {
                        if !in_sep {
                            out.push(std::mem::take(&mut cur));
                            in_sep = true;
                        }
                    } else {
                        in_sep = false;
                        cur.push(c);
                    }
                }
                out.push(cur);
                Some(out)
            }
        }
        _ => None,
    };
    Ok(Parsed { access_token: at, expires_in_secs, refresh_token, scopes })
}

/// A form parameter: `None` is the reference's `undefined` (written as the text "undefined").
type Param = (String, Option<Value>);

fn set_param(params: &mut Vec<Param>, k: &str, v: Option<Value>) {
    match params.iter_mut().find(|(pk, _)| pk == k) {
        Some(p) => p.1 = v,
        None => params.push((k.to_string(), v)),
    }
}

fn param_str(params: &[Param], k: &str) -> Option<String> {
    params.iter().find(|(pk, _)| pk == k).and_then(|(_, v)| v.as_ref()).and_then(Value::as_str).map(String::from)
}

fn check_extra_params(extra: Option<&Value>, what: &str) -> Result<(), ConnectorError> {
    if let Some(Value::Object(m)) = extra {
        for k in m.keys() {
            if RESERVED_TOKEN_PARAMS.contains(&k.as_str()) {
                return cerr(format!("{what}: extraParams may not set '{k}'"));
            }
        }
    }
    Ok(())
}

fn post_token(manifest: &Value, endpoint: &str, params: &[Param], client_secret: Option<&Value>, fetch: Option<&FetchFn>) -> Result<Parsed, ConnectorError> {
    use base64::Engine;
    let id = manifest["id"].as_str().unwrap_or("").to_string();
    let mut headers = Map::new();
    headers.insert("content-type".into(), json!("application/x-www-form-urlencoded"));
    headers.insert("accept".into(), json!("application/json"));
    let mut body: Vec<Param> = params.to_vec();
    if manifest.get("clientAuth").and_then(Value::as_str) == Some("basic") {
        let Some(secret) = client_secret else { return cerr(format!("[{id}] clientAuth 'basic' requires a clientSecret")) };
        let cid = body.iter().find(|(k, _)| k == "client_id").and_then(|(_, v)| v.clone());
        let Some(cid) = cid else { return cerr(format!("[{id}] missing client_id for basic auth")) };
        let raw = format!("{}:{}", js_value_string(&cid), js_value_string(secret));
        headers.insert("authorization".into(), json!(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))));
        body.retain(|(k, _)| k != "client_id" && k != "client_secret");
    }
    let secrets: Vec<String> = [
        client_secret.and_then(Value::as_str).map(String::from),
        param_str(params, "code"),
        param_str(params, "code_verifier"),
        param_str(params, "refresh_token"),
        headers.get("authorization").and_then(Value::as_str).map(String::from),
    ]
    .into_iter()
    .flatten()
    .collect();
    let form = body
        .iter()
        .map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(&v.as_ref().map_or("undefined".to_string(), js_value_string))))
        .collect::<Vec<_>>()
        .join("&");
    let init = json!({ "method": "POST", "headers": headers, "body": form });
    let res = match fetch {
        None => return cerr(format!("[{id}] token transport error: fetchImpl is not a function")),
        Some(f) => match f(endpoint, &init) {
            Ok(r) => r,
            Err(e) => return cerr(format!("[{id}] token transport error: {}", redact(&e, &secrets))),
        },
    };
    if !res.ok {
        let detail = match &res.text {
            Ok(t) => {
                let u: Vec<u16> = t.encode_utf16().take(256).collect();
                redact(&String::from_utf16_lossy(&u), &secrets)
            }
            Err(_) => "<unreadable body>".to_string(),
        };
        return cerr(format!("[{id}] token endpoint {}: {detail}", res.status));
    }
    let j = match res.json {
        Ok(j) => j,
        Err(_) => return cerr(format!("[{id}] unparseable token JSON")),
    };
    parse_token_response(&j, &id)
}

fn now_ms(args: &Value) -> Result<f64, ConnectorError> {
    match args.get("now") {
        None | Some(Value::Null) => Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)),
        Some(v) => crate::connect::finite(Some(v)).ok_or_else(|| ConnectorError::plain("now must be a finite number")),
    }
}

fn requested_scopes(args: &Value, manifest: &Value) -> Result<Vec<String>, ConnectorError> {
    match args.get("scopes") {
        None | Some(Value::Null) => Ok(strs(manifest.get("defaultScopes"))),
        Some(v @ Value::Array(_)) if str_array(Some(v)) => Ok(strs(Some(v))),
        Some(_) => Err(ConnectorError::plain("scopes must be a list of strings")),
    }
}

fn store_connection(
    vault: &TokenVault,
    manifest: &Value,
    parsed: &Parsed,
    requested: &[String],
    bind: &Value,
    now: f64,
    prior_refresh_token: Option<&str>,
) -> Result<Value, ConnectorError> {
    let expires_at = match parsed.expires_in_secs {
        Some(s) => now + s * 1000.0,
        None => now + DEFAULT_TOKEN_LIFETIME_MS,
    };
    let granted: Vec<String> = parsed.scopes.clone().unwrap_or_else(|| requested.to_vec());
    let refresh_token = parsed.refresh_token.clone().or_else(|| prior_refresh_token.map(String::from));
    let a = bind.get("authority");
    let mut authority = Map::new();
    if let Some(p) = a.and_then(|a| a.get("principal")) {
        authority.insert("principal".into(), p.clone());
    }
    authority.insert(
        "scopes".into(),
        match a.and_then(|a| a.get("scopes")).filter(|s| !s.is_null()) {
            Some(s) => s.clone(),
            None => json!(requested),
        },
    );
    if let Some(au) = a.and_then(|a| a.get("audience")) {
        authority.insert("audience".into(), au.clone());
    }
    let mut put = Map::new();
    if let Some(v) = bind.get("agentId") {
        put.insert("agentId".into(), v.clone());
    }
    put.insert("provider".into(), manifest["id"].clone());
    put.insert("accessToken".into(), json!(parsed.access_token));
    put.insert("expiresAt".into(), jnum(expires_at));
    put.insert("scopes".into(), json!(granted));
    put.insert("authority".into(), Value::Object(authority));
    if let Some(c) = bind.get("connectionId") {
        put.insert("connectionId".into(), c.clone());
    }
    if let Some(r) = refresh_token {
        put.insert("refreshToken".into(), json!(r));
    }
    Ok(vault.put_connection(&Value::Object(put))?)
}

/// Exchange an authorization code for tokens at the provider's token endpoint and store the connection in `vault`. `args`:
/// providerId, clientId, clientSecret?, code, redirectUri, codeVerifier?, scopes?, bind `{agentId, connectionId?, authority:
/// {principal, scopes?, audience?}}`, now?, vars?, extraParams?. Returns the stored connection.
pub fn exchange_code(args: &Value, vault: &TokenVault, fetch: Option<&FetchFn>, registry: Option<&ProviderRegistry>) -> Result<Value, ConnectorError> {
    let manifest = require_provider(registry, &args["providerId"])?;
    let id = manifest["id"].as_str().unwrap_or("").to_string();
    let now = now_ms(args)?;
    let requested = requested_scopes(args, &manifest)?;
    let code = match args.get("code") {
        Some(Value::String(c)) if !c.is_empty() => c.clone(),
        _ => return cerr(format!("[{id}] an authorization code is required")),
    };
    check_extra_params(args.get("extraParams"), &format!("[{id}] exchangeCode"))?;
    if manifest.get("pkce") == Some(&Value::Bool(true)) && args.get("codeVerifier").is_none() {
        return cerr(format!("[{id}] provider uses PKCE; a codeVerifier is required to exchange the code"));
    }
    let mut params: Vec<Param> = vec![
        ("grant_type".into(), Some(json!("authorization_code"))),
        ("code".into(), Some(json!(code))),
        ("redirect_uri".into(), args.get("redirectUri").cloned()),
        ("client_id".into(), args.get("clientId").cloned()),
    ];
    if let Some(s) = args.get("clientSecret") {
        set_param(&mut params, "client_secret", Some(s.clone()));
    }
    if let Some(v) = args.get("codeVerifier") {
        set_param(&mut params, "code_verifier", Some(v.clone()));
    }
    if let Some(Value::Object(x)) = args.get("extraParams") {
        for (k, v) in x {
            set_param(&mut params, k, Some(v.clone()));
        }
    }
    let endpoint = substitute_vars(manifest["tokenUrl"].as_str().unwrap_or(""), args.get("vars"))?;
    let parsed = post_token(&manifest, &endpoint, &params, args.get("clientSecret"), fetch)?;
    store_connection(vault, &manifest, &parsed, &requested, &args["bind"], now, None)
}

/// Refresh a connection's tokens at the provider and store the result in `vault` (the refresh token is kept unless the provider
/// rotates it). `args` as for [`exchange_code`], with `refreshToken` in place of code, redirectUri and codeVerifier.
pub fn refresh(args: &Value, vault: &TokenVault, fetch: Option<&FetchFn>, registry: Option<&ProviderRegistry>) -> Result<Value, ConnectorError> {
    let manifest = require_provider(registry, &args["providerId"])?;
    let id = manifest["id"].as_str().unwrap_or("").to_string();
    if manifest["refresh"]["mode"].as_str() == Some("none") {
        return cerr(format!("[{id}] provider does not support token refresh"));
    }
    let now = now_ms(args)?;
    let requested = requested_scopes(args, &manifest)?;
    let rt = match args.get("refreshToken") {
        Some(Value::String(r)) if !r.is_empty() => r.clone(),
        _ => return cerr(format!("[{id}] a refresh token is required")),
    };
    check_extra_params(args.get("extraParams"), &format!("[{id}] refresh"))?;
    let mut params: Vec<Param> = vec![
        ("grant_type".into(), Some(json!("refresh_token"))),
        ("refresh_token".into(), Some(json!(rt))),
        ("client_id".into(), args.get("clientId").cloned()),
    ];
    if let Some(s) = args.get("clientSecret") {
        set_param(&mut params, "client_secret", Some(s.clone()));
    }
    if let Some(Value::Object(x)) = manifest["refresh"].get("extraParams") {
        for (k, v) in x {
            set_param(&mut params, k, Some(v.clone()));
        }
    }
    if let Some(Value::Object(x)) = args.get("extraParams") {
        for (k, v) in x {
            set_param(&mut params, k, Some(v.clone()));
        }
    }
    if manifest["refresh"].get("supportsScopeNarrowing") == Some(&Value::Bool(true)) && !requested.is_empty() {
        let sep = manifest.get("scopeSeparator").and_then(Value::as_str).unwrap_or(" ");
        set_param(&mut params, "scope", Some(json!(requested.join(sep))));
    }
    let endpoint_tpl =
        manifest["refresh"].get("tokenEndpoint").and_then(Value::as_str).unwrap_or_else(|| manifest["tokenUrl"].as_str().unwrap_or("")).to_string();
    let endpoint = substitute_vars(&endpoint_tpl, args.get("vars"))?;
    let parsed = post_token(&manifest, &endpoint, &params, args.get("clientSecret"), fetch)?;
    store_connection(vault, &manifest, &parsed, &requested, &args["bind"], now, Some(&rt))
}

/// The vault's token-endpoint configuration for a refreshable manifest (`creds`: `{clientId, clientSecret?, vars?}`).
pub fn manifest_to_provider_config(manifest: &Value, creds: &Value) -> Result<Value, ConnectorError> {
    let id = manifest["id"].as_str().unwrap_or("");
    if manifest["refresh"]["mode"].as_str() == Some("none") {
        return cerr(format!("[{id}] provider does not support token refresh; no ProviderConfig"));
    }
    let endpoint_tpl =
        manifest["refresh"].get("tokenEndpoint").and_then(Value::as_str).unwrap_or_else(|| manifest["tokenUrl"].as_str().unwrap_or("")).to_string();
    let mut config = Map::new();
    config.insert("tokenEndpoint".into(), json!(substitute_vars(&endpoint_tpl, creds.get("vars"))?));
    if let Some(c) = creds.get("clientId") {
        config.insert("clientId".into(), c.clone());
    }
    if let Some(s) = creds.get("clientSecret") {
        config.insert("clientSecret".into(), s.clone());
    }
    if let Some(sn) = manifest["refresh"].get("supportsScopeNarrowing") {
        config.insert("supportsScopeNarrowing".into(), sn.clone());
    }
    if let Some(ep) = manifest["refresh"].get("extraParams") {
        config.insert("extraParams".into(), ep.clone());
    }
    Ok(Value::Object(config))
}

/// The `providers` option of a TokenVault from per-provider credentials; non-refreshable providers are skipped.
pub fn build_vault_providers(creds_by_id: &Value, registry: Option<&ProviderRegistry>) -> Result<Value, ConnectorError> {
    let mut out = Map::new();
    if let Value::Object(m) = creds_by_id {
        for (pid, creds) in m {
            let manifest = with_registry(registry, |r| r.require(pid))?;
            if manifest["refresh"]["mode"].as_str() == Some("none") {
                continue;
            }
            out.insert(pid.clone(), manifest_to_provider_config(&manifest, creds)?);
        }
    }
    Ok(Value::Object(out))
}
