//! Proof-Carrying Authority gateway: the decision logic of a deny-by-default enforcement point, over JSON request values.
//! Port of the TypeScript reference (`@atlasauth/pca-gateway`).
//!
//! A request is a JSON object `{method, path, query?, authority?, bodySha256?, body?, headers}`. The proof travels as the `PCA-Action`
//! header; the gateway's own audience and a route -> capability map are configured once. Every step denies by default. The Envoy HTTP and
//! gRPC ext_authz shapes and the AWS Lambda authorizers are plain functions over event values. The Cloudflare Worker adapter is
//! [`Gateway::cloudflare_worker`]: a fetch-style request in, a forward-or-respond outcome out (the caller owns the transport).
//!
//! Nothing here authorizes on its own: it extracts the proof, verifies it with the fail-closed offline core, checks the capability the
//! route maps to, and maps that onto the gateway's contract.
//!
//! shortcut: in signature-only mode the only hook is `revocation` and the only core gate is `freshness` (the attestation / threshold / zk
//! hooks and the taint gate are not expressible in [`GatewayOptions`], so they cannot be configured and silently ignored); use full-policy
//! mode (the core `authorize` pipeline via [`FullPolicy::options`]) for those. In full mode the gateway sets the provenance observation
//! and bundle callbacks of the options itself (the options' own `with_provenance_observed` / `with_provenance_bundle` are replaced; use
//! [`FullPolicy::observed`] to add observations).
//! shortcut: a provenance observation whose `origin` / `source` is an object or array never equals another (JavaScript `===` identity).
//! shortcut: object-keyed Lambda query parameters keep insertion order (JavaScript orders integer-like keys first).
use crate::oauth::{js_str, spread, truthy};
use crate::{
    decode_pca_header, js_stringify, params_digest, strict_parse, verify_pcactn_core_with, AuthorizeOptions, CheckStatus, FreshnessGate, K1Input, Operation,
    PresentedK1, VerifyOptions, ARTIFACT_SIZE_REASON, MAX_ARTIFACT_BYTES,
};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

pub const PCA_HEADER: &str = "PCA-Action";
pub const PCA_INJECTED_HEADERS: [&str; 3] = ["x-pca-verdict", "x-pca-verb", "x-pca-grant"];
pub const DEFAULT_REQUIRE_CHECKS: [&str; 1] = ["revocation"];

static NULL: Value = Value::Null;

// ---------------------------------------------------------------------------------------------------- JS helpers
/// `o[k]` when `o` is an object and the member is not null / undefined.
fn g<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.get(k).filter(|v| !v.is_null())
}

fn first<'a>(vs: &[Option<&'a Value>]) -> Option<&'a Value> {
    vs.iter().find_map(|v| *v)
}

fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err("callback panicked".to_string()))
}

fn system_now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

// ---------------------------------------------------------------------------------------------------- configuration
/// The capability a route requires of a verified PCActn: a PCA verb, optionally bound to a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct RequiredCapability {
    pub verb: String,
    pub resource: Option<String>,
}

impl RequiredCapability {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("verb".into(), json!(self.verb));
        if let Some(r) = &self.resource {
            m.insert("resource".into(), json!(r));
        }
        Value::Object(m)
    }
}

/// One route -> capability rule. First matching rule wins. `method` `None` / `*` / `ANY` matches any method; `path` `*` or `/*` matches
/// any path, a trailing `/*` a segment-boundary prefix, a trailing `*` a raw prefix, otherwise exact.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteRule {
    pub method: Option<String>,
    pub path: String,
    pub capability: RequiredCapability,
}

/// Which request attributes are bound into the proof (method, path and query always are). `body`: `Some(true)` binds the body hash
/// (a request without one is refused), `Some(false)` never binds it, `None` binds it whenever the request carries a `bodySha256`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct BindOptions {
    pub authority: bool,
    pub body: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum BindRequest {
    /// The default: method, path, query and (when the request supplies one) the body hash.
    #[default]
    Default,
    /// The explicit opt-out: the gateway is then a structural pre-filter and a verified proof is a bearer for the matched route.
    Off,
    On(BindOptions),
}

/// `(grant_ref, pcactn) -> the root grant`; `Ok(None)` for an unknown grant (denies). `grant_ref` is JSON null when the PCActn has none.
pub type ResolveGrantFn = Arc<dyn Fn(&Value, &Value) -> Result<Option<Value>, String> + Send + Sync>;
/// `{pcactn, grant, nowEpoch} -> {enforced, ok?, reason?}`; an `Err` refuses the proof.
pub type RevocationHook = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
/// `{pcactn, grant, verdict, request, required?} -> true | false | {allow, reason?}`; `Err` denies.
pub type CheckProofFn = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
/// The gateway clock (epoch ms).
pub type NowFn = Arc<dyn Fn() -> i64 + Send + Sync>;
/// Extra provenance observations for the session (joined with the gateway's own log; raise only).
pub type ObservedFn = Arc<dyn Fn(&Value, &Operation, Option<&str>) -> Vec<Value> + Send + Sync>;

/// Single-use store. `claim` returns `Ok(true)` for the first presentation, `Ok(false)` for a replay, `Err` when unavailable (denies, 503).
pub trait ReplayGuard: Send + Sync {
    fn claim(&self, key: &str, expires_at_ms: f64, now_ms: f64) -> Result<bool, String>;
}

/// The gateway's per-session log of untrusted content it relayed.
pub trait ProvenanceLog: Send + Sync {
    fn seen(&self, session: &str) -> Vec<Value>;
    fn add(&self, session: &str, o: &Value);
}

/// Where a full-policy gateway reads the operation's params from.
#[derive(Clone)]
pub enum ParamsSource {
    /// The request body (a strict JSON object; the request must carry `body`).
    Body,
    /// Built from the request; `None` denies.
    Func(Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>),
}

/// The caveat-language K1 input: fixed, or a function of the request and the proof.
#[derive(Clone)]
pub enum K1Source {
    Fixed(K1Input),
    Dynamic(Arc<dyn Fn(&Value, &Value) -> Result<K1Input, String> + Send + Sync>),
}

#[derive(Clone, Default)]
pub enum ProvLogMode {
    /// An in-memory log per policy.
    #[default]
    Default,
    Off,
    Custom(Arc<dyn ProvenanceLog>),
}

/// Full-policy mode: the grant's limits are evaluated against the real params by the core `authorize` pipeline.
#[derive(Clone)]
pub struct FullPolicy {
    pub params: ParamsSource,
    /// The core authorize components (replay store, revocation check, hooks, gates). `None` is a configuration error.
    pub options: Option<AuthorizeOptions>,
    pub k1: Option<K1Source>,
    pub provenance_log: ProvLogMode,
    pub observed: Option<ObservedFn>,
    default_log: Arc<MemoryProvenanceLog>,
}

impl FullPolicy {
    pub fn new(params: ParamsSource, options: AuthorizeOptions) -> Self {
        FullPolicy {
            params,
            options: Some(options),
            k1: None,
            provenance_log: ProvLogMode::Default,
            observed: None,
            default_log: Arc::new(MemoryProvenanceLog::new(10_000)),
        }
    }
}

#[derive(Clone)]
pub enum Policy {
    /// The proof is genuine and bound to the request; the grant's limits are NOT evaluated (needs a replay guard and, by default, a revocation hook).
    SignatureOnly,
    Full(Box<FullPolicy>),
    /// An unrecognised mode: a configuration error.
    Unknown(String),
}

/// Gateway configuration.
#[derive(Clone, Default)]
pub struct GatewayOptions {
    pub audience: String,
    pub routes: Vec<RouteRule>,
    pub resolve_grant: Option<ResolveGrantFn>,
    pub authorized_plan_roots: Option<Vec<String>>,
    pub insecure_skip_plan_root_check: bool,
    /// `deny` (default), `allow` or `require-proof`.
    pub unmatched_route: Option<String>,
    pub replay_guard: Option<Arc<dyn ReplayGuard>>,
    pub bind_request: BindRequest,
    pub revocation: Option<RevocationHook>,
    pub enforce_freshness: Option<FreshnessGate>,
    /// Core checks that must report `pass` (default in signature-only mode: `["revocation"]`).
    pub require_checks: Option<Vec<String>>,
    pub check_proof: Option<CheckProofFn>,
    /// `strict` (default) denies ambiguous request targets; anything else disables the check.
    pub path_policy: Option<String>,
    pub now: Option<NowFn>,
    pub realm: Option<String>,
    /// REQUIRED: absent, the gateway is misconfigured and denies.
    pub policy: Option<Policy>,
}

// ---------------------------------------------------------------------------------------------------- canonical query / binding
/// JavaScript `decodeURIComponent`: a `%` without two hex digits, or bytes that are not UTF-8, are an error.
fn decode_uri_component(s: &str) -> Result<String, ()> {
    fn hex2(b: &[u8], i: usize) -> Option<u8> {
        let h = |c: u8| (c as char).to_digit(16);
        Some((h(*b.get(i)?)? * 16 + h(*b.get(i + 1)?)?) as u8)
    }
    let b = s.as_bytes();
    let (mut out, mut i, mut start) = (String::new(), 0, 0);
    while i < b.len() {
        if b[i] != b'%' {
            i += 1;
            continue;
        }
        out.push_str(&s[start..i]);
        let mut bytes = Vec::new();
        while i < b.len() && b[i] == b'%' {
            bytes.push(hex2(b, i + 1).ok_or(())?);
            i += 3;
        }
        out.push_str(std::str::from_utf8(&bytes).map_err(|_| ())?);
        start = i;
    }
    out.push_str(&s[start..]);
    Ok(out)
}

/// Strip a leading `?`, drop empty pairs, sort the raw pairs (UTF-16 code unit order) and join with `&`. Errs on a query that is
/// ambiguous across upstream parsers: a repeated parameter name (percent-decoded, `+` as space, case-insensitive), a `;` separator, or
/// a malformed percent escape in a name (the gateway turns it into a request-mismatch deny).
pub fn canonical_query(query: &str) -> Result<String, String> {
    let q = query.strip_prefix('?').unwrap_or(query);
    if q.contains(';') {
        return Err("query contains ';' (parsers disagree on it as a separator)".into());
    }
    let mut pairs: Vec<&str> = q.split('&').filter(|x| !x.is_empty()).collect();
    let mut seen = HashSet::new();
    for pair in &pairs {
        let raw_key = pair.find('=').map_or(*pair, |i| &pair[..i]);
        let key =
            decode_uri_component(&raw_key.replace('+', " ")).map_err(|_| "query parameter name has a malformed percent escape".to_string())?.to_lowercase();
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate query parameter '{key}'"));
        }
    }
    pairs.sort_by_key(|p| p.encode_utf16().collect::<Vec<u16>>());
    Ok(pairs.join("&"))
}

#[derive(Clone, Copy, PartialEq)]
enum BodyMode {
    Default,
    Bind,
    Skip,
}

fn binding_with(req: &Value, authority: bool, body: BodyMode) -> Result<Value, String> {
    let method = req.get("method").and_then(Value::as_str).ok_or("request method must be a string")?;
    let path = req.get("path").and_then(Value::as_str).ok_or("request path must be a string")?;
    let query = match req.get("query") {
        None => String::new(),
        Some(Value::String(q)) => canonical_query(q)?,
        Some(_) => return Err("request query must be a string".into()),
    };
    let lower = |k: &str| -> Result<String, String> {
        match g(req, k) {
            None => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.to_lowercase()),
            Some(_) => Err(format!("request {k} must be a string")),
        }
    };
    let mut b = Map::new();
    b.insert("v".into(), json!(2));
    b.insert("method".into(), json!(method.to_uppercase()));
    b.insert("path".into(), json!(path));
    b.insert("query".into(), json!(query));
    if authority {
        b.insert("authority".into(), json!(lower("authority")?));
    }
    if body == BodyMode::Bind || (body == BodyMode::Default && req.get("bodySha256").is_some()) {
        b.insert("body_sha256".into(), json!(lower("bodySha256")?));
    }
    Ok(Value::Object(b))
}

/// The canonical binding of a request an agent signs as its action params: upper-cased method, path, canonical query and
/// optionally the authority and body hash. `opts` is `{authority?, body?}` (`body`: `true` binds the hash, any other value never,
/// absent binds it whenever the request carries `bodySha256`).
pub fn request_binding(req: &Value, opts: Option<&Value>) -> Result<Value, String> {
    let authority = opts.is_some_and(|o| truthy(o.get("authority")));
    let body = match opts.and_then(|o| o.get("body")) {
        None => BodyMode::Default,
        Some(Value::Bool(true)) => BodyMode::Bind,
        Some(_) => BodyMode::Skip,
    };
    binding_with(req, authority, body)
}

/// The params an agent signs for a full-policy gateway: the params plus the request binding as a `binding` member (pass `None` when
/// the gateway runs with `bind_request` off). Params that already have a `binding` member are refused.
pub fn bind_params(params: &Value, binding: Option<&Value>) -> Result<Value, String> {
    let Some(binding) = binding else { return Ok(params.clone()) };
    let mut m = params.as_object().ok_or("params must be an object")?.clone();
    if m.contains_key("binding") {
        return Err("params already have a 'binding' member".into());
    }
    m.insert("binding".into(), binding.clone());
    Ok(Value::Object(m))
}

/// Why `path` is ambiguous for route matching (the upstream may route a different path), or `None` when canonical.
pub fn ambiguous_path_reason(path: &str) -> Option<&'static str> {
    if path.chars().any(|c| (c as u32) <= 0x1f || c == '\u{7f}' || c == '\\') {
        return Some("control character or backslash in path");
    }
    if path.contains("//") {
        return Some("repeated slash in path");
    }
    if path.contains(';') {
        return Some("path parameter (;) in path");
    }
    if path.split('/').any(|s| s == "." || s == "..") {
        return Some("dot segment in path");
    }
    let b = path.as_bytes();
    let hex = |i: usize| -> Option<u8> {
        let h = |c: u8| (c as char).to_digit(16);
        Some((h(*b.get(i)?)? * 16 + h(*b.get(i + 1)?)?) as u8)
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(code) = hex(i + 1) {
                if code < 0x20 || code == 0x7f {
                    return Some("percent-encoded control character in path");
                }
                if code == b'/' || code == b'\\' {
                    return Some("percent-encoded slash in path");
                }
                if code == b';' {
                    return Some("percent-encoded path parameter delimiter in path");
                }
                if code.is_ascii_alphanumeric() || matches!(code, b'-' | b'.' | b'_' | b'~') {
                    return Some("non-canonical percent-encoding in path");
                }
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    if (0..b.len()).any(|i| b[i] == b'%' && hex(i + 1).is_none()) {
        return Some("malformed percent-encoding in path");
    }
    None
}

// ---------------------------------------------------------------------------------------------------- replay guard / provenance log
/// In-process single-use store. State is per process: use a shared store for more than one instance. A claim stays live through its
/// expiry inclusive. Fails closed (errs) when `max_entries` unexpired claims are held.
pub struct MemoryReplayGuard {
    seen: Mutex<HashMap<String, f64>>,
    max: usize,
    now: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl MemoryReplayGuard {
    pub fn new(max_entries: usize, now: Arc<dyn Fn() -> f64 + Send + Sync>) -> Self {
        MemoryReplayGuard { seen: Mutex::new(HashMap::new()), max: max_entries, now }
    }

    /// The system clock; 100 000 entries is the reference default.
    pub fn with_system_clock(max_entries: usize) -> Self {
        Self::new(max_entries, Arc::new(system_now_ms))
    }

    /// `claim` with an optional explicit `now` (the guard's own clock otherwise).
    pub fn claim_at(&self, key: &str, expires_at_ms: f64, now_ms: Option<f64>) -> Result<bool, String> {
        let t = now_ms.unwrap_or_else(|| (self.now)());
        if !t.is_finite() || !expires_at_ms.is_finite() {
            return Err("replay guard: the clock and the claim expiry must be finite numbers".into());
        }
        let mut seen = self.seen.lock().map_err(|_| "replay guard poisoned".to_string())?;
        if seen.len() >= self.max {
            seen.retain(|_, exp| !(*exp < t));
            if seen.len() >= self.max {
                return Err("replay guard full".into());
            }
        }
        if seen.get(key).is_some_and(|e| *e >= t) {
            return Ok(false);
        }
        seen.insert(key.to_string(), expires_at_ms);
        Ok(true)
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn claim(&self, key: &str, expires_at_ms: f64, now_ms: f64) -> Result<bool, String> {
        self.claim_at(key, expires_at_ms, Some(now_ms))
    }
}

fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

#[derive(Default)]
struct LogState {
    tick: u64,
    map: HashMap<String, (u64, Vec<Value>)>,
}

/// The gateway's per-session record of untrusted content it relayed: at most `max_sessions` sessions (oldest dropped first),
/// 256 observations each.
pub struct MemoryProvenanceLog {
    st: Mutex<LogState>,
    max: usize,
}

impl MemoryProvenanceLog {
    pub fn new(max_sessions: usize) -> Self {
        MemoryProvenanceLog { st: Mutex::new(LogState::default()), max: max_sessions }
    }
}

impl ProvenanceLog for MemoryProvenanceLog {
    fn seen(&self, session: &str) -> Vec<Value> {
        self.st.lock().map(|s| s.map.get(session).map(|x| x.1.clone()).unwrap_or_default()).unwrap_or_default()
    }

    fn add(&self, session: &str, o: &Value) {
        let Ok(mut st) = self.st.lock() else { return };
        let mut cur = st.map.remove(session).map(|x| x.1).unwrap_or_default();
        let (origin, source) = (o.get("origin"), o.get("source"));
        if !cur.iter().any(|x| same(x.get("origin"), origin) && same(x.get("source"), source)) && cur.len() < 256 {
            let mut m = Map::new();
            if let Some(v) = origin {
                m.insert("origin".into(), v.clone());
            }
            if let Some(v) = source {
                m.insert("source".into(), v.clone());
            }
            cur.push(Value::Object(m));
        }
        st.tick += 1;
        let tick = st.tick;
        st.map.insert(session.to_string(), (tick, cur));
        while st.map.len() > self.max {
            let oldest = st.map.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    st.map.remove(&k);
                }
                None => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------- headers / extraction
/// Case-insensitive single-value lookup over a header map: the first key that matches; an array reads as its first element.
pub fn get_header<'a>(headers: &'a Value, name: &str) -> Option<&'a Value> {
    let obj = headers.as_object()?;
    let lower = name.to_lowercase();
    for (k, v) in obj {
        if k.to_lowercase() != lower {
            continue;
        }
        return match v {
            Value::Array(a) => a.first().filter(|x| !x.is_null()),
            Value::Null => None,
            v => Some(v),
        };
    }
    None
}

fn decode_pcactn(text: &str) -> Result<Value, String> {
    if text.len() > MAX_ARTIFACT_BYTES {
        return Err(ARTIFACT_SIZE_REASON.to_string());
    }
    match strict_parse(text)? {
        v @ Value::Object(_) => Ok(v),
        _ => Err("decodePCActn: not an object".to_string()),
    }
}

fn decode_header_value(v: &Value) -> Result<Value, String> {
    let raw = v.as_str().ok_or("PCA header is not a string")?;
    strict_parse(&decode_pca_header(raw).map_err(|e| e.to_string())?)
}

fn extract_pcactn(headers: &Value) -> Result<Value, (&'static str, String)> {
    let raw = match get_header(headers, PCA_HEADER) {
        None => return Err(("no-proof", format!("no {PCA_HEADER} header"))),
        Some(Value::String(s)) if s.is_empty() => return Err(("no-proof", format!("no {PCA_HEADER} header"))),
        Some(r) => r,
    };
    let res = match raw.as_str() {
        Some(r) => decode_pca_header(r).map_err(|e| e.to_string()).and_then(|t| decode_pcactn(&t)),
        None => Err("PCA-Action header is not a string".to_string()),
    };
    res.map_err(|e| ("invalid-proof", format!("undecodable {PCA_HEADER} header: {e}")))
}

fn body_object(req: &Value) -> Option<Map<String, Value>> {
    match req.get("body") {
        Some(Value::String(b)) if !b.is_empty() => match strict_parse(b) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        },
        _ => None,
    }
}

/// The provenance bundle a request presents: header `PCA-Provenance` (strict base64url JSON), else body member `pca_provenance` when
/// the body is not the signed params. `None` when it presents none; `Some(Null)` when presented but unreadable (the gate denies it).
pub fn presented_provenance(req: &Value, params: &ParamsSource) -> Option<Value> {
    let headers = req.get("headers").unwrap_or(&NULL);
    if let Some(h) = get_header(headers, "pca-provenance") {
        if h.as_str() != Some("") {
            return Some(decode_header_value(h).unwrap_or(Value::Null));
        }
    }
    if matches!(params, ParamsSource::Func(_)) {
        if let Some(v) = body_object(req).and_then(|b| b.get("pca_provenance").cloned()) {
            return Some(v);
        }
    }
    None
}

/// The discharges and narrow block a request presents (headers, then body members when the body is not the signed params).
pub fn presented_artifacts(req: &Value, params: &ParamsSource) -> Map<String, Value> {
    let mut out = Map::new();
    let headers = req.get("headers").unwrap_or(&NULL);
    if let Some(d) = get_header(headers, "pca-discharges").filter(|d| d.as_str() != Some("")) {
        if let Ok(arr @ Value::Array(_)) = decode_header_value(d) {
            out.insert("discharges".into(), arr);
        }
    }
    if let Some(n) = get_header(headers, "pca-narrow").filter(|n| n.as_str() != Some("")) {
        if let Ok(v) = decode_header_value(n) {
            out.insert("narrow".into(), v);
        }
    }
    if matches!(params, ParamsSource::Func(_)) {
        if let Some(b) = body_object(req) {
            if !out.contains_key("discharges") {
                if let Some(a @ Value::Array(_)) = b.get("pca_discharges") {
                    out.insert("discharges".into(), a.clone());
                }
            }
            if !out.contains_key("narrow") {
                if let Some(n) = b.get("pca_narrow") {
                    out.insert("narrow".into(), n.clone());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------- routes / decisions
fn match_method(rule: &RouteRule, method: &str) -> bool {
    match &rule.method {
        None => true,
        Some(m) => m == "*" || m.to_uppercase() == "ANY" || m.to_uppercase() == method.to_uppercase(),
    }
}

fn match_path(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "/*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

fn error_token(code: &str) -> &'static str {
    match code {
        "no-proof" => "missing_proof",
        "invalid-proof" | "unknown-grant" | "verify-failed" => "invalid_proof",
        "wrong-audience" => "invalid_resource",
        "insufficient-capability" => "insufficient_capability",
        "invalid-path" => "invalid_request",
        "replayed-proof" => "replayed_proof",
        "replay-guard-unavailable" => "temporarily_unavailable",
        "request-mismatch" => "proof_not_bound_to_request",
        _ => "access_denied",
    }
}

/// The outcome of [`authorize`].
#[derive(Debug, Clone)]
pub struct Decision {
    pub allow: bool,
    pub status: u16,
    pub code: String,
    pub reason: String,
    /// Response headers in order: `www-authenticate` on a deny, `x-pca-verdict` / `x-pca-verb` / `x-pca-grant` on an allow.
    pub headers: Vec<(String, String)>,
    pub verdict: Option<Value>,
    pub pcactn: Option<Value>,
    pub matched: Option<RequiredCapability>,
    pub policy_verdict: Option<Value>,
}

impl Decision {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct Extra {
    verdict: Option<Value>,
    pcactn: Option<Value>,
    matched: Option<RequiredCapability>,
    policy_verdict: Option<Value>,
}

fn deny(code: &str, status: u16, reason: impl Into<String>, realm: &str, x: Extra) -> Decision {
    Decision {
        allow: false,
        status,
        code: code.to_string(),
        reason: reason.into(),
        headers: vec![("www-authenticate".to_string(), format!("PCA realm=\"{realm}\", error=\"{}\"", error_token(code)))],
        verdict: x.verdict,
        pcactn: x.pcactn,
        matched: x.matched,
        policy_verdict: x.policy_verdict,
    }
}

fn allow(reason: impl Into<String>, x: Extra) -> Decision {
    let mut headers = Vec::new();
    if let Some(v) = &x.verdict {
        headers.push(("x-pca-verdict".to_string(), js_stringify(v)));
    }
    if let Some(p) = &x.pcactn {
        headers.push(("x-pca-verb".to_string(), js_str(&p["action"]["verb"])));
        headers.push(("x-pca-grant".to_string(), js_str(&p["grant_ref"])));
    }
    Decision {
        allow: true,
        status: 200,
        code: "allow".into(),
        reason: reason.into(),
        headers,
        verdict: x.verdict,
        pcactn: x.pcactn,
        matched: x.matched,
        policy_verdict: x.policy_verdict,
    }
}

fn missing_text(opts: &GatewayOptions, missing: &[String]) -> String {
    let who = if matches!(opts.policy, None | Some(Policy::SignatureOnly)) { "the gateway" } else { "full policy mode" };
    format!("{who} is missing {}", missing.join(", "))
}

fn missing_policy(opts: &GatewayOptions) -> Vec<String> {
    match &opts.policy {
        None => vec!["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })".to_string()],
        Some(Policy::SignatureOnly) => {
            let mut m = Vec::new();
            if opts.replay_guard.is_none() {
                m.push("replayGuard (signature-only mode needs a single-use guard)".to_string());
            }
            let waived = opts.require_checks.as_ref().is_some_and(|rc| !rc.iter().any(|c| c == "revocation"));
            if !waived && opts.revocation.is_none() {
                m.push("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)".to_string());
            }
            m
        }
        Some(Policy::Unknown(mode)) => vec![format!("a known policy mode (got '{mode}')")],
        Some(Policy::Full(f)) => {
            let mut m = Vec::new();
            if opts.audience.is_empty() {
                m.push("audience".to_string());
            }
            if opts.resolve_grant.is_none() {
                m.push("resolveGrant".to_string());
            }
            if f.options.is_none() {
                m.push("state".to_string());
                m.push("isRevoked".to_string());
            }
            m
        }
    }
}

/// Full-policy mode: the params the agent must have signed for this request.
fn signed_params(req: &Value, fp: &FullPolicy, bind: &BindRequest) -> Result<Value, String> {
    let params = match &fp.params {
        ParamsSource::Body => {
            let body = req.get("body").and_then(Value::as_str).ok_or("full policy mode reads the params from the body, and the request carries none")?;
            strict_parse(body).map_err(|e| format!("the body is not strict JSON: {e}"))?
        }
        ParamsSource::Func(f) => guarded(|| Ok(f(req))).ok().flatten().unwrap_or(Value::Null),
    };
    let Value::Object(mut m) = params else { return Err("the request params are not a JSON object".into()) };
    let b = match bind {
        BindRequest::Off => return Ok(Value::Object(m)),
        BindRequest::Default => BindOptions::default(),
        BindRequest::On(b) => *b,
    };
    if m.contains_key("binding") {
        return Err("the request params carry a 'binding' member (reserved for the request binding)".into());
    }
    if (b.authority && !truthy(req.get("authority"))) || (b.body == Some(true) && !truthy(req.get("bodySha256"))) {
        return Err("request lacks an attribute the proof must bind (authority / body hash)".into());
    }
    // the params carry the body, so its hash is bound only when asked for explicitly (body: true)
    let binding = binding_with(req, b.authority, if b.body == Some(true) { BodyMode::Bind } else { BodyMode::Skip })
        .map_err(|e| format!("the request cannot be bound: {e}"))?;
    m.insert("binding".into(), binding);
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------------------------------- core verification
struct Verified {
    allow: bool,
    reason: Option<String>,
    verdict: Value,
    wire: bool,
    aud: bool,
}

fn verify(pcactn: &Value, grant: &Value, opts: &GatewayOptions, now: i64) -> Verified {
    let mut vo = VerifyOptions::default();
    vo.authorized_plan_roots = opts.authorized_plan_roots.as_deref();
    vo.insecure_skip_plan_root_check = opts.insecure_skip_plan_root_check;
    vo.freshness_gate = opts.enforce_freshness;
    let v = verify_pcactn_core_with(pcactn, grant, now, &opts.audience, &vo);
    let (wire, aud) = (v.checks.get("wire") == Some(&true), v.checks.get("audience") == Some(&true));
    let mut allow = v.allow;
    let mut reason = if v.reason.is_empty() { None } else { Some(v.reason.clone()) };
    let mut revocation = "not-enforced";
    if let (Some(hook), true) = (&opts.revocation, wire) {
        let ctx = json!({"pcactn": pcactn, "grant": grant, "nowEpoch": now});
        match guarded(|| hook(&ctx)) {
            Ok(res) => {
                if !truthy(res.get("enforced")) {
                    revocation = "not-enforced";
                } else if truthy(res.get("ok")) {
                    revocation = "pass";
                } else {
                    revocation = "fail";
                    if allow || reason.is_none() {
                        reason = Some(format!("revocation: {}", g(&res, "reason").map_or("rejected".to_string(), js_str)));
                    }
                    allow = false;
                }
            }
            Err(e) => {
                revocation = "fail";
                if allow || reason.is_none() {
                    reason = Some(format!("malformed PCActn: {e}"));
                }
                allow = false;
            }
        }
    }
    let mut checks = Map::new();
    for (k, ok) in &v.checks {
        checks.insert(if k == "chain" { "cap_chain".to_string() } else { k.clone() }, json!(if *ok { "pass" } else { "fail" }));
    }
    if opts.insecure_skip_plan_root_check && opts.authorized_plan_roots.is_none() {
        checks.insert("plan_root_authorized".into(), json!("not-enforced"));
    }
    checks.insert("attestation".into(), json!("not-enforced"));
    checks.insert("threshold".into(), json!("not-enforced"));
    checks.insert("revocation".into(), json!(revocation));
    checks.entry("taint_gate").or_insert(json!("not-enforced"));
    let mut verdict = Map::new();
    verdict.insert("allow".into(), json!(allow));
    verdict.insert("checks".into(), Value::Object(checks));
    if let Some(r) = &reason {
        verdict.insert("reason".into(), json!(r));
    }
    Verified { allow, reason, verdict: Value::Object(verdict), wire, aud }
}

/// The framework-agnostic core: extract the PCActn, map the request to the capability its route requires, verify (fail closed),
/// enforce audience, capability, request binding, required checks, the proof hook, the policy and single use.
pub fn authorize(req: &Value, opts: &GatewayOptions) -> Decision {
    let realm = opts.realm.clone().unwrap_or_else(|| opts.audience.clone());
    let unmatched = opts.unmatched_route.as_deref().filter(|s| !s.is_empty()).unwrap_or("deny");
    let (Some(path), Some(method)) = (req.get("path").and_then(Value::as_str), req.get("method").and_then(Value::as_str)) else {
        return deny("invalid-path", 400, "request method and path must be strings", &realm, Extra::default());
    };

    // 0. an ambiguous request target is never matched against the route map
    if opts.path_policy.as_deref().unwrap_or("strict") == "strict" {
        if let Some(bad) = ambiguous_path_reason(path) {
            return deny("invalid-path", 400, bad, &realm, Extra::default());
        }
    }

    // 1. route -> required capability; an unmapped route follows unmatched_route (default deny)
    let rule = opts.routes.iter().find(|r| match_method(r, method) && match_path(&r.path, path));
    if rule.is_none() {
        if unmatched == "allow" {
            return allow(format!("route {method} {path} is unmapped (unmatchedRoute=allow)"), Extra::default());
        }
        if unmatched == "deny" {
            return deny("unmapped-route", 403, format!("no capability mapping for {method} {path} (deny-by-default)"), &realm, Extra::default());
        }
    }
    let required: Option<&RequiredCapability> = rule.map(|r| &r.capability);

    // 2. the proof (fail closed)
    let pcactn = match extract_pcactn(req.get("headers").unwrap_or(&NULL)) {
        Ok(p) => p,
        Err((code, why)) => return deny(code, 401, why, &realm, Extra::default()),
    };
    let with_p = || Extra { pcactn: Some(pcactn.clone()), ..Default::default() };

    // 3. the grant the chain must root in
    let grant_ref = pcactn.get("grant_ref");
    let resolved = match &opts.resolve_grant {
        Some(f) => match guarded(|| f(grant_ref.unwrap_or(&NULL), &pcactn)) {
            Ok(r) => r,
            Err(e) => return deny("unknown-grant", 401, format!("grant lookup failed: {e}"), &realm, with_p()),
        },
        None => None,
    };
    let grant = match resolved {
        Some(gr) if truthy(Some(&gr)) => gr,
        _ => {
            let shown = grant_ref.map_or("undefined".to_string(), js_str);
            return deny("unknown-grant", 401, format!("unknown grant_ref {shown}"), &realm, with_p());
        }
    };

    // 3b. a configuration with a missing component denies every request (fail closed)
    let missing = missing_policy(opts);
    if !missing.is_empty() {
        return deny("proof-rejected", 403, format!("{} (fail closed)", missing_text(opts, &missing)), &realm, with_p());
    }

    // 4. offline verification, the audience bound to THIS gateway
    let now = opts.now.as_ref().map_or_else(|| system_now_ms() as i64, |f| f());
    let ver = verify(&pcactn, &grant, opts, now);
    let verdict = ver.verdict.clone();
    let with_v = || Extra { verdict: Some(verdict.clone()), pcactn: Some(pcactn.clone()), ..Default::default() };
    if !ver.allow {
        let aud_failed = ver.wire && !ver.aud;
        let code = if aud_failed { "wrong-audience" } else { "verify-failed" };
        return deny(code, if aud_failed { 403 } else { 401 }, ver.reason.unwrap_or_else(|| "PCActn verification failed".into()), &realm, with_v());
    }

    // 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
    let action = &pcactn["action"];
    if let Some(r) = required {
        let with_m = || Extra { matched: Some(r.clone()), ..with_v() };
        if action["verb"].as_str() != Some(r.verb.as_str()) {
            let why = format!("route requires capability '{}' but the proof authorizes '{}'", r.verb, js_str(&action["verb"]));
            return deny("insufficient-capability", 403, why, &realm, with_m());
        }
        if let Some(res) = &r.resource {
            if action["resource"].as_str() != Some(res.as_str()) {
                let why = format!("route is bound to resource '{res}' but the proof targets '{}'", js_str(&action["resource"]));
                return deny("insufficient-capability", 403, why, &realm, with_m());
            }
        }
    }

    let full = match &opts.policy {
        Some(Policy::Full(fp)) => Some(fp.as_ref()),
        _ => None,
    };
    let mut full_params: Option<Value> = None;
    if let Some(fp) = full {
        // 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
        let params = match signed_params(req, fp, &opts.bind_request) {
            Ok(p) => p,
            Err(e) => return deny("request-mismatch", 403, e, &realm, with_v()),
        };
        if action["params_digest"].as_str() != Some(params_digest(Some(&params)).as_str()) {
            return deny("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)", &realm, with_v());
        }
        full_params = Some(params);
    } else if opts.bind_request != BindRequest::Off {
        // 5b. request binding: the signed params digest must be the digest of THIS request
        let b = match &opts.bind_request {
            BindRequest::On(b) => *b,
            _ => BindOptions::default(),
        };
        if (b.authority && !truthy(req.get("authority"))) || (b.body == Some(true) && !truthy(req.get("bodySha256"))) {
            return deny("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)", &realm, with_v());
        }
        let mode = match b.body {
            Some(true) => BodyMode::Bind,
            Some(false) => BodyMode::Skip,
            None => BodyMode::Default,
        };
        let bound = match binding_with(req, b.authority, mode) {
            Ok(v) => params_digest(Some(&v)),
            Err(e) => return deny("request-mismatch", 403, format!("the request cannot be bound: {e}"), &realm, with_v()),
        };
        if action["params_digest"].as_str() != Some(bound.as_str()) {
            return deny("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)", &realm, with_v());
        }
    }

    // 5c. required checks must have PASSED (not merely "not-enforced"); full mode takes revocation from is_revoked
    let required_checks: Vec<String> = match &opts.require_checks {
        Some(rc) => rc.clone(),
        None if full.is_none() => DEFAULT_REQUIRE_CHECKS.iter().map(|s| s.to_string()).collect(),
        None => Vec::new(),
    };
    for c in &required_checks {
        let status = verdict["checks"].get(c.as_str()).and_then(Value::as_str);
        if status != Some("pass") {
            return deny("proof-rejected", 403, format!("required check '{c}' is {}", status.unwrap_or("absent")), &realm, with_v());
        }
    }

    // 5d. per-proof policy hook (limits, budgets, revocation lists); an error denies
    if let Some(cp) = &opts.check_proof {
        let mut ctx = json!({"pcactn": pcactn, "grant": grant, "verdict": verdict, "request": req});
        if let Some(r) = required {
            ctx["required"] = r.to_value();
        }
        match guarded(|| cp(&ctx)) {
            Ok(r) => {
                let ok = match &r {
                    Value::Bool(b) => *b,
                    other => truthy(other.get("allow")),
                };
                if !ok {
                    let why = if r.is_object() { g(&r, "reason").filter(|x| truthy(Some(*x))).map(js_str) } else { None };
                    return deny("proof-rejected", 403, why.unwrap_or_else(|| "rejected by checkProof".into()), &realm, with_v());
                }
            }
            Err(e) => return deny("proof-rejected", 403, format!("checkProof failed: {e}"), &realm, with_v()),
        }
    }

    // 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
    let mut policy_verdict = None;
    if let (Some(fp), Some(params)) = (full, full_params.as_ref()) {
        match full_policy(req, opts, fp, &pcactn, &grant, required, params, &verdict, &realm, now) {
            Ok(pv) => policy_verdict = Some(pv),
            Err(d) => return d,
        }
    }

    // 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
    if let Some(rg) = &opts.replay_guard {
        let key = format!("{}:{}", js_str(&pcactn["grant_ref"]), pcactn.get("sig").map_or("undefined".to_string(), js_str));
        let exp = pcactn.get("exp").and_then(Value::as_f64).unwrap_or(f64::NAN);
        match guarded(|| rg.claim(&key, exp, now as f64)) {
            Ok(true) => {}
            Ok(false) => return deny("replayed-proof", 403, "this proof has already been used", &realm, with_v()),
            Err(e) => return deny("replay-guard-unavailable", 503, format!("replay guard unavailable: {e}"), &realm, with_v()),
        }
    }

    let reason = if policy_verdict.is_some() { "proof-carrying action authorized (full policy)" } else { "proof-carrying action verified" };
    allow(reason, Extra { verdict: Some(verdict.clone()), pcactn: Some(pcactn.clone()), matched: required.cloned(), policy_verdict })
}

/// Full-policy mode: delegate to the core `authorize` pipeline with the gateway's own audience, grant and clock.
#[allow(clippy::too_many_arguments)]
fn full_policy(
    req: &Value,
    opts: &GatewayOptions,
    fp: &FullPolicy,
    pcactn: &Value,
    grant: &Value,
    required: Option<&RequiredCapability>,
    full_params: &Value,
    verdict: &Value,
    realm: &str,
    now: i64,
) -> Result<Value, Decision> {
    let ex = || Extra { verdict: Some(verdict.clone()), pcactn: Some(pcactn.clone()), ..Default::default() };
    let Some(base) = &fp.options else {
        return Err(deny("proof-rejected", 403, "full policy failed: no authorize options (fail closed)", realm, ex()));
    };
    let mut options = base.clone();
    let arts = presented_artifacts(req, &fp.params);
    let presented = PresentedK1 { discharges: arts.get("discharges").and_then(Value::as_array).cloned(), narrow: arts.get("narrow").cloned() };
    if let Some(k1) = &fp.k1 {
        let own = match k1 {
            K1Source::Fixed(k) => Ok(k.clone()),
            K1Source::Dynamic(f) => guarded(|| f(req, pcactn)),
        };
        match own {
            Ok(k) => options = options.with_k1(k),
            Err(e) => return Err(deny("proof-rejected", 403, format!("k1 input failed: {e} (fail closed)"), realm, ex())),
        }
    }
    let bundle = presented_provenance(req, &fp.params);
    let log: Option<Arc<dyn ProvenanceLog>> = match &fp.provenance_log {
        ProvLogMode::Off => None,
        ProvLogMode::Default => Some(fp.default_log.clone()),
        ProvLogMode::Custom(l) => Some(l.clone()),
    };
    let holder = match pcactn.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last()).filter(|l| l.is_object()) {
        Some(l) => l.get("holder").map_or("undefined".to_string(), js_str),
        None => "undefined".to_string(),
    };
    let session =
        bundle.as_ref().and_then(|b| g(b, "receipts")).and_then(Value::as_array).and_then(|r| r.first()).and_then(|r| r.get("session")).and_then(Value::as_str);
    let log_key = format!("{}\n{}\n{}", js_str(&pcactn["grant_ref"]), holder, session.unwrap_or("-"));
    if fp.observed.is_some() || log.is_some() {
        let (user, lg, key) = (fp.observed.clone(), log.clone(), log_key.clone());
        options = options.with_provenance_observed(move |p, op, sess| {
            let mut v = user.as_ref().map(|u| u(p, op, sess)).unwrap_or_default();
            if let Some(l) = &lg {
                v.extend(l.seen(&key));
            }
            v
        });
    }
    if let Some(b) = &bundle {
        let b = b.clone();
        options = options.with_provenance_bundle(move |_| Ok(Some(b.clone())));
    }
    let action = &pcactn["action"];
    let verb = required.map_or_else(|| js_str(&action["verb"]), |r| r.verb.clone());
    let resource = required.and_then(|r| r.resource.clone()).unwrap_or_else(|| js_str(&action["resource"]));
    let op = Operation::new(verb, resource, full_params.clone());
    let grant_c = grant.clone();
    let resolver = move |_r: &str| -> Result<Option<Value>, String> { Ok(Some(grant_c.clone())) };
    let run = catch_unwind(AssertUnwindSafe(|| {
        options.run_presented(Some(pcactn), Some(&op), &opts.audience, &resolver, Some(now), None, None, None, Some(&presented))
    }));
    let Ok(d) = run else {
        return Err(deny("proof-rejected", 403, "full policy failed: callback panicked (fail closed)", realm, ex()));
    };
    let checks: Map<String, Value> = d.checks.iter().map(|(k, v)| (k.clone(), json!(v.as_str()))).collect();
    // what this call returns flows back into the agent's context: the session has now seen untrusted content
    if d.allow {
        if let Some(l) = &log {
            l.add(&log_key, &json!({"origin": "tool", "source": action["verb"]}));
        }
        return Ok(json!({"allow": true, "checks": checks}));
    }
    let code = if matches!(d.checks.get("replay"), Some(CheckStatus::Fail)) {
        "replayed-proof"
    } else if matches!(d.checks.get("operation"), Some(CheckStatus::Fail)) {
        "insufficient-capability"
    } else if d.status == 401 {
        "verify-failed"
    } else {
        "proof-rejected"
    };
    let pv = json!({"allow": false, "checks": checks, "reason": d.reason});
    Err(deny(code, d.status, d.reason.clone().unwrap_or_else(|| "rejected".into()), realm, Extra { policy_verdict: Some(pv), ..ex() }))
}

/// A reusable authorizer bound to one configuration.
pub struct Gateway {
    opts: GatewayOptions,
}

/// Build a gateway. Errs (a configuration error) when a required component is missing.
pub fn create_gateway(opts: GatewayOptions) -> Result<Gateway, String> {
    let missing = missing_policy(&opts);
    if !missing.is_empty() {
        return Err(format!("pca-gateway: {}", missing_text(&opts, &missing)));
    }
    Ok(Gateway { opts })
}

fn deny_response(d: &Decision) -> Value {
    let mut headers = Map::new();
    headers.insert("content-type".into(), json!("application/json"));
    for (k, v) in &d.headers {
        headers.insert(k.clone(), json!(v));
    }
    json!({"status": d.status, "headers": headers, "body": js_stringify(&json!({"error": d.code, "reason": d.reason}))})
}

fn invalid_request_response() -> Value {
    json!({"status": 403, "headers": {"content-type": "application/json"}, "body": js_stringify(&json!({"error": "invalid-request", "reason": "malformed request attributes"}))})
}

fn s_of(v: &Value) -> Result<String, ()> {
    v.as_str().map(String::from).ok_or(())
}

// ---------------------------------------------------------------------------------------------------- Envoy HTTP ext_authz
fn query_of_target(target: &str) -> &str {
    let Some(q) = target.find('?') else { return "" };
    let rest = &target[q + 1..];
    rest.find('#').map_or(rest, |h| &rest[..h])
}

fn envoy_request(check: &Value) -> Result<Value, ()> {
    let empty = json!({});
    let headers = g(check, "headers").unwrap_or(&empty);
    let method = first(&[g(check, "method"), g(headers, ":method")]).map_or(Ok("*".to_string()), s_of)?;
    let target = first(&[g(check, "path"), g(headers, ":path")]).map_or(Ok("/".to_string()), s_of)?;
    let raw_path = target.find(['?', '#']).map_or(target.as_str(), |i| &target[..i]);
    let path = if raw_path.is_empty() { "/" } else { raw_path };
    let mut req = Map::new();
    req.insert("method".into(), json!(method));
    req.insert("path".into(), json!(path));
    req.insert("query".into(), json!(query_of_target(&target)));
    req.insert("headers".into(), headers.clone());
    if let Some(a) = first(&[g(check, "authority"), g(headers, ":authority")]) {
        req.insert("authority".into(), json!(s_of(a)?));
    }
    if let Some(b) = g(check, "body") {
        req.insert("body".into(), b.clone());
    }
    Ok(Value::Object(req))
}

pub const GRPC_OK: i64 = 0;
pub const GRPC_UNAUTHENTICATED: i64 = 16;
pub const GRPC_PERMISSION_DENIED: i64 = 7;
pub const GRPC_UNAVAILABLE: i64 = 14;
pub const OVERWRITE_IF_EXISTS_OR_ADD: i64 = 2;

fn header_options(h: &[(String, String)]) -> Vec<Value> {
    h.iter().map(|(k, v)| json!({"header": {"key": k, "value": v}, "appendAction": OVERWRITE_IF_EXISTS_OR_ADD})).collect()
}

// ---------------------------------------------------------------------------------------------------- AWS Lambda authorizers
fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn lambda_method_path(event: &Value) -> Result<(String, String), ()> {
    let http = g(event, "requestContext").and_then(|r| g(r, "http"));
    let method = first(&[http.and_then(|h| g(h, "method")), g(event, "httpMethod")]);
    let path = first(&[g(event, "rawPath"), g(event, "path"), http.and_then(|h| g(h, "path"))]);
    if let (Some(m), Some(p)) = (method, path) {
        return Ok((s_of(m)?, s_of(p)?));
    }
    let method = method.map(s_of).transpose()?;
    let path = path.map(s_of).transpose()?;
    if let Some(arn) = first(&[g(event, "methodArn"), g(event, "routeArn")]) {
        let arn = arn.as_str().ok_or(())?;
        let joined = arn.split(':').skip(5).collect::<Vec<_>>().join(":");
        let parts: Vec<&str> = joined.split('/').collect();
        let arn_method = parts.get(2).map(|p| p.split(' ').next().unwrap_or("").to_string());
        let path = path.unwrap_or_else(|| format!("/{}", parts.iter().skip(3).copied().collect::<Vec<_>>().join("/")));
        return Ok((method.or(arn_method).unwrap_or_else(|| "*".into()), path));
    }
    Ok((method.unwrap_or_else(|| "*".into()), path.unwrap_or_else(|| "/".into())))
}

fn lambda_query(event: &Value) -> Result<String, ()> {
    if let Some(Value::String(raw)) = event.get("rawQueryString") {
        return Ok(raw.clone());
    }
    let (multi, single) = (g(event, "multiValueQueryStringParameters"), g(event, "queryStringParameters"));
    let mut pairs = Vec::new();
    if let Some(obj) = multi.filter(|m| truthy(Some(*m))).and_then(Value::as_object) {
        for (k, vs) in obj {
            if vs.is_null() {
                continue;
            }
            for v in spread(vs, "query values").map_err(|_| ())? {
                pairs.push(format!("{}={}", encode_uri_component(k), encode_uri_component(&js_str(&v))));
            }
        }
    } else if let Some(obj) = single.filter(|m| truthy(Some(*m))).and_then(Value::as_object) {
        for (k, v) in obj {
            pairs.push(format!("{}={}", encode_uri_component(k), encode_uri_component(&js_str(v))));
        }
    }
    Ok(pairs.join("&"))
}

fn lambda_request(event: &Value) -> Result<Value, ()> {
    let (method, path) = lambda_method_path(event)?;
    let empty = json!({});
    Ok(json!({"method": method, "path": path, "query": lambda_query(event)?, "headers": g(event, "headers").unwrap_or(&empty)}))
}

fn lambda_context(d: &Decision) -> Value {
    if d.allow {
        return match &d.verdict {
            Some(v) => json!({"pcaVerdict": js_stringify(v)}),
            None => json!({}),
        };
    }
    json!({"pcaDenied": "true", "pcaCode": d.code, "pcaReason": d.reason, "pcaStatus": d.status.to_string()})
}

fn lambda_deny_policy(event: &Value, reason: &str) -> Value {
    json!({"principalId": "anonymous", "policyDocument": {"Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke", "Effect": "Deny", "Resource": lambda_resource(event)}]},
        "context": {"pcaDenied": "true", "pcaCode": "invalid-request", "pcaReason": reason, "pcaStatus": "403"}})
}

fn lambda_resource(event: &Value) -> Value {
    first(&[g(event, "methodArn"), g(event, "routeArn")]).cloned().unwrap_or_else(|| json!("*"))
}

// ---------------------------------------------------------------------------------------------------- Cloudflare Worker
/// The structural subset of a fetch `Request` the Worker adapter reads. `body` is the request body text when the caller can supply it
/// (full-policy mode with the params read from the body needs it; a clone of the request body in the reference).
#[derive(Debug, Clone, Default)]
pub struct WorkerRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl WorkerRequest {
    /// `Headers.get`: case-insensitive, repeated headers joined with `, `.
    pub fn header(&self, name: &str) -> Option<String> {
        let v: Vec<&str> = self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect();
        if v.is_empty() {
            None
        } else {
            Some(v.join(", "))
        }
    }
}

/// What the Worker adapter decided: forward the (cleaned) request upstream, or answer with a deny response.
#[derive(Debug, Clone)]
pub enum WorkerOutcome {
    Forward(WorkerRequest),
    Respond { status: u16, headers: Vec<(String, String)>, body: String },
}

/// The path, authority and raw query of a request URL string, parsed without a URL library (the reference does the same).
fn worker_path_from_url(url: &str) -> (String, String, String) {
    let mut rest = url;
    let mut authority = "";
    if let Some(i) = rest.find("://") {
        rest = &rest[i + 3..];
        match rest.find('/') {
            Some(slash) => {
                authority = &rest[..slash];
                rest = &rest[slash..];
            }
            None => {
                authority = rest;
                rest = "/";
            }
        }
    }
    let path = rest.find(['?', '#']).map_or(rest, |m| &rest[..m]);
    (if path.is_empty() { "/" } else { path }.to_string(), authority.to_string(), query_of_target(rest).to_string())
}

fn worker_respond(status: u16, headers: Vec<(String, String)>, body: &Value) -> WorkerOutcome {
    WorkerOutcome::Respond { status, headers, body: js_stringify(body) }
}

impl Gateway {
    /// The framework-agnostic decision for one request value.
    pub fn authorize(&self, req: &Value) -> Decision {
        authorize(req, &self.opts)
    }

    /// Envoy HTTP ext_authz: 200 plus the verified verdict headers on allow (every injected header is overwritten, the unset ones
    /// blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny.
    pub fn envoy_ext_authz(&self, check: &Value) -> Value {
        let Ok(req) = envoy_request(check) else { return invalid_request_response() };
        let d = self.authorize(&req);
        if !d.allow {
            return deny_response(&d);
        }
        let mut headers = Map::new();
        for h in PCA_INJECTED_HEADERS {
            headers.insert(h.into(), json!(""));
        }
        for (k, v) in &d.headers {
            headers.insert(k.clone(), json!(v));
        }
        json!({"status": 200, "headers": headers, "body": ""})
    }

    /// Envoy gRPC ext_authz `Check` over a decoded CheckRequest value (camelCase). On allow it also lists every x-pca-* header it did
    /// not set in `headersToRemove`, so a client cannot smuggle a forged verdict through an unmapped-route allow.
    pub fn envoy_grpc_ext_authz(&self, c: &Value) -> Value {
        let invalid = |why: &str| {
            json!({"status": {"code": GRPC_PERMISSION_DENIED, "message": "no http request attributes"},
                "deniedResponse": {"status": {"code": 403}, "headers": [], "body": js_stringify(&json!({"error": "invalid-request", "reason": why}))}})
        };
        let Some(http) = g(c, "attributes").and_then(|a| g(a, "request")).and_then(|r| g(r, "http")).filter(|h| truthy(Some(*h))) else {
            return invalid("CheckRequest carried no HTTP attributes");
        };
        let empty = json!({});
        let headers = g(http, "headers").unwrap_or(&empty);
        let mut req = Map::new();
        req.insert("headers".into(), headers.clone());
        if let Some(m) = first(&[g(http, "method"), g(headers, ":method")]) {
            req.insert("method".into(), m.clone());
        }
        if let Some(p) = first(&[g(http, "path"), g(headers, ":path")]) {
            req.insert("path".into(), p.clone());
        }
        if let Some(a) = first(&[g(http, "host"), g(headers, ":authority")]) {
            req.insert("authority".into(), a.clone());
        }
        if let Some(b) = g(http, "body") {
            req.insert("body".into(), b.clone());
        }
        let Ok(req) = envoy_request(&Value::Object(req)) else { return invalid("malformed request attributes") };
        let d = self.authorize(&req);
        if d.allow {
            let remove: Vec<&str> = PCA_INJECTED_HEADERS.iter().copied().filter(|h| d.header(h).is_none()).collect();
            return json!({"status": {"code": GRPC_OK, "message": ""}, "okResponse": {"headers": header_options(&d.headers), "headersToRemove": remove}});
        }
        let code = match d.status {
            401 => GRPC_UNAUTHENTICATED,
            503 => GRPC_UNAVAILABLE,
            _ => GRPC_PERMISSION_DENIED,
        };
        let mut hs = vec![("content-type".to_string(), "application/json".to_string())];
        hs.extend(d.headers.iter().cloned());
        json!({"status": {"code": code, "message": d.reason},
            "deniedResponse": {"status": {"code": d.status}, "headers": header_options(&hs), "body": js_stringify(&json!({"error": d.code, "reason": d.reason}))}})
    }

    /// AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on `context.pcaVerdict`) on a valid proof, else a Deny
    /// policy. REST (`methodArn`) and HTTP-API (`routeArn`) payloads.
    pub fn lambda_authorizer(&self, event: &Value) -> Value {
        let Ok(req) = lambda_request(event) else { return lambda_deny_policy(event, "malformed authorizer event") };
        let d = self.authorize(&req);
        let effect = if d.allow { "Allow" } else { "Deny" };
        let principal = d.pcactn.as_ref().and_then(|p| g(p, "grant_ref")).cloned().unwrap_or_else(|| json!("anonymous"));
        json!({"principalId": principal,
            "policyDocument": {"Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke", "Effect": effect, "Resource": lambda_resource(event)}]},
            "context": lambda_context(&d)})
    }

    /// Cloudflare Worker middleware over a fetch-style request: verifies the inbound PCActn and answers `Forward` (the request to send
    /// upstream) or `Respond` (the deny response; the upstream is never reached). On allow every inbound `x-pca-*` header is removed from
    /// the forwarded request so a client cannot forge the headers the gateway owns; with `rewrite_request` false a request that carries
    /// one is answered 400 instead of forwarded.
    pub fn cloudflare_worker(&self, request: WorkerRequest, rewrite_request: bool) -> WorkerOutcome {
        let (path, authority, query) = worker_path_from_url(&request.url);
        let mut headers = Map::new();
        if let Some(v) = request.header(PCA_HEADER) {
            headers.insert(PCA_HEADER.to_ascii_lowercase(), json!(v));
        }
        for h in ["pca-discharges", "pca-narrow"] {
            if let Some(v) = request.header(h) {
                headers.insert(h.into(), json!(v));
            }
        }
        let mut req = Map::new();
        req.insert("method".into(), json!(request.method));
        req.insert("path".into(), json!(path));
        req.insert("query".into(), json!(query));
        req.insert("authority".into(), json!(authority));
        req.insert("headers".into(), Value::Object(headers));
        let reads_body = matches!(&self.opts.policy, Some(Policy::Full(f)) if matches!(f.params, ParamsSource::Body));
        if let (true, Some(b)) = (reads_body, &request.body) {
            req.insert("body".into(), json!(b));
        }
        let d = self.authorize(&Value::Object(req));
        if !d.allow {
            let mut h = vec![("content-type".to_string(), "application/json".to_string())];
            h.extend(d.headers.iter().cloned());
            return worker_respond(d.status, h, &json!({"error": d.code, "reason": d.reason}));
        }
        let mut forged: Vec<String> = Vec::new();
        for (k, _) in &request.headers {
            let k = k.to_ascii_lowercase();
            if k.starts_with("x-pca-") && !forged.contains(&k) {
                forged.push(k);
            }
        }
        if forged.is_empty() {
            return WorkerOutcome::Forward(request);
        }
        if rewrite_request {
            let mut clean = request;
            clean.headers.retain(|(k, _)| !forged.contains(&k.to_ascii_lowercase()));
            return WorkerOutcome::Forward(clean);
        }
        worker_respond(
            400,
            vec![("content-type".to_string(), "application/json".to_string())],
            &json!({"error": "forged-pca-header", "reason": "inbound x-pca-* header cannot be removed"}),
        )
    }

    /// HTTP-API simple-response variant: `{isAuthorized, context}` instead of an IAM policy.
    pub fn lambda_simple_authorizer(&self, event: &Value) -> Value {
        let Ok(req) = lambda_request(event) else {
            return json!({"isAuthorized": false, "context": {"pcaDenied": "true", "pcaCode": "invalid-request", "pcaReason": "malformed authorizer event", "pcaStatus": "403"}});
        };
        let d = self.authorize(&req);
        json!({"isAuthorized": d.allow, "context": lambda_context(&d)})
    }
}
