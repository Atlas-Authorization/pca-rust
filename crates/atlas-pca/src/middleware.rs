//! Ergonomic tower / axum middleware for Proof-Carrying Authority, built ON TOP of the core
//! verifier in [`crate`]. This module is gated behind the optional `axum` cargo feature so the base
//! crate stays dependency-light; it adds `axum`, `tower-layer` and `tower-service`.
//!
//! The pipeline reads a PCActn from the `PCA-Action` request header (base64url -> JSON -> strict
//! parse) or, absent that, from a JSON body `{"pcactn": ...}`; resolves the referenced grant
//! (capability root) via a caller-supplied resolver; and runs the existing offline verifier
//! ([`verify_pcactn_core_with`]). On success the [`Verdict`] and the PCActn are inserted into the request
//! extensions and the inner service is called. On failure the request is short-circuited with a
//! `401` (the proof is absent / undecodable / its grant is unknown) or `403` (a denying verdict),
//! carrying a `WWW-Authenticate: PCA realm="pca", ...` header and a small JSON body.
//!
//! Three entry points, sharing one core:
//!   * [`verify_request`] — a pure, framework-free function returning a [`GuardResult`]. Easiest to
//!     test and to embed in any handler.
//!   * [`pca_guard`] — an `async fn` usable with `axum::middleware::from_fn_with_state`.
//!   * [`PcaLayer`] / [`PcaService`] — an idiomatic tower [`Layer`]/[`Service`] pair.
//!
//! Default (0.5): every request runs through [`crate::authorize`], not the core verifier alone: binding to the operation
//! the handler will execute ([`GuardConfig::with_operation`] maps the request to it), envelope predicates, root and
//! delegated caveats, revocation and the replay counter, all required. Configure it with
//! [`GuardConfig::with_authorize`]; a config without it refuses every request with 403 `authorize_config` naming what is
//! missing. A denial never reaches the inner service. [`GuardConfig::with_signature_only`] is the explicit opt-in to
//! verify the signature, chain and freshness only.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde_json::Value;

use crate::{authorize, strict_parse, verify_pcactn_core_with, AuthorizeInput, AuthorizeOptions, AuthorizeResult, IntentPolicy, IntentV2Context, Operation, Verdict, VerifyOptions};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tower_layer::Layer;
use tower_service::Service;

/// Canonical name of the header carrying a base64url(JSON) PCActn.
pub const PCA_ACTION_HEADER: &str = "pca-action";

/// Default maximum request body size buffered to look for a `{"pcactn": ...}` envelope
/// (matches the verifier's `MAX_JSON_CHARS`, 1 MiB).
pub const DEFAULT_BODY_LIMIT: usize = 1 << 20;

/// A resolved capability / grant (the root capability the PCActn's `cap_chain` must start from),
/// represented — like everything the core verifier consumes — as a [`serde_json::Value`] object.
pub type Capability = Value;

/// `grant_ref` (base64url, 32 bytes) -> the root [`Capability`], or `None` when unknown.
type GrantResolver = Arc<dyn Fn(&str) -> Option<Capability> + Send + Sync>;
/// Current time in epoch milliseconds (the `now` the verifier compares `iat`/`exp` against).
type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Configuration for the guard: this resource server's own audience id, a grant resolver, an
/// optional clock (defaults to the system clock) and the body-buffering limit.
#[derive(Clone)]
pub struct GuardConfig {
    audience: String,
    resolver: GrantResolver,
    clock: Clock,
    body_limit: usize,
    intent: Option<IntentPolicy>,
    intent_v2: Option<IntentV2Resolver>,
    authorize: Option<AuthorizeOptions>,
    operation: Option<OperationMapper>,
    signature_only: bool,
}

/// Authorize mode: the request (head and buffered body) -> the [`Operation`] the handler will execute, or `None`
/// (denied).
type OperationMapper = Arc<dyn Fn(&Parts, &[u8]) -> Option<Operation> + Send + Sync>;

/// Per-request Intent Layer v2 verifier state: given the parsed PCActn, the host returns its [`IntentV2Context`]
/// (plaintext params, accepted schemas, session root and grants, accumulator pre-state, receipts, key sets, ...).
type IntentV2Resolver = Arc<dyn Fn(&Value) -> Option<IntentV2Context> + Send + Sync>;

impl GuardConfig {
    /// Build a config from this verifier's `audience` and a grant resolver. The resolver maps a
    /// PCActn `grant_ref` to the matching root capability (its `id` equals that `grant_ref`).
    pub fn new(
        audience: impl Into<String>,
        resolver: impl Fn(&str) -> Option<Capability> + Send + Sync + 'static,
    ) -> Self {
        Self {
            audience: audience.into(),
            resolver: Arc::new(resolver),
            clock: Arc::new(system_clock),
            body_limit: DEFAULT_BODY_LIMIT,
            intent: None,
            intent_v2: None,
            authorize: None,
            operation: None,
            signature_only: false,
        }
    }

    /// Configure the default guard, [`crate::authorize`] (0.5): every request must carry a proof for the exact operation
    /// the handler will execute, within the grant's predicates and caveats, unrevoked and not replayed (the options hold
    /// the replay store, the revocation check, the plan mode, the context and extra required checks). Set the request ->
    /// operation mapping with [`GuardConfig::with_operation`]; without one every request is denied.
    ///
    /// # Panics
    /// When [`GuardConfig::with_signature_only`] was also given (a configuration error).
    pub fn with_authorize(mut self, options: AuthorizeOptions) -> Self {
        assert!(!self.signature_only, "GuardConfig: with_authorize and with_signature_only are mutually exclusive");
        self.authorize = Some(options);
        self
    }

    /// Explicit opt-in to the signature-only guard: verify the signature, chain, audience and freshness with the core
    /// verifier and nothing else (no policy, no replay, no revocation, no operation binding).
    ///
    /// # Panics
    /// When [`GuardConfig::with_authorize`] was also given (a configuration error).
    pub fn with_signature_only(mut self) -> Self {
        assert!(self.authorize.is_none(), "GuardConfig: with_authorize and with_signature_only are mutually exclusive");
        self.signature_only = true;
        self
    }

    /// Authorize mode: map a request (head and buffered body) to the [`Operation`] the handler will execute, from your
    /// routing and parsed body, never from the PCActn. `None` (or a panic) denies with 403.
    pub fn with_operation(mut self, mapping: impl Fn(&Parts, &[u8]) -> Option<Operation> + Send + Sync + 'static) -> Self {
        self.operation = Some(Arc::new(mapping));
        self
    }

    /// Set the Intent Layer M2 policy (default: none). See [`IntentPolicy`].
    pub fn with_intent_policy(mut self, policy: IntentPolicy) -> Self {
        self.intent = Some(policy);
        self
    }

    /// Set the Intent Layer v2 state resolver (default: none, so only a v2 member on the PCActn reports the v2 checks,
    /// against an empty context). The resolver builds the per-request [`IntentV2Context`] from the parsed PCActn.
    pub fn with_intent_v2(mut self, resolver: impl Fn(&Value) -> Option<IntentV2Context> + Send + Sync + 'static) -> Self {
        self.intent_v2 = Some(Arc::new(resolver));
        self
    }

    /// Override the clock (epoch milliseconds). Useful for tests and for a monotonic trusted source.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Override the maximum request body size buffered when looking for a `{"pcactn": ...}` body.
    pub fn with_body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    /// This verifier's audience id.
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// A verified PCActn, inserted into request extensions on success so downstream handlers can read
/// the full action (`req.extensions().get::<PcaAction>()`).
#[derive(Debug, Clone)]
pub struct PcaAction(pub Value);

/// The outcome of guarding one request. Either the proof verified (`allow`, carrying the PCActn and
/// its [`Verdict`]) or it was rejected with an HTTP status (401 or 403) and a reason.
#[derive(Debug, Clone)]
pub struct GuardResult {
    /// Whether the request is allowed through to the inner service.
    pub allow: bool,
    /// HTTP status to respond with when denied (200 when allowed).
    pub status: u16,
    /// Machine-readable error code for `WWW-Authenticate` / the JSON body (None when allowed).
    pub error: Option<&'static str>,
    /// Human-readable description / verdict reason.
    pub description: String,
    /// The verified PCActn (present only when allowed).
    pub pcactn: Option<Value>,
    /// The full verdict (present when allowed, or when a verdict was produced but denied).
    pub verdict: Option<Verdict>,
    /// Authorize mode only: the full [`AuthorizeResult`] (checks, reasons, the bound operation).
    pub authorization: Option<AuthorizeResult>,
}

impl GuardResult {
    fn allow(pcactn: Value, verdict: Verdict) -> Self {
        Self {
            allow: true,
            status: 200,
            error: None,
            description: "ok".into(),
            pcactn: Some(pcactn),
            verdict: Some(verdict),
            authorization: None,
        }
    }

    fn unauthorized(code: &'static str, description: impl Into<String>) -> Self {
        Self {
            allow: false,
            status: 401,
            error: Some(code),
            description: description.into(),
            pcactn: None,
            verdict: None,
            authorization: None,
        }
    }

    fn forbidden(verdict: Verdict) -> Self {
        Self {
            allow: false,
            status: 403,
            error: Some("insufficient_authority"),
            description: verdict.reason.clone(),
            pcactn: None,
            verdict: Some(verdict),
            authorization: None,
        }
    }

    fn authorized(r: AuthorizeResult) -> Self {
        if r.allow {
            return Self {
                allow: true,
                status: 200,
                error: None,
                description: "ok".into(),
                pcactn: r.pcactn.clone(),
                verdict: r.verdict.clone(),
                authorization: Some(r),
            };
        }
        Self {
            allow: false,
            status: r.status,
            error: Some(if r.status == 401 { "invalid_pcactn" } else { "insufficient_authority" }),
            description: r.reason.clone().unwrap_or_else(|| "denied".into()),
            pcactn: None,
            verdict: None,
            authorization: Some(r),
        }
    }

    fn payload_too_large() -> Self {
        Self {
            allow: false,
            status: 413,
            error: Some("invalid_request"),
            description: "request body is too large to buffer for a PCActn".into(),
            pcactn: None,
            verdict: None,
            authorization: None,
        }
    }

    /// `true` when the request is allowed through.
    pub fn is_allow(&self) -> bool {
        self.allow
    }

    /// The `WWW-Authenticate` header value for a denial (`None` when allowed): `PCA realm="pca", error="<code>"`.
    /// Only the static error code is emitted. The description is NOT: it can carry request-derived text (the verdict
    /// reason, the presented `grant_ref`, a parse error) and so must never reach a header (CR/LF header injection);
    /// TS `requirePCA` puts no reason in its challenge either. The description stays in [`GuardResult::json_body`].
    pub fn www_authenticate(&self) -> Option<String> {
        if self.allow {
            return None;
        }
        let code = self.error.unwrap_or("invalid_request");
        Some(format!("PCA realm=\"pca\", error=\"{code}\""))
    }

    /// The JSON body for a response (allow or deny), including the per-check verdict when present.
    pub fn json_body(&self) -> Value {
        let mut m = serde_json::Map::new();
        if self.allow {
            m.insert("ok".into(), Value::Bool(true));
        } else {
            m.insert("error".into(), Value::String(self.error.unwrap_or("invalid_request").into()));
            m.insert("error_description".into(), Value::String(self.description.clone()));
        }
        if let Some(a) = &self.authorization {
            m.insert("allow".into(), Value::Bool(a.allow));
            if let Some(r) = &a.reason {
                m.insert("reason".into(), Value::String(r.clone()));
            }
            let checks = a.checks.iter().map(|(k, s)| (k.clone(), Value::String(s.as_str().into()))).collect();
            m.insert("checks".into(), Value::Object(checks));
        } else if let Some(v) = &self.verdict {
            m.insert("allow".into(), Value::Bool(v.allow));
            m.insert("reason".into(), Value::String(v.reason.clone()));
            let checks = v.checks.iter().map(|(k, b)| (k.clone(), Value::Bool(*b))).collect();
            m.insert("checks".into(), Value::Object(checks));
        }
        Value::Object(m)
    }
}

/// Run the PCActn checks for one request, framework-free.
///
/// `header` is the raw `PCA-Action` header value (base64url of the PCActn JSON), if present;
/// `body` is the raw request body, used only when no header is present and parsed as a
/// `{"pcactn": ...}` envelope. The header path strict-parses (RFC 8259 strict profile) the decoded
/// JSON; both paths then run [`verify_pcactn_core_with`] against the resolved grant and `cfg.audience`
/// at `cfg`'s clock.
///
/// Unless [`GuardConfig::with_signature_only`] was given this function has no request to map to an operation and so
/// denies (403); use [`authorize_request`] (the layer and [`pca_guard`] do).
pub fn verify_request(header: Option<&str>, body: Option<&[u8]>, cfg: &GuardConfig) -> GuardResult {
    if !cfg.signature_only {
        return authorize_request(header, body, None, cfg);
    }
    // 1. Obtain the PCActn value, preferring the header; then steps 2-4.
    let pcactn = match extract_pcactn(header, body) {
        Ok(p) => p,
        Err(denied) => return denied,
    };
    verify_extracted(pcactn, cfg)
}

/// Authorize mode, framework-free: extract the PCActn as [`verify_request`] does, then run [`crate::authorize`] for
/// `operation` (the one the handler will execute; `None` denies) with `cfg`'s audience, resolver, clock, intent policies
/// and [`AuthorizeOptions`]. A config without [`GuardConfig::with_authorize`] denies (403, check `authorize_config`,
/// naming the missing components).
pub fn authorize_request(header: Option<&str>, body: Option<&[u8]>, operation: Option<Operation>, cfg: &GuardConfig) -> GuardResult {
    let pcactn = match extract_pcactn(header, body) {
        Ok(p) => p,
        Err(denied) => return denied,
    };
    let resolver = cfg.resolver.clone();
    let resolve = move |r: &str| Ok::<_, String>(resolver(r));
    let v2 = cfg.intent_v2.clone().map(|f| move |p: &Value| Ok::<_, String>(f(p)));
    let v2_ref = v2.as_ref().map(|f| f as &crate::IntentV2Provider<'_>);
    let now = (cfg.clock)();
    let r = match &cfg.authorize {
        Some(opts) => opts.run(Some(&pcactn), operation.as_ref(), &cfg.audience, &resolve, Some(now), cfg.intent.as_ref(), v2_ref),
        // no options: an empty option set, so authorize names the absent state store and revocation check
        None => authorize(
            Some(&pcactn),
            &AuthorizeInput {
                operation: operation.as_ref(),
                audience: &cfg.audience,
                resolve_grant: Some(&resolve),
                now: Some(now),
                ..Default::default()
            },
        ),
    };
    GuardResult::authorized(r)
}

/// The request -> operation mapping of authorize mode (`None` without a mapping, or when it panics).
fn map_operation(cfg: &GuardConfig, parts: &Parts, body: &[u8]) -> Option<Operation> {
    let f = cfg.operation.as_ref()?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(parts, body))).ok().flatten()
}

/// One buffered request through the guard: authorize mode unless signature-only was chosen, then the core verifier.
fn guard_parts(cfg: &GuardConfig, parts: &Parts, body: &[u8]) -> GuardResult {
    let header = parts.headers.get(PCA_ACTION_HEADER).and_then(|v| v.to_str().ok().map(str::to_owned));
    if !cfg.signature_only {
        return authorize_request(header.as_deref(), Some(body), map_operation(cfg, parts, body), cfg);
    }
    verify_request(header.as_deref(), Some(body), cfg)
}

/// Step 1 of the guard: the PCActn value, preferring the header (a 401 [`GuardResult`] when absent or undecodable).
fn extract_pcactn(header: Option<&str>, body: Option<&[u8]>) -> Result<Value, GuardResult> {
    Ok(match header.filter(|s| !s.is_empty()) {
        // 0.4.1: STRICT unpadded base64url (`decode_b64u_strict`, the rule `decode_pca_header` applies): no padding, no
        // standard alphabet, no whitespace (nothing is trimmed), zero trailing bits; then strict UTF-8 below.
        Some(h) => match crate::decode_b64u_strict(h, None).ok_or(()) {
            Ok(raw) if raw.len() > crate::MAX_ARTIFACT_BYTES => {
                return Err(GuardResult::unauthorized(
                    "invalid_request",
                    format!("PCA-Action is not a valid PCActn: {}", crate::ARTIFACT_SIZE_REASON),
                ))
            }
            Ok(raw) => match std::str::from_utf8(&raw) {
                Ok(text) => match strict_parse(text) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(GuardResult::unauthorized(
                            "invalid_request",
                            format!("PCA-Action is not a valid PCActn: {e}"),
                        ))
                    }
                },
                Err(_) => {
                    return Err(GuardResult::unauthorized(
                        "invalid_request",
                        "PCA-Action does not decode to UTF-8 JSON",
                    ))
                }
            },
            Err(_) => {
                return Err(GuardResult::unauthorized("invalid_request", "PCA-Action is not valid base64url"))
            }
        },
        None => match body {
            // R6-01: the SAME strict profile as header mode (duplicate keys refused at any depth, depth-bounded before
            // recursion). A lenient parse collapsed duplicate keys last-wins before verification while a first-wins
            // downstream parser of the body saw the other value.
            Some(b) => match std::str::from_utf8(b).map_err(|e| e.to_string()).and_then(crate::strict_parse_envelope) {
                Ok(env) => match env.get("pcactn") {
                    Some(p) if !p.is_null() => p.clone(),
                    _ => {
                        return Err(GuardResult::unauthorized(
                            "invalid_request",
                            "no PCA-Action header and no {\"pcactn\": ...} in the body",
                        ))
                    }
                },
                Err(_) => {
                    return Err(GuardResult::unauthorized(
                        "invalid_request",
                        "no PCA-Action header and the body is not JSON",
                    ))
                }
            },
            None => {
                return Err(GuardResult::unauthorized("invalid_request", "no PCA-Action header or body supplied"))
            }
        },
    })
}

/// Steps 2-4 of the signature-only guard: resolve the grant and run the core verifier.
fn verify_extracted(pcactn: Value, cfg: &GuardConfig) -> GuardResult {
    // 2. Extract the grant reference needed to resolve the root capability.
    let grant_ref = match pcactn.get("grant_ref").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return GuardResult::unauthorized("invalid_request", "the PCActn carries no grant_ref")
        }
    };

    // 3. Resolve the grant. An unknown grant is a 401 (the presented authority is unrecognised).
    let grant = match (cfg.resolver)(grant_ref) {
        Some(g) => g,
        None => {
            return GuardResult::unauthorized(
                "unknown_grant",
                format!("no grant is registered for grant_ref '{grant_ref}'"),
            )
        }
    };

    // 4. Run the existing offline verifier (8 checks; aud vs signed aud; chain rooted at the grant).
    let now = (cfg.clock)();
    let v2 = cfg.intent_v2.as_ref().and_then(|r| r(&pcactn));
    let opts = VerifyOptions { allowed: None, intent: cfg.intent.as_ref(), intent_v2: v2.as_ref() };
    let verdict = verify_pcactn_core_with(&pcactn, &grant, now, &cfg.audience, &opts);
    if verdict.allow {
        GuardResult::allow(pcactn, verdict)
    } else {
        GuardResult::forbidden(verdict)
    }
}

/// Build the short-circuit HTTP response for a denying [`GuardResult`].
fn deny_response(result: &GuardResult) -> Response {
    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::FORBIDDEN);
    let mut response = (status, Json(result.json_body())).into_response();
    if let Some(value) = result.www_authenticate() {
        let header_value = HeaderValue::from_str(&value)
            .unwrap_or_else(|_| HeaderValue::from_static("PCA realm=\"pca\""));
        response.headers_mut().insert(header::WWW_AUTHENTICATE, header_value);
    }
    response
}

/// An allowed request with the PCActn, the verdict and (authorize mode) the [`AuthorizeResult`] in its extensions.
fn enrich(mut req: Request, result: GuardResult) -> Request {
    if let Some(pcactn) = result.pcactn {
        req.extensions_mut().insert(PcaAction(pcactn));
    }
    if let Some(verdict) = result.verdict {
        req.extensions_mut().insert(verdict);
    }
    if let Some(authorization) = result.authorization {
        req.extensions_mut().insert(authorization);
    }
    req
}

/// Apply [`verify_request`] to a live request: buffer the body, read the header, and either enrich
/// the request with the verdict + PCActn and hand it to `next`, or return the denial response.
async fn guard_and_dispatch<F, Fut>(cfg: &GuardConfig, req: Request, run_inner: F) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, cfg.body_limit).await {
        Ok(b) => b,
        Err(_) => return deny_response(&GuardResult::payload_too_large()),
    };
    let result = guard_parts(cfg, &parts, bytes.as_ref());
    if result.allow {
        run_inner(enrich(Request::from_parts(parts, Body::from(bytes)), result)).await
    } else {
        deny_response(&result)
    }
}

/// An `axum::middleware::from_fn_with_state`-compatible guard.
///
/// ```ignore
/// use axum::{middleware, routing::post, Router};
/// use atlas_pca::middleware::{pca_guard, GuardConfig};
///
/// let cfg = GuardConfig::new("rs-orders", |grant_ref| my_store.lookup(grant_ref));
/// let app = Router::new()
///     .route("/orders", post(create_order))
///     .layer(middleware::from_fn_with_state(cfg, pca_guard));
/// ```
pub async fn pca_guard(State(cfg): State<GuardConfig>, req: Request, next: Next) -> Response {
    guard_and_dispatch(&cfg, req, |req| next.run(req)).await
}

/// A tower [`Layer`] that wraps a service with the PCActn guard. See [`PcaService`].
#[derive(Clone)]
pub struct PcaLayer {
    cfg: Arc<GuardConfig>,
}

impl PcaLayer {
    /// Create a layer from a [`GuardConfig`].
    pub fn new(cfg: GuardConfig) -> Self {
        Self { cfg: Arc::new(cfg) }
    }
}

impl<S> Layer<S> for PcaLayer {
    type Service = PcaService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PcaService { inner, cfg: self.cfg.clone() }
    }
}

/// A tower [`Service`] that guards `inner` with the PCActn checks. On success the wrapped service
/// sees the verdict and PCActn in `req.extensions()`; on failure it is never called and a 401/403
/// response is produced instead.
#[derive(Clone)]
pub struct PcaService<S> {
    inner: S,
    cfg: Arc<GuardConfig>,
}

impl<S> Service<Request> for PcaService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let cfg = self.cfg.clone();
        // Clone-and-replace so the clone we move into the future is the one that was `poll_ready`'d.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = match to_bytes(body, cfg.body_limit).await {
                Ok(b) => b,
                Err(_) => return Ok(deny_response(&GuardResult::payload_too_large())),
            };
            let result = guard_parts(cfg.as_ref(), &parts, bytes.as_ref());
            if result.allow {
                inner.call(enrich(Request::from_parts(parts, Body::from(bytes)), result)).await
            } else {
                Ok(deny_response(&result))
            }
        })
    }
}
