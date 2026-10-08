//! Ergonomic tower / axum middleware for Proof-Carrying Authority, built ON TOP of the core
//! verifier in [`crate`]. This module is gated behind the optional `axum` cargo feature so the base
//! crate stays dependency-light; it adds `axum`, `tower-layer` and `tower-service`.
//!
//! The pipeline reads a PCActn from the `PCA-Action` request header (base64url -> JSON -> strict
//! parse) or, absent that, from a JSON body `{"pcactn": ...}`; resolves the referenced grant
//! (capability root) via a caller-supplied resolver; and runs the existing offline verifier
//! ([`verify_pcactn_core`]). On success the [`Verdict`] and the PCActn are inserted into the request
//! extensions and the inner service is called. On failure the request is short-circuited with a
//! `401` (the proof is absent / undecodable / its grant is unknown) or `403` (a denying verdict),
//! carrying a `WWW-Authenticate: PCA realm="pca", ...` header and a small JSON body.
//!
//! Three entry points, sharing one core:
//!   * [`verify_request`] — a pure, framework-free function returning a [`GuardResult`]. Easiest to
//!     test and to embed in any handler.
//!   * [`pca_guard`] — an `async fn` usable with `axum::middleware::from_fn_with_state`.
//!   * [`PcaLayer`] / [`PcaService`] — an idiomatic tower [`Layer`]/[`Service`] pair.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

use crate::{strict_parse, verify_pcactn_core, Verdict};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
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
}

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
        }
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
        }
    }

    /// `true` when the request is allowed through.
    pub fn is_allow(&self) -> bool {
        self.allow
    }

    /// The `WWW-Authenticate` header value for a denial (`None` when allowed). The scheme is `PCA`
    /// with `realm`, `error` and `error_description` (RFC 6750-shaped).
    pub fn www_authenticate(&self) -> Option<String> {
        if self.allow {
            return None;
        }
        let code = self.error.unwrap_or("invalid_request");
        let desc = self.description.replace('\\', "\\\\").replace('"', "\\\"");
        Some(format!("PCA realm=\"pca\", error=\"{code}\", error_description=\"{desc}\""))
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
        if let Some(v) = &self.verdict {
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
/// JSON; both paths then run [`verify_pcactn_core`] against the resolved grant and `cfg.audience`
/// at `cfg`'s clock.
pub fn verify_request(header: Option<&str>, body: Option<&[u8]>, cfg: &GuardConfig) -> GuardResult {
    // 1. Obtain the PCActn value, preferring the header.
    let pcactn: Value = match header.filter(|s| !s.is_empty()) {
        Some(h) => match URL_SAFE_NO_PAD.decode(h.as_bytes()) {
            Ok(raw) => match std::str::from_utf8(&raw) {
                Ok(text) => match strict_parse(text) {
                    Ok(v) => v,
                    Err(e) => {
                        return GuardResult::unauthorized(
                            "invalid_request",
                            format!("PCA-Action is not a valid PCActn: {e}"),
                        )
                    }
                },
                Err(_) => {
                    return GuardResult::unauthorized(
                        "invalid_request",
                        "PCA-Action does not decode to UTF-8 JSON",
                    )
                }
            },
            Err(_) => {
                return GuardResult::unauthorized("invalid_request", "PCA-Action is not valid base64url")
            }
        },
        None => match body {
            Some(b) => match serde_json::from_slice::<Value>(b) {
                Ok(env) => match env.get("pcactn") {
                    Some(p) if !p.is_null() => p.clone(),
                    _ => {
                        return GuardResult::unauthorized(
                            "invalid_request",
                            "no PCA-Action header and no {\"pcactn\": ...} in the body",
                        )
                    }
                },
                Err(_) => {
                    return GuardResult::unauthorized(
                        "invalid_request",
                        "no PCA-Action header and the body is not JSON",
                    )
                }
            },
            None => {
                return GuardResult::unauthorized("invalid_request", "no PCA-Action header or body supplied")
            }
        },
    };

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
    let verdict = verify_pcactn_core(&pcactn, &grant, now, &cfg.audience);
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
    let header = parts.headers.get(PCA_ACTION_HEADER).and_then(|v| v.to_str().ok().map(str::to_owned));
    let result = verify_request(header.as_deref(), Some(bytes.as_ref()), cfg);
    if result.allow {
        let mut req = Request::from_parts(parts, Body::from(bytes));
        if let Some(pcactn) = result.pcactn {
            req.extensions_mut().insert(PcaAction(pcactn));
        }
        if let Some(verdict) = result.verdict {
            req.extensions_mut().insert(verdict);
        }
        run_inner(req).await
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
            let header =
                parts.headers.get(PCA_ACTION_HEADER).and_then(|v| v.to_str().ok().map(str::to_owned));
            let result = verify_request(header.as_deref(), Some(bytes.as_ref()), cfg.as_ref());
            if result.allow {
                let mut req = Request::from_parts(parts, Body::from(bytes));
                if let Some(pcactn) = result.pcactn {
                    req.extensions_mut().insert(PcaAction(pcactn));
                }
                if let Some(verdict) = result.verdict {
                    req.extensions_mut().insert(verdict);
                }
                inner.call(req).await
            } else {
                Ok(deny_response(&result))
            }
        })
    }
}
