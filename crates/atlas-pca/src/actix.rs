//! Actix-web 4 adapter for Proof-Carrying Authority, built ON TOP of the framework-free core in [`crate::middleware`]
//! (feature `actix`, which implies `axum` because the core lives in that module; no axum code runs).
//!
//! * [`PcaGuard`]: an actix [`Transform`] (`App::new().wrap(PcaGuard::new(cfg))`). It reads the `PCA-Action` header (or, when
//!   enabled with [`PcaGuard::with_body_limit`], the `{"pcactn": ...}` body), runs the same pipeline as the axum guard
//!   ([`authorize_request_provenance`] when an operation mapper is set, else [`verify_request_side`], which is the
//!   signature-only guard when `cfg` was built with `with_signature_only`), and on success hands the request to the inner
//!   service with [`PcaAction`], [`Verdict`] and [`AuthorizeResult`] in its extensions.
//! * Fail closed: a denial never reaches the inner service; it is answered `401` (proof absent, undecodable or its grant
//!   unknown), `403` (a denying verdict) or `413` (body over the limit), with `WWW-Authenticate: PCA realm="pca", error="<code>"`
//!   and the same JSON body as the axum guard.
//! * The request body is NOT consumed unless a body limit is configured; when it is, the buffered bytes are put back for the
//!   handler.
//! * [`PcaVerified`]: a handler extractor for the verified action (a missing one is a 401: the guard is not installed).
//!
//! The per-request [`Operation`] comes from [`PcaGuard::with_operation`] (the request and the buffered body, empty when no body
//! limit is set), never from the PCActn; the axum-flavoured `GuardConfig::with_operation` is not used here.
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::{header, StatusCode};
use actix_web::web::Bytes;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use serde_json::Value;

use crate::middleware::{authorize_request_provenance, verify_request_side, GuardConfig, GuardResult, PcaAction, PCA_ACTION_HEADER};
use crate::{presented_k1, AuthorizeResult, Operation, Verdict};

type Mapper = dyn Fn(&HttpRequest, &[u8]) -> Option<Operation> + Send + Sync;

/// How the operation is decided for [`guard_request`].
pub enum OperationInput {
    /// No mapper: the core's own default ([`verify_request_side`]; denies in authorize mode, verifies in signature-only mode).
    Unmapped,
    /// The mapper's answer (`None` denies).
    Mapped(Option<Operation>),
}

/// The pure core of the guard: one request's headers (lowercase name, value or `None` when it is not visible ASCII) and its
/// buffered body through the shared PCA pipeline. No actix types, so it is directly testable.
pub fn guard_request(cfg: &GuardConfig, headers: &[(String, Option<String>)], body: Option<&[u8]>, operation: OperationInput) -> GuardResult {
    fn first<'a>(headers: &'a [(String, Option<String>)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.as_deref())
    }
    let action = first(headers, PCA_ACTION_HEADER);
    let fresh = first(headers, "pca-fresh-at");
    let op = match operation {
        OperationInput::Unmapped => return verify_request_side(action, body, cfg, fresh),
        OperationInput::Mapped(op) => op,
    };
    let answer = first(headers, "pca-escalation-answer");
    // a provenance header that is not visible ASCII is unreadable, not absent: it fails provenance_flow closed
    let provenance = headers.iter().find(|(k, _)| k == "pca-provenance").map(|(_, v)| v.clone().unwrap_or_else(|| "!".into()));
    // unreadable discharge headers are no discharges: the K1 caveat stays unsatisfied
    let names: Vec<(&str, &str)> = headers.iter().filter_map(|(k, v)| Some((k.as_str(), v.as_deref()?))).collect();
    let presented = presented_k1(names).unwrap_or_default();
    authorize_request_provenance(action, body, op, cfg, answer, fresh, Some(&presented), provenance.as_deref())
}

/// The denial response of a [`GuardResult`]: status, `WWW-Authenticate` challenge (static error code only) and JSON body.
pub fn deny_response(result: &GuardResult) -> HttpResponse {
    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::FORBIDDEN);
    let text = crate::restore_lone_surrogates(&result.json_body().to_string());
    let mut b = HttpResponse::build(status);
    b.content_type("application/json");
    if let Some(v) = result.www_authenticate() {
        b.insert_header((header::WWW_AUTHENTICATE, v));
    }
    b.body(text)
}

fn too_large() -> HttpResponse {
    let body = serde_json::json!({ "error": "invalid_request", "error_description": "request body is too large to buffer for a PCActn" });
    HttpResponse::build(StatusCode::PAYLOAD_TOO_LARGE)
        .content_type("application/json")
        .insert_header((header::WWW_AUTHENTICATE, "PCA realm=\"pca\", error=\"invalid_request\""))
        .body(body.to_string())
}

/// The actix middleware factory: `App::new().wrap(PcaGuard::new(cfg))`.
#[derive(Clone)]
pub struct PcaGuard {
    cfg: Arc<GuardConfig>,
    operation: Option<Arc<Mapper>>,
    body_limit: Option<usize>,
}

impl PcaGuard {
    pub fn new(cfg: GuardConfig) -> Self {
        Self { cfg: Arc::new(cfg), operation: None, body_limit: None }
    }

    /// Authorize mode: map the request (and buffered body) to the [`Operation`] the handler will execute, from your routing,
    /// never from the PCActn. `None` (or a panic) denies with 403.
    pub fn with_operation(mut self, mapping: impl Fn(&HttpRequest, &[u8]) -> Option<Operation> + Send + Sync + 'static) -> Self {
        self.operation = Some(Arc::new(mapping));
        self
    }

    /// Also read the `{"pcactn": ...}` body form: buffer at most `limit` bytes (larger is 413) and restore them for the handler.
    /// Without it the body is never consumed.
    pub fn with_body_limit(mut self, limit: usize) -> Self {
        self.body_limit = Some(limit);
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for PcaGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = PcaGuardService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PcaGuardService { service: Rc::new(service), guard: self.clone() }))
    }
}

pub struct PcaGuardService<S> {
    service: Rc<S>,
    guard: PcaGuard,
}

impl<S, B> Service<ServiceRequest> for PcaGuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let guard = self.guard.clone();
        Box::pin(async move {
            let mut buffered: Option<Bytes> = None;
            if let Some(limit) = guard.body_limit {
                let (http_req, payload) = req.parts_mut();
                match Bytes::from_request(http_req, payload).await {
                    Ok(b) if b.len() <= limit => buffered = Some(b),
                    _ => return Ok(req.into_response(too_large()).map_into_right_body()),
                }
                if let Some(b) = &buffered {
                    req.set_payload(Payload::from(b.clone()));
                }
            }
            let headers: Vec<(String, Option<String>)> =
                req.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().ok().map(str::to_owned))).collect();
            let body: &[u8] = buffered.as_deref().unwrap_or(&[]);
            let operation = match &guard.operation {
                None => OperationInput::Unmapped,
                Some(f) => OperationInput::Mapped(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(req.request(), body))).ok().flatten()),
            };
            let result = guard_request(&guard.cfg, &headers, buffered.as_deref(), operation);
            if !result.allow {
                return Ok(req.into_response(deny_response(&result)).map_into_right_body());
            }
            if let Some(p) = result.pcactn {
                req.extensions_mut().insert(PcaAction(p));
            }
            if let Some(v) = result.verdict {
                req.extensions_mut().insert(v);
            }
            if let Some(a) = result.authorization {
                req.extensions_mut().insert(a);
            }
            service.call(req).await.map(ServiceResponse::map_into_left_body)
        })
    }
}

/// Handler extractor for the action the guard verified.
#[derive(Debug, Clone)]
pub struct PcaVerified {
    pub pcactn: Value,
    pub verdict: Option<Verdict>,
    pub authorization: Option<AuthorizeResult>,
}

impl PcaVerified {
    fn of(req: &HttpRequest) -> Option<Self> {
        let ext = req.extensions();
        Some(Self { pcactn: ext.get::<PcaAction>()?.0.clone(), verdict: ext.get::<Verdict>().cloned(), authorization: ext.get::<AuthorizeResult>().cloned() })
    }
}

impl FromRequest for PcaVerified {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(Self::of(req).ok_or_else(|| actix_web::error::ErrorUnauthorized("no verified PCActn on this request (is PcaGuard installed?)")))
    }
}
