//! Runtime-neutral request guard for Proof-Carrying Authority, shaped like the Web Fetch guard of the reference
//! (`@atlasauth/pca-fetch`: `createPcaFetchGuard` / `withPCA`): wrap a handler so the inbound PCActn is verified first; on success
//! the handler runs with the verdict and the PCActn, otherwise a 401 / 403 response with a `WWW-Authenticate` challenge and a JSON
//! `{error, verdict, decision, escalation?}` body is returned. It owns no HTTP stack: a request is [`FetchRequest`]
//! (`{method, url, headers, body}`), a response is [`FetchResponse`], so any server adapts to it in a few lines (and the `axum`
//! middleware of this crate is the framework-bound sibling). Nothing here authorizes on its own: the resource server's verifier
//! decides.
//!
//! The PCActn is read from the `PCA-Action` header (strict unpadded base64url of the JSON, header names are case-insensitive) or,
//! with no (or an empty) header, from a JSON body `{"pcactn": ...}`. Default (0.5): the request is bound to the operation it will
//! execute and runs [`AuthorizeOptions`] (budget / replay store, revocation); `insecure_allow_unbound_operation` is the explicit
//! signature-only opt-in (the proof's signature, chain, audience and window only).
//!
//! shortcut: the escalation answer, `PCA-Fresh-At` and K1 discharge headers and the workflow step of the `axum` middleware are not
//! read here (those checks then fail closed inside [`AuthorizeOptions`]); a resolver error is a 403 with no resolver text in the
//! response (it could carry request-derived text).
use crate::{strict_parse, strict_parse_envelope, verify_pcactn_core_with, AuthorizeOptions, Operation, Verdict, VerifyOptions};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// A request as the guard reads it. `headers` are `(name, value)` pairs (names compare case-insensitively); `body` is the raw body.
#[derive(Debug, Clone, Default)]
pub struct FetchRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl FetchRequest {
    pub fn new(method: &str, url: &str) -> Self {
        FetchRequest { method: method.into(), url: url.into(), headers: Vec::new(), body: None }
    }

    /// The first header of that name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A response: status, headers and the body text.
#[derive(Debug, Clone, PartialEq)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl FetchResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// What a guarded handler receives on success: the verdict (`{allow, checks, reasons}`), the PCActn and, in authorize mode, the
/// operation the decision is bound to (`{verb, resource, params_digest, id}`).
#[derive(Debug, Clone)]
pub struct PcaContext {
    pub verdict: Value,
    pub pcactn: Value,
    pub operation: Option<Value>,
}

/// The outcome of guarding one request.
#[derive(Debug, Clone)]
pub struct GuardOutcome {
    pub allow: bool,
    /// 200 when allowed, else 401 / 403 (413 for nothing here).
    pub status: u16,
    /// The machine-readable error code of a denial (`invalid_request`, `unknown_grant`, `invalid_pcactn`, `insufficient_authority`).
    pub error: Option<String>,
    pub description: String,
    /// `allow`, `deny` or `escalate`.
    pub decision: String,
    pub verdict: Value,
    pub escalation: Option<Value>,
    pub pcactn: Option<Value>,
    pub operation: Option<Value>,
}

impl GuardOutcome {
    fn denied(status: u16, code: &str, description: &str) -> Self {
        GuardOutcome {
            allow: false,
            status,
            error: Some(code.into()),
            description: description.into(),
            decision: "deny".into(),
            verdict: json!({ "allow": false, "checks": {}, "reasons": [description] }),
            escalation: None,
            pcactn: None,
            operation: None,
        }
    }

    /// `WWW-Authenticate: PCA realm="pca", error="<code>"` for a denial. Only the static code is emitted: the description can carry
    /// request-derived text and must never reach a header.
    pub fn www_authenticate(&self) -> Option<String> {
        if self.allow {
            return None;
        }
        Some(format!("PCA realm=\"pca\", error=\"{}\"", self.error.as_deref().unwrap_or("invalid_request")))
    }
}

pub type ResolveGrant = Arc<dyn Fn(&str) -> Result<Option<Value>, String> + Send + Sync>;
pub type OperationFn = Arc<dyn Fn(&FetchRequest) -> Option<Operation> + Send + Sync>;
pub type DenyBodyFn = Arc<dyn Fn(&GuardOutcome) -> Value + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type PcaFetchHandler = Arc<dyn Fn(&FetchRequest, &PcaContext) -> FetchResponse + Send + Sync>;

/// The guard's configuration. `audience` and `resolve_grant` are required; then EITHER `authorize` + `operation` (the default
/// pipeline, bound to the operation each request will execute) OR `insecure_allow_unbound_operation` (signature only).
#[derive(Clone, Default)]
pub struct PcaFetchOptions {
    /// This resource server's id (the PCActn's signed `aud` must equal it).
    pub audience: String,
    /// `grant_ref` -> the root capability, `Ok(None)` when unknown, `Err` when the lookup failed (the request is then refused).
    pub resolve_grant: Option<ResolveGrant>,
    /// The request -> operation mapping (from your routing, never from the PCActn).
    pub operation: Option<OperationFn>,
    pub authorize: Option<AuthorizeOptions>,
    pub insecure_allow_unbound_operation: bool,
    /// Signature-only mode: the Merkle plan roots the principal authorized, or the explicit opt-out below.
    pub authorized_plan_roots: Option<Vec<String>>,
    pub insecure_skip_plan_root_check: bool,
    /// Epoch milliseconds (default: the system clock).
    pub now: Option<ClockFn>,
    /// Shape the 401 / 403 body (default `{error, verdict, decision, escalation?}`).
    pub deny_body: Option<DenyBodyFn>,
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn verdict_json(v: &Verdict) -> Value {
    let checks: Map<String, Value> = v.checks.iter().map(|(k, ok)| (k.clone(), json!(if *ok { "pass" } else { "fail" }))).collect();
    let reasons: Vec<String> = if v.reasons.is_empty() && !v.reason.is_empty() { vec![v.reason.clone()] } else { v.reasons.clone() };
    json!({ "allow": v.allow, "checks": checks, "reasons": reasons })
}

/// The PCActn of a request: the `PCA-Action` header (strict base64url, then strict JSON), else the body envelope `{"pcactn": ...}`.
fn extract_pcactn(req: &FetchRequest) -> Result<Value, GuardOutcome> {
    let bad = |d: &str| GuardOutcome::denied(401, "invalid_request", d);
    if let Some(h) = req.header("pca-action").filter(|h| !h.is_empty()) {
        let raw = crate::decode_b64u_strict(h, None).ok_or_else(|| bad("PCA-Action is not valid base64url"))?;
        if raw.len() > crate::MAX_ARTIFACT_BYTES {
            return Err(bad(&format!("PCA-Action is not a valid PCActn: {}", crate::ARTIFACT_SIZE_REASON)));
        }
        let text = std::str::from_utf8(&raw).map_err(|_| bad("PCA-Action does not decode to UTF-8 JSON"))?;
        return strict_parse(text).map_err(|e| bad(&format!("PCA-Action is not a valid PCActn: {e}")));
    }
    let body = req.body.as_deref().ok_or_else(|| bad("no PCA-Action header or body supplied"))?;
    let env = std::str::from_utf8(body)
        .map_err(|e| e.to_string())
        .and_then(strict_parse_envelope)
        .map_err(|_| bad("no PCA-Action header and the body is not JSON"))?;
    match env.get("pcactn") {
        Some(p) if !p.is_null() => Ok(p.clone()),
        _ => Err(bad("no PCA-Action header and no {\"pcactn\": ...} in the body")),
    }
}

/// A verifier over a [`FetchRequest`] returning the full [`GuardOutcome`], so you can compose it yourself.
#[derive(Clone)]
pub struct PcaFetchGuard {
    o: PcaFetchOptions,
    resolve: ResolveGrant,
}

/// Build the guard. An unsafe configuration is refused: no audience, no grant resolver, no operation mapping (unless the unbound
/// form is chosen explicitly), an `operation` without `authorize` options or the reverse.
pub fn create_pca_fetch_guard(options: PcaFetchOptions) -> Result<PcaFetchGuard, String> {
    if options.audience.is_empty() {
        return Err("pca-fetch: `audience` (this resource server's id) is required".into());
    }
    let resolve = options.resolve_grant.clone().ok_or("pca-fetch: `resolve_grant` is required")?;
    match (options.operation.is_some(), options.authorize.is_some()) {
        (true, true) => {}
        (true, false) => return Err("pca-fetch: `operation` needs `authorize` (the replay store and the revocation check are required)".into()),
        (false, true) => return Err("pca-fetch: `authorize` needs `operation`: map each request to the operation it will execute".into()),
        (false, false) if options.insecure_allow_unbound_operation => {}
        (false, false) => {
            return Err("pca-fetch: `operation` is required (0.5): map each request to the operation it will execute so the proof is bound to it, or use `authorize`; set insecure_allow_unbound_operation only to migrate".into())
        }
    }
    Ok(PcaFetchGuard { o: options, resolve })
}

impl PcaFetchGuard {
    /// Verify one request. Never panics on hostile input; every refusal is a [`GuardOutcome`] with `allow == false`.
    pub fn check(&self, req: &FetchRequest) -> GuardOutcome {
        let pcactn = match extract_pcactn(req) {
            Ok(p) => p,
            Err(denied) => return denied,
        };
        let now = self.o.now.as_ref().map_or_else(system_now, |f| f());
        let resolve = |r: &str| (*self.resolve)(r);
        if let Some(opts) = &self.o.authorize {
            let op = self.o.operation.as_ref().and_then(|f| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(req))).ok().flatten());
            let prov = req.header("pca-provenance");
            let r =
                opts.run_full(Some(&pcactn), op.as_ref(), &self.o.audience, &resolve, Some(now), None, None, None, None, None, prov, req.body.as_deref(), None);
            let checks: Map<String, Value> = r.checks.iter().map(|(k, s)| (k.clone(), json!(s.as_str()))).collect();
            let description = if r.allow { "ok".to_string() } else { r.reason.clone().unwrap_or_else(|| "denied".to_string()) };
            return GuardOutcome {
                allow: r.allow,
                status: r.status,
                error: (!r.allow).then(|| String::from(if r.status == 401 { "invalid_pcactn" } else { "insufficient_authority" })),
                description,
                decision: r.decision.to_string(),
                verdict: json!({ "allow": r.allow, "checks": checks, "reasons": r.reasons }),
                escalation: r.escalation.clone(),
                pcactn: if r.allow { r.pcactn.clone() } else { None },
                operation: r.operation.as_ref().map(|o| json!({ "verb": o.verb, "resource": o.resource, "params_digest": o.params_digest, "id": o.id })),
            };
        }
        let Some(grant_ref) = pcactn.get("grant_ref").and_then(Value::as_str) else {
            return GuardOutcome::denied(401, "invalid_request", "the PCActn carries no grant_ref");
        };
        let grant = match resolve(grant_ref) {
            Ok(Some(g)) => g,
            Ok(None) => return GuardOutcome::denied(401, "unknown_grant", &format!("no grant is registered for grant_ref '{grant_ref}'")),
            Err(_) => return GuardOutcome::denied(403, "insufficient_authority", "the grant could not be resolved (fail closed)"),
        };
        let vo = VerifyOptions {
            authorized_plan_roots: self.o.authorized_plan_roots.as_deref(),
            insecure_skip_plan_root_check: self.o.insecure_skip_plan_root_check,
            ..Default::default()
        };
        let v = verify_pcactn_core_with(&pcactn, &grant, now, &self.o.audience, &vo);
        let verdict = verdict_json(&v);
        if v.allow {
            return GuardOutcome {
                allow: true,
                status: 200,
                error: None,
                description: "ok".into(),
                decision: "allow".into(),
                verdict,
                escalation: None,
                pcactn: Some(pcactn),
                operation: None,
            };
        }
        let mut d = GuardOutcome::denied(403, "insufficient_authority", &v.reason);
        d.verdict = verdict;
        d
    }

    /// The 401 / 403 response for a refusal: JSON `{error, verdict, decision, escalation?}` (or `deny_body(outcome)`), the
    /// `content-type: application/json` header and the `WWW-Authenticate` challenge.
    pub fn deny_response(&self, outcome: &GuardOutcome) -> FetchResponse {
        let body = match &self.o.deny_body {
            Some(f) => f(outcome),
            None => {
                let first = outcome.verdict["reasons"].get(0).and_then(Value::as_str).unwrap_or("forbidden").to_string();
                let mut b = json!({ "error": first, "verdict": outcome.verdict, "decision": outcome.decision });
                if let Some(e) = &outcome.escalation {
                    b["escalation"] = e.clone();
                }
                b
            }
        };
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(w) = outcome.www_authenticate() {
            headers.push(("WWW-Authenticate".to_string(), w));
        }
        FetchResponse { status: outcome.status, headers, body: crate::js_stringify(&body) }
    }
}

/// A handler wrapped by [`with_pca`].
#[derive(Clone)]
pub struct PcaFetch {
    guard: PcaFetchGuard,
    handler: PcaFetchHandler,
}

/// Wrap a handler so the inbound PCActn is verified first; on success `handler(request, context)` runs, otherwise the denial
/// response is returned and the handler never runs. The configuration is checked here ([`create_pca_fetch_guard`]).
pub fn with_pca(options: PcaFetchOptions, handler: PcaFetchHandler) -> Result<PcaFetch, String> {
    Ok(PcaFetch { guard: create_pca_fetch_guard(options)?, handler })
}

impl PcaFetch {
    /// Answer one request.
    pub fn handle(&self, req: &FetchRequest) -> FetchResponse {
        let out = self.guard.check(req);
        if out.allow {
            if let Some(pcactn) = out.pcactn.clone() {
                return (self.handler)(req, &PcaContext { verdict: out.verdict.clone(), pcactn, operation: out.operation.clone() });
            }
        }
        self.guard.deny_response(&out)
    }

    /// The guard, to compose yourself.
    pub fn guard(&self) -> &PcaFetchGuard {
        &self.guard
    }
}
