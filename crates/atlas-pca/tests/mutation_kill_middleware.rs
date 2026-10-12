//! Mutation-kill suite for the tower/axum middleware (feature `axum`).
#![cfg(feature = "axum")]
mod common;
use atlas_pca::middleware::{pca_guard, verify_request, GuardConfig, PcaAction, PcaLayer, DEFAULT_BODY_LIMIT, PCA_ACTION_HEADER};
use atlas_pca::{canonicalize_strict, threshold_message, ARTIFACT_SIZE_REASON, MAX_ARTIFACT_BYTES};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

fn vector(name: &str) -> (Value, Value, i64, String) {
    let doc = load("vectors.json");
    let v = doc["vectors"].as_array().unwrap().iter().find(|v| v["name"].as_str() == Some(name)).unwrap().clone();
    (v["pcactn"].clone(), v["grant"].clone(), v["context"]["now"].as_i64().unwrap(), v["context"]["aud"].as_str().unwrap().to_string())
}

fn header_for(p: &Value) -> String {
    URL_SAFE_NO_PAD.encode(canonicalize_strict(p).unwrap().as_bytes())
}

fn cfg_for(grant: &Value, aud: &str) -> GuardConfig {
    let g = grant.clone();
    let id = g["id"].as_str().unwrap().to_string();
    GuardConfig::new(aud.to_string(), move |r: &str| if r == id { Some(g.clone()) } else { None })
}

fn block_on<F: Future>(mut fut: F) -> F::Output {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    for _ in 0..1_000_000 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::hint::spin_loop();
    }
    panic!("future did not resolve");
}

#[derive(Clone)]
struct Echo;
impl Service<Request> for Echo {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: Request) -> Self::Future {
        let ok = req.extensions().get::<PcaAction>().is_some();
        ready(Ok((if ok { StatusCode::IM_A_TEAPOT } else { StatusCode::INTERNAL_SERVER_ERROR }).into_response()))
    }
}

/// Re-sign the valid fixture for the REAL current time (the leaf is signed by the corpus `agent` key).
fn fresh_valid() -> (Value, Value, String) {
    let (mut p, grant, _now, aud) = vector("valid-in-plan-action");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    p["iat"] = json!(now - 1000);
    p["exp"] = json!(now + 300_000);
    let keys = load("keys.json");
    let seed: [u8; 32] = URL_SAFE_NO_PAD.decode(keys["agent"]["seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let msg = threshold_message(p.as_object().unwrap()).unwrap();
    p["sig"] = json!(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&seed).sign(&msg).to_bytes()));
    (p, grant, aud)
}

#[test]
fn default_system_clock_is_real_time() {
    let (p, grant, aud) = fresh_valid();
    let r = verify_request(Some(&header_for(&p)), None, &cfg_for(&grant, &aud));
    assert!(r.is_allow(), "{}", r.description);
    // the same action under a clock at epoch 0 / 1 / -1 is not yet valid, under the system clock it is
    for t in [0i64, 1, -1] {
        let r = verify_request(Some(&header_for(&p)), None, &cfg_for(&grant, &aud).with_clock(move || t));
        assert_eq!(r.status, 403, "clock {t}");
    }
}

#[test]
fn config_accessors_and_defaults() {
    let c = GuardConfig::new("rs-x", |_: &str| None);
    assert_eq!(c.audience(), "rs-x");
    assert_eq!(GuardConfig::new("", |_: &str| None).audience(), "");
    assert_eq!(DEFAULT_BODY_LIMIT, 1_048_576);
    assert_eq!(PCA_ACTION_HEADER, "pca-action");
}

#[test]
fn header_size_cap_is_exact_and_null_envelope_is_absent() {
    let (_, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = cfg_for(&grant, &aud).with_clock(move || now);
    let raw = |n: usize| {
        let pad = n - r#"{"pad":""}"#.len();
        format!(r#"{{"pad":"{}"}}"#, "x".repeat(pad))
    };
    let at = raw(MAX_ARTIFACT_BYTES);
    assert_eq!(at.len(), MAX_ARTIFACT_BYTES);
    let r = verify_request(Some(&URL_SAFE_NO_PAD.encode(at.as_bytes())), None, &cfg);
    assert_eq!((r.status, r.error), (401, Some("invalid_request")));
    assert_eq!(r.description, "the PCActn carries no grant_ref"); // parsed fine: NOT the size error
    let over = raw(MAX_ARTIFACT_BYTES + 1);
    let r = verify_request(Some(&URL_SAFE_NO_PAD.encode(over.as_bytes())), None, &cfg);
    assert_eq!(r.status, 401);
    assert_eq!(r.description, format!("PCA-Action is not a valid PCActn: {ARTIFACT_SIZE_REASON}"));
    // body envelope with a null pcactn is "absent"
    let r = verify_request(None, Some(br#"{"pcactn":null}"#), &cfg);
    assert_eq!(r.description, "no PCA-Action header and no {\"pcactn\": ...} in the body");
    let r = verify_request(None, Some(br#"{"other":1}"#), &cfg);
    assert_eq!(r.description, "no PCA-Action header and no {\"pcactn\": ...} in the body");
    let r = verify_request(None, Some(b"nope"), &cfg);
    assert_eq!(r.description, "no PCA-Action header and the body is not JSON");
    let r = verify_request(None, None, &cfg);
    assert_eq!(r.description, "no PCA-Action header or body supplied");
    let r = verify_request(Some("!!"), None, &cfg);
    assert_eq!(r.description, "PCA-Action is not valid base64url");
    let r = verify_request(Some(&URL_SAFE_NO_PAD.encode([0xffu8, 0xfe])), None, &cfg);
    assert_eq!(r.description, "PCA-Action does not decode to UTF-8 JSON");
    let r = verify_request(Some(&URL_SAFE_NO_PAD.encode(b"{")), None, &cfg);
    assert!(r.description.starts_with("PCA-Action is not a valid PCActn: strict JSON"), "{}", r.description);
    // an empty header falls through to the body
    let r = verify_request(Some(""), None, &cfg);
    assert_eq!(r.description, "no PCA-Action header or body supplied");
}

#[test]
fn json_body_and_challenge_shapes() {
    let (p, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = cfg_for(&grant, &aud).with_clock(move || now);
    let ok = verify_request(Some(&header_for(&p)), None, &cfg);
    let b = ok.json_body();
    assert_eq!(b["ok"], json!(true));
    assert_eq!(b["allow"], json!(true));
    assert_eq!(b["reason"], json!(""));
    assert_eq!(b["checks"]["wire"], json!(true));
    assert!(b.get("error").is_none());
    let bad = verify_request(Some(&header_for(&p)), None, &cfg_for(&grant, "other").with_clock(move || now));
    let b = bad.json_body();
    assert_eq!(b["error"], json!("insufficient_authority"));
    assert_eq!(b["error_description"], json!(bad.description));
    assert_eq!(b["allow"], json!(false));
    assert_eq!(b["checks"]["audience"], json!(false));
    assert!(b.get("ok").is_none());
    let un = verify_request(None, None, &cfg);
    let b = un.json_body();
    assert_eq!(b, json!({"error": "invalid_request", "error_description": "no PCA-Action header or body supplied"}));
    assert_eq!(un.www_authenticate().unwrap(), "PCA realm=\"pca\", error=\"invalid_request\", error_description=\"no PCA-Action header or body supplied\"");
    let q = verify_request(Some("!!"), None, &cfg_for(&grant, "a\"b\\c"));
    assert!(q.www_authenticate().is_some());
}

fn req(h: Option<String>, body: Vec<u8>) -> Request {
    let mut b = Request::builder().uri("/x").method("POST");
    if let Some(h) = h {
        b = b.header(PCA_ACTION_HEADER, h);
    }
    b.body(Body::from(body)).unwrap()
}

#[test]
fn layer_service_responses_are_real() {
    let (p, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = cfg_for(&grant, &aud).with_clock(move || now);
    let mut svc = PcaLayer::new(cfg.clone()).layer(Echo);
    let ok = block_on(svc.call(req(Some(header_for(&p)), vec![]))).unwrap();
    assert_eq!(ok.status(), StatusCode::IM_A_TEAPOT);
    let deny = block_on(svc.call(req(None, vec![]))).unwrap();
    assert_eq!(deny.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(deny.headers()[header::WWW_AUTHENTICATE], "PCA realm=\"pca\", error=\"invalid_request\", error_description=\"no PCA-Action header and the body is not JSON\"");
    assert_eq!(deny.headers()[header::CONTENT_TYPE], "application/json");
    let body = block_on(axum::body::to_bytes(deny.into_body(), 1 << 20)).unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], json!("invalid_request"));
    // body envelope through the service
    let env = serde_json::to_vec(&json!({"pcactn": p})).unwrap();
    assert_eq!(block_on(svc.call(req(None, env))).unwrap().status(), StatusCode::IM_A_TEAPOT);
    // 413 for an oversized body
    let mut small = PcaLayer::new(cfg.with_body_limit(8)).layer(Echo);
    let big = block_on(small.call(req(None, vec![b'x'; 100]))).unwrap();
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // 403 carries the verdict
    let (_, g2, now2, _) = vector("valid-in-plan-action");
    let mut svc2 = PcaLayer::new(cfg_for(&g2, "other").with_clock(move || now2)).layer(Echo);
    let f = block_on(svc2.call(req(Some(header_for(&p)), vec![]))).unwrap();
    assert_eq!(f.status(), StatusCode::FORBIDDEN);
    assert!(f.headers()[header::WWW_AUTHENTICATE].to_str().unwrap().contains("insufficient_authority"));
}

#[test]
fn from_fn_guard_dispatches_and_denies() {
    use axum::{middleware, routing::post, Router};
    let (p, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = cfg_for(&grant, &aud).with_clock(move || now);
    async fn h(req: Request) -> StatusCode {
        if req.extensions().get::<PcaAction>().is_some() && req.extensions().get::<atlas_pca::Verdict>().is_some() {
            StatusCode::IM_A_TEAPOT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
    let mut app: Router = Router::new().route("/x", post(h)).layer(middleware::from_fn_with_state(cfg, pca_guard));
    let ok = block_on(Service::call(&mut app, req(Some(header_for(&p)), vec![]))).unwrap();
    assert_eq!(ok.status(), StatusCode::IM_A_TEAPOT);
    let deny = block_on(Service::call(&mut app, req(None, vec![]))).unwrap();
    assert_eq!(deny.status(), StatusCode::UNAUTHORIZED);
    assert!(deny.headers().contains_key(header::WWW_AUTHENTICATE));
}

struct Gate {
    ready_after: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Clone for Gate {
    fn clone(&self) -> Self {
        Gate { ready_after: self.ready_after.clone() }
    }
}
impl Service<Request> for Gate {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        if self.ready_after.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn call(&mut self, _: Request) -> Self::Future {
        ready(Ok(StatusCode::OK.into_response()))
    }
}

#[test]
fn poll_ready_propagates_the_inner_state() {
    let (_, grant, _, aud) = vector("valid-in-plan-action");
    let gate = Gate { ready_after: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)) };
    let mut svc = PcaLayer::new(cfg_for(&grant, &aud)).layer(gate);
    let waker = futures_noop();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(svc.poll_ready(&mut cx), Poll::Pending));
    assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
}

fn futures_noop() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}
