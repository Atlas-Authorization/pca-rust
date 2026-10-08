//! Tests for the tower/axum PCA middleware. Compiled only with `--features axum`; without the
//! feature the whole file is empty. The valid-PCActn fixtures are the genuinely-signed conformance
//! vectors, loaded with the same sanitiser the core conformance harness uses.
#![cfg(feature = "axum")]

use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use atlas_pca::middleware::{
    verify_request, GuardConfig, PcaAction, PcaLayer, PCA_ACTION_HEADER,
};
use atlas_pca::{canonicalize_strict, Verdict};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use tower_layer::Layer;
use tower_service::Service;

// ---- conformance-vector loader (mirrors tests/conformance.rs) ---------------------------

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");
const LONE: char = '\u{10FFFF}';

fn sanitize_lone_surrogates(text: &str) -> String {
    let cs: Vec<char> = text.chars().collect();
    let hex = |at: usize| -> Option<u32> {
        let s: String = cs.get(at..at + 4)?.iter().collect();
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if !in_str {
            in_str = c == '"';
            out.push(c);
            i += 1;
        } else if c == '"' {
            in_str = false;
            out.push(c);
            i += 1;
        } else if c == '\\' {
            if cs.get(i + 1) == Some(&'u') {
                match hex(i + 2) {
                    Some(hi) if (0xD800..=0xDBFF).contains(&hi) => {
                        let paired = cs.get(i + 6) == Some(&'\\')
                            && cs.get(i + 7) == Some(&'u')
                            && hex(i + 8).map_or(false, |lo| (0xDC00..=0xDFFF).contains(&lo));
                        if paired {
                            out.extend(&cs[i..i + 12]);
                            i += 12;
                        } else {
                            out.push(LONE);
                            i += 6;
                        }
                    }
                    Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                        out.push(LONE);
                        i += 6;
                    }
                    _ => {
                        out.extend(&cs[i..(i + 2).min(cs.len())]);
                        i += 2;
                    }
                }
            } else {
                out.extend(&cs[i..(i + 2).min(cs.len())]);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn load(name: &str) -> Value {
    let b = std::fs::read_to_string(format!("{DIR}{name}")).expect("read file");
    serde_json::from_str(&sanitize_lone_surrogates(&b)).expect("parse json")
}

/// Pull a named vector; returns (pcactn, grant, now, aud).
fn vector(name: &str) -> (Value, Value, i64, String) {
    let doc = load("vectors.json");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("vector {name} not found"))
        .clone();
    let now = v["context"]["now"].as_i64().unwrap();
    let aud = v["context"]["aud"].as_str().unwrap().to_string();
    (v["pcactn"].clone(), v["grant"].clone(), now, aud)
}

/// base64url(strict-canonical JSON) of the PCActn — a valid `PCA-Action` header value.
fn header_for(pcactn: &Value) -> String {
    URL_SAFE_NO_PAD.encode(canonicalize_strict(pcactn).expect("canonical").as_bytes())
}

fn config_for(grant: &Value, aud: &str, now: i64) -> GuardConfig {
    let grant = grant.clone();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    GuardConfig::new(aud.to_string(), move |grant_ref: &str| {
        if grant_ref == grant_id {
            Some(grant.clone())
        } else {
            None
        }
    })
    .with_clock(move || now)
}

// ---- verify_request: the four required cases --------------------------------------------

#[test]
fn valid_header_allows_and_exposes_the_action() {
    let (pcactn, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = config_for(&grant, &aud, now);
    let header = header_for(&pcactn);

    let result = verify_request(Some(&header), None, &cfg);

    assert!(result.is_allow(), "expected allow, got: {}", result.description);
    assert_eq!(result.status, 200);
    assert!(result.www_authenticate().is_none());
    let verdict = result.verdict.as_ref().expect("verdict present");
    assert!(verdict.allow);
    assert!(verdict.checks.values().all(|v| *v));
    // The verified action is exposed for downstream handlers.
    assert_eq!(result.pcactn.as_ref().and_then(|p| p.get("grant_ref")), pcactn.get("grant_ref"));
}

#[test]
fn absent_proof_is_401_with_www_authenticate() {
    let (_, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = config_for(&grant, &aud, now);

    let result = verify_request(None, None, &cfg);

    assert!(!result.is_allow());
    assert_eq!(result.status, 401);
    let challenge = result.www_authenticate().expect("challenge header");
    assert!(challenge.starts_with("PCA realm=\"pca\""), "got: {challenge}");
    assert!(challenge.contains("error="));
}

#[test]
fn unknown_grant_is_401() {
    let (pcactn, _grant, now, aud) = vector("valid-in-plan-action");
    // A resolver that knows no grants at all.
    let cfg = GuardConfig::new(aud, |_: &str| None).with_clock(move || now);
    let header = header_for(&pcactn);

    let result = verify_request(Some(&header), None, &cfg);

    assert!(!result.is_allow());
    assert_eq!(result.status, 401);
    assert_eq!(result.error, Some("unknown_grant"));
}

#[test]
fn wrong_audience_is_403_denying_verdict() {
    let (pcactn, grant, now, _aud) = vector("valid-in-plan-action");
    // Correct grant and clock, but this resource server has a different audience id.
    let cfg = config_for(&grant, "rs-some-other-service", now);
    let header = header_for(&pcactn);

    let result = verify_request(Some(&header), None, &cfg);

    assert!(!result.is_allow());
    assert_eq!(result.status, 403);
    let verdict = result.verdict.as_ref().expect("a verdict was produced");
    assert_eq!(verdict.checks.get("audience"), Some(&false));
}

#[test]
fn body_envelope_path_also_works() {
    let (pcactn, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = config_for(&grant, &aud, now);
    let envelope = serde_json::json!({ "pcactn": pcactn });
    let body = serde_json::to_vec(&envelope).unwrap();

    let result = verify_request(None, Some(&body), &cfg);

    assert!(result.is_allow(), "expected allow, got: {}", result.description);
}

// ---- end-to-end through the tower Layer/Service -----------------------------------------

/// A minimal inner service: 200 iff the guard inserted both the PCActn and the verdict.
#[derive(Clone)]
struct InnerEcho;

impl Service<Request> for InnerEcho {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let saw_action = req.extensions().get::<PcaAction>().is_some();
        let saw_verdict = req.extensions().get::<Verdict>().is_some();
        let status = if saw_action && saw_verdict {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        ready(Ok(status.into_response()))
    }
}

/// Dependency-free executor for the in-memory middleware future (resolves without real I/O).
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

#[test]
fn tower_service_runs_inner_on_a_valid_header() {
    let (pcactn, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = config_for(&grant, &aud, now);
    let header = header_for(&pcactn);

    let mut svc = PcaLayer::new(cfg).layer(InnerEcho);
    let req = Request::builder()
        .uri("/orders")
        .header(PCA_ACTION_HEADER, header)
        .body(Body::empty())
        .unwrap();

    let resp = block_on(svc.call(req)).expect("infallible");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn tower_service_rejects_a_missing_header() {
    let (_, grant, now, aud) = vector("valid-in-plan-action");
    let cfg = config_for(&grant, &aud, now);

    let mut svc = PcaLayer::new(cfg).layer(InnerEcho);
    let req = Request::builder().uri("/orders").body(Body::empty()).unwrap();

    let resp = block_on(svc.call(req)).expect("infallible");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key(axum::http::header::WWW_AUTHENTICATE));
}
