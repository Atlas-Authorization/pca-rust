//! The axum guard on top of `authorize` carries the K5 workflow gate: the request's step comes from the config callback, else the
//! JSON body member `workflow`. Cases are the first of packages/pca/conformance/authorize-workflow-fixtures.json.
#![cfg(feature = "axum")]

use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use atlas_pca::middleware::{authorize_request, GuardConfig, PcaLayer, PCA_ACTION_HEADER};
use atlas_pca::{canonicalize_strict, AuthorizeOptions, MemoryStateStore, Operation, WorkflowCall, WorkflowGate};
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use tower_layer::Layer;
use tower_service::Service;

fn fixtures() -> Value {
    let path = format!("{}/../../conformance/authorize-workflow-fixtures.json", env!("CARGO_MANIFEST_DIR"));
    atlas_pca::strict_parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))).expect("parse")
}

fn case(f: &Value, name: &str) -> Value {
    f["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no case {name}")).clone()
}

/// A guard over the fixture grant; `gate` None leaves the workflow option off. Every config of one case shares `store`.
fn config(f: &Value, store: &Arc<MemoryStateStore>, gate: Option<bool>) -> GuardConfig {
    let grant = f["grant"].clone();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    let plan = f["plan"].clone();
    let now = f["now"].as_i64().unwrap();
    let mut opts = AuthorizeOptions::new(store.clone(), |_: &Value, _: &Value| Ok(false))
        .with_plan(None)
        .with_context(move |_| Ok(Some(json!({ "plan": plan, "plan_authorized": true }))));
    if let Some(required) = gate {
        opts = opts.with_workflow(WorkflowGate { principal: f["principal"].as_str().unwrap().into(), rs_signer: f["rs_signer"].as_str().unwrap().into(), required });
    }
    GuardConfig::new(f["audience"].as_str().unwrap().to_string(), move |r: &str| if r == grant_id { Some(grant.clone()) } else { None })
        .with_clock(move || now)
        .with_authorize(opts)
}

fn header(pcactn: &Value) -> String {
    URL_SAFE_NO_PAD.encode(canonicalize_strict(pcactn).unwrap().as_bytes())
}

/// Run every step of the case through the body-member path; each result is (status, description).
fn run_body(f: &Value, name: &str, gate: Option<bool>) -> Vec<(u16, String)> {
    let c = case(f, name);
    let store = Arc::new(MemoryStateStore::new());
    let cfg = config(f, &store, gate);
    c["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let body = s.get("workflow").map(|w| json!({ "workflow": w }).to_string());
            let r = authorize_request(Some(&header(&s["pcactn"])), body.as_deref().map(str::as_bytes), Operation::from_json(&s["operation"]), &cfg);
            (r.status, r.description)
        })
        .collect()
}

#[test]
fn a_valid_step_in_the_body_passes() {
    let f = fixtures();
    for (i, (status, why)) in run_body(&f, "pay-after-quote", Some(false)).into_iter().enumerate() {
        assert_eq!(status, 200, "step {i}: {why}");
    }
}

#[test]
fn a_step_violating_an_edge_is_403() {
    let f = fixtures();
    let r = run_body(&f, "amount-over-the-quote", Some(false));
    assert_eq!(r, vec![(403, "workflow: edge_relation (step pay)".to_string())]);
}

#[test]
fn required_and_absent_is_403() {
    let f = fixtures();
    let r = run_body(&f, "workflow-required-but-absent", Some(true));
    assert_eq!(r, vec![(403, "workflow: this call carries no workflow step (fail closed)".to_string())]);
}

#[test]
fn required_and_absent_wins_over_an_unreadable_pcactn() {
    let f = fixtures();
    let cfg = config(&f, &Arc::new(MemoryStateStore::new()), Some(true));
    let op = Operation::from_json(&case(&f, "workflow-required-but-absent")["steps"][0]["operation"]);
    let r = authorize_request(Some("not-a-pcactn"), None, op, &cfg);
    assert_eq!((r.status, r.description.as_str()), (403, "workflow: this call carries no workflow step (fail closed)"));
}

#[test]
fn an_unreadable_pcactn_is_the_guards_401_even_with_a_step() {
    let f = fixtures();
    let c = case(&f, "pay-after-quote");
    let s = &c["steps"][0];
    let cfg = config(&f, &Arc::new(MemoryStateStore::new()), Some(false));
    let body = json!({ "workflow": s["workflow"] }).to_string();
    let r = authorize_request(Some("not-a-pcactn"), Some(body.as_bytes()), Operation::from_json(&s["operation"]), &cfg);
    assert_eq!(r.status, 401, "{}", r.description);
}

#[test]
fn a_malformed_workflow_member_is_refused_not_ignored() {
    let f = fixtures();
    let c = case(&f, "pay-after-quote");
    let s = &c["steps"][0];
    let cfg = config(&f, &Arc::new(MemoryStateStore::new()), Some(false));
    let r = authorize_request(Some(&header(&s["pcactn"])), Some(br#"{"workflow":"x"}"#), Operation::from_json(&s["operation"]), &cfg);
    assert_eq!((r.allow, r.status), (false, 403), "{}", r.description);
}

#[test]
fn without_the_workflow_option_a_body_member_changes_nothing() {
    let f = fixtures();
    let c = case(&f, "amount-over-the-quote");
    let s = &c["steps"][0];
    let cfg = config(&f, &Arc::new(MemoryStateStore::new()), None);
    let body = json!({ "workflow": s["workflow"] }).to_string();
    let r = authorize_request(Some(&header(&s["pcactn"])), Some(body.as_bytes()), Operation::from_json(&s["operation"]), &cfg);
    assert!(r.allow, "{}", r.description);
}

// ---- the live tower layer, with the per-request callback --------------------------------------------------

#[derive(Clone)]
struct Inner;

impl Service<Request> for Inner {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _req: Request) -> Self::Future {
        ready(Ok(StatusCode::OK.into_response()))
    }
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

#[test]
fn the_callback_step_is_admitted_or_refused_by_the_layer() {
    let f = fixtures();
    // a layer needs the request -> operation mapping; the fixture steps share one operation per case, so map by the case's first step
    let ok = layer_with_op(&f, "pay-after-quote", Some(false));
    assert_eq!(ok, vec![StatusCode::OK, StatusCode::OK]);
    assert_eq!(layer_with_op(&f, "amount-over-the-quote", Some(false)), vec![StatusCode::FORBIDDEN]);
    assert_eq!(layer_with_op(&f, "workflow-required-but-absent", Some(true)), vec![StatusCode::FORBIDDEN]);
}

/// Send each step of the case through a `PcaLayer` whose `with_workflow_step` / `with_operation` callbacks hand out the step under test.
fn layer_with_op(f: &Value, name: &str, gate: Option<bool>) -> Vec<StatusCode> {
    let c = case(f, name);
    let current: Arc<Mutex<(Option<WorkflowCall>, Option<Operation>)>> = Arc::new(Mutex::new((None, None)));
    let (cb, ob) = (current.clone(), current.clone());
    let cfg = config(f, &Arc::new(MemoryStateStore::new()), gate)
        .with_workflow_step(move |_, _| cb.lock().unwrap().0.clone())
        .with_operation(move |_, _| ob.lock().unwrap().1.clone());
    let mut svc = PcaLayer::new(cfg).layer(Inner);
    c["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let call = s.get("workflow").map(|w| WorkflowCall {
                commitment: w["commitment"].clone(),
                receipts: w["receipts"].clone(),
                step: w["step"].clone(),
                units: w.get("units").cloned().unwrap_or_else(|| json!({})),
                goal_digest: w.get("goal_digest").cloned().unwrap_or(Value::Null),
            });
            *current.lock().unwrap() = (call, Operation::from_json(&s["operation"]));
            let req = Request::builder().uri("/pay").header(PCA_ACTION_HEADER, header(&s["pcactn"])).body(Body::empty()).unwrap();
            block_on(svc.call(req)).expect("infallible").status()
        })
        .collect()
}
