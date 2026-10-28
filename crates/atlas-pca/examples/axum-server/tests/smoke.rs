//! End to end through the router: a valid proof is allowed once; the same proof again, and a request without one, are
//! refused with a `doc` link.
use atlas_pca::protect::{protect, ProtectOptions};
use atlas_pca::{canonicalize_strict, strict_parse};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;

const DOCS: &str = "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md";

async fn post(app: &axum::Router, header: Option<&str>, body: &Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method("POST").uri("/refunds").header("content-type", "application/json");
    if let Some(h) = header {
        req = req.header("pca-action", h);
    }
    let res = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn allows_a_valid_proof_once_and_refuses_the_rest_with_a_doc_link() {
    // the shared authorize fixture: a proof for payments.send on payments/acme with {amount: 50, currency: usd}
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let (grant, step) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    let (now, audience) = (d["now"].as_i64().unwrap(), d["audience"].as_str().unwrap());
    let header = URL_SAFE_NO_PAD.encode(canonicalize_strict(&step["pcactn"]).unwrap().as_bytes());
    let body = json!({ "amount": 50, "currency": "usd" });

    // the same wiring as axum_server_example::guard, with a pinned clock so the fixture proof is inside its window
    let p = protect(ProtectOptions::new(audience, vec![grant], axum_server_example::refund_operation).clock(move || now));
    let app = axum_server_example::app(&p);

    let (status, out) = post(&app, Some(&header), &body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out, json!({ "refunded": 50, "currency": "usd" }));

    // the same proof again is a replay
    let (status, out) = post(&app, Some(&header), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(out["doc"], format!("{DOCS}#replay"));

    // a proof for $50 does not execute $400 (a fresh server, so replay cannot be the reason)
    let p = protect(ProtectOptions::new(audience, vec![d["cases"][0]["grant"].clone()], axum_server_example::refund_operation).clock(move || now));
    let (status, out) = post(&axum_server_example::app(&p), Some(&header), &json!({ "amount": 400, "currency": "usd" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(out["doc"].as_str().unwrap().starts_with(DOCS), "{out}");

    // no proof at all
    let (status, out) = post(&app, None, &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(out["doc"].as_str().unwrap().starts_with(DOCS), "{out}");
}
