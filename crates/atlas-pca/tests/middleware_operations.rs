//! The axum guard hands an allowed request's authorization to the operation executor: at most once, answered from the record
//! on a retry, and the outcome maps to an HTTP status.
#![cfg(feature = "axum")]

use std::sync::Arc;

use atlas_pca::middleware::{authorize_request, operation_response, GuardConfig};
use atlas_pca::{canonicalize_strict, AuthorizeOptions, ExecuteOptions, ExecuteOutcome, MemoryOperationStore, MemoryStateStore, Operation, PlanRegistry};
use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

#[test]
fn an_allowed_request_executes_once_and_a_retry_is_answered_from_the_record() {
    let d = fixtures();
    let (grant, s) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let now = d["now"].as_i64().unwrap();
    let header = URL_SAFE_NO_PAD.encode(canonicalize_strict(&s["pcactn"]).unwrap().as_bytes());
    let cfg = GuardConfig::new(d["audience"].as_str().unwrap().to_string(), move |_: &str| Some(grant.clone()))
        .with_clock(move || now)
        .with_authorize(AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)).with_plans(Arc::new(PlanRegistry::new())))
        .with_operation({
            let op = op.clone();
            move |_, _| Some(op.clone())
        });
    let store = MemoryOperationStore::new();
    // the fixture action is irreversible, so a re-check (revocation, expiry, approval) is required before it runs
    let recheck = |_: &atlas_pca::ExecutionHandle| Ok::<(), String>(());
    let clock = move || now;
    let opts = ExecuteOptions { store: Some(&store), recheck: Some(&recheck), now: Some(&clock), ..Default::default() };
    let calls = std::cell::Cell::new(0);

    let guard = authorize_request(Some(&header), None, Some(op.clone()), &cfg);
    assert!(guard.allow, "{}", guard.description);
    let first = guard.execute(&opts, |h| {
        calls.set(calls.get() + 1);
        Ok(json!({"key": h.idempotency_key}))
    });
    assert!(matches!(first, ExecuteOutcome::Committed { replayed: false, recorded: true, .. }), "{first:?}");
    assert_eq!(operation_response(&first).status(), StatusCode::OK);

    // the same authorization executed again (a double submit of the allowed result) never runs the function again
    let again = guard.execute(&opts, |_| {
        calls.set(calls.get() + 1);
        Ok(json!(null))
    });
    assert!(matches!(again, ExecuteOutcome::Committed { replayed: true, .. }), "{again:?}");
    assert_eq!(calls.get(), 1);

    // the second presentation of the PCActn is a replay denial from authorize
    let retry = authorize_request(Some(&header), None, Some(op), &cfg);
    assert!(!retry.allow);
    assert_eq!(
        operation_response(&retry.execute(&opts, |_| Ok(json!(1)))).status(),
        StatusCode::FORBIDDEN,
        "a denied request never executes"
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn outcomes_map_to_statuses() {
    let id = || "op".to_string();
    let cases = [
        (ExecuteOutcome::Failed { operation_id: id(), error: "x".into(), replayed: false }, StatusCode::INTERNAL_SERVER_ERROR),
        (ExecuteOutcome::Aborted { operation_id: id(), reason: "x".into(), replayed: true }, StatusCode::CONFLICT),
        (ExecuteOutcome::Pending { operation_id: id() }, StatusCode::CONFLICT),
        (ExecuteOutcome::Uncertain { operation_id: id(), reason: "x".into() }, StatusCode::CONFLICT),
        (ExecuteOutcome::Refused { reason: "x".into() }, StatusCode::FORBIDDEN),
    ];
    for (o, want) in cases {
        assert_eq!(operation_response(&o).status(), want, "{o:?}");
    }
}
