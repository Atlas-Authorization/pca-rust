//! `intent_v2_active` (= TS `intentV2Active`, 9bd00fd38): true iff any v2 check would be reported, a PRESENT but malformed
//! verifier context included (`decide_intent_v2` reports a failing check for it, so a host gating v2 on this helper must not
//! skip enforcement: fail closed).
use pca_zkvm_core::intent_v2::{decide_intent_v2, intent_v2_active, intent_v2_context_error};
use serde_json::{json, Value};

#[test]
fn active_iff_any_v2_check_is_reported_malformed_context_included() {
    let plain = json!({});
    assert!(!intent_v2_active(&plain, None));
    assert!(!intent_v2_active(&plain, Some(&json!({}))));
    assert!(intent_v2_active(&json!({"intent_session": {}}), None));
    assert!(intent_v2_active(&plain, Some(&json!({"policy": {"session": {"require": true}}}))));
    assert!(intent_v2_active(&plain, Some(&json!({"policy": {"schema": {"closed_world": true}}}))));
    assert!(intent_v2_active(&plain, Some(&json!({"policy": {"map": {"require": true}}}))));
    // flags present but false are not active
    assert!(!intent_v2_active(&plain, Some(&json!({"policy": {"session": {"require": false}}}))));

    // a misconfigured verifier: the checks fail closed, so the helper must say active
    let bad = json!({"policy": {"session": {"require": "yes"}}});
    assert!(intent_v2_context_error(Some(&bad)).is_some());
    assert!(intent_v2_active(&plain, Some(&bad)));
    assert!(intent_v2_active(&plain, Some(&json!({"policy": null}))));
    assert!(intent_v2_active(&plain, Some(&json!(5))));
    assert!(intent_v2_active(&plain, Some(&Value::Null)));
}

#[test]
fn malformed_context_is_active_and_the_pipeline_reports_a_failing_check() {
    let bad = json!({"policy": {"session": {"require": "yes"}}});
    assert!(intent_v2_active(&json!({}), Some(&bad)));
    let d = decide_intent_v2(&json!({}), &json!({}), Some(&bad), 0.0);
    assert!(!d.checks.is_empty());
    assert!(!d.all_ok());
}
