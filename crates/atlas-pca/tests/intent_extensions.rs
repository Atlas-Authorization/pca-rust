//! `INTENT_WIRE_EXTENSION` and `INTENT_EXTENSIONS` are the very functions the core verifier runs: a malformed slot is described, an absent
//! intent without a policy is not reported.
use atlas_pca::serde_json::json;
use atlas_pca::{INTENT_EXTENSIONS, INTENT_WIRE_EXTENSION};

#[test]
fn the_wire_validators_describe_a_malformed_slot() {
    assert_eq!((INTENT_WIRE_EXTENSION.intent)(&json!("x")).as_deref(), Some("'intent' must be an object"));
    assert!((INTENT_WIRE_EXTENSION.intent_session)(&json!(1)).is_some());
    assert!((INTENT_WIRE_EXTENSION.fresh_at)(&json!(1)).is_some());
    assert!((INTENT_EXTENSIONS.wire.intent)(&json!({})).is_some());
}

#[test]
fn the_decisions_are_the_core_ones() {
    assert!((INTENT_EXTENSIONS.intent_binding)(None, &json!({}), None, None).is_none());
    assert!((INTENT_EXTENSIONS.intent_v2)(&json!({}), &json!({}), None, 0).checks.is_empty());
    assert!(matches!((INTENT_EXTENSIONS.fresh_at)(None, None, 0), atlas_pca::fresh_at::FreshAtCheck::None));
}
