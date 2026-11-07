//! k05 kill tests pinned to packages/pca/src/obligations.ts (FIELD_RE, log.sink, MAX_OBLIGATIONS after merging).
use super::*;

#[test]
fn field_paths_start_with_a_letter_or_underscore() {
    for good in ["a", "_", "_a1", "A.b_c"] {
        assert!(field_ok(good), "{good}");
    }
    for bad in ["1a", "-a", "a.1b", ""] {
        assert!(!field_ok(bad), "{bad}");
    }
}

#[test]
fn a_log_sink_is_checked_only_for_log() {
    let p = |x: Value| x.as_object().unwrap().clone();
    let reason = "log.sink must be a non-empty string of at most 128 characters".to_string();
    assert_eq!(params_error("log", &p(json!({"sink": ""}))), Some(reason.clone()));
    assert_eq!(params_error("log", &p(json!({"sink": "s".repeat(129)}))), Some(reason));
    assert_eq!(params_error("log", &p(json!({"sink": "s"}))), None);
    assert_eq!(params_error("log", &p(json!({}))), None);
    // another kind that holds no sink is not refused by the log clause
    assert_eq!(params_error("require_receipt", &p(json!({}))), None);
}

#[test]
fn sixteen_merged_obligations_are_the_limit() {
    let list = |from: i32, to: i32| Value::Array((from..to).map(|i| json!({"kind": "notify", "params": {"to": format!("t{i}")}})).collect());
    assert_eq!(merge_obligations(&[list(0, 8), list(8, 16)]).map(|m| m.len()), Ok(16));
    assert_eq!(merge_obligations(&[list(0, 8), list(8, 17)]), Err("more than 16 obligations after merging".to_string()));
}
