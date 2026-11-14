//! F6: an obligation list that is present but JSON `null` is malformed (obligations.ts `obligationsError`: only `undefined` is the
//! empty list), in the validator, the merge, the PEP gate and the outcome check.
use atlas_pca::obligations::*;
use atlas_pca::serde_json::{json, Value};

const NOT_ARRAY: &str = "obligations must be an array";

#[test]
fn a_present_null_is_refused_and_an_absent_list_is_empty() {
    assert_eq!(obligations_error(&Value::Null).as_deref(), Some(NOT_ARRAY));
    assert_eq!(obligations_error_opt(Some(&Value::Null)).as_deref(), Some(NOT_ARRAY));
    assert_eq!(obligations_error_opt(None), None);
    assert_eq!(obligations_error(&json!([])), None);
    for bad in [json!("x"), json!({}), json!(0), json!(false)] {
        assert_eq!(obligations_error(&bad).as_deref(), Some(NOT_ARRAY), "{bad}");
    }
}

#[test]
fn the_merge_refuses_a_null_input_and_skips_an_absent_one() {
    assert_eq!(merge_obligations(&[json!([]), Value::Null]), Err(NOT_ARRAY.to_string()));
    let kept = json!([{"kind": "require_receipt"}]);
    assert_eq!(merge_obligations_opt(&[Some(&json!([])), None, Some(&kept)]), Ok(vec![json!({"kind": "require_receipt"})]));
    assert_eq!(merge_obligations_opt(&[Some(&Value::Null)]), Err(NOT_ARRAY.to_string()));
    assert_eq!(merge_obligations_opt(&[]), Ok(vec![]));
}

#[test]
fn the_gate_denies_a_null_list_and_allows_an_absent_one() {
    let supported = json!(["require_receipt"]);
    let null = pep_obligation_gate("allow", false, &Value::Null, &supported);
    assert_eq!((null.decision, null.perform.len(), null.unsupported.len()), ("deny", 0, 0));
    assert_eq!(pep_obligation_gate_opt("allow", false, Some(&Value::Null), &supported).decision, "deny");
    let absent = pep_obligation_gate_opt("allow", false, None, &supported);
    assert_eq!((absent.decision, absent.perform.len()), ("allow", 0));
    let listed = pep_obligation_gate_opt("allow", false, Some(&json!([{"kind": "require_receipt"}])), &supported);
    assert_eq!((listed.decision, listed.perform.len()), ("allow", 1));
}

#[test]
fn the_outcome_check_treats_null_as_malformed_and_absent_as_empty() {
    let ok = obligation_outcome_opt(None, &json!([]), &json!(10));
    assert_eq!((ok.outcome, ok.overdue.len(), ok.status), ("ok", 0, None));
    let null = obligation_outcome(&Value::Null, &json!([]), &json!(10));
    assert_eq!((null.outcome, null.status), ("escalate", Some("obligation_unmet")));
}
