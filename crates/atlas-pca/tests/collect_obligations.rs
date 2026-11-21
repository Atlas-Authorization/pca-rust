//! Policy-side obligation collection: a rule whose condition is true OR undecidable adds its duties (more duties is the tightening
//! direction); only a decidably false one adds nothing.
use atlas_pca::obligations::collect_obligations;
use atlas_pca::serde_json::{json, Value};

fn rules() -> Value {
    json!([
        {"id": "refunds", "when": {"field": "action.verb", "op": "eq", "value": "stripe.refund"}, "obligations": [{"kind": "log", "params": {"sink": "audit"}}]},
        {"id": "pii", "when": {"field": "subject.region", "op": "eq", "value": "eu"}, "obligations": [{"kind": "notify", "params": {"to": "dpo"}}, {"kind": "log", "params": {"sink": "audit"}}]},
    ])
}

fn kinds(r: Result<Vec<Value>, String>) -> Vec<String> {
    r.unwrap().iter().map(|o| o["kind"].as_str().unwrap().to_string()).collect()
}

#[test]
fn true_and_undecidable_rules_add_duties_false_ones_do_not() {
    let r = rules();
    // refunds is true; the subject region is missing, so pii cannot be decided and adds its duties: merged, deduplicated, sorted
    assert_eq!(kinds(collect_obligations(Some(&r), &json!({"action": {"verb": "stripe.refund"}}))), ["log", "notify"]);
    // refunds is decidably false; pii is undecidable
    assert_eq!(kinds(collect_obligations(Some(&r), &json!({"action": {"verb": "files.read"}}))), ["log", "notify"]);
    // both decidably false
    assert!(collect_obligations(Some(&r), &json!({"action": {"verb": "files.read"}, "subject": {"region": "us"}})).unwrap().is_empty());
    // only refunds applies
    assert_eq!(kinds(collect_obligations(Some(&r), &json!({"action": {"verb": "stripe.refund"}, "subject": {"region": "us"}}))), ["log"]);
}

#[test]
fn an_absent_list_is_empty_and_a_malformed_one_is_refused() {
    let ctx = json!({});
    assert!(collect_obligations(None, &ctx).unwrap().is_empty());
    assert_eq!(collect_obligations(Some(&json!({})), &ctx).unwrap_err(), "obligation rules must be an array");
    assert_eq!(collect_obligations(Some(&json!([1])), &ctx).unwrap_err(), "obligation rule 0 is malformed");
    assert_eq!(
        collect_obligations(Some(&json!([{"id": "a", "when": {}, "obligations": [{"kind": "log"}], "x": 1}])), &ctx).unwrap_err(),
        "obligation rule 0 is malformed"
    );
    let one = json!({"id": "a", "when": {"field": "a", "op": "eq", "value": 1}, "obligations": [{"kind": "log"}]});
    assert_eq!(collect_obligations(Some(&json!([one, one])), &ctx).unwrap_err(), "obligation rule id 'a' is a duplicate");
    assert_eq!(
        collect_obligations(Some(&json!([{"id": "a", "when": {}, "obligations": []}])), &ctx).unwrap_err(),
        "obligation rule 'a': obligations must not be empty"
    );
    assert!(collect_obligations(Some(&json!([{"id": "a", "when": {}}])), &ctx).unwrap_err().contains("must not be empty"));
    assert!(collect_obligations(Some(&json!([{"id": "a", "when": {}, "obligations": [{"kind": "bogus"}]}])), &ctx)
        .unwrap_err()
        .starts_with("obligation rule 'a': obligations[0]"));
}
