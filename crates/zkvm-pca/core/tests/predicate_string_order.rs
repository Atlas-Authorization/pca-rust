//! String order of the lt/lte/gt/gte predicates is the byte order of the UTF-8 encoding (== code point order).
//! The vectors are shared with the TypeScript reference (packages/pca/src/predicate-string-order.test.ts).
use pca_zkvm_core::predicates::{evaluate_predicates, Ctx};
use serde_json::{json, Value};

const TABLE: &str = include_str!("../../../../packages/pca-conformance/predicate-string-order.json");

fn holds(op: &str, field: &str, operand: &str) -> bool {
    let root = json!({"action": {"verb": "v", "resource": "/r", "params": {"s": field}}, "subject": {}, "env": {}});
    let pred = json!({"verb": "v", "resource": "/r", "where": [{"field": "action.params.s", "op": op, "value": operand}]});
    evaluate_predicates(&[pred], &Ctx::new(&root)).allowed
}

#[test]
fn shared_vectors_agree_with_the_utf8_byte_order() {
    let doc: Value = serde_json::from_str(TABLE).expect("vector table parses");
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 20);
    for v in vectors {
        let (name, a, b) = (v["name"].as_str().unwrap(), v["a"].as_str().unwrap(), v["b"].as_str().unwrap());
        let cmp = v["cmp"].as_i64().unwrap();
        assert_eq!(holds("lt", a, b), cmp < 0, "{name}: lt");
        assert_eq!(holds("lte", a, b), cmp <= 0, "{name}: lte");
        assert_eq!(holds("gt", a, b), cmp > 0, "{name}: gt");
        assert_eq!(holds("gte", a, b), cmp >= 0, "{name}: gte");
    }
}
