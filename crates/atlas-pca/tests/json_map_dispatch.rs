//! The JSON object lookups the verifier relies on, under the crate's real serde_json features (`preserve_order`, so
//! `Map` is an IndexMap). This is the behaviour the Kani harness `json_value_get_dispatch` stated; that harness cannot
//! run on a 16 GB runner since `Map` became an IndexMap (hashbrown insert exhausts memory), so it is checked here
//! exhaustively over the same abstract value kinds, plus every PCActn field name and the order-preservation the crate
//! depends on.
use serde_json::{Map, Number, Value};

const KEYS: [&str; 8] = ["id", "ver", "aud", "iat", "exp", "counter", "grant_ref", "cap_chain"];
const ABSENT: [&str; 6] = ["plan", "action", "alg", "pq_pk", "sig", "pq_sig"];

fn vals() -> Vec<Value> {
    let mut v = vec![Value::Null, Value::String("r".into()), Value::String(String::new())];
    for n in [i64::MIN, -1, 0, 1, i64::MAX] { v.push(Value::Number(Number::from(n))); }
    v.push(Value::Number(Number::from(u64::MAX)));
    v
}

#[test]
fn get_returns_exactly_the_stored_value_or_none() {
    for key in KEYS {
        for v in vals() {
            for present in [false, true] {
                let mut m = Map::new();
                if present { m.insert(key.to_string(), v.clone()); }
                let o = Value::Object(m);
                match o.get(key) {
                    Some(got) => { assert!(present, "{key}: found without insert"); assert_eq!(got, &v); }
                    None => assert!(!present, "{key}: stored value not found"),
                }
                for other in KEYS.iter().chain(ABSENT.iter()).filter(|k| **k != key) {
                    assert!(o.get(*other).is_none(), "{key}: get({other}) must be None");
                }
            }
        }
    }
}

#[test]
fn non_objects_have_no_fields() {
    for v in vals() {
        for key in KEYS { assert!(v.get(key).is_none()); }
    }
}

#[test]
fn every_field_together_each_found_and_order_kept() {
    let vs = vals();
    let mut m = Map::new();
    for (i, key) in KEYS.iter().enumerate() { m.insert(key.to_string(), vs[i % vs.len()].clone()); }
    let o = Value::Object(m);
    for (i, key) in KEYS.iter().enumerate() { assert_eq!(o.get(*key), Some(&vs[i % vs.len()])); }
    for key in ABSENT { assert!(o.get(key).is_none()); }
    // preserve_order: iteration is insertion order (violations are reported in the reference's key order)
    let order: Vec<&str> = o.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(order, KEYS);
    // a duplicate key replaces the value in place, never adds a second entry
    let mut m2 = o.as_object().unwrap().clone();
    m2.insert("iat".to_string(), Value::Null);
    assert_eq!(m2.len(), KEYS.len());
    assert_eq!(m2.get("iat"), Some(&Value::Null));
}
