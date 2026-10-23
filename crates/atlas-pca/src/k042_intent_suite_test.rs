//! The suite seam of the Intent Layer v2 artifacts (intent_suite.rs): the shape rule and the pinned-suite verification,
//! on both sides of every condition.
use super::*;
use serde_json::json;

fn o(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn shape_rule_of_a_v2_artifact() {
    // a classical artifact: a string sig and no PQ members
    assert_eq!(suite_shape_error(&o(json!({"sig": "s"})), "receipt", "receipt.alg: ", "receipt.sig"), None);
    assert_eq!(suite_shape_error(&o(json!({"alg": "ed25519", "sig": "s"})), "receipt", "receipt.alg: ", "receipt.sig"), None);
    // either PQ member alone is enough to refuse a classical artifact
    assert_eq!(suite_shape_error(&o(json!({"sig": "s", "pq_pk": "k"})), "receipt", "receipt.alg: ", "receipt.sig").as_deref(), Some("an ed25519 receipt must not carry pq_pk / pq_sig"));
    assert_eq!(suite_shape_error(&o(json!({"sig": "s", "pq_sig": "q"})), "key set", "alg: ", "sig").as_deref(), Some("an ed25519 key set must not carry pq_pk / pq_sig"));
    assert_eq!(suite_shape_error(&o(json!({"sig": "s", "pq_pk": null})), "receipt", "receipt.alg: ", "receipt.sig").as_deref(), Some("an ed25519 receipt must not carry pq_pk / pq_sig"));
    assert_eq!(suite_shape_error(&o(json!({"sig": "s", "pq_pk": "k", "pq_sig": "q"})), "receipt", "receipt.alg: ", "receipt.sig").as_deref(), Some("an ed25519 receipt must not carry pq_pk / pq_sig"));
    // a missing / non-string sig
    assert_eq!(suite_shape_error(&o(json!({})), "receipt", "receipt.alg: ", "receipt.sig").as_deref(), Some("receipt.sig must be a string"));
    assert_eq!(suite_shape_error(&o(json!({"sig": 5})), "key set", "alg: ", "sig").as_deref(), Some("sig must be a string"));
    assert_eq!(suite_shape_error(&o(json!({"sig": null})), "x", "alg: ", "sig").as_deref(), Some("sig must be a string"));
    // the suite is judged first
    assert_eq!(suite_shape_error(&o(json!({"alg": 5, "sig": "s"})), "r", "alg: ", "sig").as_deref(), Some("alg: alg must be a string"));
    assert!(suite_shape_error(&o(json!({"alg": "rsa", "sig": "s"})), "r", "alg: ", "sig").unwrap().starts_with("alg: unsupported_suite: "));
    // a PQ suite may carry the PQ members
    assert_eq!(suite_shape_error(&o(json!({"alg": "ml-dsa-65", "sig": "s", "pq_pk": "k", "pq_sig": "q"})), "r", "alg: ", "sig"), None);
    assert_eq!(suite_shape_error(&o(json!({"alg": "ml-dsa-65", "sig": "s"})), "r", "alg: ", "sig"), None);
}

#[test]
fn suite_resolution_and_binding() {
    assert_eq!(suite_of(None).unwrap().alg, "ed25519");
    assert!(!suite_of(None).unwrap().needs_pq_pk);
    assert!(suite_of(Some(&json!("ml-dsa-65"))).unwrap().needs_pq_pk);
    assert!(suite_of(Some(&json!("hybrid-ed25519-ml-dsa-65"))).unwrap().needs_pq_pk);
    assert_eq!(suite_of(Some(&json!(1))).unwrap_err(), "alg must be a string");
    assert_eq!(suite_of(Some(&Value::Null)).unwrap_err(), "alg must be a string");
    assert_eq!(suite_of(Some(&json!("rsa"))).unwrap_err(), "unsupported_suite: 'rsa'");
    assert_eq!(optional_alg_error(None), None);
    assert_eq!(optional_alg_error(Some(&json!("ed25519"))), None);
    assert!(optional_alg_error(Some(&json!("rsa"))).is_some());
    assert!(optional_alg_error(Some(&json!(1))).is_some());
    // a classical suite binds nothing; a PQ suite binds alg and pq_pk, and a missing pq_pk is not representable
    let mut base = Map::new();
    assert_eq!(bind_suite_fields(&mut base, None, Some(&json!("k"))), Ok(true));
    assert!(base.is_empty());
    assert_eq!(bind_suite_fields(&mut base, Some(&json!("ml-dsa-65")), Some(&json!("k"))), Ok(true));
    assert_eq!(Value::Object(base.clone()), json!({"alg": "ml-dsa-65", "pq_pk": "k"}));
    let mut base = Map::new();
    assert_eq!(bind_suite_fields(&mut base, Some(&json!("ml-dsa-65")), None), Ok(false));
    assert!(bind_suite_fields(&mut Map::new(), Some(&json!("rsa")), None).is_err());
}

#[test]
fn pinned_pq_verification_fails_closed_before_any_signature_work() {
    let msg = b"m";
    let sig = json!("s");
    let pq = json!("k");
    // the suite the dispatch refuses
    assert!(verify_pinned_suite(Some(&json!("rsa")), "id", None, msg, Some(&sig), None, None).is_err());
    // a PQ suite needs a non-empty artifact pq_pk ...
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", None, msg, Some(&sig), Some(&sig), Some(("id", &pq))), Ok(false));
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&json!(5)), msg, Some(&sig), Some(&sig), Some(("id", &pq))), Ok(false));
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&json!("")), msg, Some(&sig), Some(&sig), Some(("id", &json!("")))), Ok(false));
    // ... and a pin for THIS identity, equal to it
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&pq), msg, Some(&sig), Some(&sig), None), Ok(false));
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&pq), msg, Some(&sig), Some(&sig), Some(("other", &pq))), Ok(false));
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&pq), msg, Some(&sig), Some(&sig), Some(("id", &json!("k2")))), Ok(false));
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&pq), msg, Some(&sig), Some(&sig), Some(("id", &json!(5)))), Ok(false));
    // a pinned key that is not a PQ key does not verify
    assert_eq!(verify_pinned_suite(Some(&json!("ml-dsa-65")), "id", Some(&pq), msg, Some(&sig), Some(&sig), Some(("id", &pq))), Ok(false));
}

#[test]
fn domain_message_is_the_domain_then_the_strict_canonical_body() {
    let body = o(json!({"b": 2, "a": 1}));
    assert_eq!(domain_message("dom\0", body), Some(b"dom\0{\"a\":1,\"b\":2}".to_vec()));
    assert_eq!(domain_message("", o(json!({}))), Some(b"{}".to_vec()));
    assert_eq!(domain_message("d", o(json!({"v": 9007199254740992u64}))), None);
}
