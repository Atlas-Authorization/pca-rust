//! The principal's hash-chained receipt log.
use atlas_pca::receipt_log::*;
use atlas_pca::serde_json::{json, Value};

fn act(verb: &str, iat: i64) -> Value {
    json!({"action": {"verb": verb, "resource": "r"}, "iat": iat, "exp": iat + 1})
}

#[test]
fn a_log_chains_and_the_head_commits_to_it() {
    let ok = json!({"allow": true, "checks": {"audience": "pass"}});
    let log = append_receipt(&[], &act("a", 5), &ok, None).unwrap();
    let log = append_receipt(&log, &act("b", 6), &json!({"allow": false}), Some(99)).unwrap();
    assert_eq!(
        (log[0]["seq"].clone(), log[0]["prev"].clone(), log[0]["at"].clone(), log[0]["outcome"].clone()),
        (json!(0), json!(""), json!(5), json!("allow"))
    );
    assert_eq!((log[1]["seq"].clone(), log[1]["at"].clone(), log[1]["outcome"].clone()), (json!(1), json!(99), json!("deny")));
    assert_eq!(log[1]["prev"], log[0]["hash"]);
    assert!(log[1].get("checks").is_none());
    assert_eq!(receipt_head(&log), log[1]["hash"].as_str().unwrap());
    assert_eq!(receipt_head(&[]), "");
    assert_eq!(verify_receipt_chain(&log), Ok(()));
    assert_eq!(verify_receipt_chain(&[]), Ok(()));
}

#[test]
fn every_tamper_names_the_broken_link() {
    let log = append_receipt(&append_receipt(&[], &act("a", 5), &json!({"allow": true}), None).unwrap(), &act("b", 6), &json!({"allow": true}), None).unwrap();
    let mut t = log.clone();
    t[0]["verb"] = json!("evil");
    assert_eq!(verify_receipt_chain(&t).unwrap_err(), (json!(0), "hash mismatch at seq 0 (tampered body)".to_string()));
    assert_eq!(verify_receipt_chain(&[log[1].clone()]).unwrap_err().1, "seq 1 out of order (expected 0)");
    let mut t = log.clone();
    t[1]["prev"] = json!("x");
    assert_eq!(verify_receipt_chain(&t).unwrap_err().1, "prev link mismatch at seq 1");
    assert_eq!(verify_receipt_chain(&[log[0].clone(), log[0].clone()]).unwrap_err().1, "seq 0 out of order (expected 1)");
}
