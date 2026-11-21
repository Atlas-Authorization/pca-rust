//! The tighten-only fold of detector receipts: a valid suspicious receipt lowers, a valid no_finding never changes, an invalid one escalates.
use atlas_pca::agent::KeyPair;
use atlas_pca::dataflow_detectors::*;
use atlas_pca::serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn gw() -> KeyPair {
    KeyPair::from_seed(&[7u8; 32])
}

fn policy(on: &str) -> Value {
    json!({"detectors": [{"id": "lakera", "keys": [{"pk": gw().public}], "on_suspicious": on, "max_age_ms": 60_000}]})
}

fn receipt(verdict: &str, cats: &[&str], iat: i64, content: &str, key: &KeyPair) -> Value {
    sign_detector_receipt(
        &json!({"v": 1, "kind": "pca-detector-receipt", "detector": "lakera", "version": "v2", "input_digest": detector_input_digest(&json!(content)).unwrap(),
            "verdict": verdict, "categories": cats, "iat": iat}),
        key,
    )
    .unwrap()
}

fn run(pol: &Value, receipts: Option<&Value>, now: &Value) -> DetectorOutcome {
    let digests = vec![detector_input_digest(&json!("page")).unwrap()];
    detector_signal(&DetectorInput { receipts, policy: pol, input_digests: &digests, session: None, now })
}

#[test]
fn a_valid_suspicious_receipt_lowers_to_the_policy_action() {
    for on in ["escalate", "deny"] {
        let r = json!([receipt("suspicious", &["prompt_injection"], NOW - 1_000, "page", &gw())]);
        let o = run(&policy(on), Some(&r), &json!(NOW));
        assert_eq!(o.signal, on);
        assert_eq!(o.flagged, vec!["lakera".to_string()]);
        assert_eq!(o.env, json!({"detect": {"lakera": true, "invalid": 0}}));
        assert!(o.rejected.is_empty());
    }
}

#[test]
fn no_finding_is_the_same_as_no_receipt() {
    let none = run(&policy("deny"), None, &json!(NOW));
    let clean = json!([receipt("no_finding", &[], NOW, "page", &gw())]);
    let with = run(&policy("deny"), Some(&clean), &json!(NOW));
    assert_eq!((none.signal, &none.env), ("ok", &json!({"detect": {"lakera": false, "invalid": 0}})));
    assert_eq!(with, none);
}

#[test]
fn every_invalid_receipt_escalates_and_is_never_evidence() {
    let pol = policy("deny");
    let cases = [
        ("unpinned key", receipt("suspicious", &[], NOW, "page", &KeyPair::from_seed(&[8u8; 32])), "no pinned key signed it"),
        ("other content", receipt("suspicious", &[], NOW, "other", &gw()), "about other content"),
        ("from the future", receipt("suspicious", &[], NOW + 1, "page", &gw()), "from the future"),
        ("stale", receipt("suspicious", &[], NOW - 60_001, "page", &gw()), "stale"),
    ];
    for (name, r, why) in cases {
        let o = run(&pol, Some(&json!([r])), &json!(NOW));
        assert_eq!(o.signal, "escalate", "{name}");
        assert!(o.flagged.is_empty(), "{name}");
        assert!(o.rejected[0].1.contains(why), "{name}: {:?}", o.rejected);
        assert_eq!(o.env["detect"]["invalid"], json!(1));
    }
    let o = run(&pol, Some(&json!([{"v": 1}])), &json!(NOW));
    assert!(o.rejected[0].1.starts_with("malformed: "));
    assert_eq!(o.signal, "escalate");
}

#[test]
fn categories_filter_which_receipts_act() {
    let mut pol = policy("deny");
    pol["detectors"][0]["categories"] = json!(["pii"]);
    let other = json!([receipt("suspicious", &["prompt_injection"], NOW, "page", &gw())]);
    assert_eq!(run(&pol, Some(&other), &json!(NOW)).signal, "ok");
    let hit = json!([receipt("suspicious", &["pii", "prompt_injection"], NOW, "page", &gw())]);
    assert_eq!(run(&pol, Some(&hit), &json!(NOW)).signal, "deny");
    let bare = json!([receipt("suspicious", &[], NOW, "page", &gw())]);
    assert_eq!(run(&pol, Some(&bare), &json!(NOW)).signal, "deny", "an empty category list always acts");
}

#[test]
fn a_malformed_policy_or_input_is_refused() {
    let bad = run(&json!({"detectors": [], "x": 1}), None, &json!(NOW));
    assert_eq!((bad.signal, bad.rejected[0].0), ("deny", -1));
    assert_eq!(detector_policy_error(&json!({"detectors": []})), None);
    assert!(detector_policy_error(&json!({"detectors": [{"id": "invalid", "keys": [{"pk": "a"}], "on_suspicious": "deny", "max_age_ms": 1}]}))
        .unwrap()
        .contains("distinct"));
    let dup = json!({"detectors": [{"id": "a", "keys": [{"pk": "k"}], "on_suspicious": "deny", "max_age_ms": 1}, {"id": "a", "keys": [{"pk": "k"}], "on_suspicious": "deny", "max_age_ms": 1}]});
    assert!(detector_policy_error(&dup).is_some());
    assert!(detector_policy_error(&json!({"detectors": [{"id": "a", "keys": [], "on_suspicious": "deny", "max_age_ms": 1}]}))
        .unwrap()
        .contains("keys must hold 1..8"));
    assert!(detector_policy_error(&json!({"detectors": [{"id": "a", "keys": [{"pk": "k"}], "on_suspicious": "ok", "max_age_ms": 1}]}))
        .unwrap()
        .contains("on_suspicious"));
    assert!(detector_policy_error(&json!({"detectors": [{"id": "a", "keys": [{"pk": "k"}], "on_suspicious": "deny", "max_age_ms": 86_400_001}]}))
        .unwrap()
        .contains("max_age_ms"));
    assert_eq!(run(&policy("deny"), Some(&json!("nope")), &json!(NOW)).signal, "escalate");
    assert_eq!(run(&policy("deny"), None, &json!(1.5)).signal, "escalate");
    let many = Value::Array(vec![json!({}); MAX_DETECTOR_RECEIPTS + 1]);
    assert_eq!(run(&policy("deny"), Some(&many), &json!(NOW)).rejected, vec![(-1, "receipt list or clock malformed".to_string())]);
}
