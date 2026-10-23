//! Small public-API kill tests (0.4.2 mutation phase): the suite policy on the raw-text entry point, `cap_hash`, the
//! `PCA-Action` header error text and the suite refusal wording.
mod common;
use atlas_pca::*;
use common::*;
use serde_json::{json, Value};

/// A core vector that is admitted, with its context.
fn admitted() -> (Value, Value, i64, String) {
    let core = load("vectors.json");
    for v in core["vectors"].as_array().unwrap() {
        if v["expect"]["allow"] == Value::Bool(true) && v["context"].get("allowed_suites").is_none() && v.get("pcactn_json").is_none() && unsupported_suite(v).is_none() && !has_lone(&v["pcactn"]) {
            return (v["pcactn"].clone(), v["grant"].clone(), v["context"]["now"].as_i64().unwrap(), v["context"]["aud"].as_str().unwrap().to_string());
        }
    }
    panic!("no admitted vector");
}

#[test]
fn the_suite_policy_applies_on_the_raw_text_entry_point() {
    let (p, grant, now, aud) = admitted();
    let text = canonicalize(&p);
    assert!(verify_pcactn_json(&text, &grant, now, &aud).allow);
    assert!(verify_pcactn_json_policy(&text, &grant, now, &aud, None).allow);
    // the leaf suite of this vector is ed25519: a policy that lists it admits, one that does not refuses
    let alg = p.get("alg").and_then(Value::as_str).unwrap_or("ed25519").to_string();
    assert!(verify_pcactn_json_policy(&text, &grant, now, &aud, Some(&[alg.clone()])).allow);
    let other = vec!["slh-dsa-sha2-128f".to_string()];
    let v = verify_pcactn_json_policy(&text, &grant, now, &aud, Some(&other));
    assert!(!v.allow, "{:?}", v.checks);
    let empty: Vec<String> = Vec::new();
    assert!(!verify_pcactn_json_policy(&text, &grant, now, &aud, Some(&empty)).allow);
    // the same policy through the parsed entry point
    assert!(!verify_pcactn_core_policy(&p, &grant, now, &aud, Some(&other)).allow);
}

#[test]
fn cap_hash_is_the_hash_of_the_whole_capability() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let c = json!({"id": "x", "issuer": "i", "sig": "s", "caveats": []});
    let want = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonicalize(&c).as_bytes()));
    assert_eq!(cap_hash(&c), want);
    assert_eq!(cap_hash(&c).len(), 43);
    assert_ne!(cap_hash(&c), cap_hash(&json!({"id": "x", "issuer": "i", "sig": "t", "caveats": []})));
    assert_ne!(cap_hash(&c), "xyzzy");
}

#[test]
fn the_header_error_texts() {
    assert_eq!(PcaHeaderError::Empty.to_string(), "PCA-Action header is empty");
    assert_eq!(PcaHeaderError::NotBase64url.to_string(), "PCA-Action header is not strict unpadded base64url");
    assert_eq!(PcaHeaderError::NotUtf8.to_string(), "PCA-Action header does not decode to UTF-8 text");
}
