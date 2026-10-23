//! Signature suites in the guest (`pq_suites::verify_with_suite`) against the TypeScript reference `verifyWithSuite`
//! (fixtures/ts_pq_suites.json, gen_ts_pq_suites.ts) over every registered suite: valid, corrupted primary / PQ signature,
//! missing PQ signature, wrong Ed25519 key, wrong message, missing / truncated PQ key. Suites the guest implements must agree
//! exactly (FN-DSA through fn-dsa-vrfy); LESS is refused with `unsupported_suite` (fail closed).
use pca_zkvm_core::pq_suites::{suite_supported, verify_with_suite, SuiteError};
use serde_json::Value;

const UNSUPPORTED: [&str; 2] = ["less-cat1", "hybrid-ed25519-less-cat1"];

#[test]
fn every_suite_matches_the_reference_or_is_refused_as_unsupported() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ts_pq_suites.json");
    let d: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let cases = d["cases"].as_array().unwrap();
    assert!(cases.len() >= 90);
    let mut bad = Vec::new();
    for c in cases {
        let alg = c["alg"].as_str().unwrap();
        let msg = base64_decode(c["msg"].as_str().unwrap());
        let s = |k: &str| c.get(k).and_then(|v| v.as_str());
        let got = verify_with_suite(Some(alg), &msg, s("ed_pk"), s("sig"), s("pq_pk"), s("pq_sig"));
        if UNSUPPORTED.contains(&alg) {
            assert!(!suite_supported(Some(alg)));
            if got != Err(SuiteError::Unsupported(alg.to_string())) {
                bad.push(format!("{}: want unsupported_suite, got {got:?}", c["name"]));
            }
        } else if got.is_ok() != c["ok"].as_bool().unwrap() {
            bad.push(format!("{}: guest {got:?}, TS ok={}", c["name"], c["ok"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} suite cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
    assert_eq!(verify_with_suite(Some("made-up"), b"m", None, None, None, None), Err(SuiteError::Unsupported("made-up".into())));
    assert_eq!(SuiteError::Unsupported("x".into()).to_string(), "unsupported_suite: x");
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}
