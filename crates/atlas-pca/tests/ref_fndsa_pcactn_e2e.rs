//! FN-DSA PCActn end to end (test-data/ref-fndsa-pcactn.json): the agent signer reproduces the reference's signed `body`
//! byte for byte for fn-dsa-512 / fn-dsa-1024, and the public verifier gives allow == expect_allow on every case.
//! FN-DSA signing needs the `fndsa-sign` feature; verification is always built in, so there is no feature-off "no backend"
//! configuration to test (the suites are native here) and no global FN-DSA backend state to reset.
#![cfg(feature = "fndsa-sign")]
use atlas_pca::agent::*;
use atlas_pca::serde_json::Value;
use atlas_pca::*;
use sha2::{Digest, Sha256};

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}

fn fixture() -> Value {
    let p = format!("{}/test-data/ref-fndsa-pcactn.json", env!("CARGO_MANIFEST_DIR"));
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(p).expect("fixture")).expect("fixture json")
}

#[test]
fn fndsa_pcactn_signs_byte_exact_and_verifies() {
    let doc = fixture();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    let mut signed = 0;
    for c in cases {
        let name = c["name"].as_str().unwrap();
        if let Some(body) = c.get("body") {
            let l = &c["key_labels"];
            let leaf = KeyPair::from_seed(&seed(l["agent_ed25519"].as_str().unwrap()));
            let pq = PqKeyPair::from_seed(if c["alg"] == "fn-dsa-512" { "FN-DSA-512" } else { "FN-DSA-1024" }, &seed(l["fndsa_keygen"].as_str().unwrap()))
                .and_then(|k| k.with_fn_dsa_sign_seed(seed(l["fndsa_sign_seed"].as_str().unwrap())))
                .unwrap();
            assert_eq!(pq.public, c["pq_pk"].as_str().unwrap(), "{name}: pq_pk");
            let out = sign_pcactn(body, &leaf, &Suite { alg: c["alg"].as_str(), pq: Some(&pq) }).unwrap();
            assert_eq!(out, c["pcactn"], "{name}: signed body differs");
            signed += 1;
        }
        let grant = c.get("grant").unwrap_or(&cases[if c["alg"] == "fn-dsa-512" { 0 } else { 6 }]["grant"]);
        let aud = c.get("audience").unwrap_or(&cases[if c["alg"] == "fn-dsa-512" { 0 } else { 6 }]["audience"]);
        let now = c.get("now_epoch").unwrap_or(&cases[if c["alg"] == "fn-dsa-512" { 0 } else { 6 }]["now_epoch"]);
        let opts = VerifyOptions { insecure_skip_plan_root_check: true, ..VerifyOptions::default() };
        let v = verify_pcactn_core_with(&c["pcactn"], grant, now.as_i64().unwrap(), aud.as_str().unwrap(), &opts);
        assert_eq!(v.allow, c["expect_allow"].as_bool().unwrap(), "{name}: {}", v.reason);
    }
    assert_eq!(signed, 2);
}
