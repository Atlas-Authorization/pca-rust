//! Differential replay of the release signing of the built-in defs (`sign_builtins`): the attestation per verb against the reference.
//! The reviewer secret is derived from the case's seed label, never stored.
mod common;
use atlas_pca::actions_kit::data::builtin_defs;
use atlas_pca::actions_kit_ops::review::sign_builtins;
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn sign_builtins_matches_the_reference() {
    let cases = common::ref_cases("actions-signbuiltins-py");
    assert_eq!(cases.len(), 4);
    let all = builtin_defs();
    for c in &cases {
        let a = &c["args"][0];
        let label = a["secret"]["$seed"].as_str().expect("seed label");
        let secret = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes());
        let (from, to) = (a["from"].as_u64().unwrap() as usize, a["to"].as_u64().unwrap() as usize);
        let signed = sign_builtins(a["kid"].as_str().unwrap(), &secret, a["ts"].as_i64().unwrap(), None, Some(&all[from..to])).expect("signs");
        let got: Vec<Value> = signed.iter().map(|d| json!([d["verb"], d["review"]["state"], d["review"]["attestation"]])).collect();
        assert_eq!(Value::Array(got), c["out"], "{}", c["name"]);
    }
}
