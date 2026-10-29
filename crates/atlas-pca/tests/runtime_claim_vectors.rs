//! Runtime-class claims: packages/pca/conformance/runtime-claim-vectors.json. A missing file fails, it never skips.
use atlas_pca::runtime_claim::verified_runtime_class;
use atlas_pca::serde_json::Value;

fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

#[test]
fn runtime_claim_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/runtime-claim-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read runtime-claim-vectors.json")).expect("parse");
    let t = &doc["trust"];
    let (pinned, pd, ev) = (strs(&t["pinnedAttestors"]), t["passportDigest"].as_str().unwrap(), strs(&t["verifiedEvidenceDigests"]));
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 8);
    let mut bad = Vec::new();
    for c in cases {
        let got = verified_runtime_class(&c["claim"], &pinned, pd, &ev, c["now"].as_i64().unwrap());
        if got != c["expect"].as_str().unwrap() {
            bad.push(format!("{}: {got}", c["name"]));
        }
    }
    let first = &cases[0];
    let now = first["now"].as_i64().unwrap();
    if verified_runtime_class(&first["claim"], &[], pd, &ev, now) != "none" {
        bad.push("unpinned attestor accepted".into());
    }
    if verified_runtime_class(&first["claim"], &pinned, pd, &[], now) != "none" {
        bad.push("unverified evidence accepted".into());
    }
    if verified_runtime_class(&Value::Null, &pinned, pd, &ev, now) != "none" {
        bad.push("null claim".into());
    }
    assert!(bad.is_empty(), "{bad:?}");
}
