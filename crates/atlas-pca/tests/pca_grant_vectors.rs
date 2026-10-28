//! The `pca_grant` authorization-details type: packages/pca/conformance/pca-grant-vectors.json. A missing file fails.
use atlas_pca::pca_grant::{check_presentation, chain_digest, parse_details, validate_detail};
use atlas_pca::serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/pca-grant-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read pca-grant-vectors.json"))
        .expect("parse pca-grant-vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(1));
    doc
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect()
}

#[test]
fn pca_grant_vectors() {
    let doc = load();
    let mut bad = Vec::new();
    for v in doc["digest"].as_array().unwrap() {
        if chain_digest(&strs(&v["ids"])).as_deref() != v["digest"].as_str() {
            bad.push(format!("digest {}", v["ids"]));
        }
    }
    for v in doc["detail"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let got = validate_detail(&v["input"]);
        let exp = &v["expect"];
        let ok = match (&got, exp["ok"].as_bool().unwrap()) {
            (Ok(()), true) => true,
            (Err(c), false) => Some(*c) == exp["code"].as_str(),
            _ => false,
        };
        if !ok {
            bad.push(format!("detail {name}: {got:?} vs {exp}"));
        }
    }
    for v in doc["array"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let got = parse_details(&v["input"]);
        let exp = &v["expect"];
        let ok = match (&got, exp["ok"].as_bool().unwrap()) {
            (Ok(l), true) => Some(l.len() as i64) == exp["count"].as_i64(),
            (Err(c), false) => Some(*c) == exp["code"].as_str(),
            _ => false,
        };
        if !ok {
            bad.push(format!("array {name}: {got:?} vs {exp}"));
        }
    }
    for v in doc["presentation"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let p = &v["presented"];
        let details: Vec<Value> = v["details"].as_array().unwrap().clone();
        let got = check_presentation(&details, p["resource"].as_str().unwrap(), &strs(&p["chain_ids"]), p["proof_verified"].as_bool().unwrap());
        let exp = &v["expect"];
        let ok = match (&got, exp["allow"].as_bool().unwrap()) {
            (Ok(i), true) => Some(*i as i64) == exp["index"].as_i64(),
            (Err(c), false) => Some(*c) == exp["code"].as_str(),
            _ => false,
        };
        if !ok {
            bad.push(format!("presentation {name}: {got:?} vs {exp}"));
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
