//! Build provenance gates (track K9): packages/pca/conformance/provenance-vectors.json. A missing file fails, it never skips.
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{model_paths_read, needs_discharge_error, provenance_caveat, provenance_gate, rfc9162_leaf_hash, verify_rfc9162_inclusion, ProvenanceCaveatOptions};

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn provenance_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/provenance-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read provenance-vectors.json")).expect("parse");
    let p = &doc["primitives"];
    let mut bad = Vec::new();
    let mut n = 0;
    for v in p["merkle_inclusion"].as_array().unwrap() {
        let i = &v["input"];
        let proof: Vec<Vec<u8>> = i["proof_hex"].as_array().unwrap().iter().map(|x| unhex(x.as_str().unwrap())).collect();
        let got = verify_rfc9162_inclusion(
            &rfc9162_leaf_hash(&unhex(i["leaf_hex"].as_str().unwrap())),
            i["index"].as_u64().unwrap(),
            i["size"].as_u64().unwrap(),
            &proof,
            &unhex(i["root_hex"].as_str().unwrap()),
        );
        if json!({ "ok": got }) != v["expect"] {
            bad.push(format!("merkle {}: {got}", v["name"]));
        }
        n += 1;
    }
    for v in p["gate"].as_array().unwrap() {
        let got = match provenance_gate(&v["input"]) {
            Ok(r) => json!({ "ok": true, "level": r.level, "claims": r.claims }),
            Err(code) => json!({ "ok": false, "code": code }),
        };
        if got != v["expect"] {
            bad.push(format!("gate {}: {got}", v["name"]));
        }
        n += 1;
    }
    for v in p["model_path"].as_array().unwrap() {
        let path = v["input"]["path"].as_str().unwrap();
        let model = model_paths_read(&[json!([{ "where": [{ "field": path }] }])], &[]) == vec![path.to_string()];
        if json!({ "model": model }) != v["expect"] {
            bad.push(format!("model_path {path}: {model}"));
        }
        n += 1;
    }
    assert_eq!(n, 96, "vector count");
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn provenance_caveat_defaults_and_order() {
    let c = provenance_caveat(&ProvenanceCaveatOptions { issuer: "slsa".into(), min_level: 3, source_repo: Some("r".into()), ..Default::default() });
    assert_eq!(
        c,
        json!({"type": "needs_discharge", "id": "provenance", "issuer": "slsa", "issuer_class": "artifact", "bind": "action", "ttl_ms": 300000,
            "require": [{"claim": "slsa_level", "op": "gte", "value": 3}, {"claim": "source_repo", "op": "eq", "value": "r"}, {"claim": "runtime_bound", "op": "eq", "value": true}]})
    );
    assert!(needs_discharge_error(&c).is_none());
    let all = provenance_caveat(&ProvenanceCaveatOptions {
        id: Some("prov".into()),
        issuer: "slsa".into(),
        min_level: 2,
        builder_ids: Some(vec!["b".into()]),
        oidc_issuer: Some("i".into()),
        require_runtime: Some(false),
        bind: Some("chain_hop".into()),
        ttl_ms: Some(1000),
        ..Default::default()
    });
    assert_eq!(
        all["require"],
        json!([{"claim": "slsa_level", "op": "gte", "value": 2}, {"claim": "builder_id", "op": "in", "value": ["b"]}, {"claim": "oidc_issuer", "op": "eq", "value": "i"}])
    );
    assert_eq!((&all["id"], &all["bind"], &all["ttl_ms"]), (&json!("prov"), &json!("chain_hop"), &json!(1000)));
}
