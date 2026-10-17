//! Rule 19 (V15, committed map and Z0 disclosure) and the read-purpose primitive, against the shared conformance corpus
//! (`primitives.intent_map_commit`, `primitives.intent_map`, `primitives.intent_read_purpose` of
//! packages/pca/conformance/vectors.json): the guest (intent_map.rs, label_receipts.rs) must agree with the TS reference.
use pca_zkvm_core::chain::decode_b64u_strict;
use pca_zkvm_core::intent_map::{decide_map_disclosure, leaf_hash, map_commit_of, node_hash, LeafKind};
use pca_zkvm_core::label_receipts::decide_read_purpose;
use serde_json::Value;

fn corpus_block(name: &str) -> Vec<Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conformance/vectors.json");
    let text = std::fs::read_to_string(p).expect("conformance vectors.json");
    let head = format!("\"{name}\": [");
    let mut lines = text.lines().skip_while(|l| l.trim() != head).skip(1);
    let body: Vec<&str> = lines.by_ref().take_while(|l| !l.trim().starts_with(']')).collect();
    assert!(!body.is_empty(), "primitives.{name} block not found");
    serde_json::from_str(&format!("[{}]", body.join("\n"))).unwrap_or_else(|e| panic!("primitives.{name} parses: {e}"))
}

/// The RFC 6962 split tree over leaf hashes (builder side, for the commit vectors).
fn root(hs: &[[u8; 32]]) -> [u8; 32] {
    if hs.len() == 1 {
        return hs[0];
    }
    let mut k = 1;
    while k * 2 < hs.len() {
        k *= 2;
    }
    node_hash(&root(&hs[..k]), &root(&hs[k..]))
}

#[test]
fn conformance_intent_map_commit_vectors_match() {
    let cases = corpus_block("intent_map_commit");
    assert!(cases.len() >= 7);
    for c in &cases {
        let leaves = c["input"]["leaves"].as_array().unwrap();
        let hs: Vec<[u8; 32]> = leaves
            .iter()
            .map(|l| {
                let kind = match l["kind"].as_str().unwrap() {
                    "header" => LeafKind::Header,
                    "cell" => LeafKind::Cell,
                    "metrics" => LeafKind::Metrics,
                    _ => LeafKind::Learner,
                };
                leaf_hash(kind, &decode_b64u_strict(l["salt"].as_str().unwrap(), 32).unwrap(), &l["leaf"])
            })
            .collect();
        assert_eq!(map_commit_of(hs.len() as u64, &root(&hs)), c["expect"]["map_commit"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn conformance_intent_map_vectors_match() {
    let cases = corpus_block("intent_map");
    assert!(cases.len() >= 50);
    let mut bad = Vec::new();
    for c in &cases {
        let i = &c["input"];
        let eps = i.get("max_residual_risk_ppm").and_then(pca_zkvm_core::jsnum::safe_int);
        let got = decide_map_disclosure(i.get("map_commit"), i.get("action"), i.get("params"), &i["disclosure"], eps);
        let want = &c["expect"];
        let ok = match (&got, want["ok"].as_bool().unwrap()) {
            (Ok(p), true) => {
                let cell: Vec<i64> = want["cell"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
                p.cell == cell && Some(p.p_ppm) == want["p_ppm"].as_i64()
            }
            (Err(_), false) => true,
            _ => false,
        };
        if !ok {
            bad.push(format!("{}: got {got:?}, want {want}", c["name"]));
        }
    }
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn conformance_intent_read_purpose_vectors_match() {
    let cases = corpus_block("intent_read_purpose");
    assert!(cases.len() >= 14);
    for c in &cases {
        let i = &c["input"];
        let d = decide_read_purpose(i.get("fields"), i.get("purpose"), i.get("coverage"), i.get("on_uncovered"));
        let strs = |v: &Value| v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
        let e = &c["expect"];
        assert_eq!(d.outcome, e["outcome"].as_str().unwrap(), "{}", c["name"]);
        assert_eq!(d.minimise, strs(&e["minimise"]), "{}", c["name"]);
        assert_eq!(d.uncovered, strs(&e["uncovered"]), "{}", c["name"]);
    }
}
