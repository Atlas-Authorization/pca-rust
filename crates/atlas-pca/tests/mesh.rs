use atlas_pca::*;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

/// The shared mesh corpus (packages/pca/conformance/mesh-vectors.json): whole mesh proofs with the TypeScript verdict.
#[test]
fn mesh_vectors() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}mesh-vectors.json")).unwrap()).unwrap();
    let vecs = doc["mesh"].as_array().unwrap();
    assert!(vecs.len() >= 100, "expected at least 100 mesh vectors, got {}", vecs.len());
    let mut errors = Vec::new();
    for v in vecs {
        let name = v["name"].as_str().unwrap();
        let expect = &v["expect"];
        let want_ok = expect["ok"].as_bool().unwrap();
        let got = verify_mesh_proof(&v["proof"], &v["trust"]);
        if got.ok != want_ok {
            errors.push(format!("{name}: ok = {} ({:?}), want {want_ok} ({})", got.ok, got.reason, expect["reason"]));
            continue;
        }
        if want_ok {
            continue;
        }
        let want_reason = expect["reason"].as_str().unwrap_or("");
        let got_reason = got.reason.clone().unwrap_or_default();
        if want_reason.starts_with("chain:") {
            if !got_reason.starts_with("chain:") {
                errors.push(format!("{name}: reason {got_reason:?}, want a chain refusal ({want_reason:?})"));
            }
            continue;
        }
        if got_reason != want_reason {
            errors.push(format!("{name}: reason {got_reason:?}, want {want_reason:?}"));
        }
        let want_hop = expect.get("hop").and_then(Value::as_u64).map(|h| h as usize);
        if got.hop != want_hop {
            errors.push(format!("{name}: hop {:?}, want {want_hop:?}", got.hop));
        }
    }
    assert!(errors.is_empty(), "{} mesh vectors disagree:\n{}", errors.len(), errors.join("\n"));
}
