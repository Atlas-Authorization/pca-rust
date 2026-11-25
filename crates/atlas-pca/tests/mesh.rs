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

/// A pinned head that is JSON null is no pin (the reference's `if (pin)`): an accepted proof stays accepted.
#[test]
fn a_null_pinned_head_is_no_pin() {
    fn domains(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "domain" {
                        if let Some(d) = x.as_str() {
                            out.push(d.to_string());
                        }
                    }
                    domains(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| domains(x, out)),
            _ => {}
        }
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}mesh-vectors.json")).unwrap()).unwrap();
    let v = doc["mesh"].as_array().unwrap().iter().find(|v| v["expect"]["ok"] == Value::Bool(true)).unwrap();
    let mut ds = Vec::new();
    domains(&v["proof"], &mut ds);
    assert!(!ds.is_empty());
    let mut trust = v["trust"].clone();
    trust["pinnedHeads"] = Value::Object(ds.into_iter().map(|d| (d, Value::Null)).collect());
    let got = verify_mesh_proof(&v["proof"], &trust);
    assert!(got.ok, "{:?}", got.reason);
}
