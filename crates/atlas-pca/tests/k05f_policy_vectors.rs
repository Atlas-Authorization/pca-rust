//! The policy layer (packages/pca/conformance/policy-vectors.json): every vector's caveat projection AND whole decision (reason codes
//! and unsatisfied caveat types per group) is reproduced, none skipped.
use atlas_pca::*;
use serde_json::{json, Value};

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/policy-vectors.json");

#[test]
fn every_policy_vector_is_reproduced() {
    let d: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let vecs = d["policy_decision"].as_array().unwrap();
    assert_eq!(vecs.len(), 413);
    let mut bad: Vec<String> = Vec::new();
    for v in vecs {
        let (grant, chain, ctx) = (&v["grant"], &v["chain"], &v["context"]);
        let act = &ctx["action"];
        let call = json!({"tool": act["verb"].as_str().unwrap_or(""), "args": if act["params"].is_object() { act["params"].clone() } else { json!({}) }});
        let (ok, failed) = evaluate_agent_caveats(&policy_caveats(grant, chain), ctx, Some(&json!({"action": act})), Some(&call));
        let got_c = json!({"allow": ok, "failed": failed});
        let got_d = policy_decision(grant, chain, ctx);
        if got_c != v["expect"]["caveats"] || got_d != v["expect"]["decision"] {
            bad.push(format!("{}: caveats {got_c} vs {}; decision {got_d} vs {}", v["name"], v["expect"]["caveats"], v["expect"]["decision"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ, e.g.\n{}", bad.len(), vecs.len(), bad.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}
