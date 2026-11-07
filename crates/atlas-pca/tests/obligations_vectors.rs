//! Decision obligations: packages/pca/conformance/obligations-vectors.json. A missing file fails, it never skips.
use atlas_pca::obligations::{merge_obligations, obligation_outcome, obligations_error, pep_obligation_gate};
use atlas_pca::serde_json::Value;

#[test]
fn obligations_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/obligations-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read obligations-vectors.json")).expect("parse");
    let mut bad = Vec::new();
    let all = |k: &str| doc[k].as_array().unwrap().clone();
    assert!(!all("validate").is_empty() && !all("merge").is_empty() && !all("gate").is_empty() && !all("outcome").is_empty());
    for c in all("validate") {
        if obligations_error(&c["input"]).is_none() != c["expect"]["ok"].as_bool().unwrap() {
            bad.push(format!("validate {}", c["name"]));
        }
    }
    for c in all("merge") {
        let got = merge_obligations(c["inputs"].as_array().unwrap());
        let ok = match (&got, c["expect"]["ok"].as_bool().unwrap()) {
            (Ok(l), true) => &Value::Array(l.clone()) == &c["expect"]["obligations"],
            (Err(_), false) => true,
            _ => false,
        };
        if !ok {
            bad.push(format!("merge {}: {got:?}", c["name"]));
        }
    }
    for c in all("gate") {
        let got = pep_obligation_gate(c["decision"].as_str().unwrap(), c["answered"].as_bool().unwrap(), &c["obligations"], &c["supported"]);
        let e = &c["expect"];
        let ok = Some(got.decision) == e["decision"].as_str()
            && Value::Array(got.perform.clone()) == e["perform"]
            && Value::from(got.unsupported.clone()) == e["unsupported"];
        if !ok {
            bad.push(format!("gate {}: {got:?}", c["name"]));
        }
    }
    for c in all("outcome") {
        let got = obligation_outcome(&c["obligations"], &c["fulfilled"], &c["now"]);
        let e = &c["expect"];
        let ok = Some(got.outcome) == e["outcome"].as_str()
            && Value::from(got.overdue.clone()) == e["overdue"]
            && got.status == e["status"].as_str();
        if !ok {
            bad.push(format!("outcome {}: {got:?}", c["name"]));
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
