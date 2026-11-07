//! Typed missing context and the stored-wins merge: packages/pca/conformance/missing-context-vectors.json. A missing file fails.
use atlas_pca::missing_context::{bind_context, decide_with_missing, supplier_table};
use atlas_pca::serde_json::Value;

#[test]
fn missing_context_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/missing-context-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read missing-context-vectors.json")).expect("parse");
    let (decide, bind) = (doc["decide"].as_array().unwrap(), doc["bind"].as_array().unwrap());
    assert!(decide.len() >= 20 && bind.len() >= 8);
    let mut bad = Vec::new();
    for c in decide {
        let (got, exp) = (decide_with_missing(&c["where"], &c["bound"], &c["supplied"], c.get("suppliers")), &c["expect"]);
        let want = exp["missing"].as_array().unwrap();
        let ok = Some(got.decision) == exp["decision"].as_str()
            && got.reason.as_deref() == exp["reason"].as_str()
            && got.missing.len() == want.len()
            && got.missing.iter().zip(want).all(|(g, w)| Some(g.path.as_str()) == w["path"].as_str() && Some(g.supplier.as_str()) == w["supplier"].as_str());
        if !ok {
            bad.push(format!("decide {}: {got:?} want {exp}", c["name"]));
        }
    }
    for c in bind {
        let got = bind_context(&c["bound"], &c["supplied"], &supplier_table(&c["suppliers"]));
        let exp = &c["expect"];
        let names = |v: &Value| v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
        if got.context != exp["context"] || got.conflicts != names(&exp["conflicts"]) || got.dropped != names(&exp["dropped"]) {
            bad.push(format!("bind {}: {got:?} want {exp}", c["name"]));
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
