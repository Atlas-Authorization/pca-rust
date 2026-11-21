//! Agent blueprints: packages/pca/conformance/blueprint-vectors.json. A missing file fails, it never skips.
use atlas_pca::blueprint::{check_blueprints_admitted, verify_blueprint, BlueprintRegistry};
use atlas_pca::serde_json::Value;

#[test]
fn blueprint_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/blueprint-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read blueprint-vectors.json")).expect("parse");
    let recs = doc["records"].as_array().unwrap();
    let mut bad = Vec::new();
    for (i, r) in recs.iter().enumerate() {
        // 8 has a bad signature; 14-21 and 24 are validly signed but malformed (runtime_pins shapes)
        if verify_blueprint(r) != ![8, 14, 15, 16, 17, 18, 19, 20, 21, 24].contains(&i) {
            bad.push(format!("record {i}"));
        }
    }
    for s in doc["scenarios"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        let reg = BlueprintRegistry::new(vec![doc["operator"].as_str().unwrap().to_string()], std::sync::Arc::new(atlas_pca::blueprint::MemoryBlueprintStore::new()));
        for st in s["steps"].as_array().unwrap() {
            let exp = &st["expect"];
            if st["op"] == "accept" {
                let got = reg.accept(&recs[st["record"].as_u64().unwrap() as usize]);
                let ok = match (&got, exp["ok"].as_bool().unwrap()) {
                    (Ok(r), true) => Some(*r) == exp["replaced"].as_bool(),
                    (Err(c), false) => Some(*c) == exp["code"].as_str(),
                    _ => false,
                };
                if !ok {
                    bad.push(format!("{name}: accept {got:?}"));
                }
            } else {
                let o = &st["opts"];
                // opts.admitted: 'all' | 'none' | [instance keys] is the admitted(holder, bp) hook; absent = no hook
                let keys: Vec<String> = o["admitted"].as_array().map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let hook = |holder: &str, _bp: &Value| match &o["admitted"] {
                    Value::String(m) => m == "all",
                    Value::Array(_) => keys.iter().any(|k| k == holder),
                    _ => false,
                };
                let admitted: Option<&dyn Fn(&str, &Value) -> bool> = if o["admitted"].is_null() { None } else { Some(&hook) };
                let got = check_blueprints_admitted(&st["chain"], &reg, &o["now"], o["mode"].as_str().unwrap(), o["minEpoch"].as_i64(), admitted);
                let mut ok = Some(got.decision) == exp["decision"].as_str();
                if let Some(c) = exp["code"].as_str() {
                    ok &= got.code == Some(c);
                }
                if let Some(b) = exp["blueprint"].as_str() {
                    ok &= got.blueprint.as_deref() == Some(b);
                }
                if let Some(g) = exp["governed"].as_array() {
                    ok &= got.governed.iter().map(String::as_str).collect::<Vec<_>>() == g.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                }
                if exp["decision"] == "escalate" {
                    ok &= Some(got.have) == exp["have"].as_i64() && Some(got.need) == exp["need"].as_i64();
                }
                if !ok {
                    bad.push(format!("{name}: check {got:?}"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
