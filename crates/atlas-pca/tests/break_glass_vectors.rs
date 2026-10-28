//! Break-glass grants: packages/pca/conformance/break-glass-vectors.json. A missing file fails, it never skips.
use atlas_pca::break_glass::{BreakGlassPolicy, BreakGlassRegistry};
use atlas_pca::serde_json::Value;

#[test]
fn break_glass_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/break-glass-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read break-glass-vectors.json")).expect("parse");
    let (grants, reviews) = (doc["grants"].as_array().unwrap(), doc["reviews"].as_array().unwrap());
    let scenarios = doc["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 15 && !grants.is_empty() && !reviews.is_empty());
    let mut bad = Vec::new();
    for s in scenarios {
        let name = s["name"].as_str().unwrap();
        let mut reviewers = vec![doc["reviewer"].as_str().unwrap().to_string()];
        reviewers.extend(s["extra_reviewers"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
        let mut reg = BreakGlassRegistry::new(BreakGlassPolicy { authorities: vec![doc["authority"].as_str().unwrap().to_string()], reviewers });
        for st in s["steps"].as_array().unwrap() {
            let exp = &st["expect"];
            let ok = match st["op"].as_str().unwrap() {
                op @ ("accept" | "review") => {
                    let got = if op == "accept" {
                        reg.accept(&grants[st["grant"].as_u64().unwrap() as usize], &st["now"])
                    } else {
                        reg.review(&reviews[st["review"].as_u64().unwrap() as usize], st["holder"].as_str().unwrap(), &st["now"])
                    };
                    match (&got, exp["ok"].as_bool().unwrap()) {
                        (Ok(replaced), true) => Some(*replaced) == exp["replaced"].as_bool(),
                        (Err(c), false) => Some(*c) == exp["code"].as_str(),
                        _ => false,
                    }
                }
                "use" => {
                    let g = reg.use_grant(st["id"].as_str().unwrap(), st["holder"].as_str().unwrap(), st["action_digest"].as_str().unwrap(), &st["now"], &st["notified"]);
                    Some(g.decision) == exp["decision"].as_str()
                        && g.code == exp["code"].as_str()
                        && g.id.as_deref() == exp["id"].as_str()
                        && g.use_n == exp["use"].as_i64()
                        && g.remaining == exp["remaining"].as_i64()
                        && g.review_due == exp["review_due"].as_i64()
                }
                _ => Some(reg.frozen(st["holder"].as_str().unwrap(), &st["now"])) == exp.as_bool(),
            };
            if !ok {
                bad.push(format!("{name}: {st}"));
            }
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
