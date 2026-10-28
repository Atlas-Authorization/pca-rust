//! Policy classes: packages/pca/conformance/policy-classes-vectors.json. A missing file fails, it never skips.
use atlas_pca::policy_classes::{class_verdicts_error, decide_classes};
use atlas_pca::serde_json::Value;

#[test]
fn policy_classes_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/policy-classes-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read policy-classes-vectors.json")).expect("parse");
    let (validate, decide) = (doc["validate"].as_array().unwrap(), doc["decide"].as_array().unwrap());
    assert!(validate.len() >= 8 && decide.len() >= 6);
    let mut bad = Vec::new();
    for c in validate {
        if class_verdicts_error(&c["input"]).is_none() != c["expect"]["ok"].as_bool().unwrap() {
            bad.push(format!("validate {}", c["name"]));
        }
    }
    for c in decide {
        let (got, exp) = (decide_classes(&c["input"]), &c["expect"]);
        let names = |v: &Value| v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
        let classes_ok = got.classes.len() == exp["classes"].as_array().unwrap().len()
            && got.classes.iter().zip(exp["classes"].as_array().unwrap()).all(|(g, w)| {
                Some(g.class.as_str()) == w["class"].as_str() && Some(g.revision) == w["revision"].as_i64() && Some(g.digest.as_str()) == w["digest"].as_str() && Some(g.decision.as_str()) == w["decision"].as_str()
            });
        let ok = Some(got.decision) == exp["decision"].as_str()
            && got.reason.as_deref() == exp["reason"].as_str()
            && classes_ok
            && got.denied_by == names(&exp["denied_by"])
            && got.escalated_by == names(&exp["escalated_by"]);
        if !ok {
            bad.push(format!("decide {}: {got:?} want {exp}", c["name"]));
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
