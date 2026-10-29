//! Shared vectors for the forbid-wins certificate (table) and linked policy templates:
//! packages/pca/conformance/forbid-certificate-vectors.json and policy-link-vectors.json.
use atlas_pca::serde_json::Value;
use atlas_pca::{
    forbid_certificate_consistent, instantiate_template, resolve_link, template_def_error,
    template_digest, template_ref_error, verify_template, verify_tighten,
};

fn load(name: &str) -> Value {
    let p = format!(
        "{}/../../conformance/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn forbid_certificate_table() {
    let doc = load("forbid-certificate-vectors.json");
    let table = doc["table"].as_array().unwrap();
    assert!(table.len() >= 19);
    for e in table {
        let prec = list(&e["options"]["precedence"]);
        assert_eq!(
            forbid_certificate_consistent(&e["certificate"], &prec),
            e["expect"]["consistent"].as_bool().unwrap(),
            "{}",
            e["name"]
        );
    }
    for bad in [
        Value::Null,
        atlas_pca::serde_json::json!(5),
        atlas_pca::serde_json::json!({}),
        atlas_pca::serde_json::json!({"v": 1, "kind": "forbid-wins", "clauses": "x"}),
    ] {
        assert!(!forbid_certificate_consistent(&bad, &[]));
    }
}

#[test]
fn policy_link_vectors() {
    let doc = load("policy-link-vectors.json");
    let def = &doc["template"]["def"];
    assert_eq!(
        template_digest(def).as_deref(),
        doc["template"]["digest"].as_str()
    );
    for e in doc["def_errors"].as_array().unwrap() {
        assert_eq!(
            template_def_error(&e["def"]).as_deref(),
            e["expect"].as_str(),
            "{}",
            e["name"]
        );
    }
    let inst = doc["instantiate"].as_array().unwrap();
    assert!(inst.len() >= 14);
    for e in inst {
        let got = instantiate_template(def, &e["slots"]);
        let x = &e["expect"];
        if x["ok"].as_bool().unwrap() {
            assert_eq!(got.as_ref().unwrap(), &x["policy"], "{}", e["name"]);
        } else {
            assert_eq!(
                got.unwrap_err(),
                x["reason"].as_str().unwrap(),
                "{}",
                e["name"]
            );
        }
    }
    for e in doc["verify"].as_array().unwrap() {
        let trusted = list(&e["trusted"]);
        let got = if e["kind"] == "template" {
            verify_template(&e["signed"], &trusted)
        } else {
            verify_tighten(&e["signed"], &trusted)
        };
        let x = &e["expect"];
        assert_eq!(got.is_ok(), x["ok"].as_bool().unwrap(), "{}", e["name"]);
        if let Err(r) = got {
            assert_eq!(r, x["reason"].as_str().unwrap(), "{}", e["name"]);
        }
    }
    for e in doc["ref_errors"].as_array().unwrap() {
        assert_eq!(
            template_ref_error(&e["ref"]).as_deref(),
            e["expect"].as_str(),
            "{}",
            e["name"]
        );
    }
    for e in doc["resolve"].as_array().unwrap() {
        let got = resolve_link(&e["ref"], &e["registry"]);
        let x = &e["expect"];
        if x["ok"].as_bool().unwrap() {
            let (p, n) = got.unwrap_or_else(|r| panic!("{}: {}", e["name"], r));
            assert_eq!(p, x["policy"], "{}", e["name"]);
            assert_eq!(n as u64, x["overlays"].as_u64().unwrap(), "{}", e["name"]);
        } else {
            assert_eq!(
                got.unwrap_err(),
                x["reason"].as_str().unwrap(),
                "{}",
                e["name"]
            );
        }
    }
}
