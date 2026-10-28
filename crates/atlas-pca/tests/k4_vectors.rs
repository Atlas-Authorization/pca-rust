//! K4: packages/pca/conformance/k4-vectors.json (escalation pricing, network-token binding, ERC-7715 check). A missing file fails.
use atlas_pca::k4::*;
use atlas_pca::serde_json::{Map, Value};

#[test]
fn k4_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/k4-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read k4-vectors.json")).expect("parse");
    let mut bad: Vec<String> = Vec::new();
    let esc = &doc["escalation"];
    let cc = esc["config_cases"].as_array().unwrap();
    assert!(cc.len() >= 6);
    for c in cc {
        if pricing_config_error(&c["config"]) != c["expect"].as_str() {
            bad.push(format!("config {}", c["name"]));
        }
    }
    let ds = esc["decisions"].as_array().unwrap();
    assert!(ds.len() >= 14);
    for c in ds {
        let got = decide_escalation(&esc["config"], &c["calibration"], &c["risk"]);
        if got.ask != c["expect"]["ask"].as_bool().unwrap() || Some(got.reason) != c["expect"]["reason"].as_str() {
            bad.push(format!("decision {}", c["risk"]));
        }
    }
    for c in esc["calibration"].as_array().unwrap() {
        let risks: &Map<String, Value> = c["risks"].as_object().unwrap();
        let (m, seen) = update_calibration(&c["config"], &c["start"], c["answers"].as_array().unwrap(), risks);
        let want: Vec<&str> = c["expect"]["seen"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        if Some(m) != c["expect"]["multiplierPpm"].as_i64() || seen != want {
            bad.push(format!("calibration {}", c["name"]));
        }
    }
    let bs = doc["network_binding"]["cases"].as_array().unwrap();
    assert!(bs.len() >= 15);
    for c in bs {
        let e = &c["expect_in"];
        if verify_network_token_binding(&c["binding"], &e["grant"], e["holder"].as_str().unwrap(), e["issuer_nonce"].as_str().unwrap(), e["provider"].as_str()) != c["expect"].as_str() {
            bad.push(format!("binding {}", c["name"]));
        }
    }
    let es = doc["erc7715"]["cases"].as_array().unwrap();
    assert!(es.len() >= 24);
    for c in es {
        let o = &c["opts"];
        let mgrs: Vec<String> = o["allowedManagers"].as_array().unwrap().iter().filter_map(|m| m.as_str().map(String::from)).collect();
        let ctxs = o["contexts"].clone();
        let owner = move |k: &str| ctxs.get(k).and_then(Value::as_str).map(String::from);
        if verify_granted_permission(&c["envelope"], &c["sent"], &c["got"], &mgrs, &owner) != c["expect"].as_str() {
            bad.push(format!("erc7715 {}", c["name"]));
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}
