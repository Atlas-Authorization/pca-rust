//! Discovery document build, parse and fetch.
use atlas_pca::discovery::*;
use atlas_pca::serde_json::{json, Value};

#[test]
fn build_then_parse_round_trips_and_defaults_match_the_reference() {
    let d = build_discovery_document("api", &BuildDiscoveryOptions::default()).unwrap();
    assert_eq!(d["pca_versions"], json!([2]));
    assert_eq!(d["action_header"], "PCA-Action");
    assert_eq!(d["signature_suites"], json!(["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]));
    assert_eq!(d["required_checks"].as_array().unwrap().len(), 7);
    assert_eq!(parse_discovery_document(&d).unwrap(), d);
    assert!(accepts_suite(&d, "ml-dsa-65") && !accepts_suite(&d, "slh-dsa-sha2-128f"));
    assert!(build_discovery_document("", &BuildDiscoveryOptions::default()).is_err());
}

#[test]
fn parse_refuses_the_malformed() {
    let good = build_discovery_document("api", &BuildDiscoveryOptions::default()).unwrap();
    for (k, bad) in [("audience", json!("")), ("pca_versions", json!(["2"])), ("signature_suites", json!([1])), ("action_header", json!(""))] {
        let mut d = good.clone();
        d[k] = bad;
        assert!(parse_discovery_document(&d).is_err(), "{k}");
    }
    assert!(parse_discovery_document(&json!(null)).is_err());
    let mut d = good.clone();
    d["obligations_supported"] = json!([1]);
    assert!(parse_discovery_document(&d).is_err());
    // an optional member of the wrong type is dropped, not trusted
    let mut d = good;
    d["trusted_roots"] = json!("nope");
    assert!(parse_discovery_document(&d).unwrap().get("trusted_roots").is_none());
}

#[test]
fn the_intent_block_is_closed() {
    let ok = json!({"versions": [1, 2], "actions_uri": "https://x/a", "question_relay": true, "tiers": {"stripe.refund": 3},
        "schema_keys": [{"kid": "k", "alg": "ed25519", "pk": "p"}]});
    assert_eq!(parse_discovery_intent(&ok).unwrap(), ok);
    for bad in [
        json!({"versions": []}),
        json!({"versions": [3]}),
        json!({"versions": [1], "x": 1}),
        json!({"versions": [1], "actions_uri": ""}),
        json!({"versions": [1], "tiers": {"v": 5}}),
        json!({"versions": [1], "tiers": {"v": 1.5}}),
        json!({"versions": [1], "question_relay": "y"}),
        json!({"versions": [1], "schema_keys": [{"kid": "k"}]}),
        json!([1]),
    ] {
        assert!(parse_discovery_intent(&bad).is_err(), "{bad}");
    }
}

#[test]
fn fetch_appends_the_well_known_path_and_refuses_non_2xx() {
    let doc = build_discovery_document("api", &BuildDiscoveryOptions::default()).unwrap();
    let d = doc.clone();
    let ok = move |url: &str, accept: &str| -> Result<(u16, Value), String> {
        assert_eq!((url, accept), ("https://api.example/.well-known/pca-configuration", "application/json"));
        Ok((200, d.clone()))
    };
    assert_eq!(fetch_discovery("https://api.example//", &ok).unwrap(), doc);
    let nf = |_: &str, _: &str| Ok((404u16, Value::Null));
    assert!(fetch_discovery("https://a", &nf).unwrap_err().contains("returned 404"));
    let down = |_: &str, _: &str| Err::<(u16, Value), _>("refused".to_string());
    assert_eq!(fetch_discovery("https://a", &down).unwrap_err(), "refused");
    let junk = |_: &str, _: &str| Ok((200u16, json!({"x": 1})));
    assert!(fetch_discovery("https://a", &junk).is_err());
}
