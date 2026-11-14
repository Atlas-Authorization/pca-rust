//! Server-side PQ pins through `authorize` end to end (authorize-pq-pin-fixtures.json): the pq_pin check status, the exact reason, the
//! failing checks (a lower bound) and the 401 a pq_pin denial reports. A classical grant from a PINNED issuer is refused (a
//! quantum adversary holding the issuer's Ed25519 key could otherwise mint grants the pin never sees); an unpinned issuer, empty pins
//! and unset pins are unchanged.
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/authorize-pq-pin-fixtures.json");

#[test]
fn every_fixture_case_is_reproduced_through_authorize() {
    let d = strict_parse(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    assert_eq!(d["format"], "pca-authorize-pq-pin-fixtures/1");
    let op = Operation::from_json(&d["operation"]).unwrap();
    let cases = d["cases"].as_array().unwrap();
    assert!(cases.len() >= 9);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let grant = c["grant"].clone();
        let resolve = move |id: &str| Ok::<_, String>(if grant["id"] == id { Some(grant.clone()) } else { None });
        let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
        let store = MemoryStateStore::new();
        let input = AuthorizeInput {
            risk: Some(&insecure_calm_risk as &RiskFn),
            operation: Some(&op),
            audience: d["audience"].as_str().unwrap(),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&not_revoked),
            now: d["now"].as_i64(),
            plan: Some("single-step"),
            pq_pins: c["pq_pins"].as_object(),
            ..Default::default()
        };
        let r = authorize(Some(&c["pcactn"]), &input);
        let want = &c["expect"];
        assert_eq!(json!(r.allow), want["allow"], "{name} allow: {:?}", r.reasons);
        assert_eq!(json!(r.decision), want["decision"], "{name} decision");
        assert_eq!(json!(r.status), want["status"], "{name} status");
        let failing: Vec<&str> = r.checks.iter().filter(|(_, v)| **v == CheckStatus::Fail).map(|(k, _)| k.as_str()).collect();
        for f in want["failed_includes"].as_array().unwrap() {
            assert!(failing.contains(&f.as_str().unwrap()), "{name}: {f} is not among the failing checks {failing:?}");
        }
        let pin = r.checks.get("pq_pin").map_or("absent", CheckStatus::as_str);
        assert_eq!(json!(pin), want["checks"]["pq_pin"], "{name} pq_pin");
        if let Some(reason) = want["reason"].as_str() {
            assert!(r.reasons.iter().any(|x| x.contains(reason)), "{name}: {:?}", r.reasons);
        }
    }
}
