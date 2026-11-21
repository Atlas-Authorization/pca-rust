//! `requireLinkedTemplate` (F3): a grant whose envelope carries a `template_ref` must hold exactly the policy the reference denotes
//! (`verify_linked_policy`, over the shared policy-link-vectors resolve rows), and the gate of `authorize` refuses a grant that links
//! nothing or whose policy differs, before any state is touched.
mod common;

use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;
use common::*;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/policy-link-vectors.json");

fn doc() -> Value {
    strict_parse(&std::fs::read_to_string(FILE).unwrap()).unwrap()
}

fn envelope(policy: &Value, reference: &Value) -> atlas_pca::serde_json::Map<String, Value> {
    let mut e = atlas_pca::serde_json::Map::new();
    e.insert("predicates".into(), policy["predicates"].clone());
    e.insert("caveats".into(), policy["caveats"].clone());
    e.insert("template_ref".into(), reference.clone());
    e
}

#[test]
fn an_envelope_must_be_exactly_the_instantiation_its_reference_denotes() {
    let d = doc();
    let row = d["resolve"].as_array().unwrap().iter().find(|r| r["name"] == "a reference resolves to the instantiation").unwrap();
    let (reference, reg, policy) = (&row["ref"], &row["registry"], &row["expect"]["policy"]);
    assert_eq!(verify_linked_policy(&envelope(policy, reference), reg), Ok(()));
    // no template_ref: nothing to verify
    let mut plain = envelope(policy, reference);
    plain.remove("template_ref");
    assert_eq!(verify_linked_policy(&plain, reg), Ok(()));
    // a widened predicate, or a dropped caveat, is a different policy
    let mut wide = envelope(policy, reference);
    wide["predicates"][0]["resource"] = json!("/acct/*");
    assert_eq!(verify_linked_policy(&wide, reg), Err("grant policy differs from the linked template instantiation".into()));
    let mut dropped = envelope(policy, reference);
    dropped["caveats"] = json!([]);
    assert_eq!(verify_linked_policy(&dropped, reg), Err("grant policy differs from the linked template instantiation".into()));
    // a reference the registry cannot resolve carries the resolver's reason
    let missing = d["resolve"].as_array().unwrap().iter().find(|r| r["name"] == "a registry without the version").unwrap();
    assert_eq!(verify_linked_policy(&envelope(policy, &missing["ref"]), &missing["registry"]), Err(missing["expect"]["reason"].as_str().unwrap().to_string()));
}

#[test]
fn the_gate_refuses_a_grant_that_links_nothing() {
    use atlas_pca::agent::*;
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), "rs-link", 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Default::default(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let reg = || json!({"templates": {}, "trusted": []});
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        risk: Some(&insecure_calm_risk as &RiskFn),
        require_linked_template: Some(&reg),
        operation: Some(&op),
        audience: "rs-link",
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: a.pcactn["iat"].as_i64(),
        plan: Some("single-step"),
        provenance_mediators: &harness_pins(),
        provenance_bundle: Some(&principal_direct),
        ..Default::default()
    };
    let r = authorize(Some(&a.pcactn), &input);
    assert!(!r.allow);
    assert_eq!(r.status, 403);
    assert!(r.reasons.iter().any(|x| x == "template: the grant carries no template_ref"), "{:?}", r.reasons);
    let stream = format!("{}:{}", grant["id"].as_str().unwrap(), a.pcactn["cap_chain"][0]["holder"].as_str().unwrap());
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
}
