//! `named_unmet_limit_reason` and `discharge_requests`.
use atlas_pca::agent::{mint_root, KeyPair, Suite};
use atlas_pca::discharge_requests;
use atlas_pca::facade::{compile_policy, CompileOptions};
use atlas_pca::named_unmet_limit_reason;
use atlas_pca::serde_json::json;

#[test]
fn the_unmet_limit_is_named_only_when_the_action_is_in_scope() {
    let perms = json!({"stripe": ["refund"]});
    let limits = json!({"refund": "$100"});
    let p =
        compile_policy(&CompileOptions { permissions: &perms, limits: Some(&limits), catalog: None, budget_model: None, risk_policy: None, now: 0 }).unwrap();
    let over = json!({"action": {"verb": "stripe.refund", "resource": "acct:1", "params": {"amount": 500}}});
    assert_eq!(named_unmet_limit_reason(&p.predicates, &over).as_deref(), Some("amount <= 100 not satisfied for stripe.refund on acct:1"));
    let within = json!({"action": {"verb": "stripe.refund", "resource": "acct:1", "params": {"amount": 5}}});
    assert_eq!(named_unmet_limit_reason(&p.predicates, &within), None);
    let other = json!({"action": {"verb": "gmail.send", "resource": "x", "params": {}}});
    assert_eq!(named_unmet_limit_reason(&p.predicates, &other), None, "out of scope: the plain wording stays");
    assert_eq!(named_unmet_limit_reason(&p.predicates, &json!({})), None);
}

#[test]
fn a_discharge_request_per_undischarged_needs_discharge_caveat() {
    let kyc = json!({"type": "needs_discharge", "id": "kyc", "issuer": "risk-team", "issuer_class": "human", "bind": "chain_hop", "ttl_ms": 600000, "require": [{"claim": "kyc_level", "op": "gte", "value": 2}]});
    let act = json!({"type": "needs_discharge", "id": "ok", "issuer": "risk-team", "issuer_class": "human", "bind": "action", "ttl_ms": 1000, "require": [{"claim": "kyc_level", "op": "gte", "value": 1}]});
    let broken = json!({"type": "needs_discharge", "id": "x"});
    let root = mint_root(
        &KeyPair::from_seed(&[1u8; 32]),
        &KeyPair::from_seed(&[2u8; 32]).public,
        &json!([kyc.clone(), act, broken, {"type": "expires", "at": 4_000_000_000_000i64}]),
        None,
        &Suite::default(),
    )
    .unwrap();
    let reqs = discharge_requests(&root, &json!([root.clone()]), Some("DIGEST"));
    assert_eq!(reqs.len(), 2, "the malformed caveat and the stock caveat are skipped");
    assert_eq!(
        (reqs[0]["kind"].as_str(), reqs[0]["caveat_id"].as_str(), reqs[0]["bind"].as_str()),
        (Some("pca-discharge-request"), Some("kyc"), Some("chain_hop"))
    );
    assert!(reqs[0].get("action_digest").is_none(), "only an action-bound caveat carries the action digest");
    assert_eq!((reqs[1]["caveat_id"].as_str(), reqs[1]["action_digest"].as_str()), (Some("ok"), Some("DIGEST")));
    assert_eq!(reqs[0]["cap_hash"], json!(atlas_pca::hash_canonical_strict(&root).unwrap()));
    assert_eq!(reqs[0]["ttl_ms"], json!(600000));
    assert!(discharge_requests(&root, &json!([root.clone()]), None)[1].get("action_digest").is_none());
    assert!(discharge_requests(&json!({"caveats": [{"type": "expires", "at": 1}]}), &json!([]), None).is_empty());
}
