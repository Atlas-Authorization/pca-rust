//! The attestation and zero-knowledge verifier hooks of `authorize`: a verdict is a check, a refusal or a panic fails it, and with
//! no verifier a grant that binds the agent or a PCActn that carries a proof is refused (fail closed).

mod common;

use atlas_pca::agent::{build_pcactn, default_risk_policy, mint_grant, KeyPair, PcactnInput, Suite};
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::{authorize, AttestationHookFn, AuthorizeInput, AuthorizeResult, CheckStatus, HookResult, MemoryStateStore, Operation, ZkHookFn};

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

fn run(p: &Value, grant: &Value, op: &Operation, aud: &str, now: Option<i64>, attestation: Option<&AttestationHookFn>, zk: Option<&ZkHookFn>) -> AuthorizeResult {
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let is_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let pins = common::harness_pins();
    let input = AuthorizeInput {
        risk: Some(&atlas_pca::insecure_calm_risk as &atlas_pca::RiskFn),
        operation: Some(op),
        audience: aud,
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&is_revoked),
        now,
        plan: Some("single-step"),
        provenance_mediators: &pins,
        provenance_bundle: Some(&common::principal_direct),
        attestation,
        zk,
        ..Default::default()
    };
    authorize(Some(p), &input)
}

fn verdict(ok: bool, reason: Option<&str>) -> HookResult {
    HookResult::Enforced { ok, reason: reason.map(str::to_string), t: None }
}

#[test]
fn an_attestation_verdict_is_a_check() {
    let d = fixtures();
    let (grant, step) = (&d["cases"][0]["grant"], &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&step["operation"]).unwrap();
    let go = |hook: Option<&AttestationHookFn>| run(&step["pcactn"], grant, &op, d["audience"].as_str().unwrap(), d["now"].as_i64(), hook, None);

    let none = go(None);
    assert!(none.allow, "{:?}", none.reason);
    assert_eq!(none.check("attestation"), None, "the grant does not bind the agent: nothing to enforce");

    let pass = go(Some(&|_: &Value, _: &Value, _: i64| verdict(true, None)));
    assert!(pass.allow, "{:?}", pass.reason);
    assert_eq!(pass.check("attestation"), Some(CheckStatus::Pass));

    let refused = go(Some(&|_: &Value, _: &Value, _: i64| verdict(false, Some("measurement is not on the allowlist"))));
    assert!(!refused.allow);
    assert_eq!(refused.check("attestation"), Some(CheckStatus::Fail));
    assert!(refused.reasons.iter().any(|r| r.contains("measurement is not on the allowlist")), "{:?}", refused.reasons);

    let silent = go(Some(&|_: &Value, _: &Value, _: i64| HookResult::NotEnforced));
    assert_eq!(silent.check("attestation"), Some(CheckStatus::NotEnforced));

    let panicked = go(Some(&|_: &Value, _: &Value, _: i64| -> HookResult { panic!("verifier crashed") }));
    assert!(!panicked.allow);
    assert_eq!(panicked.check("attestation"), Some(CheckStatus::Fail));
}

#[test]
fn a_carried_zk_proof_is_accepted_only_from_a_verifier() {
    let (principal, agent) = (KeyPair::from_seed(&[7; 32]), KeyPair::from_seed(&[8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &agent.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let plan = [json!({"id": "a", "verb": "refund", "resource": "orders/1"})];
    let mut extra = Map::new();
    extra.insert("zk_compliance".to_string(), json!({"proof": "x"}));
    let chain = [grant.clone()];
    let p = build_pcactn(&PcactnInput { grant: &grant, chain: &chain, plan: &plan, node_id: "a", params: None, counter: 1, signer: &agent, aud: "rs-test", iat: 1000, exp: None, extra, suite: Suite::default() }).unwrap();
    let op = Operation::new("refund", "orders/1", json!({}));
    let go = |hook: Option<&ZkHookFn>| run(&p, &grant, &op, "rs-test", Some(1000), None, hook).check("zk_compliance");

    assert_eq!(go(None), Some(CheckStatus::Fail), "no verifier: a carried proof is never accepted unverified");
    assert_eq!(go(Some(&|_: &Value, _: &Value, _: i64| HookResult::NotEnforced)), Some(CheckStatus::Fail));
    assert_eq!(go(Some(&|_: &Value, _: &Value, _: i64| verdict(false, Some("bad proof")))), Some(CheckStatus::Fail));
    assert_eq!(go(Some(&|_: &Value, _: &Value, _: i64| -> HookResult { panic!("verifier crashed") })), Some(CheckStatus::Fail));
    assert_eq!(go(Some(&|p: &Value, _: &Value, _: i64| verdict(p["zk_compliance"]["proof"] == "x", None))), Some(CheckStatus::Pass));
}
