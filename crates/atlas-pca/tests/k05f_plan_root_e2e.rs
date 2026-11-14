//! End to end (through `authorize`, never the helper): a bad plan root is a DENY with the reference's reason, an unauthorized one is a
//! deny, and only the plan the principal authorized and the PCActn committed passes. The core verdict's `plan_root_authorized`
//! is ANDed into the decision.
mod common;

use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use common::*;

const AUD: &str = "rs-plan";

fn run(ctx_plan: Option<Value>, authorized: bool) -> AuthorizeResult {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Map::new(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    // the plan the PCActn committed, exactly as the agent built it
    let committed = json!([{"id": "n1", "verb": "refund", "resource": "orders/1", "params_digest": params_digest(Some(&params))}]);
    let plan = match ctx_plan {
        Some(p) if p.is_null() => committed,
        Some(p) => p,
        None => Value::Null,
    };
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let ctx = move |_: &Value| Ok::<_, String>(Some(json!({"plan": plan, "plan_authorized": authorized})));
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        risk: Some(&insecure_calm_risk as &RiskFn),
        operation: Some(&op),
        audience: AUD,
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        context: Some(&ctx),
        now: a.pcactn["iat"].as_i64(),
        provenance_mediators: &harness_pins(),
        provenance_bundle: Some(&principal_direct),
        ..Default::default()
    };
    authorize(Some(&a.pcactn), &input)
}

#[test]
fn only_the_authorized_committed_plan_is_admitted() {
    let ok = run(Some(Value::Null), true);
    assert!(ok.allow, "{:?}", ok.reasons);
    assert_eq!(ok.checks.get("plan_root_authorized"), Some(&CheckStatus::Pass));
}

#[test]
fn a_plan_that_is_not_the_committed_one_is_denied_with_the_reference_reason() {
    let other = json!([{"id": "n1", "verb": "refund", "resource": "orders/2", "params_digest": "x"}]);
    let r = run(Some(other), true);
    assert!(!r.allow && r.status == 403);
    assert_eq!(r.checks.get("plan_root_authorized"), Some(&CheckStatus::Fail));
    assert!(r.reasons.iter().any(|x| x == "plan_root_authorized: known plan does not match plan.root"), "{:?}", r.reasons);
}

#[test]
fn a_plan_the_principal_has_not_authorized_is_denied() {
    let r = run(Some(Value::Null), false);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "plan_root_authorized: the plan root has not been authorized by the principal"), "{:?}", r.reasons);
}

#[test]
fn no_plan_at_all_is_a_default_deny() {
    let r = run(None, true);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.starts_with("plan_root_authorized: default-deny: no authorized plan is configured")), "{:?}", r.reasons);
}
