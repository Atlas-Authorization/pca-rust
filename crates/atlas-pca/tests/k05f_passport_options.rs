//! `requirePassport` as reusable `AuthorizeOptions` configuration: a call with no passport (or one that does not verify) is refused
//! with `passport: <reason>` BEFORE the replay counter is spent, and a configuration with no trusted issuers or no revocation source
//! is refused (fail closed), as the reference requires.
mod common;

use std::sync::Arc;

use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;
use common::*;

const AUD: &str = "rs-passport";

struct Call {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn call() -> Call {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Default::default(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    Call { grant, pcactn: a.pcactn, op }
}

fn opts(store: Arc<dyn StateStore>, req: PassportRequirement) -> AuthorizeOptions {
    AuthorizeOptions::new(store, |_, _| Ok(false))
        .with_plan(Some(SINGLE_STEP))
        .with_risk(insecure_calm_risk)
        .with_provenance_mediators(harness_pins())
        .with_provenance_bundle(principal_direct)
        .with_require_passport(req)
}

fn run(c: &Call, o: &AuthorizeOptions, passport: Option<&Value>) -> AuthorizeResult {
    let g = c.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    o.run_with_passport(Some(&c.pcactn), Some(&c.op), AUD, &resolve, c.pcactn["iat"].as_i64(), passport)
}

fn requirement() -> PassportRequirement {
    PassportRequirement { trusted_issuers: vec!["some-issuer".into()], revoked: Some(Arc::new(|_, _, _| Ok(false))), ..Default::default() }
}

#[test]
fn a_call_without_a_passport_is_refused_before_the_counter_is_spent() {
    let c = call();
    let store = Arc::new(MemoryStateStore::new());
    let o = opts(store.clone(), requirement());
    let r = run(&c, &o, None);
    assert!(!r.allow && r.status == 403);
    assert!(r.reasons.iter().any(|x| x == "passport: malformed"), "{:?}", r.reasons);
    let stream = format!("{}:{}", c.grant["id"].as_str().unwrap(), c.pcactn["cap_chain"][0]["holder"].as_str().unwrap());
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
    // a passport that is not for a trusted issuer is refused with its reason
    let bogus = json!({"typ": "atlas-pca/passport", "ver": 1, "iss": "someone", "sub": "x", "sig": "s", "passport": {"id": "p", "model_id": "m", "operator": "o", "hardware_rooted": false}, "nbf": 1, "exp": 2, "iat": 1});
    let r = run(&c, &o, Some(&bogus));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.starts_with("passport: ")), "{:?}", r.reasons);
}

#[test]
fn a_configuration_without_issuers_or_a_revocation_source_is_refused() {
    let c = call();
    let o = opts(Arc::new(MemoryStateStore::new()), PassportRequirement::default());
    let r = run(&c, &o, None);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "authorize_config: missing required component(s): require_passport.trusted_issuers, require_passport.revoked (fail closed)"), "{:?}", r.reasons);
}
