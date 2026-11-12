//! The core verifier's `pq_pin` rule (VerifyOptions::pq_pins): a classical root grant whose issuer has a pin is refused with the
//! server verifier's reason; an unrelated pin, empty pins or no pins leave the verdict unchanged and add no `pq_pin` check.
use std::collections::HashMap;

use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const AUD: &str = "rs-core-pin";

fn fixture() -> (Value, Value) {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let a = agent.act("refund", "orders/1", Some(&json!({"amount_cents": 500})), Default::default(), &Suite::default()).unwrap();
    (grant, a.pcactn)
}

fn verdict(grant: &Value, p: &Value, pins: Option<&HashMap<String, String>>) -> Verdict {
    let opts = VerifyOptions { insecure_skip_plan_root_check: true, pq_pins: pins, ..VerifyOptions::default() };
    verify_pcactn_core_with(p, grant, p["iat"].as_i64().unwrap(), AUD, &opts)
}

#[test]
fn a_classical_root_from_a_pinned_issuer_is_refused() {
    let (grant, p) = fixture();
    let issuer = grant["issuer"].as_str().unwrap().to_string();
    let pins = HashMap::from([(issuer, "some-pq-public-key".to_string())]);
    let v = verdict(&grant, &p, Some(&pins));
    assert!(!v.allow);
    assert_eq!(v.checks.get("pq_pin"), Some(&false));
    assert_eq!(v.reason, "pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused");
    assert_eq!(v.checks.get("chain"), Some(&true), "the chain check itself is unchanged");
}

#[test]
fn an_unrelated_pin_empty_pins_or_no_pins_change_nothing() {
    let (grant, p) = fixture();
    let base = verdict(&grant, &p, None);
    assert!(base.allow, "{}", base.reason);
    for pins in [HashMap::new(), HashMap::from([("someone-else".to_string(), "k".to_string())])] {
        let v = verdict(&grant, &p, Some(&pins));
        assert!(v.allow, "{}", v.reason);
        assert!(!v.checks.contains_key("pq_pin"), "no pq_pin check appears");
        assert_eq!(v.checks, base.checks);
    }
}
