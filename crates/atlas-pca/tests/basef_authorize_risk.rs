//! F2 end to end: a REAL minted grant and a REAL signed PCActn (the agent producers) driven through `authorize` with the policy
//! VM's risk step: a calm action is admitted and its spend is stored with the counter, a risky one needs a threshold verifier, a
//! concurrent spend is a budget conflict that consumes nothing, and an admitted action raises the revocation-epoch pin.
mod common;

use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use base64::Engine;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Mutex;

const AUD: &str = "rs-risk";

struct Fixture {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn fixture() -> Fixture {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    // the signed freshness epoch the revocation gate's epoch must not exceed (the pin test serves epoch 3)
    let mut extra = Map::new();
    extra.insert("freshness".into(), json!({"beacon_ref": "b", "epoch": 3, "accumulator_witness": "w"}));
    let a = agent.act("refund", "orders/1", Some(&params), extra, &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    Fixture { grant, pcactn: a.pcactn, op }
}

fn calm(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"semanticDistance": 0.1, "reversibility": 0.9, "blastRadius": 0.1, "taint": 0, "confidence": 0.9, "age": 0}).as_object().cloned().unwrap())
}

fn worst(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1}).as_object().cloned().unwrap())
}

/// Records every claim and can force a budget conflict, like a second instance that spent first.
struct Spy {
    inner: MemoryStateStore,
    conflict: bool,
    keys: Mutex<Vec<String>>,
}
impl StateStore for Spy {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.inner.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.inner.last(key)
    }
    fn supports_pins(&self) -> bool {
        true
    }
    fn pin(&self, key: &str) -> Result<Option<i64>, StoreError> {
        self.inner.pin(key)
    }
    fn raise_pin(&self, key: &str, v: i64) -> Result<(), StoreError> {
        self.inner.raise_pin(key, v)
    }
    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.inner.budget(key)
    }
    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        self.keys.lock().unwrap().push(key.to_string());
        if self.conflict && after.is_some() {
            return Ok(BudgetClaim::Conflict);
        }
        self.inner.claim_budgeted(key, counter, before, after)
    }
}

fn spy(conflict: bool) -> Spy {
    Spy { inner: MemoryStateStore::new(), conflict, keys: Mutex::new(Vec::new()) }
}

fn run(f: &Fixture, store: &Spy, risk: &RiskFn, hook: Option<&ThresholdHookFn>, gate: Option<&RevocationStaleness>) -> AuthorizeResult {
    let g = f.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let input = AuthorizeInput {
        risk: Some(risk),
        threshold: hook,
        operation: Some(&f.op),
        audience: AUD,
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&not_revoked),
        revocation_staleness: gate,
        now: f.pcactn["iat"].as_i64(),
        plan: Some("single-step"),
        provenance_mediators: &harness_pins(),
        provenance_bundle: Some(&principal_direct),
        ..Default::default()
    };
    authorize(Some(&f.pcactn), &input)
}

#[test]
fn a_calm_action_is_admitted_and_its_spend_is_stored_with_the_counter() {
    let f = fixture();
    let s = spy(false);
    let r = run(&f, &s, &calm, None, None);
    assert!(r.allow, "{:?}", r.reasons);
    let key = s.keys.lock().unwrap().first().cloned().expect("the claim went through claim_budgeted");
    let b = s.inner.budget(&key).unwrap().expect("a metered spend is stored");
    assert!(b["B"].as_f64().unwrap() < 1.0, "the spend debits the budget: {b}");
    assert_eq!(s.inner.last(&key), Some(Some(1)));
}

#[test]
fn a_risky_action_needs_a_threshold_verifier_and_an_enforced_one_must_report_enough() {
    let f = fixture();
    let r = run(&f, &spy(false), &worst, None, None);
    assert!(!r.allow, "an action at the worst-case risk with no threshold verifier is never admitted");
    let hook = |_: &Value, _: &Value, _now: i64| HookResult::Enforced { ok: true, reason: None, t: Some(1) };
    let r = run(&f, &spy(false), &worst, Some(&hook), None);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.contains("below the server-derived threshold")), "{:?}", r.reasons);
}

#[test]
fn a_concurrent_spend_is_a_budget_conflict_that_consumes_nothing() {
    let f = fixture();
    let s = spy(true);
    let r = run(&f, &s, &calm, None, None);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.contains("the trust budget changed while this action was decided")), "{:?}", r.reasons);
    let key = s.keys.lock().unwrap()[0].clone();
    assert_eq!(s.inner.last(&key), Some(None), "the counter was not consumed");
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn an_admitted_action_raises_the_revocation_epoch_pin() {
    let f = fixture();
    let guardian = SigningKey::from_bytes(&[7u8; 32]);
    let (gref, iat) = (f.pcactn["grant_ref"].as_str().unwrap().to_string(), f.pcactn["iat"].as_i64().unwrap());
    let mut e = json!({"instance_id": "i", "grant_ref": gref, "epoch": 3, "set_size": 0, "root": "r", "issued_at": iat - 1_000, "not_after": iat + 600_000});
    let mut msg = b"atlas-pca/revepoch/v1\0".to_vec();
    msg.extend_from_slice(canonicalize(&e).as_bytes());
    e["guardian"] = json!(b64(guardian.verifying_key().as_bytes()));
    e["sig"] = json!(b64(&guardian.sign(&msg).to_bytes()));
    let gate = RevocationStaleness::new(RevocationStalenessPolicy::default(), move |_, _| Ok(Some(RevocationState { epoch: Some(e.clone()), ..Default::default() })))
        .unwrap()
        .with_guardian(b64(guardian.verifying_key().as_bytes()))
        .with_ids(|_| Vec::new());
    let s = spy(false);
    let r = run(&f, &s, &calm, None, Some(&gate));
    assert!(r.allow, "{:?}", r.reasons);
    let pin = format!("{}:epoch", f.grant["id"].as_str().unwrap());
    assert_eq!(s.inner.pin(&pin), Ok(Some(3)));
}

fn run_adaptive(f: &Fixture, adp: &AdaptivePolicyFn) -> AuthorizeResult {
    let g = f.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = spy(false);
    let input = AuthorizeInput {
        risk: Some(&calm as &RiskFn),
        adaptive_policy: Some(adp),
        operation: Some(&f.op),
        audience: AUD,
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: f.pcactn["iat"].as_i64(),
        plan: Some("single-step"),
        provenance_mediators: &harness_pins(),
        provenance_bundle: Some(&principal_direct),
        ..Default::default()
    };
    authorize(Some(&f.pcactn), &input)
}

#[test]
fn an_adaptive_policy_can_only_tighten_and_an_invalid_one_refuses() {
    let f = fixture();
    // no tightening offered: unchanged
    assert!(run_adaptive(&f, &|_| None).allow);
    // the grant's own policy offered back: not tighter, still admitted
    let same = default_risk_policy();
    assert!(run_adaptive(&f, &move |_| Some(same.clone())).allow);
    // a policy that puts this action's risk in a higher band needs a higher threshold than the grant's
    let mut tight = default_risk_policy();
    tight["theta1"] = json!(0.01);
    tight["theta2"] = json!(0.02);
    let r = run_adaptive(&f, &move |_| Some(tight.clone()));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.contains("adaptive: tightened policy requires threshold t=") && x.contains("(grant policy: t=1)")), "{:?}", r.reasons);
    // an invalid policy
    let r = run_adaptive(&f, &|_| Some(json!({})));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.contains("adaptive: invalid policy (")), "{:?}", r.reasons);
}
