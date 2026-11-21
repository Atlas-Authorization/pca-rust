//! Edge cases of `authorize` end to end with a REAL minted grant and a REAL signed PCActn: the F-1 threshold verdict arms, the
//! required risk inputs, a carried budget, an unreadable stored budget, the behavioural-contract gate (before and after the replay
//! claim), the taint gate, the principal resolver, a hardware-rooted passport requirement, the linked-template gate, the chain
//! shape of `policy_decision`, and the core verifier's suite policy, PQ pin and freshness gate.
mod common;

use atlas_pca::agent::*;
use atlas_pca::contracts::{sign_contract, ContractEnforcer};
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::taint::{InMemoryTrustedInputRegistry, TaintGate};
use atlas_pca::*;
use common::*;
use std::collections::HashMap;
use std::sync::Arc;

const AUD: &str = "rs-edges";

struct Fixture {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn fixture() -> Fixture {
    fixture_with(&json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()}))
}

fn fixture_with(env: &Value) -> Fixture {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let grant = mint_grant(&principal, &key.public, env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Default::default(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    Fixture { grant, pcactn: a.pcactn, op }
}

fn calm(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"semanticDistance": 0.1, "reversibility": 0.9, "blastRadius": 0.1, "taint": 0, "confidence": 0.9, "age": 0}).as_object().cloned().unwrap())
}

fn worst(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1}).as_object().cloned().unwrap())
}

/// Every input but `taint` and `semanticDistance`.
fn partial(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"reversibility": 0.9, "blastRadius": 0.1, "confidence": 0.9, "age": 0}).as_object().cloned().unwrap())
}

/// Every input but the semantic distance.
fn no_sd(_: &Operation, _: &Value, _: &Value) -> Result<Map<String, Value>, String> {
    Ok(json!({"reversibility": 0.9, "blastRadius": 0.1, "taint": 0, "confidence": 0.9, "age": 0}).as_object().cloned().unwrap())
}

/// `input` over a fixture; the statements in `$body` configure it (`$i` is the mutable `AuthorizeInput`).
macro_rules! go {
    ($f:expr, |$i:ident| { $($body:tt)* }) => {{
        let store = MemoryStateStore::new();
        go!($f, &store, |$i| { $($body)* })
    }};
    ($f:expr, $store:expr, |$i:ident| { $($body:tt)* }) => {{
        let f: &Fixture = $f;
        let g = f.grant.clone();
        let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
        let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
        let pins = harness_pins();
        #[allow(unused_mut)]
        let mut $i = AuthorizeInput {
            operation: Some(&f.op),
            audience: AUD,
            resolve_grant: Some(&resolve),
            state_store: Some($store),
            is_revoked: Some(&not_revoked),
            now: f.pcactn["iat"].as_i64(),
            plan: Some("single-step"),
            provenance_mediators: &pins,
            provenance_bundle: Some(&principal_direct),
            ..Default::default()
        };
        $($body)*
        authorize(Some(&f.pcactn), &$i)
    }};
}

fn has(r: &AuthorizeResult, needle: &str) -> bool {
    r.reasons.iter().any(|x| x.contains(needle))
}

// ---- the F-1 threshold verdict

#[test]
fn a_threshold_hook_that_enforced_enough_admits_a_risky_action() {
    let f = fixture();
    let hook = |_: &Value, _: &Value, _now: i64| HookResult::Enforced { ok: true, reason: None, t: Some(3) };
    let r = go!(&f, |i| {
        i.risk = Some(&worst as &RiskFn);
        i.threshold = Some(&hook as &ThresholdHookFn);
    });
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(r.checks.get("threshold"), Some(&CheckStatus::Pass));
}

#[test]
fn a_rejected_threshold_proof_is_named_as_such() {
    let f = fixture();
    let hook = |_: &Value, _: &Value, _now: i64| HookResult::Enforced { ok: false, reason: Some("bad cosignature".into()), t: Some(3) };
    let r = go!(&f, |i| {
        i.risk = Some(&worst as &RiskFn);
        i.threshold = Some(&hook as &ThresholdHookFn);
    });
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "threshold: t=3 required and the threshold proof was rejected"), "{:?}", r.reasons);
    assert!(r.reasons.iter().any(|x| x == "threshold: bad cosignature"), "{:?}", r.reasons);
}

// ---- required risk inputs

#[test]
fn required_risk_inputs_are_checked_only_when_configured_and_named_when_missing() {
    let f = fixture();
    // not configured: no risk_inputs check at all
    let r = go!(&f, |i| {
        i.risk = Some(&calm as &RiskFn);
    });
    assert!(r.allow, "{:?}", r.reasons);
    assert!(!r.checks.contains_key("risk_inputs"));
    // configured and supplied
    let r = go!(&f, |i| {
        i.risk = Some(&calm as &RiskFn);
        i.require_risk_inputs = &["taint", "reversibility"];
    });
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(r.checks.get("risk_inputs"), Some(&CheckStatus::Pass));
    // configured and NOT supplied (the single-step plan supplies only the semantic distance)
    let r = go!(&f, |i| {
        i.risk = Some(&partial as &RiskFn);
        i.require_risk_inputs = &["taint", "reversibility"];
    });
    assert!(!r.allow);
    assert_eq!(r.checks.get("risk_inputs"), Some(&CheckStatus::Fail));
    assert!(r.reasons.iter().any(|x| x == "risk_inputs: required risk input(s) not supplied by the server: taint"), "{:?}", r.reasons);
    let r = go!(&f, |i| {
        i.risk = Some(&no_sd as &RiskFn);
        i.require_risk_inputs = &["semanticDistance"];
    });
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(r.checks.get("risk_inputs"), Some(&CheckStatus::Pass));
    let r = go!(&f, |i| {
        i.risk = Some(&partial as &RiskFn);
        i.require_risk_inputs = &["taint", "semanticDistance", "blastRadius", "age", "confidence", "reversibility"];
    });
    assert!(r.reasons.iter().any(|x| x == "risk_inputs: required risk input(s) not supplied by the server: taint"), "{:?}", r.reasons);
}

// ---- the budget

#[test]
fn a_carried_budget_is_used_instead_of_the_stored_or_seeded_one() {
    let f = fixture();
    let iat = f.pcactn["iat"].as_i64().unwrap();
    let ctx = move |_: &Value| Ok::<_, String>(Some(json!({"budget": {"B": 0, "tau": iat, "asOf": iat}})));
    let r = go!(&f, |i| {
        i.risk = Some(&calm as &RiskFn);
        i.context = Some(&ctx as &ContextProvider);
    });
    assert!(!r.allow, "an empty budget cannot cover a metered action");
    assert!(has(&r, "required but no threshold verifier is enforced"), "{:?}", r.reasons);
    // a malformed carried budget is ignored (the grant's own bMax seeds it)
    let bad = move |_: &Value| Ok::<_, String>(Some(json!({"budget": {"B": "0", "tau": iat}})));
    let r = go!(&f, |i| {
        i.risk = Some(&calm as &RiskFn);
        i.context = Some(&bad as &ContextProvider);
    });
    assert!(r.allow, "{:?}", r.reasons);
}

/// A store whose budget read answers as configured; everything else is the memory store.
struct OddBudget {
    inner: MemoryStateStore,
    answer: Result<Option<Value>, StoreError>,
}
impl StateStore for OddBudget {
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
    fn budget(&self, _key: &str) -> Result<Option<Value>, StoreError> {
        self.answer.clone()
    }
    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        self.inner.claim_budgeted(key, counter, before, after)
    }
}

#[test]
fn an_unreadable_or_malformed_stored_budget_fails_only_the_budget_check() {
    let f = fixture();
    for (answer, why) in [
        (Ok(Some(json!({"B": "x"}))), "budget: the stored trust budget is malformed (fail closed)"),
        (Err(StoreError("down".into())), "budget: the trust budget could not be read (fail closed)"),
    ] {
        let s = OddBudget { inner: MemoryStateStore::new(), answer };
        // the worst-case risk would ALSO fail `threshold` if the risk step ran on the seeded budget
        let r = go!(&f, &s, |i| {
            i.risk = Some(&worst as &RiskFn);
        });
        assert!(!r.allow);
        assert!(r.reasons.iter().any(|x| x == why), "{:?}", r.reasons);
        assert_eq!(r.failed_checks(), vec!["budget"], "{:?}", r.reasons);
    }
}

// ---- the behavioural-contract gate

fn kp() -> KeyPair {
    KeyPair::from_seed(&[21u8; 32])
}

fn signed_never(verb: &str) -> Value {
    let c = json!({"version": 1, "principal": kp().public, "clauses": [{"id": "n", "kind": "never", "p": {"verb": verb}}]});
    sign_contract(&c, &kp()).unwrap()
}

fn enforcer(kv: Arc<dyn AtomicKv>, verb: &str) -> ContractEnforcer {
    ContractEnforcer::open(kv, &signed_never(verb), &kp().public, None, Some(Box::new(|| 1.0e12)), true).unwrap()
}

/// A store that reads fine and fails every write: the peek before the replay claim passes, the commit after it cannot.
struct NoWrite(MemoryAtomicKv);
impl AtomicKv for NoWrite {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.get(key)
    }
    fn update(&self, _key: &str, _f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        Err(StoreError("down".into()))
    }
}

#[test]
fn a_violated_contract_refuses_before_the_counter_is_spent_with_its_clause_ids() {
    let f = fixture();
    let e = enforcer(Arc::new(MemoryAtomicKv::new()), "refund");
    let store = MemoryStateStore::new();
    let r = go!(&f, &store, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.contracts = Some(&e);
    });
    assert!(!r.allow && r.status == 403);
    assert_eq!(r.reason.as_deref(), Some("contract: violated (n)"));
    assert_eq!(r.checks.get("contract"), Some(&CheckStatus::Fail));
    let stream = format!("{}:{}", f.grant["id"].as_str().unwrap(), f.pcactn["cap_chain"][0]["holder"].as_str().unwrap());
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
}

#[test]
fn a_contract_store_that_cannot_be_read_refuses_without_clause_ids() {
    struct NoRead;
    impl AtomicKv for NoRead {
        fn get(&self, _key: &str) -> Result<Option<Value>, StoreError> {
            Err(StoreError("down".into()))
        }
        fn update(&self, _key: &str, _f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
            Err(StoreError("down".into()))
        }
    }
    let f = fixture();
    let e = enforcer(Arc::new(NoRead), "other");
    let r = go!(&f, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.contracts = Some(&e);
    });
    assert!(!r.allow);
    assert_eq!(r.reason.as_deref(), Some("contract: store-error"));
}

#[test]
fn an_admitted_action_commits_its_contract_state_and_a_failing_commit_denies() {
    let f = fixture();
    let kv = Arc::new(MemoryAtomicKv::new());
    let e = enforcer(kv.clone(), "other");
    let r = go!(&f, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.contracts = Some(&e);
    });
    assert!(r.allow, "{:?}", r.reasons);
    assert!(e.state().unwrap().is_some(), "the admitted action advanced the durable contract state");
    // the commit after the claim fails: the action is denied, with the check's own prefix
    let e = enforcer(Arc::new(NoWrite(MemoryAtomicKv::new())), "other");
    let r = go!(&f, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.contracts = Some(&e);
    });
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "contract: contract: store-error"), "{:?}", r.reasons);
}

// ---- the taint gate

#[test]
fn the_taint_gate_denies_a_ref_the_server_cannot_vouch_for() {
    let f = fixture();
    let gate = TaintGate { registry: Arc::new(InMemoryTrustedInputRegistry::new()), resource_graph: None, max_taint: 0.0 };
    let r = go!(&f, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.enforce_taint = Some(&gate);
    });
    assert!(!r.allow);
    assert!(r.failed_checks().contains(&"taint_gate"), "{:?}", r.reasons);
}

// ---- the principal resolver

#[test]
fn the_principal_resolver_decides_the_principal_check() {
    let f = fixture();
    let run = |answer: Result<Option<Value>, String>, require: bool| {
        let resolver = move |_: &str, _: &Value| answer.clone();
        go!(&f, |i| {
            i.risk = Some(&insecure_calm_risk as &RiskFn);
            i.resolve_principal = Some(&resolver as &PrincipalResolver);
            i.require_verified_principal = require;
        })
    };
    let ok = run(Ok(Some(json!({"verified": true}))), false);
    assert!(ok.allow, "{:?}", ok.reasons);
    assert_eq!(ok.checks.get("principal"), Some(&CheckStatus::Pass));
    let loose = run(Ok(Some(json!({"verified": false}))), false);
    assert!(loose.allow, "{:?}", loose.reasons);
    assert_eq!(loose.checks.get("principal"), Some(&CheckStatus::NotEnforced));
    let unknown = run(Ok(None), false);
    assert!(unknown.allow);
    assert_eq!(unknown.checks.get("principal"), Some(&CheckStatus::NotEnforced));
    let verified_required = run(Ok(Some(json!({"verified": true}))), true);
    assert!(verified_required.allow, "{:?}", verified_required.reasons);
    assert_eq!(verified_required.checks.get("principal"), Some(&CheckStatus::Pass));
    for answer in [Ok::<_, String>(Some(json!({"verified": false}))), Ok(Some(json!({"verified": "true"}))), Ok(None)] {
        let r = run(answer.clone(), true);
        assert!(!r.allow, "{answer:?}");
        assert!(r.reasons.iter().any(|x| x == "principal: the grant issuer is not an enrolled, verified principal"), "{:?}", r.reasons);
    }
    let down = run(Err("down".into()), false);
    assert!(!down.allow);
    assert!(down.reasons.iter().any(|x| x == "principal: the principal resolver failed (fail closed)"), "{:?}", down.reasons);
}

// ---- a hardware-rooted passport requirement

#[test]
fn a_software_passport_does_not_meet_a_hardware_requirement() {
    let f = fixture();
    let iat = f.pcactn["iat"].as_i64().unwrap();
    let holder = f.pcactn["cap_chain"][0]["holder"].as_str().unwrap().to_string();
    let issuer = KeyPair::generate().unwrap();
    let pp = issue_passport(&json!({"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": iat - 1000})).unwrap();
    let sp = sign_passport(&pp, &issuer, &holder, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let other = sign_passport(&pp, &issuer, &KeyPair::generate().unwrap().public, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let run_with = |hardware: bool, sp: &Value| {
        let req = PassportRequirement { trusted_issuers: vec![issuer.public.clone()], revoked: Some(Arc::new(|_, _, _| Ok(false))), hardware, ..Default::default() };
        let o = AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_, _| Ok(false))
            .with_plan(Some(SINGLE_STEP))
            .with_risk(insecure_calm_risk)
            .with_provenance_mediators(harness_pins())
            .with_provenance_bundle(principal_direct)
            .with_require_passport(req);
        let g = f.grant.clone();
        let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
        o.run_with_passport(Some(&f.pcactn), Some(&f.op), AUD, &resolve, Some(iat), Some(sp))
    };
    let run = |hardware: bool| run_with(hardware, &sp);
    let soft = run(false);
    assert!(soft.allow, "{:?}", soft.reasons);
    let hard = run(true);
    assert!(!hard.allow && hard.status == 403);
    assert!(hard.reasons.iter().any(|x| x == "passport: hardware_evidence_missing"), "{:?}", hard.reasons);
    // a passport issued for another key is refused: the subject is the PCActn's leaf holder
    let wrong = run_with(false, &other);
    assert!(!wrong.allow && wrong.reasons.iter().any(|x| x == "passport: subject_mismatch"), "{:?}", wrong.reasons);
}

// ---- the linked-template gate

#[test]
fn a_grant_with_a_template_ref_gets_the_resolvers_reason_not_the_missing_ref_text() {
    let doc = strict_parse(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/policy-link-vectors.json")).unwrap()).unwrap();
    let row = doc["resolve"].as_array().unwrap().iter().find(|r| r["name"] == "a registry without the version").unwrap();
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy(), "template_ref": row["ref"].clone()});
    let f = fixture_with(&env);
    let registry = row["registry"].clone();
    let reg = move || registry.clone();
    let r = go!(&f, |i| {
        i.risk = Some(&insecure_calm_risk as &RiskFn);
        i.require_linked_template = Some(&reg);
    });
    assert!(!r.allow);
    assert_eq!(r.reason, Some(format!("template: {}", row["expect"]["reason"].as_str().unwrap())));
}

// ---- policy_decision

#[test]
fn a_null_chain_is_no_chain_and_any_other_non_array_is_malformed() {
    let f = fixture();
    let ctx = json!({"now": f.pcactn["iat"], "action": {"verb": "refund", "resource": "orders/1", "params": {}}});
    let none = policy_decision(&f.grant, &Value::Null, &ctx);
    assert!(!none["reasons"].as_array().unwrap().iter().any(|r| r == "chain_malformed"), "{none}");
    let bad = policy_decision(&f.grant, &json!("x"), &ctx);
    assert!(bad["reasons"].as_array().unwrap().iter().any(|r| r == "chain_malformed"), "{bad}");
}

// ---- the core verifier

fn core_opts<'a>(f: &Fixture, pins: Option<&'a HashMap<String, String>>) -> VerifyOptions<'a> {
    let _ = f;
    VerifyOptions { insecure_skip_plan_root_check: true, pq_pins: pins, ..VerifyOptions::default() }
}

#[test]
fn the_allowed_suites_policy_reaches_the_core_verifier_through_both_wrappers() {
    let f = fixture();
    let iat = f.pcactn["iat"].as_i64().unwrap();
    let text = atlas_pca::serde_json::to_string(&f.pcactn).unwrap();
    let none: &[String] = &[];
    let open = verify_pcactn_core_policy(&f.pcactn, &f.grant, iat, AUD, None);
    assert_eq!(open.checks.get("leaf_signature"), Some(&true), "{open:?}");
    let shut = verify_pcactn_core_policy(&f.pcactn, &f.grant, iat, AUD, Some(none));
    assert_eq!(shut.checks.get("leaf_signature"), Some(&false), "{shut:?}");
    let open = verify_pcactn_json_policy(&text, &f.grant, iat, AUD, None);
    assert_eq!(open.checks.get("leaf_signature"), Some(&true), "{open:?}");
    let shut = verify_pcactn_json_policy(&text, &f.grant, iat, AUD, Some(none));
    assert_eq!(shut.checks.get("leaf_signature"), Some(&false), "{shut:?}");
}

#[test]
fn a_pq_pin_refuses_a_grant_that_names_ed25519_explicitly_and_ignores_other_suites() {
    let f = fixture();
    let iat = f.pcactn["iat"].as_i64().unwrap();
    let pins = HashMap::from([(f.grant["issuer"].as_str().unwrap().to_string(), "some-pq-public-key".to_string())]);
    let with_alg = |alg: &str| {
        let mut g = f.grant.clone();
        g["alg"] = json!(alg);
        verify_pcactn_core_with(&f.pcactn, &g, iat, AUD, &core_opts(&f, Some(&pins)))
    };
    assert_eq!(with_alg("ed25519").checks.get("pq_pin"), Some(&false));
    assert!(!with_alg("ml-dsa-65").checks.contains_key("pq_pin"), "a post-quantum grant is not the downgrade the pin refuses");
}

#[test]
fn the_freshness_gate_of_the_core_verifier_reports_its_check() {
    let f = fixture();
    let iat = f.pcactn["iat"].as_i64().unwrap();
    let opts = VerifyOptions { insecure_skip_plan_root_check: true, freshness_gate: Some(FreshnessGate { max_age_ms: 1000.0, epoch_ms: Some(1000.0), now: None, clock_skew_ms: None }), ..VerifyOptions::default() };
    let v = verify_pcactn_core_with(&f.pcactn, &f.grant, iat, AUD, &opts);
    assert!(!v.allow);
    assert_eq!(v.checks.get("freshness_anchor"), Some(&false), "{v:?}");
    assert!(!verify_pcactn_core_with(&f.pcactn, &f.grant, iat, AUD, &core_opts(&f, None)).checks.contains_key("freshness_anchor"));
}
