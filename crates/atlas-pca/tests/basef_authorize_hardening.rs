//! 0.5 hardening of `authorize`: the state store's pins, budgets and scope, `multi_instance`, the plan default (no plan configured
//! denies `plan_root_authorized`) and the risk reasons. The fixtures are the shared authorize-fixtures (zero risk weights).
mod common;

use atlas_pca::{authorize, AuthorizeInput, BudgetClaim, ClaimResult, MemoryStateStore, Operation, StateStore, StoreError, StoreScope};
use serde_json::{json, Value};
use std::sync::Arc;

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

/// A store that implements only the two required methods: every default applies.
struct Bare(MemoryStateStore);
impl StateStore for Bare {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
}

fn budget(b: f64) -> Value {
    json!({"B": b, "tau": 0, "asOf": 0})
}

#[test]
fn the_memory_store_is_process_scoped_and_holds_monotone_pins() {
    let s = MemoryStateStore::new();
    assert_eq!(s.scope(), StoreScope::Process);
    assert!(s.supports_pins());
    assert_eq!(s.pin("g:epoch"), Ok(None));
    s.raise_pin("g:epoch", 5).unwrap();
    assert_eq!(s.pin("g:epoch"), Ok(Some(5)));
    s.raise_pin("g:epoch", 3).unwrap();
    assert_eq!(s.pin("g:epoch"), Ok(Some(5)), "a pin never lowers");
    s.raise_pin("g:epoch", 5).unwrap();
    s.raise_pin("g:epoch", 7).unwrap();
    assert_eq!(s.pin("g:epoch"), Ok(Some(7)));
    assert_eq!(s.pin("other:epoch"), Ok(None), "pins are per key");
    // concurrent raises keep the maximum
    let s = Arc::new(MemoryStateStore::new());
    std::thread::scope(|t| {
        for v in [7, 6, 9, 1, 8] {
            let s = s.clone();
            t.spawn(move || s.raise_pin("k", v).unwrap());
        }
    });
    assert_eq!(s.pin("k"), Ok(Some(9)));
}

#[test]
fn a_store_without_pins_or_budgets_fails_closed_by_default() {
    let b = Bare(MemoryStateStore::new());
    assert_eq!(b.scope(), StoreScope::Shared, "an unknown store is assumed shared");
    assert!(!b.supports_pins());
    assert!(b.pin("k").is_err());
    assert!(b.raise_pin("k", 1).is_err());
    assert_eq!(b.budget("k"), Ok(None));
    // a claim with nothing to store is a plain claim
    assert_eq!(b.claim_budgeted("k", 1, None, None), Ok(BudgetClaim::Claimed));
    assert_eq!(b.claim_budgeted("k", 1, None, None), Ok(BudgetClaim::Replay(Some(1))));
    // a metered action (a budget to store) is refused: the spend would be forgotten
    let refused = b.claim_budgeted("k", 2, None, Some(&budget(0.5)));
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(b.last("k"), Some(Some(1)), "a refused claim consumes nothing");
}

#[test]
fn the_budget_moves_with_the_counter_and_a_stale_read_is_a_conflict() {
    let s = MemoryStateStore::new();
    assert_eq!(s.budget("k"), Ok(None));
    assert_eq!(s.claim_budgeted("k", 1, None, Some(&budget(0.8))), Ok(BudgetClaim::Claimed));
    assert_eq!(s.budget("k"), Ok(Some(budget(0.8))));
    assert_eq!(s.last("k"), Some(Some(1)));
    // another action read the budget before the first one wrote: its CAS fails and nothing is written
    assert_eq!(s.claim_budgeted("k", 2, None, Some(&budget(0.5))), Ok(BudgetClaim::Conflict));
    assert_eq!(s.budget("k"), Ok(Some(budget(0.8))));
    assert_eq!(s.last("k"), Some(Some(1)), "a conflict does not consume the counter");
    // read the current budget and the CAS holds
    assert_eq!(s.claim_budgeted("k", 2, Some(&budget(0.8)), Some(&budget(0.5))), Ok(BudgetClaim::Claimed));
    assert_eq!(s.budget("k"), Ok(Some(budget(0.5))));
    // a replayed counter is a replay (checked before the budget), whatever the budget says
    assert_eq!(s.claim_budgeted("k", 2, Some(&budget(0.5)), Some(&budget(0.1))), Ok(BudgetClaim::Replay(Some(2))));
    assert_eq!(s.claim_budgeted("k", 1, None, None), Ok(BudgetClaim::Replay(Some(2))));
    assert_eq!(s.budget("k"), Ok(Some(budget(0.5))));
    // a claim with no budget to store leaves the stored one (and still needs it to match)
    assert_eq!(s.claim_budgeted("k", 3, Some(&budget(0.5)), None), Ok(BudgetClaim::Claimed));
    assert_eq!(s.budget("k"), Ok(Some(budget(0.5))));
    assert_eq!(s.claim_budgeted("k", 4, None, None), Ok(BudgetClaim::Conflict), "a budget exists but the caller read none");
}

fn run(multi_instance: Option<bool>, plan: Option<&str>, risk: Option<&atlas_pca::RiskFn>, store: &dyn StateStore) -> atlas_pca::AuthorizeResult {
    let d = fixtures();
    let c = &d["cases"][0];
    let s = &c["steps"][0];
    let op = Operation::from_json(&s["operation"]).unwrap();
    let g = c["grant"].clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let pins = common::harness_pins();
    let input = AuthorizeInput {
        risk,
        multi_instance,
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&revoked),
        now: d["now"].as_i64(),
        plan,
        provenance_mediators: &pins,
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    authorize(Some(&s["pcactn"]), &input)
}

fn calm() -> Option<&'static atlas_pca::RiskFn> {
    Some(&atlas_pca::insecure_calm_risk)
}
const SINGLE: Option<&str> = Some("single-step");

#[test]
fn multi_instance_refuses_a_process_scoped_store() {
    const WHY: &str = "authorize_config: multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)";
    let process = run(Some(true), SINGLE, calm(), &MemoryStateStore::new());
    assert_eq!((process.allow, process.status, process.reason.as_deref()), (false, 403, Some(WHY)), "{process:?}");
    // a shared store is accepted, and so is a process store when the host says it is one process (or says nothing)
    assert!(run(Some(true), SINGLE, calm(), &Bare(MemoryStateStore::new())).allow);
    assert!(run(Some(false), SINGLE, calm(), &MemoryStateStore::new()).allow);
    assert!(run(None, SINGLE, calm(), &MemoryStateStore::new()).allow);
}

#[test]
fn no_plan_configured_denies_plan_root_authorized() {
    let denied = run(None, None, calm(), &MemoryStateStore::new());
    assert!(!denied.allow, "{denied:?}");
    assert_eq!(denied.failed_checks(), vec!["plan_root_authorized"]);
    assert!(denied.reason.as_deref().unwrap_or("").starts_with("plan_root_authorized: default-deny: no authorized plan is configured"), "{:?}", denied.reason);
    assert!(run(None, SINGLE, calm(), &MemoryStateStore::new()).allow, "single-step accepts the one-node plan");
}

#[test]
fn missing_risk_inputs_are_named_in_the_reasons_and_supplied_ones_are_not() {
    // zero weights: r = 0 whatever the inputs, so the action is released either way; the single-step plan supplies the semantic distance
    let none = run(None, SINGLE, None, &MemoryStateStore::new());
    assert!(none.allow, "{none:?}");
    assert!(
        none.reasons.iter().any(|r| r == "policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence"),
        "{:?}",
        none.reasons
    );
    let calm = run(None, SINGLE, calm(), &MemoryStateStore::new());
    assert!(calm.allow && !calm.reasons.iter().any(|r| r.contains("risk input")), "{:?}", calm.reasons);
}

#[test]
fn a_failing_risk_provider_denies() {
    let failing = |_: &Operation, _: &Value, _: &Value| -> Result<serde_json::Map<String, Value>, String> { Err("down".into()) };
    let r = run(None, SINGLE, Some(&failing as &atlas_pca::RiskFn), &MemoryStateStore::new());
    assert!(!r.allow, "{r:?}");
    assert_eq!(r.failed_checks(), vec!["risk"]);
    assert!(r.reason.as_deref().unwrap_or("").starts_with("risk: the server risk provider failed (fail closed)"), "{:?}", r.reason);
    let panicking = |_: &Operation, _: &Value, _: &Value| -> Result<serde_json::Map<String, Value>, String> { panic!("boom") };
    assert!(!run(None, SINGLE, Some(&panicking as &atlas_pca::RiskFn), &MemoryStateStore::new()).allow);
}
