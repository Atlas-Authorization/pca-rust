//! F11: the atomic-kv, trust-budget and monotone-pin conformance kits. The shipped stores pass; each deliberately broken store fails the
//! kit that guards the property it breaks (so a green run means something).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atlas_pca::store_conformance::*;
use atlas_pca::*;
use serde_json::Value;

fn opts() -> Options {
    Options { rounds: 4, copies: 12, durable: true }
}

fn failed(r: &ConformanceReport) -> Vec<&'static str> {
    r.tests.iter().filter(|t| t.status == Status::Fail).map(|t| t.test).collect()
}

fn state(b: Arc<dyn StateStore>) -> impl Fn() -> Arc<dyn StateStore> + Send + Sync {
    move || b.clone()
}

#[test]
fn the_shipped_stores_pass_every_kit() {
    let kv = Arc::new(MemoryAtomicKv::new());
    let r = run_kv_store_conformance(&|| kv.clone() as Arc<dyn AtomicKv>, &opts());
    r.assert_passed();
    assert_eq!(r.tests.iter().map(|t| t.test).collect::<Vec<_>>(), ["kv-basic", "kv-update-atomic", "kv-list-prefix", "kv-durability"]);
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
    let st: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let r = run_budget_store_conformance(&state(st.clone()), &opts());
    r.assert_passed();
    assert_eq!(r.tests.iter().map(|t| t.test).collect::<Vec<_>>(), ["budget-claim", "budget-conflict", "budget-concurrent", "budget-durability"]);
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
    let r = run_pin_store_conformance(&state(st), &opts());
    r.assert_passed();
    assert_eq!(r.tests.iter().map(|t| t.test).collect::<Vec<_>>(), ["pin-monotone", "pin-concurrent", "pin-durability"]);
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
}

#[test]
fn a_non_durable_store_skips_the_durability_tests() {
    let st: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let o = Options { durable: false, ..opts() };
    let skipped = |r: &ConformanceReport| r.tests.iter().filter(|t| t.status == Status::Skip).map(|t| t.test).collect::<Vec<_>>();
    assert_eq!(skipped(&run_budget_store_conformance(&state(st.clone()), &o)), ["budget-durability"]);
    assert_eq!(skipped(&run_pin_store_conformance(&state(st), &o)), ["pin-durability"]);
    let kv = Arc::new(MemoryAtomicKv::new());
    assert_eq!(skipped(&run_kv_store_conformance(&|| kv.clone() as Arc<dyn AtomicKv>, &o)), ["kv-durability"]);
}

/// Reads, waits, then writes: two racers both start from the same value.
struct RacyKv(MemoryAtomicKv);
impl AtomicKv for RacyKv {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.get(key)
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        let cur = self.0.get(key)?;
        std::thread::sleep(std::time::Duration::from_millis(2));
        if let Some(n) = f(cur.as_ref()) {
            self.0.update(key, &mut |_| Some(n.clone()))?;
        }
        self.0.get(key)
    }
    fn list(&self, prefix: &str) -> Result<Option<Vec<Value>>, StoreError> {
        self.0.list(prefix)
    }
}

/// Lists every document whatever the prefix.
struct ListsEverything(MemoryAtomicKv);
impl AtomicKv for ListsEverything {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.get(key)
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        self.0.update(key, f)
    }
    fn list(&self, _: &str) -> Result<Option<Vec<Value>>, StoreError> {
        self.0.list("")
    }
}

/// Stores `None` as a write of the stored value's absence: an update that declines still creates the key.
struct CreatesOnNone(MemoryAtomicKv);
impl AtomicKv for CreatesOnNone {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.get(key)
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        self.0.update(key, &mut |cur| Some(f(cur).unwrap_or_else(|| cur.cloned().unwrap_or_else(|| serde_json::json!({})))))
    }
    fn list(&self, prefix: &str) -> Result<Option<Vec<Value>>, StoreError> {
        self.0.list(prefix)
    }
}

#[test]
fn broken_kvs_fail_the_kit_that_guards_the_property() {
    let racy = Arc::new(RacyKv(MemoryAtomicKv::new()));
    assert_eq!(failed(&run_kv_store_conformance(&|| racy.clone() as Arc<dyn AtomicKv>, &opts())), ["kv-update-atomic"]);
    let all = Arc::new(ListsEverything(MemoryAtomicKv::new()));
    assert_eq!(failed(&run_kv_store_conformance(&|| all.clone() as Arc<dyn AtomicKv>, &opts())), ["kv-list-prefix"]);
    let c = Arc::new(CreatesOnNone(MemoryAtomicKv::new()));
    assert!(failed(&run_kv_store_conformance(&|| c.clone() as Arc<dyn AtomicKv>, &opts())).contains(&"kv-basic"));
}

/// Delegates everything, but `claim_budgeted` compares nothing: the swap always goes through.
struct IgnoresBefore(MemoryStateStore);
impl StateStore for IgnoresBefore {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.budget(key)
    }
    fn claim_budgeted(&self, key: &str, counter: u64, _: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        let stored = self.0.budget(key)?;
        self.0.claim_budgeted(key, counter, stored.as_ref(), after)
    }
}

/// Claims the counter but forgets the budget it was given.
struct DropsBudget(MemoryStateStore);
impl StateStore for DropsBudget {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.0.budget(key)
    }
    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, _: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        self.0.claim_budgeted(key, counter, before, None)
    }
}

#[test]
fn broken_budget_stores_fail_the_budget_kit() {
    let a: Arc<dyn StateStore> = Arc::new(IgnoresBefore(MemoryStateStore::new()));
    assert!(failed(&run_budget_store_conformance(&state(a), &opts())).contains(&"budget-conflict"));
    let b: Arc<dyn StateStore> = Arc::new(DropsBudget(MemoryStateStore::new()));
    assert!(failed(&run_budget_store_conformance(&state(b), &opts())).contains(&"budget-claim"));
}

/// Pins that an equal or LOWER epoch overwrites (a rollback is accepted).
struct LowersPins(MemoryStateStore, Mutex<HashMap<String, i64>>);
impl StateStore for LowersPins {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
    fn supports_pins(&self) -> bool {
        true
    }
    fn pin(&self, key: &str) -> Result<Option<i64>, StoreError> {
        Ok(self.1.lock().unwrap().get(key).copied())
    }
    fn raise_pin(&self, key: &str, value: i64) -> Result<(), StoreError> {
        self.1.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }
}

/// A store with no pin support at all (every default).
struct NoPins(MemoryStateStore);
impl StateStore for NoPins {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
}

#[test]
fn broken_pin_stores_fail_the_pin_kit() {
    let a: Arc<dyn StateStore> = Arc::new(LowersPins(MemoryStateStore::new(), Mutex::new(HashMap::new())));
    let r = run_pin_store_conformance(&state(a), &opts());
    assert!(failed(&r).contains(&"pin-monotone"), "{r:?}");
    let b: Arc<dyn StateStore> = Arc::new(NoPins(MemoryStateStore::new()));
    assert!(failed(&run_pin_store_conformance(&state(b), &opts())).contains(&"pin-monotone"));
}

// ---- each failing property is reported with its own note ------------------------------------------------------

fn note_of(r: &ConformanceReport, test: &str) -> String {
    let t = r.tests.iter().find(|t| t.test == test).unwrap_or_else(|| panic!("no test {test}"));
    assert_eq!(t.status, Status::Fail, "{test}: {r:?}");
    t.note.clone().unwrap()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kv {
    Faithful,
    AbsentIsSome,
    DeclineAnswersSome,
    DeclineCreates,
    Phantom,
    ReturnsPrevious,
    DeclineAnswersNone,
    DeclineRemovesAnswersOld,
    UpdateErrors,
    AnswersNothing,
    GetOffByOne,
    GetsTampered,
}

/// An atomic key/value store that is correct except for the one deviation named by `mode`.
struct FaultKv {
    mode: Kv,
    m: Mutex<std::collections::BTreeMap<String, Value>>,
    calls: Mutex<HashMap<String, u32>>,
}

impl FaultKv {
    fn open(mode: Kv) -> impl Fn() -> Arc<dyn AtomicKv> + Send + Sync {
        let k = Arc::new(FaultKv { mode, m: Mutex::new(Default::default()), calls: Mutex::new(HashMap::new()) });
        move || k.clone() as Arc<dyn AtomicKv>
    }
}

impl AtomicKv for FaultKv {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        let stored = self.m.lock().unwrap().get(key).cloned();
        let n = stored.as_ref().and_then(|v| v["n"].as_u64()).unwrap_or(0);
        Ok(match (self.mode, stored) {
            (Kv::AbsentIsSome, None) => Some(serde_json::json!({})),
            (Kv::GetOffByOne, Some(_)) => Some(serde_json::json!({"n": n.saturating_sub(1)})),
            (Kv::GetsTampered, Some(_)) => Some(serde_json::json!({"n": n + 1})),
            (_, s) => s,
        })
    }

    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        if self.mode == Kv::UpdateErrors {
            return Err(StoreError("boom".into()));
        }
        let mut m = self.m.lock().unwrap();
        let n = {
            let mut c = self.calls.lock().unwrap();
            let e = c.entry(key.to_string()).or_insert(0);
            *e += 1;
            *e
        };
        let cur = m.get(key).cloned();
        let seen = if self.mode == Kv::Phantom && n == 2 { Some(serde_json::json!({"n": 5})) } else { cur.clone() };
        let next = f(seen.as_ref());
        match &next {
            Some(v) => {
                m.insert(key.to_string(), v.clone());
            }
            None if self.mode == Kv::DeclineCreates => {
                m.insert(key.to_string(), serde_json::json!({}));
            }
            None if self.mode == Kv::DeclineRemovesAnswersOld => {
                m.remove(key);
            }
            None => {}
        }
        let stored = m.get(key).cloned();
        Ok(match self.mode {
            Kv::ReturnsPrevious => cur,
            Kv::AnswersNothing => None,
            Kv::DeclineAnswersSome if next.is_none() => Some(serde_json::json!({"junk": 1})),
            Kv::DeclineAnswersNone | Kv::DeclineCreates if next.is_none() => None,
            Kv::DeclineRemovesAnswersOld if next.is_none() => cur,
            _ => stored,
        })
    }
}

fn kv_report(mode: Kv) -> ConformanceReport {
    run_kv_store_conformance(&FaultKv::open(mode), &opts())
}

#[test]
fn the_kv_kit_names_the_exact_property_a_store_breaks() {
    kv_report(Kv::Faithful).assert_passed();
    assert_eq!(note_of(&kv_report(Kv::AbsentIsSome), "kv-basic"), "an unused key was not absent");
    for mode in [Kv::DeclineAnswersSome, Kv::DeclineCreates] {
        assert_eq!(note_of(&kv_report(mode), "kv-basic"), "an update that returned None created the key", "{mode:?}");
    }
    for mode in [Kv::Phantom, Kv::ReturnsPrevious] {
        assert_eq!(note_of(&kv_report(mode), "kv-basic"), "update stored {n:1} but answered None", "{mode:?}");
    }
    for mode in [Kv::DeclineAnswersNone, Kv::DeclineRemovesAnswersOld] {
        assert!(note_of(&kv_report(mode), "kv-basic").starts_with("an update that returned None changed the stored value ("), "{mode:?}");
    }
    assert!(note_of(&kv_report(Kv::UpdateErrors), "kv-update-atomic").starts_with("round 0: an update errored under load: Err(StoreError(\"boom\"))"));
    let n = note_of(&kv_report(Kv::AnswersNothing), "kv-update-atomic");
    assert!(n.starts_with("round 0: 12 concurrent increments answered ") && n.ends_with("(a lost update)"), "{n}");
    assert_eq!(note_of(&kv_report(Kv::GetOffByOne), "kv-update-atomic"), "round 0: the stored count is 11, expected 12");
    let n = note_of(&kv_report(Kv::GetsTampered), "kv-durability");
    assert!(n.starts_with("a fresh handle read Some(") && n.ends_with("after the write; documents did not survive"), "{n}");
}

#[test]
fn a_racing_kv_is_reported_as_a_lost_update() {
    let racy = Arc::new(RacyKv(MemoryAtomicKv::new()));
    let n = note_of(&run_kv_store_conformance(&|| racy.clone() as Arc<dyn AtomicKv>, &opts()), "kv-update-atomic");
    assert!(n.contains("concurrent increments answered") && n.ends_with("(a lost update)"), "{n}");
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum St {
    Faithful,
    FreshHasBudget,
    NeverClaims,
    DropsBudget,
    DropsCounter,
    ReplayClaims,
    ReplayWrites,
    NoAfterRefuses,
    NoAfterClears,
    StrictShape,
    IgnoresBefore,
    ConflictWritesBudget,
    ConflictConsumes,
    ErrsUnderLoad,
    AdmitsAll,
    StoresWrongBudget,
    FreshHasPin,
    PinLeaks,
    RaiseErrs,
    PinOffByOne,
}

/// A replay-state store that is correct except for the one deviation named by `mode`.
struct FaultState {
    mode: St,
    last: Mutex<HashMap<String, u64>>,
    budgets: Mutex<HashMap<String, Value>>,
    pins: Mutex<HashMap<String, i64>>,
    global_pin: Mutex<Option<i64>>,
}

impl FaultState {
    fn open(mode: St) -> impl Fn() -> Arc<dyn StateStore> + Send + Sync {
        let s: Arc<dyn StateStore> = Arc::new(FaultState { mode, last: Mutex::new(HashMap::new()), budgets: Mutex::new(HashMap::new()), pins: Mutex::new(HashMap::new()), global_pin: Mutex::new(None) });
        move || s.clone()
    }
}

impl StateStore for FaultState {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let mut last = self.last.lock().unwrap();
        if let Some(&seen) = last.get(key) {
            if counter <= seen {
                return Ok(ClaimResult { ok: false, last_counter: Some(seen) });
            }
        }
        last.insert(key.to_string(), counter);
        Ok(ClaimResult::claimed())
    }

    fn last(&self, key: &str) -> Option<Option<u64>> {
        Some(self.last.lock().unwrap().get(key).copied())
    }

    fn supports_pins(&self) -> bool {
        true
    }

    fn pin(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let stored = self.pins.lock().unwrap().get(key).copied();
        Ok(match self.mode {
            St::FreshHasPin => Some(stored.unwrap_or(0)),
            St::PinLeaks => *self.global_pin.lock().unwrap(),
            St::PinOffByOne => stored.map(|v| v - 1),
            _ => stored,
        })
    }

    fn raise_pin(&self, key: &str, value: i64) -> Result<(), StoreError> {
        if self.mode == St::RaiseErrs {
            return Err(StoreError("boom".into()));
        }
        let mut g = self.global_pin.lock().unwrap();
        *g = Some(g.map_or(value, |c| c.max(value)));
        let mut pins = self.pins.lock().unwrap();
        let e = pins.entry(key.to_string()).or_insert(value);
        *e = (*e).max(value);
        Ok(())
    }

    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        let stored = self.budgets.lock().unwrap().get(key).cloned();
        Ok(if self.mode == St::FreshHasBudget { stored.or(Some(serde_json::json!({"B": 0, "tau": 0, "asOf": 0}))) } else { stored })
    }

    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        let m = self.mode;
        match m {
            St::NeverClaims => return Ok(BudgetClaim::Replay(None)),
            St::ErrsUnderLoad => return Err(StoreError("boom".into())),
            St::NoAfterRefuses if after.is_none() => return Ok(BudgetClaim::Conflict),
            St::StrictShape if after.is_some_and(|a| !a.get("B").is_some_and(Value::is_number)) => return Err(StoreError("bad budget".into())),
            _ => {}
        }
        let mut last = self.last.lock().unwrap();
        let mut b = self.budgets.lock().unwrap();
        if m == St::AdmitsAll {
            last.insert(key.to_string(), counter);
            return Ok(BudgetClaim::Claimed);
        }
        if let Some(&seen) = last.get(key) {
            if counter <= seen {
                if m == St::ReplayClaims {
                    return Ok(BudgetClaim::Claimed);
                }
                if let (St::ReplayWrites, Some(a)) = (m, after) {
                    b.insert(key.to_string(), a.clone());
                }
                return Ok(BudgetClaim::Replay(Some(seen)));
            }
        }
        if m != St::IgnoresBefore && b.get(key) != before {
            if let (St::ConflictWritesBudget, Some(a)) = (m, after) {
                b.insert(key.to_string(), a.clone());
            }
            if m == St::ConflictConsumes {
                last.insert(key.to_string(), counter);
            }
            return Ok(BudgetClaim::Conflict);
        }
        if m != St::DropsCounter {
            last.insert(key.to_string(), counter);
        }
        match after {
            Some(_) if m == St::StoresWrongBudget => {
                b.insert(key.to_string(), serde_json::json!({"B": 0.99, "tau": 0, "asOf": 0}));
            }
            Some(a) if m != St::DropsBudget => {
                b.insert(key.to_string(), a.clone());
            }
            None if m == St::NoAfterClears => {
                b.remove(key);
            }
            _ => {}
        }
        Ok(BudgetClaim::Claimed)
    }
}

fn budget_report(mode: St) -> ConformanceReport {
    run_budget_store_conformance(&FaultState::open(mode), &opts())
}

fn pin_report(mode: St) -> ConformanceReport {
    run_pin_store_conformance(&FaultState::open(mode), &opts())
}

#[test]
fn a_store_that_checks_the_budget_shape_still_passes_the_budget_kit() {
    budget_report(St::Faithful).assert_passed();
    budget_report(St::StrictShape).assert_passed();
    pin_report(St::Faithful).assert_passed();
}

#[test]
fn the_budget_kit_names_the_exact_property_a_store_breaks() {
    assert_eq!(note_of(&budget_report(St::FreshHasBudget), "budget-claim"), "an unused stream has a budget");
    assert_eq!(note_of(&budget_report(St::NeverClaims), "budget-claim"), "the first budgeted claim answered Ok(Replay(None))");
    for mode in [St::DropsBudget, St::DropsCounter] {
        assert_eq!(note_of(&budget_report(mode), "budget-claim"), "the budget and the counter did not both move", "{mode:?}");
        assert_eq!(note_of(&budget_report(mode), "budget-durability"), "a fresh handle did not see the stored budget and counter", "{mode:?}");
    }
    assert_eq!(note_of(&budget_report(St::ReplayClaims), "budget-claim"), "a replayed counter answered Ok(Claimed)");
    assert_eq!(note_of(&budget_report(St::ReplayWrites), "budget-claim"), "a replayed counter changed the stored budget");
    assert_eq!(note_of(&budget_report(St::NoAfterRefuses), "budget-claim"), "a claim with no budget to store answered Ok(Conflict)");
    assert_eq!(note_of(&budget_report(St::NoAfterClears), "budget-claim"), "a claim with no budget to store changed the stored budget");
    assert_eq!(note_of(&budget_report(St::IgnoresBefore), "budget-conflict"), "a stale read answered Ok(Claimed), expected a conflict");
    for mode in [St::ConflictWritesBudget, St::ConflictConsumes] {
        assert_eq!(note_of(&budget_report(mode), "budget-conflict"), "a conflicting claim changed the budget or consumed the counter", "{mode:?}");
    }
    assert!(note_of(&budget_report(St::ErrsUnderLoad), "budget-concurrent").starts_with("round 0: a budgeted claim errored under load: "));
    assert_eq!(note_of(&budget_report(St::AdmitsAll), "budget-concurrent"), "round 0: 12 of 12 concurrent budgeted claims were admitted (must be exactly 1)");
    let n = note_of(&budget_report(St::StoresWrongBudget), "budget-concurrent");
    assert!(n.starts_with("round 0: copy ") && n.contains(" won but the stored budget is Some("), "{n}");
}

#[test]
fn the_pin_kit_names_the_exact_property_a_store_breaks() {
    let b: Arc<dyn StateStore> = Arc::new(NoPins(MemoryStateStore::new()));
    assert_eq!(note_of(&run_pin_store_conformance(&state(b), &opts()), "pin-monotone"), "the store does not declare pin support");
    assert_eq!(note_of(&pin_report(St::FreshHasPin), "pin-monotone"), "an unused key has a pin");
    assert_eq!(note_of(&pin_report(St::PinLeaks), "pin-monotone"), "a pin leaked into another key");
    assert!(note_of(&pin_report(St::RaiseErrs), "pin-concurrent").starts_with("a raise errored under load: Err(StoreError(\"boom\"))"));
    assert_eq!(note_of(&pin_report(St::PinOffByOne), "pin-concurrent"), "racing raises of 1..=12 left the pin at Some(11), expected 12");
}
