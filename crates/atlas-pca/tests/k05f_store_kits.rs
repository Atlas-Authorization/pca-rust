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
