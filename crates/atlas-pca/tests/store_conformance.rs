//! The reusable store-conformance helper: the shipped stores pass it, and deliberately broken stores fail it (so a green run
//! means something).
use std::sync::Arc;

use atlas_pca::store_conformance::*;
use atlas_pca::*;

fn opts() -> Options {
    Options { rounds: 5, copies: 12, durable: true }
}

#[test]
fn the_memory_state_store_passes() {
    let backend = Arc::new(MemoryStateStore::new());
    let report = run_state_store_conformance(&|| backend.clone() as Arc<dyn StateStore>, &opts());
    report.assert_passed();
    assert_eq!(report.tests.iter().map(|t| t.test).collect::<Vec<_>>(), ["claim-burst", "claim-concurrent", "claim-durability", "crash-after-claim"]);
    assert!(report.tests.iter().all(|t| t.status == Status::Pass), "{report:?}");
}

#[test]
fn the_memory_operation_stores_pass() {
    let mem = Arc::new(MemoryOperationStore::new());
    let r = run_operation_store_conformance(&|| mem.clone() as Arc<dyn OperationStore>, &opts());
    r.assert_passed();
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
    let kv = Arc::new(KvOperationStore::new(Arc::new(MemoryAtomicKv::new())));
    let r = run_operation_store_conformance(&|| kv.clone() as Arc<dyn OperationStore>, &opts());
    r.assert_passed();
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
}

#[test]
fn a_non_durable_store_skips_the_durability_tests_and_says_so() {
    let backend = Arc::new(MemoryStateStore::new());
    let report = run_state_store_conformance(&|| backend.clone() as Arc<dyn StateStore>, &Options { durable: false, ..opts() });
    assert!(report.passed());
    let skipped: Vec<_> = report.tests.iter().filter(|t| t.status == Status::Skip).map(|t| t.test).collect();
    assert_eq!(skipped, ["claim-durability", "crash-after-claim"]);
}

/// Admits everything: the replay guarantee is gone.
struct AlwaysClaims;
impl StateStore for AlwaysClaims {
    fn claim(&self, _: &str, _: u64) -> Result<ClaimResult, StoreError> {
        Ok(ClaimResult::claimed())
    }
    fn last(&self, _: &str) -> Option<Option<u64>> {
        Some(None)
    }
}

/// Reads then writes without a lock between them: two racers both see "unclaimed".
struct RacyClaims(std::sync::Mutex<std::collections::HashMap<String, u64>>);
impl StateStore for RacyClaims {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let seen = self.0.lock().unwrap().get(key).copied();
        std::thread::sleep(std::time::Duration::from_millis(2));
        if seen.is_some_and(|s| counter <= s) {
            return Ok(ClaimResult::replay(seen));
        }
        self.0.lock().unwrap().insert(key.to_string(), counter);
        Ok(ClaimResult::claimed())
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        Some(self.0.lock().unwrap().get(key).copied())
    }
}

#[test]
fn broken_state_stores_fail() {
    let always = Arc::new(AlwaysClaims);
    let r = run_state_store_conformance(&|| always.clone() as Arc<dyn StateStore>, &opts());
    assert!(!r.passed());
    assert!(r.tests.iter().any(|t| t.test == "claim-burst" && t.status == Status::Fail), "{r:?}");

    let racy = Arc::new(RacyClaims(Default::default()));
    let r = run_state_store_conformance(&|| racy.clone() as Arc<dyn StateStore>, &opts());
    assert!(r.tests.iter().any(|t| t.test == "claim-concurrent" && t.status == Status::Fail), "{r:?}");
}

/// A store whose `create` overwrites and whose `transition` ignores `from`: the compare-and-set is gone.
#[derive(Default)]
struct NoCas(std::sync::Mutex<std::collections::BTreeMap<String, OperationRecord>>);
impl OperationStore for NoCas {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        self.0.lock().unwrap().insert(record.id.clone(), record);
        Ok(CreateOutcome::Created)
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        Ok(self.0.lock().unwrap().get(id).cloned())
    }
    fn transition(&self, id: &str, _from: OperationState, next: OperationRecord) -> Result<bool, StoreError> {
        self.0.lock().unwrap().insert(id.to_string(), next);
        Ok(true)
    }
}

#[test]
fn a_broken_operation_store_fails() {
    let bad = Arc::new(NoCas::default());
    let r = run_operation_store_conformance(&|| bad.clone() as Arc<dyn OperationStore>, &opts());
    assert!(!r.passed());
    for name in ["create-once", "transition-cas", "execute-once"] {
        assert!(r.tests.iter().any(|t| t.test == name && t.status == Status::Fail), "{name}: {r:?}");
    }
    assert!(r.tests.iter().any(|t| t.test == "list-open" && t.status == Status::Skip));
}

#[test]
#[should_panic(expected = "pca-state conformance failed")]
fn assert_passed_panics_on_a_failure() {
    let always = Arc::new(AlwaysClaims);
    run_state_store_conformance(&|| always.clone() as Arc<dyn StateStore>, &opts()).assert_passed();
}
