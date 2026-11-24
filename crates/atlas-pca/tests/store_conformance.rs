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
    assert_eq!(report.tests.iter().map(|t| t.test).collect::<Vec<_>>(), ["claim-burst", "claim-concurrent", "claim-durability", "crash-after-claim", "retry-after-timeout"]);
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

/// Reads, meets a partner, then writes without a lock between them: two racers both see "unclaimed". Racers pair off per key in
/// arrival order (the kit's retry race has two racers and its bursts a dozen or more, so a barrier of a fixed size would not fit
/// both), and a pair writes only once both have read, so the lost update always happens whatever the scheduler or the machine speed
/// does (a wall-clock sleep let a late racer run alone). Calls from the thread that built the store are serial setup and never wait. A
/// racer left without a partner for 30 s panics, which fails the test.
struct RacyClaims {
    map: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    owner: std::thread::ThreadId,
    arrivals: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    cv: std::sync::Condvar,
}

impl RacyClaims {
    fn new() -> Self {
        RacyClaims { map: Default::default(), owner: std::thread::current().id(), arrivals: Default::default(), cv: std::sync::Condvar::new() }
    }

    fn meet(&self, key: &str) {
        let mut g = self.arrivals.lock().unwrap();
        let ticket = {
            let e = g.entry(key.to_string()).or_insert(0);
            *e += 1;
            *e
        };
        let target = (ticket + 1) / 2 * 2;
        if ticket >= target {
            self.cv.notify_all();
            return;
        }
        let (g, res) = self
            .cv
            .wait_timeout_while(g, std::time::Duration::from_secs(30), |m| m.get(key).copied().unwrap_or(0) < target)
            .unwrap();
        drop(g);
        assert!(!res.timed_out(), "racy claims: no partner reached the rendezvous on {key}");
    }
}

impl StateStore for RacyClaims {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let seen = self.map.lock().unwrap().get(key).copied();
        if std::thread::current().id() != self.owner {
            self.meet(key);
        }
        if seen.is_some_and(|s| counter <= s) {
            return Ok(ClaimResult::replay(seen));
        }
        self.map.lock().unwrap().insert(key.to_string(), counter);
        Ok(ClaimResult::claimed())
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        Some(self.map.lock().unwrap().get(key).copied())
    }
}

#[test]
fn broken_state_stores_fail() {
    let always = Arc::new(AlwaysClaims);
    let r = run_state_store_conformance(&|| always.clone() as Arc<dyn StateStore>, &opts());
    assert!(!r.passed());
    assert!(r.tests.iter().any(|t| t.test == "claim-burst" && t.status == Status::Fail), "{r:?}");

    let racy = Arc::new(RacyClaims::new());
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

/// A store that persists a transition but drops its `executing_at`: a restart cannot tell when the side effect began.
struct DropsExecutingAt(MemoryOperationStore);
impl OperationStore for DropsExecutingAt {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        self.0.create(record)
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        self.0.get(id)
    }
    fn transition(&self, id: &str, from: OperationState, mut next: OperationRecord) -> Result<bool, StoreError> {
        next.executing_at = None;
        self.0.transition(id, from, next)
    }
}

fn fails(r: &ConformanceReport, names: &[&str]) {
    for name in names {
        assert!(r.tests.iter().any(|t| t.test == *name && t.status == Status::Fail), "{name}: {r:?}");
    }
}

#[test]
fn durability_and_cas_need_the_executing_record_exactly() {
    let bad = Arc::new(DropsExecutingAt(MemoryOperationStore::new()));
    fails(&run_operation_store_conformance(&|| bad.clone() as Arc<dyn OperationStore>, &opts()), &["durability", "transition-cas"]);
}

/// A second `create` answers with the CALLER's record instead of the stored one.
struct ExistsEchoesCaller(MemoryOperationStore);
impl OperationStore for ExistsEchoesCaller {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        Ok(match self.0.create(record.clone())? {
            CreateOutcome::Exists(_) => CreateOutcome::Exists(record),
            c => c,
        })
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        self.0.get(id)
    }
    fn transition(&self, id: &str, from: OperationState, next: OperationRecord) -> Result<bool, StoreError> {
        self.0.transition(id, from, next)
    }
}

/// A refused transition still writes: the compare-and-set answers false but the record moves.
#[derive(Default)]
struct WritesOnRefusal(std::sync::Mutex<std::collections::BTreeMap<String, OperationRecord>>);
impl OperationStore for WritesOnRefusal {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        let mut m = self.0.lock().unwrap();
        if let Some(r) = m.get(&record.id) {
            return Ok(CreateOutcome::Exists(r.clone()));
        }
        m.insert(record.id.clone(), record);
        Ok(CreateOutcome::Created)
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        Ok(self.0.lock().unwrap().get(id).cloned())
    }
    fn transition(&self, id: &str, from: OperationState, next: OperationRecord) -> Result<bool, StoreError> {
        let mut m = self.0.lock().unwrap();
        let ok = m.get(id).is_some_and(|r| r.state == from);
        m.insert(id.to_string(), next);
        Ok(ok)
    }
}

#[test]
fn broken_create_answers_and_refusals_that_write_fail() {
    let echo = Arc::new(ExistsEchoesCaller(MemoryOperationStore::new()));
    fails(&run_operation_store_conformance(&|| echo.clone() as Arc<dyn OperationStore>, &opts()), &["create-once", "terminal-states-stick"]);
    let writes = Arc::new(WritesOnRefusal::default());
    fails(&run_operation_store_conformance(&|| writes.clone() as Arc<dyn OperationStore>, &opts()), &["terminal-states-stick"]);
}

/// Claims correctly but reports a stale stream head.
struct StaleLast(MemoryStateStore);
impl StateStore for StaleLast {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, _: &str) -> Option<Option<u64>> {
        Some(Some(1))
    }
}

#[test]
fn a_stale_stream_head_fails_the_concurrent_claims() {
    let s = Arc::new(StaleLast(MemoryStateStore::new()));
    fails(&run_state_store_conformance(&|| s.clone() as Arc<dyn StateStore>, &opts()), &["claim-concurrent"]);
}

/// A correct store whose answer for one counter is scripted.
struct Scripted(MemoryStateStore, u64, Result<bool, ()>);
impl StateStore for Scripted {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        if counter != self.1 {
            return self.0.claim(key, counter);
        }
        match self.2 {
            Ok(true) => Ok(ClaimResult::claimed()),
            Ok(false) => Ok(ClaimResult::replay(None)),
            Err(()) => Err(StoreError("down".into())),
        }
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.0.last(key)
    }
}

fn retry_note(s: Arc<dyn StateStore>) -> String {
    let r = run_state_store_conformance(&|| s.clone(), &opts());
    let t = r.tests.iter().find(|t| t.test == "retry-after-timeout").unwrap();
    assert_eq!(t.status, Status::Fail, "{r:?}");
    t.note.clone().unwrap()
}

#[test]
fn a_lost_answer_the_store_readmits_fails_retry_after_timeout() {
    let cases: [(u64, Result<bool, ()>, &str); 6] = [
        (1, Ok(true), "retry=admitted, next counter=admitted; in-flight retry: 1 admitted of 2"),
        (1, Err(()), "retry=error, next counter=admitted; in-flight retry: 1 admitted of 2"),
        (2, Ok(false), "retry=replay, next counter=replay; in-flight retry: 1 admitted of 2"),
        (2, Err(()), "retry=replay, next counter=error; in-flight retry: 1 admitted of 2"),
        (3, Ok(true), "retry=replay, next counter=admitted; in-flight retry: 2 admitted of 2"),
        (3, Ok(false), "retry=replay, next counter=admitted; in-flight retry: 0 admitted of 2"),
    ];
    for (counter, answer, want) in cases {
        let note = retry_note(Arc::new(Scripted(MemoryStateStore::new(), counter, answer)));
        assert_eq!(note, format!("lost answer: first=error, {want}"));
    }
    // Per-handle state passed off as shared: the retry on another instance is admitted again.
    let r = run_state_store_conformance(&|| Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>, &opts());
    let t = r.tests.iter().find(|t| t.test == "retry-after-timeout").unwrap();
    assert_eq!(t.note.as_deref(), Some("lost answer: first=error, retry=admitted, next counter=admitted; in-flight retry: 2 admitted of 2"));
}

/// The trait default: a backend that does not override `list` cannot enumerate.
struct NoList;
impl AtomicKv for NoList {
    fn get(&self, _: &str) -> Result<Option<atlas_pca::serde_json::Value>, StoreError> {
        Ok(None)
    }
    fn update(&self, _: &str, _: &mut dyn FnMut(Option<&atlas_pca::serde_json::Value>) -> Option<atlas_pca::serde_json::Value>) -> Result<Option<atlas_pca::serde_json::Value>, StoreError> {
        Ok(None)
    }
}

#[test]
fn an_atomic_kv_without_list_cannot_enumerate() {
    assert_eq!(NoList.list("").ok(), Some(None));
}
