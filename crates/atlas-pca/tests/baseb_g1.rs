//! 0.5 mutation kills (group g1): every failure note of the store-conformance helper is pinned against a store built to break
//! exactly one contract, plus three small kills in `attest::util` and the escalation request.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use atlas_pca::attest::util::{b64_lenient, parse_iso_ms};
use atlas_pca::serde_json::json;
use atlas_pca::store_conformance::*;
use atlas_pca::*;

fn opts() -> Options {
    Options { rounds: 5, copies: 12, durable: true }
}

fn boom() -> StoreError {
    StoreError("boom".into())
}

// ------------------------------------------------------------------------------------------------ state stores

type ClaimFn = Box<dyn Fn(&MemoryStateStore, &str, u64) -> Result<ClaimResult, StoreError> + Send + Sync>;

/// A correct store whose `claim` is replaced by `f` (which may call the inner store).
struct StHook {
    inner: MemoryStateStore,
    f: ClaimFn,
}
impl StHook {
    fn new(f: impl Fn(&MemoryStateStore, &str, u64) -> Result<ClaimResult, StoreError> + Send + Sync + 'static) -> Self {
        StHook { inner: MemoryStateStore::new(), f: Box::new(f) }
    }
}
impl StateStore for StHook {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        (self.f)(&self.inner, key, counter)
    }
    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.inner.last(key)
    }
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

/// Admits everything.
struct AlwaysClaims;
impl StateStore for AlwaysClaims {
    fn claim(&self, _: &str, _: u64) -> Result<ClaimResult, StoreError> {
        Ok(ClaimResult::claimed())
    }
    fn last(&self, _: &str) -> Option<Option<u64>> {
        Some(None)
    }
}

/// The failure note of one state test (the test must fail).
fn state_note(s: impl StateStore + 'static, test: &str) -> String {
    let s: Arc<dyn StateStore> = Arc::new(s);
    let r = run_state_store_conformance(&|| s.clone(), &opts());
    let t = r.tests.iter().find(|t| t.test == test).unwrap();
    assert_eq!(t.status, Status::Fail, "{r:?}");
    t.note.clone().unwrap()
}

#[test]
fn claim_durability_notes() {
    // a fresh counter denied
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":dur") && c == 2 { Ok(ClaimResult::replay(None)) } else { m.claim(k, c) }), "claim-durability");
    assert_eq!(n, "a fresh counter 2 was denied");
    // a consumed counter admitted again by a fresh handle (its second claim)
    let calls = Arc::new(AtomicUsize::new(0));
    let n = state_note(
        StHook::new(move |m, k, c| {
            if k.ends_with(":dur") && c == 2 && calls.fetch_add(1, Ordering::SeqCst) > 0 {
                return Ok(ClaimResult::claimed());
            }
            m.claim(k, c)
        }),
        "claim-durability",
    );
    assert_eq!(n, "counter 2 was admitted again by a fresh handle: consumed counters did not survive");
    // the next counter denied
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":dur") && c == 4 { Ok(ClaimResult::replay(None)) } else { m.claim(k, c) }), "claim-durability");
    assert_eq!(n, "the next counter was denied by a fresh handle");
}

#[test]
fn crash_after_claim_notes() {
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":crash") && c == 7 { Ok(ClaimResult::replay(None)) } else { m.claim(k, c) }), "crash-after-claim");
    assert_eq!(n, "a fresh counter was denied");
    // the counter admitted before the crash is admitted again afterwards
    let calls = Arc::new(AtomicUsize::new(0));
    let n = state_note(
        StHook::new(move |m, k, c| {
            if k.ends_with(":crash") && c == 7 && calls.fetch_add(1, Ordering::SeqCst) > 0 {
                return Ok(ClaimResult::claimed());
            }
            m.claim(k, c)
        }),
        "crash-after-claim",
    );
    assert_eq!(n, "the counter admitted before the crash was admitted again");
    // every copy admits the next counter
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":crash") && c == 8 { Ok(ClaimResult::claimed()) } else { m.claim(k, c) }), "crash-after-claim");
    assert_eq!(n, "12 of 12 concurrent claims of the next counter were admitted (must be exactly 1)");
}

#[test]
fn claim_burst_notes() {
    // the last step (b, 1, false) is answered true
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":b") && c == 1 { Ok(ClaimResult::claimed()) } else { m.claim(k, c) }), "claim-burst");
    assert_eq!(n, "claim(stream b, counter 1) answered true but the contract says false");
    // a denial of counter 4 reports a stored counter below it
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":a") && c == 4 { Ok(ClaimResult::replay(Some(1))) } else { m.claim(k, c) }), "claim-burst");
    assert_eq!(n, "a denial of counter 4 reported a stored counter 1 below it");
    // a stale stream head
    let n = state_note(StaleLast(MemoryStateStore::new()), "claim-burst");
    assert!(n.starts_with("last(") && n.ends_with(") is Some(Some(1)), expected Some(Some(6))"), "{n}");
}

#[test]
fn claim_concurrent_notes() {
    let n = state_note(AlwaysClaims, "claim-concurrent");
    assert!(n.starts_with("round 0: 12 of 12 concurrent claims of one counter were admitted (must be exactly 1); outcomes "), "{n}");
    // one claim of the shuffled race errors (only its first call)
    let calls = Arc::new(AtomicUsize::new(0));
    let n = state_note(
        StHook::new(move |m, k, c| {
            if k.ends_with(":order") && c == 5 && calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(boom());
            }
            m.claim(k, c)
        }),
        "claim-concurrent",
    );
    assert_eq!(n, "a claim errored under load: Err(StoreError(\"boom\"))");
    // counter 3 is admitted again after the race
    let calls = Arc::new(AtomicUsize::new(0));
    let n = state_note(
        StHook::new(move |m, k, c| {
            if k.ends_with(":order") && c == 3 && calls.fetch_add(1, Ordering::SeqCst) > 0 {
                return Ok(ClaimResult::claimed());
            }
            m.claim(k, c)
        }),
        "claim-concurrent",
    );
    assert_eq!(n, "counter 3 was admitted again after the race (the stream is at 12)");
    // the store records everything but answers "not admitted" to every racer
    let n = state_note(StHook::new(|m, k, c| if k.ends_with(":order") { m.claim(k, c).map(|_| ClaimResult::replay(None)) } else { m.claim(k, c) }), "claim-concurrent");
    assert_eq!(n, "no claim of the race was admitted");
}

// ------------------------------------------------------------------------------------------------ operation stores

type CreateFn = Box<dyn Fn(&MemoryOperationStore, OperationRecord) -> Result<CreateOutcome, StoreError> + Send + Sync>;
type GetFn = Box<dyn Fn(&MemoryOperationStore, &str) -> Result<Option<OperationRecord>, StoreError> + Send + Sync>;
type TransFn = Box<dyn Fn(&MemoryOperationStore, &str, OperationState, OperationRecord) -> Result<bool, StoreError> + Send + Sync>;
type ListFn = Box<dyn Fn(&MemoryOperationStore) -> Result<Option<Vec<OperationRecord>>, StoreError> + Send + Sync>;

/// A correct store with any of its four calls replaced.
#[derive(Default)]
struct OpHook {
    inner: MemoryOperationStore,
    create: Option<CreateFn>,
    get: Option<GetFn>,
    trans: Option<TransFn>,
    list: Option<ListFn>,
}
impl OpHook {
    fn create(mut self, f: impl Fn(&MemoryOperationStore, OperationRecord) -> Result<CreateOutcome, StoreError> + Send + Sync + 'static) -> Self {
        self.create = Some(Box::new(f));
        self
    }
    fn get(mut self, f: impl Fn(&MemoryOperationStore, &str) -> Result<Option<OperationRecord>, StoreError> + Send + Sync + 'static) -> Self {
        self.get = Some(Box::new(f));
        self
    }
    fn trans(mut self, f: impl Fn(&MemoryOperationStore, &str, OperationState, OperationRecord) -> Result<bool, StoreError> + Send + Sync + 'static) -> Self {
        self.trans = Some(Box::new(f));
        self
    }
    fn list(mut self, f: impl Fn(&MemoryOperationStore) -> Result<Option<Vec<OperationRecord>>, StoreError> + Send + Sync + 'static) -> Self {
        self.list = Some(Box::new(f));
        self
    }
}
impl OperationStore for OpHook {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        match &self.create {
            Some(f) => f(&self.inner, record),
            None => self.inner.create(record),
        }
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        match &self.get {
            Some(f) => f(&self.inner, id),
            None => self.inner.get(id),
        }
    }
    fn transition(&self, id: &str, from: OperationState, next: OperationRecord) -> Result<bool, StoreError> {
        match &self.trans {
            Some(f) => f(&self.inner, id, from, next),
            None => self.inner.transition(id, from, next),
        }
    }
    fn list_open(&self) -> Result<Option<Vec<OperationRecord>>, StoreError> {
        match &self.list {
            Some(f) => f(&self.inner),
            None => self.inner.list_open(),
        }
    }
}

fn op_note(s: OpHook, test: &str) -> String {
    let s: Arc<dyn OperationStore> = Arc::new(s);
    let r = run_operation_store_conformance(&|| s.clone(), &opts());
    let t = r.tests.iter().find(|t| t.test == test).unwrap();
    assert_eq!(t.status, Status::Fail, "{r:?}");
    t.note.clone().unwrap()
}

fn rec(id: &str, state: OperationState) -> OperationRecord {
    OperationRecord {
        id: id.to_string(),
        state,
        verb: "phantom".into(),
        resource: "/conformance".into(),
        params_digest: params_digest(None),
        reversibility: Reversibility::Reversible,
        started_at: 1_000,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    }
}

#[test]
fn create_once_notes() {
    let n = op_note(OpHook::default().create(|m, r| if r.verb == "claimant-3" { Err(boom()) } else { m.create(r) }), "create-once");
    assert_eq!(n, "round 0: create errored: replay store: boom");
    // every copy is told it created the record (only claimant-0's is stored)
    let n = op_note(OpHook::default().create(|m, r| if r.verb == "claimant-0" { m.create(r) } else { Ok(CreateOutcome::Created) }), "create-once");
    assert_eq!(n, "round 0: 12 of 12 concurrent creates succeeded (must be exactly 1)");
    // the stored record is not the winner's
    let n = op_note(
        OpHook::default().get(|m, id| {
            Ok(m.get(id)?.map(|mut r| {
                r.verb = "tampered".into();
                r
            }))
        }),
        "create-once",
    );
    assert_eq!(n, "round 0: the stored record is not the winner's");
}

#[test]
fn transition_cas_notes() {
    let n = op_note(
        OpHook::default().create(|m, r| {
            let again = r.clone();
            m.create(r).map(|_| CreateOutcome::Exists(again))
        }),
        "transition-cas",
    );
    assert_eq!(n, "a fresh id was not created");
    // the stale transition (to committed) is reported as having worked
    let n = op_note(OpHook::default().trans(|m, id, from, next| if next.state == OperationState::Committed { Ok(true) } else { m.transition(id, from, next) }), "transition-cas");
    assert_eq!(n, "a transition from the wrong state succeeded");
    // one racer's transition errors
    let n = op_note(OpHook::default().trans(|m, id, from, next| if next.executing_at == Some(3) && from == OperationState::Pending { Err(boom()) } else { m.transition(id, from, next) }), "transition-cas");
    assert_eq!(n, "round 0: transition errored: replay store: boom");
}

#[test]
fn terminal_states_stick_notes() {
    // an id nobody created reads back as a record
    let n = op_note(
        OpHook::default().get(|m, id| match m.get(id)? {
            None => Ok(Some(rec(id, OperationState::Pending))),
            some => Ok(some),
        }),
        "terminal-states-stick",
    );
    assert_eq!(n, "an id nobody created exists");
    // the legal path is applied but the committing transition answers false
    let n = op_note(OpHook::default().trans(|m, id, from, next| if next.state == OperationState::Committed { m.transition(id, from, next).map(|_| false) } else { m.transition(id, from, next) }), "terminal-states-stick");
    assert_eq!(n, "the legal pending -> executing -> committed path was refused");
    // a transition out of committed answers true
    let n = op_note(OpHook::default().trans(|m, id, from, next| if next.state == OperationState::Failed { Ok(true) } else { m.transition(id, from, next) }), "terminal-states-stick");
    assert_eq!(n, "a committed record was moved out of by a transition from pending");
}

#[test]
fn list_open_notes() {
    let n = op_note(OpHook::default().list(|m| Ok(m.list_open()?.map(|v| v.into_iter().filter(|r| !r.id.ends_with("-executing")).collect()))), "list-open");
    assert!(n.starts_with("list_open returned [\"") && n.ends_with("], expected exactly the pending and the executing record"), "{n}");
    // a transition error while preparing the fixture is the test's failure
    let n = op_note(OpHook::default().trans(|m, id, from, next| if id.ends_with("-executing") && next.state == OperationState::Executing { Err(boom()) } else { m.transition(id, from, next) }), "list-open");
    assert_eq!(n, "replay store: boom");
}

#[test]
fn durability_notes() {
    let n = op_note(OpHook::default().trans(|m, id, from, next| m.transition(id, from, next).map(|ok| ok && !id.starts_with("conf-dur-"))), "durability");
    assert_eq!(n, "pending -> executing was refused");
    let n = op_note(
        OpHook::default().create(|m, r| {
            let dur = r.id.starts_with("conf-dur-");
            m.create(r).map(|o| if dur { CreateOutcome::Created } else { o })
        }),
        "durability",
    );
    assert_eq!(n, "a fresh handle created an id that was already claimed");
}

#[test]
fn a_non_durable_operation_store_skips_durability() {
    let s: Arc<dyn OperationStore> = Arc::new(MemoryOperationStore::new());
    let r = run_operation_store_conformance(&|| s.clone(), &Options { durable: false, ..opts() });
    assert!(r.passed(), "{r:?}");
    let t = r.tests.iter().find(|t| t.test == "durability").unwrap();
    assert_eq!(t.status, Status::Skip);
    assert_eq!(t.note.as_deref(), Some("the store declares itself non-durable"));
    // the durable run does run it
    let r = run_operation_store_conformance(&|| s.clone(), &opts());
    assert_eq!(r.tests.iter().find(|t| t.test == "durability").unwrap().status, Status::Pass);
}

#[test]
fn execute_once_notes() {
    // every handle is told it created the record and won the transition: the function runs on all of them
    let n = op_note(
        OpHook::default()
            .create(|m, r| {
                let exec = r.id.starts_with("conf-exec-");
                m.create(r).map(|o| if exec { CreateOutcome::Created } else { o })
            })
            .trans(|m, id, from, next| m.transition(id, from, next).map(|ok| ok || id.starts_with("conf-exec-"))),
        "execute-once",
    );
    assert_eq!(n, "the function ran 12 times across 12 handles (must be exactly 1)");
    // the losers are refused (their create errors), neither answered from the record nor pending
    let n = op_note(
        OpHook::default().create(|m, r| {
            let exec = r.id.starts_with("conf-exec-");
            match m.create(r)? {
                CreateOutcome::Exists(_) if exec => Err(boom()),
                o => Ok(o),
            }
        }),
        "execute-once",
    );
    assert_eq!(n, "a losing execution was neither answered from the record nor pending: Refused { reason: \"executeAuthorized: operation store: boom (fail closed)\" }");
}

// ------------------------------------------------------------------------------------------------ small kills

#[test]
fn base64_decoding_stops_at_the_first_padding() {
    assert_eq!(b64_lenient("QQ==QQ"), vec![0x41]);
}

#[test]
fn iso_digits_must_be_digits() {
    // 'a' - '0' = 49 would be a valid second if the digit check were skipped
    assert_eq!(parse_iso_ms("2024-01-01T00:00:0aZ"), None);
    assert!(parse_iso_ms("2024-01-01T00:00:09Z").is_some());
}

#[test]
fn an_escalation_request_carries_the_render_digest_only_when_given() {
    let grant = json!({"id": "g"});
    let act = json!({"action": {"verb": "v", "resource": "r"}});
    let with = build_escalation_request_with_render("a", &grant, &act, None, &[], 1, None, Some("abc")).unwrap();
    assert_eq!(with["render_digest"], "abc");
    let without = build_escalation_request_with_render("a", &grant, &act, None, &[], 1, None, None).unwrap();
    assert!(without.get("render_digest").is_none());
}
