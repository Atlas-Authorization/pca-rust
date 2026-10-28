//! A reusable conformance helper for YOUR stores: run the replay-state and operation-record contracts against a store
//! factory, in your own test suite.
//!
//! ```ignore
//! let backend = Arc::new(MyStateStore::connect(url)?);
//! let report = atlas_pca::store_conformance::run_state_store_conformance(&|| backend.clone(), &Options::default());
//! report.assert_passed();
//! ```
//!
//! The factory is called once per simulated verifier instance and must return a handle on the SAME shared backend each time
//! (for an in-process store, a clone of one `Arc`; for a database, a new connection to it). Every test uses keys and ids no
//! earlier run has used, so a shared database needs no cleanup.
//!
//! Replay-state profile ([`run_state_store_conformance`], the Rust form of the `pca-state` profile of the reference kit):
//!   * `claim-burst`: one stream, sequential: a counter is admitted once, an equal or older one is denied (carrying the stored
//!     counter when the store reports it), `last` agrees; streams do not interfere.
//!   * `claim-concurrent`: `copies` threads race the same counter for `rounds` rounds: exactly one is admitted per round; and
//!     distinct counters racing in shuffled order leave the stream at the highest one, every counter at or below it consumed.
//!   * `claim-durability`: after every handle is dropped, a fresh handle still sees the consumed counters.
//!   * `crash-after-claim`: admitted, then the instance dies before its handler runs (handle abandoned): the same counter is
//!     denied afterwards by any instance, the next counter admitted exactly once.
//!
//! Operation-record profile ([`run_operation_store_conformance`]):
//!   * `create-once`: `copies` threads create one id: exactly one creates it, every other sees that same record unchanged.
//!   * `transition-cas`: `copies` threads move `pending -> executing`: exactly one wins; a stale `from` never changes a record.
//!   * `terminal-states-stick`, `list-open` (skipped when the store cannot enumerate), `durability`.
//!   * `execute-once`: `copies` executions of one authorization through [`crate::execute_authorized`], each on its own handle,
//!     run the function exactly once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::json;

use crate::authorize::{AuthorizedOperation, StateStore};
use crate::operations::{
    execute_authorized, CreateOutcome, ExecutableAuthorization, ExecuteOptions, ExecuteOutcome, OperationRecord, OperationState, OperationStore,
};
use crate::staleness::Reversibility;

/// Options of a conformance run.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Rounds per race test (a fresh counter or id each). Default 10.
    pub rounds: usize,
    /// Concurrent copies in each race. Default 16.
    pub copies: usize,
    /// The store claims durability: consumed counters and records survive dropping every handle. Default true; declare false
    /// ONLY for a single-process in-memory store whose lifetime covers the action lifetime (the durability tests then skip).
    pub durable: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { rounds: 10, copies: 16, durable: true }
    }
}

/// A test's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

/// One test's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub test: &'static str,
    pub status: Status,
    /// Why it failed or was skipped.
    pub note: Option<String>,
}

/// A profile's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub profile: &'static str,
    pub tests: Vec<TestReport>,
}

impl ConformanceReport {
    /// True when no test failed (skips do not fail a report, they are listed).
    pub fn passed(&self) -> bool {
        self.tests.iter().all(|t| t.status != Status::Fail)
    }

    /// Panics, listing every failure, unless [`passed`](Self::passed).
    pub fn assert_passed(&self) {
        let failed: Vec<String> = self.tests.iter().filter(|t| t.status == Status::Fail).map(|t| format!("{}: {}", t.test, t.note.as_deref().unwrap_or("failed"))).collect();
        assert!(failed.is_empty(), "{} conformance failed: {}", self.profile, failed.join("; "));
    }
}

fn run(test: &'static str, f: impl FnOnce() -> Result<(), String>) -> TestReport {
    match f() {
        Ok(()) => TestReport { test, status: Status::Pass, note: None },
        Err(note) => TestReport { test, status: Status::Fail, note: Some(note) },
    }
}

fn skipped(test: &'static str, note: &str) -> TestReport {
    TestReport { test, status: Status::Skip, note: Some(note.to_string()) }
}

/// A prefix no earlier run used (time and a process-wide counter).
fn unique(tag: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static N: AtomicUsize = AtomicUsize::new(0);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("conf-{tag}-{t:x}-{}", N.fetch_add(1, Ordering::SeqCst))
}

/// Run `copies` threads that start together; each gets its index.
fn race<T: Send + 'static>(copies: usize, f: impl Fn(usize) -> T + Send + Sync + 'static) -> Vec<T> {
    let gate = Arc::new(Barrier::new(copies));
    let f = Arc::new(f);
    let handles: Vec<_> = (0..copies)
        .map(|i| {
            let (gate, f) = (gate.clone(), f.clone());
            std::thread::spawn(move || {
                gate.wait();
                f(i)
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap_or_else(|_| panic!("a conformance thread panicked"))).collect()
}

/// A deterministic shuffle (no random source needed).
fn shuffled(n: u64, salt: u64) -> Vec<u64> {
    let mut v: Vec<u64> = (1..=n).collect();
    let mut x = salt | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
    v
}

// ---------------------------------------------------------------------------------------------------- replay state

/// A factory of handles on one shared replay-state backend.
pub type StateOpen<'a> = dyn Fn() -> Arc<dyn StateStore> + Send + Sync + 'a;

/// Run the replay-state profile against the store `open` hands out.
pub fn run_state_store_conformance(open: &StateOpen<'_>, opts: &Options) -> ConformanceReport {
    let mut tests = Vec::new();
    tests.push(state_burst(open));
    tests.push(state_concurrent(open, opts));
    if opts.durable {
        tests.push(state_durability(open));
        tests.push(state_crash(open, opts));
    } else {
        tests.push(skipped("claim-durability", "the store declares itself non-durable"));
        tests.push(skipped("crash-after-claim", "the store declares itself non-durable"));
    }
    ConformanceReport { profile: "pca-state", tests }
}

fn claim(s: &dyn StateStore, key: &str, c: u64) -> Result<bool, String> {
    s.claim(key, c).map(|r| r.ok).map_err(|e| format!("claim({key}, {c}) errored: {e}"))
}

fn state_burst(open: &StateOpen<'_>) -> TestReport {
    run("claim-burst", || {
        let s = open();
        let (a, b) = (format!("{}:a", unique("burst")), format!("{}:b", unique("burst")));
        let steps: [(&str, u64, bool); 7] = [("a", 5, true), ("a", 5, false), ("a", 4, false), ("a", 6, true), ("b", 1, true), ("a", 0, false), ("b", 1, false)];
        for (stream, c, want) in steps {
            let key = if stream == "a" { &a } else { &b };
            let r = s.claim(key, c).map_err(|e| format!("claim({key}, {c}) errored: {e}"))?;
            if r.ok != want {
                return Err(format!("claim(stream {stream}, counter {c}) answered {} but the contract says {want}", r.ok));
            }
            // a denial that reports the stored counter reports one at or above the counter denied
            if let (false, Some(last)) = (r.ok, r.last_counter) {
                if last < c {
                    return Err(format!("a denial of counter {c} reported a stored counter {last} below it"));
                }
            }
        }
        match s.last(&a) {
            Some(Some(6)) => {}
            other => return Err(format!("last({a}) is {other:?}, expected Some(Some(6))")),
        }
        Ok(())
    })
}

fn state_concurrent(open: &StateOpen<'_>, o: &Options) -> TestReport {
    run("claim-concurrent", || {
        let copies = o.copies.max(2);
        for round in 0..o.rounds.max(1) {
            let key = Arc::new(format!("{}:r{round}", unique("race")));
            let handles: Vec<Arc<dyn StateStore>> = (0..copies).map(|_| open()).collect();
            let handles = Arc::new(handles);
            let k = key.clone();
            let h = handles.clone();
            let outs = race(copies, move |i| h[i].claim(&k, 1).map(|r| r.ok));
            let admitted = outs.iter().filter(|r| matches!(r, Ok(true))).count();
            if admitted != 1 {
                return Err(format!("round {round}: {admitted} of {copies} concurrent claims of one counter were admitted (must be exactly 1); outcomes {outs:?}"));
            }
        }
        // distinct counters racing in shuffled order: the stream ends at the highest, everything at or below it is consumed
        let n = copies as u64;
        let key = Arc::new(format!("{}:order", unique("race")));
        let order = Arc::new(shuffled(n, 0x9E37_79B9_7F4A_7C15));
        let handles: Arc<Vec<Arc<dyn StateStore>>> = Arc::new((0..copies).map(|_| open()).collect());
        let (k, ord, h) = (key.clone(), order.clone(), handles.clone());
        let outs = race(copies, move |i| h[i].claim(&k, ord[i]).map(|r| r.ok));
        if let Some(e) = outs.iter().find(|r| r.is_err()) {
            return Err(format!("a claim errored under load: {e:?}"));
        }
        let s = open();
        match s.last(&key) {
            Some(Some(last)) if last == n => {}
            other => return Err(format!("after racing counters 1..={n} the stream is at {other:?}, expected Some(Some({n}))")),
        }
        for c in 1..=n {
            if claim(s.as_ref(), &key, c)? {
                return Err(format!("counter {c} was admitted again after the race (the stream is at {n})"));
            }
        }
        if !outs.iter().any(|r| matches!(r, Ok(true))) {
            return Err("no claim of the race was admitted".into());
        }
        Ok(())
    })
}

fn state_durability(open: &StateOpen<'_>) -> TestReport {
    run("claim-durability", || {
        let key = format!("{}:dur", unique("dur"));
        {
            let s = open();
            for c in [1, 2, 3] {
                if !claim(s.as_ref(), &key, c)? {
                    return Err(format!("a fresh counter {c} was denied"));
                }
            }
        }
        let s = open();
        for c in [1, 2, 3] {
            if claim(s.as_ref(), &key, c)? {
                return Err(format!("counter {c} was admitted again by a fresh handle: consumed counters did not survive"));
            }
        }
        if !claim(s.as_ref(), &key, 4)? {
            return Err("the next counter was denied by a fresh handle".into());
        }
        Ok(())
    })
}

fn state_crash(open: &StateOpen<'_>, o: &Options) -> TestReport {
    run("crash-after-claim", || {
        let key = Arc::new(format!("{}:crash", unique("crash")));
        // admitted, then the instance dies before its handler runs: it is abandoned with nothing else done
        let dying = open();
        if !claim(dying.as_ref(), &key, 7)? {
            return Err("a fresh counter was denied".into());
        }
        drop(dying);
        // the same proof is denied afterwards by every instance; the next counter is admitted exactly once
        let copies = o.copies.max(2);
        let handles: Arc<Vec<Arc<dyn StateStore>>> = Arc::new((0..copies).map(|_| open()).collect());
        let (k, h) = (key.clone(), handles.clone());
        let replays = race(copies, move |i| h[i].claim(&k, 7).map(|r| r.ok));
        if replays.iter().any(|r| matches!(r, Ok(true))) {
            return Err("the counter admitted before the crash was admitted again".into());
        }
        let (k, h) = (key.clone(), handles.clone());
        let nexts = race(copies, move |i| h[i].claim(&k, 8).map(|r| r.ok));
        let admitted = nexts.iter().filter(|r| matches!(r, Ok(true))).count();
        if admitted != 1 {
            return Err(format!("{admitted} of {copies} concurrent claims of the next counter were admitted (must be exactly 1)"));
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------------- operation records

/// A factory of handles on one shared operation-record backend.
pub type OperationOpen<'a> = dyn Fn() -> Arc<dyn OperationStore> + Send + Sync + 'a;

fn record(id: &str, state: OperationState) -> OperationRecord {
    OperationRecord {
        id: id.to_string(),
        state,
        verb: "conformance.op".into(),
        resource: "/conformance".into(),
        params_digest: crate::params_digest(None),
        reversibility: Reversibility::Reversible,
        started_at: 1_000,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    }
}

/// Run the operation-record profile against the store `open` hands out.
pub fn run_operation_store_conformance(open: &OperationOpen<'_>, opts: &Options) -> ConformanceReport {
    let mut tests = vec![op_create_once(open, opts), op_transition_cas(open, opts), op_terminal(open), op_list_open(open)];
    tests.push(if opts.durable { op_durability(open) } else { skipped("durability", "the store declares itself non-durable") });
    tests.push(op_execute_once(open, opts));
    ConformanceReport { profile: "operation-records", tests }
}

fn op_create_once(open: &OperationOpen<'_>, o: &Options) -> TestReport {
    run("create-once", || {
        let copies = o.copies.max(2);
        for round in 0..o.rounds.max(1) {
            let id = Arc::new(format!("{}-r{round}", unique("create")));
            let handles: Arc<Vec<Arc<dyn OperationStore>>> = Arc::new((0..copies).map(|_| open()).collect());
            let (i2, h) = (id.clone(), handles.clone());
            let outs = race(copies, move |i| {
                let mut rec = record(&i2, OperationState::Pending);
                rec.verb = format!("claimant-{i}");
                h[i].create(rec)
            });
            let mut created = Vec::new();
            for (i, out) in outs.iter().enumerate() {
                match out {
                    Ok(CreateOutcome::Created) => created.push(i),
                    Ok(CreateOutcome::Exists(_)) => {}
                    Err(e) => return Err(format!("round {round}: create errored: {e}")),
                }
            }
            if created.len() != 1 {
                return Err(format!("round {round}: {} of {copies} concurrent creates succeeded (must be exactly 1)", created.len()));
            }
            let winner = format!("claimant-{}", created[0]);
            for out in outs.iter().flatten() {
                if let CreateOutcome::Exists(r) = out {
                    if r.verb != winner || r.state != OperationState::Pending {
                        return Err(format!("round {round}: a loser saw {:?} / {}, not the winner's pending record", r.state, r.verb));
                    }
                }
            }
            let stored = open().get(&id).map_err(|e| e.to_string())?;
            if stored.map(|r| r.verb) != Some(winner) {
                return Err(format!("round {round}: the stored record is not the winner's"));
            }
        }
        Ok(())
    })
}

fn op_transition_cas(open: &OperationOpen<'_>, o: &Options) -> TestReport {
    run("transition-cas", || {
        let copies = o.copies.max(2);
        for round in 0..o.rounds.max(1) {
            let id = Arc::new(format!("{}-r{round}", unique("cas")));
            let s = open();
            if s.create(record(&id, OperationState::Pending)).map_err(|e| e.to_string())? != CreateOutcome::Created {
                return Err("a fresh id was not created".into());
            }
            // a stale `from` never changes the record
            let mut stale = record(&id, OperationState::Committed);
            stale.finished_at = Some(2_000);
            if s.transition(&id, OperationState::Executing, stale).map_err(|e| e.to_string())? {
                return Err("a transition from the wrong state succeeded".into());
            }
            let handles: Arc<Vec<Arc<dyn OperationStore>>> = Arc::new((0..copies).map(|_| open()).collect());
            let (i2, h) = (id.clone(), handles.clone());
            let outs = race(copies, move |i| {
                let mut next = record(&i2, OperationState::Executing);
                next.executing_at = Some(10 + i as i64);
                h[i].transition(&i2, OperationState::Pending, next)
            });
            if let Some(e) = outs.iter().find_map(|r| r.as_ref().err()) {
                return Err(format!("round {round}: transition errored: {e}"));
            }
            let won = outs.iter().filter(|r| matches!(r, Ok(true))).count();
            if won != 1 {
                return Err(format!("round {round}: {won} of {copies} concurrent pending->executing transitions won (must be exactly 1)"));
            }
            match s.get(&id).map_err(|e| e.to_string())? {
                Some(r) if r.state == OperationState::Executing && r.executing_at.is_some() => {}
                other => return Err(format!("round {round}: the stored record after the race is {other:?}")),
            }
        }
        Ok(())
    })
}

fn op_terminal(open: &OperationOpen<'_>) -> TestReport {
    run("terminal-states-stick", || {
        let s = open();
        let id = unique("terminal");
        if s.get(&id).map_err(|e| e.to_string())?.is_some() {
            return Err("an id nobody created exists".into());
        }
        let mut first = record(&id, OperationState::Pending);
        first.verb = "original".into();
        s.create(first).map_err(|e| e.to_string())?;
        let mut other = record(&id, OperationState::Pending);
        other.verb = "overwrite".into();
        match s.create(other).map_err(|e| e.to_string())? {
            CreateOutcome::Exists(r) if r.verb == "original" => {}
            other => return Err(format!("a second create answered {other:?} instead of the original record unchanged")),
        }
        let step = |from, to: OperationState| -> Result<bool, String> {
            let mut next = record(&id, to);
            next.verb = "original".into();
            next.finished_at = Some(3_000);
            s.transition(&id, from, next).map_err(|e| e.to_string())
        };
        if !step(OperationState::Pending, OperationState::Executing)? || !step(OperationState::Executing, OperationState::Committed)? {
            return Err("the legal pending -> executing -> committed path was refused".into());
        }
        for from in [OperationState::Pending, OperationState::Executing] {
            if step(from, OperationState::Failed)? {
                return Err(format!("a committed record was moved out of by a transition from {}", from.as_str()));
            }
        }
        match s.get(&id).map_err(|e| e.to_string())? {
            Some(r) if r.state == OperationState::Committed => Ok(()),
            other => Err(format!("the committed record changed: {other:?}")),
        }
    })
}

fn op_list_open(open: &OperationOpen<'_>) -> TestReport {
    let s = open();
    match s.list_open() {
        Err(e) => return TestReport { test: "list-open", status: Status::Fail, note: Some(e.to_string()) },
        Ok(None) => return skipped("list-open", "the store cannot enumerate open records (recover by id)"),
        Ok(Some(_)) => {}
    }
    run("list-open", || {
        let tag = unique("open");
        let ids: Vec<String> = ["pending", "executing", "committed"].iter().map(|n| format!("{tag}-{n}")).collect();
        for id in &ids {
            s.create(record(id, OperationState::Pending)).map_err(|e| e.to_string())?;
        }
        s.transition(&ids[1], OperationState::Pending, record(&ids[1], OperationState::Executing)).map_err(|e| e.to_string())?;
        s.transition(&ids[2], OperationState::Pending, record(&ids[2], OperationState::Executing)).map_err(|e| e.to_string())?;
        s.transition(&ids[2], OperationState::Executing, record(&ids[2], OperationState::Committed)).map_err(|e| e.to_string())?;
        let open_ids: Vec<String> = s.list_open().map_err(|e| e.to_string())?.unwrap_or_default().into_iter().map(|r| r.id).filter(|i| i.starts_with(&tag)).collect();
        let mut got = open_ids.clone();
        got.sort();
        let mut want = vec![ids[0].clone(), ids[1].clone()];
        want.sort();
        if got != want {
            return Err(format!("list_open returned {open_ids:?}, expected exactly the pending and the executing record"));
        }
        Ok(())
    })
}

fn op_durability(open: &OperationOpen<'_>) -> TestReport {
    run("durability", || {
        let id = unique("dur");
        {
            let s = open();
            s.create(record(&id, OperationState::Pending)).map_err(|e| e.to_string())?;
            let mut running = record(&id, OperationState::Executing);
            running.executing_at = Some(5);
            if !s.transition(&id, OperationState::Pending, running).map_err(|e| e.to_string())? {
                return Err("pending -> executing was refused".into());
            }
        }
        // the instance died while the side effect ran: a fresh handle sees an executing record, never a free id
        let s = open();
        match s.get(&id).map_err(|e| e.to_string())? {
            Some(r) if r.state == OperationState::Executing && r.executing_at == Some(5) => {}
            other => return Err(format!("a fresh handle saw {other:?} instead of the executing record")),
        }
        if s.create(record(&id, OperationState::Pending)).map_err(|e| e.to_string())? == CreateOutcome::Created {
            return Err("a fresh handle created an id that was already claimed".into());
        }
        Ok(())
    })
}

fn op_execute_once(open: &OperationOpen<'_>, o: &Options) -> TestReport {
    run("execute-once", || {
        let copies = o.copies.max(2);
        let id = Arc::new(unique("exec"));
        let runs = Arc::new(AtomicUsize::new(0));
        let handles: Arc<Vec<Arc<dyn OperationStore>>> = Arc::new((0..copies).map(|_| open()).collect());
        let (i2, h, r2) = (id.clone(), handles.clone(), runs.clone());
        let outs = race(copies, move |i| {
            let az = ExecutableAuthorization {
                allow: true,
                pcactn: Some(json!({"action": {"reversibility_class": "reversible"}})),
                operation: Some(AuthorizedOperation { verb: "conformance.op".into(), resource: "/conformance".into(), params_digest: crate::params_digest(None), id: (*i2).clone() }),
            };
            let opts = ExecuteOptions { store: Some(h[i].as_ref()), ..Default::default() };
            let r3 = r2.clone();
            execute_authorized(
                &az,
                move |_| {
                    r3.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    Ok(json!("done"))
                },
                &opts,
            )
        });
        let ran = runs.load(Ordering::SeqCst);
        if ran != 1 {
            return Err(format!("the function ran {ran} times across {copies} handles (must be exactly 1)"));
        }
        let fresh = outs.iter().filter(|o| matches!(o, ExecuteOutcome::Committed { replayed: false, .. })).count();
        if fresh != 1 {
            return Err(format!("{fresh} executions reported a fresh commit (must be exactly 1): {outs:?}"));
        }
        if let Some(bad) = outs.iter().find(|o| !matches!(o, ExecuteOutcome::Committed { .. } | ExecuteOutcome::Pending { .. })) {
            return Err(format!("a losing execution was neither answered from the record nor pending: {bad:?}"));
        }
        Ok(())
    })
}
