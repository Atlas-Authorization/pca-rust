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
//!   * `one-instance` / `instances` / `processes`: the same race through the real guard with real signed PCActns: `copies` copies
//!     of one proof to one guard, spread over several guards on separate handles (declared multi-instance), and over several child
//!     processes ([`guard::ProcessSpec`]; the test binary re-executes itself, see [`guard::run_worker_if_requested`]): exactly one
//!     admitted per round.
//!   * `crash-after-claim-process`: a child process is killed right after the guard admitted a proof; the same proof is then a replay
//!     in a new process and the next counter is admitted.
//!   * `retry-after-timeout`: a claim commits but its answer is lost: the retry on another instance is a replay and the next
//!     counter is admitted; and a retry racing the first claim admits exactly one of the two.
//!
//! Operation-record profile ([`run_operation_store_conformance`]):
//!   * `create-once`: `copies` threads create one id: exactly one creates it, every other sees that same record unchanged.
//!   * `transition-cas`: `copies` threads move `pending -> executing`: exactly one wins; a stale `from` never changes a record.
//!   * `terminal-states-stick`, `list-open` (skipped when the store cannot enumerate), `durability`.
//!   * `execute-once`: `copies` executions of one authorization through [`crate::execute_authorized`], each on its own handle,
//!     run the function exactly once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::{json, Value};

use crate::authorize::{AuthorizedOperation, BudgetClaim, StateStore};
use crate::kv::AtomicKv;
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
    run_state_store_conformance_with(open, opts, None)
}

/// [`run_state_store_conformance`] plus the child-process tests (`processes`, `crash-after-claim-process`) when `processes` names how
/// to start a worker (see [`guard::ProcessSpec`]); without it, and for a process-scoped store, they are not run (`instances` is not run for a
/// process-scoped store either). Besides the direct claim tests the profile runs
/// the store behind the REAL guard ([`crate::authorize`]) with real signed PCActns: `one-instance`, `instances`, `processes`.
pub fn run_state_store_conformance_with(open: &StateOpen<'_>, opts: &Options, processes: Option<&guard::ProcessSpec>) -> ConformanceReport {
    let mut tests = Vec::new();
    tests.push(state_burst(open));
    tests.push(state_concurrent(open, opts));
    if opts.durable {
        tests.push(state_durability(open));
    } else {
        tests.push(skipped("claim-durability", "the store declares itself non-durable"));
    }
    tests.push(guard::one_instance(open, opts));
    // a process-scoped store (an in-memory one) has one instance by definition: the multi-instance and process tests do not apply
    let shared = open().scope() == crate::StoreScope::Shared;
    if shared {
        tests.push(guard::instances(open, opts));
    }
    if let (true, Some(spec)) = (shared, processes) {
        tests.push(guard::processes(opts, spec));
    }
    if opts.durable {
        tests.push(state_crash(open, opts));
        if let (true, Some(spec)) = (shared, processes) {
            tests.push(guard::crash_in_process(spec));
        }
    } else {
        tests.push(skipped("crash-after-claim", "the store declares itself non-durable"));
    }
    tests.push(state_retry(open));
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

fn state_retry(open: &StateOpen<'_>) -> TestReport {
    run("retry-after-timeout", || {
        let word = |r: Result<crate::ClaimResult, crate::authorize::StoreError>| match r {
            Ok(c) if c.ok => "admitted",
            Ok(_) => "replay",
            Err(_) => "error",
        };
        let key = Arc::new(format!("{}:retry", unique("retry")));
        let (first, other) = (open(), open());
        // the commit lands and its answer is lost: whatever the store said is never seen
        let _ = first.claim(&key, 1);
        let retry = word(other.claim(&key, 1));
        let next = word(other.claim(&key, 2));
        // the first commit is still in flight when the caller retries elsewhere
        let (k, h) = (key.clone(), Arc::new([first, other]));
        let pair = race(2, move |i| h[i].claim(&k, 3).map(|r| r.ok)).iter().filter(|r| matches!(r, Ok(true))).count();
        if retry != "replay" || next != "admitted" || pair != 1 {
            return Err(format!("lost answer: first=error, retry={retry}, next counter={next}; in-flight retry: {pair} admitted of 2"));
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------------- atomic kv

/// A factory of handles on one shared atomic key/value backend.
pub type KvOpen<'a> = dyn Fn() -> Arc<dyn AtomicKv> + Send + Sync + 'a;

fn counter_of(v: Option<&Value>) -> u64 {
    v.and_then(|x| x.get("n")).and_then(Value::as_u64).unwrap_or(0)
}

/// Run the atomic key/value profile (`pca-kv`): `update` is one atomic read-modify-write across every handle.
pub fn run_kv_store_conformance(open: &KvOpen<'_>, opts: &Options) -> ConformanceReport {
    let mut tests = vec![kv_basic(open), kv_cas(open, opts), kv_list(open)];
    tests.push(if opts.durable { kv_durability(open) } else { skipped("kv-durability", "the store declares itself non-durable") });
    ConformanceReport { profile: "pca-kv", tests }
}

fn kv_basic(open: &KvOpen<'_>) -> TestReport {
    run("kv-basic", || {
        let s = open();
        let key = format!("{}:basic", unique("kv"));
        if s.get(&key).map_err(|e| e.to_string())?.is_some() {
            return Err("an unused key was not absent".into());
        }
        // `None` leaves the key unchanged: nothing is created, the returned value is what is stored
        let r = s.update(&key, &mut |_| None).map_err(|e| e.to_string())?;
        if r.is_some() || s.get(&key).map_err(|e| e.to_string())?.is_some() {
            return Err("an update that returned None created the key".into());
        }
        let r = s.update(&key, &mut |cur| if cur.is_none() { Some(json!({"n": 1})) } else { None }).map_err(|e| e.to_string())?;
        if r != Some(json!({"n": 1})) {
            return Err(format!("update stored {{n:1}} but answered {r:?}"));
        }
        // the function sees the stored value; `None` keeps it
        let r = s.update(&key, &mut |cur| if counter_of(cur) == 1 { None } else { Some(json!({"n": 99})) }).map_err(|e| e.to_string())?;
        if r != Some(json!({"n": 1})) || s.get(&key).map_err(|e| e.to_string())? != Some(json!({"n": 1})) {
            return Err(format!("an update that returned None changed the stored value ({r:?})"));
        }
        Ok(())
    })
}

fn kv_cas(open: &KvOpen<'_>, o: &Options) -> TestReport {
    run("kv-update-atomic", || {
        let copies = o.copies.max(2);
        for round in 0..o.rounds.max(1) {
            let key = Arc::new(format!("{}:cas{round}", unique("kv")));
            let handles: Arc<Vec<Arc<dyn AtomicKv>>> = Arc::new((0..copies).map(|_| open()).collect());
            let (k, h) = (key.clone(), handles.clone());
            // every copy increments the same document: a lost update shows as a final count below `copies`
            let outs = race(copies, move |i| h[i].update(&k, &mut |cur| Some(json!({"n": counter_of(cur) + 1}))).map(|v| counter_of(v.as_ref())));
            if let Some(e) = outs.iter().find(|r| r.is_err()) {
                return Err(format!("round {round}: an update errored under load: {e:?}"));
            }
            let mut seen: Vec<u64> = outs.into_iter().map(|r| r.unwrap_or(0)).collect();
            seen.sort_unstable();
            let want: Vec<u64> = (1..=copies as u64).collect();
            if seen != want {
                return Err(format!("round {round}: {copies} concurrent increments answered {seen:?}, expected each of 1..={copies} exactly once (a lost update)"));
            }
            let fin = counter_of(open().get(&key).map_err(|e| e.to_string())?.as_ref());
            if fin != copies as u64 {
                return Err(format!("round {round}: the stored count is {fin}, expected {copies}"));
            }
        }
        Ok(())
    })
}

fn kv_list(open: &KvOpen<'_>) -> TestReport {
    run("kv-list-prefix", || {
        let s = open();
        let base = unique("kvl");
        for (suffix, n) in [("a/1", 1), ("a/2", 2), ("b/1", 3)] {
            s.update(&format!("{base}/{suffix}"), &mut |_| Some(json!({"n": n}))).map_err(|e| e.to_string())?;
        }
        match s.list(&format!("{base}/a/")).map_err(|e| e.to_string())? {
            None => Ok(()), // the backend cannot enumerate: allowed by the contract
            Some(mut docs) => {
                docs.sort_by_key(|d| counter_of(Some(d)));
                if docs == vec![json!({"n": 1}), json!({"n": 2})] {
                    Ok(())
                } else {
                    Err(format!("list(prefix) answered {docs:?}, expected exactly the two documents under the prefix"))
                }
            }
        }
    })
}

fn kv_durability(open: &KvOpen<'_>) -> TestReport {
    run("kv-durability", || {
        let key = format!("{}:dur", unique("kv"));
        open().update(&key, &mut |_| Some(json!({"n": 7}))).map_err(|e| e.to_string())?;
        match open().get(&key).map_err(|e| e.to_string())? {
            Some(v) if v == json!({"n": 7}) => Ok(()),
            other => Err(format!("a fresh handle read {other:?} after the write; documents did not survive")),
        }
    })
}

// ---------------------------------------------------------------------------------------------------- trust budget + pins

fn bud(b: f64) -> Value {
    json!({"B": b, "tau": 0, "asOf": 0})
}

/// Run the trust-budget profile (`pca-budget`) against a replay-state store: the budget moves with the counter in ONE atomic step
/// and only if the stored budget is still the one that was read.
pub fn run_budget_store_conformance(open: &StateOpen<'_>, opts: &Options) -> ConformanceReport {
    let mut tests = vec![budget_basic(open), budget_conflict(open), budget_concurrent(open, opts)];
    tests.push(if opts.durable { budget_durability(open) } else { skipped("budget-durability", "the store declares itself non-durable") });
    ConformanceReport { profile: "pca-budget", tests }
}

fn budget_basic(open: &StateOpen<'_>) -> TestReport {
    run("budget-claim", || {
        let s = open();
        let key = format!("{}:b", unique("bud"));
        if s.budget(&key).map_err(|e| e.to_string())?.is_some() {
            return Err("an unused stream has a budget".into());
        }
        match s.claim_budgeted(&key, 1, None, Some(&bud(0.8))) {
            Ok(BudgetClaim::Claimed) => {}
            other => return Err(format!("the first budgeted claim answered {other:?}")),
        }
        if s.budget(&key).map_err(|e| e.to_string())? != Some(bud(0.8)) || s.last(&key) != Some(Some(1)) {
            return Err("the budget and the counter did not both move".into());
        }
        // a replayed counter writes nothing, even with the stored budget as `before`
        match s.claim_budgeted(&key, 1, Some(&bud(0.8)), Some(&bud(0.1))) {
            Ok(BudgetClaim::Replay(_)) => {}
            other => return Err(format!("a replayed counter answered {other:?}")),
        }
        if s.budget(&key).map_err(|e| e.to_string())? != Some(bud(0.8)) {
            return Err("a replayed counter changed the stored budget".into());
        }
        // a claim with nothing to store is a plain claim and leaves the budget alone
        match s.claim_budgeted(&key, 2, Some(&bud(0.8)), None) {
            Ok(BudgetClaim::Claimed) => {}
            other => return Err(format!("a claim with no budget to store answered {other:?}")),
        }
        if s.budget(&key).map_err(|e| e.to_string())? != Some(bud(0.8)) {
            return Err("a claim with no budget to store changed the stored budget".into());
        }
        Ok(())
    })
}

fn budget_conflict(open: &StateOpen<'_>) -> TestReport {
    run("budget-conflict", || {
        let s = open();
        let key = format!("{}:c", unique("bud"));
        s.claim_budgeted(&key, 1, None, Some(&bud(0.8))).map_err(|e| e.to_string())?;
        // another action read `None` before the first one wrote: its swap fails and NOTHING is written (the counter stays free)
        match s.claim_budgeted(&key, 2, None, Some(&bud(0.5))) {
            Ok(BudgetClaim::Conflict) => {}
            other => return Err(format!("a stale read answered {other:?}, expected a conflict")),
        }
        if s.budget(&key).map_err(|e| e.to_string())? != Some(bud(0.8)) || s.last(&key) != Some(Some(1)) {
            return Err("a conflicting claim changed the budget or consumed the counter".into());
        }
        match s.claim_budgeted(&key, 2, Some(&bud(0.8)), Some(&bud(0.5))) {
            Ok(BudgetClaim::Claimed) => Ok(()),
            other => Err(format!("the claim with the right read answered {other:?}")),
        }
    })
}

fn budget_concurrent(open: &StateOpen<'_>, o: &Options) -> TestReport {
    run("budget-concurrent", || {
        let copies = o.copies.max(2);
        for round in 0..o.rounds.max(1) {
            let key = Arc::new(format!("{}:r{round}", unique("bud")));
            let handles: Arc<Vec<Arc<dyn StateStore>>> = Arc::new((0..copies).map(|_| open()).collect());
            let (k, h) = (key.clone(), handles.clone());
            // every copy read "no budget" and spends a different amount: exactly one may win, and the stored budget is the winner's
            let outs = race(copies, move |i| h[i].claim_budgeted(&k, 1, None, Some(&bud(i as f64 / 100.0))).map(|c| c == BudgetClaim::Claimed));
            if let Some(e) = outs.iter().find(|r| r.is_err()) {
                return Err(format!("round {round}: a budgeted claim errored under load: {e:?}"));
            }
            let winners: Vec<usize> = outs.iter().enumerate().filter(|(_, r)| matches!(r, Ok(true))).map(|(i, _)| i).collect();
            if winners.len() != 1 {
                return Err(format!("round {round}: {} of {copies} concurrent budgeted claims were admitted (must be exactly 1)", winners.len()));
            }
            let stored = open().budget(&key).map_err(|e| e.to_string())?;
            if stored != Some(bud(winners[0] as f64 / 100.0)) {
                return Err(format!("round {round}: copy {} won but the stored budget is {stored:?}", winners[0]));
            }
        }
        Ok(())
    })
}

fn budget_durability(open: &StateOpen<'_>) -> TestReport {
    run("budget-durability", || {
        let key = format!("{}:d", unique("bud"));
        open().claim_budgeted(&key, 1, None, Some(&bud(0.4))).map_err(|e| e.to_string())?;
        let s = open();
        if s.budget(&key).map_err(|e| e.to_string())? != Some(bud(0.4)) || s.last(&key) != Some(Some(1)) {
            return Err("a fresh handle did not see the stored budget and counter".into());
        }
        Ok(())
    })
}

/// Run the monotone-pin profile (`pca-pins`): the store holds the highest revocation epoch accepted per key, which never lowers.
pub fn run_pin_store_conformance(open: &StateOpen<'_>, opts: &Options) -> ConformanceReport {
    let mut tests = vec![pin_monotone(open), pin_concurrent(open, opts)];
    tests.push(if opts.durable { pin_durability(open) } else { skipped("pin-durability", "the store declares itself non-durable") });
    ConformanceReport { profile: "pca-pins", tests }
}

fn pin_monotone(open: &StateOpen<'_>) -> TestReport {
    run("pin-monotone", || {
        let s = open();
        if !s.supports_pins() {
            return Err("the store does not declare pin support".into());
        }
        let (a, b) = (format!("{}:a:epoch", unique("pin")), format!("{}:b:epoch", unique("pin")));
        if s.pin(&a).map_err(|e| e.to_string())?.is_some() {
            return Err("an unused key has a pin".into());
        }
        for (v, want) in [(5, 5), (3, 5), (9, 9), (9, 9), (0, 9)] {
            s.raise_pin(&a, v).map_err(|e| e.to_string())?;
            let got = s.pin(&a).map_err(|e| e.to_string())?;
            if got != Some(want) {
                return Err(format!("after raising to {v} the pin is {got:?}, expected {want} (a pin never lowers)"));
            }
        }
        if s.pin(&b).map_err(|e| e.to_string())?.is_some() {
            return Err("a pin leaked into another key".into());
        }
        Ok(())
    })
}

fn pin_concurrent(open: &StateOpen<'_>, o: &Options) -> TestReport {
    run("pin-concurrent", || {
        let copies = o.copies.max(2);
        let key = Arc::new(format!("{}:epoch", unique("pin")));
        let order = Arc::new(shuffled(copies as u64, 0xD1B5_4A32_D192_ED03));
        let handles: Arc<Vec<Arc<dyn StateStore>>> = Arc::new((0..copies).map(|_| open()).collect());
        let (k, ord, h) = (key.clone(), order.clone(), handles.clone());
        let outs = race(copies, move |i| h[i].raise_pin(&k, ord[i] as i64));
        if let Some(e) = outs.iter().find(|r| r.is_err()) {
            return Err(format!("a raise errored under load: {e:?}"));
        }
        let got = open().pin(&key).map_err(|e| e.to_string())?;
        if got != Some(copies as i64) {
            return Err(format!("racing raises of 1..={copies} left the pin at {got:?}, expected {copies}"));
        }
        Ok(())
    })
}

fn pin_durability(open: &StateOpen<'_>) -> TestReport {
    run("pin-durability", || {
        let key = format!("{}:epoch", unique("pin"));
        open().raise_pin(&key, 4).map_err(|e| e.to_string())?;
        match open().pin(&key).map_err(|e| e.to_string())? {
            Some(4) => Ok(()),
            other => Err(format!("a fresh handle read pin {other:?}, expected 4")),
        }
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
                next.executing_at = Some(i as i64 + 1); // the winner's stamp: the stored record must be the winner's
                h[i].transition(&i2, OperationState::Pending, next)
            });
            if let Some(e) = outs.iter().find_map(|r| r.as_ref().err()) {
                return Err(format!("round {round}: transition errored: {e}"));
            }
            let won: Vec<usize> = outs.iter().enumerate().filter(|(_, r)| matches!(r, Ok(true))).map(|(i, _)| i).collect();
            if won.len() != 1 {
                return Err(format!("round {round}: {} of {copies} concurrent pending->executing transitions won (must be exactly 1)", won.len()));
            }
            match s.get(&id).map_err(|e| e.to_string())? {
                Some(r) if r.state == OperationState::Executing && r.executing_at == Some(won[0] as i64 + 1) => {}
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

#[cfg(test)]
mod tests {
    #[test]
    fn the_shuffle_is_pinned() {
        assert_eq!(super::shuffled(12, 0x9E37_79B9_7F4A_7C15), [7, 3, 6, 9, 12, 2, 8, 5, 4, 11, 1, 10]);
    }
}

// the non-Unix exit-status arm lives in its own file so the Windows-only mutation slice mutates exactly the code Windows compiles
#[cfg(not(unix))]
#[path = "store_conformance_not_unix.rs"]
mod not_unix;

// ---------------------------------------------------------------------------------------------------- the real guard

/// The store behind [`crate::authorize`] with real signed PCActns (one grant, one agent, counters 1..n), in this process or in child
/// processes.
pub mod guard {
    use super::*;
    use crate::agent::{default_risk_policy, mint_grant, Agent, KeyPair, Suite};
    use crate::arg_provenance::{principal_direct_provenance, ProvenanceRecorder};
    use crate::{authorize, insecure_calm_risk, AuthorizeInput, CheckStatus, Operation, RiskFn};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    const AUDIENCE: &str = "pca-store-conformance";
    const WORKER_ENV: &str = "ATLAS_PCA_STATE_WORKER";

    /// How a child process is started. The worker is this very test binary: `program` is [`std::env::current_exe`], `args` select
    /// the one test that calls [`run_worker_if_requested`] first thing (e.g. `["--exact", "my_conformance_test", "--nocapture"]`).
    #[derive(Debug, Clone)]
    pub struct ProcessSpec {
        pub program: PathBuf,
        pub args: Vec<String>,
        /// Child processes per race (default 3).
        pub processes: usize,
        /// Extra environment for the workers (where the shared backend lives, for example).
        pub env: Vec<(String, String)>,
    }

    impl ProcessSpec {
        pub fn new(program: PathBuf, args: Vec<String>) -> Self {
            ProcessSpec { program, args, processes: 3, env: Vec::new() }
        }
    }

    /// admitted / denied as a replay / any other denial (fail closed, e.g. a store error).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Outcome {
        Admitted,
        Replay,
        Error,
    }

    /// A grant plus pre-signed PCActns (counters 1..n) from one agent: JSON, so child processes share it.
    #[derive(Debug, Clone)]
    pub struct GuardFixture {
        pub grant: Value,
        pub proofs: Vec<Value>,
    }

    impl GuardFixture {
        pub fn new(n: usize) -> Result<GuardFixture, String> {
            let (principal, agent_key) = (KeyPair::generate()?, KeyPair::generate()?);
            let env = json!({"predicates": [{"verb": "read", "resource": "doc:*"}], "caveats": [], "risk_policy": default_risk_policy()});
            let grant = mint_grant(&principal, &agent_key.public, &env, "store conformance", None, None, &Suite::default())?.grant;
            let agent = Agent::new(agent_key, grant.clone(), AUDIENCE, 0);
            let mut proofs = Vec::new();
            for _ in 0..n {
                proofs.push(agent.act("read", "doc:1", Some(&json!({})), serde_json::Map::new(), &Suite::default())?.pcactn);
            }
            Ok(GuardFixture { grant, proofs })
        }

        fn to_json(&self) -> Value {
            json!({"grant": self.grant, "proofs": self.proofs})
        }

        fn from_json(v: &Value) -> Result<GuardFixture, String> {
            Ok(GuardFixture { grant: v["grant"].clone(), proofs: v["proofs"].as_array().ok_or("fixture: proofs")?.clone() })
        }
    }

    fn recorder() -> Result<ProvenanceRecorder, String> {
        ProvenanceRecorder::new("pca-store-conformance", "k1", Some([1u8; 32]))
    }

    fn bundle(op: &Operation) -> Result<Option<Value>, String> {
        principal_direct_provenance(&mut recorder()?, op).map(Some)
    }

    /// Present proof number `counter` (1-based) to the guard over `store`.
    pub fn check(fx: &GuardFixture, store: &dyn StateStore, counter: usize, multi_instance: bool) -> Outcome {
        let Some(proof) = counter.checked_sub(1).and_then(|i| fx.proofs.get(i)) else { return Outcome::Error };
        let Ok(pin) = recorder().map(|r| r.pin()) else { return Outcome::Error };
        let pins = vec![pin];
        let op = Operation::new("read", "doc:1", json!({}));
        let grant = fx.grant.clone();
        let id = grant["id"].as_str().unwrap_or_default().to_string();
        let resolve = move |r: &str| Ok::<_, String>((r == id).then(|| grant.clone()));
        let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
        let input = AuthorizeInput {
            risk: Some(&insecure_calm_risk as &RiskFn),
            operation: Some(&op),
            audience: AUDIENCE,
            resolve_grant: Some(&resolve),
            state_store: Some(store),
            is_revoked: Some(&not_revoked),
            plan: Some(crate::SINGLE_STEP),
            provenance_mediators: &pins,
            provenance_bundle: Some(&bundle),
            multi_instance: multi_instance.then_some(true),
            ..Default::default()
        };
        let r = authorize(Some(proof), &input);
        if r.allow {
            Outcome::Admitted
        } else if r.check("replay") == Some(CheckStatus::Fail) && r.reasons.iter().chain(r.reason.iter()).any(|s| s.contains("(replay)")) {
            Outcome::Replay
        } else {
            Outcome::Error
        }
    }

    fn admitted_of(fx: &Arc<GuardFixture>, guards: &Arc<Vec<Arc<dyn StateStore>>>, counter: usize, copies: usize, multi: bool) -> usize {
        let (fx, guards) = (fx.clone(), guards.clone());
        race(copies, move |i| check(&fx, guards[i % guards.len()].as_ref(), counter, multi)).into_iter().filter(|o| *o == Outcome::Admitted).count()
    }

    fn exactly_one(test: &'static str, fx: GuardFixture, guards: Vec<Arc<dyn StateStore>>, o: &Options, multi: bool) -> TestReport {
        run(test, || {
            let (fx, guards) = (Arc::new(fx), Arc::new(guards));
            let mut admitted = Vec::new();
            for r in 1..=o.rounds.max(1) {
                admitted.push(admitted_of(&fx, &guards, r, o.copies.max(2), multi));
            }
            if admitted.iter().all(|n| *n == 1) {
                Ok(())
            } else {
                Err(format!("admitted per round {admitted:?}: each proof must be admitted exactly once"))
            }
        })
    }

    pub(super) fn one_instance(open: &StateOpen<'_>, o: &Options) -> TestReport {
        match GuardFixture::new(o.rounds.max(1)) {
            Ok(fx) => exactly_one("one-instance", fx, vec![open()], o, false),
            Err(e) => run("one-instance", || Err(e)),
        }
    }

    pub(super) fn instances(open: &StateOpen<'_>, o: &Options) -> TestReport {
        match GuardFixture::new(o.rounds.max(1)) {
            // a store only an in-process lock can serialise is refused in multi-instance mode, which fails the race
            Ok(fx) => exactly_one("instances", fx, (0..4).map(|_| open()).collect(), o, true),
            Err(e) => run("instances", || Err(e)),
        }
    }

    // ------------------------------------------------------------------------------------------ child processes

    fn now_ms() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }

    fn temp_dir(tag: &str) -> Result<PathBuf, String> {
        let d = std::env::temp_dir().join(unique(tag));
        std::fs::create_dir_all(&d).map_err(|e| format!("temp dir: {e}"))?;
        Ok(d)
    }

    struct WorkerOut {
        admitted: u64,
        replays: u64,
        errors: u64,
        lines: Vec<Value>,
        killed: bool,
    }

    #[cfg(unix)]
    fn killed_by_signal(s: &std::process::ExitStatus) -> bool {
        std::os::unix::process::ExitStatusExt::signal(s).is_some()
    }
    #[cfg(not(unix))]
    use super::not_unix::killed_by_signal;

    fn collect(out: &std::path::Path, status: &std::process::ExitStatus) -> WorkerOut {
        let text = std::fs::read_to_string(out).unwrap_or_default();
        let lines: Vec<Value> = text.lines().filter(|l| !l.is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect();
        let sum = |k: &str| lines.iter().map(|l| l[k].as_u64().unwrap_or(0)).sum::<u64>();
        WorkerOut { admitted: sum("admitted"), replays: sum("replays"), errors: sum("errors"), lines, killed: killed_by_signal(status) }
    }

    fn spawn(spec: &ProcessSpec, cfg: &Value) -> Result<std::process::Child, String> {
        Command::new(&spec.program)
            .args(&spec.args)
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .env(WORKER_ENV, cfg.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start a worker process: {e}"))
    }

    fn run_one(spec: &ProcessSpec, cfg: Value, out: &std::path::Path) -> Result<WorkerOut, String> {
        let status = spawn(spec, &cfg)?.wait().map_err(|e| format!("worker: {e}"))?;
        Ok(collect(out, &status))
    }

    pub(super) fn processes(o: &Options, spec: &ProcessSpec) -> TestReport {
        run("processes", || {
            let rounds = o.rounds.max(1);
            let dir = temp_dir("pstate")?;
            let fx_file = dir.join("fixture.json");
            std::fs::write(&fx_file, GuardFixture::new(rounds)?.to_json().to_string()).map_err(|e| e.to_string())?;
            let (round_ms, origin) = (150u64, now_ms() + 3000);
            let mut kids = Vec::new();
            for p in 0..spec.processes.max(2) {
                let out = dir.join(format!("p{p}.jsonl"));
                let cfg = json!({"mode": "race", "fixture": fx_file, "out": out, "rounds": rounds, "origin": origin, "roundMs": round_ms, "copies": o.copies.max(2), "instances": 2});
                kids.push((out, spawn(spec, &cfg)?));
            }
            let mut outs = Vec::new();
            for (out, mut child) in kids {
                let status = child.wait().map_err(|e| format!("worker: {e}"))?;
                outs.push(collect(&out, &status));
            }
            let admitted: Vec<u64> = (1..=rounds as u64)
                .map(|c| outs.iter().flat_map(|w| w.lines.iter()).filter(|l| l["counter"].as_u64() == Some(c)).map(|l| l["admitted"].as_u64().unwrap_or(0)).sum())
                .collect();
            let unfinished = outs.iter().filter(|w| w.killed || w.lines.len() != rounds).count();
            let errors: u64 = outs.iter().map(|w| w.errors).sum();
            if unfinished > 0 {
                return Err(format!("{unfinished} worker(s) did not finish ({errors} fail-closed errors)"));
            }
            if admitted.iter().all(|n| *n == 1) {
                Ok(())
            } else {
                Err(format!("admitted per round {admitted:?} across {} processes ({errors} fail-closed errors)", outs.len()))
            }
        })
    }

    /// A child process is killed right after the guard admitted a proof, before any handler: the same proof is a replay in a new
    /// process and the next counter is admitted.
    pub(super) fn crash_in_process(spec: &ProcessSpec) -> TestReport {
        run("crash-after-claim-process", || {
            let dir = temp_dir("pcrash")?;
            let fx_file = dir.join("fixture.json");
            std::fs::write(&fx_file, GuardFixture::new(4)?.to_json().to_string()).map_err(|e| e.to_string())?;
            let cfg = |mode: &str, counter: u64, name: &str| json!({"mode": mode, "fixture": fx_file, "out": dir.join(name), "counter": counter, "rounds": 1, "copies": 1, "instances": 1});
            let killed = run_one(spec, cfg("admit-then-die", 3, "a.jsonl"), &dir.join("a.jsonl"))?;
            let retried = run_one(spec, cfg("race", 3, "b.jsonl"), &dir.join("b.jsonl"))?;
            let fresh = run_one(spec, cfg("race", 4, "c.jsonl"), &dir.join("c.jsonl"))?;
            if killed.killed && killed.admitted == 1 && retried.admitted == 0 && retried.replays == 1 && fresh.admitted == 1 {
                Ok(())
            } else {
                Err(format!(
                    "killed after admission={}, admitted before kill={}, retry in a new process admitted {} (replays {}), next counter admitted {}",
                    killed.killed, killed.admitted, retried.admitted, retried.replays, fresh.admitted
                ))
            }
        })
    }

    /// The entry of a child process: when the worker variable is set, run the worker over the store `open` hands out and return true
    /// (the caller then returns without doing anything else). Call it first thing in the test the [`ProcessSpec`] selects.
    pub fn run_worker_if_requested(open: &StateOpen<'_>) -> bool {
        let Ok(raw) = std::env::var(WORKER_ENV) else { return false };
        let ok = serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()).and_then(|cfg| worker(&cfg, open));
        if let Err(e) = ok {
            eprintln!("state worker: {e}");
            std::process::exit(3);
        }
        true
    }

    fn record(out: &str, counter: u64, rs: &[Outcome]) -> Result<(), String> {
        let n = |w: Outcome| rs.iter().filter(|x| **x == w).count();
        let line = json!({"counter": counter, "admitted": n(Outcome::Admitted), "replays": n(Outcome::Replay), "errors": n(Outcome::Error)});
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(out).map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| e.to_string())
    }

    fn worker(cfg: &Value, open: &StateOpen<'_>) -> Result<(), String> {
        let text = |k: &str| cfg[k].as_str().map(String::from).ok_or_else(|| format!("worker config: {k}"));
        let fx = Arc::new(GuardFixture::from_json(&serde_json::from_str(&std::fs::read_to_string(text("fixture")?).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?)?);
        let out = text("out")?;
        let instances = cfg["instances"].as_u64().unwrap_or(1).max(1) as usize;
        let guards: Arc<Vec<Arc<dyn StateStore>>> = Arc::new((0..instances).map(|_| open()).collect());
        let multi = instances > 1 || text("mode")? == "race";
        if text("mode")? == "admit-then-die" {
            let counter = cfg["counter"].as_u64().unwrap_or(1);
            let r = check(&fx, guards[0].as_ref(), counter as usize, multi);
            record(&out, counter, &[r])?;
            // the instance dies after the claim committed and before any handler ran
            std::process::abort();
        }
        let (rounds, copies) = (cfg["rounds"].as_u64().unwrap_or(1), cfg["copies"].as_u64().unwrap_or(1).max(1) as usize);
        let (origin, round_ms) = (cfg["origin"].as_u64().unwrap_or_else(now_ms), cfg["roundMs"].as_u64().unwrap_or(0));
        for r in 0..rounds {
            let counter = cfg["counter"].as_u64().unwrap_or(r + 1);
            let at = origin + r * round_ms;
            while now_ms() < at {
                std::thread::sleep(std::time::Duration::from_millis((at - now_ms()).min(5)));
            }
            let (fx2, g2) = (fx.clone(), guards.clone());
            let rs = race(copies, move |i| check(&fx2, g2[i % g2.len()].as_ref(), counter as usize, multi));
            record(&out, counter, &rs)?;
        }
        Ok(())
    }
}
