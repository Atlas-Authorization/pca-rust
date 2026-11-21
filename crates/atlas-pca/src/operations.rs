//! Operation records: execute an authorized operation at most once, with a durable record of what happened.
//!
//! [`authorize`](crate::authorize) decides and consumes the PCActn's replay counter. Between that decision and the end of
//! the side effect the process can crash, the client can time out and retry, or two workers can pick up the same
//! authorization. This module closes the gap with a record per operation id ([`AuthorizedOperation::id`], the digest of
//! the presented PCActn):
//!
//!   1. [`execute_authorized`] creates the record in state `pending` BEFORE anything runs (one atomic create-if-absent: of N
//!      concurrent executions of one authorization exactly one gets to run the function);
//!   2. for an irreversible operation it re-checks revocation, expiry and approval immediately before the function runs
//!      (`recheck`; required, fail closed); a failed re-check records `aborted` and the function never runs;
//!   3. it moves the record to `executing` and only then calls the function, with the operation id as the idempotency key;
//!   4. the record becomes `committed` (with the function's result) or `failed` (with its error) afterwards.
//!
//! A second execution of the same id never runs the function again: it is answered from the record. Nothing is re-run
//! after a crash either. Once `pending_timeout_ms` has passed, a record still `pending` is settled as `aborted` (the side
//! effect never started) and one still `executing` as `uncertain` (it may or may not have happened: an operator or a
//! reconciliation job settles it with [`resolve_operation`], asking the downstream system by the idempotency key).
//! [`Executor`] combines `authorize` and `execute_authorized` so that a retry of the same PCActn is answered from the record
//! instead of a bare replay denial.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::authorize::{AuthorizeOptions, AuthorizeResult, AuthorizedOperation, Operation, StoreError};
use crate::kv::AtomicKv;
use crate::plans::PlanCheckOptions;
use crate::staleness::{effective_reversibility, js_num, Reversibility};
use crate::{hash_canonical, hash_canonical_strict};

/// Default age after which an open record is settled (5 minutes).
pub const OPERATION_PENDING_TIMEOUT_MS: i64 = 300_000;

/// Where an operation is in its execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// Claimed, the function not started yet (re-check running), or the process crashed before starting it.
    Pending,
    /// The function has been started: the side effect is running, or the process crashed during or after it.
    Executing,
    /// The side effect completed; `result` is what the function returned.
    Committed,
    /// The function failed; `error` is its message. Not re-run.
    Failed,
    /// The pre-execution re-check refused: the function never ran.
    Aborted,
    /// Found `executing` after the timeout: the outcome is unknown and must be reconciled, never silently re-run.
    Uncertain,
}

impl OperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            OperationState::Pending => "pending",
            OperationState::Executing => "executing",
            OperationState::Committed => "committed",
            OperationState::Failed => "failed",
            OperationState::Aborted => "aborted",
            OperationState::Uncertain => "uncertain",
        }
    }

    pub fn parse(s: &str) -> Option<OperationState> {
        Some(match s {
            "pending" => OperationState::Pending,
            "executing" => OperationState::Executing,
            "committed" => OperationState::Committed,
            "failed" => OperationState::Failed,
            "aborted" => OperationState::Aborted,
            "uncertain" => OperationState::Uncertain,
            _ => return None,
        })
    }
}

/// One operation's durable record.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationRecord {
    /// The operation id, also the idempotency key handed to the function.
    pub id: String,
    pub state: OperationState,
    pub verb: String,
    pub resource: String,
    pub params_digest: String,
    /// The effective reversibility class the execution ran under.
    pub reversibility: Reversibility,
    /// When the record was created (epoch ms).
    pub started_at: i64,
    pub executing_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// `committed`: the value the function returned (JSON).
    pub result: Option<Value>,
    /// `failed` / `aborted` / `uncertain`: why.
    pub error: Option<String>,
}

impl OperationRecord {
    /// The record as the shared vectors write it (`startedAt`, `executingAt`, `finishedAt`; absent members omitted).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("state".into(), json!(self.state.as_str()));
        m.insert("verb".into(), json!(self.verb));
        m.insert("resource".into(), json!(self.resource));
        m.insert("params_digest".into(), json!(self.params_digest));
        m.insert("reversibility".into(), json!(self.reversibility.as_str()));
        m.insert("startedAt".into(), json!(self.started_at));
        if let Some(t) = self.executing_at {
            m.insert("executingAt".into(), json!(t));
        }
        if let Some(t) = self.finished_at {
            m.insert("finishedAt".into(), json!(t));
        }
        if let Some(r) = &self.result {
            m.insert("result".into(), r.clone());
        }
        if let Some(e) = &self.error {
            m.insert("error".into(), json!(e));
        }
        Value::Object(m)
    }

    /// `None` when the document is not a well-formed record.
    pub fn from_json(v: &Value) -> Option<OperationRecord> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let t = |k: &str| v.get(k).and_then(Value::as_i64);
        Some(OperationRecord {
            id: s("id")?,
            state: OperationState::parse(v.get("state")?.as_str()?)?,
            verb: s("verb")?,
            resource: s("resource")?,
            params_digest: s("params_digest")?,
            reversibility: Reversibility::parse(v.get("reversibility")?.as_str()?)?,
            started_at: t("startedAt")?,
            executing_at: t("executingAt"),
            finished_at: t("finishedAt"),
            result: v.get("result").cloned(),
            error: s("error"),
        })
    }
}

/// The answer of [`OperationStore::create`].
#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created,
    /// A record with this id already exists (returned unchanged).
    Exists(OperationRecord),
}

/// Durable, shared storage for operation records. `create` and `transition` MUST be atomic across every thread, process and
/// node that shares the store (a unique-key insert and a conditional `UPDATE ... WHERE state = ?`, a Lua script, an
/// [`AtomicKv::update`]). A call that cannot decide MUST return an error; the executor then refuses or reports the outcome
/// as unknown.
pub trait OperationStore: Send + Sync {
    /// Atomically insert `record` if no record with its id exists; otherwise return the existing record unchanged.
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError>;
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError>;
    /// Atomically replace the record with `next` only if its current state is `from`. Returns whether it did.
    fn transition(&self, id: &str, from: OperationState, next: OperationRecord) -> Result<bool, StoreError>;
    /// Records still `pending` or `executing` (for [`recover_operations`]); `None`: the store cannot enumerate, recover by id.
    fn list_open(&self) -> Result<Option<Vec<OperationRecord>>, StoreError> {
        Ok(None)
    }
}

fn is_open(r: &OperationRecord) -> bool {
    matches!(r.state, OperationState::Pending | OperationState::Executing)
}

/// In-memory [`OperationStore`] for ONE process (tests, a single worker). Its records die with the process.
#[derive(Debug, Default)]
pub struct MemoryOperationStore {
    m: Mutex<BTreeMap<String, OperationRecord>>,
}

impl MemoryOperationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OperationStore for MemoryOperationStore {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        let mut m = self.m.lock().map_err(|_| StoreError("the operation store lock is poisoned".into()))?;
        if let Some(cur) = m.get(&record.id) {
            return Ok(CreateOutcome::Exists(cur.clone()));
        }
        m.insert(record.id.clone(), record);
        Ok(CreateOutcome::Created)
    }

    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        Ok(self.m.lock().map_err(|_| StoreError("the operation store lock is poisoned".into()))?.get(id).cloned())
    }

    fn transition(&self, id: &str, from: OperationState, mut next: OperationRecord) -> Result<bool, StoreError> {
        let mut m = self.m.lock().map_err(|_| StoreError("the operation store lock is poisoned".into()))?;
        if m.get(id).map(|r| r.state) != Some(from) {
            return Ok(false);
        }
        next.id = id.to_string();
        m.insert(id.to_string(), next);
        Ok(true)
    }

    fn list_open(&self) -> Result<Option<Vec<OperationRecord>>, StoreError> {
        let m = self.m.lock().map_err(|_| StoreError("the operation store lock is poisoned".into()))?;
        Ok(Some(m.values().filter(|r| is_open(r)).cloned().collect()))
    }
}

/// [`OperationStore`] over any [`AtomicKv`] (for example `SqliteAtomicKv`: crash-safe and multi-process-safe on one host).
/// `prefix` namespaces the keys. It can list open records when the key/value store can enumerate.
pub struct KvOperationStore {
    kv: Arc<dyn AtomicKv>,
    prefix: String,
}

impl KvOperationStore {
    pub fn new(kv: Arc<dyn AtomicKv>) -> Self {
        KvOperationStore { kv, prefix: "pca-op:".to_string() }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, id: &str) -> String {
        format!("{}{id}", self.prefix)
    }
}

fn corrupt(id: &str) -> StoreError {
    StoreError(format!("the stored record of operation {id} is malformed"))
}

impl OperationStore for KvOperationStore {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        let mut existing: Option<OperationRecord> = None;
        let mut bad = false;
        let doc = record.to_json();
        self.kv.update(&self.key(&record.id), &mut |prev| match prev {
            None => Some(doc.clone()),
            Some(p) => {
                existing = OperationRecord::from_json(p);
                bad = existing.is_none();
                None
            }
        })?;
        if bad {
            return Err(corrupt(&record.id));
        }
        Ok(existing.map_or(CreateOutcome::Created, CreateOutcome::Exists))
    }

    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        match self.kv.get(&self.key(id))? {
            None => Ok(None),
            Some(v) => OperationRecord::from_json(&v).map(Some).ok_or_else(|| corrupt(id)),
        }
    }

    fn transition(&self, id: &str, from: OperationState, mut next: OperationRecord) -> Result<bool, StoreError> {
        next.id = id.to_string();
        let doc = next.to_json();
        let mut done = false;
        self.kv.update(&self.key(id), &mut |prev| {
            done = prev.and_then(OperationRecord::from_json).map(|r| r.state) == Some(from);
            done.then(|| doc.clone())
        })?;
        Ok(done)
    }

    fn list_open(&self) -> Result<Option<Vec<OperationRecord>>, StoreError> {
        Ok(self.kv.list(&self.prefix)?.map(|docs| docs.iter().filter_map(OperationRecord::from_json).filter(is_open).collect()))
    }
}

/// What the executed function receives.
#[derive(Debug, Clone)]
pub struct ExecutionHandle {
    /// The operation id: pass it as the idempotency key of the downstream call (for example `Idempotency-Key`).
    pub idempotency_key: String,
    pub operation: AuthorizedOperation,
    pub pcactn: Value,
}

/// A pre-execution re-check: `Ok(())` the authorization still stands, `Err(reason)` it does not. A panic counts as a refusal.
pub type RecheckFn<'a> = dyn Fn(&ExecutionHandle) -> Result<(), String> + 'a;

/// Which operations are re-checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecheckFor {
    /// Irreversible operations only (the default).
    #[default]
    Irreversible,
    /// Every operation.
    Always,
}

/// Options of [`execute_authorized`].
#[derive(Clone, Copy, Default)]
pub struct ExecuteOptions<'a> {
    /// REQUIRED: the operation record store (shared and durable in production). Absent: refused.
    pub store: Option<&'a dyn OperationStore>,
    /// The operation about to execute. When given, the authorization must be for exactly it.
    pub operation: Option<&'a Operation>,
    /// Re-check, immediately before the function, that the authorization still stands (grant not revoked, approval not
    /// withdrawn). REQUIRED for an irreversible operation (fail closed). The PCActn's own expiry is always checked with it.
    pub recheck: Option<&'a RecheckFn<'a>>,
    pub recheck_for: RecheckFor,
    /// The server's authoritative reversibility class; the stricter of it and the signed class applies (missing = irreversible).
    pub reversibility_class: Option<&'a str>,
    /// An open record older than this (ms) is settled. Default [`OPERATION_PENDING_TIMEOUT_MS`].
    pub pending_timeout_ms: Option<i64>,
    /// Clock (epoch ms). Default the system clock.
    pub now: Option<&'a dyn Fn() -> i64>,
}

/// What can be executed: an allowed [`AuthorizeResult`] (`ExecutableAuthorization::from`), or the three parts directly.
#[derive(Debug, Clone)]
pub struct ExecutableAuthorization {
    pub allow: bool,
    pub pcactn: Option<Value>,
    pub operation: Option<AuthorizedOperation>,
}

impl From<&AuthorizeResult> for ExecutableAuthorization {
    fn from(r: &AuthorizeResult) -> Self {
        ExecutableAuthorization {
            allow: r.allow && r.verdict.as_ref().is_some_and(|v| v.allow),
            pcactn: r.pcactn.clone(),
            operation: r.operation.clone(),
        }
    }
}

/// The outcome of an execution attempt. `replayed: true` means it was answered from an existing record.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecuteOutcome {
    /// `recorded: false`: the function ran but the record could not be written (it stays `executing`, so `uncertain`).
    Committed { operation_id: String, result: Value, replayed: bool, recorded: bool },
    Failed { operation_id: String, error: String, replayed: bool },
    Aborted { operation_id: String, reason: String, replayed: bool },
    /// Another execution of this id is in flight (or crashed less than the timeout ago). The function did not run here.
    Pending { operation_id: String },
    /// The outcome of an earlier execution is unknown. The function did not run here.
    Uncertain { operation_id: String, reason: String },
    /// Not executed and nothing recorded: the authorization does not allow this operation, or the configuration is incomplete.
    Refused { reason: String },
}

impl ExecuteOutcome {
    /// The outcome as the shared vectors write it.
    pub fn to_json(&self) -> Value {
        match self {
            ExecuteOutcome::Committed { operation_id, result, replayed, recorded } => {
                json!({"status": "committed", "operationId": operation_id, "result": result, "replayed": replayed, "recorded": recorded})
            }
            ExecuteOutcome::Failed { operation_id, error, replayed } => json!({"status": "failed", "operationId": operation_id, "error": error, "replayed": replayed}),
            ExecuteOutcome::Aborted { operation_id, reason, replayed } => json!({"status": "aborted", "operationId": operation_id, "reason": reason, "replayed": replayed}),
            ExecuteOutcome::Pending { operation_id } => json!({"status": "pending", "operationId": operation_id, "replayed": true}),
            ExecuteOutcome::Uncertain { operation_id, reason } => json!({"status": "uncertain", "operationId": operation_id, "reason": reason, "replayed": true}),
            ExecuteOutcome::Refused { reason } => json!({"status": "refused", "reason": reason}),
        }
    }
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
    match e.downcast::<String>() {
        Ok(s) => *s,
        Err(e) => e.downcast::<&str>().map(|s| s.to_string()).unwrap_or_else(|_| "unknown".to_string()),
    }
}

/// Settle an open record older than `timeout_ms`: `pending` -> `aborted`, `executing` -> `uncertain`.
fn settle_stale(store: &dyn OperationStore, rec: OperationRecord, now: i64, timeout_ms: i64) -> Result<OperationRecord, StoreError> {
    if !is_open(&rec) {
        return Ok(rec);
    }
    // `executing` is aged from the moment the function was started (a slow re-check does not count against it)
    let since = if rec.state == OperationState::Executing { rec.executing_at.unwrap_or(rec.started_at) } else { rec.started_at };
    if !(now - since > timeout_ms) {
        return Ok(rec);
    }
    let mut next = rec.clone();
    next.finished_at = Some(now);
    if rec.state == OperationState::Pending {
        next.state = OperationState::Aborted;
        next.error = Some(format!("not started within {timeout_ms} ms of the claim: the side effect never ran"));
    } else {
        next.state = OperationState::Uncertain;
        next.error = Some(format!("no outcome recorded within {timeout_ms} ms of the start: the side effect may or may not have happened"));
    }
    store.transition(&rec.id, rec.state, next.clone())?;
    // whatever is stored now (the original execution may have finished in between)
    Ok(store.get(&rec.id)?.unwrap_or(next))
}

fn store_unknown(id: &str, e: StoreError) -> ExecuteOutcome {
    ExecuteOutcome::Uncertain { operation_id: id.to_string(), reason: format!("operation store: {} (fail closed)", e.0) }
}

/// Answer an execution attempt from an existing record (never runs anything).
fn from_record(store: &dyn OperationStore, rec0: OperationRecord, now: i64, timeout_ms: i64) -> ExecuteOutcome {
    let id = rec0.id.clone();
    let rec = match settle_stale(store, rec0, now, timeout_ms) {
        Ok(r) => r,
        Err(e) => return store_unknown(&id, e),
    };
    let operation_id = rec.id.clone();
    match rec.state {
        OperationState::Committed => ExecuteOutcome::Committed { operation_id, result: rec.result.unwrap_or(Value::Null), replayed: true, recorded: true },
        OperationState::Failed => ExecuteOutcome::Failed { operation_id, error: rec.error.unwrap_or_else(|| "failed".into()), replayed: true },
        OperationState::Aborted => ExecuteOutcome::Aborted { operation_id, reason: rec.error.unwrap_or_else(|| "aborted".into()), replayed: true },
        OperationState::Uncertain => ExecuteOutcome::Uncertain { operation_id, reason: rec.error.unwrap_or_else(|| "outcome unknown".into()) },
        OperationState::Pending | OperationState::Executing => ExecuteOutcome::Pending { operation_id },
    }
}

/// Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state.
fn finish(store: &dyn OperationStore, rec: &OperationRecord, update: impl FnOnce(&mut OperationRecord)) -> Result<bool, StoreError> {
    let mut out = rec.clone();
    update(&mut out);
    if store.transition(&rec.id, rec.state, out.clone())? {
        return Ok(true);
    }
    if rec.state == OperationState::Executing {
        return store.transition(&rec.id, OperationState::Uncertain, out);
    }
    Ok(false)
}

/// Answer from the record as it is stored now (a concurrent recovery or execution changed it).
fn answer_current(store: &dyn OperationStore, id: &str, now: i64, timeout_ms: i64) -> ExecuteOutcome {
    match store.get(id) {
        Ok(Some(cur)) => from_record(store, cur, now, timeout_ms),
        Ok(None) => ExecuteOutcome::Uncertain { operation_id: id.to_string(), reason: "the operation record disappeared".into() },
        Err(e) => store_unknown(id, e),
    }
}

fn matches_operation(bound: &AuthorizedOperation, op: &Operation) -> bool {
    op.params.is_object() && bound.verb == op.verb && bound.resource == op.resource && hash_canonical_strict(&op.params).as_deref() == Some(bound.params_digest.as_str())
}

/// Execute an allowed authorization at most once, with a durable record (see the module doc). `f` runs only if this call
/// created the `pending` record and the re-check (when required) passed; every other outcome is answered from the record.
/// A failure or panic of `f` is recorded as `failed` and returned.
pub fn execute_authorized(
    authorization: &ExecutableAuthorization,
    f: impl FnOnce(&ExecutionHandle) -> Result<Value, String>,
    opts: &ExecuteOptions<'_>,
) -> ExecuteOutcome {
    let refused = |reason: String| ExecuteOutcome::Refused { reason };
    let Some(store) = opts.store else {
        return refused("executeAuthorized: missing required component: store (fail closed)".into());
    };
    let (Some(pcactn), Some(operation)) = (authorization.pcactn.as_ref(), authorization.operation.as_ref()) else {
        return refused("executeAuthorized: the authorization did not allow an operation".into());
    };
    if !authorization.allow || operation.id.is_empty() {
        return refused("executeAuthorized: the authorization did not allow an operation".into());
    }
    if opts.operation.is_some_and(|want| !matches_operation(operation, want)) {
        return refused("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)".into());
    }
    let clock = |s: &ExecuteOptions<'_>| s.now.map_or_else(system_now, |f| f());
    let timeout_ms = opts.pending_timeout_ms.unwrap_or(OPERATION_PENDING_TIMEOUT_MS);
    let reversibility = effective_reversibility(opts.reversibility_class, pcactn.get("action").and_then(|a| a.get("reversibility_class")));
    let must_recheck = reversibility == Reversibility::Irreversible || opts.recheck_for == RecheckFor::Always;
    if must_recheck && opts.recheck.is_none() {
        return refused(format!(
            "executeAuthorized: a {} operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)",
            reversibility.as_str()
        ));
    }

    let handle = ExecutionHandle { idempotency_key: operation.id.clone(), operation: operation.clone(), pcactn: pcactn.clone() };
    let rec = OperationRecord {
        id: operation.id.clone(),
        state: OperationState::Pending,
        verb: operation.verb.clone(),
        resource: operation.resource.clone(),
        params_digest: operation.params_digest.clone(),
        reversibility,
        started_at: clock(opts),
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    };
    match store.create(rec.clone()) {
        Ok(CreateOutcome::Created) => {}
        Ok(CreateOutcome::Exists(existing)) => return from_record(store, existing, clock(opts), timeout_ms),
        Err(e) => return refused(format!("executeAuthorized: operation store: {} (fail closed)", e.0)),
    }

    if let (true, Some(recheck)) = (must_recheck, opts.recheck) {
        let t = clock(opts);
        let expired = pcactn.get("exp").and_then(Value::as_f64).filter(|exp| (t as f64) > *exp);
        let rc: Result<(), String> = match expired {
            Some(exp) => Err(format!("the PCActn expired at {}", js_num(exp))),
            None => match catch_unwind(AssertUnwindSafe(|| recheck(&handle))) {
                Ok(r) => r,
                Err(e) => Err(format!("recheck error (fail closed): {}", panic_message(e))),
            },
        };
        if let Err(why) = rc {
            let reason = format!("recheck: {}", if why.is_empty() { "refused" } else { why.as_str() });
            let at = clock(opts);
            return match finish(store, &rec, |o| {
                o.state = OperationState::Aborted;
                o.error = Some(reason.clone());
                o.finished_at = Some(at);
            }) {
                Ok(true) => ExecuteOutcome::Aborted { operation_id: rec.id, reason, replayed: false },
                Ok(false) => answer_current(store, &rec.id, clock(opts), timeout_ms),
                Err(e) => store_unknown(&rec.id, e),
            };
        }
    }

    // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
    let mut running = rec.clone();
    running.state = OperationState::Executing;
    running.executing_at = Some(clock(opts));
    match store.transition(&rec.id, OperationState::Pending, running.clone()) {
        Ok(true) => {}
        Ok(false) => return answer_current(store, &rec.id, clock(opts), timeout_ms),
        Err(e) => return refused(format!("executeAuthorized: operation store: {} (fail closed)", e.0)),
    }

    let ran = catch_unwind(AssertUnwindSafe(|| f(&handle))).unwrap_or_else(|e| Err(panic_message(e)));
    match ran {
        Err(error) => {
            let at = clock(opts);
            let _ = finish(store, &running, |o| {
                o.state = OperationState::Failed;
                o.error = Some(error.clone());
                o.finished_at = Some(at);
            });
            ExecuteOutcome::Failed { operation_id: rec.id, error, replayed: false }
        }
        Ok(result) => {
            let at = clock(opts);
            let recorded = finish(store, &running, |o| {
                o.state = OperationState::Committed;
                o.result = Some(result.clone());
                o.finished_at = Some(at);
            })
            .unwrap_or(false);
            ExecuteOutcome::Committed { operation_id: rec.id, result, replayed: false, recorded }
        }
    }
}

/// Options of [`recover_operations`] / [`recover_operation`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoverOptions {
    /// Settle open records older than this (ms). Default [`OPERATION_PENDING_TIMEOUT_MS`].
    pub older_than_ms: Option<i64>,
    /// The current time (epoch ms). Default the system clock.
    pub now: Option<i64>,
}

/// Settle every open record older than the age (run it at startup and periodically): `pending` -> `aborted` (the side
/// effect never started), `executing` -> `uncertain`. Returns the records it settled. Nothing is re-run: reconcile each
/// `uncertain` one with [`resolve_operation`]. Errors when the store cannot enumerate (recover by id instead).
pub fn recover_operations(store: &dyn OperationStore, opts: &RecoverOptions) -> Result<Vec<OperationRecord>, StoreError> {
    let open = store.list_open()?.ok_or_else(|| StoreError("recoverOperations: the store has no list_open (recover by id with recover_operation)".into()))?;
    let mut out = Vec::new();
    for r in open {
        if let Some(u) = recover_operation(store, &r.id, opts)? {
            if u.state != r.state {
                out.push(u);
            }
        }
    }
    Ok(out)
}

/// [`recover_operations`] for one id. Returns the record as it now stands (`None`: no record, the operation never started).
pub fn recover_operation(store: &dyn OperationStore, id: &str, opts: &RecoverOptions) -> Result<Option<OperationRecord>, StoreError> {
    match store.get(id)? {
        None => Ok(None),
        Some(r) => settle_stale(store, r, opts.now.unwrap_or_else(system_now), opts.older_than_ms.unwrap_or(OPERATION_PENDING_TIMEOUT_MS)).map(Some),
    }
}

/// The reconciled outcome of an `uncertain` operation.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedOutcome {
    Committed(Option<Value>),
    Failed(String),
}

/// Settle an `uncertain` record after reconciling with the downstream system (look the idempotency key up there). Returns
/// false if the record is not `uncertain`.
pub fn resolve_operation(store: &dyn OperationStore, id: &str, outcome: &ResolvedOutcome, now: Option<i64>) -> Result<bool, StoreError> {
    let Some(mut r) = store.get(id)? else { return Ok(false) };
    if r.state != OperationState::Uncertain {
        return Ok(false);
    }
    r.finished_at = Some(now.unwrap_or_else(system_now));
    match outcome {
        ResolvedOutcome::Committed(result) => {
            r.state = OperationState::Committed;
            r.result = result.clone();
        }
        ResolvedOutcome::Failed(error) => {
            r.state = OperationState::Failed;
            r.error = Some(error.clone());
        }
    }
    store.transition(id, OperationState::Uncertain, r)
}

type GrantFn = dyn Fn(&str) -> Result<Option<Value>, String> + Send + Sync;
type ClassFn = dyn Fn(&Operation) -> Option<String> + Send + Sync;
type ClockFn = dyn Fn() -> i64 + Send + Sync;
type SharedRecheck = dyn Fn(&ExecutionHandle) -> Result<(), String> + Send + Sync;

/// The executor's answer: the execution outcome, or the authorization denial (nothing ran).
#[derive(Debug, Clone)]
pub enum ExecutorOutcome {
    Executed(ExecuteOutcome),
    Denied(Box<AuthorizeResult>),
}

/// `authorize` + [`execute_authorized`] in one call, with retries answered from the record: a second presentation of the
/// same PCActn is refused by `authorize` as a replay, and if that replay is the ONLY failing check and a record exists for
/// its operation id and this operation, the record's outcome is returned (`replayed: true`) instead of the denial. No
/// record means the first attempt never reached execution: the denial stands (the agent signs a fresh PCActn).
///
/// Before an irreversible operation runs it re-checks, on top of your own `recheck`: the revocation hook against the grant
/// from `resolve_grant`, the PCActn's expiry, and (with a plan registry on the authorize options) that a registered plan is
/// still executable.
pub struct Executor {
    authorize: AuthorizeOptions,
    audience: String,
    resolve_grant: Arc<GrantFn>,
    operations: Arc<dyn OperationStore>,
    recheck: Option<Arc<SharedRecheck>>,
    recheck_for: RecheckFor,
    class_of: Option<Arc<ClassFn>>,
    pending_timeout_ms: i64,
    clock: Option<Arc<ClockFn>>,
}

impl Executor {
    pub fn new(
        authorize: AuthorizeOptions,
        audience: impl Into<String>,
        resolve_grant: impl Fn(&str) -> Result<Option<Value>, String> + Send + Sync + 'static,
        operations: Arc<dyn OperationStore>,
    ) -> Self {
        Executor {
            authorize,
            audience: audience.into(),
            resolve_grant: Arc::new(resolve_grant),
            operations,
            recheck: None,
            recheck_for: RecheckFor::Irreversible,
            class_of: None,
            pending_timeout_ms: OPERATION_PENDING_TIMEOUT_MS,
            clock: None,
        }
    }

    /// An extra re-check before an irreversible operation (for example a step-up approval still stands).
    pub fn with_recheck(mut self, f: impl Fn(&ExecutionHandle) -> Result<(), String> + Send + Sync + 'static) -> Self {
        self.recheck = Some(Arc::new(f));
        self
    }

    pub fn with_recheck_for(mut self, which: RecheckFor) -> Self {
        self.recheck_for = which;
        self
    }

    /// The server's reversibility class for an operation (a tool catalog). Absent: the signed class.
    pub fn with_reversibility_class_of(mut self, f: impl Fn(&Operation) -> Option<String> + Send + Sync + 'static) -> Self {
        self.class_of = Some(Arc::new(f));
        self
    }

    pub fn with_pending_timeout_ms(mut self, ms: i64) -> Self {
        self.pending_timeout_ms = ms;
        self
    }

    pub fn with_clock(mut self, f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Arc::new(f));
        self
    }

    fn now(&self) -> i64 {
        self.clock.as_ref().map_or_else(system_now, |c| c())
    }

    fn recheck_now(&self, h: &ExecutionHandle) -> Result<(), String> {
        let grant_ref = h.pcactn.get("grant_ref").and_then(Value::as_str).unwrap_or("");
        let grant = match (self.resolve_grant)(grant_ref) {
            Ok(Some(g)) => g,
            Ok(None) => return Err("the grant is no longer known".into()),
            Err(_) => return Err("revocation could not be checked".into()),
        };
        match self.authorize.revoked(&h.pcactn, &grant) {
            Ok(false) => {}
            Ok(true) => return Err("the grant has been revoked".into()),
            Err(_) => return Err("revocation could not be checked".into()),
        }
        // a registered plan must still be executable: not revoked, the principal's approval not expired
        if let (Some(plans), Some(root)) = (self.authorize.plans(), h.pcactn.get("plan").and_then(|p| p.get("root")).and_then(Value::as_str)) {
            if plans.get(grant_ref, root).is_some() {
                let node_id = h.pcactn.get("plan").and_then(|p| p.get("node_id")).and_then(Value::as_str).map(str::to_string);
                let ps = plans.check(grant_ref, root, &PlanCheckOptions { node_id, operation: None, now: Some(self.now()) });
                if !ps.executable {
                    return Err(ps.reason.unwrap_or_else(|| format!("plan is {}", ps.state)));
                }
            }
        }
        match &self.recheck {
            Some(extra) => extra(h),
            None => Ok(()),
        }
    }

    /// Authorize `pcactn` for `operation` and, if allowed, run `f` at most once (see the type doc).
    pub fn execute(&self, pcactn: &Value, operation: &Operation, f: impl FnOnce(&ExecutionHandle) -> Result<Value, String>) -> ExecutorOutcome {
        let now = self.now();
        let resolve = |g: &str| (self.resolve_grant)(g);
        let r = self.authorize.run(Some(pcactn), Some(operation), &self.audience, &resolve, Some(now), None, None);
        if r.allow {
            let class = self.class_of.as_ref().and_then(|c| c(operation));
            let recheck = |h: &ExecutionHandle| self.recheck_now(h);
            let clock = || self.now();
            let az = ExecutableAuthorization::from(&r);
            let out = execute_authorized(
                &az,
                f,
                &ExecuteOptions {
                    store: Some(self.operations.as_ref()),
                    operation: Some(operation),
                    recheck: Some(&recheck),
                    recheck_for: self.recheck_for,
                    reversibility_class: class.as_deref(),
                    pending_timeout_ms: Some(self.pending_timeout_ms),
                    now: Some(&clock),
                },
            );
            return ExecutorOutcome::Executed(out);
        }
        if r.status != 403 || r.failed_checks() != ["replay"] {
            return ExecutorOutcome::Denied(Box::new(r));
        }
        // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
        let id = hash_canonical_strict(pcactn).unwrap_or_else(|| hash_canonical(pcactn));
        let want_digest = hash_canonical_strict(&operation.params);
        match self.operations.get(&id) {
            Ok(Some(rec)) if rec.verb == operation.verb && rec.resource == operation.resource && want_digest.as_deref() == Some(rec.params_digest.as_str()) => {
                ExecutorOutcome::Executed(from_record(self.operations.as_ref(), rec, self.now(), self.pending_timeout_ms))
            }
            _ => ExecutorOutcome::Denied(Box::new(r)),
        }
    }
}
