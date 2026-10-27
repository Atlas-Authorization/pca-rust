//! Plan lifecycle: explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the
//! principal's authorization of it.
//!
//! ```text
//!   draft --validate--> validated --commit--> committed --authorize--> authorized
//!     \_____________________\______________________\___________revoke______/--> revoked
//! ```
//!
//! * `draft`: the nodes are recorded; the root is computed from them (never taken from the caller).
//! * `validated`: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the
//!   server's own validator.
//! * `committed`: the root is fixed. A committed plan is NOT executable: it still needs the principal.
//! * `authorized`: the principal approved this root for this grant, optionally until `expires_at`.
//! * `revoked`: terminal; every later action against the root is denied.
//!
//! "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is `authorized`, the
//! approval has not expired, and its stored nodes still hash to the root. [`PlanRegistry::check`] adds the per-action
//! staleness rules a server applies immediately before execution: the node exists and the operation's verb, resource and
//! params still match what the principal approved. Wire formats are unchanged: the registry only feeds `plan` /
//! `plan_authorized` into the authorize context (`AuthorizeInput::plans`).

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::authorize::Operation;
use crate::kv::{AtomicKv, MemoryAtomicKv};
use crate::{hash_canonical_strict, merkle_root, params_digest, plan_leaf};

/// Where a plan is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanState {
    Draft,
    Validated,
    Committed,
    Authorized,
    Revoked,
}

impl PlanState {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanState::Draft => "draft",
            PlanState::Validated => "validated",
            PlanState::Committed => "committed",
            PlanState::Authorized => "authorized",
            PlanState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<PlanState> {
        Some(match s {
            "draft" => PlanState::Draft,
            "validated" => PlanState::Validated,
            "committed" => PlanState::Committed,
            "authorized" => PlanState::Authorized,
            "revoked" => PlanState::Revoked,
            _ => return None,
        })
    }
}

/// The principal's approval of a committed plan.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanApproval {
    /// Who approved (the principal's key or account id, for the record). Required.
    pub by: String,
    /// The approval lapses at this time (epoch ms). `None`: until revoked. A non-finite value is refused.
    pub expires_at: Option<f64>,
}

impl PlanApproval {
    /// Lenient construction from `{by, expiresAt?}`: `None` for anything that is not an object; a missing or non-string `by`
    /// is empty (refused at `authorize`), a present non-numeric `expiresAt` is NaN (refused).
    pub fn from_json(v: &Value) -> Option<PlanApproval> {
        let o = v.as_object()?;
        Some(PlanApproval {
            by: o.get("by").and_then(Value::as_str).unwrap_or("").to_string(),
            expires_at: o.get("expiresAt").map(|x| x.as_f64().unwrap_or(f64::NAN)),
        })
    }
}

/// A number as a JSON integer when it is one.
fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

/// One plan's stored record.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanRecord {
    pub grant_ref: String,
    /// Merkle root of `nodes` (computed by the registry).
    pub root: String,
    /// The plan nodes exactly as drafted (`{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`).
    pub nodes: Vec<Value>,
    pub state: PlanState,
    pub created_at: i64,
    pub validated_at: Option<i64>,
    pub committed_at: Option<i64>,
    pub authorized_at: Option<i64>,
    pub approval: Option<PlanApproval>,
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
}

impl PlanRecord {
    /// The record as the shared vectors write it (camelCase, absent members omitted).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("grantRef".into(), json!(self.grant_ref));
        m.insert("root".into(), json!(self.root));
        m.insert("nodes".into(), Value::Array(self.nodes.clone()));
        m.insert("state".into(), json!(self.state.as_str()));
        m.insert("createdAt".into(), json!(self.created_at));
        for (k, t) in [("validatedAt", self.validated_at), ("committedAt", self.committed_at), ("authorizedAt", self.authorized_at)] {
            if let Some(t) = t {
                m.insert(k.into(), json!(t));
            }
        }
        if let Some(a) = &self.approval {
            let mut o = Map::new();
            o.insert("by".into(), json!(a.by));
            if let Some(e) = a.expires_at {
                o.insert("expiresAt".into(), num(e));
            }
            m.insert("approval".into(), Value::Object(o));
        }
        if let Some(t) = self.revoked_at {
            m.insert("revokedAt".into(), json!(t));
        }
        if let Some(r) = &self.revoked_reason {
            m.insert("revokedReason".into(), json!(r));
        }
        Value::Object(m)
    }

    /// `None` when the document is not a plan record.
    pub fn from_json(v: &Value) -> Option<PlanRecord> {
        let t = |k: &str| v.get(k).and_then(Value::as_i64);
        Some(PlanRecord {
            grant_ref: v.get("grantRef")?.as_str()?.to_string(),
            root: v.get("root")?.as_str()?.to_string(),
            nodes: v.get("nodes")?.as_array()?.clone(),
            state: PlanState::parse(v.get("state")?.as_str()?)?,
            created_at: t("createdAt")?,
            validated_at: t("validatedAt"),
            committed_at: t("committedAt"),
            authorized_at: t("authorizedAt"),
            approval: v.get("approval").and_then(PlanApproval::from_json),
            revoked_at: t("revokedAt"),
            revoked_reason: v.get("revokedReason").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// The result of a lifecycle transition.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanTransition {
    Ok(PlanRecord),
    /// `state` is the plan's state when the transition was refused (`"unknown"` for an unknown plan).
    Refused { state: String, reason: String },
}

impl PlanTransition {
    pub fn is_ok(&self) -> bool {
        matches!(self, PlanTransition::Ok(_))
    }

    pub fn to_json(&self) -> Value {
        match self {
            PlanTransition::Ok(r) => json!({"ok": true, "record": r.to_json()}),
            PlanTransition::Refused { state, reason } => json!({"ok": false, "state": state, "reason": reason}),
        }
    }
}

/// A plan's state at the moment of use.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanStatus {
    /// The state name, or `"unknown"`.
    pub state: String,
    pub executable: bool,
    /// Why it is not executable.
    pub reason: Option<String>,
    pub record: Option<PlanRecord>,
}

impl PlanStatus {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("state".into(), json!(self.state));
        m.insert("executable".into(), json!(self.executable));
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        if let Some(r) = &self.record {
            m.insert("record".into(), r.to_json());
        }
        Value::Object(m)
    }
}

/// The verifier context for an action against a root.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanContext {
    pub plan: Vec<Value>,
    pub plan_authorized: bool,
    pub status: PlanStatus,
}

impl PlanContext {
    pub fn to_json(&self) -> Value {
        json!({"plan": self.plan, "planAuthorized": self.plan_authorized, "status": self.status.to_json()})
    }
}

/// Options of [`PlanRegistry::check`].
#[derive(Debug, Clone, Default)]
pub struct PlanCheckOptions {
    /// The plan node the action executes (the PCActn's `plan.node_id`).
    pub node_id: Option<String>,
    /// The operation about to execute: must match the node (verb, resource, params digest).
    pub operation: Option<Operation>,
    /// The current time (epoch ms). Default the registry clock.
    pub now: Option<i64>,
}

type ClockFn = dyn Fn() -> i64 + Send + Sync;
type ValidatorFn = dyn Fn(&PlanRecord) -> Result<(), String> + Send + Sync;

/// The plan registry. Cheap to share behind an `Arc`; every transition is one atomic [`AtomicKv::update`].
pub struct PlanRegistry {
    kv: Arc<dyn AtomicKv>,
    prefix: String,
    now: Arc<ClockFn>,
    validator: Option<Arc<ValidatorFn>>,
}

impl Default for PlanRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The Merkle leaf of one plan node (`planNodeLeaf`): the node's own fields plus the digest of its pre / post conditions.
fn node_leaf(n: &Value) -> Result<Value, String> {
    let cond = hash_canonical_strict(&json!({"pre": n.get("pre").cloned().unwrap_or(Value::Null), "post": n.get("post").cloned().unwrap_or(Value::Null)}))
        .ok_or("the node conditions are outside the strict JSON profile")?;
    plan_leaf(n.get("id"), n.as_object(), &cond).ok_or_else(|| "a plan node needs an id".to_string())
}

/// The Merkle root of a node list; equal to the TypeScript `merkleRoot(nodes.map(planNodeLeaf))`.
pub fn plan_root_of(nodes: &[Value]) -> Result<String, String> {
    let leaves: Vec<Value> = nodes.iter().map(node_leaf).collect::<Result<_, _>>()?;
    merkle_root(&leaves).map_err(|e| format!("merkleRoot: {e}"))
}

/// Structural validity of a plan's nodes (the reason, or `None` when valid).
fn structural_problem(nodes: &[Value]) -> Option<String> {
    if nodes.is_empty() {
        return Some("a plan needs at least one node".into());
    }
    let mut ids = BTreeSet::new();
    for n in nodes {
        let id = match n.get("id").and_then(Value::as_str) {
            Some(i) if !i.is_empty() => i,
            _ => return Some("every node needs an id".into()),
        };
        if !ids.insert(id) {
            return Some(format!("duplicate node id '{id}'"));
        }
        let ok = |k: &str| n.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !ok("verb") || !ok("resource") {
            return Some(format!("node '{id}' needs a verb and a resource"));
        }
        if let Some(c) = n.get("reversibility_class") {
            if !matches!(c.as_str(), Some("reversible" | "rate_limited" | "costly" | "irreversible")) {
                return Some(format!("node '{id}' has an unknown reversibility class '{}'", crate::intent_v2::js_value_string(c)));
            }
        }
    }
    None
}

fn refused(state: &str, reason: String) -> PlanTransition {
    PlanTransition::Refused { state: state.to_string(), reason }
}

fn unknown(root: &str) -> String {
    format!("plan {root} is unknown for this grant")
}

impl PlanRegistry {
    /// A registry in memory (one process). Use [`with_kv`](Self::with_kv) with a durable store for several workers.
    pub fn new() -> Self {
        PlanRegistry { kv: Arc::new(MemoryAtomicKv::new()), prefix: "pca-plan:".to_string(), now: Arc::new(system_now), validator: None }
    }

    /// Where the records live.
    pub fn with_kv(mut self, kv: Arc<dyn AtomicKv>) -> Self {
        self.kv = kv;
        self
    }

    /// Key prefix in the store (default `pca-plan:`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Clock (epoch ms). Default the system clock.
    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    /// The server's validation, run by [`validate`](Self::validate) after the structural checks (for example each node is
    /// within the grant's predicates). `Err(reason)` refuses; a panic refuses too (fail closed).
    pub fn with_validator(mut self, v: impl Fn(&PlanRecord) -> Result<(), String> + Send + Sync + 'static) -> Self {
        self.validator = Some(Arc::new(v));
        self
    }

    fn key(&self, grant_ref: &str, root: &str) -> String {
        let mut enc = String::new();
        for b in grant_ref.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                enc.push(b as char);
            } else {
                enc.push_str(&format!("%{b:02X}"));
            }
        }
        format!("{}{enc}:{root}", self.prefix)
    }

    fn load(&self, grant_ref: &str, root: &str) -> Result<Option<PlanRecord>, String> {
        match self.kv.get(&self.key(grant_ref, root)).map_err(|e| e.0)? {
            None => Ok(None),
            Some(v) => Ok(PlanRecord::from_json(&v)),
        }
    }

    /// The stored record (`None` for an unknown plan, or when the store cannot answer).
    pub fn get(&self, grant_ref: &str, root: &str) -> Option<PlanRecord> {
        self.load(grant_ref, root).ok().flatten()
    }

    /// Atomically move `from` -> next (computed from the current record).
    fn step(&self, grant_ref: &str, root: &str, from: &[PlanState], verb: &str, next: impl Fn(&PlanRecord) -> PlanRecord) -> PlanTransition {
        let mut out = refused("unknown", unknown(root));
        let r = self.kv.update(&self.key(grant_ref, root), &mut |prev| {
            let rec = prev.and_then(PlanRecord::from_json)?;
            if !from.contains(&rec.state) {
                out = refused(rec.state.as_str(), format!("plan {root} is {}: cannot {verb}", rec.state.as_str()));
                return None;
            }
            let n = next(&rec);
            let doc = n.to_json();
            out = PlanTransition::Ok(n);
            Some(doc)
        });
        match r {
            Ok(_) => out,
            Err(e) => refused("unknown", format!("plan store: {} (fail closed)", e.0)),
        }
    }

    /// Record a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused.
    pub fn draft(&self, grant_ref: &str, nodes: &[Value]) -> PlanTransition {
        if grant_ref.is_empty() {
            return refused("unknown", "a plan needs a grant".into());
        }
        // structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
        let root = match plan_root_of(nodes) {
            Ok(r) => r,
            Err(e) => return refused("unknown", format!("the plan cannot be committed: {e}")),
        };
        let rec = PlanRecord {
            grant_ref: grant_ref.to_string(),
            root: root.clone(),
            nodes: nodes.to_vec(),
            state: PlanState::Draft,
            created_at: (self.now)(),
            validated_at: None,
            committed_at: None,
            authorized_at: None,
            approval: None,
            revoked_at: None,
            revoked_reason: None,
        };
        let doc = rec.to_json();
        let mut out = PlanTransition::Ok(rec);
        let r = self.kv.update(&self.key(grant_ref, &root), &mut |prev| match prev.and_then(PlanRecord::from_json) {
            Some(p) => {
                out = refused(p.state.as_str(), format!("plan {root} already exists ({})", p.state.as_str()));
                None
            }
            None => Some(doc.clone()),
        });
        match r {
            Ok(_) => out,
            Err(e) => refused("unknown", format!("plan store: {} (fail closed)", e.0)),
        }
    }

    /// draft -> validated (structural checks, then the server's validator).
    pub fn validate(&self, grant_ref: &str, root: &str) -> PlanTransition {
        let cur = match self.load(grant_ref, root) {
            Ok(Some(c)) => c,
            Ok(None) => return refused("unknown", unknown(root)),
            Err(e) => return refused("unknown", format!("plan store: {e} (fail closed)")),
        };
        if cur.state != PlanState::Draft {
            return refused(cur.state.as_str(), format!("plan {root} is {}: cannot validate", cur.state.as_str()));
        }
        let problem = structural_problem(&cur.nodes).or_else(|| (plan_root_of(&cur.nodes).ok().as_deref() != Some(root)).then(|| "the stored nodes no longer hash to the root".to_string()));
        if let Some(p) = problem {
            return refused(cur.state.as_str(), format!("plan {root} is invalid: {p}"));
        }
        if let Some(v) = &self.validator {
            let verdict = match catch_unwind(AssertUnwindSafe(|| v(&cur))) {
                Ok(r) => r,
                Err(e) => Err(format!("validator error (fail closed): {}", panic_message(e))),
            };
            if let Err(why) = verdict {
                return refused(cur.state.as_str(), format!("plan {root} is invalid: {why}"));
            }
        }
        let at = (self.now)();
        self.step(grant_ref, root, &[PlanState::Draft], "validate", |r| PlanRecord { state: PlanState::Validated, validated_at: Some(at), ..r.clone() })
    }

    /// validated -> committed: the root is fixed; it still needs the principal's authorization to execute.
    pub fn commit(&self, grant_ref: &str, root: &str) -> PlanTransition {
        let at = (self.now)();
        self.step(grant_ref, root, &[PlanState::Validated], "commit", |r| PlanRecord { state: PlanState::Committed, committed_at: Some(at), ..r.clone() })
    }

    /// committed -> authorized: the principal's approval (call it only after verifying the principal's consent).
    pub fn authorize(&self, grant_ref: &str, root: &str, approval: Option<&PlanApproval>) -> PlanTransition {
        let state_now = || self.get(grant_ref, root).map_or("unknown", |r| r.state.as_str()).to_string();
        let Some(a) = approval.filter(|a| !a.by.is_empty()) else {
            return PlanTransition::Refused { state: state_now(), reason: "an approval names who approved (`by`)".into() };
        };
        if a.expires_at.is_some_and(|e| !e.is_finite()) {
            return PlanTransition::Refused { state: state_now(), reason: "approval.expiresAt must be a time (epoch ms)".into() };
        }
        let at = (self.now)();
        self.step(grant_ref, root, &[PlanState::Committed], "authorize", |r| PlanRecord {
            state: PlanState::Authorized,
            authorized_at: Some(at),
            approval: Some(a.clone()),
            ..r.clone()
        })
    }

    /// Any state except revoked -> revoked (terminal).
    pub fn revoke(&self, grant_ref: &str, root: &str, reason: &str) -> PlanTransition {
        let at = (self.now)();
        self.step(grant_ref, root, &[PlanState::Draft, PlanState::Validated, PlanState::Committed, PlanState::Authorized], "revoke", |r| PlanRecord {
            state: PlanState::Revoked,
            revoked_at: Some(at),
            revoked_reason: Some(reason.to_string()),
            ..r.clone()
        })
    }

    /// The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root).
    pub fn status(&self, grant_ref: &str, root: &str, now: Option<i64>) -> PlanStatus {
        let now = now.unwrap_or_else(|| (self.now)());
        let record = match self.load(grant_ref, root) {
            Ok(Some(r)) => r,
            Ok(None) => return PlanStatus { state: "unknown".into(), executable: false, reason: Some(unknown(root)), record: None },
            Err(e) => return PlanStatus { state: "unknown".into(), executable: false, reason: Some(format!("plan store: {e} (fail closed)")), record: None },
        };
        let st = record.state.as_str().to_string();
        let no = |reason: String, record: PlanRecord| PlanStatus { state: st.clone(), executable: false, reason: Some(reason), record: Some(record) };
        if record.state != PlanState::Authorized {
            let why = match record.state {
                PlanState::Committed => "committed but not authorized by the principal".to_string(),
                PlanState::Revoked => format!("revoked ({})", record.revoked_reason.as_deref().unwrap_or("no reason given")),
                _ => format!("{st}, not authorized"),
            };
            return no(format!("plan {root} is {why}"), record);
        }
        if let Some(e) = record.approval.as_ref().and_then(|a| a.expires_at) {
            if !((now as f64) < e) {
                return no(format!("plan {root}: the principal's approval expired at {}", crate::staleness::js_num(e)), record);
            }
        }
        if plan_root_of(&record.nodes).ok().as_deref() != Some(root) {
            return no(format!("plan {root}: the stored nodes no longer hash to the root"), record);
        }
        PlanStatus { state: st, executable: true, reason: None, record: Some(record) }
    }

    /// [`status`](Self::status) plus the per-action staleness rules (node exists, the operation matches it). Run it
    /// immediately before execution.
    pub fn check(&self, grant_ref: &str, root: &str, o: &PlanCheckOptions) -> PlanStatus {
        let s = self.status(grant_ref, root, Some(o.now.unwrap_or_else(|| (self.now)())));
        let Some(record) = s.record.clone().filter(|_| s.executable) else { return s };
        if o.node_id.is_none() && o.operation.is_none() {
            return s;
        }
        let deny = |reason: String| PlanStatus { executable: false, reason: Some(reason), ..s.clone() };
        let node = o.node_id.as_deref().and_then(|id| record.nodes.iter().find(|n| n.get("id").and_then(Value::as_str) == Some(id)));
        if let (Some(id), None) = (o.node_id.as_deref(), node) {
            return deny(format!("plan {root} has no node '{id}'"));
        }
        if let Some(op) = &o.operation {
            let digest = match op.params {
                Value::Null => params_digest(None),
                ref p if hash_canonical_strict(p).is_some() => params_digest(Some(p)),
                _ => return deny(format!("plan {root}: the operation's params cannot be hashed")),
            };
            let empty = params_digest(None);
            let same = |n: &Value| {
                n.get("verb").and_then(Value::as_str) == Some(op.verb.as_str())
                    && n.get("resource").and_then(Value::as_str) == Some(op.resource.as_str())
                    && n.get("params_digest").and_then(Value::as_str).unwrap_or(&empty) == digest
            };
            let ok = match node {
                Some(n) => same(n),
                None => record.nodes.iter().any(same),
            };
            if !ok {
                return deny(format!("plan {root}: the operation ({} on {} with these params) is not what the principal approved", op.verb, op.resource));
            }
        }
        s
    }

    /// True only when the plan is executable now (for `isPlanAuthorized`-style hooks).
    pub fn is_plan_authorized(&self, grant_ref: &str, plan_root: &str) -> bool {
        catch_unwind(AssertUnwindSafe(|| self.status(grant_ref, plan_root, None).executable)).unwrap_or(false)
    }

    /// The verifier context for an action against `root`: the stored plan, and `plan_authorized` = executable. `None`:
    /// unknown root.
    pub fn context(&self, grant_ref: &str, root: &str, now: Option<i64>) -> Option<PlanContext> {
        let s = self.status(grant_ref, root, now);
        let record = s.record.as_ref()?;
        Some(PlanContext { plan: record.nodes.clone(), plan_authorized: s.executable, status: s })
    }
}

fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
    match e.downcast::<String>() {
        Ok(s) => *s,
        Err(e) => e.downcast::<&str>().map(|s| s.to_string()).unwrap_or_else(|_| "unknown".to_string()),
    }
}
