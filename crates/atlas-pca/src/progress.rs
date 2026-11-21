//! Proof of progress toward a committed goal (port of `progress.ts`).
//!
//! A goal (objective, potential id, embedder id, metric, epsilon, exploration budget) is hashed into a commitment. Each step is a
//! hash-chained body binding the goal commitment, the action digest, the before and after state digests, the sequence number and the
//! previous step; the verifier recomputes the integer potential from the committed id and the carried states (nothing the prover says
//! about potentials is trusted) and the mode: `progress` (`after <= before - epsilon`, or the goal is reached) or `exploration`, whose
//! shortfall is charged to a bounded budget. A step can be signed by the acting holder (Ed25519, domain separated), the post-state can
//! carry a state source's signed attestation (the step commits to it through its evidence digest), and the trajectory head can be
//! anchored in the transparency ledger.
//!
//! JSON-valued: goals, states and steps are `serde_json::Value`s in the reference's member names; results are `{ok, ...}` objects. Every
//! digest is the STRICT canonical hash (the wire form). A potential is a pure function `fn(objective, state) -> f64` that must return a
//! non-negative safe integer (anything else is the denial `bad-potential`). Sources are synchronous.
//!
//! A state attestation by a post-quantum or hybrid suite verifies only under the PQ key PINNED for the source; the reference's legacy
//! unbound opt-out (`allowUnboundPq`) is deliberately not offered.
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, LazyLock};

use serde_json::{json, Map, Number, Value};

use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use crate::intent_v2::{js_number_string, js_value_string};
use crate::ledger_store::TransparencyLedger;

/// Wire / commitment format version of goals, steps and signed proofs.
pub const PROGRESS_VERSION: u32 = 2;
/// Domain separator of the Ed25519 signature over a progress step.
pub const PROGRESS_SIG_DOMAIN: &str = "atlas-pca/progress-step/v2";
/// Domain-separated tag of a trajectory-head anchor leaf.
pub const TRAJECTORY_ANCHOR_DOMAIN: &str = "atlas-pca/trajectory-anchor/v1";
/// Domain separator of a source's signed state attestation.
pub const STATE_ATTESTATION_DOMAIN: &str = "atlas-pca/progress-state-attestation/v1\0";

const GENESIS: &str = "genesis";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

// ---- JavaScript number and value semantics ---------------------------------------------------------------------------------------

fn is_safe(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE
}

/// `Number.isSafeInteger` of a JSON value (a JSON number only).
fn safe_int(v: Option<&Value>) -> Option<f64> {
    v?.as_number()?.as_f64().filter(|f| is_safe(*f))
}

fn assert_int(v: Option<&Value>, what: &str) -> Result<f64, String> {
    safe_int(v).ok_or_else(|| format!("{what}: safe integer required"))
}

fn assert_f(n: f64, what: &str) -> Result<f64, String> {
    if is_safe(n) {
        Ok(n)
    } else {
        Err(format!("{what}: safe integer required"))
    }
}

/// `o?.k`: an absent or non-object receiver has no member.
fn prop<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object()?.get(k)
}

fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

/// A JSON number for a safe integer (an integer member prints without a fraction); anything else is the nearest double.
fn jnum(f: f64) -> Value {
    if is_safe(f) {
        json!(f as i64)
    } else {
        Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

/// A JavaScript `Set`'s notion of identity: values of different types never collide, `-0` is `0`, objects are distinct.
fn set_key(v: Option<&Value>) -> String {
    match v {
        None => "u".into(),
        Some(Value::Null) => "z".into(),
        Some(Value::Bool(b)) => format!("b{b}"),
        Some(Value::String(s)) => format!("s{s}"),
        Some(Value::Number(n)) => format!("n{}", js_number_string(n.as_f64().unwrap_or(f64::NAN))),
        Some(o) => format!("o{:p}", o as *const Value),
    }
}

/// base64url(sha256(strict canonical(v))).
fn hash_strict(v: &Value) -> Result<String, String> {
    let c = crate::canonicalize_strict(v)?;
    Ok(crate::b64_encode(&crate::sha(c.as_bytes())))
}

/// A deep, canonical, detached copy (the lenient canonical form: `-0` becomes `0`).
fn snapshot(v: &Value) -> Result<Value, String> {
    serde_json::from_str(&crate::canonicalize(v)).map_err(|e| e.to_string())
}

fn fail(reason: &str) -> Value {
    json!({"ok": false, "reason": reason})
}

/// A denial with its code (`unknown-potential`, `embedder-mismatch`, `bad-potential`).
struct PErr {
    code: &'static str,
    msg: String,
}

fn bad(msg: String) -> PErr {
    PErr {
        code: "bad-potential",
        msg,
    }
}

// ---- potentials and the registry --------------------------------------------------------------------------------------------------

/// A potential maps (objective, state) to a non-negative safe integer, the distance to the goal. It must be pure.
pub type PotentialFn = Arc<dyn Fn(&Value, &Value) -> Result<f64, String> + Send + Sync>;

/// A registered potential: the function and the embedder id it is bound to (committed in the goal).
#[derive(Clone)]
pub struct PotentialSpec {
    pub f: PotentialFn,
    pub embedder: String,
}

/// Verifier-held registry of version-pinned potentials: ids cannot be shadowed once registered, and the registry can be frozen. An id
/// that is not registered fails closed.
#[derive(Clone, Default)]
pub struct PotentialRegistry {
    m: HashMap<String, PotentialSpec>,
    frozen: bool,
}

impl PotentialRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `f` under `id` (1..128 UTF-16 units; a re-registration is refused).
    pub fn register(&mut self, id: &str, f: PotentialFn, embedder: &str) -> Result<&mut Self, String> {
        if self.frozen {
            return Err("registry is frozen".into());
        }
        if !(1..=128).contains(&units(id)) {
            return Err("potential id: 1..128 chars".into());
        }
        if self.m.contains_key(id) {
            return Err(format!("potential {id} already registered"));
        }
        self.m.insert(
            id.to_string(),
            PotentialSpec {
                f,
                embedder: embedder.to_string(),
            },
        );
        Ok(self)
    }

    /// [`register`](Self::register) for values read from JSON: a non-string id or embedder is refused (an absent embedder is `""`).
    pub fn register_json(&mut self, id: &Value, f: PotentialFn, embedder: Option<&Value>) -> Result<&mut Self, String> {
        if self.frozen {
            return Err("registry is frozen".into());
        }
        let Some(id) = id.as_str() else {
            return Err("potential id: 1..128 chars".into());
        };
        if !(1..=128).contains(&units(id)) {
            return Err("potential id: 1..128 chars".into());
        }
        let embedder = match embedder {
            None => "",
            Some(Value::String(s)) => s.as_str(),
            Some(_) => return Err("embedder must be a string".into()),
        };
        self.register(id, f, embedder)
    }

    /// Resolve a committed id, or `None` (callers must treat that as a denial).
    pub fn get(&self, id: &str) -> Option<&PotentialSpec> {
        self.m.get(id)
    }

    pub fn has(&self, id: &str) -> bool {
        self.m.contains_key(id)
    }

    /// Registered ids, sorted by UTF-16 code unit (deterministic).
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.m.keys().cloned().collect();
        v.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        v
    }

    /// Forbid further registration.
    pub fn freeze(&mut self) -> &mut Self {
        self.frozen = true;
        self
    }

    /// Build from `(id, function, embedder)` records (an absent embedder is `""`).
    pub fn from_record(rec: &[(&str, PotentialFn, Option<&str>)]) -> Result<Self, String> {
        let mut r = Self::new();
        for (id, f, e) in rec {
            r.register(id, f.clone(), e.unwrap_or(""))?;
        }
        Ok(r)
    }

    /// A fresh, mutable registry holding the three built-in potentials.
    pub fn defaults() -> Self {
        let mut r = Self::new();
        let list: [(&str, PotentialFn); 3] = [
            ("l1-feature-v1", Arc::new(l1_feature_potential)),
            ("dag-remaining-v1", Arc::new(dag_remaining_potential)),
            ("dag-weighted-v1", Arc::new(dag_weighted_potential)),
        ];
        for (id, f) in list {
            r.m.insert(
                id.to_string(),
                PotentialSpec {
                    f,
                    embedder: String::new(),
                },
            );
        }
        r
    }
}

/// The frozen registry of the built-in potentials (used when none is supplied).
pub static DEFAULT_POTENTIALS: LazyLock<PotentialRegistry> = LazyLock::new(|| {
    let mut r = PotentialRegistry::defaults();
    r.freeze();
    r
});

/// Built-in potential 1: L1 distance in a committed feature space. Objective `{target: int[]}`, state `{x: int[]}`.
pub fn l1_feature_potential(objective: &Value, state: &Value) -> Result<f64, String> {
    let t = prop(objective, "target").and_then(Value::as_array);
    let x = prop(state, "x").and_then(Value::as_array);
    let (Some(t), Some(x)) = (t, x) else {
        return Err("l1-feature-v1: bad shape".into());
    };
    if t.len() != x.len() {
        return Err("l1-feature-v1: bad shape".into());
    }
    let mut d = 0.0;
    for (a, b) in t.iter().zip(x) {
        let a = assert_int(Some(a), "target")?;
        let b = assert_int(Some(b), "x")?;
        d += (a - b).abs();
        assert_f(d, "distance")?;
    }
    Ok(d)
}

/// Built-in potential 2: the remaining cost of a task set. Objective `{tasks: [{id, cost}]}`, state `{done: string[]}`.
pub fn dag_remaining_potential(objective: &Value, state: &Value) -> Result<f64, String> {
    let tasks = prop(objective, "tasks").and_then(Value::as_array);
    let done = prop(state, "done").and_then(Value::as_array);
    let (Some(tasks), Some(done)) = (tasks, done) else {
        return Err("dag-remaining-v1: bad shape".into());
    };
    let mut ids = HashSet::new();
    for t in tasks {
        if t.is_null() {
            return Err("Cannot read properties of null (reading 'id')".into());
        }
        ids.insert(set_key(prop(t, "id")));
    }
    if ids.len() != tasks.len() {
        return Err("dag-remaining-v1: duplicate task id".into());
    }
    let mut done_set = HashSet::new();
    for d in done {
        let k = set_key(Some(d));
        if done_set.contains(&k) {
            continue;
        }
        if !ids.contains(&k) {
            return Err(format!("dag-remaining-v1: unknown task {}", js_value_string(d)));
        }
        done_set.insert(k);
    }
    let mut rem = 0.0;
    for t in tasks {
        let cost = assert_int(prop(t, "cost"), "cost")?;
        if cost < 0.0 {
            return Err("negative cost".into());
        }
        if !done_set.contains(&set_key(prop(t, "id"))) {
            rem += cost;
        }
        assert_f(rem, "remaining")?;
    }
    Ok(rem)
}

/// Built-in potential 3: the weighted-DAG remaining cost with dependency integrity. Objective `{tasks: [{id, cost, deps?}]}` (ids unique,
/// dependencies known, the graph acyclic), state `{done: string[]}` (unique ids, dependency-closed: a task is done only if all its
/// dependencies are).
pub fn dag_weighted_potential(objective: &Value, state: &Value) -> Result<f64, String> {
    let tasks = prop(objective, "tasks").and_then(Value::as_array);
    let done = prop(state, "done").and_then(Value::as_array);
    let (Some(tasks), Some(done)) = (tasks, done) else {
        return Err("dag-weighted-v1: bad shape".into());
    };
    // (id, cost, deps) in insertion order
    let mut by_id: Vec<(String, f64, Vec<String>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for t in tasks {
        let Some(o) = t.as_object() else {
            return Err("dag-weighted-v1: bad task".into());
        };
        let Some(id) = o.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            return Err("dag-weighted-v1: bad task".into());
        };
        if index.contains_key(id) {
            return Err("dag-weighted-v1: duplicate task id".into());
        }
        let cost = assert_int(o.get("cost"), "cost")?;
        if cost < 0.0 {
            return Err("negative cost".into());
        }
        let deps: Vec<String> = match o.get("deps") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => {
                let mut v = Vec::new();
                for d in a {
                    match d.as_str() {
                        Some(s) => v.push(s.to_string()),
                        None => return Err("dag-weighted-v1: bad deps".into()),
                    }
                }
                v
            }
            Some(_) => return Err("dag-weighted-v1: bad deps".into()),
        };
        index.insert(id.to_string(), by_id.len());
        by_id.push((id.to_string(), cost, deps));
    }
    // dependencies must exist, and the graph must be acyclic (Kahn)
    let mut indeg: Vec<usize> = vec![0; by_id.len()];
    let mut rev: Vec<Vec<usize>> = vec![Vec::new(); by_id.len()];
    for (i, (id, _, deps)) in by_id.iter().enumerate() {
        let mut seen = HashSet::new();
        let uniq: Vec<&String> = deps.iter().filter(|d| seen.insert(d.as_str())).collect();
        indeg[i] = uniq.len();
        for d in uniq {
            match index.get(d.as_str()) {
                Some(&j) if d != id => rev[j].push(i),
                _ => return Err(format!("dag-weighted-v1: bad dependency {d}")),
            }
        }
    }
    let mut q: Vec<usize> = (0..by_id.len()).filter(|&i| indeg[i] == 0).collect();
    let mut seen = 0usize;
    while let Some(i) = q.pop() {
        seen += 1;
        for &n in &rev[i] {
            indeg[n] -= 1;
            if indeg[n] == 0 {
                q.push(n);
            }
        }
    }
    if seen != by_id.len() {
        return Err("dag-weighted-v1: cycle".into());
    }
    let mut done_set: Vec<usize> = Vec::new();
    let mut in_done = HashSet::new();
    for d in done {
        let Some(&i) = d.as_str().and_then(|s| index.get(s)) else {
            return Err(format!("dag-weighted-v1: unknown task {}", js_value_string(d)));
        };
        if !in_done.insert(i) {
            return Err("dag-weighted-v1: duplicate done".into());
        }
        done_set.push(i);
    }
    for &i in &done_set {
        for dep in &by_id[i].2 {
            if !in_done.contains(&index[dep.as_str()]) {
                return Err(format!("dag-weighted-v1: {} done before dependency {dep}", by_id[i].0));
            }
        }
    }
    let mut rem = 0.0;
    for (i, (_, cost, _)) in by_id.iter().enumerate() {
        if !in_done.contains(&i) {
            rem += cost;
        }
        assert_f(rem, "remaining")?;
    }
    Ok(rem)
}

// ---- goal commitment --------------------------------------------------------------------------------------------------------------

fn validate_goal(goal: &Value) -> Result<(), String> {
    let Some(o) = goal.as_object() else {
        return Err("goal must be an object".into());
    };
    let epsilon = assert_int(o.get("epsilon"), "epsilon")?;
    let budget = assert_int(o.get("explorationBudget"), "explorationBudget")?;
    if epsilon < 1.0 {
        return Err("epsilon must be >= 1".into());
    }
    if budget < 0.0 {
        return Err("explorationBudget must be >= 0".into());
    }
    if !o.get("potential").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err("potential id required".into());
    }
    if !o.get("metric").is_some_and(Value::is_string) {
        return Err("metric must be a string".into());
    }
    if o.get("embedder").is_some_and(|e| !e.is_string()) {
        return Err("embedder must be a string".into());
    }
    Ok(())
}

/// The commitment hash of a goal: binds the objective, potential id, embedder (an absent one is `""`), metric, epsilon and budget.
pub fn goal_digest(goal: &Value) -> Result<String, String> {
    validate_goal(goal)?;
    let o = goal.as_object().ok_or("goal must be an object")?;
    let objective = o.get("objective").ok_or("canonicalize: unsupported type undefined")?;
    hash_strict(&json!({
        "t": "pca-goal",
        "v": PROGRESS_VERSION,
        "objective": objective,
        "potential": o["potential"],
        "embedder": o.get("embedder").cloned().unwrap_or_else(|| json!("")),
        "metric": o["metric"],
        "epsilon": o["epsilon"],
        "explorationBudget": o["explorationBudget"],
    }))
}

/// Commit a goal: `{goal: <detached canonical copy>, commitment}`.
pub fn commit_goal(goal: &Value) -> Result<Value, String> {
    let c = goal_digest(goal)?;
    Ok(json!({"goal": snapshot(goal)?, "commitment": c}))
}

/// A goal is bound iff it hashes to the commitment the grant carries. Never fails.
pub fn verify_goal_commitment(goal: &Value, commitment: &Value) -> bool {
    goal_digest(goal).is_ok_and(|d| commitment.as_str() == Some(d.as_str()))
}

// ---- steps and the trajectory -----------------------------------------------------------------------------------------------------

fn step_body_digest(body: &Map<String, Value>) -> Result<String, String> {
    let mut m = Map::new();
    m.insert("t".into(), json!("pca-progress-step"));
    m.insert("v".into(), json!(PROGRESS_VERSION));
    for (k, v) in body {
        m.insert(k.clone(), v.clone());
    }
    hash_strict(&Value::Object(m))
}

/// The digest committing to a state (strict profile: a state with `-0`, a long fraction or an unsafe integer has none).
pub fn state_digest(state: &Value) -> Result<String, String> {
    hash_strict(&json!({"t": "pca-state", "state": state}))
}

/// The trajectory head to publish or anchor: the `digest` of the last step (`genesis` for none), as the reference reads the member
/// (an absent member is `null`); a `null` last step is an `Err`.
pub fn trajectory_head(steps: &[Value]) -> Result<Value, String> {
    match steps.last() {
        None => Ok(json!(GENESIS)),
        Some(Value::Null) => Err("Cannot read properties of null (reading 'digest')".into()),
        Some(s) => Ok(prop(s, "digest").cloned().unwrap_or(Value::Null)),
    }
}

/// The digest to place in a PCActn alongside its params digest: the step's `digest` member (`null` when absent), `Err` for a `null` step.
pub fn progress_step_digest(step: &Value) -> Result<Value, String> {
    if step.is_null() {
        return Err("Cannot read properties of null (reading 'digest')".into());
    }
    Ok(prop(step, "digest").cloned().unwrap_or(Value::Null))
}

/// The salted commitment of a trajectory head, the opaque leaf appended to the transparency ledger. `Err` for an empty or non-string
/// salt or head.
pub fn trajectory_anchor_commit(salt: &Value, head: &Value) -> Result<String, String> {
    match (salt.as_str(), head.as_str()) {
        (Some(s), Some(h)) if !s.is_empty() && !h.is_empty() => hash_strict(&json!({"t": TRAJECTORY_ANCHOR_DOMAIN, "salt": s, "head": h})),
        _ => Err("trajectoryAnchorCommit: salt and head must be non-empty strings".into()),
    }
}

/// `true` iff `salt` and `head` reproduce the anchored `commit`. Never fails.
pub fn verify_trajectory_anchor(commit: &Value, salt: &Value, head: &Value) -> bool {
    trajectory_anchor_commit(salt, head).is_ok_and(|c| commit.as_str() == Some(c.as_str()))
}

/// Anchor the current trajectory head into `ledger` as a salted commitment: `{head, salt, commit, index, ledgerHead}`. The salt defaults to
/// 16 random bytes; pass one for deterministic output. Sign `ledgerHead` and pin it: a monitor that demands a consistency proof detects any
/// later rollback that drops this head.
pub fn anchor_trajectory_head(ledger: &mut TransparencyLedger, steps: &[Value], salt: Option<&str>) -> Result<Value, String> {
    let head = trajectory_head(steps)?;
    let salt = match salt {
        Some(s) => s.to_string(),
        None => crate::b64_encode(&crate::agent::rand_bytes::<16>()?),
    };
    let commit = trajectory_anchor_commit(&json!(salt), &head)?;
    let index = ledger.append_commitment(&commit)?["index"].clone();
    Ok(json!({"head": head, "salt": salt, "commit": commit, "index": index, "ledgerHead": ledger.head()}))
}

fn resolve<'r>(goal: &Value, reg: &'r PotentialRegistry) -> Result<&'r PotentialSpec, PErr> {
    let id = prop(goal, "potential").and_then(Value::as_str).unwrap_or("");
    let Some(spec) = reg.get(id) else {
        return Err(PErr {
            code: "unknown-potential",
            msg: format!("unknown potential {id}"),
        });
    };
    if spec.embedder != prop(goal, "embedder").and_then(Value::as_str).unwrap_or("") {
        return Err(PErr {
            code: "embedder-mismatch",
            msg: "embedder mismatch".into(),
        });
    }
    Ok(spec)
}

fn potential_of(goal: &Value, reg: &PotentialRegistry, state: &Value) -> Result<f64, PErr> {
    let spec = resolve(goal, reg)?;
    let objective = prop(goal, "objective").unwrap_or(&Value::Null);
    let p = catch_unwind(AssertUnwindSafe(|| (spec.f)(objective, state))).unwrap_or_else(|_| Err("potential panicked".into()));
    let p = p.and_then(|p| assert_f(p, "potential")).map_err(bad)?;
    if p < 0.0 {
        return Err(bad("potential must be >= 0".into()));
    }
    Ok(p)
}

/// The single source of truth for mode and charge: reaching the goal (after == 0) from a state closer than epsilon still counts as
/// progress; anything else short of `before - epsilon` is exploration, charged the integer shortfall (>= 1).
fn classify(pb: f64, pa: f64, epsilon: f64) -> Result<(&'static str, f64), PErr> {
    let required = pb - epsilon;
    if pa <= required || (pa == 0.0 && pb > 0.0) {
        return Ok(("progress", 0.0));
    }
    let charge = assert_f(pa - required, "charge").map_err(bad)?;
    Ok(("exploration", charge))
}

fn epsilon_of(goal: &Value) -> f64 {
    safe_int(prop(goal, "epsilon")).unwrap_or(f64::NAN)
}

fn budget_of(goal: &Value) -> f64 {
    safe_int(prop(goal, "explorationBudget")).unwrap_or(f64::NAN)
}

/// What a guard is asked about: the transition a step makes.
pub struct Transition<'a> {
    pub seq: f64,
    pub before: &'a Value,
    pub after: &'a Value,
    pub action_digest: &'a str,
}

/// Negative-authority hook (compose a prohibition set here): `true` allows the transition. A panic denies. It runs in the tracker and in
/// the verifier, so a forbidden action cannot be laundered through a good-looking descent.
pub type StepGuard<'a> = &'a dyn Fn(&Transition<'_>) -> bool;

/// Hook letting the verifier check source-specific evidence (receipt, TEE quote, zk) for a step. `true` allows; a panic denies.
pub type StateAttestationVerifier<'a> = &'a dyn Fn(&Value) -> bool;

fn run_guard(g: &dyn Fn(&Transition<'_>) -> bool, t: &Transition<'_>) -> bool {
    catch_unwind(AssertUnwindSafe(|| g(t))).unwrap_or(false)
}

// ---- state sources and attestations -----------------------------------------------------------------------------------------------

/// The trust boundary. A production source observes the REAL effect of an action and attests to it. `observe` takes
/// `{action_digest, goal_commitment, prior_digest}` and returns `{state, state_digest, source, evidence?}`.
pub trait StateSource {
    fn id(&self) -> &str;
    fn observe(&mut self, req: &Value) -> Result<Value, String>;
}

/// In-memory source for tests and demos: the world is a value changed through [`apply`](Self::apply); its evidence is a counter record.
pub struct InMemoryStateSource {
    id: String,
    cur: Value,
    n: u64,
    /// The requests received so far.
    pub requests: Vec<Value>,
}

impl InMemoryStateSource {
    pub fn new(initial: &Value, id: &str) -> Result<Self, String> {
        Ok(Self {
            id: id.to_string(),
            cur: snapshot(initial)?,
            n: 0,
            requests: Vec::new(),
        })
    }

    /// Change the world (what the real action would do).
    pub fn apply(&mut self, next: &Value) -> Result<(), String> {
        self.cur = snapshot(next)?;
        Ok(())
    }
}

impl StateSource for InMemoryStateSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn observe(&mut self, req: &Value) -> Result<Value, String> {
        self.requests.push(req.clone());
        let state = snapshot(&self.cur)?;
        let n = self.n;
        self.n += 1;
        let mut ev = json!({"kind": "in-memory", "n": n});
        for (to, from) in [("prior", "prior_digest"), ("action", "action_digest")] {
            if let Some(v) = prop(req, from) {
                ev[to] = v.clone();
            }
        }
        Ok(json!({"state_digest": state_digest(&state)?, "state": state, "source": self.id, "evidence": ev}))
    }
}

/// A key the attestation lookup is keyed by: `action \0 prior \0 state` as the reference's template string reads them.
fn attestation_key(action: Option<&Value>, prior: Option<&Value>, state: Option<&Value>) -> String {
    let s = |v: Option<&Value>| v.map_or_else(|| "undefined".to_string(), js_value_string);
    format!("{}\0{}\0{}", s(action), s(prior), s(state))
}

/// The signed message of a state attestation: the domain, then the strict canonical statement with the suite fields bound. `None` where
/// the reference throws (a missing statement member, a PQ suite without its key).
fn attestation_message(a: &Value, alg: Option<&Value>, pq_pk: Option<&Value>) -> Option<Vec<u8>> {
    let mut body = Map::new();
    for k in ["source", "goal_commitment", "action_digest", "prior_digest", "state_digest"] {
        body.insert(k.into(), prop(a, k)?.clone());
    }
    if !bind_suite_fields(&mut body, alg, pq_pk).ok()? {
        return None;
    }
    domain_message(STATE_ATTESTATION_DOMAIN, body)
}

/// Verify a state attestation's signature under a TRUSTED source key, bound to its exact statement. A post-quantum or hybrid suite verifies
/// only when `pin["pqPins"][trusted_public_key]` equals the attestation's `pq_pk`; the legacy unbound opt-out is not offered. Never fails.
pub fn verify_state_attestation(att: &Value, trusted_public_key: &Value, pin: Option<&Value>) -> bool {
    let Some(o) = att.as_object() else { return false };
    if !o.get("sig").is_some_and(Value::is_string) || !o.get("source").is_some_and(Value::is_string) {
        return false;
    }
    let Some(trusted) = trusted_public_key.as_str().filter(|k| !k.is_empty()) else {
        return false;
    };
    if suite_of(o.get("alg")).is_err() {
        return false;
    }
    let Some(msg) = attestation_message(att, o.get("alg"), o.get("pq_pk")) else {
        return false;
    };
    let pinned = pin
        .and_then(|p| prop(p, "pqPins"))
        .and_then(|p| prop(p, trusted))
        .filter(|p| p.is_string());
    verify_pinned_suite(
        o.get("alg"),
        trusted,
        o.get("pq_pk"),
        &msg,
        o.get("sig"),
        o.get("pq_sig"),
        pinned.map(|p| (trusted, p)),
    )
    .unwrap_or(false)
}

/// A [`StateSource`] whose observations carry a verifiable SIGNED attestation: for each observation it signs the statement "`state_digest`
/// is the state after `action_digest` applied to `prior_digest`, for this goal, observed by me". Pair it with [`attested_state_verifier`].
pub struct AttestedStateSource<'a> {
    id: String,
    /// The source's base64url Ed25519 public key: register it in the verifier's trusted-key map.
    pub public_key: String,
    ed: KeyPair,
    observe_state: Box<dyn FnMut(&Value) -> Result<Value, String> + 'a>,
    suite: Suite<'a>,
    attestations: Vec<Value>,
}

impl<'a> AttestedStateSource<'a> {
    /// `signer_secret` is the 32-byte Ed25519 seed; `observe_state` reads the real post-action world for a request; `suite` selects the
    /// signature suite (default Ed25519; a PQ or hybrid suite needs its key pair).
    pub fn new(
        id: &str,
        signer_secret: &[u8],
        observe_state: impl FnMut(&Value) -> Result<Value, String> + 'a,
        suite: Option<Suite<'a>>,
    ) -> Result<Self, String> {
        if id.is_empty() {
            return Err("AttestedStateSource: id is required".into());
        }
        let suite = suite.unwrap_or_default();
        if let Some(alg) = suite.alg {
            if suite_of(Some(&json!(alg))).is_err() {
                return Err(format!("AttestedStateSource: unknown signature alg '{alg}'"));
            }
        }
        let seed: [u8; 32] = signer_secret
            .try_into()
            .map_err(|_| format!("private key of length 32 expected, got {}", signer_secret.len()))?;
        let ed = KeyPair::from_seed(&seed);
        Ok(Self {
            id: id.to_string(),
            public_key: ed.public.clone(),
            ed,
            observe_state: Box::new(observe_state),
            suite,
            attestations: Vec::new(),
        })
    }

    /// The signed attestations emitted so far (hand these to [`attested_state_verifier`]).
    pub fn attestations(&self) -> &[Value] {
        &self.attestations
    }
}

impl StateSource for AttestedStateSource<'_> {
    fn id(&self) -> &str {
        &self.id
    }

    fn observe(&mut self, req: &Value) -> Result<Value, String> {
        let state = snapshot(&(self.observe_state)(req)?)?;
        let sd = state_digest(&state)?;
        let mut stmt = Map::new();
        stmt.insert("source".into(), json!(self.id));
        for k in ["goal_commitment", "action_digest", "prior_digest"] {
            stmt.insert(k.into(), prop(req, k).ok_or("canonicalize: unsupported type undefined")?.clone());
        }
        stmt.insert("state_digest".into(), json!(sd));
        let att = sign_artifact(
            STATE_ATTESTATION_DOMAIN,
            &Value::Object(stmt),
            &self.ed,
            &Suite {
                alg: self.suite.alg,
                pq: self.suite.pq,
            },
        )?;
        self.attestations.push(att.clone());
        Ok(json!({"state": state, "state_digest": sd, "source": self.id, "evidence": att}))
    }
}

/// The step-attestation hook over the attestations a source produced. `opts` is `{trustedKeys: {source id: public key}, pqPins?,
/// attestations: [...]}`. For a step it requires: the step's source has a trusted key; an attestation for exactly this transition (action,
/// before to after) names that source; the step's evidence digest is the hash of that attestation as carried; the signature verifies under
/// the trusted key. Combine with `trusted_state_sources` so a self-reported or unknown source is refused before this runs.
pub fn attested_state_verifier(opts: &Value) -> Result<Box<dyn Fn(&Value) -> bool + Send + Sync>, String> {
    let mut by_key: HashMap<String, Value> = HashMap::new();
    let list: &[Value] = match opts.get("attestations") {
        None | Some(Value::Null) | Some(Value::String(_)) => &[],
        Some(Value::Array(a)) => a,
        Some(_) => return Err("opts.attestations is not iterable".into()),
    };
    for att in list {
        let s = |k: &str| prop(att, k).filter(|v| v.is_string());
        if let (Some(a), Some(p), Some(st)) = (s("action_digest"), s("prior_digest"), s("state_digest")) {
            by_key.insert(attestation_key(Some(a), Some(p), Some(st)), att.clone());
        }
    }
    let opts = opts.clone();
    Ok(Box::new(move |step: &Value| {
        let Some(source) = prop(step, "state_source").and_then(Value::as_str) else {
            return false;
        };
        let Some(public) = prop(&opts, "trustedKeys")
            .and_then(|k| prop(k, source))
            .filter(|k| k.as_str().is_some_and(|s| !s.is_empty()))
        else {
            return false; // source not trusted
        };
        let key = attestation_key(prop(step, "action_digest"), prop(step, "before_digest"), prop(step, "after_digest"));
        let Some(att) = by_key.get(&key) else { return false };
        if prop(att, "source").and_then(Value::as_str) != Some(source) {
            return false; // no attestation for this transition
        }
        // the step must commit to exactly this attestation (the same canonical form the tracker hashed)
        let Ok(h) = hash_strict(&json!({"t": "pca-evidence", "e": att})) else {
            return false;
        };
        if prop(step, "evidence_digest").and_then(Value::as_str) != Some(h.as_str()) {
            return false;
        }
        verify_state_attestation(att, public, Some(&opts))
    }))
}

// ---- the tracker ------------------------------------------------------------------------------------------------------------------

/// The prover side: holds the last state, the chain head and the exploration spent. A step that would push `spent` over the budget is
/// REFUSED (no proof is produced, the state does not advance): the step-up or denial mechanism. In-memory: concurrent agents sharing a goal
/// need atomic escrow.
pub struct ProgressTracker<'a> {
    seq: u64,
    head: String,
    spent_total: f64,
    cur: Value,
    cur_digest: String,
    log: Vec<Value>,
    reg: PotentialRegistry,
    guard: Option<Box<dyn Fn(&Transition<'_>) -> bool + 'a>>,
    /// A detached snapshot of the committed goal.
    pub goal: Value,
    pub commitment: String,
}

impl<'a> ProgressTracker<'a> {
    /// `Err` when the goal does not match the commitment, or the initial state has no potential under the goal (unknown id, embedder
    /// mismatch, a bad state).
    pub fn new(
        goal: &Value,
        commitment: &Value,
        initial: &Value,
        registry: Option<&PotentialRegistry>,
        guard: Option<Box<dyn Fn(&Transition<'_>) -> bool + 'a>>,
    ) -> Result<Self, String> {
        if !verify_goal_commitment(goal, commitment) {
            return Err("goal does not match commitment".into());
        }
        let goal = snapshot(goal)?;
        let reg = registry.cloned().unwrap_or_else(|| (*DEFAULT_POTENTIALS).clone());
        let cur = snapshot(initial)?;
        let cur_digest = state_digest(&cur)?;
        potential_of(&goal, &reg, &cur).map_err(|e| e.msg)?; // fail fast: unknown id / embedder / bad initial state
        Ok(Self {
            seq: 0,
            head: GENESIS.into(),
            spent_total: 0.0,
            cur,
            cur_digest,
            log: Vec::new(),
            reg,
            guard,
            goal,
            commitment: commitment.as_str().unwrap_or_default().to_string(),
        })
    }

    /// Total exploration charged so far (always `<=` the budget).
    pub fn spent(&self) -> f64 {
        self.spent_total
    }

    pub fn remaining(&self) -> f64 {
        budget_of(&self.goal) - self.spent_total
    }

    pub fn state(&self) -> &Value {
        &self.cur
    }

    /// The digest of the current state.
    pub fn current_state_digest(&self) -> &str {
        &self.cur_digest
    }

    pub fn reached(&self) -> Result<bool, String> {
        potential_of(&self.goal, &self.reg, &self.cur).map(|p| p == 0.0).map_err(|e| e.msg)
    }

    /// The proofs issued so far.
    pub fn steps(&self) -> Vec<Value> {
        self.log.clone()
    }

    /// Attempt a step to a self-reported `after`: `{ok: true, step, spent, remaining}` or `{ok: false, reason, stepUp}`. Does not advance
    /// on a denial.
    pub fn step(&mut self, after: &Value, action_digest: &Value) -> Value {
        self.advance(after, action_digest, "", "")
    }

    /// Observe the post-action state from a source and step to it. The observation's digest and source id are checked and the source id and
    /// evidence digest are committed into the step. Any failure of the source is `state-source-mismatch`; nothing advances on a denial.
    pub fn step_observed(&mut self, source: &mut dyn StateSource, action_digest: &Value) -> Value {
        let mismatch = || json!({"ok": false, "reason": "state-source-mismatch", "stepUp": false});
        let req = json!({"action_digest": action_digest, "goal_commitment": self.commitment, "prior_digest": self.cur_digest});
        let Ok(obs) = source.observe(&req) else { return mismatch() };
        let id = source.id().to_string();
        if !truthy(&obs) || prop(&obs, "source").and_then(Value::as_str) != Some(id.as_str()) {
            return mismatch();
        }
        let Some(state) = prop(&obs, "state") else { return mismatch() };
        match state_digest(state) {
            Ok(d) if prop(&obs, "state_digest").and_then(Value::as_str) == Some(d.as_str()) => {}
            _ => return mismatch(),
        }
        let evidence = prop(&obs, "evidence").filter(|e| !e.is_null()).cloned().unwrap_or(Value::Null);
        let Ok(evidence_digest) = hash_strict(&json!({"t": "pca-evidence", "e": evidence})) else {
            return mismatch();
        };
        self.advance(state, action_digest, &id, &evidence_digest)
    }

    fn advance(&mut self, after_in: &Value, action_digest: &Value, state_source: &str, evidence_digest: &str) -> Value {
        let denied = |reason: &str, step_up: bool| json!({"ok": false, "reason": reason, "stepUp": step_up});
        let Some(action) = action_digest.as_str().filter(|a| !a.is_empty()) else {
            return denied("malformed", false);
        };
        let prepared: Result<_, PErr> = (|| {
            let after = snapshot(after_in).map_err(bad)?;
            let after_digest = state_digest(&after).map_err(bad)?;
            let pb = potential_of(&self.goal, &self.reg, &self.cur)?;
            let pa = potential_of(&self.goal, &self.reg, &after)?;
            let cls = classify(pb, pa, epsilon_of(&self.goal))?;
            Ok((after, after_digest, pb, pa, cls))
        })();
        let (after, after_digest, pb, pa, (mode, charge)) = match prepared {
            Ok(x) => x,
            Err(e) => return denied(e.code, false),
        };
        if let Some(g) = &self.guard {
            let t = Transition {
                seq: self.seq as f64,
                before: &self.cur,
                after: &after,
                action_digest: action,
            };
            if !run_guard(g.as_ref(), &t) {
                return denied("prohibited", false);
            }
        }
        let next_spent = self.spent_total + charge;
        if !is_safe(next_spent) || next_spent > budget_of(&self.goal) {
            return denied("exploration-exhausted", true);
        }
        let mut body = Map::new();
        body.insert("goal_commitment".into(), json!(self.commitment));
        body.insert("seq".into(), json!(self.seq));
        body.insert("before".into(), self.cur.clone());
        body.insert("after".into(), after.clone());
        body.insert("before_digest".into(), json!(self.cur_digest));
        body.insert("after_digest".into(), json!(after_digest));
        body.insert("action_digest".into(), json!(action));
        body.insert("mode".into(), json!(mode));
        body.insert("potential_before".into(), jnum(pb));
        body.insert("potential_after".into(), jnum(pa));
        body.insert("charge".into(), jnum(charge));
        body.insert("state_source".into(), json!(state_source));
        body.insert("evidence_digest".into(), json!(evidence_digest));
        body.insert("prev".into(), json!(self.head));
        let Ok(digest) = step_body_digest(&body) else {
            return denied("bad-potential", false);
        };
        body.insert("digest".into(), json!(digest));
        let step = Value::Object(body);
        self.log.push(step.clone());
        self.seq += 1;
        self.head = digest;
        self.spent_total = next_spent;
        self.cur = after;
        self.cur_digest = after_digest;
        json!({"ok": true, "step": step, "spent": jnum(self.spent_total), "remaining": jnum(self.remaining())})
    }
}

// ---- verification -----------------------------------------------------------------------------------------------------------------

/// The checks every verification shares.
#[derive(Clone, Copy, Default)]
pub struct Checks<'a> {
    /// The verifier-held registry (the built-in potentials when absent).
    pub registry: Option<&'a PotentialRegistry>,
    /// Negative-authority check re-run by the verifier.
    pub guard: Option<StepGuard<'a>>,
    /// When set, the step's `state_source` must be one of these ids (`""`, self-reported, is refused).
    pub trusted_state_sources: Option<&'a [String]>,
    /// `Some(false)` accepts a self-reported `after` state (the proof then shows only that the CLAIMED states descend, not that the world
    /// reached them). Anything else refuses a step whose `state_source` is `""`.
    pub require_attested_state: Option<bool>,
    /// When set, must return `true` for the step (the evidence check).
    pub attestation: Option<StateAttestationVerifier<'a>>,
}

/// The options of [`verify_progress_step`].
#[derive(Clone, Copy, Default)]
pub struct VerifyStepOptions<'a> {
    pub expected_seq: Option<f64>,
    pub expected_prev: Option<&'a str>,
    /// Require the step to be bound to this action digest.
    pub expected_action_digest: Option<&'a str>,
    /// Require the step to start from / end at this state digest.
    pub expected_before_digest: Option<&'a str>,
    pub expected_after_digest: Option<&'a str>,
    pub checks: Checks<'a>,
}

/// The options of [`verify_trajectory`].
#[derive(Clone, Copy, Default)]
pub struct VerifyTrajectoryOptions<'a> {
    /// Require the first step to start from this state.
    pub initial: Option<&'a Value>,
    /// The same by digest (wins over `initial`).
    pub initial_digest: Option<&'a str>,
    /// Require `step[i].action_digest == expected_action_digests[i]` (and an equal length).
    pub expected_action_digests: Option<&'a [String]>,
    pub checks: Checks<'a>,
}

fn is_step(s: &Value) -> bool {
    let Some(o) = s.as_object() else { return false };
    let st = |k: &str| o.get(k).is_some_and(Value::is_string);
    let si = |k: &str| safe_int(o.get(k)).is_some();
    st("goal_commitment")
        && safe_int(o.get("seq")).is_some_and(|n| n >= 0.0)
        && st("before_digest")
        && st("after_digest")
        && st("action_digest")
        && matches!(o.get("mode").and_then(Value::as_str), Some("progress" | "exploration"))
        && si("potential_before")
        && si("potential_after")
        && si("charge")
        && st("state_source")
        && st("evidence_digest")
        && st("prev")
        && st("digest")
        && o.contains_key("before")
        && o.contains_key("after")
}

fn num_of(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn verify_step_inner(goal: &Value, commitment: &Value, step: &Value, opts: &VerifyStepOptions<'_>) -> Result<Value, String> {
    if !verify_goal_commitment(goal, commitment) {
        return Ok(fail("goal-mismatch"));
    }
    if !is_step(step) {
        return Ok(fail("malformed"));
    }
    let o = step.as_object().ok_or("malformed")?;
    let text = |k: &str| o[k].as_str().unwrap_or("");
    if Some(text("goal_commitment")) != commitment.as_str() {
        return Ok(fail("goal-mismatch"));
    }
    if opts.expected_seq.is_some_and(|e| num_of(&o["seq"]) != e) {
        return Ok(fail("seq-mismatch"));
    }
    if opts.expected_prev.is_some_and(|e| text("prev") != e) {
        return Ok(fail("chain-break"));
    }
    if opts.expected_action_digest.is_some_and(|e| text("action_digest") != e) {
        return Ok(fail("action-mismatch"));
    }
    if opts.expected_before_digest.is_some_and(|e| text("before_digest") != e) {
        return Ok(fail("state-mismatch"));
    }
    if opts.expected_after_digest.is_some_and(|e| text("after_digest") != e) {
        return Ok(fail("state-mismatch"));
    }
    let mut body = o.clone();
    body.remove("digest");
    if step_body_digest(&body)? != text("digest") {
        return Ok(fail("digest-mismatch"));
    }
    if state_digest(&o["before"])? != text("before_digest") || state_digest(&o["after"])? != text("after_digest") {
        return Ok(fail("state-digest-mismatch"));
    }
    let c = &opts.checks;
    let reg = c.registry.unwrap_or(&*DEFAULT_POTENTIALS);
    let judged = (|| {
        let pb = potential_of(goal, reg, &o["before"])?;
        let pa = potential_of(goal, reg, &o["after"])?;
        let cls = classify(pb, pa, epsilon_of(goal))?;
        Ok::<_, PErr>((pb, pa, cls))
    })();
    let (pb, pa, (mode, charge)) = match judged {
        Ok(x) => x,
        Err(e) => return Ok(fail(e.code)),
    };
    if pb != num_of(&o["potential_before"]) || pa != num_of(&o["potential_after"]) {
        return Ok(fail("potential-mismatch"));
    }
    if text("mode") != mode {
        return Ok(fail("mode-mismatch"));
    }
    if num_of(&o["charge"]) != charge {
        return Ok(fail("charge-mismatch"));
    }
    if c.trusted_state_sources
        .is_some_and(|t| !t.iter().any(|s| s == text("state_source")))
    {
        return Ok(fail("untrusted-state-source"));
    }
    if c.require_attested_state != Some(false) && text("state_source").is_empty() {
        return Ok(fail("untrusted-state-source"));
    }
    if let Some(g) = c.guard {
        let t = Transition {
            seq: num_of(&o["seq"]),
            before: &o["before"],
            after: &o["after"],
            action_digest: text("action_digest"),
        };
        if !run_guard(g, &t) {
            return Ok(fail("prohibited"));
        }
    }
    if let Some(a) = c.attestation {
        if !catch_unwind(AssertUnwindSafe(|| a(step))).unwrap_or(false) {
            return Ok(fail("attestation-failed"));
        }
    }
    Ok(json!({"ok": true, "charge": jnum(charge)}))
}

/// Re-check one step against the committed goal: `{ok: true, charge}` or `{ok: false, reason}`. Pure and deterministic, never fails; the
/// first failing check wins, in the reference's order. Nothing the step claims is trusted: the state digests, both potentials, the mode
/// and the charge are all recomputed.
pub fn verify_progress_step(goal: &Value, commitment: &Value, step: &Value, opts: &VerifyStepOptions<'_>) -> Value {
    verify_step_inner(goal, commitment, step, opts).unwrap_or_else(|_| fail("malformed"))
}

fn traj_fail(reason: &str, at: i64) -> Value {
    json!({"ok": false, "reason": reason, "at": at})
}

/// Verify a whole trajectory: the goal binding, every step re-checked, hash-chained, states contiguous (`step[i].after_digest ==
/// step[i+1].before_digest`), starting from `initial` if given, per-step action binding if given, and the strict global invariant
/// `sum(charge) <= explorationBudget`. Charges are recomputed, never trusted. `{ok: true, spent, remaining, reached, finalPotential,
/// steps, head}` or `{ok: false, reason, at}`.
pub fn verify_trajectory(goal: &Value, commitment: &Value, steps: &Value, opts: &VerifyTrajectoryOptions<'_>) -> Value {
    if !verify_goal_commitment(goal, commitment) {
        return traj_fail("goal-mismatch", -1);
    }
    let Some(steps) = steps.as_array() else {
        return traj_fail("malformed", -1);
    };
    let eads = opts.expected_action_digests;
    if let Some(e) = eads {
        if e.len() != steps.len() {
            return traj_fail("action-mismatch", e.len().min(steps.len()) as i64);
        }
    }
    let mut anchor: Option<String> = match (opts.initial_digest, opts.initial) {
        (Some(d), _) => Some(d.to_string()),
        (None, Some(i)) => match state_digest(i) {
            Ok(d) => Some(d),
            Err(_) => return traj_fail("malformed", -1),
        },
        (None, None) => None,
    };
    let (mut prev, mut spent, mut final_potential) = (GENESIS.to_string(), 0.0, -1.0);
    if steps.is_empty() {
        if let Some(i) = opts.initial {
            match potential_of(goal, opts.checks.registry.unwrap_or(&*DEFAULT_POTENTIALS), i) {
                Ok(p) => final_potential = p,
                Err(e) => return traj_fail(e.code, -1),
            }
        }
    }
    let budget = budget_of(goal);
    for (i, s) in steps.iter().enumerate() {
        let so = VerifyStepOptions {
            expected_seq: Some(i as f64),
            expected_prev: Some(prev.as_str()),
            expected_action_digest: eads.and_then(|e| e.get(i)).map(String::as_str),
            checks: opts.checks,
            ..Default::default()
        };
        let r = verify_progress_step(goal, commitment, s, &so);
        if r["ok"] != json!(true) {
            return traj_fail(r["reason"].as_str().unwrap_or("malformed"), i as i64);
        }
        if anchor
            .as_deref()
            .is_some_and(|a| prop(s, "before_digest").and_then(Value::as_str) != Some(a))
        {
            return traj_fail("discontinuous-state", i as i64);
        }
        spent += num_of(&r["charge"]);
        if !is_safe(spent) || spent > budget {
            return traj_fail("budget-exceeded", i as i64);
        }
        anchor = prop(s, "after_digest").and_then(Value::as_str).map(str::to_string);
        prev = prop(s, "digest").and_then(Value::as_str).unwrap_or_default().to_string();
        final_potential = num_of(&s["potential_after"]);
    }
    json!({
        "ok": true,
        "spent": jnum(spent),
        "remaining": jnum(budget - spent),
        "reached": final_potential == 0.0,
        "finalPotential": jnum(final_potential),
        "steps": steps.len(),
        "head": prev,
    })
}

// ---- signed proofs (Ed25519, domain separated) ------------------------------------------------------------------------------------

fn sig_message(step: &Value, holder: &str) -> Result<Vec<u8>, String> {
    let mut b = Map::new();
    b.insert("holder".into(), json!(holder));
    for (k, from) in [
        ("goal_commitment", "goal_commitment"),
        ("action_digest", "action_digest"),
        ("before_digest", "before_digest"),
        ("after_digest", "after_digest"),
        ("seq", "seq"),
        ("prev", "prev"),
        ("step_digest", "digest"),
    ] {
        b.insert(
            k.into(),
            prop(step, from).ok_or("canonicalize: unsupported type undefined")?.clone(),
        );
    }
    Ok(crate::canonicalize_strict(&json!({"d": PROGRESS_SIG_DOMAIN, "b": b}))?.into_bytes())
}

/// Sign a step as the acting holder: `{step, holder, sig}`, Ed25519 over the domain-separated binding of the step to the holder.
/// `holder_public_key` is committed in the message and is not checked against `key` (the verifier pins the holder).
pub fn sign_progress_step(step: &Value, key: &KeyPair, holder_public_key: &str) -> Result<Value, String> {
    let sig = crate::b64_encode(&key.sign(&sig_message(step, holder_public_key)?));
    Ok(json!({"step": step, "holder": holder_public_key, "sig": sig}))
}

fn signed_shape(s: &Value) -> bool {
    s.is_object()
        && prop(s, "holder").is_some_and(Value::is_string)
        && prop(s, "sig").is_some_and(Value::is_string)
        && prop(s, "step").is_some_and(is_step)
}

/// The signature check of one signed step; `Err` where the reference throws.
fn signature_holds(signed: &Value) -> Result<bool, String> {
    let (holder, sig, step) = (
        signed["holder"].as_str().unwrap_or(""),
        signed["sig"].as_str().unwrap_or(""),
        &signed["step"],
    );
    Ok(crate::verify_b64u(holder, &sig_message(step, holder)?, sig))
}

/// Verify a signed step offline: the shape, the expected holder, the bound action and goal, the signature (strict Ed25519, domain
/// separated), THEN the full deterministic step re-check. Rebinding to another action, goal, state or holder fails. `opts.expected_action_digest`
/// is required (a missing one never matches).
pub fn verify_signed_progress_step(
    goal: &Value,
    commitment: &Value,
    signed: &Value,
    expected_holder: &str,
    opts: &VerifyStepOptions<'_>,
) -> Value {
    if !signed_shape(signed) {
        return fail("malformed");
    }
    if signed["holder"].as_str() != Some(expected_holder) {
        return fail("holder-mismatch");
    }
    if opts.expected_action_digest != signed["step"]["action_digest"].as_str() {
        return fail("action-mismatch");
    }
    if signed["step"]["goal_commitment"].as_str() != commitment.as_str() {
        return fail("goal-mismatch");
    }
    match signature_holds(signed) {
        Ok(true) => {}
        Ok(false) => return fail("bad-signature"),
        Err(_) => return fail("malformed"),
    }
    verify_progress_step(goal, commitment, &signed["step"], opts)
}

/// Verify the signatures on every step (see [`verify_signed_progress_step`]) and then the whole trajectory over the unsigned steps.
/// `opts.expected_action_digests` is required: `Err` without it, as the reference throws.
pub fn verify_signed_trajectory(
    goal: &Value,
    commitment: &Value,
    signed: &Value,
    expected_holder: &str,
    opts: &VerifyTrajectoryOptions<'_>,
) -> Result<Value, String> {
    let Some(list) = signed.as_array() else {
        return Ok(traj_fail("malformed", -1));
    };
    let eads = opts
        .expected_action_digests
        .ok_or("Cannot read properties of undefined (reading 'length')")?;
    if eads.len() != list.len() {
        return Ok(traj_fail("action-mismatch", eads.len().min(list.len()) as i64));
    }
    for (i, sp) in list.iter().enumerate() {
        let at = i as i64;
        if !signed_shape(sp) {
            return Ok(traj_fail("malformed", at));
        }
        if sp["holder"].as_str() != Some(expected_holder) {
            return Ok(traj_fail("holder-mismatch", at));
        }
        if sp["step"]["action_digest"].as_str() != Some(eads[i].as_str()) {
            return Ok(traj_fail("action-mismatch", at));
        }
        match signature_holds(sp) {
            Ok(true) => {}
            Ok(false) => return Ok(traj_fail("bad-signature", at)),
            Err(_) => return Ok(traj_fail("malformed", at)),
        }
    }
    let steps = Value::Array(list.iter().map(|s| s["step"].clone()).collect());
    Ok(verify_trajectory(goal, commitment, &steps, opts))
}
