//! [`authorize`]: the full authorization pipeline for a resource server or tool guard (0.5, additive).
//!
//! [`verify_pcactn_core_with`] answers "is this a validly signed PCActn for this audience". [`authorize`] answers "may
//! THIS operation run now", in the same order as the TypeScript `authorize()` / `verifyPCActn`:
//!
//!   1. configuration: `audience`, `resolve_grant`, `state_store` and `is_revoked` are REQUIRED, and the call must name
//!      the [`Operation`] it will execute (verb, resource, params). A missing one denies with its name; nothing is ever
//!      downgraded to "not enforced".
//!   2. the core checks ([`verify_pcactn_core_with`]: wire, version, audience, validity, chain, grant_ref_bound,
//!      plan_inclusion, leaf_signature, counter format, intent), then `revocation` (`is_revoked`), then `zk_compliance`
//!      (a carried proof cannot be verified here: fail closed).
//!   3. `operation`: the signed `action.verb` / `action.resource` equal the operation's, and the signed
//!      `action.params_digest` opens to exactly the operation's params. Those params are what the predicates and caveats
//!      read, so a $400 operation is judged as $400 even when the agent signed $50 (and then refused for the mismatch).
//!   4. `grant_ref`, `params_digest`, `plan_root_authorized` (`plan = "single-step"` or a `context` plan),
//!      `attestation` (a grant whose `agent_binding` pins the agent needs an attestation verifier this crate does not
//!      have: fail closed), `reversibility` (when the context names an authoritative class).
//!   5. policy: the grant's envelope predicates (default deny), the envelope's caveats and the ROOT caveats outside the
//!      envelope (`policy`), and the caveats delegation hops appended (`delegated_caveats`). `predicates` and
//!      `tool_schema` caveats are enforced against the operation; unknown caveat types fail closed.
//!   6. replay: only when everything above passes, the counter is consumed through [`StateStore::claim`], one atomic
//!      compare-and-set per action (key = [`state_key`]`(grant id, leaf holder)`). A replayed or older counter denies.
//!
//! Not ported from the TypeScript policy VM: the risk score, trust budget and threshold step-up (`risk_policy`). A grant
//! whose risk policy would make the TypeScript verifier ask for a co-signature is decided here on predicates and caveats
//! alone.
//!
//! Never panics: any internal error (a panicking callback included) is a denial.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::caveat_lang::{discharge_action_digest, evaluate_k1, is_k1_caveat, reserve_max_uses, K1Ctx, K1Input, PresentedK1, UsesVerdict, CAVEAT_MAX_USES};
use crate::escalation::{
    build_escalation_request_with_render, escalation_action_digest, escalation_history_head, escalation_policy_digest, verify_escalation_answer, EscalationBinding,
    EscalationVerdict, PinnedSigner,
};
use crate::fresh_at::FreshAtPolicy;
use crate::intent_v2::js_value_string;
use crate::assurance::{assurance_report, refresh_assurance, unmet_assurance, AssuranceHooks, AssuranceReport, AssuranceRequirement, AssuranceSources, CheckAssurance};
use crate::plans::{PlanRegistry, PlanStatus};
use crate::staleness::RevocationStaleness;
use crate::workflow::{admit_step, AdmitInput, Decision as WfDecision};
use crate::predicates::{first_unmet_limit, predicate_matches, Ctx};
use crate::safe_regex::with_regex_budget;
use crate::{
    canonicalize_strict, decide_intent_v2, evaluate_caveats, fin, hash_canonical, hash_canonical_strict, merkle_root, plan_leaf, safe_int,
    strict_parse, verify_pcactn_core_with_fresh_at, IntentPolicy, IntentV2Context, Verdict, VerifyOptions, ENVELOPE_CAVEAT, MAX_ARTIFACT_BYTES,
};

/// The only plan mode [`authorize`] synthesizes itself: a one-node plan whose node is exactly the operation.
pub const SINGLE_STEP: &str = "single-step";

/// The checks that must be `pass` (not merely "not failed"): the TypeScript `DEFAULT_REQUIRED_CHECKS` plus the operation
/// binding and the policy. [`AuthorizeInput::require`] can add names, never remove these.
pub const DEFAULT_REQUIRED_CHECKS: [&str; 10] =
    ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy"];

// A failing one of these is an authentication failure (401), everything else is insufficient authority (403); the same
// split as the TypeScript requirePCA (this crate names the chain check `chain`, TypeScript `cap_chain`).
const AUTHN_CHECKS: [&str; 9] = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref"];

// The order the core verifier runs its checks in (its verdict map is sorted by name): the decisive reason follows it.
const CORE_ORDER: [&str; 18] = [
    "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "intent", "schema",
    "intent_session", "layers", "accumulators", "map", "facts", "provenance", "classes",
];

// ---- the replay store ------------------------------------------------------------------------------------------------

/// What [`StateStore::claim`] returns. `ok` is true only when THIS call consumed the counter; on a replay
/// `last_counter` is the stored counter when the store can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimResult {
    pub ok: bool,
    pub last_counter: Option<u64>,
}

impl ClaimResult {
    /// The counter was consumed by this call.
    pub fn claimed() -> Self {
        ClaimResult { ok: true, last_counter: None }
    }

    /// The counter was not consumed (`last` = the stored counter, when known).
    pub fn replay(last: Option<u64>) -> Self {
        ClaimResult { ok: false, last_counter: last }
    }
}

/// A replay store that could not decide (backend down, lock poisoned, ...). [`authorize`] denies on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "replay store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// The replay-store interface: ONE atomic operation of your backend. If a counter is stored for `key` and `counter` is
/// not strictly greater, return `ClaimResult { ok: false, last_counter: Some(stored) }`; otherwise store `counter` and
/// return [`ClaimResult::claimed`]. A claim that cannot decide must return `ok: false` or an error ([`authorize`] then
/// denies).
pub trait StateStore: Send + Sync {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError>;

    /// The last admitted counter of a stream: `Some(None)` = none yet, `Some(Some(n))`, or `None` when the store cannot read
    /// it right now (an error). REQUIRED: an escalation answer is bound to the holder's history head (the highest admitted
    /// counter), so the verifier must be able to read it, as the TypeScript store's `get` does. An answered escalation whose
    /// head cannot be read stays refused.
    fn last(&self, key: &str) -> Option<Option<u64>>;

    /// A TTL'd consume-once (K1 `max_uses` slots): `Ok(true)` iff this call is the first consume of `key` with no live record,
    /// where a live record has `retain_until_ms >= now_ms`. The store remembers a consumed key at least until `retain_until_ms`
    /// (the maximum of the horizons it was given) and may forget it afterwards. A `retain_until_ms < now_ms` or an empty `key`
    /// is an `Err` (never `Ok(true)`) and a refused call leaves nothing behind. The default falls back to the permanent
    /// first-claim (`claim(key, 1)`), which never forgets: override it to let spent slots expire and be pruned.
    fn consume_once(&self, key: &str, retain_until_ms: i64, now_ms: i64) -> Result<bool, StoreError> {
        consume_once_args(key, retain_until_ms, now_ms)?;
        self.claim(key, 1).map(|r| r.ok)
    }
}

/// The argument check every [`StateStore::consume_once`] shares.
pub fn consume_once_args(key: &str, retain_until_ms: i64, now_ms: i64) -> Result<(), StoreError> {
    if key.is_empty() || retain_until_ms < now_ms {
        return Err(StoreError("consume_once: invalid key or retention horizon".into()));
    }
    Ok(())
}

/// In-process reference store (one mutex). Correct for ONE process only; use a database for several workers (feature
/// `sqlite`: `SqliteStateStore`).
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    last: Mutex<HashMap<String, u64>>,
    once: Mutex<HashMap<String, i64>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStateStore {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let mut last = self.last.lock().map_err(|_| StoreError("the memory store lock is poisoned".into()))?;
        if let Some(&seen) = last.get(key) {
            if counter <= seen {
                return Ok(ClaimResult::replay(Some(seen)));
            }
        }
        last.insert(key.to_string(), counter);
        Ok(ClaimResult::claimed())
    }

    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.last.lock().ok().map(|l| l.get(key).copied())
    }

    fn consume_once(&self, key: &str, retain_until_ms: i64, now_ms: i64) -> Result<bool, StoreError> {
        consume_once_args(key, retain_until_ms, now_ms)?;
        let mut once = self.once.lock().map_err(|_| StoreError("the memory store lock is poisoned".into()))?;
        if once.get(key).is_some_and(|&until| until >= now_ms) {
            return Ok(false);
        }
        once.retain(|_, until| *until >= now_ms); // forget what has fully elapsed
        once.insert(key.to_string(), retain_until_ms);
        Ok(true)
    }
}

/// Test seam (hidden): edits the core verdict (e.g. injects an escalate-class failure) before the pipeline reads it. Always
/// `None` in production.
#[doc(hidden)]
pub static CORE_HOOK: Mutex<Option<fn(&mut Verdict)>> = Mutex::new(None);

/// The store key of a holder's counter stream (the TypeScript `pcaStateKey` default scope).
pub fn state_key(grant_id: &str, leaf_holder: &str) -> String {
    format!("{grant_id}:{leaf_holder}")
}

// ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ---------------------------------

fn risk_policy_error(p: Option<&Value>) -> Option<&'static str> {
    let p = match p.and_then(Value::as_object) {
        Some(p) => p,
        None => return Some("risk_policy must be an object"),
    };
    let w = match p.get("weights").and_then(Value::as_object) {
        Some(w) => w,
        None => return Some("risk_policy.weights missing"),
    };
    for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        if !fin(w.get(k)).is_some_and(|v| v >= 0.0) {
            return Some("risk_policy.weights must be finite and >= 0");
        }
    }
    let mut vals = [0f64; 6];
    for (i, k) in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"].iter().enumerate() {
        match fin(p.get(*k)) {
            Some(v) => vals[i] = v,
            None => return Some("risk_policy members must be finite"),
        }
    }
    let [theta1, theta2, kappa, lambda, rho, b_max] = vals;
    if theta1 < 0.0 || theta2 < theta1 {
        return Some("risk_policy requires 0 <= theta1 <= theta2");
    }
    if kappa <= 0.0 {
        return Some("risk_policy.kappa must be > 0");
    }
    if lambda < 0.0 || rho < 0.0 || b_max < 0.0 {
        return Some("risk_policy lambda/rho/bMax must be >= 0");
    }
    None
}

/// The grant's policy envelope: its FIRST `envelope` caveat without `type`, or `None` when absent or malformed
/// (`goal_commit` a string, `predicates` and `caveats` arrays, `agent_binding` an object or array, a valid
/// `risk_policy`).
pub fn read_envelope(grant: &Value) -> Option<Map<String, Value>> {
    let cs = grant.get("caveats")?.as_array()?;
    let cv = cs.iter().find(|c| c.is_object() && c.get("type").and_then(Value::as_str) == Some(ENVELOPE_CAVEAT))?;
    let mut e = cv.as_object()?.clone();
    e.remove("type");
    if !e.get("goal_commit").is_some_and(Value::is_string) {
        return None;
    }
    if !e.get("predicates").is_some_and(Value::is_array) || !e.get("caveats").is_some_and(Value::is_array) {
        return None;
    }
    if !e.get("agent_binding").is_some_and(|b| b.is_object() || b.is_array()) {
        return None;
    }
    if risk_policy_error(e.get("risk_policy")).is_some() {
        return None;
    }
    Some(e)
}

/// Every root caveat except the first `envelope` one (TypeScript `rootCaveats`); a non-array is returned as is (`Null`
/// when absent).
pub fn root_caveats(grant: &Value) -> Value {
    let cs = match grant.get("caveats") {
        Some(Value::Array(cs)) => cs,
        other => return other.cloned().unwrap_or(Value::Null),
    };
    let mut out = cs.clone();
    if let Some(i) = out.iter().position(|c| c.is_object() && c.get("type").and_then(Value::as_str) == Some(ENVELOPE_CAVEAT)) {
        out.remove(i);
    }
    Value::Array(out)
}

/// TypeScript `requiresAttestation`: any agent pin in `agent_binding` requires a bound attestation.
fn requires_attestation(binding: Option<&Value>) -> bool {
    let empty = Map::new();
    let b = binding.and_then(Value::as_object).unwrap_or(&empty);
    let ne = |k: &str| b.get(k).and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    let has_min = b.get("min_measurement").is_some_and(|m| m.as_str() != Some(""));
    ne("model_allowlist")
        || has_min
        || b.get("operator").and_then(Value::as_str).is_some_and(|o| !o.is_empty())
        || ne("weights_allowlist")
        || ne("system_prompt_allowlist")
        || ne("tool_manifest_allowlist")
        || b.get("require_hardware") == Some(&Value::Bool(true))
        || b.get("require_measured_weights") == Some(&Value::Bool(true))
}

// ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) ---------------------------------------

pub const MAX_SCHEMA_DEPTH: usize = 8;
pub const MAX_SCHEMA_NODES: usize = 256;
pub const MAX_OBJECT_PROPS: usize = 64;
pub const MAX_ENUM_VALUES: usize = 256;
pub const DEFAULT_MAX_ARRAY_ITEMS: usize = 256;
pub const ABSOLUTE_MAX_ARRAY_ITEMS: usize = 4096;
pub const DEFAULT_MAX_STRING_LEN: usize = 65_536;
pub const ABSOLUTE_MAX_STRING_LEN: usize = 1_048_576;
pub const MAX_VALUE_NODES: usize = 10_000;

fn spec_keys(t: &str) -> Option<&'static [&'static str]> {
    Some(match t {
        "string" => &["type", "enum", "const", "minLength", "maxLength", "prefix"],
        "number" | "integer" => &["type", "enum", "const", "min", "max"],
        "boolean" => &["type", "enum", "const"],
        "object" => &["type", "props", "required"],
        "array" => &["type", "items", "minItems", "maxItems"],
        _ => return None,
    })
}

/// JavaScript `string.length` (UTF-16 code units).
fn jslen(s: &str) -> usize {
    s.encode_utf16().count()
}

fn is_int(v: Option<&Value>) -> bool {
    fin(v).is_some_and(|f| f.fract() == 0.0)
}

fn non_neg_int(v: Option<&Value>, mx: usize) -> bool {
    fin(v).is_some_and(|f| f.fract() == 0.0 && f >= 0.0 && f <= mx as f64)
}

fn only_keys(o: &Map<String, Value>, allowed: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str()))
}

/// JavaScript `===` on the scalars a schema can hold (numbers compare as doubles; a bool is never a number).
fn js_eq(a: &Value, b: &Value) -> bool {
    let (fa, fb) = (fin(Some(a)), fin(Some(b)));
    if fa.is_some() || fb.is_some() {
        return fa.is_some() && fb.is_some() && fa == fb;
    }
    match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        _ => false,
    }
}

fn safe_name(n: &str) -> bool {
    (1..=64).contains(&n.len()) && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Validate a `tool_schema` argument schema (closed; shape, depth, node count, bounds). `None` when valid.
pub fn validate_arg_schema(schema: &Value) -> Option<String> {
    let s = match schema.as_object() {
        Some(s) => s,
        None => return Some("schema must be an object".into()),
    };
    if !only_keys(s, &["props", "required"]) {
        return Some("unknown schema key".into());
    }
    let mut nodes = 0usize;
    object_schema_error(s.get("props"), s.get("required"), 1, &mut nodes)
}

fn object_schema_error(props: Option<&Value>, required: Option<&Value>, depth: usize, nodes: &mut usize) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Some("schema too deep".into());
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Some("schema too large".into());
    }
    let props = match props.and_then(Value::as_object) {
        Some(p) => p,
        None => return Some("props must be an object".into()),
    };
    if props.len() > MAX_OBJECT_PROPS {
        return Some("too many props".into());
    }
    for (n, spec) in props {
        if !safe_name(n) {
            return Some(format!("invalid property name '{}'", n.chars().take(32).collect::<String>()));
        }
        if let Some(e) = spec_error(Some(spec), depth + 1, nodes) {
            return Some(format!("{n}: {e}"));
        }
    }
    if let Some(required) = required {
        let req = match required.as_array() {
            Some(r) if r.len() <= MAX_OBJECT_PROPS => r,
            _ => return Some("required must be a short array".into()),
        };
        for r in req {
            if !r.as_str().is_some_and(|r| props.contains_key(r)) {
                return Some("required names an undeclared property".into());
            }
        }
    }
    None
}

fn spec_error(spec: Option<&Value>, depth: usize, nodes: &mut usize) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Some("schema too deep".into());
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Some("schema too large".into());
    }
    let (spec, t, keys) = match spec.and_then(Value::as_object) {
        Some(s) => match s.get("type").and_then(Value::as_str).and_then(|t| spec_keys(t).map(|k| (t, k))) {
            Some((t, k)) => (s, t, k),
            None => return Some("unknown type".into()),
        },
        None => return Some("unknown type".into()),
    };
    if !only_keys(spec, keys) {
        return Some("unknown spec key".into());
    }
    if t == "object" {
        *nodes -= 1; // counted once by object_schema_error
        return object_schema_error(spec.get("props"), spec.get("required"), depth, nodes);
    }
    if t == "array" {
        if spec.contains_key("minItems") && !non_neg_int(spec.get("minItems"), ABSOLUTE_MAX_ARRAY_ITEMS) {
            return Some("bad minItems".into());
        }
        if spec.contains_key("maxItems") && !non_neg_int(spec.get("maxItems"), ABSOLUTE_MAX_ARRAY_ITEMS) {
            return Some("bad maxItems".into());
        }
        if let (Some(lo), Some(hi)) = (fin(spec.get("minItems")), fin(spec.get("maxItems"))) {
            if lo > hi {
                return Some("minItems > maxItems".into());
            }
        }
        return spec_error(spec.get("items"), depth + 1, nodes);
    }
    let ok = |v: &Value| match t {
        "string" => v.as_str().is_some_and(|s| jslen(s) <= 1024),
        "boolean" => v.is_boolean(),
        _ => fin(Some(v)).is_some() && (t == "number" || is_int(Some(v))),
    };
    if spec.get("const").is_some_and(|c| !ok(c)) {
        return Some("bad const".into());
    }
    if let Some(en) = spec.get("enum") {
        match en.as_array() {
            Some(en) if !en.is_empty() && en.len() <= MAX_ENUM_VALUES && en.iter().all(ok) => {}
            _ => return Some("bad enum".into()),
        }
    }
    if t == "string" {
        if spec.contains_key("minLength") && !non_neg_int(spec.get("minLength"), ABSOLUTE_MAX_STRING_LEN) {
            return Some("bad minLength".into());
        }
        if spec.contains_key("maxLength") && !non_neg_int(spec.get("maxLength"), ABSOLUTE_MAX_STRING_LEN) {
            return Some("bad maxLength".into());
        }
        if let (Some(lo), Some(hi)) = (fin(spec.get("minLength")), fin(spec.get("maxLength"))) {
            if lo > hi {
                return Some("minLength > maxLength".into());
            }
        }
        if let Some(p) = spec.get("prefix") {
            if !p.as_str().is_some_and(|p| jslen(p) <= 512) {
                return Some("bad prefix".into());
            }
        }
    } else if t == "number" || t == "integer" {
        if spec.contains_key("min") && fin(spec.get("min")).is_none() {
            return Some("bad min".into());
        }
        if spec.contains_key("max") && fin(spec.get("max")).is_none() {
            return Some("bad max".into());
        }
        if let (Some(lo), Some(hi)) = (fin(spec.get("min")), fin(spec.get("max"))) {
            if lo > hi {
                return Some("min > max".into());
            }
        }
    }
    None
}

/// A key as the reference prints it in a reason: JSON-quoted, cut to 48 characters (`…` appended).
fn show(k: &str) -> String {
    let s = if jslen(k) > 48 { format!("{}…", k.chars().take(48).collect::<String>()) } else { k.to_string() };
    serde_json::to_string(&Value::String(s)).unwrap_or_default()
}

fn check_value(spec: &Map<String, Value>, v: &Value, path: &str, depth: usize, n: &mut usize) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH + 1 {
        return Some(format!("{path}: too deep"));
    }
    *n += 1;
    if *n > MAX_VALUE_NODES {
        return Some(format!("{path}: too many values"));
    }
    let empty = Map::new();
    let t = spec.get("type").and_then(Value::as_str).unwrap_or("");
    match t {
        "object" => {
            let obj = match v.as_object() {
                Some(o) => o,
                None => return Some(format!("{path}: expected object")),
            };
            let props = spec.get("props").and_then(Value::as_object).unwrap_or(&empty);
            return check_object(props, spec.get("required"), obj, path, depth, n);
        }
        "array" => {
            let arr = match v.as_array() {
                Some(a) => a,
                None => return Some(format!("{path}: expected array")),
            };
            let mx = fin(spec.get("maxItems")).unwrap_or(DEFAULT_MAX_ARRAY_ITEMS as f64).min(ABSOLUTE_MAX_ARRAY_ITEMS as f64);
            if arr.len() as f64 > mx {
                return Some(format!("{path}: exceeds maxItems"));
            }
            if fin(spec.get("minItems")).is_some_and(|lo| (arr.len() as f64) < lo) {
                return Some(format!("{path}: below minItems"));
            }
            let items = spec.get("items").and_then(Value::as_object).unwrap_or(&empty);
            for (i, x) in arr.iter().enumerate() {
                if let Some(e) = check_value(items, x, &format!("{path}[{i}]"), depth + 1, n) {
                    return Some(e);
                }
            }
            return None;
        }
        "string" => {
            let s = match v.as_str() {
                Some(s) => s,
                None => return Some(format!("{path}: wrong type (expected string)")),
            };
            let len = jslen(s) as f64;
            if len > fin(spec.get("maxLength")).unwrap_or(DEFAULT_MAX_STRING_LEN as f64).min(ABSOLUTE_MAX_STRING_LEN as f64) {
                return Some(format!("{path}: exceeds maxLength"));
            }
            if fin(spec.get("minLength")).is_some_and(|lo| len < lo) {
                return Some(format!("{path}: below minLength"));
            }
            if let Some(p) = spec.get("prefix") {
                if !p.as_str().is_some_and(|p| s.starts_with(p)) {
                    return Some(format!("{path}: violates prefix"));
                }
            }
        }
        "number" | "integer" => {
            let f = match fin(Some(v)) {
                Some(f) if t == "number" || f.fract() == 0.0 => f,
                _ => return Some(format!("{path}: wrong type (expected {t})")),
            };
            if fin(spec.get("min")).is_some_and(|lo| f < lo) {
                return Some(format!("{path}: below min"));
            }
            if fin(spec.get("max")).is_some_and(|hi| f > hi) {
                return Some(format!("{path}: above max"));
            }
        }
        "boolean" => {
            if !v.is_boolean() {
                return Some(format!("{path}: wrong type (expected boolean)"));
            }
        }
        _ => return Some(format!("{path}: unknown type")),
    }
    if spec.get("const").is_some_and(|c| !js_eq(c, v)) {
        return Some(format!("{path}: violates const"));
    }
    if let Some(en) = spec.get("enum") {
        if !en.as_array().is_some_and(|en| en.iter().any(|e| js_eq(e, v))) {
            return Some(format!("{path}: violates enum"));
        }
    }
    None
}

fn check_object(props: &Map<String, Value>, required: Option<&Value>, obj: &Map<String, Value>, path: &str, depth: usize, n: &mut usize) -> Option<String> {
    for k in obj.keys() {
        if !props.contains_key(k) {
            return Some(format!("{path}: unexpected argument {}", show(k)));
        }
    }
    for r in required.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let r = r.as_str().unwrap_or("");
        if !obj.contains_key(r) {
            return Some(format!("{path}: missing required argument '{r}'"));
        }
    }
    let empty = Map::new();
    for (k, v) in obj {
        let spec = props.get(k).and_then(Value::as_object).unwrap_or(&empty);
        if let Some(e) = check_value(spec, v, &format!("{path}.{k}"), depth + 1, n) {
            return Some(e);
        }
    }
    None
}

/// Evaluate a tool call `{"tool", "args", "tool_signature_digest"?}` against a `tool_schema` caveat. Returns
/// `(ok, reason)`. Same rules as the TypeScript `evaluateToolSchema`: a closed schema (depth 8, 256 nodes, 64 props, 256
/// enum values), string lengths in UTF-16 code units, integers as finite doubles without a fraction, `enum` / `const`
/// with JavaScript `===`, and the caveat's `schema_digest` / `binding_digest` recomputed. Never panics.
pub fn evaluate_tool_schema(caveat: &Value, call: &Value) -> (bool, Option<String>) {
    catch_unwind(AssertUnwindSafe(|| match tool_schema_error(caveat, call) {
        Some(e) => (false, Some(e)),
        None => (true, None),
    }))
    .unwrap_or_else(|_| (false, Some("evaluation error (fail closed)".into())))
}

fn tool_schema_error(caveat: &Value, call: &Value) -> Option<String> {
    let c = match caveat.as_object() {
        Some(c) if c.get("type").and_then(Value::as_str) == Some("tool_schema") => c,
        _ => return Some("malformed tool_schema caveat".into()),
    };
    let tool = match c.get("tool").and_then(Value::as_str) {
        Some(t) if !t.is_empty() => t,
        _ => return Some("malformed tool_schema caveat".into()),
    };
    let schema = c.get("schema").unwrap_or(&Value::Null);
    if let Some(e) = validate_arg_schema(schema) {
        return Some(format!("malformed tool_schema caveat: {e}"));
    }
    let eval_error = || Some("evaluation error (fail closed)".to_string());
    let schema_digest = match hash_canonical_strict(schema) {
        Some(d) => d,
        None => return eval_error(),
    };
    if c.get("schema_digest").and_then(Value::as_str) != Some(schema_digest.as_str()) {
        return Some("schema digest mismatch".into());
    }
    let sig = match c.get("signature_digest") {
        Some(s) => js_value_string(s),
        None => "undefined".to_string(),
    };
    let binding = match hash_canonical_strict(&json!({"tool": tool, "signature_digest": sig, "schema": schema})) {
        Some(d) => d,
        None => return eval_error(),
    };
    if c.get("binding_digest").and_then(Value::as_str) != Some(binding.as_str()) {
        return Some("binding digest mismatch".into());
    }
    let (call_tool, args) = match (call.get("tool").and_then(Value::as_str), call.get("args").and_then(Value::as_object)) {
        (Some(t), Some(a)) if call.is_object() => (t, a),
        _ => return Some("malformed call".into()),
    };
    if call_tool != tool {
        return Some(format!("tool {} not authorized", show(call_tool)));
    }
    if let Some(d) = call.get("tool_signature_digest") {
        if d != c.get("signature_digest").unwrap_or(&Value::Null) {
            return Some("signed tool_binding differs from the authorized tool signature".into());
        }
    }
    let empty = Map::new();
    let props = schema.get("props").and_then(Value::as_object).unwrap_or(&empty);
    let mut n = 0usize;
    check_object(props, schema.get("required"), args, "args", 1, &mut n)
}

// ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) ----------------------------------------------

fn agent_caveat_satisfied(cv: &Value, ctx: &Value, action_ctx: &Value, tool_call: &Value) -> bool {
    if !cv.is_object() || !ctx.is_object() {
        return false;
    }
    match cv.get("type").and_then(Value::as_str) {
        Some("tool_schema") => evaluate_tool_schema(cv, tool_call).0,
        Some("predicates") => match (action_ctx.is_object(), cv.get("allow").and_then(Value::as_array)) {
            (true, Some(allow)) => {
                let pctx = Ctx::new(action_ctx);
                allow.iter().any(|p| predicate_matches(p, &pctx))
            }
            _ => false,
        },
        // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
        _ => evaluate_caveats(&Value::Array(vec![cv.clone()]), ctx).0,
    }
}

/// Evaluate caveats with the agent-native evaluator: the stock types of [`evaluate_caveats`], plus `predicates`
/// (`allow`: the action must match one predicate; needs `action_ctx` = `{"action": {...}, "subject"?, "env"?}`) and
/// `tool_schema` (needs `tool_call` = `{"tool", "args", "tool_signature_digest"?}`). `ctx` is the stock context (`now`,
/// `action`, `blast_radius`, ...). Unknown types fail closed. Returns `(ok, failed_types)`. Never panics.
pub fn evaluate_agent_caveats(caveats: &Value, ctx: &Value, action_ctx: Option<&Value>, tool_call: Option<&Value>) -> (bool, Vec<String>) {
    let empty = Value::Object(Map::new());
    let action_ctx = action_ctx.filter(|a| !a.is_null()).unwrap_or(&empty);
    let tool_call = tool_call.filter(|t| !t.is_null()).unwrap_or(&empty);
    let run = || {
        let list = match caveats.as_array() {
            Some(l) => l,
            None => return (false, vec!["<malformed caveats>".to_string()]),
        };
        if !list.is_empty() && !ctx.is_object() {
            return (false, vec!["<evaluation error>".to_string()]);
        }
        let mut failed = Vec::new();
        for cv in list {
            if !agent_caveat_satisfied(cv, ctx, action_ctx, tool_call) {
                failed.push(cv.get("type").and_then(Value::as_str).unwrap_or("<malformed>").to_string());
            }
        }
        (failed.is_empty(), failed)
    };
    catch_unwind(AssertUnwindSafe(|| with_regex_budget(run))).unwrap_or_else(|_| (false, vec!["<evaluation error>".to_string()]))
}

// ---- authorize -------------------------------------------------------------------------------------------------------

/// A check's outcome in an [`AuthorizeResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    NotEnforced,
    /// The PCActn carries a feature this verifier does not implement (today `bond_ref`, check `bond`): reported, never a pass.
    Unsupported,
}

impl CheckStatus {
    /// `"pass"`, `"fail"`, `"not-enforced"` or `"unsupported"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Fail => "fail",
            CheckStatus::NotEnforced => "not-enforced",
            CheckStatus::Unsupported => "unsupported",
        }
    }

    /// The status named by `s` (`None` for anything else).
    pub fn parse(s: &str) -> Option<CheckStatus> {
        Some(match s {
            "pass" => CheckStatus::Pass,
            "fail" => CheckStatus::Fail,
            "not-enforced" => CheckStatus::NotEnforced,
            "unsupported" => CheckStatus::Unsupported,
            _ => return None,
        })
    }
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The operation a handler / tool WILL execute, from the server's own routing and parsed input, never from the PCActn.
/// [`authorize`] requires `verb` and `resource` to be non-empty and `params` to be a JSON object.
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub verb: String,
    pub resource: String,
    pub params: Value,
}

impl Operation {
    pub fn new(verb: impl Into<String>, resource: impl Into<String>, params: Value) -> Self {
        Operation { verb: verb.into(), resource: resource.into(), params }
    }

    /// From a JSON `{"verb", "resource", "params"}` (string verb and resource, `params` present); `None` otherwise.
    pub fn from_json(v: &Value) -> Option<Operation> {
        Some(Operation::new(v.get("verb")?.as_str()?, v.get("resource")?.as_str()?, v.get("params")?.clone()))
    }

    fn is_valid(&self) -> bool {
        !self.verb.is_empty() && !self.resource.is_empty() && self.params.is_object()
    }
}

/// The operation an allowing decision is bound to. `id` is the digest of the presented PCActn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedOperation {
    pub verb: String,
    pub resource: String,
    pub params_digest: String,
    pub id: String,
}

/// Outcome of [`authorize`]. `allow` is the one thing a caller must branch on.
///
/// `status` is 200, 401 (no / undecodable / unauthenticated proof) or 403. `checks` maps each check to its
/// [`CheckStatus`]; `reason` is the decisive one (an `operation` failure first, then `plan_state`). `missing` names configuration
/// components that were absent (the call was refused before any verification).
#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    pub allow: bool,
    pub status: u16,
    pub checks: BTreeMap<String, CheckStatus>,
    pub reasons: Vec<String>,
    pub reason: Option<String>,
    pub operation: Option<AuthorizedOperation>,
    pub pcactn: Option<Value>,
    pub verdict: Option<Verdict>,
    pub missing: Option<Vec<String>>,
    /// `"allow"` (and `allow` is true), `"escalate"` (refused: `escalation` is the request to put to the principal) or
    /// `"deny"`. `allow` is exactly `decision == "allow"`: an escalate is never an allow.
    pub decision: &'static str,
    /// `decision == "escalate"`: the escalation request; on an allow admitted by an answer: `{"answered_by": <principal>}`.
    pub escalation: Option<Value>,
    /// Passing checks that rest on a compatibility mode (check name -> why): `tighten` under rule 21's `model_polarity`
    /// `"legacy"`. A caller with a high-assurance policy must not accept a degraded pass.
    pub degraded: BTreeMap<String, String>,
    /// What each check rests on (see [`crate::assurance`]): per check its outcome and, on a pass, the evidence behind it
    /// (software or hardware attestation, the signature suites, ...). Features the verifier lacks are `unsupported`.
    pub assurance: AssuranceReport,
}

/// The `degraded["tighten"]` text of a verdict that passed rule 21 under `model_polarity` `"legacy"`.
pub const LEGACY_POLARITY_DEGRADED: &str = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)";

impl AuthorizeResult {
    /// The names of the failing checks, sorted.
    pub fn failed_checks(&self) -> Vec<&str> {
        self.checks.iter().filter(|(_, s)| **s == CheckStatus::Fail).map(|(k, _)| k.as_str()).collect()
    }

    /// The status of one check (`None` when it was not reported).
    pub fn check(&self, name: &str) -> Option<CheckStatus> {
        self.checks.get(name).copied()
    }
}

/// `(grant_ref) -> Ok(Some(grant))`, `Ok(None)` when unknown, `Err` when the lookup failed (denies, 403).
pub type GrantResolver<'a> = dyn Fn(&str) -> Result<Option<Value>, String> + 'a;
/// `(pcactn, grant) -> Ok(revoked)`. Only `Ok(false)` passes; `Ok(true)`, an error or a panic denies.
pub type RevocationCheck<'a> = dyn Fn(&Value, &Value) -> Result<bool, String> + 'a;
/// `(pcactn) -> Ok(Some(context))`: an object with optional `plan`, `plan_authorized`, `subject`, `env`,
/// `blast_radius`, `recent_action_times`, `reversibility_class` (the server's authoritative class; the agent may only
/// declare a stricter one). `Ok(None)` is an empty context; anything that is not an object, or an error, denies.
pub type ContextProvider<'a> = dyn Fn(&Value) -> Result<Option<Value>, String> + 'a;
/// `(pcactn) -> Ok(Some(IntentV2Context))`: the per-request Intent Layer v2 verifier state (its `params` default to the
/// operation's). An error denies.
pub type IntentV2Provider<'a> = dyn Fn(&Value) -> Result<Option<IntentV2Context>, String> + 'a;

/// Workflow admission inside [`authorize`] (K5, C-308): the keys THIS server pinned. `principal` is the workflow commitment's signer
/// and `rs_signer` the step receipts' signer; a key named inside either is never trusted. With `required`, a call that carries no
/// [`WorkflowCall`] is refused (fail closed); otherwise such a call proceeds unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowGate {
    pub principal: String,
    pub rs_signer: String,
    pub required: bool,
}

/// The workflow step one [`authorize`] call is: the signed commitment, the receipts so far and the step id, as raw JSON so hostile
/// input is refused by `admit_step` rather than failing to type. A null `units` counts as `{}` and a null `goal_digest` as none.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowCall {
    pub commitment: Value,
    pub receipts: Value,
    pub step: Value,
    pub units: Value,
    pub goal_digest: Value,
}

impl WorkflowCall {
    /// `units` defaults to `{}` and `goal_digest` to null.
    pub fn new(commitment: Value, receipts: Value, step: impl Into<String>) -> Self {
        WorkflowCall { commitment, receipts, step: Value::String(step.into()), units: json!({}), goal_digest: Value::Null }
    }
}

/// The inputs of [`authorize`]. `audience`, `resolve_grant`, `state_store` and `is_revoked` are required (a missing one
/// denies); build it with `..Default::default()` for the optional members.
#[derive(Clone, Copy, Default)]
pub struct AuthorizeInput<'a> {
    /// What the handler / tool WILL execute (from the server, never from the PCActn).
    pub operation: Option<&'a Operation>,
    /// This resource server's id (the PCActn's signed `aud` must equal it).
    pub audience: &'a str,
    pub resolve_grant: Option<&'a GrantResolver<'a>>,
    /// Replay store with an atomic [`StateStore::claim`].
    pub state_store: Option<&'a dyn StateStore>,
    pub is_revoked: Option<&'a RevocationCheck<'a>>,
    /// Verifier-side revocation staleness (off unless set): runs after `is_revoked` and fails the same `revocation` check
    /// when the revocation state is too old for the action's class (see [`RevocationStaleness`]).
    pub revocation_staleness: Option<&'a RevocationStaleness>,
    /// A plan registry: when the `context` supplies no `plan`, the stored plan for the PCActn's `plan.root` and whether it is
    /// executable now (authorized, approval unexpired) feed `plan_root_authorized`, and a plan that is not executable also
    /// fails `plan_state` with the plan's own reason.
    pub plans: Option<&'a PlanRegistry>,
    /// The labels of the verifier's own hooks (attestation, zk, threshold, revocation): they decide what a passing check is
    /// reported to rest on. Labels come from here, never from the presented evidence.
    pub assurance_hooks: Option<&'a AssuranceHooks>,
    /// A high-assurance policy: when the evidence is weaker, missing, failed, unlabelled, awaiting-audit, degraded or unsupported,
    /// the `assurance` check fails (before any replay state is written) and the request is denied.
    pub require_assurance: Option<&'a AssuranceRequirement>,
    /// Checks that may be `unsupported` without denying (today only `bond`, for a PCActn that carries `bond_ref`).
    pub allow_unsupported: &'a [&'a str],
    /// Epoch milliseconds (default: the system clock).
    pub now: Option<i64>,
    /// `Some("single-step")`: accept a one-node plan whose node is exactly this operation. Otherwise `context` must
    /// return the principal-authorized `plan` with `plan_authorized: true`. Any other value is refused.
    pub plan: Option<&'a str>,
    pub context: Option<&'a ContextProvider<'a>>,
    /// Forwarded to the core verifier ([`VerifyOptions::intent`]).
    pub intent_policy: Option<&'a IntentPolicy>,
    pub intent_v2: Option<&'a IntentV2Provider<'a>>,
    /// Forwarded to the core verifier ([`VerifyOptions::allowed`]).
    pub allowed_suites: Option<&'a [String]>,
    /// The `fresh_at` consistency-token policy, forwarded to [`verify_pcactn_core_with_fresh_at`] (default none: a PCActn that
    /// carries the member is then refused, fail closed).
    pub fresh_at: Option<&'a FreshAtPolicy>,
    /// Extra check names that must pass (the defaults always apply).
    pub require: &'a [&'a str],
    /// Pinned principals whose EscalationAnswers count: [`PinnedSigner::ed25519`] for an Ed25519 key, [`PinnedSigner::with_pq`] for
    /// a principal that signs with a post-quantum / hybrid suite (empty: every escalate is refused). A verdict whose every failing
    /// check is escalate-class has `decision == "escalate"`; it is admitted only by `escalation_answer` signed by one of them and
    /// bound to this grant, this PCActn and the holder's history head (the store must implement [`StateStore::last`]); the
    /// replay claim spends it; an answer never upgrades a deny.
    pub escalation_principals: &'a [PinnedSigner],
    pub escalation_answer: Option<&'a Value>,
    /// How long an issued EscalationRequest is valid, in ms (`None`: one hour).
    pub escalation_request_ttl_ms: Option<i64>,
    /// K7: recompute H(R), the canonical approval render digest, from the executed params and the verifier's own definition
    /// (`render_approval` + `approval_render_digest`); `None` from the callback means none could be derived. By default an answer is
    /// admitted only over a recomputed render and must be signed over exactly it.
    pub escalation_render: Option<&'a EscalationRenderFn>,
    /// The documented INSECURE opt-out of that default: accept answers with no recomputed render (an answer that carries a render is
    /// still refused when none was recomputed).
    pub insecure_unbound_approval: bool,
    /// Caveat language v2 (K1), off unless set (a K1 caveat type without it stays unsatisfied, like any unknown type): the verifier's discharge-issuer pins, the
    /// discharges and narrow block presented with the action, the verified SPIFFE ID of the presenting workload and the
    /// holder's history. `action_digest` is always the verifier's own [`discharge_action_digest`] of the PCActn (whatever is
    /// set here is replaced). K1 caveat types are evaluated by `evaluate_k1`, never by the stock evaluators.
    pub k1: Option<&'a K1Input>,
    /// Where K1 `max_uses` caveats are spent (an atomic first-claim store, like `state_store`; a durable shared one makes the
    /// count hold across processes). A chain with a `max_uses` caveat and no store here is refused (fail closed). A use is
    /// spent only for an otherwise admitted action, after the replay claim succeeded.
    pub uses_store: Option<&'a dyn StateStore>,
    /// K5 (C-308): admit the call's workflow step before the replay claim (see [`WorkflowGate`]). Off unless set.
    pub workflow: Option<&'a WorkflowGate>,
    /// The workflow step this call is (read only when `workflow` is set).
    pub workflow_call: Option<&'a WorkflowCall>,
}

/// Names of the required components that are absent (empty = complete), in the order `audience`, `resolve_grant`,
/// `state_store`, `is_revoked`.
pub fn missing_authorize_components(input: &AuthorizeInput<'_>) -> Vec<String> {
    let mut missing = Vec::new();
    if input.audience.is_empty() {
        missing.push("audience".to_string());
    }
    if input.resolve_grant.is_none() {
        missing.push("resolve_grant".to_string());
    }
    if input.state_store.is_none() {
        missing.push("state_store".to_string());
    }
    if input.is_revoked.is_none() {
        missing.push("is_revoked".to_string());
    }
    missing
}

/// The checks in the order they were first reported (the decisive reason follows it).
#[derive(Default)]
struct Checks {
    list: Vec<(String, CheckStatus)>,
    reasons: Vec<String>,
    /// A feature the PCActn carries that this verifier lacks and the caller did not allow: denies without a failing check.
    unsupported_refused: bool,
}

impl Checks {
    fn get(&self, name: &str) -> Option<CheckStatus> {
        self.list.iter().find(|(n, _)| n == name).map(|(_, s)| *s)
    }

    fn mark(&mut self, name: &str, st: CheckStatus) {
        match self.list.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 = st,
            None => self.list.push((name.to_string(), st)),
        }
    }

    fn fail(&mut self, name: &str, why: impl fmt::Display) {
        self.mark(name, CheckStatus::Fail);
        self.reasons.push(format!("{name}: {why}"));
    }

    /// At least one check failed and every failing check has at least one reason `"<check>: <body>"` whose bodies all start
    /// with an escalate prefix (`decision_of(...) == "escalate"`).
    fn all_failures_escalate(&self) -> bool {
        let checks: serde_json::Map<String, Value> =
            self.list.iter().map(|(n, s)| (n.clone(), Value::String(s.as_str().to_string()))).collect();
        let reasons: Vec<Value> = self.reasons.iter().map(|r| Value::String(r.clone())).collect();
        crate::decision::decision_of(&json!({"allow": false, "checks": checks, "reasons": reasons})) == "escalate"
    }

    /// An answered escalation: the escalate-class failures become passes.
    fn promote_failures(&mut self) {
        for (_, s) in self.list.iter_mut() {
            if *s == CheckStatus::Fail {
                *s = CheckStatus::Pass;
            }
        }
    }

    fn any_fail(&self) -> bool {
        self.unsupported_refused || self.list.iter().any(|(_, s)| *s == CheckStatus::Fail)
    }

    /// The decisive reason: the first failing check (an `operation` failure first, then `plan_state`) with a reason of its own.
    fn decisive(&self) -> String {
        let ops = self.list.iter().filter(|(n, _)| n == "operation");
        let plan = self.list.iter().filter(|(n, _)| n == "plan_state");
        let rest = self.list.iter().filter(|(n, _)| n != "operation" && n != "plan_state");
        for (n, s) in ops.chain(plan).chain(rest) {
            if *s != CheckStatus::Fail {
                continue;
            }
            let prefix = format!("{n}:");
            if let Some(r) = self.reasons.iter().find(|r| r.starts_with(&prefix)) {
                return r.clone();
            }
        }
        self.reasons.first().cloned().unwrap_or_else(|| "denied".to_string())
    }

    fn map(&self) -> BTreeMap<String, CheckStatus> {
        self.list.iter().cloned().collect()
    }
}

/// The check statuses as the report names them (the chain check is `cap_chain` in the reference).
fn report_statuses(list: &[(String, CheckStatus)]) -> Vec<(String, CheckStatus)> {
    list.iter().map(|(n, s)| (if n == "chain" { "cap_chain".to_string() } else { n.clone() }, *s)).collect()
}

/// The report of a result decided before any verification ran: `{ <check>: { outcome } }` per recorded check.
fn bare_report(checks: &BTreeMap<String, CheckStatus>) -> AssuranceReport {
    let mut r = AssuranceReport::new();
    for (n, s) in checks {
        r.set(n, CheckAssurance::new(*s));
    }
    r
}

fn refuse(status: u16, check: &str, reason: String, missing: Option<Vec<String>>, pcactn: Option<&Value>) -> AuthorizeResult {
    let mut checks = BTreeMap::new();
    checks.insert(check.to_string(), CheckStatus::Fail);
    AuthorizeResult {
        allow: false,
        status,
        assurance: bare_report(&checks),
        checks,
        reasons: vec![reason.clone()],
        reason: Some(reason),
        operation: None,
        pcactn: pcactn.cloned(),
        verdict: None,
        missing,
        decision: "deny",
        escalation: None,
        degraded: BTreeMap::new(),
    }
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn class_rank(c: Option<&Value>) -> u8 {
    match c.and_then(Value::as_str) {
        Some("reversible") => 0,
        Some("rate_limited") | Some("costly") => 1,
        _ => 2,
    }
}

/// `String(v)` as the Python reference prints an absent member (`None` -> "null").
fn js_or_null(v: Option<&Value>) -> String {
    v.map(js_value_string).unwrap_or_else(|| "null".to_string())
}

enum Presented<'a> {
    Value(Option<&'a Value>),
    Text(&'a str),
}

/// Authorize ONE operation (see the module doc for the pipeline). `pcactn` is the presented PCActn as parsed JSON
/// (`None` when absent); use [`authorize_json`] for its raw text. Never panics: an internal error denies (403,
/// check `authorize`).
pub fn authorize(pcactn: Option<&Value>, input: &AuthorizeInput<'_>) -> AuthorizeResult {
    guarded(Presented::Value(pcactn), input)
}

/// [`authorize`] for the PCActn's JSON text (strict profile, at most [`MAX_ARTIFACT_BYTES`]); undecodable text is a
/// 401 `wire` failure.
pub fn authorize_json(text: &str, input: &AuthorizeInput<'_>) -> AuthorizeResult {
    guarded(Presented::Text(text), input)
}

fn guarded(src: Presented<'_>, input: &AuthorizeInput<'_>) -> AuthorizeResult {
    catch_unwind(AssertUnwindSafe(|| authorize_inner(src, input)))
        .unwrap_or_else(|_| refuse(403, "authorize", "authorize: error (fail closed): internal panic".into(), None, None))
}

/// The `plan_root_authorized` decision. Default-deny: with no plan configured (`nodes` is `None`) it FAILS, unless the explicit,
/// loudly named `insecure_skip_plan_root_check` is set, which reports `not-enforced`. Returns the status and, on failure, the reason.
/// [`authorize`] always passes `false` for the opt-out.
pub fn plan_root_check(nodes: Option<&Value>, authorized: bool, signed_root: Option<&str>, insecure_skip_plan_root_check: bool) -> (CheckStatus, Option<String>) {
    let fail = |why: &str| (CheckStatus::Fail, Some(why.to_string()));
    match nodes {
        Some(nodes) => {
            let known = known_plan_root(nodes);
            if known.is_none() || known.as_deref() != signed_root {
                fail("known plan does not match plan.root")
            } else if !authorized {
                fail("the plan root has not been authorized by the principal")
            } else {
                (CheckStatus::Pass, None)
            }
        }
        None if insecure_skip_plan_root_check => (CheckStatus::NotEnforced, None),
        None => fail("default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecure_skip_plan_root_check)"),
    }
}

/// The single-step / context plan's Merkle root (`None` when a node is malformed).
fn known_plan_root(nodes: &Value) -> Option<String> {
    let mut leaves = Vec::new();
    for n in nodes.as_array()? {
        let n = n.as_object()?;
        if !n.contains_key("verb") || !n.contains_key("resource") {
            return None;
        }
        let pre = n.get("pre").cloned().unwrap_or(Value::Null);
        let post = n.get("post").cloned().unwrap_or(Value::Null);
        let cond = hash_canonical_strict(&json!({"pre": pre, "post": post}))?;
        leaves.push(plan_leaf(n.get("id"), Some(n), &cond)?);
    }
    merkle_root(&leaves).ok()
}

/// The grant's envelope carries `units` / `tighten` / `model_polarity`, or a grant-side `where` reads a model-derived path.
fn needs_model_rules(grant: &Value) -> bool {
    match read_envelope(grant) {
        None => false,
        Some(e) => {
            ["units", "tighten", "model_polarity"].iter().any(|k| e.contains_key(*k))
                || !crate::decision::model_paths_read(&[e.get("predicates").cloned().unwrap_or(Value::Null)], &[]).is_empty()
        }
    }
}

/// The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (TypeScript `v2Env`).
fn v2_env(p: &Value, grant: &Value, v2: Option<&IntentV2Context>, now: i64, env: Option<&Value>) -> Option<Value> {
    if p.get("intent_session").is_none() {
        return env.filter(|e| !e.is_null()).cloned();
    }
    let mut rest = env.and_then(Value::as_object).cloned().unwrap_or_default();
    for k in ["acc", "mon", "canon", "world", "prov", "class"] {
        rest.remove(k);
    }
    for (k, v) in decide_intent_v2(p, grant, v2, now).env {
        if !v.is_null() {
            rest.insert(k, v);
        }
    }
    Some(Value::Object(rest))
}

/// `evaluatePredicates(...)` with its denial reason: default deny, an empty list allows nothing.
fn envelope_predicates_denial(predicates: &[Value], action_ctx: &Value) -> Option<String> {
    if predicates.is_empty() {
        return Some("envelope grants no predicates".into());
    }
    let ctx = Ctx::new(action_ctx);
    if predicates.iter().any(|p| predicate_matches(p, &ctx)) {
        return None;
    }
    let a = action_ctx.get("action");
    let part = |k: &str| a.and_then(|a| a.get(k)).map(js_value_string).unwrap_or_else(|| "undefined".to_string());
    if let Some(limit) = first_unmet_limit(predicates, &ctx) {
        return Some(format!("{limit} not satisfied for {} on {}", part("verb"), part("resource")));
    }
    Some(format!("no predicate permits {} on {}", part("verb"), part("resource")))
}

fn policy_step(env: Option<&Map<String, Value>>, grant: &Value, cctx: &Value, action_ctx: &Value, tool_call: &Value, k1_on: bool) -> Vec<String> {
    let env = match env {
        Some(e) => e,
        None => return vec!["grant carries no valid envelope".to_string()],
    };
    let mut why = Vec::new();
    let preds = env.get("predicates").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    if let Some(d) = envelope_predicates_denial(preds, action_ctx) {
        why.push(d);
    }
    let (ok, failed) = evaluate_agent_caveats(env.get("caveats").unwrap_or(&Value::Null), cctx, Some(action_ctx), Some(tool_call));
    if !ok {
        why.push(format!("caveat(s) not satisfied: {}", failed.join(", ")));
    }
    // with K1 on, its types are evaluated over the chain by `evaluate_k1` (authorize_inner), not by the stock evaluator
    let root = match root_caveats(grant) {
        Value::Array(list) if k1_on => Value::Array(list.into_iter().filter(|c| !is_k1_caveat(c)).collect()),
        other => other,
    };
    let (ok, failed) = evaluate_agent_caveats(&root, cctx, Some(action_ctx), Some(tool_call));
    if !ok {
        why.push(format!("root caveat(s) not satisfied: {}", failed.join(", ")));
    }
    why
}

fn authorize_inner(src: Presented<'_>, input: &AuthorizeInput<'_>) -> AuthorizeResult {
    let mut missing = missing_authorize_components(input);
    if input.plan.is_some_and(|p| p != SINGLE_STEP) {
        missing.push("plan (only 'single-step' or None)".to_string());
    }
    if !missing.is_empty() {
        let why = format!("authorize_config: missing required component(s): {} (fail closed)", missing.join(", "));
        return refuse(403, "authorize_config", why, Some(missing), None);
    }
    let (resolve_grant, state_store, is_revoked) = match (input.resolve_grant, input.state_store, input.is_revoked) {
        (Some(r), Some(s), Some(i)) => (r, s, i),
        _ => return refuse(403, "authorize_config", "authorize_config: missing required component(s) (fail closed)".into(), None, None),
    };
    let operation = match input.operation.filter(|o| o.is_valid()) {
        Some(o) => o,
        None => {
            let why = "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)";
            return refuse(403, "operation", why.into(), None, None);
        }
    };
    // a private copy: the params that are verified cannot change under the verifier
    let params = match canonicalize_strict(&operation.params).and_then(|t| strict_parse(&t)) {
        Ok(v) => v,
        Err(e) => return refuse(403, "authorize", format!("authorize: error (fail closed): {e}"), None, None),
    };
    let op = Operation::new(operation.verb.clone(), operation.resource.clone(), params);

    // K5 workflow, required and absent: refused before the PCActn is read (it needs no PCActn).
    if input.workflow.is_some_and(|w| w.required) && input.workflow_call.is_none() {
        return refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)".into(), None, None);
    }
    let undecodable = || refuse(401, "pcactn", "undecodable PCActn: could not be decoded".into(), None, None);
    let p: Value = match src {
        Presented::Value(Some(v)) if v.is_object() => v.clone(),
        Presented::Value(None) => return refuse(401, "wire", "wire: no PCActn presented".into(), None, None),
        Presented::Text(t) if t.len() <= MAX_ARTIFACT_BYTES => match strict_parse(t) {
            Ok(v) if v.is_object() => v,
            _ => return undecodable(),
        },
        _ => return undecodable(),
    };
    let grant_ref = match p.get("grant_ref") {
        Some(Value::String(s)) => s.clone(),
        _ => return refuse(401, "malformed", "malformed: grant_ref is not a string".into(), None, Some(&p)),
    };
    let grant = match catch_unwind(AssertUnwindSafe(|| resolve_grant(&grant_ref))) {
        Ok(Ok(Some(g))) if g.is_object() => g,
        Ok(Ok(_)) => return refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant".into(), None, Some(&p)),
        _ => return refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)".into(), None, Some(&p)),
    };

    let now = input.now.unwrap_or_else(system_now);
    let mut ctx = Map::new();
    if let Some(f) = input.context {
        match catch_unwind(AssertUnwindSafe(|| f(&p))) {
            Ok(Ok(None)) | Ok(Ok(Some(Value::Null))) => {}
            Ok(Ok(Some(Value::Object(m)))) => ctx = m,
            Ok(Ok(Some(_))) => {
                let why = "context: the context callback must return a dict (fail closed)";
                return refuse(403, "context", why.into(), None, Some(&p));
            }
            _ => return refuse(403, "context", "context: the context callback failed (fail closed)".into(), None, Some(&p)),
        }
    }
    // K5 workflow admission (C-308): BEFORE any replay state is touched, so a refusal never consumes the PCActn's counter.
    if let Some(w) = input.workflow {
        match input.workflow_call {
            None => {} // not required (a required, absent step was refused above)
            Some(c) => {
                // an unreadable plan root stays null, which cannot equal a committed root
                let root = p.get("plan").and_then(|pl| pl.get("root")).filter(|v| v.is_string()).cloned().unwrap_or(Value::Null);
                let units = if c.units.is_null() { json!({}) } else { c.units.clone() };
                let request = json!({ "step": c.step, "verb": op.verb, "resource": op.resource, "params": op.params, "units": units, "goal_digest": c.goal_digest, "plan_root": root });
                let (pv, rv, nv) = (json!(w.principal), json!(w.rs_signer), json!(now));
                let d = admit_step(&AdmitInput { workflow: &c.commitment, principal: &pv, rs_signer: &rv, receipts: &c.receipts, now: &nv, request: &request });
                if d.decision != WfDecision::Allow {
                    let at = d.step.as_deref().filter(|s| !s.is_empty()).map(|s| format!(" (step {s})")).unwrap_or_default();
                    let mut res = refuse(403, "workflow", format!("workflow: {}{at}", d.code.unwrap_or("refused")), None, Some(&p));
                    if d.decision == WfDecision::Escalate {
                        // an escalate with no request to answer: allow stays false, `escalation` stays None
                        res.decision = "escalate";
                    }
                    return res;
                }
            }
        }
    }
    let mut plan_status: Option<PlanStatus> = None;
    if let Some(reg) = input.plans {
        if ctx.get("plan").is_none_or(Value::is_null) {
            let root = p.get("plan").and_then(|pl| pl.get("root")).and_then(Value::as_str).unwrap_or("");
            if let Some(pc) = reg.context(&grant_ref, root, Some(now)) {
                ctx.insert("plan".into(), Value::Array(pc.plan));
                ctx.insert("plan_authorized".into(), Value::Bool(pc.plan_authorized));
                plan_status = Some(pc.status);
            }
        }
    }
    let mut v2: Option<IntentV2Context> = None;
    if let Some(f) = input.intent_v2 {
        match catch_unwind(AssertUnwindSafe(|| f(&p))) {
            Ok(Ok(c)) => v2 = c,
            _ => return refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)".into(), None, Some(&p)),
        }
    }
    // Rules 20 / 21 read the signed envelope of the stored grant: when it carries `units` / `tighten` / `model_polarity` or a
    // grant-side `where` reads a model-derived path, the v2 pipeline needs the plaintext params and the host env even if the
    // host configured no v2 context (TypeScript `needsModelRules`).
    if v2.is_none() && needs_model_rules(&grant) {
        v2 = IntentV2Context::from_json(&Value::Object(Map::new()));
    }
    if let Some(Value::Object(m)) = v2.as_ref().map(IntentV2Context::as_json) {
        let mut m = m.clone();
        let mut changed = false;
        if m.get("params").is_none_or(Value::is_null) {
            m.insert("params".into(), op.params.clone());
            changed = true;
        }
        if m.get("env").is_none_or(Value::is_null) {
            // `intentV2.env ?? ctx.env`: a null env is the authorize context's (a non-object one is malformed)
            if m.remove("env").is_some() {
                changed = true;
            }
            if let Some(e) = ctx.get("env").filter(|e| !e.is_null()) {
                m.insert("env".into(), e.clone());
                changed = true;
            }
        }
        if changed {
            v2 = IntentV2Context::from_json(&Value::Object(m));
        }
    }

    // ---- 1. the core checks
    let opts = VerifyOptions { allowed: input.allowed_suites, intent: input.intent_policy, intent_v2: v2.as_ref() };
    #[allow(unused_mut)]
    let mut core = verify_pcactn_core_with_fresh_at(&p, &grant, now, input.audience, &opts, input.fresh_at);
    let core_legacy = core.legacy_model_polarity;
    if let Some(h) = CORE_HOOK.lock().ok().and_then(|g| *g) {
        h(&mut core);
    }
    if core.checks.get("wire") == Some(&false) {
        let r = if core.reason.is_empty() { "wire: malformed PCActn".to_string() } else { core.reason.clone() };
        let mut checks = BTreeMap::new();
        checks.insert("wire".to_string(), CheckStatus::Fail);
        checks.insert("malformed".to_string(), CheckStatus::Fail);
        return AuthorizeResult {
            allow: false,
            status: 401,
            assurance: bare_report(&checks),
            checks,
            reasons: vec![r.clone()],
            reason: Some(r),
            operation: None,
            pcactn: Some(p),
            verdict: Some(core),
            missing: None,
            decision: "deny",
            escalation: None,
            degraded: BTreeMap::new(),
        };
    }
    let mut ck = Checks::default();
    let status_of = |ok: bool| if ok { CheckStatus::Pass } else { CheckStatus::Fail };
    for name in CORE_ORDER {
        if let Some(ok) = core.checks.get(name) {
            ck.mark(name, status_of(*ok));
        }
    }
    for (name, ok) in &core.checks {
        if !CORE_ORDER.contains(&name.as_str()) {
            ck.mark(name, status_of(*ok));
        }
    }
    if !core.allow {
        if !core.reasons.is_empty() {
            // the first failure, then every further failing v2 check: the whole set decides escalate vs deny
            ck.reasons.extend(core.reasons.iter().cloned());
        } else if !core.reason.is_empty() {
            ck.reasons.push(core.reason.clone());
        }
    }

    // a feature the PCActn carries that this verifier does not implement is reported `unsupported`, never a pass, and denies
    // unless the caller listed it
    if p.get("bond_ref").is_some() {
        ck.mark("bond", CheckStatus::Unsupported);
        if !input.allow_unsupported.contains(&"bond") {
            ck.unsupported_refused = true;
            ck.reasons.push("bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)".into());
        }
    }

    // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
    match catch_unwind(AssertUnwindSafe(|| is_revoked(&p, &grant))) {
        Ok(Ok(false)) => match input.revocation_staleness {
            None => ck.mark("revocation", CheckStatus::Pass),
            Some(gate) => {
                let server_class = ctx.get("reversibility_class").and_then(Value::as_str);
                match catch_unwind(AssertUnwindSafe(|| gate.check(&p, &grant, server_class, now as f64))) {
                    Ok(Ok(())) => ck.mark("revocation", CheckStatus::Pass),
                    Ok(Err(why)) => ck.fail("revocation", why),
                    Err(_) => ck.fail("revocation", "the revocation staleness check failed (fail closed)"),
                }
            }
        },
        Ok(Ok(true)) => ck.fail("revocation", "the grant is revoked"),
        _ => ck.fail("revocation", "the revocation check failed (fail closed)"),
    }
    if p.get("zk_compliance").is_some() {
        ck.fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)");
    }

    let empty = Map::new();
    let action = p.get("action").and_then(Value::as_object).unwrap_or(&empty);
    let signed_digest = action.get("params_digest").and_then(Value::as_str);
    let op_digest = match hash_canonical_strict(&op.params) {
        Some(d) => d,
        None => return refuse(403, "authorize", "authorize: error (fail closed): params digest".into(), None, Some(&p)),
    };

    // ---- 3. the operation binding
    if action.get("verb").and_then(Value::as_str) != Some(op.verb.as_str())
        || action.get("resource").and_then(Value::as_str) != Some(op.resource.as_str())
    {
        let why = format!(
            "the proof is for {} on {}, but this operation is {} on {}",
            js_or_null(action.get("verb")),
            js_or_null(action.get("resource")),
            op.verb,
            op.resource
        );
        ck.fail("operation", why);
    } else if signed_digest != Some(op_digest.as_str()) {
        ck.fail("operation", format!("the proof's params_digest does not match the params of this {} operation", op.verb));
    } else {
        ck.mark("operation", CheckStatus::Pass);
    }

    // ---- 4. grant_ref, params, plan, attestation, reversibility
    if grant.get("id").and_then(Value::as_str) == Some(grant_ref.as_str()) {
        ck.mark("grant_ref", CheckStatus::Pass);
    } else {
        ck.fail("grant_ref", "does not reference the supplied grant");
    }
    if signed_digest == Some(op_digest.as_str()) {
        ck.mark("params_digest", CheckStatus::Pass);
    } else {
        ck.fail("params_digest", "supplied params do not hash to action.params_digest");
    }

    let pl = p.get("plan").and_then(Value::as_object).unwrap_or(&empty);
    let node_id = pl.get("node_id");
    let mut plan_nodes: Option<Value> = ctx.get("plan").filter(|v| !v.is_null()).cloned();
    let mut plan_authorized = ctx.get("plan_authorized") == Some(&Value::Bool(true));
    if input.plan == Some(SINGLE_STEP) && plan_nodes.is_none() {
        plan_nodes = Some(json!([{
            "id": js_or_null(node_id), "verb": op.verb, "resource": op.resource, "params_digest": op_digest,
            "reversibility_class": action.get("reversibility_class").cloned().unwrap_or(Value::Null),
        }]));
        plan_authorized = true;
    }
    // `authorize` never accepts the opt-out: a verifier with no authorized plan configured refuses.
    match plan_root_check(plan_nodes.as_ref(), plan_authorized, pl.get("root").and_then(Value::as_str), false) {
        (st, None) => ck.mark("plan_root_authorized", st),
        (_, Some(why)) => ck.fail("plan_root_authorized", why),
    }
    if let Some(ps) = &plan_status {
        if ps.executable {
            ck.mark("plan_state", CheckStatus::Pass);
        } else {
            ck.fail("plan_state", ps.reason.clone().unwrap_or_else(|| format!("plan is {}", ps.state)));
        }
    }

    let env = read_envelope(&grant);
    if requires_attestation(env.as_ref().and_then(|e| e.get("agent_binding"))) {
        ck.fail(
            "attestation",
            "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)",
        );
    }

    let declared = action.get("reversibility_class").filter(|v| !v.is_null()).cloned();
    let mut effective = declared.clone();
    if let Some(server_class) = ctx.get("reversibility_class").filter(|v| !v.is_null()) {
        let (dr, sr) = (class_rank(declared.as_ref()), class_rank(Some(server_class)));
        if dr < sr {
            let why = format!(
                "declared class '{}' is less restrictive than the authoritative '{}'",
                js_or_null(declared.as_ref()),
                js_value_string(server_class)
            );
            ck.fail("reversibility", why);
        } else {
            ck.mark("reversibility", CheckStatus::Pass);
        }
        effective = if dr > sr { declared.clone() } else { Some(server_class.clone()) };
    }

    // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
    let empty_chain = Vec::new();
    let chain = p.get("cap_chain").and_then(Value::as_array).unwrap_or(&empty_chain);
    let depth = chain.len().saturating_sub(1);
    let mut inner = Map::new();
    inner.insert("verb".into(), action.get("verb").cloned().unwrap_or(Value::Null));
    inner.insert("resource".into(), action.get("resource").cloned().unwrap_or(Value::Null));
    inner.insert("params".into(), op.params.clone());
    if let Some(e) = &effective {
        inner.insert("reversibility_class".into(), e.clone());
    }
    let inner = Value::Object(inner);
    let mut actx = Map::new();
    actx.insert("action".into(), inner.clone());
    if let Some(s) = ctx.get("subject").filter(|v| !v.is_null()) {
        actx.insert("subject".into(), s.clone());
    }
    if let Some(e) = v2_env(&p, &grant, v2.as_ref(), now, ctx.get("env")) {
        actx.insert("env".into(), e);
    }
    let action_ctx = Value::Object(actx);
    let mut tc = Map::new();
    tc.insert("tool".into(), Value::String(inner["verb"].as_str().unwrap_or("").to_string()));
    tc.insert("args".into(), op.params.clone());
    if let Some(Value::String(b)) = p.get("tool_binding") {
        tc.insert("tool_signature_digest".into(), Value::String(b.clone()));
    }
    let tool_call = Value::Object(tc);
    let mut rev_class = effective.clone();
    if rev_class.is_none() && node_id.is_some_and(Value::is_string) {
        if let Some(nodes) = plan_nodes.as_ref().and_then(Value::as_array) {
            rev_class = nodes
                .iter()
                .find(|n| n.is_object() && n.get("id") == node_id)
                .and_then(|n| n.get("reversibility_class"))
                .filter(|v| !v.is_null())
                .cloned();
        }
    }
    let mut c = Map::new();
    c.insert("now".into(), json!(now));
    c.insert("action".into(), inner.clone());
    c.insert("delegation_depth".into(), json!(depth));
    if let Some(b) = ctx.get("blast_radius").filter(|v| !v.is_null()) {
        c.insert("blast_radius".into(), b.clone());
    }
    if let Some(r) = rev_class {
        c.insert("reversibility_class".into(), r);
    }
    if let Some(t) = ctx.get("recent_action_times").filter(|v| !v.is_null()) {
        c.insert("recent_action_times".into(), t.clone());
    }
    let cctx = Value::Object(c);

    // Caveat language v2 (K1): evaluated whenever any hop carries a K1 caveat type (or a narrow block is presented). Without an
    // `input.k1` the evaluator refuses every K1 caveat of every hop ("not configured"), so no path leaves one to a stock evaluator.
    let chain_v = p.get("cap_chain").unwrap_or(&Value::Null);
    let any_k1 = std::iter::once(&grant)
        .chain(chain.iter())
        .any(|h| h.get("caveats").and_then(Value::as_array).is_some_and(|cs| cs.iter().any(is_k1_caveat)));
    let k1_result = if any_k1 || input.k1.is_some_and(|k| k.narrow.is_some()) {
        let mut k1 = input.k1.cloned();
        if let Some(k) = k1.as_mut() {
            k.action_digest = discharge_action_digest(&p);
        }
        Some(evaluate_k1(&grant, chain_v, k1.as_ref(), &K1Ctx { now, action: Some(&inner) }))
    } else {
        None
    };
    let k1_report = |mut failed: Vec<String>| {
        let mut why = String::new();
        if let Some(k) = k1_result.as_ref().filter(|k| !k.ok) {
            failed.extend(k.failed.iter().cloned());
            why = format!(" ({})", k.reasons.join("; "));
        }
        format!("delegation caveat(s) not satisfied: {}{}", failed.join(", "), why)
    };
    let k1_ok = k1_result.as_ref().map_or(true, |k| k.ok);
    let k1_plain: Vec<Value> = k1_result.as_ref().map(|k| k.plain.clone()).unwrap_or_default();
    if let Some(leaf) = chain.last() {
        let gcs = grant.get("caveats").and_then(Value::as_array).map_or(0, Vec::len);
        let mut extra = match leaf.get("caveats").and_then(Value::as_array) {
            Some(cs) => Value::Array(cs.get(gcs..).unwrap_or(&[]).to_vec()),
            None => Value::Null,
        };
        if k1_result.is_some() {
            if let Value::Array(list) = &mut extra {
                list.retain(|c| !is_k1_caveat(c));
                list.extend(k1_plain.iter().cloned());
            }
        }
        let (ok, failed) = evaluate_agent_caveats(&extra, &cctx, Some(&action_ctx), Some(&tool_call));
        if ok && k1_ok {
            ck.mark("delegated_caveats", CheckStatus::Pass);
        } else {
            ck.fail("delegated_caveats", k1_report(failed));
        }
    } else if k1_result.is_some() {
        // no hop beyond the grant: the grant's own K1 caveats (and a narrow block's plain caveats) still apply
        let (ok, failed) = evaluate_agent_caveats(&Value::Array(k1_plain.clone()), &cctx, Some(&action_ctx), Some(&tool_call));
        if ok && k1_ok {
            ck.mark("delegated_caveats", CheckStatus::Pass);
        } else {
            ck.fail("delegated_caveats", k1_report(failed));
        }
    }

    let policy_why = catch_unwind(AssertUnwindSafe(|| with_regex_budget(|| policy_step(env.as_ref(), &grant, &cctx, &action_ctx, &tool_call, k1_result.is_some()))))
        .unwrap_or_else(|_| vec!["policy evaluation error (fail closed)".to_string()]);
    if policy_why.is_empty() {
        ck.mark("policy", CheckStatus::Pass);
    } else {
        ck.mark("policy", CheckStatus::Fail);
        ck.reasons.extend(policy_why.iter().map(|w| format!("policy: {w}")));
    }

    // ---- required checks (default-deny), then the replay claim. `replay` passes tentatively and flips to fail when the
    // store refuses the claim below. A `require` entry `counter` is the 0.4 name of `replay`.
    // what each check rests on, from the verifier's own labels (replay is not decided yet, as in the reference)
    let degraded_pairs: Vec<(String, String)> =
        if core_legacy && ck.get("tighten") == Some(CheckStatus::Pass) { vec![("tighten".to_string(), LEGACY_POLARITY_DEGRADED.to_string())] } else { Vec::new() };
    let no_hooks = AssuranceHooks::default();
    let base_report = assurance_report(&AssuranceSources {
        checks: &report_statuses(&ck.list),
        pcactn: Some(&p),
        hooks: Some(input.assurance_hooks.unwrap_or(&no_hooks)),
        attestation_hook: None,
        threshold_t: None,
        allow_unbound_pq: false,
        degraded: &degraded_pairs,
    });
    if let Some(req) = input.require_assurance {
        match unmet_assurance(&base_report, req) {
            None => ck.mark("assurance", CheckStatus::Pass),
            Some(unmet) => {
                ck.mark("assurance", CheckStatus::Fail);
                ck.reasons.push(unmet);
            }
        }
    }
    let final_report = |ck: &Checks| {
        let mut r = base_report.clone();
        refresh_assurance(&mut r, &report_statuses(&ck.list));
        r
    };

    ck.mark("replay", CheckStatus::Pass);
    let required: Vec<&str> = DEFAULT_REQUIRED_CHECKS
        .iter()
        .copied()
        .chain(input.require.iter().map(|n| if *n == "counter" { "replay" } else { *n }))
        .collect();
    for name in required {
        let st = ck.get(name);
        if st != Some(CheckStatus::Pass) && st != Some(CheckStatus::Fail) {
            let shown = st.map_or("absent", |s| s.as_str());
            ck.mark(name, CheckStatus::Fail);
            ck.reasons.push(format!("{name}: required check is {shown} (default-deny: not enforced by this resource server)"));
        }
    }

    let deny = |ck: &Checks, core: Verdict, p: Value, escalation: Option<Value>| {
        let status = if AUTHN_CHECKS.iter().any(|c| ck.get(c) == Some(CheckStatus::Fail)) { 401 } else { 403 };
        AuthorizeResult {
            allow: false,
            status,
            assurance: final_report(ck),
            checks: ck.map(),
            reasons: ck.reasons.clone(),
            reason: Some(ck.decisive()),
            operation: None,
            pcactn: Some(p),
            verdict: Some(core),
            missing: None,
            decision: if escalation.is_some() { "escalate" } else { "deny" },
            escalation,
            degraded: BTreeMap::new(),
        }
    };
    let holder = chain.last().and_then(|l| l.get("holder")).and_then(Value::as_str);
    let grant_id = grant.get("id").and_then(Value::as_str);
    let mut answered_by: Option<String> = None;
    if ck.any_fail() {
        // Ternary decision: escalate only when every failing check is escalate-class. Never admitted by itself.
        let (h, g) = match (holder, grant_id) {
            (Some(h), Some(g)) if ck.all_failures_escalate() => (h, g),
            _ => return deny(&ck, core, p, None),
        };
        let key = state_key(g, h);
        let last = catch_unwind(AssertUnwindSafe(|| state_store.last(&key))).unwrap_or(None);
        let render_digest: Option<String> = input.escalation_render.and_then(|f| catch_unwind(AssertUnwindSafe(|| f(&p))).ok().flatten());
        let req = match build_escalation_request_with_render(input.audience, &grant, &p, last.flatten(), &ck.reasons, now, input.escalation_request_ttl_ms, render_digest.as_deref()) {
            Some(r) => r,
            None => return deny(&ck, core, p, None),
        };
        let mut admitted = false;
        if let (false, Some(_), Some(_), None, false) = (input.escalation_principals.is_empty(), input.escalation_answer, last, &render_digest, input.insecure_unbound_approval) {
            // K7 default: an answer is admitted only over a render the verifier recomputed
            ck.reasons.push("escalation: an approval render is required and none could be recomputed (set escalation_render, or insecure_unbound_approval)".into());
        } else if let (false, Some(answer), Some(last)) = (input.escalation_principals.is_empty(), input.escalation_answer, last) {
            if let (Some(pd), Some(ad), Some(hh)) = (escalation_policy_digest(&grant), escalation_action_digest(&p), escalation_history_head(last)) {
                match verify_escalation_answer(answer, input.escalation_principals, &EscalationBinding { policy_digest: pd, action_digest: ad, history_head: hh, render_digest: render_digest.clone() }, now) {
                    EscalationVerdict::Ok { principal, decision } if decision == "allow" => {
                        ck.promote_failures();
                        ck.mark("escalation", CheckStatus::Pass);
                        ck.reasons.push(format!("escalation: answered allow by principal {}", principal.chars().take(8).collect::<String>()));
                        answered_by = Some(principal);
                        admitted = true;
                    }
                    EscalationVerdict::Ok { .. } => ck.reasons.push("escalation: the principal answered deny".into()),
                    EscalationVerdict::Refused(why) => ck.reasons.push(format!("escalation: {why}")),
                }
            }
        }
        if !admitted {
            return deny(&ck, core, p, Some(req));
        }
    }

    let counter = p.get("counter").and_then(safe_int).and_then(|c| u64::try_from(c).ok());
    let (holder, grant_id, counter) = match (holder, grant_id, counter) {
        (Some(h), Some(g), Some(c)) => (h, g, c),
        _ => {
            ck.fail("replay", "no counter stream for this proof (fail closed)");
            return deny(&ck, core, p, None);
        }
    };
    match catch_unwind(AssertUnwindSafe(|| state_store.claim(&state_key(grant_id, holder), counter))) {
        Ok(Ok(c)) if c.ok => {}
        Ok(Ok(ClaimResult { last_counter: Some(last), .. })) => {
            ck.fail("replay", format!("{counter} is not greater than last seen {last} (replay)"));
            return deny(&ck, core, p, None);
        }
        Ok(Ok(_)) => {
            ck.fail("replay", format!("{counter} was already claimed (replay)"));
            return deny(&ck, core, p, None);
        }
        _ => {
            ck.fail("replay", "the replay store failed (fail closed)");
            return deny(&ck, core, p, None);
        }
    }
    // K1 `max_uses` is spent only for an action that is otherwise admitted, after the counter above accepted it
    if let Some(k) = k1_result.as_ref().filter(|k| k.bound.iter().any(|b| b.caveat.get("type").and_then(Value::as_str) == Some(CAVEAT_MAX_USES))) {
        let why = match input.uses_store {
            None => Some("max_uses: the chain carries a max_uses caveat and no uses_store is configured (fail closed)".to_string()),
            Some(store) => match reserve_max_uses(store, &k.bound, now) {
                UsesVerdict::Ok { .. } => None,
                UsesVerdict::Fail { reason } => Some(format!("max_uses: {reason}")),
            },
        };
        if let Some(why) = why {
            ck.fail("max_uses", why);
            return deny(&ck, core, p, None);
        }
    }
    let id = hash_canonical_strict(&p).unwrap_or_else(|| hash_canonical(&p));
    AuthorizeResult {
        allow: true,
        status: 200,
        assurance: final_report(&ck),
        checks: ck.map(),
        reasons: ck.reasons.clone(),
        reason: None,
        operation: Some(AuthorizedOperation { verb: op.verb, resource: op.resource, params_digest: op_digest, id }),
        pcactn: Some(p),
        verdict: Some(core),
        missing: None,
        decision: "allow",
        escalation: answered_by.map(|a| json!({ "answered_by": a })),
        degraded: if core_legacy && ck.get("tighten") == Some(CheckStatus::Pass) {
            BTreeMap::from([("tighten".to_string(), LEGACY_POLARITY_DEGRADED.to_string())])
        } else {
            BTreeMap::new()
        },
    }
}

/// True only if `result` allowed exactly this operation (verb, resource, params digest). Call it where the side effect
/// runs, with the values it is about to use.
pub fn is_authorized_for(result: &AuthorizeResult, operation: &Operation) -> bool {
    let b = match &result.operation {
        Some(b) if result.allow => b,
        _ => return false,
    };
    if !operation.is_valid() {
        return false;
    }
    b.verb == operation.verb && b.resource == operation.resource && hash_canonical_strict(&operation.params).as_deref() == Some(b.params_digest.as_str())
}

/// K7: `|pcactn| Some(H(R))`, the verifier's recomputation of the approval render digest (see [`AuthorizeInput::escalation_render`]).
pub type EscalationRenderFn = dyn Fn(&Value) -> Option<String> + Send + Sync;
type SharedRevocationCheck = dyn Fn(&Value, &Value) -> Result<bool, String> + Send + Sync;
type SharedContextProvider = dyn Fn(&Value) -> Result<Option<Value>, String> + Send + Sync;

/// The [`authorize`] components a guard adds on top of its audience and grant resolver (the opt-in of the `axum`
/// middleware's `GuardConfig::with_authorize`). `plan` defaults to `"single-step"`.
#[derive(Clone)]
pub struct AuthorizeOptions {
    state_store: Arc<dyn StateStore>,
    is_revoked: Arc<SharedRevocationCheck>,
    plan: Option<String>,
    context: Option<Arc<SharedContextProvider>>,
    require: Vec<String>,
    escalation_principals: Vec<PinnedSigner>,
    escalation_request_ttl_ms: Option<i64>,
    escalation_render: Option<Arc<EscalationRenderFn>>,
    insecure_unbound_approval: bool,
    revocation_staleness: Option<RevocationStaleness>,
    plans: Option<Arc<PlanRegistry>>,
    assurance_hooks: Option<AssuranceHooks>,
    require_assurance: Option<AssuranceRequirement>,
    allow_unsupported: Vec<String>,
    k1: Option<K1Input>,
    uses_store: Option<Arc<dyn StateStore>>,
    pub(crate) workflow: Option<WorkflowGate>,
    pub(crate) fresh_at: Option<FreshAtPolicy>,
}

impl AuthorizeOptions {
    /// The replay store and the revocation check are required (see [`AuthorizeInput`]).
    pub fn new(
        state_store: Arc<dyn StateStore>,
        is_revoked: impl Fn(&Value, &Value) -> Result<bool, String> + Send + Sync + 'static,
    ) -> Self {
        AuthorizeOptions { state_store, is_revoked: Arc::new(is_revoked), plan: Some(SINGLE_STEP.to_string()), context: None, require: Vec::new(), escalation_principals: Vec::new(), escalation_request_ttl_ms: None, escalation_render: None, insecure_unbound_approval: false, revocation_staleness: None, plans: None, assurance_hooks: None, require_assurance: None, allow_unsupported: Vec::new(), k1: None, uses_store: None, workflow: None, fresh_at: None }
    }

    /// The labels of this verifier's hooks (see [`AuthorizeInput::assurance_hooks`]).
    pub fn with_assurance_hooks(mut self, hooks: AssuranceHooks) -> Self {
        self.assurance_hooks = Some(hooks);
        self
    }

    /// A high-assurance policy (see [`AuthorizeInput::require_assurance`]).
    pub fn with_require_assurance(mut self, req: AssuranceRequirement) -> Self {
        self.require_assurance = Some(req);
        self
    }

    /// Checks that may be `unsupported` without denying (see [`AuthorizeInput::allow_unsupported`]).
    pub fn with_allow_unsupported<S: Into<String>>(mut self, names: impl IntoIterator<Item = S>) -> Self {
        self.allow_unsupported = names.into_iter().map(Into::into).collect();
        self
    }

    /// Feed the plan registry's stored plan and its executable state into the authorize context (see [`AuthorizeInput::plans`]).
    pub fn with_plans(mut self, plans: Arc<PlanRegistry>) -> Self {
        self.plans = Some(plans);
        self
    }

    /// The plan registry, if one was configured.
    pub fn plans(&self) -> Option<&PlanRegistry> {
        self.plans.as_deref()
    }

    /// Run the boolean revocation hook (`Ok(true)` = revoked).
    pub fn revoked(&self, pcactn: &Value, grant: &Value) -> Result<bool, String> {
        (self.is_revoked)(pcactn, grant)
    }

    /// Cap the age of the revocation state per reversibility class (see [`RevocationStaleness`]); off by default.
    pub fn with_revocation_staleness(mut self, gate: RevocationStaleness) -> Self {
        self.revocation_staleness = Some(gate);
        self
    }

    /// The `fresh_at` consistency-token policy (default none; see [`AuthorizeInput::fresh_at`]).
    pub fn with_fresh_at(mut self, policy: FreshAtPolicy) -> Self {
        self.fresh_at = Some(policy);
        self
    }

    /// The plan mode (default `Some("single-step")`; `None` = only a `context` plan is accepted).
    pub fn with_plan(mut self, plan: Option<&str>) -> Self {
        self.plan = plan.map(str::to_string);
        self
    }

    /// The per-request context (see [`ContextProvider`]).
    pub fn with_context(mut self, context: impl Fn(&Value) -> Result<Option<Value>, String> + Send + Sync + 'static) -> Self {
        self.context = Some(Arc::new(context));
        self
    }

    /// Extra check names that must pass.
    pub fn with_require<S: Into<String>>(mut self, names: impl IntoIterator<Item = S>) -> Self {
        self.require = names.into_iter().map(Into::into).collect();
        self
    }

    /// The pinned principal keys (b64u Ed25519) whose EscalationAnswers count; none (default) refuses every escalate.
    pub fn with_escalation_principals<S: Into<String>>(mut self, keys: impl IntoIterator<Item = S>) -> Self {
        self.escalation_principals = keys.into_iter().map(PinnedSigner::ed25519).collect();
        self
    }

    /// How long an issued EscalationRequest is valid, in ms (default one hour).
    pub fn with_escalation_request_ttl_ms(mut self, ttl_ms: i64) -> Self {
        self.escalation_request_ttl_ms = Some(ttl_ms);
        self
    }

    /// K7: recompute the approval render digest from the executed params and your own definition. Answers are then admitted only when
    /// signed over exactly it.
    pub fn with_escalation_render(mut self, f: impl Fn(&Value) -> Option<String> + Send + Sync + 'static) -> Self {
        self.escalation_render = Some(Arc::new(f));
        self
    }

    /// The documented INSECURE opt-out of the default that an answer needs a recomputed, matching approval render.
    pub fn insecure_unbound_approval(mut self) -> Self {
        self.insecure_unbound_approval = true;
        self
    }

    /// The pinned principals whose EscalationAnswers count, each with the PQ key it may sign with (see [`PinnedSigner`]).
    pub fn with_escalation_signers(mut self, signers: impl IntoIterator<Item = PinnedSigner>) -> Self {
        self.escalation_principals = signers.into_iter().collect();
        self
    }

    /// Turn the caveat language v2 on with the verifier's own K1 input (pins, revocations, SPIFFE ID, history). Discharges and a
    /// narrow block a request presents (headers `PCA-Discharges`, `PCA-Narrow`) are merged in by the middleware; own values win.
    /// Without it a K1 caveat in the chain is refused.
    pub fn with_k1(mut self, k1: K1Input) -> Self {
        self.k1 = Some(k1);
        self
    }

    /// Where K1 `max_uses` caveats are spent (an atomic store; a durable shared one makes the count hold across workers).
    pub fn with_uses_store(mut self, store: Arc<dyn StateStore>) -> Self {
        self.uses_store = Some(store);
        self
    }

    /// K5 (C-308): admit each call's workflow step before the replay claim (see [`WorkflowGate`]); pass the step to
    /// [`AuthorizeOptions::run_workflow`]. Off by default.
    pub fn with_workflow(mut self, gate: WorkflowGate) -> Self {
        self.workflow = Some(gate);
        self
    }

    /// [`AuthorizeOptions::run`] for a call that carries a workflow step (`None`: it carries none).
    pub fn run_workflow(
        &self,
        pcactn: Option<&Value>,
        operation: Option<&Operation>,
        audience: &str,
        resolve_grant: &GrantResolver<'_>,
        now: Option<i64>,
        workflow_call: Option<&WorkflowCall>,
    ) -> AuthorizeResult {
        self.run_full(pcactn, operation, audience, resolve_grant, now, None, None, None, None, workflow_call)
    }

    /// Run [`authorize`] with these options.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        pcactn: Option<&Value>,
        operation: Option<&Operation>,
        audience: &str,
        resolve_grant: &GrantResolver<'_>,
        now: Option<i64>,
        intent_policy: Option<&IntentPolicy>,
        intent_v2: Option<&IntentV2Provider<'_>>,
    ) -> AuthorizeResult {
        self.run_answered(pcactn, operation, audience, resolve_grant, now, intent_policy, intent_v2, None)
    }

    /// [`AuthorizeOptions::run`] with the principal's EscalationAnswer for this action.
    #[allow(clippy::too_many_arguments)]
    pub fn run_answered(
        &self,
        pcactn: Option<&Value>,
        operation: Option<&Operation>,
        audience: &str,
        resolve_grant: &GrantResolver<'_>,
        now: Option<i64>,
        intent_policy: Option<&IntentPolicy>,
        intent_v2: Option<&IntentV2Provider<'_>>,
        escalation_answer: Option<&Value>,
    ) -> AuthorizeResult {
        self.run_presented(pcactn, operation, audience, resolve_grant, now, intent_policy, intent_v2, escalation_answer, None)
    }

    /// [`AuthorizeOptions::run_answered`] with the discharges / narrow block the request presented (merged into the configured
    /// K1 input; ignored when no K1 input is configured).
    #[allow(clippy::too_many_arguments)]
    pub fn run_presented(
        &self,
        pcactn: Option<&Value>,
        operation: Option<&Operation>,
        audience: &str,
        resolve_grant: &GrantResolver<'_>,
        now: Option<i64>,
        intent_policy: Option<&IntentPolicy>,
        intent_v2: Option<&IntentV2Provider<'_>>,
        escalation_answer: Option<&Value>,
        presented: Option<&PresentedK1>,
    ) -> AuthorizeResult {
        self.run_full(pcactn, operation, audience, resolve_grant, now, intent_policy, intent_v2, escalation_answer, presented, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_full(
        &self,
        pcactn: Option<&Value>,
        operation: Option<&Operation>,
        audience: &str,
        resolve_grant: &GrantResolver<'_>,
        now: Option<i64>,
        intent_policy: Option<&IntentPolicy>,
        intent_v2: Option<&IntentV2Provider<'_>>,
        escalation_answer: Option<&Value>,
        presented: Option<&PresentedK1>,
        workflow_call: Option<&WorkflowCall>,
    ) -> AuthorizeResult {
        let k1 = self.k1.as_ref().map(|own| presented.map_or_else(|| own.clone(), |p| p.merged_into(own)));
        let require: Vec<&str> = self.require.iter().map(String::as_str).collect();
        let allow_unsupported: Vec<&str> = self.allow_unsupported.iter().map(String::as_str).collect();
        let context = self.context.as_deref().map(|c| c as &ContextProvider<'_>);
        let input = AuthorizeInput {
            operation,
            audience,
            resolve_grant: Some(resolve_grant),
            state_store: Some(self.state_store.as_ref()),
            is_revoked: Some(self.is_revoked.as_ref() as &RevocationCheck<'_>),
            revocation_staleness: self.revocation_staleness.as_ref(),
            plans: self.plans.as_deref(),
            assurance_hooks: self.assurance_hooks.as_ref(),
            require_assurance: self.require_assurance.as_ref(),
            allow_unsupported: &allow_unsupported,
            now,
            plan: self.plan.as_deref(),
            context,
            intent_policy,
            intent_v2,
            allowed_suites: None,
            fresh_at: self.fresh_at.as_ref(),
            require: &require,
            escalation_principals: &self.escalation_principals,
            escalation_answer,
            escalation_request_ttl_ms: self.escalation_request_ttl_ms,
            escalation_render: self.escalation_render.as_deref(),
            insecure_unbound_approval: self.insecure_unbound_approval,
            k1: k1.as_ref(),
            uses_store: self.uses_store.as_deref(),
            workflow: self.workflow.as_ref(),
            workflow_call,
        };
        authorize(pcactn, &input)
    }
}

#[cfg(test)]
#[path = "b2_limit_reasons_test.rs"]
mod b2_limit_reasons_test;
