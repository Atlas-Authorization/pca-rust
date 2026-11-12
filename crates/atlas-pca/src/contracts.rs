//! Bounded safety-LTL behavioural contracts (port of `contracts.ts` and `contract-enforcer.ts`): authority, positive AND negative, as a
//! small temporal program of clauses that EACH action proves it transitions validly, over the same hash-chained monitor state as the
//! prohibition monitor. A contract with no clauses is exactly a prohibition constitution. Clauses: `always`, `never`, `precedes` /
//! `requires_prior`, `responds_within` (a bounded-liveness obligation enforced as a safety property with a deadline counter in the
//! state) and `and`. Everything malformed or unresolvable FAILS CLOSED; every function is total.
//!
//! [`ContractEnforcer`] keeps the monitor state as ONE document in an atomic key/value store and runs the whole read-check-advance
//! inside its atomic `update`, so concurrent callers are serialised, a stale or rolled-back state can never be advanced, only a contract
//! signed by the PINNED principal is loaded, and a real violation LATCHES the enforcer until the principal signs a reset.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::forbid::{validate_when, when_matches};
use crate::intent_v2::{js_number_string, js_value_string};
use crate::kv::AtomicKv;
use crate::prohibitions::{advance_state_strict, check_prohibitions, empty_state, state_digest, state_problem, validate_invariant, when_affirmative, MAX_DEADLINE, MAX_INVARIANTS};
use crate::safe_regex::with_regex_budget;

pub const CONTRACT_VERSION: i64 = 1;
pub const CONTRACT_SIG_DOMAIN: &str = "atlas-pca/contract/v1\0";
pub const CONTRACT_RESET_DOMAIN: &str = "atlas-pca/contract-reset/v1\0";
/// Max clauses (counting nested) in one contract.
pub const MAX_CONTRACT_CLAUSES: usize = 256;
/// Max nesting depth of `and` clauses.
pub const MAX_CLAUSE_DEPTH: usize = 16;
const MAX_ID_LEN: usize = 128;
const FORBIDDEN_IDS: [&str; 3] = ["__proto__", "constructor", "prototype"];

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn fin(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn js_str(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

// ---- validation ----------------------------------------------------------------------------------

/// Structural problems with a clause (empty = well formed); collects every id into `seen` to enforce global uniqueness.
pub fn validate_clause(cl: &Value, seen: &mut Vec<String>, depth: usize) -> Vec<String> {
    if depth > MAX_CLAUSE_DEPTH {
        return vec!["clause nesting too deep".into()];
    }
    let o = match cl.as_object() {
        Some(o) => o,
        None => return vec!["clause not an object".into()],
    };
    let id = match o.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) {
        Some(i) => i.to_string(),
        None => return vec!["<no id>: missing clause id".into()],
    };
    let err = |m: &str| vec![format!("{id}: {m}")];
    if u16len(&id) > MAX_ID_LEN {
        return err("id too long");
    }
    if FORBIDDEN_IDS.contains(&id.as_str()) {
        return err("forbidden id");
    }
    if seen.contains(&id) {
        return err("duplicate id");
    }
    seen.push(id.clone());
    let when = |k: &str| validate_when(o.get(k).unwrap_or(&Value::Null), k);
    match o.get("kind").and_then(Value::as_str) {
        Some("always" | "never") => when("p").map_or_else(Vec::new, |e| err(&e)),
        Some("precedes" | "requires_prior") => when("p").or_else(|| when("q")).map_or_else(Vec::new, |e| err(&e)),
        Some("responds_within") => {
            if let Some(e) = when("p").or_else(|| when("q")) {
                return err(&e);
            }
            let w = fin(o.get("within")).filter(|w| w.fract() == 0.0 && (1.0..=MAX_DEADLINE).contains(w));
            if w.is_none() {
                return err("within must be an integer in [1, MAX_DEADLINE]");
            }
            Vec::new()
        }
        Some("and") => match o.get("clauses").and_then(Value::as_array) {
            Some(subs) if !subs.is_empty() => subs.iter().flat_map(|sub| validate_clause(sub, seen, depth + 1)).collect(),
            _ => err("and.clauses must be a non-empty array"),
        },
        _ => err(&format!("unknown clause kind {}", js_str(o.get("kind")))),
    }
}

fn count_clauses(cls: &[Value], depth: usize) -> usize {
    // bounded recursion: an absurdly deep nest is "too many" at once
    if depth > MAX_CLAUSE_DEPTH + 1 {
        return MAX_CONTRACT_CLAUSES + 1;
    }
    let mut n = 0;
    for cl in cls {
        n += 1;
        if cl.get("kind").and_then(Value::as_str) == Some("and") {
            if let Some(sub) = cl.get("clauses").and_then(Value::as_array) {
                n += count_clauses(sub, depth + 1);
            }
        }
    }
    n
}

/// Structural problems with a contract (empty = well formed). Total.
pub fn validate_contract(c: &Value) -> Vec<String> {
    let o = match c.as_object() {
        Some(o) => o,
        None => return vec!["contract not an object".into()],
    };
    let mut out: Vec<String> = Vec::new();
    if fin(o.get("version")) != Some(CONTRACT_VERSION as f64) {
        out.push(format!("unsupported version {}", js_str(o.get("version"))));
    }
    if !o.get("principal").and_then(Value::as_str).is_some_and(|p| !p.is_empty()) {
        out.push("principal missing".into());
    }
    let mut ids: Vec<String> = Vec::new();
    if let Some(invs) = o.get("invariants") {
        let invs = match invs.as_array() {
            Some(a) => a,
            None => {
                out.push("invariants not an array".into());
                return out;
            }
        };
        if invs.len() > MAX_INVARIANTS {
            out.push("too many invariants".into());
        }
        for inv in invs {
            out.extend(validate_invariant(inv));
            if let Some(id) = inv.get("id").and_then(Value::as_str) {
                if ids.iter().any(|x| x == id) {
                    out.push(format!("{id}: duplicate id"));
                }
                ids.push(id.to_string());
            }
        }
    }
    if let Some(cls) = o.get("clauses") {
        let cls = match cls.as_array() {
            Some(a) => a,
            None => {
                out.push("clauses not an array".into());
                return out;
            }
        };
        if count_clauses(cls, 1) > MAX_CONTRACT_CLAUSES {
            out.push("too many clauses".into());
        }
        // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
        for cl in cls {
            out.extend(validate_clause(cl, &mut ids, 1));
        }
    }
    out
}

// ---- commitment -----------------------------------------------------------------------------------

/// The contract's content address: the canonical hash of its body (without `id` and `sig`).
pub fn contract_id(c: &Value) -> Option<String> {
    let mut body = c.as_object()?.clone();
    body.remove("id");
    body.remove("sig");
    crate::hash_canonical_strict(&Value::Object(body))
}

fn domain_message(domain: &str, id: &str) -> Vec<u8> {
    let mut m = domain.as_bytes().to_vec();
    m.extend(crate::sha(id.as_bytes()));
    m
}

/// Verify: well formed, id matches content, signature by `expected_principal` (or the embedded one).
pub fn verify_contract(sc: &Value, expected_principal: Option<&str>) -> Result<(), String> {
    if let Some(p) = validate_contract(sc).into_iter().next() {
        return Err(p);
    }
    let principal = sc["principal"].as_str().unwrap_or_default();
    if expected_principal.is_some_and(|e| e != principal) {
        return Err("principal mismatch".into());
    }
    let id = match sc.get("id").and_then(Value::as_str) {
        Some(id) if contract_id(sc).as_deref() == Some(id) => id,
        _ => return Err("id does not match content".into()),
    };
    match sc.get("sig").and_then(Value::as_str) {
        Some(sig) if crate::verify_b64u(principal, &domain_message(CONTRACT_SIG_DOMAIN, id), sig) => Ok(()),
        _ => Err("bad signature".into()),
    }
}

/// The principal signs the contract (authoring time; refuses a malformed one).
pub fn sign_contract(c: &Value, principal: &crate::agent::KeyPair) -> Result<Value, String> {
    let problems = validate_contract(c);
    if !problems.is_empty() {
        return Err(format!("signContract: {}", problems.join("; ")));
    }
    let id = contract_id(c).ok_or("signContract: contract is not canonicalizable")?;
    let sig = crate::b64_encode(&principal.sign(&domain_message(CONTRACT_SIG_DOMAIN, &id)));
    let mut m = c.as_object().cloned().unwrap_or_default();
    m.remove("id");
    m.remove("sig");
    m.insert("id".into(), json!(id));
    m.insert("sig".into(), json!(sig));
    Ok(Value::Object(m))
}

/// The embedded prohibition constitution of a contract (empty when `invariants` is omitted).
pub fn embedded_constitution(c: &Value) -> Value {
    json!({"version": 1, "principal": c["principal"], "invariants": c.get("invariants").filter(|i| i.is_array()).cloned().unwrap_or_else(|| json!([]))})
}

// ---- clause evaluation ------------------------------------------------------------------------------

struct Transition {
    ok: bool,
    reason: Option<String>,
    rows: Vec<Value>,
    latch_set: Map<String, Value>,
    /// id -> new deadline budget, or null to clear.
    deadline_set: Map<String, Value>,
}

fn row(id: &Value, kind: &Value, ok: bool, reason: Option<&str>) -> Value {
    let mut r = json!({"id": id, "kind": kind, "result": if ok { "pass" } else { "violated" }});
    if let Some(x) = reason.filter(|x| !x.is_empty()) {
        r["reason"] = json!(x);
    }
    r
}

fn desc_or(cl: &Value, default: &str) -> String {
    match cl.get("description") {
        None | Some(Value::Null) => default.to_string(),
        Some(d) => js_value_string(d),
    }
}

fn eval_clause(cl: &Value, ctx: &Value, state: &Value, now: f64) -> Transition {
    catch_unwind(AssertUnwindSafe(|| eval_inner(cl, ctx, state, now))).unwrap_or_else(|_| base(cl, false, Some("clause evaluation error (fail closed)")))
}

fn base(cl: &Value, ok: bool, reason: Option<&str>) -> Transition {
    Transition { ok, reason: reason.map(String::from), rows: vec![row(&cl["id"], &cl["kind"], ok, reason)], latch_set: Map::new(), deadline_set: Map::new() }
}

fn eval_inner(cl: &Value, ctx: &Value, state: &Value, now: f64) -> Transition {
    let id = cl["id"].as_str().unwrap_or("");
    let latched_has = state["latched"].get(id).is_some();
    let p = cl.get("p").unwrap_or(&Value::Null);
    let q = cl.get("q").unwrap_or(&Value::Null);
    match cl["kind"].as_str().unwrap_or("") {
        // positive authority: every action must AFFIRMATIVELY satisfy p; unresolvable => violation
        "always" => {
            if when_affirmative(p, ctx) {
                base(cl, true, None)
            } else {
                base(cl, false, Some(&desc_or(cl, "always-invariant violated (action does not satisfy p)")))
            }
        }
        // = always not-p; conservative: an unresolvable trigger counts as matched (veto)
        "never" => {
            if when_matches(p, ctx) {
                base(cl, false, Some(&desc_or(cl, "never-invariant violated (forbidden action)")))
            } else {
                base(cl, true, None)
            }
        }
        "precedes" | "requires_prior" => {
            let is_q = when_matches(q, ctx); // guarded action, conservative
            let ok = !is_q || latched_has;
            let mut t = if ok { base(cl, true, None) } else { base(cl, false, Some(&desc_or(cl, "precedence violated (prerequisite p not yet admitted before q)"))) };
            // latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
            if !latched_has && when_affirmative(p, ctx) {
                t.latch_set.insert(id.to_string(), crate::prohibitions::num_value(now));
            }
            t
        }
        "responds_within" => {
            let within = fin(cl.get("within")).unwrap_or(0.0);
            let mut violated = false;
            let mut carried: Option<f64> = None;
            if let Some(cur) = state.get("deadlines").and_then(|d| d.get(id)) {
                if when_affirmative(q, ctx) {
                    carried = None; // any response discharges all open obligations
                } else {
                    let r = fin(Some(cur)).unwrap_or(0.0) - 1.0;
                    if r <= 0.0 {
                        violated = true; // window exhausted with no response => violation at this action
                    } else {
                        carried = Some(r);
                    }
                }
            }
            if violated {
                let reason = desc_or(cl, &format!("bounded-liveness deadline missed (no q within {} actions of p)", js_number_string(within)));
                return Transition { ok: false, reason: Some(reason.clone()), rows: vec![row(&cl["id"], &cl["kind"], false, Some(&reason))], latch_set: Map::new(), deadline_set: Map::new() };
            }
            // a (conservative) stimulus opens a fresh obligation of budget `within`; the binding deadline is the MOST URGENT open one
            let mut next = carried;
            if when_matches(p, ctx) {
                next = Some(next.map_or(within, |n| n.min(within)));
            }
            let mut ds = Map::new();
            ds.insert(id.to_string(), next.map_or(Value::Null, crate::prohibitions::num_value));
            Transition { ok: true, reason: None, rows: vec![row(&cl["id"], &cl["kind"], true, None)], latch_set: Map::new(), deadline_set: ds }
        }
        "and" => {
            let mut t = Transition { ok: true, reason: None, rows: Vec::new(), latch_set: Map::new(), deadline_set: Map::new() };
            for sub in cl["clauses"].as_array().into_iter().flatten() {
                let r = eval_clause(sub, ctx, state, now);
                t.rows.extend(r.rows);
                t.latch_set.extend(r.latch_set);
                t.deadline_set.extend(r.deadline_set);
                if !r.ok && t.ok {
                    t.ok = false;
                    t.reason = r.reason;
                }
            }
            t
        }
        _ => base(cl, false, Some("unknown clause kind (fail closed)")),
    }
}

// ---- the contract monitor -------------------------------------------------------------------------------

/// Outcome of evaluating a whole contract against one action.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractResult {
    pub ok: bool,
    pub violated: Vec<String>,
    pub reasons: Vec<String>,
    pub evaluated: Vec<Value>,
}

impl ContractResult {
    pub fn to_json(&self) -> Value {
        json!({"ok": self.ok, "violated": self.violated, "reasons": self.reasons, "evaluated": self.evaluated})
    }
}

fn fail(id: &str, reason: &str) -> ContractResult {
    ContractResult { ok: false, violated: vec![id.to_string()], reasons: vec![format!("{id}: {reason}")], evaluated: vec![json!({"id": id, "kind": "structural", "result": "violated", "reason": reason})] }
}

fn action_ok(action: &Value) -> bool {
    let a = action.get("action");
    a.and_then(|a| a.get("verb")).is_some_and(Value::is_string) && a.and_then(|a| a.get("resource")).is_some_and(Value::is_string)
}

/// Evaluate a whole contract (embedded constitution + temporal clauses) against one action and the running state, WITHOUT advancing.
/// Every invariant and clause is evaluated (no short-circuit). The whole contract is one document for the regex budget.
pub fn check_contract(action: &Value, contract: &Value, state: &Value) -> ContractResult {
    with_regex_budget(|| catch_unwind(AssertUnwindSafe(|| check_inner(action, contract, state))).unwrap_or_else(|_| fail("<monitor>", "monitor error (fail closed)")))
}

fn check_inner(action: &Value, contract: &Value, state: &Value) -> ContractResult {
    if let Some(p) = validate_contract(contract).into_iter().next() {
        return fail("<contract>", &p);
    }
    if !action_ok(action) {
        return fail("<action>", "malformed action");
    }
    if let Some(p) = state_problem(state) {
        return fail("<state>", &p);
    }
    let mut evaluated: Vec<Value> = Vec::new();
    let constitution = embedded_constitution(contract);
    if constitution["invariants"].as_array().is_some_and(|i| !i.is_empty()) {
        evaluated.extend(check_prohibitions(action, &constitution, state).evaluated);
    }
    let now = fin(state.get("now")).unwrap_or(0.0);
    for cl in contract.get("clauses").and_then(Value::as_array).into_iter().flatten() {
        evaluated.extend(eval_clause(cl, action, state, now).rows);
    }
    let bad: Vec<&Value> = evaluated.iter().filter(|e| e["result"] == "violated").collect();
    ContractResult {
        ok: bad.is_empty(),
        violated: bad.iter().map(|e| e["id"].as_str().unwrap_or("").to_string()).collect(),
        reasons: bad.iter().map(|e| format!("{}: {}", e["id"].as_str().unwrap_or(""), e["reason"].as_str().unwrap_or("violated"))).collect(),
        evaluated,
    }
}

/// `advance_contract`'s verdict plus the next state (== the input state unless `ok`); `decided_by` is `contract`, `state` or `none`.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvanceContract {
    pub result: ContractResult,
    pub next: Value,
    pub decided_by: &'static str,
}

/// Compare-and-swap guards and the clock of [`advance_contract`].
#[derive(Debug, Clone, Default)]
pub struct AdvanceOptions {
    pub expected_seq: Option<f64>,
    pub expected_state_digest: Option<String>,
    /// Evaluation time (epoch ms); must be >= `state.now`. Defaults to `state.now`.
    pub now: Option<f64>,
}

/// Check the whole contract against one action and, iff it holds, advance the hash-chained monitor state EXACTLY like the prohibition
/// monitor, then overlay the temporal clauses' precedence latches and bounded-liveness deadline counters. Fail-closed on anything
/// unresolvable or on a stale chain head; `next` is then the input state, unchanged.
pub fn advance_contract(state: &Value, action: &Value, contract: &Value, opts: &AdvanceOptions) -> AdvanceContract {
    catch_unwind(AssertUnwindSafe(|| advance_inner(state, action, contract, opts))).unwrap_or_else(|_| refuse(state, "state", None, Some("advance error (fail closed)"), action, contract))
}

fn refuse(state: &Value, decided_by: &'static str, r: Option<ContractResult>, reason: Option<&str>, action: &Value, contract: &Value) -> AdvanceContract {
    let base = r.unwrap_or_else(|| check_contract(action, contract, state));
    let result = match reason {
        None => base,
        Some(why) => {
            let mut violated: Vec<String> = base.violated.iter().filter(|v| *v != "<state>").cloned().collect();
            violated.push("<state>".into());
            let mut reasons = base.reasons.clone();
            reasons.push(format!("<state>: {why}"));
            ContractResult { ok: false, violated, reasons, evaluated: base.evaluated }
        }
    };
    AdvanceContract { result: ContractResult { ok: false, ..result }, next: state.clone(), decided_by }
}

fn advance_inner(state: &Value, action: &Value, contract: &Value, opts: &AdvanceOptions) -> AdvanceContract {
    let now = opts.now.or_else(|| fin(state.get("now")));
    // CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
    if let Some(seq) = opts.expected_seq {
        if !state.is_object() || fin(state.get("seq")) != Some(seq) {
            return refuse(state, "state", None, Some("stale state head (seq)"), action, contract);
        }
    }
    if let Some(d) = &opts.expected_state_digest {
        if state_digest(state).as_deref() != Some(d.as_str()) {
            return refuse(state, "state", None, Some("stale state head (digest)"), action, contract);
        }
    }
    let verdict = check_contract(action, contract, state);
    if !verdict.ok {
        let structural = verdict.violated.iter().any(|v| v.starts_with('<') && v.ends_with('>'));
        return AdvanceContract { result: verdict, next: state.clone(), decided_by: if structural { "state" } else { "contract" } };
    }
    let constitution = embedded_constitution(contract);
    let adv = match advance_state_strict(action, &constitution, state, now) {
        Ok(a) => a,
        Err(why) => return refuse(state, "state", Some(verdict), Some(&format!("advance failed: {why}")), action, contract),
    };
    let mut latched: Map<String, Value> = adv["latched"].as_object().cloned().unwrap_or_default();
    let mut deadlines: Map<String, Value> = state.get("deadlines").and_then(Value::as_object).cloned().unwrap_or_default();
    // a second evaluation pass of the same clauses: its own document budget
    let now_f = now.unwrap_or(0.0);
    with_regex_budget(|| {
        for cl in contract.get("clauses").and_then(Value::as_array).into_iter().flatten() {
            let t = eval_clause(cl, action, state, now_f);
            for (k, v) in t.latch_set {
                latched.entry(k).or_insert(v);
            }
            for (k, v) in t.deadline_set {
                if v.is_null() {
                    deadlines.remove(&k);
                } else {
                    deadlines.insert(k, v);
                }
            }
        }
    });
    let mut next = adv.clone();
    next["latched"] = Value::Object(latched);
    if !deadlines.is_empty() {
        next["deadlines"] = Value::Object(deadlines);
    }
    if let Some(sp) = state_problem(&next) {
        return refuse(state, "state", Some(verdict), Some(&format!("resulting state invalid: {sp}")), action, contract);
    }
    AdvanceContract { result: verdict, next, decided_by: "none" }
}

/// `allow = permitted AND contract.ok`, and on allow the state advances. The permission verdict is an INPUT that can only be ANDed;
/// the contract monitor runs unconditionally so denial reasons are complete.
pub fn check_and_advance_contract(permitted: bool, state: &Value, action: &Value, contract: &Value, opts: &AdvanceOptions) -> (bool, AdvanceContract) {
    let adv = advance_contract(state, action, contract, opts);
    if !adv.result.ok {
        return (false, adv);
    }
    if !permitted {
        let mut reasons = adv.result.reasons.clone();
        reasons.push("<permission>: not permitted".into());
        let result = ContractResult { ok: false, violated: adv.result.violated.clone(), reasons, evaluated: adv.result.evaluated.clone() };
        return (false, AdvanceContract { result, next: state.clone(), decided_by: "contract" });
    }
    (true, adv)
}

// ---- durable enforcement ---------------------------------------------------------------------------------

/// What [`ContractEnforcer::check`] / [`ContractEnforcer::peek`] answer. `reason` is `ok`, `violated`, `latched`, `permission`,
/// `state-error` or `store-error`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnforceResult {
    pub allow: bool,
    pub reason: &'static str,
    pub violated: Vec<String>,
    pub reasons: Vec<String>,
    /// Admitted-action count after this call.
    pub seq: i64,
}

fn enforce(allow: bool, reason: &'static str, violated: Vec<String>, reasons: Vec<String>, seq: i64) -> EnforceResult {
    EnforceResult { allow, reason, violated, reasons, seq }
}

const CORRUPT: &str = "<state>: stored state is corrupt or belongs to another contract";

fn is_doc(d: &Value, id: &str) -> bool {
    if !d.is_object() || fin(d.get("v")) != Some(1.0) || d["contract_id"].as_str() != Some(id) || state_problem(&d["state"]).is_some() {
        return false;
    }
    match d.get("latched") {
        None => true,
        Some(l) => {
            l.is_object()
                && fin(l.get("seq")).is_some_and(|s| s.fract() == 0.0 && !(s == 0.0 && s.is_sign_negative()))
                && l["violated"].as_array().is_some_and(|v| v.iter().all(Value::is_string))
        }
    }
}

fn seq_of(doc: &Value) -> i64 {
    fin(doc["state"].get("seq")).map_or(0, |s| s as i64)
}

/// Durable enforcement of a signed contract: the monitor state is one document in an atomic key/value store.
pub struct ContractEnforcer {
    kv: Arc<dyn AtomicKv>,
    contract: Value,
    key: String,
    now: Box<dyn Fn() -> f64 + Send + Sync>,
    latch: bool,
}

impl ContractEnforcer {
    /// Fails unless the contract verifies under the pinned principal (there is no trust-on-first-use). `key` defaults to
    /// `contract/<contract id>`; `now` to the wall clock; `latch_on_violation` is normally true.
    pub fn open(kv: Arc<dyn AtomicKv>, contract: &Value, principal: &str, key: Option<&str>, now: Option<Box<dyn Fn() -> f64 + Send + Sync>>, latch_on_violation: bool) -> Result<ContractEnforcer, String> {
        if principal.is_empty() {
            return Err("ContractEnforcer: a pinned principal is required".into());
        }
        verify_contract(contract, Some(principal)).map_err(|why| format!("ContractEnforcer: contract refused: {why}"))?;
        let id = contract_id(contract).ok_or("ContractEnforcer: contract refused: id does not match content")?;
        Ok(ContractEnforcer {
            kv,
            contract: contract.clone(),
            key: key.map_or_else(|| format!("contract/{id}"), String::from),
            now: now.unwrap_or_else(|| Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64))),
            latch: latch_on_violation,
        })
    }

    fn id(&self) -> &str {
        self.contract["id"].as_str().unwrap_or("")
    }

    /// Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Total.
    pub fn check(&self, action: &Value, permitted: bool) -> EnforceResult {
        let id = self.id().to_string();
        let mut out = enforce(false, "store-error", vec![], vec!["store unavailable".into()], 0);
        let wall = (self.now)();
        let r = catch_unwind(AssertUnwindSafe(|| {
            self.kv.update(&self.key, &mut |prev| {
                if let Some(p) = prev {
                    if !is_doc(p, &id) {
                        out = enforce(false, "state-error", vec![], vec![CORRUPT.into()], 0);
                        return None;
                    }
                    if !wall.is_finite() {
                        out = enforce(false, "state-error", vec![], vec!["<state>: clock is not finite".into()], seq_of(p));
                        return None;
                    }
                }
                let doc: Value = prev.cloned().unwrap_or_else(|| json!({"v": 1, "contract_id": id, "state": empty_state(if wall.is_finite() { wall } else { 0.0 })}));
                if let Some(l) = doc.get("latched") {
                    let violated: Vec<String> = l["violated"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
                    out = enforce(false, "latched", violated, vec![format!("<latched>: contract violated at seq {}", js_value_string(&l["seq"]))], seq_of(&doc));
                    return None;
                }
                let state_now = fin(doc["state"].get("now")).unwrap_or(0.0);
                let now = if wall.is_nan() { f64::NAN } else { wall.max(state_now) };
                let opts = AdvanceOptions { expected_seq: fin(doc["state"].get("seq")), expected_state_digest: None, now: Some(now) };
                let (allow, r) = check_and_advance_contract(permitted, &doc["state"], action, &self.contract, &opts);
                if allow {
                    out = enforce(true, "ok", vec![], vec![], fin(r.next.get("seq")).map_or(0, |s| s as i64));
                    let mut d = doc.clone();
                    d["state"] = r.next;
                    return Some(d);
                }
                let structural = r.decided_by == "state";
                let real = !structural && !r.result.violated.is_empty();
                out = enforce(false, if structural { "state-error" } else if real { "violated" } else { "permission" }, if real { r.result.violated.clone() } else { vec![] }, r.result.reasons.clone(), seq_of(&doc));
                if real && self.latch {
                    let mut d = doc.clone();
                    d["latched"] = json!({"seq": seq_of(&doc), "violated": r.result.violated});
                    return Some(d);
                }
                None
            })
        }));
        if r.is_err() || r.is_ok_and(|x| x.is_err()) {
            return enforce(false, "store-error", vec![], vec!["store error (fail closed)".into()], 0);
        }
        out
    }

    /// Read-only evaluation of `action` against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay
    /// counter is spent; `check` then commits once the action is actually admitted. Total.
    pub fn peek(&self, action: &Value) -> EnforceResult {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let prev = match self.kv.get(&self.key) {
                Ok(p) => p,
                Err(_) => return enforce(false, "store-error", vec![], vec!["store error (fail closed)".into()], 0),
            };
            if prev.as_ref().is_some_and(|p| !is_doc(p, self.id())) {
                return enforce(false, "state-error", vec![], vec![CORRUPT.into()], 0);
            }
            if let Some(l) = prev.as_ref().and_then(|d| d.get("latched")) {
                let violated: Vec<String> = l["violated"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
                return enforce(false, "latched", violated, vec![format!("<latched>: contract violated at seq {}", js_value_string(&l["seq"]))], seq_of(prev.as_ref().unwrap_or(&Value::Null)));
            }
            let wall = (self.now)();
            let state = prev.as_ref().map_or_else(|| empty_state(if wall.is_finite() { wall } else { 0.0 }), |d| d["state"].clone());
            let r = check_contract(action, &self.contract, &state);
            let seq = prev.as_ref().map_or(0, seq_of);
            if r.ok {
                enforce(true, "ok", vec![], vec![], seq)
            } else {
                enforce(false, "violated", r.violated, r.reasons, seq)
            }
        }));
        r.unwrap_or_else(|_| enforce(false, "store-error", vec![], vec!["store error (fail closed)".into()], 0))
    }

    /// The current stored state `(state, latched)`, or `None` when nothing was admitted yet. `Err` on a corrupt document.
    pub fn state(&self) -> Result<Option<(Value, bool)>, String> {
        match self.kv.get(&self.key).map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(d) if !is_doc(&d, self.id()) => Err("ContractEnforcer: stored state is corrupt or belongs to another contract".into()),
            Some(d) => Ok(Some((d["state"].clone(), d.get("latched").is_some()))),
        }
    }

    /// Un-latch with the principal's signature (see [`sign_contract_reset`]) at the latched sequence. Returns whether it cleared.
    pub fn reset(&self, sig: &str) -> bool {
        let mut cleared = false;
        let principal = self.contract["principal"].as_str().unwrap_or("").to_string();
        let id = self.id().to_string();
        let r = catch_unwind(AssertUnwindSafe(|| {
            self.kv.update(&self.key, &mut |prev| {
                let p = prev?;
                if !is_doc(p, &id) {
                    return None;
                }
                let seq = js_value_string(&p.get("latched")?["seq"]);
                if !crate::verify_b64u(&principal, &domain_message(CONTRACT_RESET_DOMAIN, &format!("{id}:{seq}")), sig) {
                    return None;
                }
                cleared = true;
                let mut d = p.clone();
                d.as_object_mut()?.remove("latched");
                Some(d)
            })
        }));
        cleared && r.is_ok_and(|x| x.is_ok())
    }
}

/// The principal's authorisation to un-latch contract `id` at sequence `seq` (binds both, so it cannot be replayed later).
pub fn sign_contract_reset(principal: &crate::agent::KeyPair, id: &str, seq: i64) -> String {
    crate::b64_encode(&principal.sign(&domain_message(CONTRACT_RESET_DOMAIN, &format!("{id}:{seq}"))))
}
