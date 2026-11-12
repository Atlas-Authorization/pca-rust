//! Negative authority (port of the constitution / monitor / evidence half of `prohibitions.ts`): a principal-committed CONSTITUTION of
//! invariants the agent must NEVER violate, enforced independently of the permission plan. `allow = permitted AND prohibitions.ok`.
//! Everything malformed, unknown or unresolvable FAILS CLOSED, and for a prohibition "closed" means the trigger MATCHED (see
//! [`crate::forbid::when_matches`]). Forms: `never`, `never_unless`, `cap`, `rate`, `never_after`, `require_prior`,
//! `require_approval_over`. State is a canonical, digest-committed, hash-chained monitor state; per-action evidence is bound to
//! (action digest, constitution id, state digest). Documents are plain JSON values read with JavaScript semantics; every function is
//! total.
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Map, Value};

use crate::forbid::{validate_condition, validate_when, when_matches};
use crate::intent_v2::{js_number_string, js_value_string};
use crate::predicates::{evaluate_condition, Ctx};
use crate::safe_regex::with_regex_budget;

pub const CONSTITUTION_VERSION: i64 = 1;
pub const CONSTITUTION_SIG_DOMAIN: &str = "atlas-pca/constitution/v1\0";
pub const EVIDENCE_VERSION: i64 = 1;
pub const SAFETY_EVIDENCE_SIG_DOMAIN: &str = "atlas-pca/safety-evidence/v1\0";
pub const STATE_DIGEST_DOMAIN: &str = "atlas-pca/monitor-state/v1";
pub const STATE_CHAIN_DOMAIN: &str = "atlas-pca/monitor-state-link/v1";
/// Max ledger entries kept per cap/rate invariant (older cap entries are merged, never dropped).
pub const MAX_LEDGER: usize = 10_000;
/// Max invariants in one constitution.
pub const MAX_INVARIANTS: usize = 256;
const MAX_STATE_ENTRIES: usize = 100_000;
const MAX_STATE_KEYS: usize = 1024;
const MAX_ID_LEN: usize = 128;
/// Upper bound on a bounded-liveness deadline budget.
pub const MAX_DEADLINE: f64 = 1_000_000.0;
const FORBIDDEN_IDS: [&str; 3] = ["__proto__", "constructor", "prototype"];
const UNHASHABLE: &str = "<unhashable>";

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// A finite JSON number.
fn fin(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

/// `Number.isInteger` and not `-0`.
fn nat_int(v: Option<&Value>) -> Option<f64> {
    fin(v).filter(|f| f.fract() == 0.0 && !(*f == 0.0 && f.is_sign_negative()))
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(String::from)
}

/// `String(v)` of an optional member (`undefined` when absent).
fn js_str(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

/// A JSON number from an f64 (an integral value as an integer).
pub fn num_value(f: f64) -> Value {
    num(f)
}

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

// ---- validation ------------------------------------------------------------------------

fn validate_conditions(cs: Option<&Value>, label: &str) -> Option<String> {
    match cs.and_then(Value::as_array) {
        Some(l) if !l.is_empty() => l.iter().find_map(|c| validate_condition(c, 0)),
        _ => Some(format!("{label} must be a non-empty array")),
    }
}

/// Structural problems with an invariant (empty = well formed).
pub fn validate_invariant(inv: &Value) -> Vec<String> {
    let o = match inv.as_object() {
        Some(o) => o,
        None => return vec!["invariant not an object".into()],
    };
    let id = match o.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) {
        Some(i) => i,
        None => return vec!["<no id>: missing id".into()],
    };
    let err = |m: &str| vec![format!("{id}: {m}")];
    if u16len(id) > MAX_ID_LEN {
        return err("id too long");
    }
    if FORBIDDEN_IDS.contains(&id) {
        return err("forbidden id");
    }
    let when = |k: &str, label: &str| validate_when(o.get(k).unwrap_or(&Value::Null), label);
    let amount_bad = || !o.get("amount").and_then(Value::as_str).is_some_and(|a| a.starts_with("action."));
    let e = match o.get("kind").and_then(Value::as_str) {
        Some("never") => when("when", "when"),
        Some("never_unless") => when("when", "when").or_else(|| validate_conditions(o.get("unless"), "unless")),
        Some("cap") => {
            if let Some(e) = when("when", "when") {
                Some(e)
            } else if amount_bad() {
                Some("amount must be an action.* path".into())
            } else if fin(o.get("max")).is_none_or(|m| m < 0.0) {
                Some("max must be a finite number >= 0".into())
            } else if o.get("window_secs").is_some_and(|w| fin(Some(w)).is_none_or(|w| w <= 0.0)) {
                Some("bad window_secs".into())
            } else {
                None
            }
        }
        Some("rate") => {
            if let Some(e) = when("when", "when") {
                Some(e)
            } else if nat_int(o.get("max")).is_none_or(|m| m > MAX_LEDGER as f64) {
                Some("max must be an integer in [0,10000]".into())
            } else if fin(o.get("window_secs")).is_none_or(|w| w <= 0.0) {
                Some("window_secs must be > 0".into())
            } else {
                None
            }
        }
        Some("never_after") => when("after", "after").or_else(|| when("forbid", "forbid")),
        Some("require_prior") => when("when", "when").or_else(|| when("prior", "prior")),
        Some("require_approval_over") => {
            if let Some(e) = when("when", "when") {
                Some(e)
            } else if amount_bad() {
                Some("amount must be an action.* path".into())
            } else if fin(o.get("threshold")).is_none_or(|t| t < 0.0) {
                Some("threshold must be a finite number >= 0".into())
            } else {
                validate_conditions(o.get("approved"), "approved")
            }
        }
        _ => return err(&format!("unknown invariant kind {}", js_str(o.get("kind")))),
    };
    e.map_or_else(Vec::new, |m| err(&m))
}

/// Structural problems with a constitution (empty = well formed).
pub fn validate_constitution(c: &Value) -> Vec<String> {
    let o = match c.as_object() {
        Some(o) => o,
        None => return vec!["constitution not an object".into()],
    };
    let mut out: Vec<String> = Vec::new();
    if fin(o.get("version")) != Some(CONSTITUTION_VERSION as f64) {
        out.push(format!("unsupported version {}", js_str(o.get("version"))));
    }
    if !o.get("principal").and_then(Value::as_str).is_some_and(|p| !p.is_empty()) {
        out.push("principal missing".into());
    }
    let invs = match o.get("invariants").and_then(Value::as_array) {
        Some(a) => a,
        None => {
            out.push("invariants not an array".into());
            return out;
        }
    };
    if invs.len() > MAX_INVARIANTS {
        out.push("too many invariants".into());
    }
    let mut seen: Vec<&str> = Vec::new();
    for inv in invs {
        out.extend(validate_invariant(inv));
        if let Some(id) = inv.get("id").and_then(Value::as_str) {
            if seen.contains(&id) {
                out.push(format!("{id}: duplicate id"));
            }
            seen.push(id);
        }
    }
    out
}

// ---- constitution commitment ------------------------------------------------------------

/// The constitution's content address: the canonical hash of its body (without `id` and `sig`).
pub fn constitution_id(c: &Value) -> Option<String> {
    let mut body = c.as_object()?.clone();
    body.remove("id");
    body.remove("sig");
    crate::hash_canonical_strict(&Value::Object(body))
}

/// `utf8(domain) || sha256(utf8(id))`.
fn domain_message(domain: &str, id: &str) -> Vec<u8> {
    let mut m = domain.as_bytes().to_vec();
    m.extend(crate::sha(id.as_bytes()));
    m
}

/// Verify a signed constitution: well formed, id matches content, signature by `expected_principal` (or the embedded one).
pub fn verify_constitution(sc: &Value, expected_principal: Option<&str>) -> Result<(), String> {
    if let Some(p) = validate_constitution(sc).into_iter().next() {
        return Err(p);
    }
    let principal = s(sc, "principal").unwrap_or_default();
    if expected_principal.is_some_and(|e| e != principal) {
        return Err("principal mismatch".into());
    }
    let id = match sc.get("id").and_then(Value::as_str) {
        Some(id) if constitution_id(sc).as_deref() == Some(id) => id,
        _ => return Err("id does not match content".into()),
    };
    match sc.get("sig").and_then(Value::as_str) {
        Some(sig) if crate::verify_b64u(&principal, &domain_message(CONSTITUTION_SIG_DOMAIN, id), sig) => Ok(()),
        _ => Err("bad signature".into()),
    }
}

// ---- canonical monitor state --------------------------------------------------------------

/// Genesis monitor state at time `now`.
pub fn empty_state(now: f64) -> Value {
    json!({"now": num(now), "seq": 0, "parent": null, "ledger": {}, "latched": {}})
}

fn bad_key(k: &str) -> bool {
    FORBIDDEN_IDS.contains(&k) || u16len(k) > MAX_ID_LEN
}

/// Structural problem with a monitor state (`None` = well formed). Total.
pub fn state_problem(state: &Value) -> Option<String> {
    if !state.is_object() {
        return Some("malformed monitor state".into());
    }
    catch_unwind(AssertUnwindSafe(|| state_problem_inner(state))).unwrap_or_else(|_| Some("malformed monitor state".to_string()))
}

fn state_problem_inner(state: &Value) -> Option<String> {
    let m = "malformed monitor state";
    let (ledger, latched) = match (state.get("ledger").and_then(Value::as_object), state.get("latched").and_then(Value::as_object)) {
        (Some(l), Some(t)) if state.is_object() => (l, t),
        _ => return Some(m.into()),
    };
    let now = match fin(state.get("now")) {
        Some(n) => n,
        None => return Some(m.into()),
    };
    let seq = match nat_int(state.get("seq")).filter(|s| *s >= 0.0) {
        Some(s) => s,
        None => return Some(format!("{m}: seq")),
    };
    let parent = state.get("parent");
    if !matches!(parent, Some(Value::Null) | Some(Value::String(_))) {
        return Some(format!("{m}: parent"));
    }
    let parent_null = matches!(parent, Some(Value::Null));
    if seq == 0.0 && !parent_null {
        return Some(format!("{m}: genesis has a parent"));
    }
    if seq > 0.0 && parent_null {
        return Some(format!("{m}: missing chain link"));
    }
    if ledger.len() > MAX_STATE_KEYS || latched.len() > MAX_STATE_KEYS {
        return Some(format!("{m}: too many keys"));
    }
    let mut total = 0usize;
    for (k, l) in ledger {
        if bad_key(k) {
            return Some(format!("{m}: bad ledger key"));
        }
        let l = match l.as_array().filter(|l| l.len() <= MAX_LEDGER) {
            Some(l) => l,
            None => return Some(format!("{m}: bad ledger")),
        };
        total += l.len();
        for e in l {
            match (e.is_object(), fin(e.get("t")), fin(e.get("amount"))) {
                (true, Some(t), Some(a)) if a >= 0.0 => {
                    // an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
                    if t > now {
                        return Some(format!("{m}: ledger entry after now (clock regression)"));
                    }
                }
                _ => return Some(format!("{m}: bad ledger entry")),
            }
        }
    }
    if total > MAX_STATE_ENTRIES {
        return Some(format!("{m}: too many entries"));
    }
    for (k, t) in latched {
        if bad_key(k) {
            return Some(format!("{m}: bad latch key"));
        }
        if fin(Some(t)).is_none_or(|t| t > now) {
            return Some(format!("{m}: bad latch"));
        }
    }
    if let Some(dl) = state.get("deadlines") {
        let dl = match dl.as_object() {
            Some(d) => d,
            None => return Some(format!("{m}: deadlines")),
        };
        if dl.len() > MAX_STATE_KEYS {
            return Some(format!("{m}: too many deadline keys"));
        }
        for (k, d) in dl {
            if bad_key(k) {
                return Some(format!("{m}: bad deadline key"));
            }
            // an open obligation always has a strictly positive, integral remaining budget
            if nat_int(Some(d)).is_none_or(|d| !(1.0..=MAX_DEADLINE).contains(&d)) {
                return Some(format!("{m}: bad deadline"));
            }
        }
    }
    None
}

fn entry_of(e: &Value) -> (f64, f64) {
    (fin(e.get("t")).unwrap_or(0.0), fin(e.get("amount")).unwrap_or(0.0))
}

fn cmp_entry(a: &(f64, f64), b: &(f64, f64)) -> std::cmp::Ordering {
    a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

fn entries_json(l: &[(f64, f64)]) -> Value {
    Value::Array(l.iter().map(|(t, a)| json!({"t": num(*t), "amount": num(*a)})).collect())
}

/// Canonical form of a state: unknown fields dropped, ledger entries reduced to `{t, amount}` and sorted, empty ledger arrays
/// omitted, an empty `deadlines` omitted. `Err` carries the state problem.
pub fn canonical_state(state: &Value) -> Result<Value, String> {
    if let Some(p) = state_problem(state) {
        return Err(p);
    }
    let mut ledger = Map::new();
    for (k, l) in state["ledger"].as_object().into_iter().flatten() {
        let mut es: Vec<(f64, f64)> = l.as_array().into_iter().flatten().map(entry_of).collect();
        es.sort_by(cmp_entry);
        if !es.is_empty() {
            ledger.insert(k.clone(), entries_json(&es));
        }
    }
    let mut base = json!({"d": STATE_DIGEST_DOMAIN, "now": state["now"], "seq": state["seq"], "parent": state["parent"], "ledger": ledger, "latched": state["latched"]});
    if let Some(dl) = state.get("deadlines").and_then(Value::as_object).filter(|d| !d.is_empty()) {
        base["deadlines"] = Value::Object(dl.clone());
    }
    Ok(base)
}

/// Deterministic digest of the canonical state (`None` where the reference throws).
pub fn state_digest(state: &Value) -> Option<String> {
    crate::hash_canonical_strict(&canonical_state(state).ok()?)
}

/// Deterministic clock tick: the same state at a later `now`.
pub fn tick_state(state: &Value, now: f64) -> Result<Value, String> {
    if state_problem(state).is_some() {
        return Err("malformed monitor state".into());
    }
    if !now.is_finite() || now < fin(state.get("now")).unwrap_or(0.0) {
        return Err("clock regression".into());
    }
    let mut next = state.clone();
    next["now"] = num(now);
    Ok(next)
}

// ---- the monitor ----------------------------------------------------------------------------

/// Outcome of evaluating the whole constitution against one action.
#[derive(Debug, Clone, PartialEq)]
pub struct ProhibitionResult {
    pub ok: bool,
    pub violated: Vec<String>,
    pub reasons: Vec<String>,
    /// One row per invariant in constitution order: `{id, kind, result: pass | violated, reason?}`.
    pub evaluated: Vec<Value>,
}

impl ProhibitionResult {
    pub fn to_json(&self) -> Value {
        json!({"ok": self.ok, "violated": self.violated, "reasons": self.reasons, "evaluated": self.evaluated})
    }
}

fn all_hold(cs: Option<&Value>, ctx: &Ctx) -> bool {
    cs.and_then(Value::as_array).is_some_and(|l| l.iter().all(|c| evaluate_condition(c, ctx)))
}

/// Window entries (sorted so float sums are order-independent).
fn window_entries(state: &Value, id: &str, window_secs: Option<f64>, now: f64) -> Vec<(f64, f64)> {
    let lo = window_secs.map_or(f64::NEG_INFINITY, |w| now - w * 1000.0);
    let mut v: Vec<(f64, f64)> = state["ledger"].get(id).and_then(Value::as_array).into_iter().flatten().map(entry_of).filter(|(t, _)| *t > lo && *t <= now).collect();
    v.sort_by(cmp_entry);
    v
}

fn amount_of(ctx: &Ctx, path: &str) -> Option<f64> {
    fin(ctx.resolve(path)).filter(|a| *a >= 0.0)
}

fn desc_or(inv: &Value, default: &str) -> String {
    match inv.get("description") {
        None | Some(Value::Null) => default.to_string(),
        Some(d) => js_value_string(d),
    }
}

fn eval_one(inv: &Value, context: &Value, state: &Value) -> (bool, Option<String>) {
    let ctx = &Ctx::new(context);
    let kind = inv.get("kind").and_then(Value::as_str).unwrap_or("");
    let g = |k: &str| inv.get(k).unwrap_or(&Value::Null);
    let id = inv.get("id").and_then(Value::as_str).unwrap_or("");
    let now = fin(state.get("now")).unwrap_or(0.0);
    let latched_has = state["latched"].get(id).is_some();
    match kind {
        "never" => {
            if when_matches(g("when"), context) {
                (false, Some(desc_or(inv, "forbidden action")))
            } else {
                (true, None)
            }
        }
        "never_unless" => {
            if !when_matches(g("when"), context) {
                return (true, None);
            }
            // exceptions must hold AFFIRMATIVELY (plain DSL semantics: unresolvable => false => still forbidden)
            if all_hold(inv.get("unless"), ctx) {
                (true, None)
            } else {
                (false, Some(desc_or(inv, "forbidden without required condition")))
            }
        }
        "cap" => {
            if !when_matches(g("when"), context) {
                return (true, None);
            }
            let a = match amount_of(ctx, inv.get("amount").and_then(Value::as_str).unwrap_or("")) {
                Some(a) => a,
                None => return (false, Some("amount unresolvable (fail closed)".into())),
            };
            let max = fin(inv.get("max")).unwrap_or(0.0);
            let spent: f64 = window_entries(state, id, fin(inv.get("window_secs")), now).iter().fold(0.0, |s, e| s + e.1);
            if spent + a <= max {
                (true, None)
            } else {
                (false, Some(format!("cap exceeded: {} + {} > {}", js_number_string(spent), js_number_string(a), js_number_string(max))))
            }
        }
        "rate" => {
            if !when_matches(g("when"), context) {
                return (true, None);
            }
            let n = window_entries(state, id, fin(inv.get("window_secs")), now).len();
            let max = fin(inv.get("max")).unwrap_or(0.0);
            if (n + 1) as f64 <= max {
                (true, None)
            } else {
                (false, Some(format!("rate exceeded: {} > {} per {}s", n + 1, js_number_string(max), js_number_string(fin(inv.get("window_secs")).unwrap_or(0.0)))))
            }
        }
        "never_after" => {
            if !latched_has || !when_matches(g("forbid"), context) {
                (true, None)
            } else {
                (false, Some(desc_or(inv, "forbidden after trigger")))
            }
        }
        "require_prior" => {
            if !when_matches(g("when"), context) {
                return (true, None);
            }
            if latched_has {
                (true, None)
            } else {
                (false, Some(desc_or(inv, "required prior action not admitted")))
            }
        }
        "require_approval_over" => {
            if !when_matches(g("when"), context) {
                return (true, None);
            }
            let threshold = fin(inv.get("threshold")).unwrap_or(0.0);
            // unresolvable => treated as over
            let over = amount_of(ctx, inv.get("amount").and_then(Value::as_str).unwrap_or("")).is_none_or(|a| a > threshold);
            if !over || all_hold(inv.get("approved"), ctx) {
                (true, None)
            } else {
                (false, Some(desc_or(inv, &format!("approval required over {}", js_number_string(threshold)))))
            }
        }
        _ => (false, Some("evaluation error (fail closed)".into())),
    }
}

fn action_ok(action: &Value) -> bool {
    let a = action.get("action");
    a.and_then(|a| a.get("verb")).is_some_and(Value::is_string) && a.and_then(|a| a.get("resource")).is_some_and(Value::is_string)
}

fn structural(id: &str, reason: String) -> ProhibitionResult {
    ProhibitionResult {
        ok: false,
        violated: vec![id.to_string()],
        reasons: vec![reason.clone()],
        evaluated: vec![json!({"id": id, "kind": "structural", "result": "violated", "reason": reason})],
    }
}

/// Evaluate EVERY invariant (no short-circuit) against the action and the running state. Pure, total, fail-closed. The WHOLE
/// constitution is one document: every invariant and condition shares one regex budget.
pub fn check_prohibitions(action: &Value, constitution: &Value, state: &Value) -> ProhibitionResult {
    with_regex_budget(|| catch_unwind(AssertUnwindSafe(|| check_inner(action, constitution, state))).unwrap_or_else(|_| structural("<monitor>", "monitor error (fail closed)".into())))
}

fn check_inner(action: &Value, constitution: &Value, state: &Value) -> ProhibitionResult {
    if let Some(p) = validate_constitution(constitution).into_iter().next() {
        return structural("<constitution>", p);
    }
    if !action_ok(action) {
        return structural("<action>", "malformed action".into());
    }
    if let Some(p) = state_problem(state) {
        return structural("<state>", p);
    }
    let mut evaluated: Vec<Value> = Vec::new();
    for inv in constitution["invariants"].as_array().into_iter().flatten() {
        let (ok, reason) = catch_unwind(AssertUnwindSafe(|| eval_one(inv, action, state))).unwrap_or((false, Some("evaluation error (fail closed)".into())));
        let mut row = json!({"id": inv["id"], "kind": inv["kind"], "result": if ok { "pass" } else { "violated" }});
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            row["reason"] = json!(r);
        }
        evaluated.push(row);
    }
    let bad: Vec<&Value> = evaluated.iter().filter(|e| e["result"] == "violated").collect();
    ProhibitionResult {
        ok: bad.is_empty(),
        violated: bad.iter().map(|e| s(e, "id").unwrap_or_default()).collect(),
        reasons: bad.iter().map(|e| format!("{}: {}", s(e, "id").unwrap_or_default(), s(e, "reason").unwrap_or_else(|| "violated".into()))).collect(),
        evaluated,
    }
}

/// Pure, deterministic state transition for an ADMITTED action: records cap/rate contributions, latches `never_after` /
/// `require_prior` triggers, prunes expired window entries, bounds the ledger, then extends the hash chain. `Err` — never a silently
/// unchanged state — on anything it cannot record faithfully (a dropped contribution would UNDER-count a cap).
pub fn advance_state_strict(action: &Value, constitution: &Value, state: &Value, now: Option<f64>) -> Result<Value, String> {
    with_regex_budget(|| catch_unwind(AssertUnwindSafe(|| advance_inner(action, constitution, state, now))).unwrap_or_else(|_| Err("advance error (fail closed)".into())))
}

fn advance_inner(action: &Value, constitution: &Value, state: &Value, now: Option<f64>) -> Result<Value, String> {
    if let Some(p) = validate_constitution(constitution).into_iter().next() {
        return Err(p);
    }
    if let Some(p) = state_problem(state) {
        return Err(p);
    }
    let state_now = fin(state.get("now")).unwrap_or(0.0);
    let now = now.unwrap_or(state_now);
    if !now.is_finite() || now < state_now {
        return Err("clock regression".into());
    }
    if !action_ok(action) {
        return Err("malformed action".into());
    }
    let canon = canonical_state(state)?;
    let prev_digest = crate::hash_canonical_strict(&canon).ok_or("advance error (fail closed)")?;
    let action_digest = crate::hash_canonical_strict(action).ok_or("advance error (fail closed)")?;
    let mut ledger: Map<String, Value> = canon["ledger"].as_object().cloned().unwrap_or_default();
    let mut latched: Map<String, Value> = canon["latched"].as_object().cloned().unwrap_or_default();
    let ctx = &Ctx::new(action);
    for inv in constitution["invariants"].as_array().into_iter().flatten() {
        let id = inv["id"].as_str().unwrap_or("");
        match inv["kind"].as_str().unwrap_or("") {
            kind @ ("cap" | "rate") => {
                let prev: Vec<(f64, f64)> = ledger.get(id).and_then(Value::as_array).into_iter().flatten().map(entry_of).collect();
                let window = fin(inv.get("window_secs"));
                let lo = window.map_or(f64::NEG_INFINITY, |w| now - w * 1000.0);
                let mut kept: Vec<(f64, f64)> = prev.into_iter().filter(|(t, _)| *t > lo).collect();
                if when_matches(&inv["when"], action) {
                    let mut amount = 1.0;
                    if kind == "cap" {
                        amount = amount_of(ctx, inv["amount"].as_str().unwrap_or("")).ok_or_else(|| format!("{id}: amount unresolvable"))?;
                    }
                    kept.push((now, amount));
                }
                kept.sort_by(cmp_entry);
                if kept.len() > MAX_LEDGER {
                    if kind == "rate" {
                        return Err(format!("{id}: rate ledger overflow"));
                    }
                    while kept.len() > MAX_LEDGER {
                        // merge the oldest two; keeps the LATER time => never under-counts a cap
                        let (x, y) = (kept.remove(0), kept.remove(0));
                        kept.insert(0, (y.0, x.1 + y.1));
                    }
                }
                if kept.is_empty() {
                    ledger.remove(id);
                } else {
                    ledger.insert(id.to_string(), entries_json(&kept));
                }
            }
            // conservative match: an ambiguous trigger latches (stricter)
            "never_after" => {
                if !latched.contains_key(id) && when_matches(&inv["after"], action) {
                    latched.insert(id.to_string(), num(now));
                }
            }
            // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
            "require_prior" => {
                if !latched.contains_key(id) && when_affirmative(&inv["prior"], action) {
                    latched.insert(id.to_string(), num(now));
                }
            }
            _ => {}
        }
    }
    let seq = nat_int(state.get("seq")).unwrap_or(0.0) + 1.0;
    let parent = crate::hash_canonical_strict(&json!({"d": STATE_CHAIN_DOMAIN, "state": prev_digest, "action": action_digest})).ok_or("advance error (fail closed)")?;
    let next = json!({"now": num(now), "seq": num(seq), "parent": parent, "ledger": ledger, "latched": latched});
    if state_problem(&next).is_some() {
        return Err("resulting state invalid".into());
    }
    Ok(next)
}

/// AFFIRMATIVE trigger match (plain permission-DSL semantics, unresolvable => not matched).
pub fn when_affirmative(w: &Value, context: &Value) -> bool {
    catch_unwind(AssertUnwindSafe(|| validate_when(w, "when").is_none() && crate::predicates::predicate_matches(w, &Ctx::new(context)))).unwrap_or(false)
}

// ---- per-action safety evidence ----------------------------------------------------------------

fn safe(f: Option<String>) -> String {
    f.unwrap_or_else(|| UNHASHABLE.to_string())
}

fn evidence_from(r: &ProhibitionResult, action: &Value, constitution: &Value, state: &Value) -> Value {
    let (cid, adg, sdg) = (safe(constitution_id(constitution)), safe(crate::hash_canonical_strict(action)), safe(state_digest(state)));
    let mut extra: Vec<String> = Vec::new();
    for (d, name) in [(&cid, "<constitution>"), (&adg, "<action>"), (&sdg, "<state>")] {
        if d == UNHASHABLE {
            extra.push(name.to_string());
        }
    }
    let mut violated = r.violated.clone();
    violated.extend(extra.iter().filter(|x| !r.violated.contains(x)).cloned());
    json!({"v": EVIDENCE_VERSION, "constitution": cid, "action_digest": adg, "state_digest": sdg,
        "now": fin(state.get("now")).map_or(json!(0), num), "evaluated": r.evaluated, "ok": r.ok && extra.is_empty(), "violated": violated})
}

/// The evidence a verifier re-checks. Anything that cannot be digested makes it `ok: false` with the structural id in `violated`.
pub fn prove_safety(action: &Value, constitution: &Value, state: &Value) -> Value {
    evidence_from(&check_prohibitions(action, constitution, state), action, constitution, state)
}

/// Offline re-check: recompute the monitor from (action, constitution, state) and require the evidence to match EXACTLY.
pub fn verify_safety_evidence(evidence: &Value, action: &Value, constitution: &Value, state: &Value) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| {
        if !evidence.is_object() || fin(evidence.get("v")) != Some(EVIDENCE_VERSION as f64) {
            return Err("unsupported evidence version".to_string());
        }
        let fresh = prove_safety(action, constitution, state);
        for (k, msg) in [("constitution", "constitution mismatch"), ("action_digest", "action digest mismatch"), ("state_digest", "state digest mismatch")] {
            if fresh.get(k) != evidence.get(k) {
                return Err(msg.to_string());
            }
        }
        match (crate::hash_canonical_strict(&fresh), crate::hash_canonical_strict(evidence)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => return Err("evidence does not reproduce".to_string()),
            _ => return Err("verification error (fail closed)".to_string()),
        }
        if fresh["ok"] != true {
            let v: Vec<String> = fresh["violated"].as_array().into_iter().flatten().map(js_value_string).collect();
            return Err(format!("prohibition violated: {}", v.join(",")));
        }
        Ok(())
    }))
    .unwrap_or_else(|_| Err("verification error (fail closed)".to_string()))
}

// ---- signed + bound safety evidence ---------------------------------------------------------------

/// Binding id: commits to signer + evidence digest + the three bound digests (`None` on unhashable evidence).
pub fn safety_binding_id(evidence: &Value, signer: &str) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), json!(SAFETY_EVIDENCE_SIG_DOMAIN));
    m.insert("signer".into(), json!(signer));
    m.insert("evidence".into(), json!(crate::hash_canonical_strict(evidence)?));
    for k in ["constitution", "action_digest", "state_digest"] {
        if let Some(v) = evidence.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    crate::hash_canonical_strict(&Value::Object(m))
}

/// Verify signed evidence offline. Checks, in order: expectations present; signer pinned; binding id recomputed; signature; evidence
/// bound to the expected action / constitution / state (digest equality); the expected constitution well formed; the evidence
/// internally consistent; and, when action + constitution + state are all supplied, full recomputation. Unless `requireOk: false`, the
/// evidence must attest an admit. Total. `expected` members: `signer` (string or array), `action` / `actionDigest`,
/// `constitution` / `constitutionId`, `principal`, `state` / `stateDigest`, `requireOk`.
pub fn verify_signed_safety_evidence(signed: &Value, expected: &Value) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| verify_signed_inner(signed, expected))).unwrap_or_else(|_| Err("verification error (fail closed)".to_string()))
}

fn verify_signed_inner(signed: &Value, expected: &Value) -> Result<(), String> {
    let no = |r: &str| Err(r.to_string());
    let ev = match (signed.is_object(), signed.get("evidence"), expected.is_object()) {
        (true, Some(e), true) if e.is_object() => e,
        _ => return no("malformed input"),
    };
    if fin(ev.get("v")) != Some(EVIDENCE_VERSION as f64) {
        return no("unsupported evidence version");
    }
    let signers: Vec<&Value> = match expected.get("signer") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v) => vec![v],
        None => vec![&Value::Null],
    };
    if signers.is_empty() || signers.iter().any(|x| !x.as_str().is_some_and(|x| !x.is_empty())) {
        return no("no pinned signer");
    }
    let signer = match signed.get("signer").and_then(Value::as_str).filter(|sg| signers.iter().any(|x| x.as_str() == Some(sg))) {
        Some(sg) => sg,
        None => return no("signer not trusted"),
    };
    let ex = |k: &str| expected.get(k);
    if ex("action").is_none() && ex("actionDigest").is_none() {
        return no("unbound: action not specified");
    }
    if ex("constitution").is_none() && ex("constitutionId").is_none() {
        return no("unbound: constitution not specified");
    }
    if ex("state").is_none() && ex("stateDigest").is_none() {
        return no("unbound: state not specified");
    }
    let id = match signed.get("id").and_then(Value::as_str) {
        Some(id) if safety_binding_id(ev, signer).as_deref() == Some(id) => id,
        _ => return no("binding id mismatch"),
    };
    match signed.get("sig").and_then(Value::as_str) {
        Some(sig) if crate::verify_b64u(signer, &domain_message(SAFETY_EVIDENCE_SIG_DOMAIN, id), sig) => {}
        _ => return no("bad signature"),
    }

    let want_action: Value = match ex("action") {
        Some(a) => json!(crate::hash_canonical_strict(a).ok_or("verification error (fail closed)")?),
        None => ex("actionDigest").cloned().unwrap_or(Value::Null),
    };
    if ex("action").is_some() && ex("actionDigest").is_some_and(|d| *d != want_action) {
        return no("expected action and digest disagree");
    }
    if ev.get("action_digest") != Some(&want_action) {
        return no("action digest mismatch (evidence bound to another action)");
    }

    if let Some(p) = ex("principal") {
        let sc = match ex("constitution") {
            Some(sc) if sc.get("sig").is_some_and(Value::is_string) => sc,
            _ => return no("principal pin requires a signed constitution"),
        };
        if let Err(why) = verify_constitution(sc, p.as_str()) {
            return Err(format!("constitution not authentic: {why}"));
        }
    }
    let want_const: Value = match ex("constitution") {
        Some(c) => json!(constitution_id(c).ok_or("verification error (fail closed)")?),
        None => ex("constitutionId").cloned().unwrap_or(Value::Null),
    };
    if ex("constitution").is_some() && ex("constitutionId").is_some_and(|d| *d != want_const) {
        return no("expected constitution and id disagree");
    }
    if ev.get("constitution") != Some(&want_const) {
        return no("constitution mismatch (evidence bound to another constitution)");
    }
    // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
    if let Some(c) = ex("constitution") {
        if let Some(first) = validate_constitution(c).into_iter().next() {
            return Err(format!("constitution malformed: {first}"));
        }
    }

    let want_state: Value = match ex("state") {
        Some(st) => json!(state_digest(st).ok_or("verification error (fail closed)")?),
        None => ex("stateDigest").cloned().unwrap_or(Value::Null),
    };
    if ex("state").is_some() && ex("stateDigest").is_some_and(|d| *d != want_state) {
        return no("expected state and digest disagree");
    }
    if ev.get("state_digest") != Some(&want_state) {
        return no("state digest mismatch (evidence bound to another state)");
    }

    // internal consistency: the claimed verdict must follow from the claimed rows
    let (rows, violated) = match (ev.get("evaluated").and_then(Value::as_array), ev.get("violated").and_then(Value::as_array)) {
        (Some(r), Some(v)) => (r, v),
        _ => return no("malformed evidence"),
    };
    if rows.iter().any(|r| r.is_object() && r.get("id").is_some_and(|i| !i.is_string())) {
        return no("malformed evidence");
    }
    let bad_rows = rows.iter().filter(|r| r.get("result").and_then(Value::as_str) != Some("pass")).count();
    let ev_ok = ev.get("ok");
    if ev_ok != Some(&json!(bad_rows == 0 && violated.is_empty())) {
        return no("evidence verdict inconsistent with rows");
    }
    let attests_ok = ev_ok == Some(&json!(true));

    if let (Some(a), Some(c), Some(st)) = (ex("action"), ex("constitution"), ex("state")) {
        if let Err(why) = verify_safety_evidence(ev, a, c, st) {
            if attests_ok {
                return Err(why);
            }
            if !why.starts_with("prohibition violated") {
                return Err(why);
            }
        }
    } else if attests_ok {
        if let Some(c) = ex("constitution") {
            let ids: Vec<Option<&Value>> = c["invariants"].as_array().into_iter().flatten().map(|i| i.get("id")).collect();
            if rows.len() != ids.len() || rows.iter().zip(&ids).any(|(r, i)| r.get("id") != *i) {
                return no("evidence does not cover every invariant");
            }
        }
    }
    if ex("requireOk") != Some(&json!(false)) && !attests_ok {
        let v: Vec<String> = violated.iter().map(js_value_string).collect();
        return Err(format!("prohibition violated: {}", v.join(",")));
    }
    Ok(())
}

// ---- composition and the atomic check-and-advance kernel ----------------------------------------------

/// Outcome of [`check_and_advance`]: `decided_by` is `prohibition`, `permission`, `none` (allowed) or `state`; `next` equals the
/// input state unless `allow`.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckAndAdvance {
    pub allow: bool,
    pub decided_by: &'static str,
    pub evidence: Value,
    pub prohibition: ProhibitionResult,
    pub next: Value,
    pub reason: Option<String>,
}

/// The pure kernel of the server's critical section: guard the head (`expected_seq` / `expected_state_digest`), compose authority
/// (`allow = permitted AND prohibitions.ok`), build evidence against the pre-state, and on allow compute the next state. Persisting
/// `next` iff `allow` MUST happen in the same atomic step that read `state`.
pub fn check_and_advance(permitted: bool, action: &Value, constitution: &Value, state: &Value, expected_seq: Option<f64>, expected_state_digest: Option<&str>) -> CheckAndAdvance {
    // ONE document: the constitution is evaluated once and that result feeds both the evidence and the decision
    let monitored = check_prohibitions(action, constitution, state);
    let evidence = evidence_from(&monitored, action, constitution, state);
    let decided = if !monitored.ok { "prohibition" } else if permitted { "none" } else { "permission" };
    let refuse = |decided_by: &'static str, reason: Option<&str>| CheckAndAdvance {
        allow: false,
        decided_by,
        evidence: evidence.clone(),
        prohibition: monitored.clone(),
        next: state.clone(),
        reason: reason.map(String::from),
    };
    if let Some(seq) = expected_seq {
        if !state.is_object() || fin(state.get("seq")) != Some(seq) {
            return refuse("state", Some("stale state head (seq)"));
        }
    }
    if let Some(d) = expected_state_digest {
        if safe(state_digest(state)) != d {
            return refuse("state", Some("stale state head (digest)"));
        }
    }
    if !(permitted && monitored.ok) {
        return refuse(if decided == "none" { "permission" } else { decided }, None);
    }
    if evidence["ok"] != true {
        return refuse("prohibition", Some("evidence not attestable"));
    }
    match advance_state_strict(action, constitution, state, None) {
        Ok(next) => CheckAndAdvance { allow: true, decided_by: "none", evidence, prohibition: monitored, next, reason: None },
        Err(why) => refuse("state", Some(&format!("advance failed: {why}"))),
    }
}
