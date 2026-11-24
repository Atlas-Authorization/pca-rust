//! Forbid-wins decision witness and certificate (security contract C-240, C-241): a port of `decideClauses`, `certify` and
//! `checkForbidCertificate` in `forbid-certificate.ts`, with the veto-polarity trigger (`whenMatches`) of `prohibitions.ts`.
//!
//! A policy is a flat list of CLAUSES. `permit` clauses grant (plain permission semantics: anything that cannot be decided is "not
//! matched"). `forbid` clauses veto and `escalate` clauses cap the decision at escalate; both use the prohibition polarity (anything
//! that cannot be decided is "matched"). The decision is order-independent: any forbid matched denies; else no permit matched denies;
//! else any escalate matched escalates; else allow. Every function is total: a malformed clause or action is a `deny` whose winner is
//! `malformed`.
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Map, Value};

use crate::policy_authoring::forbid_certificate_consistent;
use crate::predicates::{evaluate_condition_tri, predicate_matches, Ctx, Tri, MAX_RE_RESOURCE_LEN};
use crate::safe_regex::{is_safe_regex_source, regex_refusals};

/// Most clauses one policy may carry.
pub const MAX_CLAUSES: usize = 512;
const MAX_CONDITION_DEPTH: usize = 32;
const OPS: [&str; 14] = ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of"];

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn nonempty_str(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

pub(crate) fn validate_condition(c: &Value, depth: usize) -> Option<String> {
    let o = match c.as_object() {
        Some(o) => o,
        None => return Some("condition not an object".into()),
    };
    if depth > MAX_CONDITION_DEPTH {
        return Some("condition nesting too deep".into());
    }
    if o.contains_key("all_of") || o.contains_key("any_of") || o.contains_key("not") {
        if let Some(n) = o.get("not") {
            return validate_condition(n, depth + 1);
        }
        let key = if o.contains_key("all_of") { "all_of" } else { "any_of" };
        return match o[key].as_array() {
            Some(arr) if !arr.is_empty() => arr.iter().find_map(|ch| validate_condition(ch, depth + 1)),
            _ => Some(format!("condition.{key} must be a non-empty array")),
        };
    }
    if !nonempty_str(o.get("field")) {
        return Some("condition.field missing".into());
    }
    let op = match o.get("op").and_then(Value::as_str).filter(|op| OPS.contains(op)) {
        Some(op) => op,
        None => return Some(format!("unknown condition op {}", o.get("op").map_or_else(|| "undefined".to_string(), crate::intent_v2::js_value_string))),
    };
    if o.get("ref").is_some_and(|r| !nonempty_str(Some(r))) {
        return Some("bad condition.ref".into());
    }
    if op == "member_of" && o.get("collection").is_some_and(|c| !nonempty_str(Some(c))) {
        return Some("bad condition.collection".into());
    }
    None
}

/// The structural problem of a trigger `{verb, resource?, where?}` (`None` = well formed).
pub fn validate_when(w: &Value, label: &str) -> Option<String> {
    let o = match w.as_object() {
        Some(o) => o,
        None => return Some(format!("{label}: not an object")),
    };
    let verb_ok = match o.get("verb") {
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty() && a.iter().all(|x| nonempty_str(Some(x))),
        _ => false,
    };
    if !verb_ok {
        return Some(format!("{label}: bad verb"));
    }
    if let Some(r) = o.get("resource") {
        let r = match r.as_str() {
            Some(r) => r,
            None => return Some(format!("{label}: bad resource")),
        };
        if let Some(src) = r.strip_prefix("re:") {
            // an unsafe or over-long regex would make the matcher return false: the veto would silently NOT apply
            let units: Vec<u16> = src.encode_utf16().collect();
            if units.len() > 200 || !is_safe_regex_source(&units) {
                return Some(format!("{label}: unsafe regex resource"));
            }
        }
    }
    if let Some(wh) = o.get("where") {
        let list = match wh.as_array() {
            Some(l) => l,
            None => return Some(format!("{label}: where not an array")),
        };
        if let Some(e) = list.iter().find_map(|c| validate_condition(c, 0)) {
            return Some(format!("{label}: {e}"));
        }
    }
    None
}

/// The VETO reading of a trigger: verb and resource exactly as the permission DSL, the where-conditions conservatively; every failure
/// to decide (a malformed trigger, an unsafe or oversized regex, an unknown op, a missing field or operand) counts as MATCHED. Total.
pub fn when_matches(w: &Value, context: &Value) -> bool {
    let ctx = &Ctx::new(context);
    catch_unwind(AssertUnwindSafe(|| {
        if validate_when(w, "when").is_some() {
            return true;
        }
        let a = ctx.root.get("action");
        let (verb, resource) = match (a.and_then(|a| a.get("verb")), a.and_then(|a| a.get("resource")).and_then(Value::as_str)) {
            (Some(Value::String(_)), Some(r)) => (w["verb"].clone(), r),
            _ => return true,
        };
        let is_re = w.get("resource").and_then(Value::as_str).is_some_and(|r| r.starts_with("re:"));
        // an oversized subject for a regex resource would be "no match": a veto must say "match"
        let oversized = is_re && u16len(resource) > MAX_RE_RESOURCE_LEN;
        // a regex evaluation REFUSED by the document budget is "could not decide", never "no match"
        let refused0 = regex_refusals();
        let mut trigger = Map::new();
        trigger.insert("verb".into(), verb);
        if let (false, Some(r)) = (oversized, w.get("resource")) {
            trigger.insert("resource".into(), r.clone());
        }
        if !predicate_matches(&Value::Object(trigger), ctx) && regex_refusals() == refused0 {
            return false;
        }
        for c in w.get("where").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            if evaluate_condition_tri(c, ctx) == Tri::False {
                return false;
            }
        }
        true
    }))
    .unwrap_or(true)
}

/// `Err` = the clause list is not well formed (distinct ids, known kinds, a predicate for each).
pub fn clauses_error(clauses: &Value) -> Option<String> {
    let list = match clauses.as_array() {
        Some(l) => l,
        None => return Some("clauses must be an array".into()),
    };
    if list.len() > MAX_CLAUSES {
        return Some(format!("more than {MAX_CLAUSES} clauses"));
    }
    let mut seen: Vec<&str> = Vec::new();
    for (i, c) in list.iter().enumerate() {
        let o = match c.as_object() {
            Some(o) => o,
            None => return Some(format!("clauses[{i}] must be an object")),
        };
        let id = match o.get("id").and_then(Value::as_str).filter(|s| (1..=128).contains(&u16len(s))) {
            Some(id) => id,
            None => return Some(format!("clauses[{i}].id must be a string of 1..128 characters")),
        };
        if seen.contains(&id) {
            return Some(format!("clauses[{i}].id '{id}' is a duplicate"));
        }
        seen.push(id);
        if !o.get("kind").and_then(Value::as_str).is_some_and(|k| matches!(k, "permit" | "forbid" | "escalate")) {
            return Some(format!("clauses[{i}].kind must be permit, forbid or escalate"));
        }
        if o.get("signer").is_some_and(|s| !s.as_str().is_some_and(|s| u16len(s) <= 256)) {
            return Some(format!("clauses[{i}].signer must be a string of at most 256 characters"));
        }
        if !o.get("when").is_some_and(Value::is_object) {
            return Some(format!("clauses[{i}].when must be a predicate object"));
        }
    }
    None
}

/// Signers, most authoritative first (`precedence`), and the signers whose permits count (`permit_signers`, `None` = every signer).
#[derive(Debug, Clone, Default)]
pub struct ClauseOptions {
    pub precedence: Vec<String>,
    pub permit_signers: Option<Vec<String>>,
}

/// One clause's value in the table: `true`, `false` or `unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClauseRow {
    pub id: String,
    pub kind: String,
    pub value: &'static str,
}

/// A decision with its witness: `winner` is `(kind, id)` where kind is a clause kind, `none` or `malformed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClauseDecision {
    pub decision: &'static str,
    pub winner: (&'static str, Option<String>),
    pub shadowed: Vec<String>,
    pub values: Vec<ClauseRow>,
}

impl ClauseDecision {
    fn malformed() -> Self {
        ClauseDecision { decision: "deny", winner: ("malformed", None), shadowed: Vec::new(), values: Vec::new() }
    }
    /// The decision as the conformance vectors state it.
    pub fn to_json(&self) -> Value {
        json!({"decision": self.decision, "winner": {"kind": self.winner.0, "id": self.winner.1}, "shadowed": self.shadowed,
            "values": self.values.iter().map(|r| json!({"id": r.id, "kind": r.kind, "value": r.value})).collect::<Vec<_>>()})
    }
}

fn s_of<'a>(c: &'a Value, k: &str) -> &'a str {
    c.get(k).and_then(Value::as_str).unwrap_or("")
}

fn rank(signer: Option<&str>, precedence: &[String]) -> usize {
    signer.and_then(|s| precedence.iter().position(|p| p == s)).unwrap_or(precedence.len())
}

fn u16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn value_of(c: &Value, context: &Value) -> &'static str {
    let ctx = &Ctx::new(context);
    let when = &c["when"];
    if s_of(c, "kind") == "permit" {
        return if predicate_matches(when, ctx) { "true" } else { "false" };
    }
    // veto polarity: clean match -> true; cannot-decide-but-the-veto-applies -> unknown; clean miss -> false
    if !when_matches(when, context) {
        "false"
    } else if predicate_matches(when, ctx) {
        "true"
    } else {
        "unknown"
    }
}

/// Decide a clause list against an action context `{action: {verb, resource, params?}, subject?, env?}`. Order-independent for the
/// decision; the named winner is deterministic.
pub fn decide_clauses(clauses: &Value, context: &Value, opts: &ClauseOptions) -> ClauseDecision {
    catch_unwind(AssertUnwindSafe(|| decide_inner(clauses, context, opts))).unwrap_or_else(|_| ClauseDecision::malformed())
}

fn decide_inner(clauses: &Value, context: &Value, opts: &ClauseOptions) -> ClauseDecision {
    if clauses_error(clauses).is_some() {
        return ClauseDecision::malformed();
    }
    let a = context.get("action");
    if !(a.and_then(|a| a.get("verb")).is_some_and(Value::is_string) && a.and_then(|a| a.get("resource")).is_some_and(Value::is_string)) {
        return ClauseDecision::malformed();
    }
    let list = clauses.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let active = |c: &Value| {
        s_of(c, "kind") != "permit"
            || opts.permit_signers.as_ref().is_none_or(|ps| c.get("signer").and_then(Value::as_str).is_some_and(|s| ps.iter().any(|p| p == s)))
    };
    let values: Vec<ClauseRow> = list
        .iter()
        .map(|c| ClauseRow { id: s_of(c, "id").to_string(), kind: s_of(c, "kind").to_string(), value: if active(c) { value_of(c, context) } else { "false" } })
        .collect();
    let hit = |k: &str| -> Vec<usize> { (0..list.len()).filter(|i| values[*i].kind == k && values[*i].value != "false").collect() };
    let mut forbids = hit("forbid");
    forbids.sort_by(|x, y| {
        let (cx, cy) = (&list[*x], &list[*y]);
        rank(cx.get("signer").and_then(Value::as_str), &opts.precedence)
            .cmp(&rank(cy.get("signer").and_then(Value::as_str), &opts.precedence))
            .then_with(|| u16_cmp(s_of(cx, "id"), s_of(cy, "id")))
    });
    let (permits, escalates) = (hit("permit"), hit("escalate"));
    let others = |win: Option<usize>| -> Vec<String> {
        forbids.iter().chain(permits.iter()).chain(escalates.iter()).filter(|i| Some(**i) != win).map(|i| values[*i].id.clone()).collect()
    };
    let (decision, kind, win): (&'static str, &'static str, Option<usize>) = if let Some(w) = forbids.first() {
        ("deny", "forbid", Some(*w))
    } else if permits.is_empty() {
        ("deny", "none", None)
    } else if let Some(w) = escalates.first() {
        ("escalate", "escalate", Some(*w))
    } else {
        ("allow", "permit", Some(permits[0]))
    };
    ClauseDecision { decision, winner: (kind, win.map(|w| values[w].id.clone())), shadowed: others(win), values }
}

/// The canonical certificate for a decision (`None` where the reference's canonical hash throws).
pub fn certify(clauses: &Value, context: &Value, opts: &ClauseOptions) -> Option<Value> {
    let d = decide_clauses(clauses, context, opts);
    fn signer_of<'a>(clauses: &'a Value, id: &str) -> Option<&'a str> {
        clauses.as_array()?.iter().find(|c| s_of(c, "id") == id).and_then(|c| c.get("signer")).and_then(Value::as_str)
    }
    let rows: Vec<Value> = d
        .values
        .iter()
        .map(|v| {
            let mut m = Map::new();
            m.insert("id".into(), json!(v.id));
            m.insert("kind".into(), json!(v.kind));
            if let Some(s) = signer_of(clauses, &v.id) {
                m.insert("signer".into(), json!(s));
            }
            m.insert("value".into(), json!(v.value));
            Value::Object(m)
        })
        .collect();
    Some(json!({"v": 1, "kind": "forbid-wins", "policy": crate::hash_canonical_strict(clauses)?, "action": crate::hash_canonical_strict(context)?,
        "decision": d.decision, "winner": {"kind": d.winner.0, "id": d.winner.1}, "shadowed": d.shadowed, "clauses": rows}))
}

/// Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form). `Err` is the reason.
pub fn check_forbid_certificate(cert: &Value, clauses: &Value, context: &Value, opts: &ClauseOptions) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| {
        if clauses_error(clauses).is_some() {
            return Err("malformed clauses".to_string());
        }
        if !forbid_certificate_consistent(cert, &opts.precedence) {
            return Err("certificate table does not entail its decision".to_string());
        }
        let again = certify(clauses, context, opts).ok_or_else(|| "certificate check error (fail closed)".to_string())?;
        match (crate::hash_canonical_strict(&again), crate::hash_canonical_strict(cert)) {
            (Some(a), Some(b)) if a == b => Ok(()),
            (Some(_), Some(_)) => Err("certificate does not match the recomputed decision".to_string()),
            _ => Err("certificate check error (fail closed)".to_string()),
        }
    }))
    .unwrap_or_else(|_| Err("certificate check error (fail closed)".to_string()))
}
