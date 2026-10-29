//! Decision obligations (verification side): validate, merge, the PEP gate and the overdue outcome. An allow whose obligations the
//! enforcement point cannot all perform becomes a deny. Total: no function panics. A JSON null list is the empty list.
//! Replays packages/pca/conformance/obligations-vectors.json.
use crate::{canonicalize_strict, pep_decision, safe_int};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

/// `undo_window {id, window_end}`: the action runs under a veto window (undo ledger record `id`, open until `window_end`). An
/// enforcement point that does not run undo windows must not list it as supported (the gate then turns the allow into a deny).
pub const OBLIGATION_KINDS: [&str; 6] = ["log", "notify", "redact", "watermark", "require_receipt", "undo_window"];
pub const MAX_OBLIGATIONS: usize = 16;

fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}
fn is_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|x| !x.is_empty() && x.encode_utf16().count() <= max)
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`
fn field_ok(f: &str) -> bool {
    let segs: Vec<&str> = f.split('.').collect();
    segs.len() <= 8
        && segs.iter().all(|g| {
            let b = g.as_bytes();
            (1..=64).contains(&b.len()) && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        })
}

fn params_error(kind: &str, p: &serde_json::Map<String, Value>) -> Option<String> {
    let allowed: &[&str] = match kind {
        "log" => &["sink"],
        "notify" => &["to"],
        "redact" => &["fields"],
        "watermark" => &["id"],
        "undo_window" => &["id", "window_end"],
        _ => &[],
    };
    if let Some(k) = p.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Some(format!("unknown parameter '{k}' for '{kind}'"));
    }
    if kind == "log" && p.contains_key("sink") && !is_str(p.get("sink"), 128) {
        return Some("log.sink must be a non-empty string of at most 128 characters".into());
    }
    if kind == "notify" && !is_str(p.get("to"), 256) {
        return Some("notify.to is required".into());
    }
    if kind == "watermark" && !is_str(p.get("id"), 128) {
        return Some("watermark.id is required".into());
    }
    if kind == "undo_window" && (!is_str(p.get("id"), 128) || nat(p.get("window_end")).is_none()) {
        return Some("undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)".into());
    }
    if kind == "redact" {
        let f = p.get("fields").and_then(Value::as_array);
        let names: Vec<&str> = f.map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        if !f.is_some_and(|a| !a.is_empty() && a.len() <= 32 && names.len() == a.len() && names.iter().all(|x| field_ok(x))) {
            return Some("redact.fields must be 1..32 dotted field paths".into());
        }
        if names.iter().collect::<HashSet<_>>().len() != names.len() {
            return Some("redact.fields has a duplicate".into());
        }
    }
    None
}

/// `None` = well formed.
pub fn obligation_error(o: &Value) -> Option<String> {
    let Some(m) = o.as_object() else { return Some("an obligation must be an object".into()) };
    if let Some(k) = m.keys().find(|k| !matches!(k.as_str(), "kind" | "params" | "due")) {
        return Some(format!("unknown member '{k}'"));
    }
    let kind = m.get("kind").and_then(Value::as_str).filter(|k| OBLIGATION_KINDS.contains(k));
    let Some(kind) = kind else { return Some("unknown obligation kind".into()) };
    if m.contains_key("due") && nat(m.get("due")).is_none() {
        return Some("due must be a non-negative safe integer".into());
    }
    let empty = serde_json::Map::new();
    let p = match m.get("params") {
        None => &empty,
        Some(x) => match x.as_object() {
            Some(p) => p,
            None => return Some("params must be an object".into()),
        },
    };
    params_error(kind, p)
}

/// The canonical identity of a (valid) obligation: strict canonical JSON of `{kind, params ({} when absent), due?}`.
pub fn obligation_key(o: &Value) -> Option<String> {
    let params = o.get("params").filter(|p| !p.is_null()).cloned().unwrap_or_else(|| json!({}));
    let mut body = json!({"kind": o.get("kind")?, "params": params});
    if let Some(d) = o.get("due") {
        body["due"] = d.clone();
    }
    canonicalize_strict(&body).ok()
}

/// `None` = a well-formed, duplicate-free list of at most 16. Null is the empty list.
pub fn obligations_error(list: &Value) -> Option<String> {
    if list.is_null() {
        return None;
    }
    let Some(l) = list.as_array() else { return Some("obligations must be an array".into()) };
    if l.len() > MAX_OBLIGATIONS {
        return Some("more than 16 obligations".into());
    }
    let mut seen = HashSet::new();
    for (i, o) in l.iter().enumerate() {
        if let Some(e) = obligation_error(o) {
            return Some(format!("obligations[{i}]: {e}"));
        }
        let Some(key) = obligation_key(o) else { return Some(format!("obligations[{i}]: not canonicalizable")) };
        if !seen.insert(key) {
            return Some(format!("obligations[{i}] duplicates an earlier obligation"));
        }
    }
    None
}

/// The union of the lists, deduplicated by key and sorted by key in UTF-8 byte order. `Err` is a refusal.
pub fn merge_obligations(lists: &[Value]) -> Result<Vec<Value>, String> {
    let mut by: BTreeMap<String, Value> = BTreeMap::new();
    for l in lists {
        if let Some(e) = obligations_error(l) {
            return Err(e);
        }
        for o in l.as_array().into_iter().flatten() {
            by.insert(obligation_key(o).unwrap_or_default(), o.clone());
        }
    }
    if by.len() > MAX_OBLIGATIONS {
        return Err("more than 16 obligations after merging".into());
    }
    Ok(by.into_values().collect())
}

#[derive(Debug, PartialEq)]
pub struct ObligationGate {
    /// `allow`, `deny` or `escalate`.
    pub decision: &'static str,
    pub perform: Vec<Value>,
    pub unsupported: Vec<String>,
}

/// An allow (or an answered escalate) with any obligation outside `supported` is a deny, as is any malformed input.
pub fn pep_obligation_gate(decision: &str, answered: bool, obligations: &Value, supported: &Value) -> ObligationGate {
    let deny = |unsupported: Vec<String>| ObligationGate { decision: "deny", perform: vec![], unsupported };
    match pep_decision(decision, answered) {
        "allow" => {}
        "escalate" => return ObligationGate { decision: "escalate", perform: vec![], unsupported: vec![] },
        _ => return deny(vec![]),
    }
    if obligations_error(obligations).is_some() {
        return deny(vec![]);
    }
    let Some(sup) = supported.as_array().filter(|a| a.iter().all(Value::is_string)) else { return deny(vec![]) };
    let list: Vec<Value> = obligations.as_array().cloned().unwrap_or_default();
    let mut missing: Vec<String> = list.iter().filter_map(|o| o["kind"].as_str()).filter(|k| !sup.iter().any(|s| s.as_str() == Some(*k))).map(String::from).collect();
    missing.sort();
    missing.dedup();
    if missing.is_empty() { ObligationGate { decision: "allow", perform: list, unsupported: vec![] } } else { deny(missing) }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ObligationOutcome {
    /// `ok` or `escalate`.
    pub outcome: &'static str,
    pub overdue: Vec<usize>,
    /// `obligation_unmet` on escalate.
    pub status: Option<&'static str>,
}

/// Which obligations are overdue (`due <= now`, index not in `fulfilled`)? Malformed input is overdue-everything.
pub fn obligation_outcome(obligations: &Value, fulfilled: &Value, now: &Value) -> ObligationOutcome {
    let list = obligations.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let done: Option<Vec<i64>> = fulfilled.as_array().and_then(|a| a.iter().map(|x| nat(Some(x))).collect());
    let now = nat(Some(now));
    let (Some(done), Some(now), None) = (done, now, obligations_error(obligations)) else {
        return ObligationOutcome { outcome: "escalate", overdue: (0..list.len()).collect(), status: Some("obligation_unmet") };
    };
    let overdue: Vec<usize> = list.iter().enumerate().filter(|(i, o)| nat(o.get("due")).is_some_and(|d| d <= now) && !done.contains(&(*i as i64))).map(|(i, _)| i).collect();
    if overdue.is_empty() { ObligationOutcome { outcome: "ok", overdue, status: None } } else { ObligationOutcome { outcome: "escalate", overdue, status: Some("obligation_unmet") } }
}
