//! Session histories (Intent Layer v2 section 2.1): the host side of accumulators and monitors. Mirrors
//! `packages/pca/src/intent-history.ts`. The verifier receives the PRE-STATE of the action's group from its own store; these
//! functions compute it from the session's event history (window, key, selection and counted statuses applied) and fold a
//! monitor over it. They are pure: the store, its lock and the reservation are the host's. An `Err` is the reference's throw
//! (a corrupt history, an unusable candidate), which the caller turns into a denial.

use serde_json::{json, Map, Value};

use super::intent_acc::{acc_selects, acc_value_of, combine_acc, pre_value};
use super::intent_strict::{s, sint};
use super::predicates::{predicate_matches, Ctx};
use super::{canonicalize_strict, MAX_SAFE};

fn counted(status: Option<&Value>) -> bool {
    matches!(s(status), Some("reserved") | Some("committed"))
}

fn fnum(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

/// `inWindow(win, ti, t)`: does the counted event stamped `ti` still count at `t`? task: always; sliding(ms): (t - ms, t];
/// period(ms, t0): the period containing t; and every event stamped AFTER t (it has not left any window). A time that is not
/// a safe integer is in no window (fail closed).
pub(crate) fn in_window(win: &Map<String, Value>, ti: Option<&Value>, t: Option<&Value>) -> bool {
    let (ti, t) = match (sint(ti), sint(t)) {
        (Some(a), Some(b)) => (a as f64, b as f64),
        _ => return false,
    };
    if ti > t {
        return true;
    }
    match s(win.get("kind")) {
        Some("task") => true,
        Some("sliding") => ti > t - fnum(win.get("ms")),
        Some("period") => {
            let (ms, t0) = (fnum(win.get("ms")), fnum(win.get("t0")));
            ((ti - t0) / ms).floor() == ((t - t0) / ms).floor()
        }
        _ => false,
    }
}

/// `accKeyOf(a, params)`: the canonical key of the grouping parameter, "\u{2022}" when ungrouped, `None` when the parameter is
/// missing or not a string / safe integer.
pub(crate) fn acc_key_of(a: &Map<String, Value>, params: &Map<String, Value>) -> Option<String> {
    match a.get("key") {
        Some(Value::String(k)) => {
            let x = params.get(k.strip_prefix("action.params.").unwrap_or(k))?;
            match x {
                Value::String(_) => canonicalize_strict(x).ok(),
                n if sint(Some(n)).is_some() => canonicalize_strict(n).ok(),
                _ => None,
            }
        }
        _ => Some("\u{2022}".to_string()),
    }
}

fn empty_pre(agg: &str) -> Value {
    match agg {
        "sum" => json!({"sum": 0}),
        "count" => json!({"count": 0}),
        "max" => json!({"max": 0}),
        _ => json!({"values": []}),
    }
}

fn utf8_sorted_distinct(mut v: Vec<String>) -> Vec<String> {
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v.dedup();
    v
}

/// `accPreState(a, history, cand, schema)`: the pre-state of the accumulator for a candidate action.
pub(crate) fn acc_pre_state(a: &Map<String, Value>, history: &[Value], cand_params: &Map<String, Value>, cand_t: Option<&Value>, schema: Option<&Value>) -> Result<Value, String> {
    let key = acc_key_of(a, cand_params).ok_or("the key parameter is missing")?;
    sint(cand_t).ok_or("the candidate time is not a safe integer")?;
    let agg = s(a.get("agg")).unwrap_or("");
    let win = a.get("win").and_then(Value::as_object).ok_or("no window")?;
    let (mut sum, mut count, mut max) = (0i64, 0i64, 0i64);
    let mut vals: Vec<String> = Vec::new();
    for e in history {
        let eo = e.as_object().ok_or("event is not an object")?;
        let is_counted = counted(eo.get("status"));
        if is_counted && sint(eo.get("t")).is_none() {
            return Err("an event time is not a safe integer".into());
        }
        if !is_counted || !in_window(win, eo.get("t"), cand_t) {
            continue;
        }
        let verb = s(eo.get("verb")).unwrap_or("");
        if !acc_selects(a, verb, schema)? {
            continue;
        }
        let empty = Map::new();
        let params = eo.get("params").and_then(Value::as_object).unwrap_or(&empty);
        if acc_key_of(a, params).as_deref() != Some(key.as_str()) {
            continue;
        }
        let v = acc_value_of(a, verb, params, schema)??;
        sum += v.val;
        count += 1;
        max = max.max(v.val);
        if let Some(k) = v.key {
            vals.push(k);
        }
    }
    if agg == "sum" && sum > MAX_SAFE {
        return Err("sum exceeds 2^53-1".into());
    }
    Ok(match agg {
        "sum" => json!({"sum": sum}),
        "count" => json!({"count": count}),
        "max" => json!({"max": max}),
        _ => json!({"values": utf8_sorted_distinct(vals)}),
    })
}

/// `accPost(a, history, cand, schema)`: the pre-state combined with the candidate when it is selected, else the pre-state's value.
pub(crate) fn acc_post(a: &Map<String, Value>, history: &[Value], verb: &str, params: &Map<String, Value>, t: Option<&Value>, schema: Option<&Value>) -> Result<i64, String> {
    let agg = s(a.get("agg")).unwrap_or("");
    let grouped = matches!(a.get("key"), Some(Value::String(_)));
    let pre = if grouped && acc_key_of(a, params).is_none() { empty_pre(agg) } else { acc_pre_state(a, history, params, t, schema)? };
    if !acc_selects(a, verb, schema)? {
        return Ok(pre_value(agg, &pre));
    }
    let v = acc_value_of(a, verb, params, schema)??;
    combine_acc(agg, &pre, &v).ok_or_else(|| "overflow".to_string())
}

fn monitor_initial(m: &Map<String, Value>) -> &'static str {
    match s(m.get("kind")) {
        Some("requires_prior") | Some("precedes") => "unmet",
        Some("never") => "clean",
        Some("always") => "ok",
        _ => "idle",
    }
}

/// `monitorStep(m, q, e)`: one monitor step on one event; statuses that do not count leave the state unchanged.
pub(crate) fn monitor_step(m: &Map<String, Value>, q: &str, e: &Value) -> String {
    let status = e.get("status");
    let counts = if s(m.get("status")) == Some("committed") { s(status) == Some("committed") } else { counted(status) };
    if !counts {
        return q.to_string();
    }
    let root = json!({"action": {"verb": e.get("verb"), "resource": e.get("resource"), "params": e.get("params")}});
    let ctx = Ctx::new(&root);
    let hit = |k: &str| m.get(k).is_some_and(|p| predicate_matches(p, &ctx));
    match s(m.get("kind")) {
        Some("requires_prior") | Some("precedes") => (if q == "met" || hit("p") { "met" } else { "unmet" }).to_string(),
        Some("never") => (if q == "seen" || hit("p") { "seen" } else { "clean" }).to_string(),
        Some("always") => (if q == "broken" || !hit("p") { "broken" } else { "ok" }).to_string(),
        Some("responds_within") => {
            if q == "missed" {
                return "missed".into();
            }
            let w = fnum(m.get("within"));
            let mut pending: Option<f64> = q.strip_prefix("pending:").map(|x| x.parse::<f64>().unwrap_or(f64::NAN));
            if let Some(p) = pending {
                if hit("q") {
                    pending = None;
                } else if p - 1.0 <= 0.0 {
                    return "missed".into();
                } else {
                    pending = Some(p - 1.0);
                }
            }
            if hit("p") {
                pending = Some(pending.map_or(w, |p| p.min(w)));
            }
            match pending {
                None => "idle".into(),
                Some(p) => format!("pending:{}", p as i64),
            }
        }
        _ => q.to_string(),
    }
}

/// `monitorState(m, history)`: the fold of the monitor over the history (admission order, current statuses).
pub(crate) fn monitor_state(m: &Map<String, Value>, history: &[Value]) -> String {
    history.iter().fold(monitor_initial(m).to_string(), |q, e| monitor_step(m, &q, e))
}
