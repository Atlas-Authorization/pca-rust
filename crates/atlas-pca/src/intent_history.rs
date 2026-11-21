//! Session histories (Intent Layer v2 section 2.1): the host side of accumulators and monitors. Mirrors
//! `packages/pca/src/intent-history.ts`. The verifier receives the PRE-STATE of the action's group from its own store; these
//! functions compute it from the session's event history (window, key, selection and counted statuses applied) and fold a
//! monitor over it. They are pure: the store, its lock and the reservation are the host's. An `Err` is the reference's throw
//! (a corrupt history, an unusable candidate), which the caller turns into a denial.

use serde_json::{json, Map, Value};

use super::actions::js_str_to_number;
use super::intent_acc::{acc_selects, ACC_AGGS, acc_value_of, combine_acc, pre_value};
use super::intent_strict::{s, sint};
use super::intent_v2::js_number_string;
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
    let win = a.get("win");
    let (mut sum, mut count, mut max) = (0i64, 0i64, 0i64);
    let mut vals: Vec<String> = Vec::new();
    for e in history {
        if e.is_null() {
            return Err("an event is null".into());
        }
        // the reference reads `e.status` of any other non-object entry as undefined: not counted
        let Some(eo) = e.as_object() else { continue };
        let is_counted = counted(eo.get("status"));
        if is_counted && sint(eo.get("t")).is_none() {
            return Err("an event time is not a safe integer".into());
        }
        if !is_counted {
            continue;
        }
        let in_win = match win {
            Some(Value::Object(w)) => in_window(w, eo.get("t"), cand_t),
            // the reference reads `win.kind` only past the future-stamp test: a missing / null window throws there, any other
            // non-object window has no kind (in no window)
            w => {
                let future = sint(eo.get("t")) > sint(cand_t);
                if !future && matches!(w, None | Some(Value::Null)) {
                    return Err("no window".into());
                }
                future
            }
        };
        if !in_win {
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
    // a host-built declaration is not validated otherwise: refused first, before any key or pre-state work (as the reference)
    let Some(agg) = s(a.get("agg")).filter(|g| ACC_AGGS.contains(g)) else { return Err("accPost: unknown agg".into()) };
    let grouped = matches!(a.get("key"), Some(Value::String(_)));
    // the reference's emptyPre: pre_value and combine_acc read every member of an empty pre-state as 0
    let pre = if grouped && acc_key_of(a, params).is_none() { Value::Null } else { acc_pre_state(a, history, params, t, schema)? };
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

/// `monitorStep(m, q, e)`: one monitor step on one event; statuses that do not count leave the state unchanged. `Err` = the
/// reference throws (a null event); `Ok(None)` = it returns undefined (a counted event under an unknown monitor kind).
pub(crate) fn monitor_step(m: &Map<String, Value>, q: &str, e: &Value) -> Result<Option<String>, String> {
    if e.is_null() {
        return Err("the event is null".into());
    }
    let status = e.get("status");
    let counts = if s(m.get("status")) == Some("committed") { s(status) == Some("committed") } else { counted(status) };
    if !counts {
        return Ok(Some(q.to_string()));
    }
    let root = json!({"action": {"verb": e.get("verb"), "resource": e.get("resource"), "params": e.get("params")}});
    let ctx = Ctx::new(&root);
    let hit = |k: &str| m.get(k).is_some_and(|p| predicate_matches(p, &ctx));
    Ok(Some(match s(m.get("kind")) {
        Some("requires_prior") | Some("precedes") => (if q == "met" || hit("p") { "met" } else { "unmet" }).to_string(),
        Some("never") => (if q == "seen" || hit("p") { "seen" } else { "clean" }).to_string(),
        Some("always") => (if q == "broken" || !hit("p") { "broken" } else { "ok" }).to_string(),
        Some("responds_within") => {
            if q == "missed" {
                return Ok(Some("missed".into()));
            }
            let w = fnum(m.get("within"));
            // JS Number(): whitespace trimmed, "" is 0, 0x / 0o / 0b prefixes, Infinity, else NaN
            let mut pending: Option<f64> = q.strip_prefix("pending:").map(js_str_to_number);
            if let Some(p) = pending {
                if hit("q") {
                    pending = None;
                } else if p - 1.0 <= 0.0 {
                    return Ok(Some("missed".into()));
                } else {
                    pending = Some(p - 1.0);
                }
            }
            if hit("p") {
                // Math.min is NaN when either side is NaN (f64::min would drop the NaN)
                pending = Some(match pending {
                    None => w,
                    Some(p) if p.is_nan() || w.is_nan() => f64::NAN,
                    Some(p) => p.min(w),
                });
            }
            match pending {
                None => "idle".into(),
                Some(p) => format!("pending:{}", js_number_string(p)),
            }
        }
        _ => return Ok(None),
    }))
}

/// `monitorState(m, history)`: the fold of the monitor over the history (admission order, current statuses). Once a step is
/// undefined (unknown kind) every later step stays undefined, but a null event still throws.
pub(crate) fn monitor_state(m: &Map<String, Value>, history: &[Value]) -> Result<Option<String>, String> {
    let mut q = Some(monitor_initial(m).to_string());
    for e in history {
        q = match q {
            Some(q) => monitor_step(m, &q, e)?,
            None if e.is_null() => return Err("the event is null".into()),
            None => None,
        };
    }
    Ok(q)
}

#[cfg(test)]
#[path = "k05_intenthistory_test.rs"]
mod k05_test;
