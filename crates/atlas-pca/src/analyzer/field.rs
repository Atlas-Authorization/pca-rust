//! The single-field interval / finite-set engine: probe values per field, interval tightening, numeric satisfiability.

use super::js::*;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub(crate) const FRESH_STRING: &str = "\u{0}atlas-analyzer::fresh-unmatched\u{0}";

/// A numeric interval.
#[derive(Clone, Copy, Debug)]
pub struct Iv {
    pub lo: f64,
    pub hi: f64,
    pub lo_inc: bool,
    pub hi_inc: bool,
}

pub const FULL_INTERVAL: Iv = Iv { lo: f64::NEG_INFINITY, hi: f64::INFINITY, lo_inc: false, hi_inc: false };

impl Iv {
    pub fn to_json(&self) -> Value {
        u(vec![("lo", num(self.lo)), ("loInclusive", Value::Bool(self.lo_inc)), ("hi", num(self.hi)), ("hiInclusive", Value::Bool(self.hi_inc))])
    }

    /// An interval from `{lo, loInclusive, hi, hiInclusive}` (anything but an object is the full interval).
    pub fn from_json(v: &Value) -> Iv {
        match obj(v) {
            Some(m) => Iv {
                lo: jsnum(mg(m, "lo")).unwrap_or(0.0),
                hi: jsnum(mg(m, "hi")).unwrap_or(0.0),
                lo_inc: mg(m, "loInclusive").as_bool().unwrap_or(false),
                hi_inc: mg(m, "hiInclusive").as_bool().unwrap_or(false),
            },
            None => FULL_INTERVAL,
        }
    }
}

pub(crate) fn numeric_cell_reps(thresholds: &[f64]) -> Vec<f64> {
    let mut s: Vec<f64> = vec![];
    for &t in thresholds {
        if !s.iter().any(|x| *x == t) && t.is_finite() {
            s.push(t);
        }
    }
    if s.is_empty() {
        return vec![];
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mut out = vec![s[0] - 1.0];
    for (i, ti) in s.iter().enumerate() {
        out.push(*ti);
        if i + 1 < s.len() {
            out.push((*ti + s[i + 1]) / 2.0);
        }
    }
    out.push(s[s.len() - 1] + 1.0);
    out
}

/// The identity of a probe value (`type:JSON`; the fresh string has a fixed key).
pub(crate) fn value_key(x: &Value) -> String {
    if x.as_str() == Some(FRESH_STRING) {
        return "s:__fresh__".to_string();
    }
    if is_undef(x) {
        return "undefined:undefined".to_string();
    }
    let t = if is_num(x) {
        "number"
    } else {
        match x {
            Value::String(_) => "string",
            Value::Bool(_) => "boolean",
            _ => "object",
        }
    };
    format!("{t}:{}", json_str(x))
}

/// The representative probe values for one field from the conjunction of `where` conditions on it.
pub(crate) fn field_probes(conditions: &Value) -> Vec<Value> {
    let mut literals: Vec<Value> = vec![];
    let mut thresholds: Vec<f64> = vec![];
    let mut prefixes: Vec<String> = vec![];
    for cc in req_list(conditions) {
        let c = match leaf(cc) {
            Some(c) if !c.contains_key("ref") => c,
            _ => continue,
        };
        let v = mg(c, "value");
        let op = mg(c, "op").as_str().unwrap_or("");
        match op {
            "eq" | "ne" => {
                literals.push(v.clone());
                if let Some(f) = fin(v) {
                    thresholds.push(f);
                }
            }
            "in" | "nin" => {
                if let Some(xs) = v.as_array() {
                    for x in xs {
                        literals.push(x.clone());
                        if let Some(f) = fin(x) {
                            thresholds.push(f);
                        }
                    }
                }
            }
            "lt" | "lte" | "gt" | "gte" => {
                if let Some(f) = fin(v) {
                    thresholds.push(f);
                }
            }
            "prefix" | "like" | "matches" | "is_a" => {
                if let Some(t) = v.as_str() {
                    literals.push(s(t));
                    if op == "prefix" {
                        prefixes.push(t.to_string());
                    }
                }
            }
            "member_of" => {
                if let Some(t) = v.as_str() {
                    literals.push(s(t));
                } else if let Some(xs) = v.as_array() {
                    for x in xs {
                        if x.is_string() {
                            literals.push(x.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out: Vec<Value> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |x: Value| {
        if seen.insert(value_key(&x)) {
            out.push(x);
        }
    };
    for l in literals {
        add(l);
    }
    for n in numeric_cell_reps(&thresholds) {
        add(num(n));
    }
    for p in prefixes {
        add(s(&p));
        add(s(&format!("{p}x")));
    }
    add(s(FRESH_STRING));
    out
}

/// Tightens an interval by one numeric condition (a non-numeric operand returns it as is).
pub(crate) fn tighten(iv: Iv, op: &Value, value: &Value) -> Iv {
    let v = match fin(value) {
        Some(v) => v,
        None => return iv,
    };
    let mut n = iv;
    match op.as_str().unwrap_or("") {
        "eq" => {
            if v > n.lo || (v == n.lo && !n.lo_inc) {
                n.lo = v;
                n.lo_inc = true;
            }
            if v < n.hi || (v == n.hi && !n.hi_inc) {
                n.hi = v;
                n.hi_inc = true;
            }
        }
        "gte" => {
            if v > n.lo {
                n.lo = v;
                n.lo_inc = true;
            }
        }
        "gt" => {
            if v > n.lo || (v == n.lo && n.lo_inc) {
                n.lo = v;
                n.lo_inc = false;
            }
        }
        "lte" => {
            if v < n.hi {
                n.hi = v;
                n.hi_inc = true;
            }
        }
        "lt" => {
            if v < n.hi || (v == n.hi && n.hi_inc) {
                n.hi = v;
                n.hi_inc = false;
            }
        }
        _ => {}
    }
    n
}

pub(crate) fn interval_empty(iv: Iv) -> bool {
    if iv.lo > iv.hi {
        return true;
    }
    if iv.lo == iv.hi {
        return !(iv.lo_inc && iv.hi_inc);
    }
    false
}

/// Is the numeric part of a field's `where` conjunction satisfiable?
pub(crate) fn numeric_conjunction_satisfiable(conditions: &Value) -> bool {
    let mut by_field: HashMap<String, Iv> = HashMap::new();
    for cc in req_list(conditions) {
        let c = match leaf(cc) {
            Some(c) if !c.contains_key("ref") => c,
            _ => continue,
        };
        let f = mg(c, "field").as_str().unwrap_or("").to_string();
        let iv = by_field.get(&f).copied().unwrap_or(FULL_INTERVAL);
        by_field.insert(f, tighten(iv, mg(c, "op"), mg(c, "value")));
    }
    !by_field.values().any(|iv| interval_empty(*iv))
}

pub(crate) fn predicate_numeric_satisfiable(where_: &Value) -> bool {
    if !where_.is_array() {
        return true;
    }
    numeric_conjunction_satisfiable(where_)
}
