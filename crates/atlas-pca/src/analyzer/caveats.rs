//! Static satisfiability of an envelope caveat set, and the constitution -> veto mapping.

use super::js::*;
use serde_json::Value;

fn unsat(reason: &str) -> Value {
    u(vec![("sat", Value::Bool(false)), ("reason", s(reason))])
}

/// The static satisfiability of an envelope caveat set: `{sat, reason?, revCap?}`.
pub(crate) fn analyze_caveats(caveats: &Value) -> Value {
    let list = match caveats.as_array() {
        Some(l) => l,
        None => return unsat("caveats are not an array"),
    };
    let mut not_before_max = f64::NEG_INFINITY;
    let mut expires_min = f64::INFINITY;
    let mut rev_cap: i64 = -1;
    for cvv in list {
        let cv = match obj(cvv) {
            Some(_) => cvv,
            None => return unsat("malformed caveat (not an object with a string type)"),
        };
        let t = match own(cv, "type").as_str() {
            Some(t) => t,
            None => return unsat("malformed caveat (not an object with a string type)"),
        };
        match t {
            "expires" => match fin(own(cv, "at")) {
                Some(at) => expires_min = expires_min.min(at),
                None => return unsat("expires.at is not a finite number"),
            },
            "not_before" => match fin(own(cv, "at")) {
                Some(at) => not_before_max = not_before_max.max(at),
                None => return unsat("not_before.at is not a finite number"),
            },
            "rate" => {
                let (mx, per) = (fin(own(cv, "max")), fin(own(cv, "per_secs")));
                match (mx, per) {
                    (Some(mx), Some(per)) if per > 0.0 => {
                        if mx < 1.0 {
                            return unsat(&format!("rate.max {} < 1 forbids every action", num_str(mx)));
                        }
                    }
                    _ => return unsat("rate caveat requires finite max and per_secs > 0"),
                }
            }
            "max_blast_radius" => match fin(own(cv, "max")) {
                Some(mx) => {
                    if mx < 0.0 {
                        return unsat("max_blast_radius.max < 0 forbids every action");
                    }
                }
                None => return unsat("max_blast_radius.max is not a finite number"),
            },
            "reversibility_max" => {
                let cls = js(own(cv, "class"));
                let idx = REV_ORDER.iter().position(|r| *r == cls);
                match idx {
                    None => return unsat(&format!("reversibility_max.class '{cls}' is unknown")),
                    Some(i) => {
                        if rev_cap < 0 || (i as i64) < rev_cap {
                            rev_cap = i as i64;
                        }
                    }
                }
            }
            "delegation_depth" => match fin(own(cv, "max")) {
                Some(mx) => {
                    if mx < 0.0 {
                        return unsat("delegation_depth.max < 0 forbids every action");
                    }
                }
                None => return unsat("delegation_depth.max is not a finite number"),
            },
            "budget_alloc" => match fin(own(cv, "limit")) {
                Some(lim) if lim >= 0.0 => {}
                _ => return unsat("budget_alloc.limit must be a finite number >= 0"),
            },
            other => return unsat(&format!("unknown caveat type '{other}' (fail closed)")),
        }
    }
    if !not_before_max.is_infinite() && !expires_min.is_infinite() && not_before_max >= expires_min {
        return unsat(&format!("not_before ({}) >= expires ({}): the validity window is empty", num_str(not_before_max), num_str(expires_min)));
    }
    let mut out = vec![("sat", Value::Bool(true))];
    if rev_cap >= 0 {
        out.push(("revCap", num(rev_cap as f64)));
    }
    u(out)
}

/// Maps a constitution's stateless invariants to analyzer vetoes; the rest are reported in `unmodeled`.
pub(crate) fn vetoes_from_constitution(c: &Value) -> Value {
    let mut vetoes = vec![];
    let mut unmodeled = vec![];
    let invs = own(c, "invariants");
    let empty = vec![];
    let list = invs.as_array().unwrap_or(&empty);
    for inv in list {
        let kind = get(inv, "kind");
        let iid = get(inv, "id");
        match kind.as_str().unwrap_or("\u{0}") {
            "never" => vetoes.push(u(vec![("id", iid.clone()), ("kind", s("deny")), ("when", get(inv, "when").clone())])),
            "never_unless" => {
                vetoes.push(u(vec![("id", iid.clone()), ("kind", s("deny")), ("when", get(inv, "when").clone()), ("unless", get(inv, "unless").clone())]))
            }
            "require_approval_over" => vetoes.push(u(vec![
                ("id", iid.clone()),
                ("kind", s("approval")),
                ("when", get(inv, "when").clone()),
                ("over", u(vec![("path", get(inv, "amount").clone()), ("threshold", get(inv, "threshold").clone())])),
                ("unless", get(inv, "approved").clone()),
            ])),
            "cap" | "rate" => unmodeled.push(u(vec![
                ("id", iid.clone()),
                ("kind", kind.clone()),
                ("reason", s("windowed total: bounded by maxExposure, not by a per-action veto")),
            ])),
            _ => unmodeled.push(u(vec![("id", iid.clone()), ("kind", kind.clone()), ("reason", s("needs action history"))])),
        }
    }
    u(vec![("vetoes", Value::Array(vetoes)), ("unmodeled", Value::Array(unmodeled))])
}
