//! Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor and the
//! regret report. A regret case carries host predicates (`admits`, `utility`) as closures.
use super::util::*;
use serde_json::{json, Value};

const FRICTION_ORDER: [&str; 4] = ["tap", "hold", "typed", "device"];

/// The fixed banner for a tainted value (`None` for trusted / first-party values); `what` defaults to "value".
pub fn provenance_banner(level: &Value, what: Option<&str>) -> Option<String> {
    let what = what.unwrap_or("value");
    match level.as_str() {
        Some("web") => Some(format!("This {what} was suggested by content on the page, not by you.")),
        Some("agent") => Some(format!("This {what} came from your agent, not from you or the site.")),
        Some("tool") => Some(format!("This {what} came from another service, not from you or this site.")),
        _ => None,
    }
}

pub fn is_tainted(level: &Value) -> bool {
    matches!(level.as_str(), Some("tool") | Some("web") | Some("agent"))
}

/// A tainted critical value is at least typed, a tainted material value at least hold; provenance only raises friction.
pub fn provenance_friction(base: &Value, sensitivity: &Value, level: &Value) -> Option<String> {
    let floor = if !is_tainted(level) {
        "tap"
    } else if sensitivity.as_str() == Some("critical") {
        "typed"
    } else {
        "hold"
    };
    let pos = |x: &str| FRICTION_ORDER.iter().position(|y| *y == x).map(|i| i as i64).unwrap_or(-1);
    let ib = base.as_str().map(pos).unwrap_or(-1);
    let i = ib.max(pos(floor));
    if i >= 0 {
        Some(FRICTION_ORDER[i as usize].to_string())
    } else {
        None
    }
}

pub struct RegretCase<'a> {
    pub feasible: &'a [Value],
    pub chosen: &'a Value,
    pub admits: &'a dyn Fn(&Value) -> bool,
    pub utility: &'a dyn Fn(&Value) -> f64,
}

/// Only options inside the effective grant compete; a chosen option outside it is denied (risk, not regret): `{regret, best, admitted}`.
pub fn within_grant_regret(c: &RegretCase) -> (f64, Option<Value>, bool) {
    let admitted = (c.admits)(c.chosen);
    let mut best: Option<Value> = None;
    let mut best_u = f64::NEG_INFINITY;
    for o in c.feasible {
        if !(c.admits)(o) {
            continue;
        }
        let u = (c.utility)(o);
        if u > best_u {
            best_u = u;
            best = Some(o.clone());
        }
    }
    if !admitted || best.is_none() {
        return (0.0, best, admitted);
    }
    let d = best_u - (c.utility)(c.chosen);
    (if d.is_nan() || d > 0.0 { d } else { 0.0 }, best, admitted)
}

pub fn regret_json(c: &RegretCase) -> Value {
    let (regret, best, admitted) = within_grant_regret(c);
    json!({"regret": num(regret), "best": best, "admitted": admitted})
}

pub fn regret_report(cases: &[RegretCase], scale: Option<f64>) -> Value {
    let (mut admitted, mut positive, mut s, mut mx) = (0usize, 0usize, 0.0f64, 0.0f64);
    for c in cases {
        let (r, _, a) = within_grant_regret(c);
        if !a {
            continue;
        }
        admitted += 1;
        s += r;
        if r > 0.0 {
            positive += 1;
        }
        if r > mx {
            mx = r;
        }
    }
    let mean = if admitted > 0 { s / admitted as f64 } else { 0.0 };
    let sc = scale.unwrap_or(1.0);
    let denom = if sc > 0.0 { sc } else { 1.0 };
    json!({"cases": cases.len(), "admitted": admitted, "positive": positive, "mean": num(mean), "max": num(mx), "regret_est_ppm": num(((mean / denom) * 1_000_000.0 + 0.5).floor())})
}
