//! Tighten-or-escalate typing of the intent-frontier modules (port of `frontier-signals.ts`): what the semantic judge threshold,
//! the objective risk and the proof of progress compute are PROXIES for "does this action serve the principal's goal", never a
//! judgement that may grant anything. This is the one place that turns each result into a signal (`ok`, `escalate` or `deny`) that can
//! only LOWER a decision; `ok` is the neutral element. Every function is total: a missing, malformed or unrecognised result is `deny`.
//!
//! JSON-valued (`&Value` in, the reference's member names out).
use serde_json::{json, Value};

/// A result counts only when it is a non-array object.
fn is_obj(v: &Value) -> bool {
    v.is_object()
}

/// A finite JSON number (a numeric string, a bool, a null or an array is not one).
fn fin(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// `ok` iff the ensemble met its quorum and the calibrated gate; a clean "not faithful" is `escalate` (ask a human); garbage is `deny`.
pub fn semantic_signal(result: &Value) -> &'static str {
    match result.get("ok").and_then(Value::as_bool) {
        Some(ok) if is_obj(result) => if ok { "ok" } else { "escalate" },
        _ => "deny",
    }
}

/// `ok` iff the step verified; running out of exploration budget escalates (the reasons `exploration-exhausted` and
/// `budget-exceeded`, exactly); every other denial (forgery, gap, mismatch, malformed) denies.
pub fn progress_signal(result: &Value) -> &'static str {
    match result.get("ok").and_then(Value::as_bool) {
        Some(true) if is_obj(result) => "ok",
        Some(false) if is_obj(result) => match result.get("reason").and_then(Value::as_str) {
            Some("exploration-exhausted" | "budget-exceeded") => "escalate",
            _ => "deny",
        },
        _ => "deny",
    }
}

/// Objective risk: nothing committed is neutral (`ok`); a committed fact that cannot be reproduced is `deny`, unless the grant's own
/// `onMismatch: "heuristic"` falls back to the server-held class heuristic (`ok`). A reproduced result adds no signal of its own: it
/// enters the decision only through [`tighten_risk_inputs`].
pub fn objective_signal(res: &Value) -> &'static str {
    if !is_obj(res) {
        return "deny";
    }
    match res.get("mode").and_then(Value::as_str) {
        Some("none" | "objective") => "ok",
        Some("mismatch") if res.get("onMismatch").and_then(Value::as_str) == Some("heuristic") => "ok",
        _ => "deny",
    }
}

/// `Math.min` of two finite numbers (`-0` is below `0`).
fn js_min(a: f64, b: f64) -> f64 {
    if a < b || (a == b && a.is_sign_negative()) {
        a
    } else {
        b
    }
}

/// `Math.max` of two finite numbers (`0` is above `-0`).
fn js_max(a: f64, b: f64) -> f64 {
    if a > b || (a == b && a.is_sign_positive()) {
        a
    } else {
        b
    }
}

fn number(f: f64) -> Value {
    if f == 0.0 && f.is_sign_negative() {
        Value::from(-0.0f64)
    } else {
        crate::prohibitions::num_value(f)
    }
}

/// Combines the server-held baseline risk inputs with the objective ones so that the objective path can only RAISE risk:
/// `{reversibility, blastRadius, semanticDistance}` with the lower reversibility and the higher blast radius of the two, and the worst
/// case (0 and 1) for both when ANY of the four is not a finite number. `semanticDistance` is the objective's when finite, else 1; it is
/// not clamped here. `Err` for a null baseline or objective (the reference reads a member of it).
pub fn tighten_risk_inputs(baseline: &Value, objective: &Value) -> Result<Value, String> {
    if baseline.is_null() || objective.is_null() {
        return Err("Cannot read properties of null (reading 'reversibility')".into());
    }
    let four = [fin(baseline.get("reversibility")), fin(objective.get("reversibility")), fin(baseline.get("blastRadius")), fin(objective.get("blastRadius"))];
    let (rev, blast) = match four {
        [Some(br), Some(or), Some(bb), Some(ob)] => (js_min(br, or), js_max(bb, ob)),
        _ => (0.0, 1.0),
    };
    Ok(json!({ "reversibility": number(rev), "blastRadius": number(blast), "semanticDistance": number(fin(objective.get("semanticDistance")).unwrap_or(1.0)) }))
}
