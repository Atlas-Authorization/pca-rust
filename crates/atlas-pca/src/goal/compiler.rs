//! The typed front door of the goal kernel (`compiler.ts`): JSON in, JSON out, no decision logic of its own. Every function
//! encodes its inputs strictly ([`super::codec`]), runs the tape kernel, and reads the answer back.
use super::codec::*;
use super::js::u16cmp;
use super::kernel::*;
use super::normalize::stable;
use super::render::Tok;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn first(t: &[Tok]) -> Result<i64, String> {
    match t.first() {
        Some(Tok::I(n)) => Ok(*n),
        _ => Err("pca-goal: malformed compiler output".into()),
    }
}
fn reasons_of(t: &[Tok]) -> Vec<String> {
    let n = match t.get(1) {
        Some(Tok::I(n)) => (*n).max(0) as usize,
        _ => 0,
    };
    t.iter().skip(2).take(n).map(|x| if let Tok::S(s) = x { s.clone() } else { String::new() }).collect()
}
fn rejected<T>() -> Result<T, String> {
    Err("pca-goal: compiler rejected the input tape".into())
}
fn to_decision(n: i64) -> &'static str {
    match n {
        2 => "allow",
        1 => "escalate",
        _ => "deny",
    }
}

/// Type reasons of a goal against an ontology; empty = well typed.
pub fn typecheck(goal: &Value, ont: &Value) -> Result<Vec<String>, String> {
    let out = typecheck_t(&encode_goal(goal)?, &encode_ontology(ont)?);
    match first(&out)? {
        0 => Ok(vec![]),
        1 => Ok(reasons_of(&out)),
        _ => rejected(),
    }
}
/// `C`: `{ok: true, policy}` or `{ok: false, reasons}`. Ill-typed goals are rejected, never coerced.
pub fn compile_goal(goal: &Value, ont: &Value) -> Result<Value, String> {
    let out = compile_t(&encode_goal(goal)?, &encode_ontology(ont)?);
    match first(&out)? {
        0 => Ok(json!({"ok": true, "policy": decode_policy(&out[1..])?})),
        1 => Ok(json!({"ok": false, "reasons": reasons_of(&out)})),
        _ => rejected(),
    }
}
/// The reference semantics `D_G(a, H)`: "allow" / "deny" / "escalate".
pub fn decide_goal(goal: &Value, ont: &Value, act: &Value, hist: &Value) -> Result<&'static str, String> {
    let out = decide_goal_t(&encode_goal(goal)?, &encode_ontology(ont)?, &encode_act(act)?, &encode_hist(hist)?);
    if first(&out)? != 0 {
        return rejected();
    }
    match out.get(1) {
        Some(Tok::I(n)) => Ok(to_decision(*n)),
        _ => Err("pca-goal: malformed compiler output".into()),
    }
}
/// The compiled policy's decision with the witness of an Allow (G-T3) and the separate checker's verdict:
/// `{ok: false, reasons}` or `{ok: true, decision, witness: {gid, bids} | null, witnessChecked}`.
pub fn decide_policy(goal: &Value, ont: &Value, act: &Value, hist: &Value) -> Result<Value, String> {
    let out = decide_policy_t(&encode_goal(goal)?, &encode_ontology(ont)?, &encode_act(act)?, &encode_hist(hist)?);
    match first(&out)? {
        1 => return Ok(json!({"ok": false, "reasons": reasons_of(&out)})),
        0 => {}
        _ => return rejected(),
    }
    let malformed = || "pca-goal: malformed compiler output".to_string();
    let decision = match out.get(1) {
        Some(Tok::I(n)) => to_decision(*n),
        _ => return Err(malformed()),
    };
    let gid = match out.get(2) {
        Some(Tok::S(s)) => s.clone(),
        _ => return Err(malformed()),
    };
    let n = match out.get(3) {
        Some(Tok::I(n)) if *n >= 0 => *n as usize,
        _ => return Err(malformed()),
    };
    let bids = reasons_like(&out, 4, n);
    let checked = matches!(out.get(4 + n), Some(Tok::I(1)));
    let witness = if decision == "allow" { json!({"gid": gid, "bids": bids}) } else { Value::Null };
    Ok(json!({"ok": true, "decision": decision, "witness": witness, "witnessChecked": checked}))
}
fn reasons_like(t: &[Tok], from: usize, n: usize) -> Vec<String> {
    t.iter().skip(from).take(n).map(|x| if let Tok::S(s) = x { s.clone() } else { String::new() }).collect()
}
/// The card as a token tape (lossless, G-T10).
pub fn render_tape(goal: &Value) -> Result<Vec<Tok>, String> {
    let out = render_t(&encode_goal(goal)?);
    if first(&out)? != 0 {
        return Err("pca-goal: goal tape rejected".into());
    }
    Ok(out[1..].to_vec())
}

/// Canonical bytes of a policy (sorted-key JSON, UTF-16 key order), the input of the policy digest (G-T5).
pub fn canonical_policy(p: &Value) -> String {
    stable(p)
}
pub fn policy_digest(p: &Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_policy(p).as_bytes()))
}
/// Kept for callers that sort ids the way the reference does.
pub fn sort_ids(v: &mut [String]) {
    v.sort_by(|a, b| u16cmp(a, b));
}
