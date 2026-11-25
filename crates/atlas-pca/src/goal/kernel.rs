//! The tape-in / tape-out goal kernel: the five total entry points of `GoalApi` (`Goal.dfy`), hand-ported from the proved Dafny
//! model and replayed against the corpus recorded from the extracted code. Every function takes and returns token tapes; the
//! first output token is 0 (ok), 1 (rejected, with reasons) or 9 (a malformed input tape).
use super::compile::*;
use super::ir::*;
use super::render::*;

fn bad() -> Vec<Tok> {
    vec![Tok::I(9)]
}
fn with_reasons(mut o: Vec<Tok>, rs: &[String]) -> Vec<Tok> {
    enc_strs(&mut o, rs);
    o
}
/// The type reasons of a goal against an ontology (a single `i0` = well typed).
pub fn typecheck_t(gt: &[Tok], ot: &[Tok]) -> Vec<Tok> {
    match (parse_goal(gt), parse_ontology(ot)) {
        (Some(g), Some(o)) => {
            let rs = type_reasons(&o, &g);
            if rs.is_empty() {
                vec![Tok::I(0)]
            } else {
                with_reasons(vec![Tok::I(1)], &rs)
            }
        }
        _ => bad(),
    }
}
pub fn compile_t(gt: &[Tok], ot: &[Tok]) -> Vec<Tok> {
    match (parse_goal(gt), parse_ontology(ot)) {
        (Some(g), Some(o)) => match compile(&o, &g) {
            CResult::Compiled(p) => {
                let mut t = vec![Tok::I(0)];
                t.extend(enc_pol(&p));
                t
            }
            CResult::Escalate(rs) => with_reasons(vec![Tok::I(1)], &rs),
        },
        _ => bad(),
    }
}
/// The reference semantics `D_G`.
pub fn decide_goal_t(gt: &[Tok], ot: &[Tok], at: &[Tok], ht: &[Tok]) -> Vec<Tok> {
    match (parse_goal(gt), parse_ontology(ot), parse_act(at), parse_hist(ht)) {
        (Some(g), Some(o), Some(a), Some(h)) => vec![Tok::I(0), Tok::I(dg(&o, &g, &a, &h) as i64)],
        _ => bad(),
    }
}
/// The compiled policy's decision with its witness and the witness checker's verdict.
pub fn decide_policy_t(gt: &[Tok], ot: &[Tok], at: &[Tok], ht: &[Tok]) -> Vec<Tok> {
    match (parse_goal(gt), parse_ontology(ot), parse_act(at), parse_hist(ht)) {
        (Some(g), Some(o), Some(a), Some(h)) => match compile(&o, &g) {
            CResult::Escalate(rs) => with_reasons(vec![Tok::I(1)], &rs),
            CResult::Compiled(p) => {
                let (d, w) = decide_w(&p, &a, &h);
                let mut t = vec![Tok::I(0), Tok::I(d as i64), Tok::S(w.gid.clone())];
                enc_strs(&mut t, &w.bids);
                t.push(Tok::I((d == ALLOW && verify_witness(&p, &a, &h, &w)) as i64));
                t
            }
        },
        _ => bad(),
    }
}
/// The card: parse and render again (the identity on every parsable tape).
pub fn render_t(gt: &[Tok]) -> Vec<Tok> {
    match parse_goal(gt) {
        Some(g) => {
            let mut t = vec![Tok::I(0)];
            t.extend(enc_goal(&g));
            t
        }
        None => bad(),
    }
}

/// The ops of the JS bridge `goalCall`.
pub fn goal_call(op: &str, goal: &[Tok], ont: &[Tok], act: &[Tok], hist: &[Tok]) -> Result<Vec<Tok>, String> {
    Ok(match op {
        "typecheck" => typecheck_t(goal, ont),
        "compile" => compile_t(goal, ont),
        "decideg" => decide_goal_t(goal, ont, act, hist),
        "decidep" => decide_policy_t(goal, ont, act, hist),
        "render" => render_t(goal),
        _ => return Err(format!("unknown goal op {op}")),
    })
}
/// Text-syntax convenience: the same call over harness text tapes (empty strings for the trailing tapes an op does not take).
pub fn goal_call_text(op: &str, goal: &str, ont: &str, act: &str, hist: &str) -> Result<String, String> {
    let t = |s: &str| tape_from_text(s);
    Ok(tape_to_text(&goal_call(op, &t(goal)?, &t(ont)?, &t(act)?, &t(hist)?)?))
}
