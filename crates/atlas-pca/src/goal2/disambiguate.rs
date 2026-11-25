//! Questions over the symmetric difference of competing readings and active disambiguation by version-space halving
//! (`disambiguate.ts`). A reading is `{id, family, deterministic, goal, notes}`.
use super::examples::{boundary_examples, build_space, cells, decide_case, replay};
use super::nversion::meet;
use super::*;
use crate::goal::fmt::fmt_act;
use serde_json::json;

/// The question options: the IR ontology the readings are decided against, an optional risk of an action (default: by the effect
/// class of its verb in `ont`; unknown verbs are the riskiest), an optional probability mass of an action cell (default 1) and the
/// question budget of [`disambiguate`] (default: the number of readings).
pub struct QOpts<'a> {
    pub ont: &'a Value,
    pub risk_of: Option<&'a dyn Fn(&Value) -> f64>,
    pub mass_of: Option<&'a dyn Fn(&Value) -> f64>,
    pub budget: Option<usize>,
}
impl<'a> QOpts<'a> {
    pub fn new(ont: &'a Value) -> Self {
        QOpts { ont, risk_of: None, mass_of: None, budget: None }
    }
}

pub fn default_risk(cls: &str) -> f64 {
    match cls {
        "read" => 1.0,
        "reversible" => 2.0,
        "external_send" => 8.0,
        _ => 10.0,
    }
}
fn h2(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        0.0
    } else {
        -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
    }
}

/// `w`: `{act, prior: [act], rels}`.
pub fn allows_witness(gl: &Value, ont: &Value, w: &Value) -> Res<bool> {
    let hist = replay(gl, ont, arr(g(w, "prior")), g(w, "rels"))?;
    Ok(decide_case(gl, ont, &json!({"act": g(w, "act"), "hist": hist, "rels": g(w, "rels")}))?["decision"] == "allow")
}
fn allow_set(r: &Value, w: &Value, ont: &Value) -> Res<bool> {
    allows_witness(g(r, "goal"), ont, w)
}

/// Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences.
fn witnesses(readings: &[Value], ont: &Value) -> Res<Vec<Value>> {
    let goals: Vec<Value> = readings.iter().map(|r| g(r, "goal").clone()).collect();
    let mut out: Vec<Value> = vec![];
    let cs = cells(&build_space(&goals, &[])?, None)?;
    for c in cs["cases"].as_array().ok_or("cases")? {
        out.push(json!({"act": g(c, "act"), "prior": [], "rels": g(c, "rels")}));
    }
    for r in readings {
        let ex = boundary_examples(g(r, "goal"), ont, &goals, &[])?;
        for e in ex["examples"].as_array().ok_or("examples")? {
            if st(g(e, "kind")) == "cap_sequence" {
                let prior: Vec<Value> = arr(g(g(e, "hist"), "adms")).iter().map(|a| g(a, "act").clone()).collect();
                out.push(json!({"act": g(e, "act"), "prior": prior, "rels": g(e, "rels")}));
            }
        }
    }
    Ok(out)
}

/// Questions ranked by H2(vote) x risk x mass (best first).
pub fn questions(readings: &[Value], opts: &QOpts) -> Res<Vec<Value>> {
    let ont = opts.ont;
    let k = readings.len();
    let mut out: Vec<Value> = vec![];
    let mut seen: Vec<String> = vec![];
    for w in witnesses(readings, ont)? {
        let mut yes: Vec<Value> = vec![];
        for r in readings {
            if allow_set(r, &w, ont)? {
                yes.push(g(r, "id").clone());
            }
        }
        if yes.is_empty() || yes.len() == k {
            continue;
        }
        let qid = jstr(&json!([g(&w, "act"), arr(g(&w, "prior")).len()]));
        if seen.contains(&qid) {
            continue;
        }
        seen.push(qid.clone());
        let n = arr(g(&w, "prior")).len();
        let act = g(&w, "act");
        let risk = match opts.risk_of {
            Some(f) => f(act),
            None => {
                let verb = g(act, "verb");
                let cls = req_arr(g(ont, "verbs"))?.iter().rev().find(|v| seq_eq(g(v, "verb"), verb)).map(|v| st(g(v, "cls"))).unwrap_or("");
                default_risk(cls)
            }
        };
        let mass = opts.mass_of.map_or(1.0, |f| f(act));
        let not_allow: Vec<Value> = readings.iter().map(|r| g(r, "id").clone()).filter(|x| !includes_v(&yes, x)).collect();
        let suffix = if n > 0 { format!(" (after {n} earlier identical action(s))") } else { String::new() };
        let text = format!("Should this be allowed: {}{suffix}?", fmt_act(act)?);
        let score = h2(yes.len() as f64 / k as f64) * risk * mass;
        out.push(
            json!({"id": qid, "act": act, "prior": g(&w, "prior"), "rels": g(&w, "rels"), "allow": yes, "notAllow": not_allow, "text": text, "score": score}),
        );
    }
    out.sort_by(|a, b| {
        let d = nm(g(b, "score")) - nm(g(a, "score"));
        if d != 0.0 && !d.is_nan() {
            return if d < 0.0 { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
        }
        crate::goal::js::u16cmp(st(g(a, "id")), st(g(b, "id")))
    });
    Ok(out)
}

/// Fraction of witness cells on which the readings do not all agree on Allow.
pub fn disagreement_mass(readings: &[Value], ont: &Value) -> Res<f64> {
    let w = witnesses(readings, ont)?;
    if w.is_empty() {
        return Ok(0.0);
    }
    let mut split = 0usize;
    for x in &w {
        let mut n = 0usize;
        for r in readings {
            if allow_set(r, x, ont)? {
                n += 1;
            }
        }
        if n > 0 && n < readings.len() {
            split += 1;
        }
    }
    Ok(split as f64 / w.len() as f64)
}

/// Active disambiguation by version-space halving over the finite class of readings: every question strictly shrinks the class, so at
/// most k-1 questions. Realizability (assumption): the principal's intent is one of the readings. `ask(question) -> "allow" | "deny"`.
/// `{status, goal, asked, residualMass, remaining}`.
pub fn disambiguate(readings: &[Value], ask: &dyn Fn(&Value) -> Res<String>, opts: &QOpts) -> Res<Value> {
    let ont = opts.ont;
    let budget = opts.budget.unwrap_or(readings.len());
    let mut active: Vec<Value> = readings.to_vec();
    let mut asked: Vec<Value> = vec![];
    while active.len() > 1 && asked.len() < budget {
        let qs = questions(&active, opts)?;
        let q = match qs.into_iter().next() {
            Some(q) => q,
            None => break, // the survivors agree on every witness cell
        };
        asked.push(q.clone());
        let ans = ask(&q)?;
        let mut next: Vec<Value> = vec![];
        for r in &active {
            if allow_set(r, &q, ont)? == (ans == "allow") {
                next.push(r.clone());
            }
        }
        active = next;
    }
    let mass = disagreement_mass(&active, ont)?;
    let gl = meet(&active.iter().map(|r| g(r, "goal").clone()).collect::<Vec<_>>())?;
    let remaining: Vec<Value> = active.iter().map(|r| g(r, "id").clone()).collect();
    if mass > 0.0 {
        let mut holes = arr(g(&gl, "holes")).to_vec();
        holes.push(json!({"hid": "budget", "q": "Question budget exhausted with disagreement left.", "domain": [], "affects": [], "global": true}));
        holes.sort_by(|a, b| crate::goal::js::u16cmp(st(g(a, "hid")), st(g(b, "hid"))));
        let mut m = gl.as_object().ok_or("goal is not an object")?.clone();
        m.insert("holes".into(), Value::Array(holes));
        return Ok(json!({"status": "budget_exhausted", "goal": m, "asked": asked, "residualMass": mass, "remaining": remaining}));
    }
    Ok(json!({"status": "resolved", "goal": gl, "asked": asked, "residualMass": 0, "remaining": remaining}))
}
