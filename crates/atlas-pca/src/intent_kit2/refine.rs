//! Cut refinement and partial answers: a "partly" answer inserts the stated cuts / values (or adds a whole dimension) to the outcome space,
//! re-enumerates the hypotheses and replays every earlier observation as a value-space region; and elicitation that accepts "yes", "no" and
//! "partly". Refinements, partial answers and questions are plain JSON (a question is a [`Question`]).
use super::learner::*;
use super::mapkit::create_learner;
use super::omega::*;
use super::util::*;
use serde_json::{json, Map, Value};

fn is_integer(v: &Value) -> bool {
    fnum(v).is_some_and(|x| x.is_finite() && x == x.floor())
}

fn uniq_nums(xs: Vec<f64>) -> Vec<f64> {
    let mut out: Vec<f64> = vec![];
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn sorted_cat(values: &[Value]) -> R<Value> {
    let mut ex: Vec<String> = vec![];
    let mut pre: Vec<String> = vec![];
    for v in values {
        let s = text(&v["value"], "value")?.to_string();
        match v["kind"].as_str() {
            Some("exact") if !ex.contains(&s) => ex.push(s),
            Some("prefix") if !pre.contains(&s) => pre.push(s),
            _ => {}
        }
    }
    sort_u16(&mut ex);
    sort_u16(&mut pre);
    let mut out: Vec<Value> = ex.iter().map(|v| json!({"kind": "exact", "value": v})).collect();
    out.extend(pre.iter().map(|v| json!({"kind": "prefix", "value": v})));
    out.push(json!({"kind": "other", "value": OTHER}));
    Ok(Value::Array(out))
}

fn cut_values(v: &Value, lo: f64, hi: f64, extra: Vec<f64>) -> R<Vec<Value>> {
    let mut all: Vec<f64> = vec![];
    for c in arr(v, "cuts")? {
        all.push(fnum(c).ok_or("a cut must be a number")?);
    }
    all.extend(extra);
    let mut cuts: Vec<f64> = uniq_nums(all).into_iter().filter(|c| *c >= lo && *c <= hi).collect();
    cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Ok(cuts.iter().map(|c| num(*c)).collect())
}

/// Omega with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged).
pub fn refine_omega(omega: &Value, r: &Value) -> R<Value> {
    let mut out = omega.clone();
    let verb = js_str(&r["verb"]);
    let path = js_str(&r["path"]);
    let vi = arr(&out["verbs"], "omega.verbs")?.iter().position(|v| v["verb"] == r["verb"]).ok_or_else(|| format!("refineOmega: no verb {verb} in \u{3a9}"))?;
    let dims = out["verbs"][vi]["dims"].as_array_mut().ok_or("dims must be a list")?;
    let i = dims.iter().position(|d| d["path"] == r["path"]);
    if let Some(nd) = member(r, "newDim").filter(|x| truthy(x)) {
        if i.is_some() {
            return Err(format!("refineOmega: {path} is already a dimension of {verb}"));
        }
        if nd["path"] != r["path"] {
            return Err("refineOmega: newDim.path must equal path".into());
        }
        let mut d = nd.clone();
        if d["kind"].as_str() == Some("cat") {
            d["values"] = sorted_cat(arr(&nd["values"], "newDim.values")?)?;
        } else {
            let lo = fnum(&nd["lo"]).ok_or("newDim.lo must be a number")?;
            let hi = fnum(&nd["hi"]).ok_or("newDim.hi must be a number")?;
            d["cuts"] = Value::Array(cut_values(&nd["cuts"], lo, hi, vec![])?);
        }
        dims.push(d);
        dims.sort_by(|a, b| u16cmp(a["path"].as_str().unwrap_or(""), b["path"].as_str().unwrap_or("")));
        return Ok(out);
    }
    let i = i.ok_or_else(|| format!("refineOmega: {verb} has no dimension {path} (pass newDim to add it)"))?;
    let d = &mut dims[i];
    if d["kind"].as_str() == Some("num") {
        if member(r, "values").is_some_and(truthy) || member(r, "prefixes").is_some_and(truthy) {
            return Err(format!("refineOmega: {path} is numeric"));
        }
        let extra: Vec<f64> = member(r, "cuts")
            .filter(|x| truthy(x))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|c| is_integer(c)).filter_map(fnum).collect())
            .unwrap_or_default();
        let lo = fnum(&d["lo"]).ok_or("dimension lo must be a number")?;
        let hi = fnum(&d["hi"]).ok_or("dimension hi must be a number")?;
        d["cuts"] = Value::Array(cut_values(&d["cuts"], lo, hi, extra)?);
    } else {
        if member(r, "cuts").is_some_and(truthy) {
            return Err(format!("refineOmega: {path} is categorical"));
        }
        let mut vals: Vec<Value> = arr(&d["values"], "values")?.clone();
        for key in [("values", "exact"), ("prefixes", "prefix")] {
            if let Some(a) = member(r, key.0).filter(|x| truthy(x)).and_then(Value::as_array) {
                for v in a {
                    vals.push(json!({"kind": key.1, "value": v}));
                }
            }
        }
        let sorted = sorted_cat(&vals)?;
        if sorted.as_array().map_or(0, Vec::len) > 20 {
            return Err(format!("refineOmega: {path} would have more than 20 values"));
        }
        d["values"] = sorted;
    }
    Ok(out)
}

/// The value-space region an observation was about, in the omega it was recorded in.
pub fn region_of_observation(omega: &Value, o: &Value) -> R<Value> {
    if let Some(r) = member(o, "region").filter(|x| truthy(x)) {
        return Ok(r.clone());
    }
    let om = Omega::parse(omega)?;
    let verb = js_str(&o["verb"]);
    let vs = om.vs_of(&verb).ok_or_else(|| format!("regionOfObservation: no verb {verb}"))?;
    region_of_cell(vs, &cell_of_json(&o["cell"])?)
}

fn cell_of_json(v: &Value) -> R<Vec<usize>> {
    let mut out = vec![];
    for x in arr(v, "cell")? {
        let f = fnum(x).filter(|f| *f >= 0.0 && *f == f.floor()).ok_or("a cell coordinate must be a non-negative integer")?;
        out.push(f as usize);
    }
    Ok(out)
}

type Rescope<'a> = &'a dyn Fn(&Value, &Value) -> R<Value>;

/// Rebuild a learner over a refined omega and replay every observation as a region (`rescope` may rewrite a region).
pub fn refine_learner(l: &mut Learner, r: &Value, rescope: Option<Rescope>) -> R<Learner> {
    let omega = refine_omega(&l.omega, r)?;
    let mut nxt = create_learner(&omega, &l.params.clone())?;
    let om = Omega::parse(&omega)?;
    for o in l.observations.clone() {
        let mut region = region_of_observation(&l.omega, &o)?;
        if let Some(f) = rescope {
            region = f(&o, &region)?;
        }
        let verb = js_str(&o["verb"]);
        let vs = om.vs_of(&verb).ok_or("the refined omega lost a verb")?;
        let mut values = o["values"].as_object().cloned().unwrap_or_default();
        for d in &vs.dims {
            if !values.contains_key(&d.path) {
                values.insert(d.path.clone(), d.rep_value(0)?);
            }
        }
        let y = fnum(&o["y"]).ok_or("observation y must be a number")?;
        nxt.observe(&json!({"verb": o["verb"], "values": Value::Object(values)}), y, text(&o["source"], "observation source")?, Some(&region))?;
    }
    Ok(nxt)
}

fn part_label(d: &Dim, j: usize, parts: &[Value]) -> R<Option<Value>> {
    let x = d.rep_value(j)?;
    for p in parts {
        if p.get("lo").is_some() {
            if !d.is_num {
                continue;
            }
            let (lo, hi) = d.cells[j];
            if fnum(&p["lo"]).is_some_and(|plo| lo >= plo) && fnum(&p["hi"]).is_some_and(|phi| hi <= phi) {
                return Ok(Some(p["y"].clone()));
            }
        } else if p.get("values").is_some() {
            if !d.is_num && d.values[j].kind == "exact" && p["values"].as_array().is_some_and(|a| a.iter().any(|v| v.as_str() == Some(js_str(&x).as_str()))) {
                return Ok(Some(p["y"].clone()));
            }
        } else if !d.is_num && d.values[j].kind != "exact" {
            return Ok(Some(p["y"].clone()));
        }
    }
    Ok(None)
}

/// Sub-cells of dimension `d` (in the refined omega) that lie inside the questioned region's dimension.
fn sub_cells(d: &Dim, region: &Value) -> R<Vec<usize>> {
    let rd = member(&region["dims"], &d.path).filter(|x| truthy(x));
    let mut out = vec![];
    for j in 0..d.ncells() {
        match rd {
            None => out.push(j),
            Some(rd) => {
                if d.is_num && rd["kind"].as_str() == Some("num") {
                    let (lo, hi) = d.cells[j];
                    if fnum(&rd["lo"]).is_some_and(|x| lo >= x) && fnum(&rd["hi"]).is_some_and(|x| hi <= x) {
                        out.push(j);
                    }
                } else if !d.is_num && rd["kind"].as_str() == Some("cat") {
                    let reference = Dim {
                        is_num: false,
                        path: d.path.clone(),
                        lo: 0.0,
                        hi: 0.0,
                        cuts: vec![],
                        dist: None,
                        values: parse_cat_values(&rd["values"])?,
                        cells: vec![],
                    };
                    let cell = reference.cat_cell_of(&d.cat_rep(j)?);
                    if arr(&rd["cells"], "region cells")?.iter().any(|c| fnum(c) == Some(cell as f64)) {
                        out.push(j);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Apply a partial answer to question `q` (`{verb, cell, outcome}`): a NEW learner over the refined omega and the observations the answer
/// added.
pub fn answer_partial(l: &mut Learner, q: &Question, a: &Value) -> R<(Learner, Vec<Value>)> {
    let old_vs = l.omega_t.vs_of(&q.verb).cloned().ok_or_else(|| format!("answerPartial: no verb {}", q.verb))?;
    let q_region = region_of_cell(&old_vs, &q.cell)?;
    let mut r = Map::new();
    r.insert("verb".into(), json!(q.verb));
    r.insert("path".into(), a["path"].clone());
    for k in ["cuts", "values", "newDim"] {
        if let Some(v) = member(a, k).filter(|x| truthy(x)) {
            r.insert(k.to_string(), v.clone());
        }
    }
    let r = Value::Object(r);
    let refined = refine_omega(&l.omega, &r)?;
    let rt = Omega::parse(&refined)?;
    let nvs = rt.vs_of(&q.verb).ok_or("the refined omega lost the verb")?;
    let d = nvs.dims.iter().find(|x| Some(x.path.as_str()) == a["path"].as_str()).ok_or("the refined omega lost the dimension")?.clone();
    let parts: Vec<Value> = a["parts"].as_array().cloned().unwrap_or_default();
    let is_new_dim = member(a, "newDim").is_some_and(truthy);
    let mut yes_cells: Vec<usize> = vec![];
    if is_new_dim {
        for j in 0..d.ncells() {
            if part_label(&d, j, &parts)?.and_then(|y| fnum(&y)) == Some(1.0) {
                yes_cells.push(j);
            }
        }
    }
    let verb_json = json!(q.verb);
    let rescope_fn = |o: &Value, region: &Value| -> R<Value> {
        if o["verb"] != verb_json || fnum(&o["y"]) != Some(1.0) {
            return Ok(region.clone());
        }
        if !d.is_num {
            return restrict_region(region, &d, &json!({"cells": yes_cells}));
        }
        // numeric: restrict to the contiguous accepted span (the "typical" range the earlier yes was about)
        if yes_cells.is_empty() {
            return restrict_region(region, &d, &json!({"lo": num(d.hi + 1.0), "hi": num(d.hi + 1.0)}));
        }
        let first = d.cells[yes_cells[0]].0;
        let last = d.cells[yes_cells[yes_cells.len() - 1]].1;
        restrict_region(region, &d, &json!({"lo": num(first), "hi": num(last)}))
    };
    let mut nxt = if is_new_dim { refine_learner(l, &r, Some(&rescope_fn))? } else { refine_learner(l, &r, None)? };
    let mut added: Vec<Value> = vec![];
    for j in sub_cells(&d, &q_region)? {
        let y = match part_label(&d, j, &parts)? {
            Some(y) => y,
            None => continue,
        };
        let region = if d.is_num {
            let (lo, hi) = d.cells[j];
            restrict_region(&q_region, &d, &json!({"lo": num(lo), "hi": num(hi)}))?
        } else {
            restrict_region(&q_region, &d, &json!({"cells": [j]}))?
        };
        let mut values = q.outcome["values"].as_object().cloned().unwrap_or_default();
        values.insert(d.path.clone(), d.rep_value(j)?);
        for x in &nvs.dims {
            if !values.contains_key(&x.path) {
                values.insert(x.path.clone(), x.rep_value(0)?);
            }
        }
        let yf = fnum(&y).ok_or("a part label y must be a number")?;
        if let Some(ob) = nxt.observe(&json!({"verb": q.verb, "values": Value::Object(values)}), yf, "elicitation", Some(&region))? {
            added.push(ob);
        }
    }
    Ok((nxt, added))
}

/// What [`elicit_adaptive`] returns.
pub struct Adaptive {
    pub stop: Option<String>,
    pub questions: usize,
    pub audit_questions: usize,
    pub seed_questions: usize,
    pub asked: Vec<Question>,
    pub learner: Learner,
    pub refinements: usize,
}

fn apply_answer(
    l: &mut Learner,
    refinements: &mut usize,
    max_ref: f64,
    asked: &mut Vec<Question>,
    answer: &mut dyn FnMut(&Question, &Learner) -> R<Value>,
    q: Question,
) -> R<()> {
    let a = answer(&q, &*l)?;
    if a.is_object() || a.is_null() {
        if (*refinements as f64) < max_ref {
            let (nl, _) = answer_partial(l, &q, &a)?;
            *l = nl;
            *refinements += 1;
        } else {
            l.observe(&q.outcome, 0.0, "elicitation", None)?;
        }
    } else {
        l.observe(&q.outcome, fnum(&a).ok_or("an answer must be 0, 1 or a partial answer")?, "elicitation", None)?;
    }
    asked.push(q);
    Ok(())
}

/// Elicitation that accepts "yes", "no" and "partly": the stop rule and audit of `elicit`; a partial answer counts as one question and swaps in
/// the refined learner; after `maxRefinements` partial answers a further one is treated as "no". `answer(q, l)` returns 0 / 1 or a partial
/// answer object. `o` is `{epsRisk, epsBurden, maxQuestions, audit?, seed?, maxRefinements?}`.
pub fn elicit_adaptive(learner: Learner, answer: &mut dyn FnMut(&Question, &Learner) -> R<Value>, o: &Value) -> R<Adaptive> {
    let mut l = learner;
    let mut asked: Vec<Question> = vec![];
    let mut refinements = 0usize;
    let max_ref = nn(o, "maxRefinements").and_then(fnum).unwrap_or(8.0);
    let eps_risk = fnum(&o["epsRisk"]).ok_or("epsRisk must be a number")?;
    let eps_burden = fnum(&o["epsBurden"]).ok_or("epsBurden must be a number")?;
    let max_q = fnum(&o["maxQuestions"]).ok_or("maxQuestions must be a number")?;
    let mut seed_questions = 0usize;
    if let Some(seed) = nn(o, "seed").and_then(Value::as_array) {
        for s in seed {
            if !((asked.len() as f64) < max_q) {
                break;
            }
            let verb = js_str(&s["verb"]);
            let cell = cell_of_json(&s["cell"])?;
            let vs = match l.omega_t.vs_of(&verb) {
                Some(v) if v.dims.len() == cell.len() => v.clone(),
                _ => continue,
            };
            let mut values = Map::new();
            for (k, d) in vs.dims.iter().enumerate() {
                values.insert(d.path.clone(), d.rep_value(cell[k])?);
            }
            let outcome = json!({"verb": verb, "values": Value::Object(values)});
            let p = l.acceptance(&outcome);
            if p <= 1e-9 || p >= 1.0 - 1e-9 || l.is_vetoed(&outcome) {
                continue;
            }
            apply_answer(&mut l, &mut refinements, max_ref, &mut asked, answer, Question { verb, cell, outcome, p, score: 0.0 })?;
            seed_questions += 1;
        }
    }
    let mut stop: Option<String> = None;
    while stop.is_none() {
        let m = l.metrics();
        if m.residual_risk <= eps_risk && m.burden <= eps_burden {
            stop = Some("converged".into());
        } else if !((asked.len() as f64) < max_q) {
            stop = Some("budget".into());
        } else {
            match l.next_question()? {
                None => stop = Some("no-disagreement".into()),
                Some(q) => apply_answer(&mut l, &mut refinements, max_ref, &mut asked, answer, q)?,
            }
        }
    }
    let mut audit_questions = 0usize;
    if member(o, "audit").is_some_and(truthy) {
        loop {
            let pending = l.unconfirmed_grant_cells();
            let mut total = 0.0;
            for x in &pending {
                total += x.2;
            }
            if pending.is_empty() || total <= eps_risk {
                break;
            }
            if !((asked.len() as f64) < max_q) {
                stop = Some("budget".into());
                break;
            }
            let (verb, cell, weight) = pending[0].clone();
            let vs = l.omega_t.vs_of(&verb).cloned().ok_or("an unconfirmed cell names a verb the omega lost")?;
            let outcome = vs.cell_rep(&cell)?;
            let p = l.acceptance(&outcome);
            apply_answer(&mut l, &mut refinements, max_ref, &mut asked, answer, Question { verb, cell, outcome, p, score: weight })?;
            audit_questions += 1;
        }
    }
    Ok(Adaptive { stop, questions: asked.len(), audit_questions, seed_questions, asked, learner: l, refinements })
}
