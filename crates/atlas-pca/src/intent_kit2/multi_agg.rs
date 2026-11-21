//! Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP, the common refinement of
//! several outcome spaces, and the aggregation over Intent Maps: the joint grant (every number recomputable from the inputs), lifting a map
//! onto a common refinement, and cross-organisation aggregation. Maps, rules and omegas are plain JSON with the reference's field names.
use super::learner::*;
use super::mapkit::*;
use super::omega::*;
use super::util::*;
use serde_json::{json, Map, Value};

const ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

/// Multi's `ppm`: floor(x * 1e6 + 0.5).
fn mppm(x: f64) -> f64 {
    (x * PPM + 0.5).floor()
}

fn is_int(v: Option<&Value>) -> Option<f64> {
    v.and_then(fnum).filter(|f| f.is_finite() && *f == f.trunc())
}

/// A rule in normal form.
pub struct NRule {
    pub weights: Vec<f64>,
    pub threshold: f64,
    pub veto: Vec<bool>,
}

fn type_error(v: &Value, k: &str) -> String {
    format!("Cannot read properties of {} (reading '{}')", if v.is_null() { "null" } else { "undefined" }, k)
}

pub fn normalize_rule(rule: &Value, refs: &[String]) -> R<NRule> {
    if rule.is_null() {
        return Err(type_error(rule, "vetoers"));
    }
    let vetoers: Vec<Value> = match member(rule, "vetoers") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Some(_) => return Err("rule.vetoers is not iterable".into()),
    };
    for v in &vetoers {
        if !refs.iter().any(|r| v.as_str() == Some(r.as_str())) {
            return Err(format!("aggregateIntentMaps: vetoer {} is not one of the maps", js_str(v)));
        }
    }
    let veto: Vec<bool> = refs.iter().map(|r| vetoers.iter().any(|v| v.as_str() == Some(r.as_str()))).collect();
    let kind = member(rule, "kind").and_then(Value::as_str);
    if kind == Some("unanimity") {
        return Ok(NRule { weights: vec![1.0; refs.len()], threshold: refs.len() as f64, veto });
    }
    if kind == Some("quorum") {
        let k = is_int(member(rule, "k")).filter(|k| *k >= 1.0 && *k <= refs.len() as f64);
        return match k {
            Some(k) => Ok(NRule { weights: vec![1.0; refs.len()], threshold: k, veto }),
            None => Err(format!("aggregateIntentMaps: quorum k must be an integer in [1, {}]", refs.len())),
        };
    }
    let wmap = member(rule, "weights");
    if let Some(Value::Null) = wmap {
        return Err(type_error(&Value::Null, &refs.first().cloned().unwrap_or_default()));
    }
    let mut weights = vec![];
    let mut bad = false;
    if wmap.is_none() && !refs.is_empty() {
        return Err(type_error(&Value::Bool(false), &refs[0]));
    }
    for r in refs {
        match is_int(wmap.and_then(|w| member(w, r))).filter(|w| *w >= 0.0) {
            Some(w) => weights.push(w),
            None => bad = true,
        }
    }
    if bad {
        return Err("aggregateIntentMaps: every principal needs a non-negative integer weight".into());
    }
    let total: f64 = weights.iter().sum();
    match is_int(member(rule, "threshold")).filter(|t| *t >= 1.0 && *t <= total) {
        Some(th) => Ok(NRule { weights, threshold: th, veto }),
        None => Err(format!("aggregateIntentMaps: threshold must be an integer in [1, {}]", js_str(&num(total)))),
    }
}

/// Vetoers must admit; the admitting weight must reach the threshold.
pub fn rule_admits(n: &NRule, ins: &[bool]) -> bool {
    let mut s = 0.0;
    for i in 0..ins.len() {
        if n.veto[i] && !ins[i] {
            return false;
        }
        if ins[i] {
            s += n.weights[i];
        }
    }
    s >= n.threshold
}

/// P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight.
pub fn joint_acceptance(n: &NRule, ps: &[f64]) -> f64 {
    let th = n.threshold as usize;
    let mut dist = vec![0.0f64; th + 1];
    dist[0] = 1.0;
    for (i, p) in ps.iter().enumerate() {
        let mut nxt = vec![0.0f64; th + 1];
        let w = n.weights[i] as usize;
        for s in 0..=th {
            let m = dist[s];
            if m == 0.0 {
                continue;
            }
            let t = th.min(s + w);
            nxt[t] += m * p;
            if !n.veto[i] {
                nxt[s] += m * (1.0 - p);
            }
        }
        dist = nxt;
    }
    dist[th]
}

// ---- cross-org: common refinement -------------------------------------------------------------------------------------------

fn sev(r: &Value) -> i64 {
    ORDER.iter().position(|x| r.as_str() == Some(*x)).map(|x| x as i64).unwrap_or(-1)
}

fn merge_dim(a: &Value, b: &Value) -> R<Value> {
    if a["kind"] != b["kind"] {
        return Err(format!("commonRefinement: {} is numeric in one \u{3a9} and categorical in another", js_str(&a["path"])));
    }
    if a["kind"].as_str() == Some("num") {
        if fnum(&a["lo"]) != fnum(&b["lo"]) || fnum(&a["hi"]) != fnum(&b["hi"]) {
            return Err(format!(
                "commonRefinement: {} has different domains ([{}, {}] vs [{}, {}])",
                js_str(&a["path"]),
                js_str(&a["lo"]),
                js_str(&a["hi"]),
                js_str(&b["lo"]),
                js_str(&b["hi"])
            ));
        }
        let mut cuts: Vec<f64> = vec![];
        for c in arr(&a["cuts"], "cuts")?.iter().chain(arr(&b["cuts"], "cuts")?.iter()) {
            let f = fnum(c).ok_or("a cut must be a number")?;
            if !cuts.contains(&f) {
                cuts.push(f);
            }
        }
        cuts.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        let mut d = Map::new();
        d.insert("kind".into(), json!("num"));
        d.insert("path".into(), a["path"].clone());
        d.insert("lo".into(), a["lo"].clone());
        d.insert("hi".into(), a["hi"].clone());
        if let Some(x) = member(a, "dist") {
            d.insert("dist".into(), x.clone());
        }
        d.insert("cuts".into(), Value::Array(cuts.iter().map(|c| num(*c)).collect()));
        return Ok(Value::Object(d));
    }
    let mut ex: Vec<String> = vec![];
    let mut pre: Vec<String> = vec![];
    for v in arr(&a["values"], "values")?.iter().chain(arr(&b["values"], "values")?.iter()) {
        let s = text(&v["value"], "value")?.to_string();
        match v["kind"].as_str() {
            Some("exact") => {
                if !ex.contains(&s) {
                    ex.push(s)
                }
            }
            Some("prefix") => {
                if !pre.contains(&s) {
                    pre.push(s)
                }
            }
            _ => {}
        }
    }
    sort_u16(&mut ex);
    sort_u16(&mut pre);
    let mut values: Vec<Value> = ex.iter().map(|v| json!({"kind": "exact", "value": v})).collect();
    values.extend(pre.iter().map(|v| json!({"kind": "prefix", "value": v})));
    values.push(json!({"kind": "other", "value": OTHER}));
    Ok(json!({"kind": "cat", "path": a["path"], "values": values}))
}

/// The union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts (domains must agree); per
/// categorical dimension the union of the named values.
pub fn common_refinement(omegas: &[Value]) -> R<Value> {
    let mut by_verb: Vec<(String, Value)> = vec![];
    let mut approx: Vec<String> = vec![];
    for o in omegas {
        for x in arr(&o["approximate"], "omega.approximate")? {
            let s = text(x, "approximate entry")?.to_string();
            if !approx.contains(&s) {
                approx.push(s);
            }
        }
        for vs in arr(&o["verbs"], "omega.verbs")? {
            let verb = text(&vs["verb"], "verb")?.to_string();
            match by_verb.iter().position(|x| x.0 == verb) {
                None => by_verb.push((verb.clone(), json!({"verb": verb, "reversibility": vs["reversibility"], "weight": 0, "dims": vs["dims"]}))),
                Some(pos) => {
                    let cur = &mut by_verb[pos].1;
                    if sev(&vs["reversibility"]) > sev(&cur["reversibility"]) {
                        cur["reversibility"] = vs["reversibility"].clone();
                    }
                    for d in arr(&vs["dims"], "dims")? {
                        let dims = cur["dims"].as_array_mut().ok_or("dims must be a list")?;
                        match dims.iter().position(|x| x["path"] == d["path"]) {
                            None => dims.push(d.clone()),
                            Some(i) => {
                                let merged = merge_dim(&dims[i], d)?;
                                dims[i] = merged;
                            }
                        }
                    }
                }
            }
        }
    }
    by_verb.sort_by(|a, b| u16cmp(&a.0, &b.0));
    let n = by_verb.len() as f64;
    let mut verbs: Vec<Value> = vec![];
    for (_, mut v) in by_verb {
        if let Some(dims) = v["dims"].as_array_mut() {
            dims.sort_by(|a, b| u16cmp(a["path"].as_str().unwrap_or(""), b["path"].as_str().unwrap_or("")));
        }
        v["weight"] = num(1.0 / n);
        verbs.push(v);
    }
    sort_u16(&mut approx);
    Ok(json!({"v": 1, "verbs": verbs, "approximate": approx}))
}

// ---- aggregation over Intent Maps --------------------------------------------------------------------------------------------

fn metric_or0(m: &Value, k: &str) -> R<f64> {
    match nn(&m["metrics"], k) {
        None => Ok(0.0),
        Some(v) => fnum(v).ok_or_else(|| format!("metric {k} must be a number")),
    }
}

/// Aggregate single-principal maps over a SHARED omega under a rule; the result has `aggregation` set. `opts` is the reference's
/// `{orgs?}` options object.
pub fn aggregate_intent_maps(maps: &[Value], rule: &Value, opts: Option<&Value>) -> R<Value> {
    let orgs = opts.and_then(|o| member(o, "orgs")).filter(|x| truthy(x));
    if maps.is_empty() {
        return Err("aggregateIntentMaps: no maps".into());
    }
    let om = crate::js_stringify(&maps[0]["omega"]);
    if maps.iter().any(|m| crate::js_stringify(&m["omega"]) != om) {
        return Err("aggregateIntentMaps: maps must share \u{3a9} (lift them with crossOrgAggregate)".into());
    }
    for m in maps {
        let single = nn(m, "aggregation").is_none() && m["principals"].as_array().is_some_and(|p| p.len() == 1) && m["intent_ref"].is_string();
        if !single {
            return Err("aggregateIntentMaps: every input must be a single-principal map with an intent_ref".into());
        }
    }
    let refs: Vec<String> = maps.iter().map(|m| m["intent_ref"].as_str().unwrap_or("").to_string()).collect();
    let mut uniq = refs.clone();
    uniq.sort();
    uniq.dedup();
    if uniq.len() != refs.len() {
        return Err("aggregateIntentMaps: duplicate principal".into());
    }
    let n = normalize_rule(rule, &refs)?;
    let omega = Omega::parse(&omega_from_json(&maps[0]["omega"])?)?;
    let mut stats: Vec<(f64, f64)> = vec![];
    for vs in &omega.verbs {
        for c in 0..vs.cell_count() {
            stats.push(cell_stats(vs, &vs.decode_cell(c as f64))?);
        }
    }
    let first_cells = arr(&maps[0]["cells"], "cells")?;
    let mut cells: Vec<Value> = vec![];
    for (i, c) in first_cells.iter().enumerate() {
        let mut ps = vec![];
        let mut ins = vec![];
        for m in maps {
            let mc = m["cells"].get(i).ok_or("a map lists fewer cells than the first map")?;
            ps.push(fnum(&mc["p_ppm"]).ok_or("cell p_ppm must be a number")? / PPM);
            ins.push(truthy(&mc["in_grant"]));
        }
        cells.push(json!({"verb": c["verb"], "cell": c["cell"], "p_ppm": num(mppm(joint_acceptance(&n, &ps))), "in_grant": rule_admits(&n, &ins)}));
    }
    let mut predicates: Vec<Value> = vec![];
    let mut worst: i64 = -1;
    let mut off = 0usize;
    for vs in &omega.verbs {
        let nc = vs.cell_count();
        let mut allowed = vec![0u8; nc];
        let mut any = false;
        for c in 0..nc {
            if cells.get(off + c).map(|x| x["in_grant"] == json!(true)).unwrap_or(false) {
                allowed[c] = 1;
                any = true;
            }
        }
        off += nc;
        if !any {
            continue;
        }
        worst = worst.max(ORDER.iter().position(|x| vs.reversibility.as_deref() == Some(*x)).map(|x| x as i64).unwrap_or(-1));
        predicates.extend(boxes_to_predicates(vs, &allowed)?);
    }
    let caveats = if worst >= 0 { json!([{"type": "reversibility_max", "class": ORDER[worst as usize]}]) } else { json!([]) };
    let grant = json!({"predicates": predicates, "caveats": caveats});
    // each principal's own posterior estimate of the JOINT grant
    let mut per: Vec<(String, Option<Value>, f64, f64, f64)> = vec![];
    for (i, m) in maps.iter().enumerate() {
        let (mut r, mut b, mut rmax) = (0.0, 0.0, 0.0);
        for (j, c) in arr(&m["cells"], "cells")?.iter().enumerate() {
            let p = fnum(&c["p_ppm"]).ok_or("cell p_ppm must be a number")? / PPM;
            let (mass, harm) = *stats.get(j).ok_or("a map lists more cells than the omega has")?;
            rmax += mass * (1.0 - p) * harm;
            if cells.get(j).map(|x| x["in_grant"] == json!(true)).unwrap_or(false) {
                r += mass * (1.0 - p) * harm;
            } else {
                b += mass * p;
            }
        }
        let org = orgs.and_then(|o| member(o, &refs[i])).filter(|x| truthy(x)).cloned();
        per.push((refs[i].clone(), org, r, b, if rmax > 0.0 { 1.0 - r / rmax } else { 1.0 }));
    }
    let kind = rule["kind"].clone();
    let mut aggregation = Map::new();
    aggregation.insert("rule".into(), kind.clone());
    if kind.as_str() == Some("quorum") {
        aggregation.insert("k".into(), rule["k"].clone());
    }
    if kind.as_str() == Some("weighted") {
        let mut w = Map::new();
        for (i, r) in refs.iter().enumerate() {
            w.insert(r.clone(), num(n.weights[i]));
        }
        aggregation.insert("weights".into(), Value::Object(w));
        aggregation.insert("threshold".into(), rule["threshold"].clone());
    }
    aggregation.insert("vetoers".into(), json!(refs.iter().enumerate().filter(|(i, _)| n.veto[*i]).map(|(_, r)| r.clone()).collect::<Vec<String>>()));
    let mut pps: Vec<Value> = vec![];
    let (mut max_r, mut max_b) = (f64::NEG_INFINITY, f64::NEG_INFINITY);
    for x in &per {
        let mut pp = Map::new();
        pp.insert("intent_ref".into(), json!(x.0));
        if let Some(o) = &x.1 {
            pp.insert("org".into(), o.clone());
        }
        let (rp, bp) = (mppm(x.2), mppm(x.3));
        max_r = max_r.max(rp);
        max_b = max_b.max(bp);
        pp.insert("residual_risk_ppm".into(), num(rp));
        pp.insert("burden_ppm".into(), num(bp));
        pps.push(Value::Object(pp));
    }
    aggregation.insert("per_principal".into(), Value::Array(pps));
    let fold = |k: &str, f: &dyn Fn(f64, f64) -> f64, init: f64| -> R<f64> {
        let mut acc = init;
        for m in maps {
            acc = f(acc, metric_or0(m, k)?);
        }
        Ok(acc)
    };
    let mx = |a: f64, b: f64| if a > b { a } else { b };
    let sm = |a: f64, b: f64| a + b;
    let log2_none = maps.iter().any(|m| nn(&m["metrics"], "log2_vs_mbits").is_none());
    let min_f = per.iter().map(|x| x.4).fold(f64::INFINITY, f64::min);
    let observations: Vec<Value> = maps.iter().flat_map(|m| m["observations"].as_array().cloned().unwrap_or_default()).collect();
    let log2_val = if log2_none { Value::Null } else { num(fold("log2_vs_mbits", &sm, 0.0)?) };
    let metrics = json!({
        "residual_risk_ppm": num(max_r),
        "burden_ppm": num(max_b),
        "uncertainty_ppm": num(fold("uncertainty_ppm", &mx, f64::NEG_INFINITY)?),
        "disagreement_ppm": num(fold("disagreement_ppm", &mx, f64::NEG_INFINITY)?),
        "mean_harm_ppm": maps[0]["metrics"]["mean_harm_ppm"].clone(),
        "fidelity_est_ppm": num(mppm(min_f)),
        "entropy_mbits": num(fold("entropy_mbits", &sm, 0.0)?),
        "log2_vs_mbits": log2_val,
        "questions": num(fold("questions", &sm, 0.0)?),
        "conflicts": num(fold("conflicts", &sm, 0.0)?),
    });
    Ok(json!({
        "v": 1,
        "kind": "pca-intent-map",
        "intent_ref": Value::Null,
        "principals": refs,
        "omega": maps[0]["omega"],
        "learner": maps[0]["learner"],
        "observations": observations,
        "cells": cells,
        "grant": grant,
        "grant_digest": grant_digest(&grant)?,
        "metrics": metrics,
        "aggregation": Value::Object(aggregation),
    }))
}

/// The unanimity rule: the joint grant is the intersection of the principals' conservative grants.
pub fn combine_intent_maps(maps: &[Value], opts: Option<&Value>) -> R<Value> {
    aggregate_intent_maps(maps, &json!({"kind": "unanimity"}), opts)
}

/// The rule an aggregated map records.
pub fn rule_of(agg: &Value) -> R<Value> {
    let a = match member(agg, "aggregation").filter(|x| truthy(x)) {
        Some(a) => a,
        None => return Err("ruleOf: not an aggregated map".into()),
    };
    let vetoers = member(a, "vetoers").ok_or("aggregation.vetoers is missing")?.clone();
    let g = |k: &str| member(a, k).cloned().unwrap_or(Value::Null);
    Ok(match a["rule"].as_str() {
        Some("unanimity") => json!({"kind": "unanimity", "vetoers": vetoers}),
        Some("quorum") => json!({"kind": "quorum", "k": g("k"), "vetoers": vetoers}),
        _ => json!({"kind": "weighted", "weights": g("weights"), "threshold": g("threshold"), "vetoers": vetoers}),
    })
}

/// Replay-verify every input map, then recompute the aggregate and compare digests (inputs share the omega): `{ok, problems}`.
pub fn verify_aggregate(agg: &Value, inputs: &[Value], opts: Option<&Value>) -> Value {
    let mut problems: Vec<String> = vec![];
    for (i, m) in inputs.iter().enumerate() {
        let r = verify_intent_map(m);
        if r["ok"] != json!(true) {
            let ps: Vec<String> = r["problems"].as_array().map(|a| a.iter().map(js_str).collect()).unwrap_or_default();
            problems.push(format!("input {i}: {}", ps.join("; ")));
        }
    }
    if problems.is_empty() {
        let again: R<bool> = (|| -> R<bool> {
            let a = aggregate_intent_maps(inputs, &rule_of(agg)?, opts)?;
            Ok(intent_map_digest(&a)? == intent_map_digest(agg)?)
        })();
        match again {
            Ok(true) => {}
            Ok(false) => problems.push("aggregate does not match its recomputation".into()),
            Err(e) => problems.push(format!("recompute failed: {e}")),
        }
    }
    json!({"ok": problems.is_empty(), "problems": problems})
}

/// Re-express a single-principal map on a refinement of its omega: observations re-applied as value-space regions and prior mass 1 on
/// the empty hypothesis for every verb the map did not cover.
pub fn lift_intent_map(m: &Value, target: &Value) -> R<Value> {
    if nn(m, "aggregation").is_some() || arr(&m["principals"], "principals")?.len() > 1 {
        return Err("liftIntentMap: lift single-principal maps, then aggregate".into());
    }
    let src_v = omega_from_json(&m["omega"])?;
    let src = Omega::parse(&src_v)?;
    let tgt = Omega::parse(target)?;
    let mut o = map_learner_options(m)?;
    let src_mass = member(&o, "nullMass").cloned();
    let mut null_mass = Map::new();
    for vs in &tgt.verbs {
        let v = if src.vs_of(&vs.verb).is_some() {
            match src_mass.as_ref().and_then(|s| nn(s, &vs.verb)) {
                Some(own) => own.clone(),
                None => json!(0.2),
            }
        } else {
            json!(1)
        };
        null_mass.insert(vs.verb.clone(), v);
    }
    o.as_object_mut().ok_or("learner options must be an object")?.insert("nullMass".into(), Value::Object(null_mass));
    let mut l = create_learner(target, &o)?;
    for ob in arr(&m["observations"], "observations")? {
        let verb = text(&ob["verb"], "observation verb")?;
        let (svs, tvs) = match (src.vs_of(verb), tgt.vs_of(verb)) {
            (Some(s), Some(t)) => (s, t),
            _ => return Err(format!("liftIntentMap: verb {verb} missing from \u{3a9}")),
        };
        let mut values = ob["values"].as_object().cloned().unwrap_or_default();
        for d in &tvs.dims {
            if !values.contains_key(&d.path) {
                values.insert(d.path.clone(), d.rep_value(0)?);
            }
        }
        let own_cell = svs
            .cell_of(&json!({"verb": verb, "values": ob["values"]}))
            .ok_or_else(|| format!("liftIntentMap: an observation of {verb} lies outside the map's own \u{3a9}"))?;
        let region = match nn(ob, "region") {
            Some(r) => r.clone(),
            None => region_of_cell(svs, &own_cell)?,
        };
        let y = fnum(&ob["y"]).ok_or("observation y must be a number")?;
        l.observe(&json!({"verb": verb, "values": Value::Object(values)}), y, text(&ob["source"], "observation source")?, Some(&region))?;
    }
    emit_intent_map(&mut l, m["intent_ref"].as_str())
}

/// The result of [`cross_org_aggregate`].
pub struct CrossOrg {
    pub aggregate: Value,
    pub lifted: Vec<Value>,
    pub omega: Value,
}

/// Replay-verify every map, lift all of them onto the common refinement of their omegas, then aggregate.
pub fn cross_org_aggregate(maps: &[Value], rule: &Value, opts: Option<&Value>) -> R<CrossOrg> {
    for (i, m) in maps.iter().enumerate() {
        let r = verify_intent_map(m);
        if r["ok"] != json!(true) {
            let ps: Vec<String> = r["problems"].as_array().map(|a| a.iter().map(js_str).collect()).unwrap_or_default();
            return Err(format!("crossOrgAggregate: map {i} does not verify: {}", ps.join("; ")));
        }
    }
    let mut omegas = vec![];
    for m in maps {
        omegas.push(omega_from_json(&m["omega"])?);
    }
    let omega = common_refinement(&omegas)?;
    let mut lifted = vec![];
    for m in maps {
        lifted.push(lift_intent_map(m, &omega)?);
    }
    let aggregate = aggregate_intent_maps(&lifted, rule, opts)?;
    Ok(CrossOrg { aggregate, lifted, omega })
}

/// Verify a cross-org aggregate by recomputing it from the ORIGINAL maps: `{ok, problems}`.
pub fn verify_cross_org_aggregate(agg: &Value, maps: &[Value], opts: Option<&Value>) -> Value {
    let r: R<bool> = (|| -> R<bool> {
        let again = cross_org_aggregate(maps, &rule_of(agg)?, opts)?.aggregate;
        Ok(intent_map_digest(&again)? == intent_map_digest(agg)?)
    })();
    match r {
        Ok(true) => json!({"ok": true, "problems": []}),
        Ok(false) => json!({"ok": false, "problems": ["aggregate does not match its recomputation"]}),
        Err(e) => json!({"ok": false, "problems": [e]}),
    }
}

/// The omega of an aggregated or single map as JSON (a comparison key).
pub fn omega_key(o: &Value) -> R<String> {
    Ok(crate::js_stringify(&omega_to_json(o)?))
}
