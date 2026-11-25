//! Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP and the common
//! refinement of several outcome spaces.
use super::omega::*;
use super::*;
use serde_json::Value;

pub const PPM: f64 = 1_000_000.0;

pub fn ppm(x: f64) -> f64 {
    (x * PPM + 0.5).floor()
}

/// A rule in normal form.
#[derive(Clone, Debug)]
pub struct NRule {
    pub weights: Vec<f64>,
    pub threshold: f64,
    pub veto: Vec<bool>,
}

impl NRule {
    pub fn to_json(&self) -> Value {
        obj(vec![
            ("weights", Value::Array(self.weights.iter().map(|w| jn(*w)).collect())),
            ("threshold", jn(self.threshold)),
            ("veto", Value::Array(self.veto.iter().map(|b| Value::Bool(*b)).collect())),
        ])
    }
    pub fn from_json(v: &Value) -> R<NRule> {
        let ws = get(v, "weights").and_then(Value::as_array).ok_or("rule: weights must be an array")?;
        let vt = get(v, "veto").and_then(Value::as_array).ok_or("rule: veto must be an array")?;
        let mut weights = vec![];
        for w in ws {
            weights.push(num(w).ok_or("rule: weights must be numbers")?);
        }
        let mut veto = vec![];
        for b in vt {
            veto.push(b.as_bool().ok_or("rule: veto must be booleans")?);
        }
        Ok(NRule { weights, threshold: get_num(v, "threshold").ok_or("rule: threshold must be a number")?, veto })
    }
}

fn is_int(v: Option<&Value>) -> Option<f64> {
    let f = v.and_then(num)?;
    if f.is_finite() && f.fract() == 0.0 {
        Some(f)
    } else {
        None
    }
}

fn js_number_text(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

/// A rule in normal form `{weights, threshold, veto}`; the reference's refusals.
pub fn normalize_rule(rule: &Value, refs: &[String]) -> R<NRule> {
    if rule.is_null() {
        return Err("Cannot read properties of null (reading 'vetoers')".into());
    }
    let vetoers: Vec<Value> = match get(rule, "vetoers") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Some(_) => return Err("rule.vetoers is not iterable".into()),
    };
    for v in &vetoers {
        if !v.as_str().is_some_and(|s| refs.iter().any(|r| r == s)) {
            return Err(format!("aggregateIntentMaps: vetoer {} is not one of the maps", crate::intent_v2::js_value_string(v)));
        }
    }
    let veto: Vec<bool> = refs.iter().map(|r| vetoers.iter().any(|v| v.as_str() == Some(r.as_str()))).collect();
    match get_str(rule, "kind") {
        Some("unanimity") => Ok(NRule { weights: refs.iter().map(|_| 1.0).collect(), threshold: refs.len() as f64, veto }),
        Some("quorum") => {
            let k = is_int(get(rule, "k"));
            match k {
                Some(k) if k >= 1.0 && k <= refs.len() as f64 => Ok(NRule { weights: refs.iter().map(|_| 1.0).collect(), threshold: k, veto }),
                _ => Err(format!("aggregateIntentMaps: quorum k must be an integer in [1, {}]", refs.len())),
            }
        }
        _ => {
            let wmap = if rule.is_object() { get(rule, "weights") } else { None };
            if let Some(first) = refs.first() {
                match wmap {
                    None => return Err(format!("Cannot read properties of undefined (reading '{first}')")),
                    Some(Value::Null) => return Err(format!("Cannot read properties of null (reading '{first}')")),
                    _ => {}
                }
            }
            let mut weights = vec![];
            for r in refs {
                match is_int(wmap.and_then(|m| get(m, r))) {
                    Some(w) if w >= 0.0 => weights.push(w),
                    _ => return Err("aggregateIntentMaps: every principal needs a non-negative integer weight".into()),
                }
            }
            let w_sum: f64 = weights.iter().sum();
            match is_int(get(rule, "threshold")) {
                Some(th) if th >= 1.0 && th <= w_sum => Ok(NRule { weights, threshold: th, veto }),
                _ => Err(format!("aggregateIntentMaps: threshold must be an integer in [1, {}]", js_number_text(w_sum))),
            }
        }
    }
}

/// Principals that bound the joint grant: explicit vetoers plus implicit ones (T > W - w_i).
pub fn effective_vetoers(rule: &Value, refs: &[String]) -> R<Vec<String>> {
    let n = normalize_rule(rule, refs)?;
    let w: f64 = n.weights.iter().sum();
    Ok(refs.iter().enumerate().filter(|(i, _)| n.veto[*i] || n.threshold > w - n.weights[*i]).map(|(_, r)| r.clone()).collect())
}

/// Vetoers must admit; the admitting weight must reach the threshold.
pub fn rule_admits(n: &NRule, ins: &[bool]) -> R<bool> {
    let mut s = 0.0;
    for (i, a) in ins.iter().enumerate() {
        if *n.veto.get(i).ok_or("ruleAdmits: veto index out of range")? && !*a {
            return Ok(false);
        }
        if *a {
            s += *n.weights.get(i).ok_or("ruleAdmits: weight index out of range")?;
        }
    }
    Ok(s >= n.threshold)
}

/// P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight.
pub fn joint_acceptance(n: &NRule, ps: &[f64]) -> R<f64> {
    if !(n.threshold >= 0.0 && n.threshold <= 16_777_216.0 && n.threshold.fract() == 0.0) {
        return Err("jointAcceptance: threshold out of range".into());
    }
    let th = n.threshold as usize;
    let mut dist = vec![0.0f64; th + 1];
    dist[0] = 1.0;
    for (i, p) in ps.iter().enumerate() {
        let mut nxt = vec![0.0f64; th + 1];
        let w = *n.weights.get(i).ok_or("jointAcceptance: weight index out of range")?;
        let veto = *n.veto.get(i).ok_or("jointAcceptance: veto index out of range")?;
        for s in 0..=th {
            let m = dist[s];
            if m == 0.0 {
                continue;
            }
            let t = js_min(th as f64, s as f64 + w) as usize;
            nxt[t] += m * p;
            if !veto {
                nxt[s] += m * (1.0 - p);
            }
        }
        dist = nxt;
    }
    Ok(dist[th])
}

// ---- cross-org: common refinement ------------------------------------------------------------------------------------------

fn sev(r: Option<&str>) -> i32 {
    match r {
        Some("reversible") => 0,
        Some("rate_limited") => 1,
        Some("irreversible") => 2,
        _ => -1,
    }
}

fn merge_dim(a: &Dim, b: &Dim) -> R<Dim> {
    match (a, b) {
        (Dim::Num { path, lo, hi, cuts, dist, .. }, Dim::Num { lo: blo, hi: bhi, cuts: bcuts, .. }) => {
            if lo != blo || hi != bhi {
                return Err(format!(
                    "commonRefinement: {path} has different domains ([{}, {}] vs [{}, {}])",
                    js_number_text(*lo),
                    js_number_text(*hi),
                    js_number_text(*blo),
                    js_number_text(*bhi)
                ));
            }
            let mut all: Vec<f64> = vec![];
            for c in cuts.iter().chain(bcuts.iter()) {
                if !all.iter().any(|x| x == c) {
                    all.push(*c);
                }
            }
            all.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            Ok(num_dim(path, *lo, *hi, all, dist.clone()))
        }
        (Dim::Cat { path, values }, Dim::Cat { values: bvalues, .. }) => {
            let mut ex: Vec<String> = vec![];
            let mut pre: Vec<String> = vec![];
            for v in values.iter().chain(bvalues.iter()) {
                if v.kind == "exact" && !ex.contains(&v.value) {
                    ex.push(v.value.clone());
                } else if v.kind == "prefix" && !pre.contains(&v.value) {
                    pre.push(v.value.clone());
                }
            }
            ex.sort_by(|x, y| u16cmp(x, y));
            pre.sort_by(|x, y| u16cmp(x, y));
            let mut out: Vec<CatVal> = ex.into_iter().map(|v| CatVal { kind: "exact".into(), value: v }).collect();
            out.extend(pre.into_iter().map(|v| CatVal { kind: "prefix".into(), value: v }));
            out.push(CatVal { kind: "other".into(), value: OTHER.into() });
            Ok(Dim::Cat { path: path.clone(), values: out })
        }
        _ => Err(format!("commonRefinement: {} is numeric in one \u{3a9} and categorical in another", a.path())),
    }
}

/// The union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts (domains must agree); per
/// categorical dimension the union of the named values.
pub fn common_refinement(omegas: &Value) -> R<Value> {
    let list = omegas.as_array().ok_or("commonRefinement: omegas must be an array")?;
    let mut by_verb: Vec<VerbSpace> = vec![];
    let mut approx: Vec<String> = vec![];
    for ov in list {
        let o = Omega::from_json(ov)?;
        for x in &o.approximate {
            if !approx.contains(x) {
                approx.push(x.clone());
            }
        }
        for vs in &o.verbs {
            match by_verb.iter().position(|c| c.verb == vs.verb) {
                None => by_verb.push(VerbSpace { verb: vs.verb.clone(), reversibility: vs.reversibility.clone(), weight: 0.0, dims: vs.dims.clone() }),
                Some(ci) => {
                    let cur = &mut by_verb[ci];
                    if sev(vs.reversibility.as_deref()) > sev(cur.reversibility.as_deref()) {
                        cur.reversibility = vs.reversibility.clone();
                    }
                    for d in &vs.dims {
                        match cur.dims.iter().position(|x| x.path() == d.path()) {
                            None => cur.dims.push(d.clone()),
                            Some(i) => {
                                let merged = merge_dim(&cur.dims[i], d)?;
                                cur.dims[i] = merged;
                            }
                        }
                    }
                }
            }
        }
    }
    by_verb.sort_by(|a, b| u16cmp(&a.verb, &b.verb));
    let n = by_verb.len() as f64;
    for v in by_verb.iter_mut() {
        v.dims.sort_by(|a, b| u16cmp(a.path(), b.path()));
        v.weight = 1.0 / n;
    }
    approx.sort_by(|a, b| u16cmp(a, b));
    Ok(Omega { verbs: by_verb, approximate: approx }.to_json())
}
