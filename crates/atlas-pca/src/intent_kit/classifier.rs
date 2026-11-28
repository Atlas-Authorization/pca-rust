//! Classifier error folded into the residual-risk estimate: the confusion calibration (exact Clopper-Pearson upper bounds per entry), the
//! risk on explicit arrays, the label-sound bound, the classifier-aware residual risk of a learner and the gamma-max JIT gate.
use super::clopper::clopper_pearson_upper;
use super::learner::*;
use super::omega::*;
use super::*;
use serde_json::Value;
use std::collections::HashMap;

fn str_list(v: &Value, what: &str) -> R<Vec<String>> {
    v.as_array()
        .ok_or_else(|| format!("{what} must be an array"))?
        .iter()
        .map(|x| x.as_str().map(String::from).ok_or_else(|| format!("{what} must hold strings")))
        .collect()
}

/// Calibrate a classifier on labelled examples (`samples` = `[{truth, predicted}]`). Labels outside the label set are refused.
pub fn calibrate_confusion(samples: &Value, labels: &Value, delta_gamma: f64) -> R<Value> {
    let mut l: Vec<String> = vec![];
    for x in str_list(labels, "calibrateConfusion: labels")? {
        if !l.contains(&x) {
            l.push(x);
        }
    }
    l.sort();
    if l.is_empty() {
        return Err("calibrateConfusion: empty label set".into());
    }
    if !(delta_gamma > 0.0 && delta_gamma < 1.0) {
        return Err("calibrateConfusion: delta must be in (0, 1)".into());
    }
    let n_l = l.len();
    let mut counts = vec![vec![0u64; n_l]; n_l];
    for s in samples.as_array().ok_or("calibrateConfusion: samples must be an array")? {
        let t = get_str(s, "truth").and_then(|x| l.iter().position(|y| y == x));
        let p = get_str(s, "predicted").and_then(|x| l.iter().position(|y| y == x));
        match (t, p) {
            (Some(t), Some(p)) => counts[t][p] += 1,
            _ => {
                return Err(format!(
                    "calibrateConfusion: label outside L ({} / {})",
                    get(s, "truth").map(crate::js_stringify).unwrap_or_default(),
                    get(s, "predicted").map(crate::js_stringify).unwrap_or_default()
                ))
            }
        }
    }
    let alpha = delta_gamma / (n_l * n_l) as f64;
    let mut gamma = vec![];
    let mut gamma_bar = vec![];
    for row in &counts {
        let n: u64 = row.iter().sum();
        gamma.push(Value::Array(row.iter().map(|c| jn(if n > 0 { *c as f64 / n as f64 } else { 0.0 })).collect()));
        let mut gb = vec![];
        for c in row {
            gb.push(jn(clopper_pearson_upper(*c, n, alpha)?));
        }
        gamma_bar.push(Value::Array(gb));
    }
    Ok(obj(vec![
        ("labels", Value::Array(l.iter().map(|s| jstr(s)).collect())),
        ("counts", Value::Array(counts.iter().map(|r| Value::Array(r.iter().map(|c| jn(*c as f64)).collect())).collect())),
        ("gamma", Value::Array(gamma)),
        ("gammaBar", Value::Array(gamma_bar)),
        ("delta_ppm", jn((delta_gamma * 1_000_000.0 + 0.5).floor())),
    ]))
}

pub fn confusion_digest(c: &Value) -> R<String> {
    let m = |k: &str| get(c, k).cloned().ok_or_else(|| format!("confusionDigest: missing {k}"));
    hash_strict(&obj(vec![
        ("d", jstr("atlas-pca/intent-classifier-calibration/v1")),
        ("labels", m("labels")?),
        ("counts", m("counts")?),
        ("delta_ppm", m("delta_ppm")?),
    ]))
}

fn matrix(v: Option<&Value>, what: &str) -> R<Vec<Vec<f64>>> {
    let rows = v.and_then(Value::as_array).ok_or_else(|| format!("{what} must be an array"))?;
    let mut out = vec![];
    for r in rows {
        let cells = r.as_array().ok_or_else(|| format!("{what} rows must be arrays"))?;
        let mut row = vec![];
        for x in cells {
            row.push(num(x).ok_or_else(|| format!("{what} must hold numbers"))?);
        }
        out.push(row);
    }
    Ok(out)
}

/// Max over true labels of the capped upper bound of any other label.
pub fn published_error_rate(c: &Value) -> R<f64> {
    let gb = matrix(get(c, "gammaBar"), "gammaBar")?;
    let mut worst = 0.0f64;
    for (t, row) in gb.iter().enumerate() {
        let mut s = 0.0;
        for (p, g) in row.iter().enumerate() {
            if p != t {
                s += *g;
            }
        }
        let e = js_min(1.0, s);
        if e > worst {
            worst = e;
        }
    }
    Ok(worst)
}

/// JavaScript `Number.prototype.toFixed(1)` for a non-negative double (the exact binary value, halves rounding up).
fn to_fixed1(x: f64) -> String {
    let s = format!("{:.60}", x);
    let (ip, fp) = s.split_once('.').unwrap_or((s.as_str(), ""));
    let d: Vec<u8> = fp.bytes().collect();
    let mut n: u128 = ip.parse::<u128>().unwrap_or(0) * 10 + (d.first().copied().unwrap_or(b'0') - b'0') as u128;
    if d.get(1).copied().unwrap_or(b'0') >= b'5' {
        n += 1;
    }
    format!("{}.{}", n / 10, n % 10)
}

pub fn classifier_card_note(id: &str, c: &Value) -> R<String> {
    let pct = to_fixed1(published_error_rate(c)? * 100.0);
    Ok(format!("\"{id}\" is decided by an attested classifier, not by a person. Published error rate: up to {pct}%."))
}

fn gamma_of_set(g: &[Vec<f64>], a: &[usize], t: usize) -> R<f64> {
    let mut s = 0.0;
    for p in a {
        s += *g.get(*p).and_then(|r| r.get(t)).ok_or("classifier: g index out of range")?;
    }
    Ok(js_min(1.0, s))
}

fn in_g_row(m: &Value, x: usize) -> R<Vec<usize>> {
    let row = get(m, "inG").and_then(Value::as_array).and_then(|r| r.get(x)).and_then(Value::as_array).ok_or("classifier: inG must be a matrix")?;
    Ok(row.iter().enumerate().filter(|(_, b)| truthy(Some(b))).map(|(p, _)| p).collect())
}

/// R_kappa(G) = sum mu (1 - a) h Gamma(A_G(x) | l), with Gamma(A | l) capped at 1.
pub fn classifier_risk(m: &Value) -> R<f64> {
    let (mu, a, h, g) = (matrix(get(m, "mu"), "mu")?, matrix(get(m, "a"), "a")?, matrix(get(m, "h"), "h")?, matrix(get(m, "g"), "g")?);
    let mut r = 0.0;
    for (x, row) in mu.iter().enumerate() {
        let aa = in_g_row(m, x)?;
        for (t, mu_v) in row.iter().enumerate() {
            let at = *a.get(x).and_then(|r| r.get(t)).ok_or("classifier: a index out of range")?;
            let ht = *h.get(x).and_then(|r| r.get(t)).ok_or("classifier: h index out of range")?;
            r += mu_v * (1.0 - at) * ht * gamma_of_set(&g, &aa, t)?;
        }
    }
    Ok(r)
}

pub fn label_sound(m: &Value) -> R<bool> {
    let a = matrix(get(m, "a"), "a")?;
    let rows = get(m, "inG").and_then(Value::as_array).ok_or("classifier: inG must be a matrix")?;
    for (x, row) in rows.iter().enumerate() {
        for (p, b) in row.as_array().ok_or("classifier: inG must be a matrix")?.iter().enumerate() {
            if truthy(Some(b)) && *a.get(x).and_then(|r| r.get(p)).ok_or("classifier: a index out of range")? != 1.0 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub fn label_sound_bound(m: &Value, h_max: f64) -> R<f64> {
    let (mu, a, g) = (matrix(get(m, "mu"), "mu")?, matrix(get(m, "a"), "a")?, matrix(get(m, "g"), "g")?);
    let mut s = 0.0;
    for (x, row) in mu.iter().enumerate() {
        let aa = in_g_row(m, x)?;
        for (t, mu_v) in row.iter().enumerate() {
            if *a.get(x).and_then(|r| r.get(t)).ok_or("classifier: a index out of range")? == 0.0 {
                s += mu_v * gamma_of_set(&g, &aa, t)?;
            }
        }
    }
    Ok(h_max * s)
}

type Groups = Vec<(String, Vec<(usize, CellInfo)>)>;

fn groups_of(l: &mut IntentLearner, spec: &Value) -> R<(Dim, Groups)> {
    let verb = get_str(spec, "verb").ok_or("classifier: spec.verb")?;
    let path = get_str(spec, "path").ok_or("classifier: spec.path")?;
    let vs = l.omega.verb(verb).ok_or_else(|| format!("classifier: no verb {verb} in \u{3a9}"))?.clone();
    let k = vs.dims.iter().position(|d| d.path() == path);
    let dim = match k.map(|k| vs.dims[k].clone()) {
        Some(d @ Dim::Cat { .. }) => d,
        _ => return Err(format!("classifier: {verb} has no categorical dimension {path}")),
    };
    let k = k.unwrap();
    let mut groups: Groups = vec![];
    let mut index: HashMap<String, usize> = HashMap::new();
    for c in l.cells() {
        if c.verb != verb {
            continue;
        }
        let key = c.cell.iter().enumerate().filter(|(i, _)| *i != k).map(|(_, x)| x.to_string()).collect::<Vec<_>>().join(",");
        let gi = *index.entry(key.clone()).or_insert_with(|| {
            groups.push((key.clone(), vec![]));
            groups.len() - 1
        });
        let at = c.cell[k];
        let slot = &mut groups[gi].1;
        match slot.iter().position(|(i, _)| *i == at) {
            Some(p) => slot[p].1 = c,
            None => slot.push((at, c)),
        }
    }
    Ok((dim, groups))
}

fn gbar(cal_labels: &[String], cal_gb: &[Vec<f64>], dim: &Dim, pred: usize, truth: usize) -> R<f64> {
    let values = match dim {
        Dim::Cat { values, .. } => values,
        _ => return Err("classifier: not categorical".into()),
    };
    let pv = &values[pred];
    let tv = &values[truth];
    if pv.kind != "exact" {
        return Ok(0.0);
    }
    let Some(pi) = cal_labels.iter().position(|x| *x == pv.value) else { return Ok(0.0) };
    let ti = if tv.kind == "exact" { cal_labels.iter().position(|x| *x == tv.value) } else { None };
    let Some(ti) = ti else { return Ok(1.0) };
    Ok(*cal_gb.get(ti).and_then(|r| r.get(pi)).ok_or("classifier: gammaBar index out of range")?)
}

fn sum_gbar(lab: &[String], gb: &[Vec<f64>], dim: &Dim, a: &[usize], t: usize) -> R<f64> {
    let mut s = 0.0;
    for p in a {
        s += gbar(lab, gb, dim, *p, t)?;
    }
    Ok(s)
}

fn cal_of(spec: &Value) -> R<(Vec<String>, Vec<Vec<f64>>)> {
    let cal = get(spec, "cal").ok_or("classifier: spec.cal")?;
    Ok((str_list(get(cal, "labels").ok_or("classifier: cal.labels")?, "cal.labels")?, matrix(get(cal, "gammaBar"), "gammaBar")?))
}

/// R-hat of the learner's grant with classifier error folded in; other verbs contribute the ordinary sum.
pub fn classifier_aware_residual_risk(l: &mut IntentLearner, specs: &Value) -> R<Value> {
    let specs = specs.as_array().ok_or("classifier: specs must be an array")?;
    let spec_verbs: Vec<&str> = specs.iter().filter_map(|s| get_str(s, "verb")).collect();
    let mut per_verb: Vec<(String, f64)> = vec![];
    for c in l.cells() {
        if spec_verbs.contains(&c.verb.as_str()) {
            continue;
        }
        let i = match per_verb.iter().position(|(v, _)| *v == c.verb) {
            Some(i) => i,
            None => {
                per_verb.push((c.verb.clone(), 0.0));
                per_verb.len() - 1
            }
        };
        if c.in_grant {
            per_verb[i].1 = per_verb[i].1 + c.mass * (1.0 - c.p) * c.harm;
        }
    }
    for spec in specs {
        let (dim, groups) = groups_of(l, spec)?;
        let (lab, gb) = cal_of(spec)?;
        let mut r = 0.0;
        for (_, g) in &groups {
            let a: Vec<usize> = g.iter().filter(|(_, m)| m.in_grant).map(|(i, _)| *i).collect();
            for (t, m) in g {
                r += m.mass * (1.0 - m.p) * m.harm * js_min(1.0, sum_gbar(&lab, &gb, &dim, &a, *t)?);
            }
        }
        let verb = get_str(spec, "verb").unwrap_or("").to_string();
        match per_verb.iter().position(|(v, _)| *v == verb) {
            Some(i) => per_verb[i].1 = r,
            None => per_verb.push((verb, r)),
        }
    }
    let mut total = 0.0;
    for (_, x) in &per_verb {
        total += *x;
    }
    let mut pv = serde_json::Map::new();
    for (v, x) in &per_verb {
        pv.insert(v.clone(), jn(*x));
    }
    Ok(obj(vec![("total", jn(total)), ("perVerb", Value::Object(pv))]))
}

/// Cells admitted on a classifier label that go to JIT consent: some true label the grant does not admit at the same x has an
/// upper-bounded mislabel rate above gamma_max.
pub fn classifier_jit_cells(l: &mut IntentLearner, spec: &Value, gamma_max: f64) -> R<Value> {
    let (dim, groups) = groups_of(l, spec)?;
    let (lab, gb) = cal_of(spec)?;
    let vs = l.omega.verb(get_str(spec, "verb").unwrap_or("")).ok_or("classifier: unknown verb")?.clone();
    let values = match &dim {
        Dim::Cat { values, .. } => values.clone(),
        _ => vec![],
    };
    let mut out: Vec<(usize, Value)> = vec![];
    for (_, g) in &groups {
        let a: Vec<usize> = g.iter().filter(|(_, m)| m.in_grant).map(|(i, _)| *i).collect();
        if a.is_empty() {
            continue;
        }
        let bad: Vec<usize> = g.iter().filter(|(t, m)| !m.in_grant && values[*t].kind == "exact").map(|(t, _)| *t).collect();
        let mut worst = 0.0f64;
        for t in bad {
            worst = js_max(worst, js_min(1.0, sum_gbar(&lab, &gb, &dim, &a, t)?));
        }
        if worst > gamma_max {
            for p in &a {
                let cell = &g.iter().find(|(i, _)| i == p).unwrap().1.cell;
                let flat = encode_cell(&vs, cell);
                out.push((flat, obj(vec![("verb", get(spec, "verb").cloned().unwrap_or(Value::Null)), ("cell", jarr_usize(cell)), ("flat", jn(flat as f64))])));
            }
        }
    }
    out.sort_by_key(|x| x.0);
    Ok(Value::Array(out.into_iter().map(|x| x.1).collect()))
}
