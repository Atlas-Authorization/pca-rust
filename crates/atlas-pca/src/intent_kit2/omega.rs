//! The intent outcome space (omega): typed dimensions derived from the grant vocabulary, cells, representatives, the workload and harm
//! measures (the default harm model), a seeded generator, the derivation from policies + slots, regions, slots and the policy
//! plumbing (an outcome as the analyzer's concrete action; the real evaluator as an admission oracle).
//! Omegas, verb spaces and dimensions are plain JSON; the typed [`Omega`] / [`Vs`] / [`Dim`] are parsed views of them.
//!
//! shortcut: only the default harm model is ported (a caller-supplied harm model is a host function the corpus cannot carry);
//! numbers are doubles throughout (the reference's only number type), so an integer beyond 2^53 is its nearest double.
use super::util::*;
use crate::intent_kit::omega as base;
use serde_json::{json, Map, Value};

pub const OTHER: &str = "\u{22a5}";
pub const ANY_RESOURCE: &str = "resource:any";

// ---- dimensions --------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CatVal {
    pub kind: String,
    pub value: String,
}

impl CatVal {
    pub fn to_json(&self) -> Value {
        json!({"kind": self.kind, "value": self.value})
    }
}

#[derive(Clone, Debug)]
pub struct Dim {
    pub is_num: bool,
    pub path: String,
    pub lo: f64,
    pub hi: f64,
    pub cuts: Vec<f64>,
    pub dist: Option<String>,
    pub values: Vec<CatVal>,
    pub cells: Vec<(f64, f64)>,
}

fn cells_of(lo: f64, hi: f64, cuts: &[f64]) -> Vec<(f64, f64)> {
    let mut out = vec![];
    let mut cur = lo;
    for &c in cuts {
        if c < lo || c > hi {
            continue;
        }
        if cur <= c - 1.0 {
            out.push((cur, c - 1.0));
        }
        out.push((c, c));
        cur = c + 1.0;
    }
    if cur <= hi {
        out.push((cur, hi));
    }
    out
}

pub fn parse_cat_values(v: &Value) -> R<Vec<CatVal>> {
    let a = v.as_array().ok_or("a categorical dimension needs values")?;
    let mut out = vec![];
    for x in a {
        let kind = x["kind"].as_str().ok_or("a categorical value needs a kind")?;
        let value = x["value"].as_str().ok_or("a categorical value needs a string value")?;
        out.push(CatVal { kind: kind.to_string(), value: value.to_string() });
    }
    Ok(out)
}

impl Dim {
    pub fn parse(v: &Value) -> R<Dim> {
        let path = v["path"].as_str().unwrap_or("").to_string();
        if v["kind"].as_str() == Some("num") {
            let lo = fnum(&v["lo"]).ok_or("a numeric dimension needs a numeric lo")?;
            let hi = fnum(&v["hi"]).ok_or("a numeric dimension needs a numeric hi")?;
            let mut cuts = vec![];
            for c in v["cuts"].as_array().ok_or("a numeric dimension needs cuts")? {
                cuts.push(fnum(c).ok_or("a cut must be a number")?);
            }
            let dist = v["dist"].as_str().map(String::from);
            let cells = cells_of(lo, hi, &cuts);
            Ok(Dim { is_num: true, path, lo, hi, cuts, dist, values: vec![], cells })
        } else {
            let values = parse_cat_values(&v["values"])?;
            Ok(Dim { is_num: false, path, lo: 0.0, hi: 0.0, cuts: vec![], dist: None, values, cells: vec![] })
        }
    }

    pub fn ncells(&self) -> usize {
        if self.is_num {
            self.cells.len()
        } else {
            self.values.len()
        }
    }

    fn loguniform(&self) -> bool {
        self.is_num && self.dist.as_deref() == Some("loguniform") && self.lo >= 0.0
    }

    /// Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > other), -1 when none.
    pub fn cat_cell_of(&self, s: &str) -> i64 {
        let mut best: i64 = -1;
        let mut best_len: i64 = -1;
        for (i, v) in self.values.iter().enumerate() {
            if v.kind == "exact" && v.value == s {
                return i as i64;
            }
            if v.kind == "prefix" && s.starts_with(&v.value) && (u16len(&v.value) as i64) > best_len {
                best = i as i64;
                best_len = u16len(&v.value) as i64;
            }
        }
        if best >= 0 {
            return best;
        }
        for (i, v) in self.values.iter().enumerate() {
            if v.kind == "other" {
                return i as i64;
            }
        }
        -1
    }

    /// Which cell a concrete value falls in, -1 outside the dimension's domain / type.
    pub fn cell_of_value(&self, x: &Value) -> i64 {
        if self.is_num {
            let f = match fnum(x) {
                Some(f) if f.is_finite() => f,
                _ => return -1,
            };
            for (i, (lo, hi)) in self.cells.iter().enumerate() {
                if f >= *lo && f <= *hi {
                    return i as i64;
                }
            }
            return -1;
        }
        match x.as_str() {
            Some(s) => self.cat_cell_of(s),
            None => -1,
        }
    }

    pub fn cat_rep(&self, i: usize) -> R<String> {
        let v = self.values.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
        if v.kind == "exact" {
            return Ok(v.value.clone());
        }
        let base = if v.kind == "prefix" { format!("{}x", v.value) } else { "other".to_string() };
        for k in 0..64 {
            let s = if k == 0 { base.clone() } else { format!("{base}{k}") };
            if self.cat_cell_of(&s) == i as i64 {
                return Ok(s);
            }
        }
        Ok(base)
    }

    pub fn num_rep(&self, i: usize) -> R<f64> {
        let (lo, hi) = *self.cells.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
        Ok(if i > 0 { lo } else { hi })
    }

    pub fn rep_value(&self, i: usize) -> R<Value> {
        if self.is_num {
            Ok(num(self.num_rep(i)?))
        } else {
            Ok(Value::String(self.cat_rep(i)?))
        }
    }

    pub fn cat_values_json(&self) -> Value {
        Value::Array(self.values.iter().map(CatVal::to_json).collect())
    }
}

// ---- verb spaces and omegas ----------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Vs {
    pub verb: String,
    pub reversibility: Option<String>,
    pub weight: Option<f64>,
    pub dims: Vec<Dim>,
}

impl Vs {
    pub fn parse(v: &Value) -> R<Vs> {
        let mut dims = vec![];
        for d in v["dims"].as_array().ok_or("a verb space needs dims")? {
            dims.push(Dim::parse(d)?);
        }
        Ok(Vs {
            verb: v["verb"].as_str().unwrap_or("").to_string(),
            reversibility: v["reversibility"].as_str().map(String::from),
            weight: fnum(&v["weight"]),
            dims,
        })
    }

    pub fn cell_count(&self) -> usize {
        self.dims.iter().map(Dim::ncells).product()
    }

    pub fn decode_cell(&self, flat: f64) -> Vec<usize> {
        let mut idx = vec![0usize; self.dims.len()];
        let mut flat = flat;
        for i in (0..self.dims.len()).rev() {
            let n = self.dims[i].ncells() as f64;
            idx[i] = flat.rem_euclid(n) as usize;
            flat = (flat / n).floor();
        }
        idx
    }

    pub fn encode_cell(&self, idx: &[f64]) -> R<f64> {
        let mut flat = 0.0;
        for (i, d) in self.dims.iter().enumerate() {
            let x = idx.get(i).ok_or("cell index has too few coordinates")?;
            flat = flat * d.ncells() as f64 + x;
        }
        Ok(flat)
    }

    pub fn cell_of(&self, o: &Value) -> Option<Vec<usize>> {
        let mut idx = vec![];
        for d in &self.dims {
            let i = d.cell_of_value(&o["values"][d.path.as_str()]);
            if i < 0 {
                return None;
            }
            idx.push(i as usize);
        }
        Some(idx)
    }

    pub fn cell_rep(&self, idx: &[usize]) -> R<Value> {
        let mut values = Map::new();
        for (i, d) in self.dims.iter().enumerate() {
            let k = *idx.get(i).ok_or("cell index has too few coordinates")?;
            values.insert(d.path.clone(), d.rep_value(k)?);
        }
        Ok(json!({"verb": self.verb, "values": Value::Object(values)}))
    }
}

#[derive(Clone, Debug)]
pub struct Omega {
    pub verbs: Vec<Vs>,
    pub approximate: Vec<String>,
}

impl Omega {
    pub fn parse(v: &Value) -> R<Omega> {
        let mut verbs = vec![];
        for x in v["verbs"].as_array().ok_or("omega needs verbs")? {
            verbs.push(Vs::parse(x)?);
        }
        let approximate = v["approximate"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        Ok(Omega { verbs, approximate })
    }

    pub fn vs_of(&self, verb: &str) -> Option<&Vs> {
        self.verbs.iter().find(|v| v.verb == verb)
    }
}

// ---- workload and harm (the default harm model): the shared implementation in `intent_kit::omega` ------------------------------

impl CatVal {
    fn to_core(&self) -> base::CatVal {
        base::CatVal { kind: self.kind.clone(), value: self.value.clone() }
    }
}

impl Dim {
    /// The typed dimension of the shared implementation.
    pub fn to_core(&self) -> base::Dim {
        if self.is_num {
            base::num_dim(&self.path, self.lo, self.hi, self.cuts.clone(), self.dist.clone())
        } else {
            base::Dim::Cat { path: self.path.clone(), values: self.values.iter().map(CatVal::to_core).collect() }
        }
    }
}

impl Vs {
    /// The typed verb space of the shared implementation (a missing weight becomes NaN; the entry points below refuse it first).
    pub fn to_core(&self) -> base::VerbSpace {
        base::VerbSpace {
            verb: self.verb.clone(),
            reversibility: self.reversibility.clone(),
            weight: self.weight.unwrap_or(f64::NAN),
            dims: self.dims.iter().map(Dim::to_core).collect(),
        }
    }

    pub(crate) fn weight_of(&self) -> R<f64> {
        self.weight.ok_or_else(|| "verb space has no weight".to_string())
    }
}

impl Omega {
    /// The typed outcome space of the shared implementation (the flagship's single design).
    pub fn to_core(&self) -> base::Omega {
        base::Omega { verbs: self.verbs.iter().map(Vs::to_core).collect(), approximate: self.approximate.clone() }
    }
}

pub fn verb_harm(vs: &Vs) -> f64 {
    base::harm_verb(&vs.to_core())
}

/// Sum of the dimension's law over the integers a..b (0 for an empty interval).
pub fn interval_weight(d: &Dim, a: f64, b: f64) -> f64 {
    base::interval_weight(d.loguniform(), a, b)
}

pub fn harm_max(omega: &Omega) -> R<f64> {
    base::harm_max(&omega.to_core())
}

/// (mu_d(cell), E[g_d | cell]) for one dimension cell; categorical values are uniform.
pub fn dim_cell_stats(d: &Dim, i: usize) -> R<(f64, f64)> {
    base::dim_cell_stats(&d.to_core(), i)
}

pub fn cell_stats(vs: &Vs, idx: &[usize]) -> R<(f64, f64)> {
    vs.weight_of()?;
    if idx.len() < vs.dims.len() {
        // the reference reads every coordinate; a short index is refused after the dimensions it does cover
        for (k, d) in vs.dims.iter().enumerate().take(idx.len()) {
            dim_cell_stats(d, idx[k])?;
        }
        return Err("cell index has too few coordinates".into());
    }
    base::cell_stats(&vs.to_core(), idx)
}

pub fn harm_of(vs: &Vs, o: &Value) -> f64 {
    base::harm_of(&vs.to_core(), o)
}

/// The seeded generator (mulberry32), bit-identical to the reference.
pub struct Rng {
    core: base::Rng,
}

impl Rng {
    pub fn new(seed: f64) -> Rng {
        Rng { core: base::Rng::new(seed) }
    }
    pub fn next_f64(&mut self) -> f64 {
        self.core.next()
    }
}

/// Draw an outcome from the workload: (index of the verb space, outcome).
pub fn sample_outcome(omega: &Omega, rng: &mut Rng) -> R<(usize, Value)> {
    if omega.verbs.is_empty() {
        let _ = rng.next_f64();
        return Err("omega has no verbs".into());
    }
    for vs in &omega.verbs {
        vs.weight_of()?;
    }
    let typed = omega.to_core();
    let (vs, o) = base::sample_outcome(&typed, &mut rng.core)?;
    let which = typed.verbs.iter().position(|x| std::ptr::eq(x, vs)).ok_or("sampled verb space not found")?;
    Ok((which, o))
}

// ---- policy plumbing ----------------------------------------------------------------------------------------------------------

/// `{predicates, caveats}`: a non-array member counts as empty.
pub fn normalize_policy(p: &Value) -> Value {
    let preds = member(p, "predicates").filter(|x| x.is_array()).cloned().unwrap_or_else(|| json!([]));
    let cavs = member(p, "caveats").filter(|x| x.is_array()).cloned().unwrap_or_else(|| json!([]));
    json!({"predicates": preds, "caveats": cavs})
}

/// [`normalize_policy`] as the reference's exported function (`'caveats' in p` throws for a truthy value that is not an object).
pub fn normalize_policy_checked(p: &Value) -> Result<Value, String> {
    // `Array.isArray(p?.predicates)` never throws, but `p && 'caveats' in p` does for a truthy non-object (a string, a number, true):
    // null and the other falsy values short-circuit and normalize to the empty policy
    if p.is_object() || p.is_array() || !crate::oauth::truthy(Some(p)) {
        Ok(normalize_policy(p))
    } else {
        Err(format!("Cannot use 'in' operator to search for 'caveats' in {}", crate::intent_v2::js_value_string(p)))
    }
}

fn set_path(root: &mut Map<String, Value>, segs: &[&str], value: Value) {
    let mut cur = root;
    for k in &segs[..segs.len() - 1] {
        let replace = !matches!(cur.get(*k), Some(Value::Object(_)));
        if replace {
            cur.insert((*k).to_string(), Value::Object(Map::new()));
        }
        cur = match cur.get_mut(*k) {
            Some(Value::Object(m)) => m,
            _ => return,
        };
    }
    cur.insert(segs[segs.len() - 1].to_string(), value);
}

/// The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the verb space).
pub fn outcome_to_action(rev: Option<&str>, o: &Value) -> R<Value> {
    let mut params = Map::new();
    let mut env = Map::new();
    let mut subject = Map::new();
    let mut resource = ANY_RESOURCE.to_string();
    if let Some(vals) = o["values"].as_object() {
        for (path, value) in vals {
            let segs: Vec<&str> = path.split('.').collect();
            if path == "action.resource" {
                resource = js_str(value);
            } else if segs[0] == "action" && segs.len() > 2 && segs[1] == "params" {
                set_path(&mut params, &segs[2..], value.clone());
            } else if segs[0] == "env" && segs.len() > 1 {
                set_path(&mut env, &segs[1..], value.clone());
            } else if segs[0] == "subject" && segs.len() > 1 {
                set_path(&mut subject, &segs[1..], value.clone());
            }
        }
    }
    let verb = o.get("verb").ok_or("outcome has no verb")?.clone();
    let mut a = Map::new();
    a.insert("verb".into(), verb);
    a.insert("resource".into(), Value::String(resource));
    a.insert("params".into(), Value::Object(params));
    if let Some(r) = rev {
        a.insert("reversibilityClass".into(), Value::String(r.to_string()));
    }
    if !env.is_empty() {
        a.insert("env".into(), Value::Object(env));
    }
    if !subject.is_empty() {
        a.insert("subject".into(), Value::Object(subject));
    }
    Ok(Value::Object(a))
}

/// A compiled admission oracle for one policy (compile once, query many times).
pub struct Admitter {
    model: Value,
}

impl Admitter {
    pub fn new(policy: &Value) -> R<Admitter> {
        Ok(Admitter { model: crate::analyzer::to_model(policy)? })
    }

    pub fn admits(&self, rev: Option<&str>, o: &Value) -> R<bool> {
        let action = outcome_to_action(rev, o)?;
        Ok(crate::analyzer::decide_action_model(&self.model, &action)? != "deny")
    }
}

// ---- slots ---------------------------------------------------------------------------------------------------------------------

fn slot_conds(sc: &Value) -> Vec<Value> {
    let mut out = vec![];
    let p = sc["path"].clone();
    if let Some(min) = nn(sc, "min") {
        out.push(json!({"field": p, "op": "gte", "value": min}));
    }
    if let Some(max) = nn(sc, "max") {
        out.push(json!({"field": p, "op": "lte", "value": max}));
    }
    let mut any_of: Vec<Value> = vec![];
    if let Some(one_of) = member(sc, "oneOf").filter(|x| truthy(x)) {
        any_of.push(json!({"field": p, "op": "in", "value": one_of}));
    }
    if let Some(a) = member(sc, "prefixOneOf").and_then(Value::as_array) {
        for x in a {
            any_of.push(json!({"field": p, "op": "prefix", "value": x}));
        }
    }
    if any_of.len() == 1 {
        out.push(any_of.remove(0));
    } else if any_of.len() > 1 {
        out.push(json!({"any_of": any_of}));
    }
    if let Some(none_of) = member(sc, "noneOf").filter(|x| truthy(x)) {
        out.push(json!({"field": p, "op": "nin", "value": none_of}));
    }
    out
}

/// One predicate per slot verb.
pub fn slots_to_policy(slots: &Value) -> R<Value> {
    let mut preds = vec![];
    for verb in arr(&slots["verbs"], "slots.verbs")? {
        let mut wh: Vec<Value> = vec![];
        for c in arr(&slots["constraints"], "slots.constraints")? {
            if nn(c, "verb").is_none() || nn(c, "verb") == Some(verb) {
                wh.extend(slot_conds(c));
            }
        }
        let mut pr = Map::new();
        pr.insert("verb".into(), verb.clone());
        pr.insert("resource".into(), json!("*"));
        if !wh.is_empty() {
            pr.insert("where".into(), Value::Array(wh));
        }
        preds.push(Value::Object(pr));
    }
    Ok(json!({"predicates": preds, "caveats": []}))
}

// ---- regions -------------------------------------------------------------------------------------------------------------------

pub fn region_of_cell(vs: &Vs, idx: &[usize]) -> R<Value> {
    let mut dims = Map::new();
    for (k, d) in vs.dims.iter().enumerate() {
        let i = *idx.get(k).ok_or("cell index has too few coordinates")?;
        if d.is_num {
            let (lo, hi) = *d.cells.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
            dims.insert(d.path.clone(), json!({"kind": "num", "lo": num(lo), "hi": num(hi)}));
        } else {
            dims.insert(d.path.clone(), json!({"kind": "cat", "values": d.cat_values_json(), "cells": [i]}));
        }
    }
    Ok(json!({"verb": vs.verb, "dims": Value::Object(dims)}))
}

/// `part` is `{lo, hi}` (numeric) or `{cells}` (categorical).
pub fn restrict_region(r: &Value, d: &Dim, part: &Value) -> R<Value> {
    let mut dims = r["dims"].as_object().cloned().unwrap_or_default();
    if d.is_num && part.get("lo").is_some() {
        dims.insert(d.path.clone(), json!({"kind": "num", "lo": part["lo"], "hi": part["hi"]}));
    } else if !d.is_num && part.get("cells").is_some() {
        dims.insert(d.path.clone(), json!({"kind": "cat", "values": d.cat_values_json(), "cells": part["cells"]}));
    } else {
        return Err(format!("restrictRegion: part does not match the kind of {}", d.path));
    }
    Ok(json!({"verb": r["verb"], "dims": Value::Object(dims)}))
}

fn ref_dim(path: &str, rd: &Value) -> R<Dim> {
    Ok(Dim { is_num: false, path: path.to_string(), lo: 0.0, hi: 0.0, cuts: vec![], dist: None, values: parse_cat_values(&rd["values"])?, cells: vec![] })
}

fn cells_set(rd: &Value) -> Vec<f64> {
    rd["cells"].as_array().map(|a| a.iter().filter_map(fnum).collect()).unwrap_or_default()
}

/// The cells of `d` covered by the region dimension: "inner" (wholly inside) or "outer" (meeting it).
pub fn dim_cells_in(d: &Dim, rd: Option<&Value>, mode: &str) -> R<Vec<usize>> {
    let n = d.ncells();
    let all: Vec<usize> = (0..n).collect();
    let rd = match rd {
        Some(r) if truthy(r) => r,
        _ => return Ok(all),
    };
    if d.is_num {
        if rd["kind"].as_str() != Some("num") {
            return Err(format!("region: {} is numeric in \u{3a9} but categorical in the region", d.path));
        }
        let rlo = fnum(&rd["lo"]).ok_or("region lo")?;
        let rhi = fnum(&rd["hi"]).ok_or("region hi")?;
        let mut out = vec![];
        for (i, (lo, hi)) in d.cells.iter().enumerate() {
            let ok = if mode == "inner" { *lo >= rlo && *hi <= rhi } else { *hi >= rlo && *lo <= rhi };
            if ok {
                out.push(i);
            }
        }
        return Ok(out);
    }
    if rd["kind"].as_str() != Some("cat") {
        return Err(format!("region: {} is categorical in \u{3a9} but numeric in the region", d.path));
    }
    let rf = ref_dim(&d.path, rd)?;
    let in_set = cells_set(rd);
    let mut out = vec![];
    for i in 0..n {
        let c = rf.cat_cell_of(&d.cat_rep(i)?);
        if in_set.contains(&(c as f64)) {
            out.push(i);
        }
    }
    Ok(out)
}

/// Flat cell indices of `vs` covered by the region (row-major, last dimension fastest); refuses a restriction the space lacks.
pub fn region_cells(vs: &Vs, r: &Value, mode: &str) -> R<Vec<usize>> {
    if r["verb"].as_str() != Some(vs.verb.as_str()) {
        return Err(format!("region: verb {} does not match {}", js_str(&r["verb"]), vs.verb));
    }
    let rdims = r["dims"].as_object().ok_or("region has no dims")?;
    for p in rdims.keys() {
        if !vs.dims.iter().any(|d| &d.path == p) {
            return Err(format!("region: restricts {p}, which \u{3a9} has no dimension for"));
        }
    }
    let mut per: Vec<Vec<usize>> = vec![];
    for d in &vs.dims {
        per.push(dim_cells_in(d, rdims.get(&d.path), mode)?);
    }
    if per.iter().any(|x| x.is_empty()) {
        return Ok(vec![]);
    }
    let mut acc: Vec<usize> = vec![0];
    for (k, cells) in per.iter().enumerate() {
        let size = vs.dims[k].ncells();
        let mut nxt = Vec::with_capacity(acc.len() * cells.len());
        for f in &acc {
            for c in cells {
                nxt.push(f * size + c);
            }
        }
        acc = nxt;
    }
    Ok(acc)
}

pub fn value_in_region_dim(path: &str, rd: &Value, x: &Value) -> R<bool> {
    if rd["kind"].as_str() == Some("num") {
        let (lo, hi) = (fnum(&rd["lo"]).ok_or("region lo")?, fnum(&rd["hi"]).ok_or("region hi")?);
        return Ok(fnum(x).is_some_and(|f| f >= lo && f <= hi));
    }
    match x.as_str() {
        Some(s) => {
            let c = ref_dim(path, rd)?.cat_cell_of(s);
            Ok(cells_set(rd).contains(&(c as f64)))
        }
        None => Ok(false),
    }
}

// ---- derivation from policies + slots ------------------------------------------------------------------------------------------------

struct Lits {
    nums: Vec<f64>,
    exacts: Vec<String>,
    prefixes: Vec<String>,
}

fn push_uniq<T: PartialEq>(v: &mut Vec<T>, x: T) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn lits<'a>(m: &'a mut Vec<(String, Lits)>, path: &str) -> &'a mut Lits {
    let pos = m.iter().position(|(p, _)| p == path);
    let i = match pos {
        Some(i) => i,
        None => {
            m.push((path.to_string(), Lits { nums: vec![], exacts: vec![], prefixes: vec![] }));
            m.len() - 1
        }
    };
    &mut m[i].1
}

fn add_num(f: &mut Lits, x: &Value) {
    if let Some(v) = fnum(x) {
        if v.is_finite() {
            push_uniq(&mut f.nums, v.floor() + 0.0);
            push_uniq(&mut f.nums, v.ceil() + 0.0);
        }
    }
}

fn collect_cond(c: &Value, m: &mut Vec<(String, Lits)>, approx: &mut Vec<String>) {
    if !c.is_object() {
        return;
    }
    if crate::predicates::is_group_condition(c) {
        if let Some(a) = c["all_of"].as_array() {
            for x in a {
                collect_cond(x, m, approx);
            }
        } else if let Some(a) = c["any_of"].as_array() {
            for x in a {
                collect_cond(x, m, approx);
            }
        } else if c.get("not").is_some() {
            collect_cond(&c["not"], m, approx);
        }
        return;
    }
    let field = match c["field"].as_str() {
        Some(f) => f,
        None => return,
    };
    let op = c["op"].as_str();
    if nn(c, "ref").is_some() {
        push_uniq(approx, format!("cross-field ref on {field}"));
    }
    if let Some(o) = op {
        if matches!(o, "like" | "matches" | "is_a" | "member_of") {
            push_uniq(approx, format!("{o} on {field}"));
        }
    }
    if op == Some("exists") {
        lits(m, field);
        return;
    }
    let f = lits(m, field);
    let value = &c["value"];
    let vals: Vec<&Value> = match value.as_array() {
        Some(a) => a.iter().collect(),
        None => vec![value],
    };
    for v in vals {
        if is_number(v) {
            add_num(f, v);
        } else if let Some(s) = v.as_str() {
            if op == Some("prefix") {
                push_uniq(&mut f.prefixes, s.to_string());
            } else {
                push_uniq(&mut f.exacts, s.to_string());
            }
        }
    }
}

fn add_resource(r: &Value, m: &mut Vec<(String, Lits)>, approx: &mut Vec<String>) {
    let r = match r.as_str() {
        Some(r) if r != "*" => r,
        _ => return,
    };
    if r.starts_with("re:") {
        push_uniq(approx, "re: resource matcher".to_string());
        return;
    }
    let f = lits(m, "action.resource");
    match r.strip_suffix('*') {
        Some(p) => push_uniq(&mut f.prefixes, p.to_string()),
        None => push_uniq(&mut f.exacts, r.to_string()),
    }
}

enum VerbsOf {
    Star,
    List(Vec<String>),
}

fn verbs_of(p: &Value) -> VerbsOf {
    match &p["verb"] {
        Value::String(s) => {
            if s == "*" {
                VerbsOf::Star
            } else {
                VerbsOf::List(vec![s.clone()])
            }
        }
        Value::Array(a) => {
            if a.iter().any(|x| x.as_str() == Some("*")) {
                VerbsOf::Star
            } else {
                VerbsOf::List(a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            }
        }
        _ => VerbsOf::List(vec![]),
    }
}

fn default_domain(path: &str) -> Option<Value> {
    match path {
        "action.params.amount" => Some(json!({"lo": 0, "hi": 100000, "dist": "loguniform"})),
        "env.hour" => Some(json!({"lo": 0, "hi": 23, "dist": "uniform"})),
        "action.params.count" => Some(json!({"lo": 0, "hi": 1000, "dist": "loguniform"})),
        _ => None,
    }
}

/// Derive the outcome space from the vocabulary of the policies and the intent slots. Wildcard verbs expand to the catalog verbs of
/// every connector that appears anywhere (or the whole catalog when none does).
pub fn derive_omega(opts: &Value) -> R<Value> {
    let catalog = crate::facade::builtin_catalog();
    // the catalogue by verb (a later entry overrides an earlier one), in catalogue order
    let mut by_verb: Vec<(String, String, String)> = vec![];
    for s in &catalog {
        match by_verb.iter().position(|x| x.0 == s.verb) {
            Some(i) => by_verb[i] = (s.verb.clone(), s.connector.clone(), s.reversibility.clone()),
            None => by_verb.push((s.verb.clone(), s.connector.clone(), s.reversibility.clone())),
        }
    }
    let mut approx: Vec<String> = vec![];
    let mut preds: Vec<Value> = vec![];
    for p in arr(&opts["policies"], "policies")? {
        if let Some(a) = normalize_policy(p)["predicates"].as_array() {
            preds.extend(a.iter().cloned());
        }
    }
    let slots = &opts["slots"];
    let mut explicit: Vec<String> = vec![];
    if let Some(a) = member(opts, "extraVerbs").and_then(Value::as_array) {
        for v in a {
            push_uniq(&mut explicit, text(v, "extraVerbs entry")?.to_string());
        }
    }
    let mut wildcard = false;
    for p in &preds {
        match verbs_of(p) {
            VerbsOf::Star => wildcard = true,
            VerbsOf::List(l) => {
                for v in l {
                    push_uniq(&mut explicit, v);
                }
            }
        }
    }
    if let Some(a) = member(slots, "verbs").and_then(Value::as_array) {
        for v in a {
            push_uniq(&mut explicit, text(v, "slots.verbs entry")?.to_string());
        }
    }
    if wildcard {
        let mut connectors: Vec<String> = vec![];
        for v in &explicit {
            push_uniq(&mut connectors, v.split('.').next().unwrap_or("").to_string());
        }
        for s in &by_verb {
            if connectors.is_empty() || connectors.contains(&s.1) {
                push_uniq(&mut explicit, s.0.clone());
            }
        }
    }
    let domains = &opts["domains"];
    let mut verbs_sorted = explicit.clone();
    sort_u16(&mut verbs_sorted);
    let mut out: Vec<Value> = vec![];
    for verb in &verbs_sorted {
        let mut m: Vec<(String, Lits)> = vec![];
        for p in &preds {
            if let VerbsOf::List(l) = verbs_of(p) {
                if !l.contains(verb) {
                    continue;
                }
            }
            add_resource(&p["resource"], &mut m, &mut approx);
            if let Some(w) = p["where"].as_array() {
                for c in w {
                    collect_cond(c, &mut m, &mut approx);
                }
            }
        }
        if let Some(cs) = member(slots, "constraints").and_then(Value::as_array) {
            for sc in cs {
                if let Some(v) = nn(sc, "verb") {
                    if v.as_str() != Some(verb.as_str()) {
                        continue;
                    }
                }
                let path = text(&sc["path"], "slot constraint path")?;
                let f = lits(&mut m, path);
                if let Some(x) = nn(sc, "max") {
                    add_num(f, x);
                }
                if let Some(x) = nn(sc, "min") {
                    add_num(f, x);
                }
                for key in ["oneOf", "noneOf"] {
                    if let Some(a) = member(sc, key).and_then(Value::as_array) {
                        for x in a {
                            push_uniq(&mut f.exacts, text(x, "slot value")?.to_string());
                        }
                    }
                }
                if let Some(a) = member(sc, "prefixOneOf").and_then(Value::as_array) {
                    for x in a {
                        push_uniq(&mut f.prefixes, text(x, "slot prefix")?.to_string());
                    }
                }
            }
        }
        let mut paths: Vec<String> = m.iter().map(|x| x.0.clone()).collect();
        sort_u16(&mut paths);
        let mut dims: Vec<Value> = vec![];
        for path in &paths {
            let f = &m.iter().find(|x| &x.0 == path).ok_or("lost a path")?.1;
            let user = member(domains, path).filter(|x| truthy(x)).cloned();
            let dom: Option<Value> = user.or_else(|| default_domain(path));
            if !f.nums.is_empty() || (f.exacts.is_empty() && f.prefixes.is_empty() && default_domain(path).is_some()) {
                let mut cuts = f.nums.clone();
                cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let max_cut = cuts.last().copied().unwrap_or(0.0);
                let min_cut = cuts.first().copied().unwrap_or(0.0);
                let dget = |k: &str| -> R<Option<f64>> {
                    match dom.as_ref().and_then(|d| nn(d, k)) {
                        Some(v) => Ok(Some(fnum(v).ok_or_else(|| format!("domain {k} must be a number"))?)),
                        None => Ok(None),
                    }
                };
                let lo = match dget("lo")? {
                    Some(v) => v,
                    None => 0f64.min(min_cut - 1.0),
                };
                let hi = match dget("hi")? {
                    Some(v) => v,
                    None => 10f64.max(2.0 * max_cut).max(max_cut + 10.0),
                };
                let dist = match dom.as_ref().and_then(|d| nn(d, "dist")) {
                    Some(v) => v.clone(),
                    None => json!(if lo >= 0.0 { "loguniform" } else { "uniform" }),
                };
                let kept: Vec<Value> = cuts.iter().filter(|c| lo <= **c && **c <= hi).map(|c| num(*c)).collect();
                dims.push(json!({"kind": "num", "path": path, "lo": num(lo), "hi": num(hi), "cuts": kept, "dist": dist}));
            } else {
                let mut ex = f.exacts.clone();
                sort_u16(&mut ex);
                let mut pre = f.prefixes.clone();
                sort_u16(&mut pre);
                let mut values: Vec<Value> = ex.iter().map(|v| json!({"kind": "exact", "value": v})).collect();
                values.extend(pre.iter().map(|v| json!({"kind": "prefix", "value": v})));
                values.push(json!({"kind": "other", "value": OTHER}));
                dims.push(json!({"kind": "cat", "path": path, "values": values}));
            }
        }
        let rev = by_verb.iter().find(|x| &x.0 == verb).map(|x| x.2.clone()).unwrap_or_else(|| "irreversible".to_string());
        out.push(json!({"verb": verb, "reversibility": rev, "weight": 0, "dims": dims}));
    }
    let n = out.len() as f64;
    for v in out.iter_mut() {
        v["weight"] = num(1.0 / n);
    }
    sort_u16(&mut approx);
    Ok(json!({"v": 1, "verbs": out, "approximate": approx}))
}
