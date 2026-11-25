//! Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision lists), the
//! conservative grant it implies, the next question, the audit round and the synthesis of the grant as predicates. The posterior
//! arithmetic keeps the reference's operation order.
use super::omega::*;
use super::policy::*;
use super::region::*;
use super::*;
use crate::wallet_omega::fdlibm;
use serde_json::{Map, Value};
use std::collections::HashMap;

const ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

fn is_integer_f(x: f64) -> bool {
    x.is_finite() && x == x.floor()
}

pub(crate) fn or1(x: f64) -> f64 {
    if x == x && x != 0.0 {
        x
    } else {
        1.0
    }
}

/// A hypothesis class.
#[derive(Clone, Debug)]
pub enum Hc {
    Box,
    Union { k: usize, decay: f64 },
    DList { max_rules: usize, atomic: bool, decay: f64 },
}

impl Hc {
    pub fn kind(&self) -> &'static str {
        match self {
            Hc::Box => "box",
            Hc::Union { .. } => "union",
            Hc::DList { .. } => "decision-list",
        }
    }
    pub fn decay(&self) -> f64 {
        match self {
            Hc::Box => 1.0,
            Hc::Union { decay, .. } | Hc::DList { decay, .. } => *decay,
        }
    }
    /// Parse a class spec (`None` / null = the box class).
    pub fn from_json(h: Option<&Value>) -> R<Hc> {
        let Some(h) = h.filter(|h| !h.is_null()) else { return Ok(Hc::Box) };
        let decay = match opt(h, "decay") {
            None => 0.25,
            Some(d) => num(d).ok_or("pca-intent: decay must be a number")?,
        };
        match get_str(h, "kind") {
            Some("box") => Ok(Hc::Box),
            Some("union") => match get(h, "k").and_then(num) {
                Some(k) if is_integer_f(k) && k >= 1.0 => Ok(Hc::Union { k: k as usize, decay }),
                _ => Err("pca-intent: union class needs an integer k \u{2265} 1".into()),
            },
            Some("decision-list") => {
                let mr = match get(h, "maxRules").and_then(num) {
                    Some(m) if is_integer_f(m) && m >= 1.0 => m as usize,
                    _ => return Err("pca-intent: decision-list class needs an integer maxRules \u{2265} 1".into()),
                };
                let atomic = match opt(h, "conditions").map(|c| c.as_str()) {
                    None | Some(Some("box")) => false,
                    Some(Some("atomic")) => true,
                    _ => return Err("pca-intent: decision-list conditions must be 'box' or 'atomic'".into()),
                };
                Ok(Hc::DList { max_rules: mr, atomic, decay })
            }
            _ => Err("pca-intent: unknown hypothesis class".into()),
        }
    }
    /// The canonical name of the class (stored in the Intent Map).
    pub fn name(&self) -> &'static str {
        match self {
            Hc::Box => "per-verb-box/v1",
            Hc::Union { .. } => "per-verb-union/v1",
            Hc::DList { atomic: true, .. } => "per-verb-decision-list/v1",
            Hc::DList { .. } => "per-verb-decision-list/v2",
        }
    }
}

/// The canonical name of a hypothesis class spec.
pub fn hypothesis_class_name(h: &Value) -> R<String> {
    let name = match get_str(h, "kind") {
        Some("box") => "per-verb-box/v1",
        Some("union") => "per-verb-union/v1",
        _ => {
            if opt(h, "conditions").and_then(Value::as_str).unwrap_or("box") == "atomic" {
                "per-verb-decision-list/v1"
            } else {
                "per-verb-decision-list/v2"
            }
        }
    };
    Ok(name.to_string())
}

thread_local! {
    static BIN_ENT_MEMO: std::cell::RefCell<std::collections::HashMap<u64, f64>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The binary entropy feeds the next-question argmax: `det_log2` (not libm) so the chosen question is identical on every platform and
/// language. The same argument recurs for every cell of a model, so the value is memoized (bounded: cleared when it grows past 4096).
fn bin_ent(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    BIN_ENT_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if let Some(v) = m.get(&p.to_bits()) {
            return *v;
        }
        let v = -(p * crate::detmath::det_log2(p) + (1.0 - p) * crate::detmath::det_log2(1.0 - p));
        if m.len() >= 4096 {
            m.clear();
        }
        m.insert(p.to_bits(), v);
        v
    })
}

fn range_choices(n: usize) -> Vec<(usize, usize)> {
    let mut v = vec![];
    for i in 0..n {
        for j in i..n {
            v.push((i, j));
        }
    }
    v
}

fn build_box_tables(vs: &VerbSpace, n_cells_d: &[usize]) -> R<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut contains = vec![];
    let mut n_choice = vec![];
    for (k, d) in vs.dims.iter().enumerate() {
        let n = n_cells_d[k];
        if d.is_num() {
            let ch = range_choices(n);
            let mut t = vec![0u8; ch.len() * n];
            for (c, (i, j)) in ch.iter().enumerate() {
                for x in *i..=*j {
                    t[c * n + x] = 1;
                }
            }
            n_choice.push(ch.len());
            contains.push(t);
        } else {
            if n > 20 {
                return Err(format!("pca-intent: categorical dimension {} has {} values (max 20 for exact enumeration)", d.path(), n));
            }
            let m = (1usize << n) - 1;
            let mut t = vec![0u8; m * n];
            for mask in 1..=m {
                for x in 0..n {
                    if mask & (1 << x) != 0 {
                        t[(mask - 1) * n + x] = 1;
                    }
                }
            }
            n_choice.push(m);
            contains.push(t);
        }
    }
    Ok((contains, n_choice))
}

fn box_masks(vs: &VerbSpace, n_cells: usize, cell_idx: &[usize], n_cells_d: &[usize], contains: &[Vec<u8>], n_choice: &[usize], cap: f64) -> R<Vec<Vec<u8>>> {
    let dn = vs.dims.len();
    let mut boxes = 1.0f64;
    for c in n_choice {
        boxes *= *c as f64;
    }
    if !(boxes <= cap) {
        return Err(format!("pca-intent: {} boxes for {} exceed the enumeration cap; coarsen the cuts", js_num(boxes), vs.verb));
    }
    let mut out = vec![];
    let mut cur = vec![0usize; dn];
    for _b in 0..(boxes as usize) {
        let mut mask = vec![0u8; n_cells];
        for c in 0..n_cells {
            let mut inside = true;
            let mut d = 0;
            while d < dn && inside {
                if contains[d][cur[d] * n_cells_d[d] + cell_idx[c * dn + d]] == 0 {
                    inside = false;
                }
                d += 1;
            }
            if inside {
                mask[c] = 1;
            }
        }
        out.push(mask);
        for d in (0..dn).rev() {
            cur[d] += 1;
            if cur[d] < n_choice[d] {
                break;
            }
            cur[d] = 0;
        }
    }
    Ok(out)
}

fn js_num(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

pub(crate) fn enumerate_unions(boxes: &[Vec<u8>], k: usize, cap: f64, verb: &str) -> R<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut sets: Vec<Vec<u8>> = vec![];
    let mut complexity: Vec<usize> = vec![];
    let mut frontier: Vec<Vec<u8>> = vec![];
    for b in boxes {
        if seen.contains_key(b) {
            continue;
        }
        seen.insert(b.clone(), sets.len());
        sets.push(b.clone());
        complexity.push(1);
        frontier.push(b.clone());
    }
    let mut work = 0.0f64;
    for level in 2..=k {
        let mut nxt: Vec<Vec<u8>> = vec![];
        for s in &frontier {
            for b in boxes {
                work += 1.0;
                if !(work <= cap) {
                    return Err(format!("pca-intent: the union-of-{k}-boxes class for {verb} exceeds the enumeration cap; coarsen the cuts or lower k"));
                }
                let u: Vec<u8> = s.iter().zip(b.iter()).map(|(x, y)| x | y).collect();
                if seen.contains_key(&u) {
                    continue;
                }
                seen.insert(u.clone(), sets.len());
                sets.push(u.clone());
                complexity.push(level);
                nxt.push(u);
            }
        }
        frontier = nxt;
    }
    Ok((sets, complexity))
}

fn atomic_tests(vs: &VerbSpace, n_cells: usize, cell_idx: &[usize], n_cells_d: &[usize]) -> Vec<Vec<u8>> {
    let dn = vs.dims.len();
    let mut tests: Vec<Vec<u8>> = vec![];
    let mut add = |k: usize, pred: &dyn Fn(usize) -> bool, tests: &mut Vec<Vec<u8>>| {
        let mut m = vec![0u8; n_cells];
        let (mut any, mut all) = (false, true);
        for c in 0..n_cells {
            if pred(cell_idx[c * dn + k]) {
                m[c] = 1;
                any = true;
            } else {
                all = false;
            }
        }
        if any && !all {
            tests.push(m);
        }
    };
    for (k, d) in vs.dims.iter().enumerate() {
        let n = n_cells_d[k];
        if d.is_num() {
            for i in 0..n.saturating_sub(1) {
                add(k, &|x| x <= i, &mut tests);
            }
            for i in 1..n {
                add(k, &|x| x >= i, &mut tests);
            }
            if n > 2 {
                for i in 1..n - 1 {
                    add(k, &|x| x == i, &mut tests);
                }
            }
        } else {
            for i in 0..n {
                add(k, &|x| x == i, &mut tests);
            }
        }
    }
    dedup_masks(tests)
}

pub(crate) fn dedup_masks(masks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut out = vec![];
    for t in masks {
        if seen.contains(&t) {
            continue;
        }
        seen.insert(t.clone());
        out.push(t);
    }
    out
}

fn enumerate_decision_lists(tests: &[Vec<u8>], n_cells: usize, l: usize, cap: f64, verb: &str) -> R<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut sets: Vec<Vec<u8>> = vec![];
    let mut complexity: Vec<usize> = vec![];
    let mut emit = |acc: &[u8], decided: &[u8], rules: usize, sets: &mut Vec<Vec<u8>>, complexity: &mut Vec<usize>| {
        for dflt in [0u8, 1u8] {
            let mut s = vec![0u8; n_cells];
            let mut any = false;
            for c in 0..n_cells {
                s[c] = if decided[c] != 0 { acc[c] } else { dflt };
                if s[c] != 0 {
                    any = true;
                }
            }
            if !any {
                continue;
            }
            if seen.contains_key(&s) {
                continue;
            }
            seen.insert(s.clone(), sets.len());
            sets.push(s);
            complexity.push(rules.max(1));
        }
    };
    let mut frontier: Vec<(Vec<u8>, Vec<u8>)> = vec![(vec![0u8; n_cells], vec![0u8; n_cells])]; // (decided, acc)
    emit(&frontier[0].1.clone(), &frontier[0].0.clone(), 0, &mut sets, &mut complexity);
    let mut work = 0.0f64;
    for depth in 1..=l {
        let mut index: HashMap<(Vec<u8>, Vec<u8>), usize> = HashMap::new();
        let mut states: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        for (st_decided, st_acc) in &frontier {
            for t in tests {
                for label in [0u8, 1u8] {
                    work += 1.0;
                    if !(work <= cap) {
                        return Err(format!("pca-intent: the decision-list class (\u{2264} {l} rules) for {verb} exceeds the enumeration cap"));
                    }
                    let mut decided = vec![0u8; n_cells];
                    let mut acc = vec![0u8; n_cells];
                    let mut fresh = false;
                    for c in 0..n_cells {
                        if st_decided[c] != 0 {
                            decided[c] = 1;
                            acc[c] = st_acc[c];
                        } else if t[c] != 0 {
                            decided[c] = 1;
                            acc[c] = label;
                            fresh = true;
                        }
                    }
                    if !fresh {
                        continue;
                    }
                    let key = (decided.clone(), acc.clone());
                    if index.contains_key(&key) {
                        continue;
                    }
                    index.insert(key, states.len());
                    states.push((decided, acc));
                }
            }
        }
        frontier = states;
        for (decided, acc) in &frontier {
            emit(acc, decided, depth, &mut sets, &mut complexity);
        }
    }
    Ok((sets, complexity))
}

/// The per-verb model of the posterior.
pub struct VerbModel {
    vs: VerbSpace,
    n_choice: Vec<usize>,
    contains: Vec<Vec<u8>>,
    n_cells_d: Vec<usize>,
    nh: usize,
    choice: Vec<usize>,
    member: Option<Vec<Vec<u8>>>,
    complexity: Option<Vec<usize>>,
    prior: Vec<f64>,
    w: Vec<f64>,
    err: Vec<f64>,
    n_cells: usize,
    cell_idx: Vec<usize>,
    mass: Vec<f64>,
    harm: Vec<f64>,
    p: Vec<f64>,
    veto: Vec<u8>,
    seen: Vec<u8>,
    dirty: bool,
}

impl VerbModel {
    fn build(vs: &VerbSpace, hc: &Hc, max_hyp: f64, max_enum: f64) -> R<VerbModel> {
        let dn = vs.dims.len();
        let n_cells_d: Vec<usize> = vs.dims.iter().map(Dim::cell_count).collect();
        let (contains, n_choice) = build_box_tables(vs, &n_cells_d)?;
        let n_cells = verb_cell_count(vs);
        let mut cell_idx = vec![0usize; n_cells * dn];
        let mut mass = vec![0.0f64; n_cells];
        let mut hm = vec![0.0f64; n_cells];
        for c in 0..n_cells {
            let idx = decode_cell(vs, c);
            for d in 0..dn {
                cell_idx[c * dn + d] = idx[d];
            }
            let (m, h) = cell_stats(vs, &idx)?;
            mass[c] = m;
            hm[c] = h;
        }
        let mut choice: Vec<usize> = vec![0];
        let mut member: Option<Vec<Vec<u8>>> = None;
        let mut complexity: Option<Vec<usize>> = None;
        let nh;
        match hc {
            Hc::Box => {
                let mut boxes = 1.0f64;
                for c in &n_choice {
                    boxes *= *c as f64;
                }
                if !(boxes + 1.0 <= max_hyp) {
                    return Err(format!(
                        "pca-intent: |\u{398}_{}| = {} exceeds maxHypotheses {}; coarsen the cuts",
                        vs.verb,
                        js_num(boxes + 1.0),
                        js_num(max_hyp)
                    ));
                }
                let nb = boxes as usize;
                nh = nb + 1;
                choice = vec![0usize; (nb * dn).max(1)];
                let mut cur = vec![0usize; dn];
                for h in 0..nb {
                    for d in 0..dn {
                        choice[h * dn + d] = cur[d];
                    }
                    for d in (0..dn).rev() {
                        cur[d] += 1;
                        if cur[d] < n_choice[d] {
                            break;
                        }
                        cur[d] = 0;
                    }
                }
            }
            _ => {
                let (sets, cx) = match hc {
                    Hc::Union { k, .. } => {
                        let bm = box_masks(vs, n_cells, &cell_idx, &n_cells_d, &contains, &n_choice, max_enum)?;
                        enumerate_unions(&bm, *k, max_enum, &vs.verb)?
                    }
                    Hc::DList { max_rules, atomic, .. } => {
                        let tests = if *atomic {
                            atomic_tests(vs, n_cells, &cell_idx, &n_cells_d)
                        } else {
                            dedup_masks(box_masks(vs, n_cells, &cell_idx, &n_cells_d, &contains, &n_choice, max_enum)?)
                        };
                        enumerate_decision_lists(&tests, n_cells, *max_rules, max_enum, &vs.verb)?
                    }
                    Hc::Box => unreachable!(),
                };
                if !(sets.len() as f64 + 1.0 <= max_hyp) {
                    return Err(format!("pca-intent: |\u{398}_{}| = {} exceeds maxHypotheses {}; coarsen the cuts", vs.verb, sets.len() + 1, js_num(max_hyp)));
                }
                nh = sets.len() + 1;
                let mut mem = vec![vec![0u8; n_cells]];
                mem.extend(sets);
                member = Some(mem);
                let mut cxs = vec![0usize];
                cxs.extend(cx);
                complexity = Some(cxs);
            }
        }
        Ok(VerbModel {
            vs: vs.clone(),
            n_choice,
            contains,
            n_cells_d,
            nh,
            choice,
            member,
            complexity,
            prior: vec![0.0; nh],
            w: vec![0.0; nh],
            err: vec![0.0; nh],
            n_cells,
            cell_idx,
            mass,
            harm: hm,
            p: vec![0.0; n_cells],
            veto: vec![0u8; n_cells],
            seen: vec![0u8; n_cells],
            dirty: true,
        })
    }

    /// Does hypothesis h (>= 1) contain flat cell c?
    fn holds(&self, h: usize, c: usize) -> bool {
        if let Some(mem) = &self.member {
            return mem[h][c] == 1;
        }
        let dn = self.vs.dims.len();
        let base = (h - 1) * dn;
        for d in 0..dn {
            let n = self.n_cells_d[d];
            if self.contains[d][self.choice[base + d] * n + self.cell_idx[c * dn + d]] == 0 {
                return false;
            }
        }
        true
    }

    fn holds_all(&self, h: usize, cells: &[usize]) -> bool {
        if h == 0 {
            return false;
        }
        cells.iter().all(|c| self.holds(h, *c))
    }
}

/// The non-empty hypotheses of Theta_v for a class as cell masks over the verb's flat cells, each with its Occam complexity.
/// `caps` = `{maxHypotheses?, maxEnumeration?}`.
pub fn hypothesis_cell_sets(vs: &VerbSpace, hc: Option<&Value>, caps: Option<&Value>) -> R<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut max_hyp = 400000.0;
    let mut max_enum = 4000000.0;
    if let Some(c) = caps {
        if let Some(x) = opt(c, "maxHypotheses").and_then(num) {
            max_hyp = x;
        }
        if let Some(x) = opt(c, "maxEnumeration").and_then(num) {
            max_enum = x;
        }
    }
    let hc = Hc::from_json(hc)?;
    let m = VerbModel::build(vs, &hc, max_hyp, max_enum)?;
    let mut sets = vec![];
    let mut cx = vec![];
    for h in 1..m.nh {
        let mut s = vec![0u8; m.n_cells];
        for c in 0..m.n_cells {
            if m.holds(h, c) {
                s[c] = 1;
            }
        }
        sets.push(s);
        cx.push(m.complexity.as_ref().map(|x| x[h]).unwrap_or(1));
    }
    Ok((sets, cx))
}

pub(crate) fn normalize(w: &mut [f64]) {
    let mut s = 0.0;
    for x in w.iter() {
        s += *x;
    }
    if s > 0.0 {
        for x in w.iter_mut() {
            *x /= s;
        }
    }
}

/// The learner's options (the reference's `LearnerOptions`).
pub struct LearnerOpts {
    pub eta: f64,
    pub eta_pos: Option<f64>,
    pub eta_neg: Option<f64>,
    pub tau: Option<f64>,
    pub strategy: String,
    pub hypothesis_class: Hc,
    pub agnostic_slack: Option<f64>,
    pub null_mass: Option<Box<dyn Fn(&VerbSpace) -> f64>>,
    /// Anchor policies with their lambda (`anchor` first, then `anchors`).
    pub anchors: Vec<(Value, f64)>,
    pub monotone: Option<(Vec<String>, f64)>,
    pub prior_mix: Option<(f64, Box<dyn Fn(&VerbSpace, &dyn Fn(f64) -> bool) -> f64>)>,
    pub max_hypotheses: f64,
    pub max_enumeration: f64,
}

impl LearnerOpts {
    pub fn default_opts() -> LearnerOpts {
        LearnerOpts {
            eta: 0.0,
            eta_pos: None,
            eta_neg: None,
            tau: None,
            strategy: "disagreement".into(),
            hypothesis_class: Hc::Box,
            agnostic_slack: None,
            null_mass: None,
            anchors: vec![],
            monotone: None,
            prior_mix: None,
            max_hypotheses: 400000.0,
            max_enumeration: 4000000.0,
        }
    }

    /// The plain-data options. The two function-valued options are named: `nullMassFn: "byRev"` (0.1 for a reversible verb, else 0.3) and
    /// `priorMix.weight` in `"size"` (1 + the number of contained cells among the first 64) / `"neg"` (-1) / `"zero"` (0).
    pub fn from_json(o: &Value) -> R<LearnerOpts> {
        let mut x = LearnerOpts::default_opts();
        let fnum = |k: &str| -> R<Option<f64>> {
            match opt(o, k) {
                None => Ok(None),
                Some(v) => num(v).map(Some).ok_or_else(|| format!("pca-intent: {k} must be a number")),
            }
        };
        if let Some(e) = fnum("eta")? {
            x.eta = e;
        }
        x.eta_pos = fnum("etaPos")?;
        x.eta_neg = fnum("etaNeg")?;
        x.tau = fnum("tau")?;
        if let Some(s) = opt(o, "strategy") {
            x.strategy = s.as_str().ok_or("pca-intent: strategy must be a string")?.to_string();
        }
        x.hypothesis_class = Hc::from_json(opt(o, "hypothesisClass"))?;
        x.agnostic_slack = fnum("agnosticSlack")?;
        if let Some(v) = fnum("maxHypotheses")? {
            x.max_hypotheses = v;
        }
        if let Some(v) = fnum("maxEnumeration")? {
            x.max_enumeration = v;
        }
        if get_str(o, "nullMassFn") == Some("byRev") {
            x.null_mass = Some(Box::new(|vs: &VerbSpace| if vs.reversibility.as_deref() == Some("reversible") { 0.1 } else { 0.3 }));
        } else if let Some(n) = fnum("nullMass")? {
            x.null_mass = Some(Box::new(move |_vs: &VerbSpace| n));
        }
        for a in opt(o, "anchor").into_iter().chain(opt(o, "anchors").and_then(Value::as_array).into_iter().flatten()) {
            if !truthy(Some(a)) {
                continue;
            }
            let lam = get_num(a, "lambda").ok_or("pca-intent: an anchor needs a numeric lambda")?;
            x.anchors.push((get(a, "policy").cloned().unwrap_or(Value::Null), lam));
        }
        if let Some(m) = opt(o, "monotone") {
            let paths = match get(m, "paths") {
                Some(Value::Array(a)) => a.iter().filter_map(|p| p.as_str().map(String::from)).collect(),
                _ => return Err("pca-intent: monotone.paths must be an array".into()),
            };
            let off = match opt(m, "offMass") {
                None => 0.0,
                Some(v) => num(v).ok_or("pca-intent: monotone.offMass must be a number")?,
            };
            x.monotone = Some((paths, off));
        }
        if let Some(pm) = opt(o, "priorMix") {
            let beta = get_num(pm, "beta").ok_or("pca-intent: priorMix.beta must be a number")?;
            let kind = get_str(pm, "weight").unwrap_or("zero").to_string();
            let w: Box<dyn Fn(&VerbSpace, &dyn Fn(f64) -> bool) -> f64> = match kind.as_str() {
                "size" => Box::new(|_vs: &VerbSpace, has: &dyn Fn(f64) -> bool| {
                    let mut k = 1.0;
                    for c in 0..64 {
                        if has(c as f64) {
                            k += 1.0;
                        }
                    }
                    k
                }),
                "neg" => Box::new(|_vs: &VerbSpace, _has: &dyn Fn(f64) -> bool| -1.0),
                _ => Box::new(|_vs: &VerbSpace, _has: &dyn Fn(f64) -> bool| 0.0),
            };
            x.prior_mix = Some((beta, w));
        }
        Ok(x)
    }
}

/// The exact posterior over Theta = prod_v Theta_v.
pub struct IntentLearner {
    pub omega: Omega,
    pub eta: f64,
    pub eta_pos: f64,
    pub eta_neg: f64,
    noisy: bool,
    pub tau: f64,
    pub strategy: String,
    pub hypothesis_class: Hc,
    pub agnostic_slack: Option<f64>,
    pub observations: Vec<Value>,
    /// The serialisable parameters (set by `mapkit::create_learner`).
    pub map_params: Option<Value>,
    models: Vec<VerbModel>,
}

/// One cell of the learner: `{verb, cell, p, mass, harm, inGrant, vetoed}`.
#[derive(Clone, Debug)]
pub struct CellInfo {
    pub verb: String,
    pub cell: Vec<usize>,
    pub p: f64,
    pub mass: f64,
    pub harm: f64,
    pub in_grant: bool,
    pub vetoed: bool,
}

impl CellInfo {
    pub fn to_json(&self) -> Value {
        obj(vec![
            ("verb", jstr(&self.verb)),
            ("cell", jarr_usize(&self.cell)),
            ("p", jn(self.p)),
            ("mass", jn(self.mass)),
            ("harm", jn(self.harm)),
            ("inGrant", Value::Bool(self.in_grant)),
            ("vetoed", Value::Bool(self.vetoed)),
        ])
    }
}

impl IntentLearner {
    pub fn new(omega: &Omega, o: LearnerOpts) -> R<IntentLearner> {
        let eta = o.eta;
        if !(eta >= 0.0 && eta < 0.5) {
            return Err("pca-intent: eta must be in [0, 0.5)".into());
        }
        let eta_pos = o.eta_pos.unwrap_or(eta);
        let eta_neg = o.eta_neg.unwrap_or(eta);
        if !(eta_pos >= 0.0 && eta_pos < 0.5 && eta_neg >= 0.0 && eta_neg < 0.5) {
            return Err("pca-intent: etaPos and etaNeg must be in [0, 0.5)".into());
        }
        let noisy = eta_pos != 0.0 || eta_neg != 0.0;
        let tau = o.tau.unwrap_or(if noisy { 0.95 } else { 1.0 });
        if let Some(s) = o.agnostic_slack {
            if !(is_integer_f(s) && s >= 0.0) {
                return Err("pca-intent: agnosticSlack must be a non-negative integer".into());
            }
            if noisy {
                return Err("pca-intent: agnostic selection replaces the noise model; use eta = 0".into());
            }
        }
        let mut models = vec![];
        for vs in &omega.verbs {
            models.push(VerbModel::build(vs, &o.hypothesis_class, o.max_hypotheses, o.max_enumeration)?);
        }
        let mut l = IntentLearner {
            omega: omega.clone(),
            eta,
            eta_pos,
            eta_neg,
            noisy,
            tau,
            strategy: o.strategy.clone(),
            hypothesis_class: o.hypothesis_class.clone(),
            agnostic_slack: o.agnostic_slack,
            observations: vec![],
            map_params: None,
            models,
        };
        l.init_prior(&o)?;
        Ok(l)
    }

    fn init_prior(&mut self, o: &LearnerOpts) -> R<()> {
        let mut admitters: Vec<(Admitter, f64)> = vec![];
        for (policy, lam) in &o.anchors {
            if *lam > 0.0 {
                admitters.push((admitter(policy)?, *lam));
            }
        }
        let decay = self.hypothesis_class.decay();
        if !(decay > 0.0 && decay <= 1.0) {
            return Err("pca-intent: decay must be in (0, 1]".into());
        }
        for m in self.models.iter_mut() {
            let nm = match &o.null_mass {
                Some(f) => f(&m.vs),
                None => 0.2,
            };
            if !(nm >= 0.0 && nm <= 1.0) {
                return Err("pca-intent: nullMass must be in [0, 1]".into());
            }
            m.w[0] = nm;
            let mut z = 0.0;
            for h in 1..m.nh {
                let raw = match &m.complexity {
                    Some(cx) => crate::detmath::det_pow_int(decay, (cx[h] as i64 - 1).max(0) as u64),
                    None => 1.0,
                };
                m.w[h] = raw;
                z += raw;
            }
            for h in 1..m.nh {
                m.w[h] = ((1.0 - nm) * m.w[h]) / or1(z);
            }
            if let Some((paths, off)) = &o.monotone {
                apply_monotone_prior(m, paths, *off)?;
            }
            if !admitters.is_empty() {
                let mut tot = 0.0;
                for c in 0..m.n_cells {
                    tot += m.mass[c];
                }
                let mut accs: Vec<Vec<u8>> = vec![];
                for (adm, _lam) in &admitters {
                    let mut acc = vec![0u8; m.n_cells];
                    for c in 0..m.n_cells {
                        let rep = cell_rep(&m.vs, &decode_cell(&m.vs, c))?;
                        acc[c] = if adm.admits(&m.vs, &rep)? { 1 } else { 0 };
                    }
                    accs.push(acc);
                }
                for h in 0..m.nh {
                    let mut mix = 0.0;
                    for (i, acc) in accs.iter().enumerate() {
                        let mut dist = 0.0;
                        for c in 0..m.n_cells {
                            let in_h = if h == 0 {
                                0u8
                            } else if m.holds(h, c) {
                                1u8
                            } else {
                                0u8
                            };
                            if in_h != acc[c] {
                                dist += m.mass[c];
                            }
                        }
                        mix += crate::detmath::det_exp((-admitters[i].1 * dist) / or1(tot));
                    }
                    m.w[h] *= mix / admitters.len() as f64;
                }
            }
            normalize(&mut m.w);
            if let Some((beta, weight)) = &o.prior_mix {
                mix_prior(m, *beta, weight)?;
            }
            m.prior = m.w.clone();
            m.dirty = true;
        }
        Ok(())
    }

    fn in_grant(&self, mi: usize, c: usize) -> bool {
        let m = &self.models[mi];
        m.veto[c] == 0 && m.p[c] >= self.tau - 1e-12
    }

    fn model_index(&self, verb: Option<&str>) -> Option<usize> {
        let v = verb?;
        self.models.iter().position(|m| m.vs.verb == v)
    }

    fn refresh(&mut self, mi: usize) {
        let m = &mut self.models[mi];
        if !m.dirty {
            return;
        }
        let mut p = vec![0.0f64; m.n_cells];
        let mut any_in = vec![0u8; m.n_cells];
        let mut any_out = vec![0u8; m.n_cells];
        let mut live = false;
        for h in 0..m.nh {
            let w = m.w[h];
            if w == 0.0 {
                continue;
            }
            live = true;
            for c in 0..m.n_cells {
                if h > 0 && m.holds(h, c) {
                    p[c] += w;
                    any_in[c] = 1;
                } else {
                    any_out[c] = 1;
                }
            }
        }
        for c in 0..m.n_cells {
            p[c] = if !live || any_in[c] == 0 {
                0.0
            } else if any_out[c] == 0 {
                1.0
            } else {
                js_min(1.0, js_max(0.0, p[c]))
            };
        }
        m.p = p;
        m.dirty = false;
    }

    fn locate(&self, o: &Value) -> Option<(usize, Vec<usize>)> {
        let mi = self.model_index(get_str(o, "verb"))?;
        let idx = cell_of(&self.models[mi].vs, o)?;
        Some((mi, idx))
    }

    fn flat(&self, mi: usize, idx: &[usize]) -> usize {
        let m = &self.models[mi];
        let mut f = 0usize;
        for d in 0..idx.len() {
            f = f * m.n_cells_d[d] + idx[d];
        }
        f
    }

    /// p_n(omega) for a concrete outcome (0 if outside Omega: the conservative reading).
    pub fn acceptance(&mut self, o: &Value) -> f64 {
        match self.locate(o) {
            None => 0.0,
            Some((mi, idx)) => {
                self.refresh(mi);
                let f = self.flat(mi, &idx);
                self.models[mi].p[f]
            }
        }
    }

    pub fn admits_outcome(&mut self, o: &Value) -> bool {
        match self.locate(o) {
            None => false,
            Some((mi, idx)) => {
                self.refresh(mi);
                let f = self.flat(mi, &idx);
                self.in_grant(mi, f)
            }
        }
    }

    pub fn is_vetoed(&self, o: &Value) -> bool {
        match self.locate(o) {
            None => false,
            Some((mi, idx)) => self.models[mi].veto[self.flat(mi, &idx)] == 1,
        }
    }

    pub fn vetoed_cells(&self) -> Vec<String> {
        let mut out = vec![];
        for m in &self.models {
            for c in 0..m.n_cells {
                if m.veto[c] != 0 {
                    out.push(format!("{}|{}", m.vs.verb, c));
                }
            }
        }
        out
    }

    /// Record the principal's answer y to "should omega be allowed?" (or, with a region, "should EVERY outcome in it be allowed?") and
    /// update the posterior. `None` when the outcome is outside Omega or the region covers no cell.
    pub fn observe(&mut self, o: &Value, y: i64, source: &str, region: Option<&Value>) -> R<Option<Value>> {
        let Some((mi, idx)) = self.locate(o) else { return Ok(None) };
        let cells: Vec<usize> = match region.filter(|r| !r.is_null()) {
            Some(r) => region_cells(&self.models[mi].vs, r, if y == 1 { "inner" } else { "outer" })?,
            None => vec![self.flat(mi, &idx)],
        };
        if cells.is_empty() {
            return Ok(None);
        }
        self.refresh(mi);
        let mut obs = Map::new();
        obs.insert("verb".into(), get(o, "verb").cloned().unwrap_or(Value::Null));
        obs.insert("values".into(), get(o, "values").cloned().filter(|v| v.is_object()).unwrap_or_else(|| Value::Object(Map::new())));
        obs.insert("cell".into(), jarr_usize(&idx));
        obs.insert("y".into(), jn(y as f64));
        obs.insert("source".into(), jstr(source));
        if let Some(r) = region.filter(|r| !r.is_null()) {
            obs.insert("region".into(), r.clone());
        }
        let (eta_pos, eta_neg, slack) = (self.eta_pos, self.eta_neg, self.agnostic_slack);
        let m = &mut self.models[mi];
        let mut region_p = 0.0;
        for h in 1..m.nh {
            if m.w[h] > 0.0 && m.holds_all(h, &cells) {
                region_p += m.w[h];
            }
        }
        let contradicts_all = if y == 0 { region_p >= 1.0 - 1e-12 } else { region_p <= 1e-12 };
        if source == "runtime" && y == 0 {
            for c in &cells {
                m.veto[*c] = 1;
            }
        }
        for c in &cells {
            m.seen[*c] = 1;
        }
        if let Some(slack) = slack {
            for h in 0..m.nh {
                let held = if m.holds_all(h, &cells) { 1 } else { 0 };
                if held != y {
                    m.err[h] += 1.0;
                }
            }
            let mut min_err = f64::INFINITY;
            for h in 0..m.nh {
                if m.prior[h] > 0.0 {
                    min_err = js_min(min_err, m.err[h]);
                }
            }
            for h in 0..m.nh {
                m.w[h] = if m.err[h] <= min_err + slack { m.prior[h] } else { 0.0 };
            }
            normalize(&mut m.w);
            if contradicts_all {
                obs.insert("conflict".into(), Value::Bool(true));
                if y == 0 {
                    for c in &cells {
                        m.veto[*c] = 1;
                    }
                }
            }
        } else {
            let prev = if eta_pos == 0.0 || eta_neg == 0.0 { Some(m.w.clone()) } else { None };
            let lik = |in_h: u8| -> f64 {
                if in_h == 1 {
                    if y == 1 {
                        1.0 - eta_neg
                    } else {
                        eta_neg
                    }
                } else if y == 1 {
                    eta_pos
                } else {
                    1.0 - eta_pos
                }
            };
            let mut total = 0.0;
            for h in 0..m.nh {
                let l = lik(if m.holds_all(h, &cells) { 1 } else { 0 });
                m.w[h] *= l;
                total += m.w[h];
            }
            if total == 0.0 && prev.is_some() {
                m.w = prev.unwrap();
                obs.insert("conflict".into(), Value::Bool(true));
                if y == 0 {
                    for c in &cells {
                        m.veto[*c] = 1;
                    }
                }
            } else {
                normalize(&mut m.w);
            }
        }
        m.dirty = true;
        let ob = Value::Object(obs);
        self.observations.push(ob.clone());
        Ok(Some(ob))
    }

    /// Every cell with its posterior acceptance.
    pub fn cells(&mut self) -> Vec<CellInfo> {
        let mut out = vec![];
        for mi in 0..self.models.len() {
            self.refresh(mi);
            for c in 0..self.models[mi].n_cells {
                let m = &self.models[mi];
                out.push(CellInfo {
                    verb: m.vs.verb.clone(),
                    cell: decode_cell(&m.vs, c),
                    p: m.p[c],
                    mass: m.mass[c],
                    harm: m.harm[c],
                    in_grant: self.in_grant(mi, c),
                    vetoed: m.veto[c] == 1,
                });
            }
        }
        out
    }

    pub fn metrics(&mut self) -> Value {
        let (mut r, mut b, mut u, mut h_ent, mut vs_bits, mut dis, mut mean_harm) = (0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64);
        for mi in 0..self.models.len() {
            self.refresh(mi);
            for c in 0..self.models[mi].n_cells {
                let ig = self.in_grant(mi, c);
                let m = &self.models[mi];
                let (p, mu) = (m.p[c], m.mass[c]);
                mean_harm += mu * m.harm[c];
                if ig {
                    r += mu * (1.0 - p) * m.harm[c];
                } else {
                    b += mu * p;
                }
                u += mu * js_min(p, 1.0 - p);
                if p > 1e-12 && p < 1.0 - 1e-12 {
                    dis += mu;
                }
            }
            let m = &self.models[mi];
            let mut alive = 0usize;
            for h in 0..m.nh {
                let w = m.w[h];
                if w > 0.0 {
                    alive += 1;
                    h_ent -= w * crate::detmath::det_log2(w);
                }
            }
            vs_bits += crate::detmath::det_log2(alive.max(1) as f64);
        }
        let questions = self.observations.iter().filter(|o| get_str(o, "source") == Some("elicitation")).count();
        let conflicts = self.observations.iter().filter(|o| truthy(get(o, "conflict"))).count();
        obj(vec![
            ("residualRisk", jn(r)),
            ("burden", jn(b)),
            ("uncertainty", jn(u)),
            ("entropyBits", jn(h_ent)),
            ("log2VersionSpace", if self.noisy { Value::Null } else { jn(vs_bits) }),
            ("disagreementMass", jn(dis)),
            ("meanHarm", jn(mean_harm)),
            ("questions", jn(questions as f64)),
            ("conflicts", jn(conflicts as f64)),
        ])
    }

    /// The next question: argmax expected information (x mu*h for the risk strategy). `None` when nothing is uncertain.
    pub fn next_question(&mut self) -> R<Option<Value>> {
        let mut best: Option<(usize, usize, f64, f64)> = None; // (model, cell, p, score)
        let h_pos = bin_ent(self.eta_pos);
        let h_neg = bin_ent(self.eta_neg);
        for mi in 0..self.models.len() {
            self.refresh(mi);
            let m = &self.models[mi];
            for c in 0..m.n_cells {
                if m.veto[c] != 0 {
                    continue;
                }
                let p = m.p[c];
                if p <= 1e-9 || p >= 1.0 - 1e-9 {
                    continue;
                }
                let pe = p * (1.0 - self.eta_neg) + (1.0 - p) * self.eta_pos;
                let mut score = bin_ent(pe) - if self.eta_pos == self.eta_neg { h_pos } else { p * h_neg + (1.0 - p) * h_pos };
                if self.strategy == "risk" {
                    score *= m.mass[c] * m.harm[c];
                }
                if score <= 1e-15 {
                    continue;
                }
                if best.is_none() || score > best.unwrap().3 + 1e-12 {
                    best = Some((mi, c, p, score));
                }
            }
        }
        match best {
            None => Ok(None),
            Some((mi, c, p, score)) => {
                let vs = &self.models[mi].vs;
                let cell = decode_cell(vs, c);
                Ok(Some(obj(vec![
                    ("verb", jstr(&vs.verb)),
                    ("cell", jarr_usize(&cell)),
                    ("outcome", cell_rep(vs, &cell)?),
                    ("p", jn(p)),
                    ("score", jn(score)),
                ])))
            }
        }
    }

    /// Grant cells INFERRED but never directly observed, most consequential first: `[(verb, cell, weight)]`.
    pub fn unconfirmed_grant_cells(&mut self) -> Vec<(String, Vec<usize>, f64)> {
        let mut out: Vec<(String, Vec<usize>, f64)> = vec![];
        for mi in 0..self.models.len() {
            self.refresh(mi);
            for c in 0..self.models[mi].n_cells {
                let m = &self.models[mi];
                if m.seen[c] != 0 || !self.in_grant(mi, c) {
                    continue;
                }
                out.push((m.vs.verb.clone(), decode_cell(&m.vs, c), m.mass[c] * m.harm[c]));
            }
        }
        out.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    /// The conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau.
    pub fn synthesize(&mut self) -> R<Value> {
        let mut predicates: Vec<Value> = vec![];
        let mut worst: i32 = -1;
        for mi in 0..self.models.len() {
            self.refresh(mi);
            let n = self.models[mi].n_cells;
            let mut allowed = vec![0u8; n];
            let mut any = false;
            for c in 0..n {
                if self.in_grant(mi, c) {
                    allowed[c] = 1;
                    any = true;
                }
            }
            if !any {
                continue;
            }
            let vs = &self.models[mi].vs;
            let rv = vs.reversibility.as_deref().and_then(|r| ORDER.iter().position(|x| *x == r)).map(|i| i as i32).unwrap_or(-1);
            worst = worst.max(rv);
            predicates.extend(boxes_to_predicates(vs, &allowed)?);
        }
        let caveats = if worst >= 0 { vec![obj(vec![("type", jstr("reversibility_max")), ("class", jstr(ORDER[worst as usize]))])] } else { vec![] };
        Ok(obj(vec![("predicates", Value::Array(predicates)), ("caveats", Value::Array(caveats))]))
    }

    /// Replay observations onto a fresh learner.
    pub fn replay(omega: &Omega, opts: LearnerOpts, observations: &[Value]) -> R<IntentLearner> {
        let mut l = IntentLearner::new(omega, opts)?;
        for o in observations {
            let oc = obj(vec![("verb", get(o, "verb").cloned().unwrap_or(Value::Null)), ("values", get(o, "values").cloned().unwrap_or(Value::Null))]);
            let y = get(o, "y").and_then(num).unwrap_or(0.0) as i64;
            l.observe(&oc, y, get_str(o, "source").unwrap_or("elicitation"), get(o, "region"))?;
        }
        Ok(l)
    }
}

fn apply_monotone_prior(m: &mut VerbModel, paths: &[String], off: f64) -> R<()> {
    if !(off >= 0.0 && off <= 1.0) {
        return Err("pca-intent: monotone.offMass must be in [0, 1]".into());
    }
    let dn = m.vs.dims.len();
    let ks: Vec<usize> = m.vs.dims.iter().enumerate().filter(|(_, d)| d.is_num() && paths.iter().any(|p| p == d.path())).map(|(k, _)| k).collect();
    if ks.is_empty() {
        return Ok(());
    }
    let stride: Vec<usize> = ks.iter().map(|k| m.n_cells_d[k + 1..].iter().product::<usize>()).collect();
    for h in 1..m.nh {
        let mut is_mono = true;
        let mut c = 0;
        while c < m.n_cells && is_mono {
            if m.holds(h, c) {
                for i in 0..ks.len() {
                    if m.cell_idx[c * dn + ks[i]] > 0 && !m.holds(h, c - stride[i]) {
                        is_mono = false;
                        break;
                    }
                }
            }
            c += 1;
        }
        if !is_mono {
            m.w[h] *= off;
        }
    }
    Ok(())
}

fn mix_prior(m: &mut VerbModel, beta: f64, weight: &dyn Fn(&VerbSpace, &dyn Fn(f64) -> bool) -> f64) -> R<()> {
    if !(beta >= 0.0 && beta < 1.0) {
        return Err("pca-intent: priorMix.beta must be in [0, 1)".into());
    }
    let mut pop = vec![0.0f64; m.nh];
    let mut z = 0.0;
    for h in 0..m.nh {
        let n_cells = m.n_cells;
        let mm: &VerbModel = m;
        let contains = |c: f64| -> bool { h != 0 && is_integer_f(c) && c >= 0.0 && c < n_cells as f64 && mm.holds(h, c as usize) };
        let x = weight(&mm.vs, &contains);
        if !(x.is_finite() && x >= 0.0) {
            return Err("pca-intent: priorMix.weight must be finite and >= 0".into());
        }
        pop[h] = x;
        z += x;
    }
    if !(z > 0.0) {
        return Ok(());
    }
    for h in 0..m.nh {
        m.w[h] = (1.0 - beta) * m.w[h] + (beta * pop[h]) / z;
    }
    Ok(())
}

// ---- synthesis: allowed cells -> union of boxes -> predicates --------------------------------------------------------------------

#[derive(Clone)]
enum Rng1 {
    Num(usize, usize),
    Cat(Vec<usize>),
}

fn box_cells(ranges: &[Rng1]) -> Vec<Vec<usize>> {
    let vals: Vec<Vec<usize>> = ranges
        .iter()
        .map(|r| match r {
            Rng1::Num(a, b) => (*a..=*b).collect(),
            Rng1::Cat(s) => {
                let mut v = s.clone();
                v.sort();
                v
            }
        })
        .collect();
    let mut out: Vec<Vec<usize>> = vec![vec![]];
    for v in &vals {
        let mut next = vec![];
        for p in &out {
            for x in v {
                let mut q = p.clone();
                q.push(*x);
                next.push(q);
            }
        }
        out = next;
    }
    out
}

fn cat_condition(d: &Dim, s: &[usize]) -> Option<Value> {
    let (path, values) = match d {
        Dim::Cat { path, values } => (path, values),
        _ => return None,
    };
    if s.len() == values.len() {
        return None;
    }
    let exacts: Vec<&String> = values.iter().filter(|v| v.kind == "exact").map(|v| &v.value).collect();
    let prefixes: Vec<&String> = values.iter().filter(|v| v.kind == "prefix").map(|v| &v.value).collect();
    let cond = |op: &str, v: Value| obj(vec![("field", jstr(path)), ("op", jstr(op)), ("value", v)]);
    let mut alts: Vec<Value> = vec![];
    let allowed_exacts: Vec<&String> = s.iter().filter(|i| values[**i].kind == "exact").map(|i| &values[*i].value).collect();
    if allowed_exacts.len() == 1 {
        alts.push(cond("eq", jstr(allowed_exacts[0])));
    } else if allowed_exacts.len() > 1 {
        alts.push(cond("in", Value::Array(allowed_exacts.iter().map(|x| jstr(x)).collect())));
    }
    let mut sorted = s.to_vec();
    sorted.sort();
    for i in sorted {
        let v = &values[i];
        if v.kind == "exact" {
            continue;
        }
        let mut parts: Vec<Value> = vec![];
        if v.kind == "prefix" {
            parts.push(cond("prefix", jstr(&v.value)));
            let under: Vec<Value> = exacts.iter().filter(|e| e.starts_with(v.value.as_str())).map(|e| jstr(e)).collect();
            if !under.is_empty() {
                parts.push(cond("nin", Value::Array(under)));
            }
            for q in &prefixes {
                if **q != v.value && q.starts_with(v.value.as_str()) {
                    parts.push(obj(vec![("not", cond("prefix", jstr(q)))]));
                }
            }
        } else {
            if !exacts.is_empty() {
                parts.push(cond("nin", Value::Array(exacts.iter().map(|e| jstr(e)).collect())));
            }
            for q in &prefixes {
                parts.push(obj(vec![("not", cond("prefix", jstr(q)))]));
            }
        }
        if parts.len() == 1 {
            alts.push(parts.remove(0));
        } else if parts.len() > 1 {
            alts.push(obj(vec![("all_of", Value::Array(parts))]));
        }
    }
    if alts.is_empty() {
        return None;
    }
    if alts.len() == 1 {
        Some(alts.remove(0))
    } else {
        Some(obj(vec![("any_of", Value::Array(alts))]))
    }
}

fn box_to_predicate(vs: &VerbSpace, ranges: &[Rng1]) -> R<Value> {
    let mut wh: Vec<Value> = vec![];
    for (k, d) in vs.dims.iter().enumerate() {
        match (d, &ranges[k]) {
            (Dim::Num { cells, path, .. }, Rng1::Num(a, b)) => {
                wh.push(obj(vec![("field", jstr(path)), ("op", jstr("gte")), ("value", jn(cells.get(*a).ok_or("synth: cell out of range")?.0))]));
                wh.push(obj(vec![("field", jstr(path)), ("op", jstr("lte")), ("value", jn(cells.get(*b).ok_or("synth: cell out of range")?.1))]));
            }
            (Dim::Cat { .. }, Rng1::Cat(s)) => {
                if let Some(c) = cat_condition(d, s) {
                    wh.push(c);
                }
            }
            _ => {}
        }
    }
    let mut m = Map::new();
    m.insert("verb".into(), jstr(&vs.verb));
    m.insert("resource".into(), jstr("*"));
    if !wh.is_empty() {
        m.insert("where".into(), Value::Array(wh));
    }
    Ok(Value::Object(m))
}

/// Cover the allowed cell set exactly with greedily-grown maximal boxes; one predicate per box.
pub fn boxes_to_predicates(vs: &VerbSpace, allowed: &[u8]) -> R<Vec<Value>> {
    let mut covered = vec![0u8; allowed.len()];
    let mut out: Vec<Value> = vec![];
    let all_ok = |ranges: &[Rng1]| -> bool { box_cells(ranges).iter().all(|idx| allowed.get(encode_cell(vs, idx)).copied() == Some(1)) };
    for c in 0..allowed.len() {
        if allowed[c] == 0 || covered[c] != 0 {
            continue;
        }
        let idx = decode_cell(vs, c);
        let mut ranges: Vec<Rng1> =
            vs.dims.iter().enumerate().map(|(k, d)| if d.is_num() { Rng1::Num(idx[k], idx[k]) } else { Rng1::Cat(vec![idx[k]]) }).collect();
        for (k, d) in vs.dims.iter().enumerate() {
            if d.is_num() {
                let n = d.cell_count();
                loop {
                    let (a, b) = match &ranges[k] {
                        Rng1::Num(a, b) => (*a, *b),
                        _ => break,
                    };
                    if b + 1 >= n {
                        break;
                    }
                    ranges[k] = Rng1::Num(a, b + 1);
                    if !all_ok(&ranges) {
                        ranges[k] = Rng1::Num(a, b);
                        break;
                    }
                }
                loop {
                    let (a, b) = match &ranges[k] {
                        Rng1::Num(a, b) => (*a, *b),
                        _ => break,
                    };
                    if a == 0 {
                        break;
                    }
                    ranges[k] = Rng1::Num(a - 1, b);
                    if !all_ok(&ranges) {
                        ranges[k] = Rng1::Num(a, b);
                        break;
                    }
                }
            } else {
                for v in 0..d.cell_count() {
                    if let Rng1::Cat(s) = &ranges[k] {
                        if s.contains(&v) {
                            continue;
                        }
                    }
                    if let Rng1::Cat(s) = &mut ranges[k] {
                        s.push(v);
                    }
                    if !all_ok(&ranges) {
                        if let Rng1::Cat(s) = &mut ranges[k] {
                            s.pop();
                        }
                    }
                }
            }
        }
        for bi in box_cells(&ranges) {
            covered[encode_cell(vs, &bi)] = 1;
        }
        out.push(box_to_predicate(vs, &ranges)?);
    }
    Ok(out)
}

// ---- the stop rule ----------------------------------------------------------------------------------------------------------------

fn seed_question(l: &mut IntentLearner, s: &Value) -> R<Option<Value>> {
    let Some(vs) = get_str(s, "verb").and_then(|v| l.omega.verb(v)).cloned() else { return Ok(None) };
    let cell: Vec<usize> = match get(s, "cell").and_then(Value::as_array) {
        Some(a) => a.iter().map(|x| as_usize(x).unwrap_or(usize::MAX)).collect(),
        None => return Ok(None),
    };
    if cell.len() != vs.dims.len() {
        return Ok(None);
    }
    let outcome = cell_rep(&vs, &cell)?;
    let p = l.acceptance(&outcome);
    if p <= 1e-9 || p >= 1.0 - 1e-9 || l.is_vetoed(&outcome) {
        return Ok(None);
    }
    Ok(Some(obj(vec![("verb", jstr(&vs.verb)), ("cell", jarr_usize(&cell)), ("outcome", outcome), ("p", jn(p)), ("score", jn(0.0))])))
}

/// Ask questions until the stop rule of spec 2.5 holds. `o` = `{epsRisk, epsBurden, maxQuestions, audit?, seed?}`; returns
/// `{stop, questions, auditQuestions, seedQuestions, asked}`.
pub fn elicit(l: &mut IntentLearner, answer: &mut dyn FnMut(&Value) -> R<i64>, o: &Value) -> R<Value> {
    let eps_risk = get_num(o, "epsRisk").ok_or("elicit: epsRisk must be a number")?;
    let eps_burden = get_num(o, "epsBurden").ok_or("elicit: epsBurden must be a number")?;
    let max_q = get_num(o, "maxQuestions").ok_or("elicit: maxQuestions must be a number")?;
    let mut asked: Vec<Value> = vec![];
    let mut seed_questions = 0usize;
    if let Some(Value::Array(seed)) = get(o, "seed") {
        for s in seed {
            if !((asked.len() as f64) < max_q) {
                break;
            }
            let m = l.metrics();
            if get_num(&m, "residualRisk").unwrap_or(f64::NAN) <= eps_risk && get_num(&m, "burden").unwrap_or(f64::NAN) <= eps_burden {
                break;
            }
            let Some(q) = seed_question(l, s)? else { continue };
            let y = answer(&q)?;
            l.observe(&q["outcome"], y, "elicitation", None)?;
            asked.push(q);
            seed_questions += 1;
        }
    }
    let mut stop: Option<&str> = None;
    while stop.is_none() {
        let m = l.metrics();
        if get_num(&m, "residualRisk").unwrap_or(f64::NAN) <= eps_risk && get_num(&m, "burden").unwrap_or(f64::NAN) <= eps_burden {
            stop = Some("converged");
        } else if !((asked.len() as f64) < max_q) {
            stop = Some("budget");
        } else {
            match l.next_question()? {
                None => stop = Some("no-disagreement"),
                Some(q) => {
                    let y = answer(&q)?;
                    l.observe(&q["outcome"], y, "elicitation", None)?;
                    asked.push(q);
                }
            }
        }
    }
    let (audit_asked, exhausted) = audit_round(l, &mut *answer, o, &mut asked)?;
    let stop = if exhausted { "budget" } else { stop.unwrap_or("budget") };
    let n_asked = asked.len();
    Ok(obj(vec![
        ("stop", jstr(stop)),
        ("questions", jn(n_asked as f64)),
        ("auditQuestions", jn(audit_asked as f64)),
        ("seedQuestions", jn(seed_questions as f64)),
        ("asked", Value::Array(asked)),
    ]))
}

/// The audit round on its own (spec 4.2c): `(questions asked, budget exhausted)`. Appends to `asked`.
pub fn audit_round(l: &mut IntentLearner, answer: &mut dyn FnMut(&Value) -> R<i64>, o: &Value, asked: &mut Vec<Value>) -> R<(usize, bool)> {
    let mut n = 0usize;
    if !truthy(get(o, "audit")) {
        return Ok((0, false));
    }
    let eps_risk = get_num(o, "epsRisk").ok_or("elicit: epsRisk must be a number")?;
    let max_q = get_num(o, "maxQuestions").ok_or("elicit: maxQuestions must be a number")?;
    loop {
        let pending = l.unconfirmed_grant_cells();
        let mut mass = 0.0;
        for x in &pending {
            mass += x.2;
        }
        if pending.is_empty() || mass <= eps_risk {
            return Ok((n, false));
        }
        if !((asked.len() as f64) < max_q) {
            return Ok((n, true));
        }
        let top = &pending[0];
        let vs = l.omega.verb(&top.0).ok_or("audit: unknown verb")?.clone();
        let outcome = cell_rep(&vs, &top.1)?;
        let p = l.acceptance(&outcome);
        let q = obj(vec![("verb", jstr(&top.0)), ("cell", jarr_usize(&top.1)), ("outcome", outcome.clone()), ("p", jn(p)), ("score", jn(top.2))]);
        let y = answer(&q)?;
        l.observe(&outcome, y, "elicitation", None)?;
        asked.push(q);
        n += 1;
    }
}
