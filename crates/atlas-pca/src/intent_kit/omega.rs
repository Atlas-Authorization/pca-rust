//! The intent outcome space (omega): typed dimensions, cells, representatives, the workload and harm measures (the default harm
//! model), a seeded generator and the derivation from policies + slots. Native port of `@atlasauth/pca-intent` omega.ts.
use super::*;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub const OTHER: &str = "\u{22a5}";
const EXACT_SPAN: f64 = 4096.0;
const EULER_GAMMA: f64 = 0.5772156649015329;

#[derive(Clone, Debug, PartialEq)]
pub struct CatVal {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Dim {
    Num { path: String, lo: f64, hi: f64, cuts: Vec<f64>, dist: Option<String>, cells: Vec<(f64, f64)> },
    Cat { path: String, values: Vec<CatVal> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerbSpace {
    pub verb: String,
    pub reversibility: Option<String>,
    pub weight: f64,
    pub dims: Vec<Dim>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Omega {
    pub verbs: Vec<VerbSpace>,
    pub approximate: Vec<String>,
}

/// The ordered cells of a numeric dimension (inclusive integer ranges; empty cells dropped).
pub fn num_cells_of(lo: f64, hi: f64, cuts: &[f64]) -> Vec<(f64, f64)> {
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

pub fn num_dim(path: &str, lo: f64, hi: f64, cuts: Vec<f64>, dist: Option<String>) -> Dim {
    let cells = num_cells_of(lo, hi, &cuts);
    Dim::Num { path: path.to_string(), lo, hi, cuts, dist, cells }
}

impl Dim {
    pub fn path(&self) -> &str {
        match self {
            Dim::Num { path, .. } | Dim::Cat { path, .. } => path,
        }
    }
    pub fn is_num(&self) -> bool {
        matches!(self, Dim::Num { .. })
    }
    pub fn cell_count(&self) -> usize {
        match self {
            Dim::Num { cells, .. } => cells.len(),
            Dim::Cat { values, .. } => values.len(),
        }
    }
    /// The law of the dimension is log-uniform (and its domain is non-negative).
    pub fn log(&self) -> bool {
        match self {
            Dim::Num { dist, lo, .. } => dist.as_deref() == Some("loguniform") && *lo >= 0.0,
            _ => false,
        }
    }
    pub fn to_json(&self) -> Value {
        match self {
            Dim::Num { path, lo, hi, cuts, dist, .. } => {
                let mut m = Map::new();
                m.insert("kind".into(), jstr("num"));
                m.insert("path".into(), jstr(path));
                m.insert("lo".into(), jn(*lo));
                m.insert("hi".into(), jn(*hi));
                m.insert("cuts".into(), Value::Array(cuts.iter().map(|c| jn(*c)).collect()));
                if let Some(d) = dist {
                    m.insert("dist".into(), jstr(d));
                }
                Value::Object(m)
            }
            Dim::Cat { path, values } => obj(vec![
                ("kind", jstr("cat")),
                ("path", jstr(path)),
                ("values", Value::Array(values.iter().map(|v| obj(vec![("kind", jstr(&v.kind)), ("value", jstr(&v.value))])).collect())),
            ]),
        }
    }
    pub fn from_json(v: &Value) -> R<Dim> {
        let path = get_str(v, "path").ok_or("omega: a dimension needs a string path")?.to_string();
        match get_str(v, "kind") {
            Some("num") => {
                let lo = get_num(v, "lo").ok_or("omega: a numeric dimension needs lo")?;
                let hi = get_num(v, "hi").ok_or("omega: a numeric dimension needs hi")?;
                let mut cuts = vec![];
                match get(v, "cuts") {
                    Some(Value::Array(a)) => {
                        for c in a {
                            cuts.push(num(c).ok_or("omega: cuts must be numbers")?);
                        }
                    }
                    None | Some(Value::Null) => {}
                    _ => return Err("omega: cuts must be an array".into()),
                }
                let dist = get_str(v, "dist").map(String::from);
                Ok(num_dim(&path, lo, hi, cuts, dist))
            }
            Some("cat") => {
                let mut values = vec![];
                match get(v, "values") {
                    Some(Value::Array(a)) => {
                        for x in a {
                            let kind = get_str(x, "kind").ok_or("omega: a categorical value needs a kind")?.to_string();
                            let value = get_str(x, "value").ok_or("omega: a categorical value needs a string value")?.to_string();
                            values.push(CatVal { kind, value });
                        }
                    }
                    _ => return Err("omega: a categorical dimension needs values".into()),
                }
                Ok(Dim::Cat { path, values })
            }
            _ => Err("omega: unknown dimension kind".into()),
        }
    }
}

impl VerbSpace {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("verb".into(), jstr(&self.verb));
        if let Some(r) = &self.reversibility {
            m.insert("reversibility".into(), jstr(r));
        }
        m.insert("weight".into(), jn(self.weight));
        m.insert("dims".into(), Value::Array(self.dims.iter().map(Dim::to_json).collect()));
        Value::Object(m)
    }
    pub fn from_json(v: &Value) -> R<VerbSpace> {
        let verb = get_str(v, "verb").ok_or("omega: a verb space needs a verb")?.to_string();
        let weight = get_num(v, "weight").ok_or("omega: a verb space needs a numeric weight")?;
        let reversibility = get_str(v, "reversibility").map(String::from);
        let mut dims = vec![];
        match get(v, "dims") {
            Some(Value::Array(a)) => {
                for d in a {
                    dims.push(Dim::from_json(d)?);
                }
            }
            _ => return Err("omega: a verb space needs dims".into()),
        }
        Ok(VerbSpace { verb, reversibility, weight, dims })
    }
}

impl Omega {
    pub fn to_json(&self) -> Value {
        obj(vec![
            ("v", jn(1.0)),
            ("verbs", Value::Array(self.verbs.iter().map(VerbSpace::to_json).collect())),
            ("approximate", Value::Array(self.approximate.iter().map(|s| jstr(s)).collect())),
        ])
    }
    pub fn from_json(v: &Value) -> R<Omega> {
        let mut verbs = vec![];
        match get(v, "verbs") {
            Some(Value::Array(a)) => {
                for x in a {
                    verbs.push(VerbSpace::from_json(x)?);
                }
            }
            _ => return Err("omega: verbs must be an array".into()),
        }
        let mut approximate = vec![];
        if let Some(Value::Array(a)) = get(v, "approximate") {
            for x in a {
                approximate.push(x.as_str().ok_or("omega: approximate must hold strings")?.to_string());
            }
        }
        Ok(Omega { verbs, approximate })
    }
    pub fn verb(&self, verb: &str) -> Option<&VerbSpace> {
        self.verbs.iter().find(|v| v.verb == verb)
    }
}

pub fn verb_cell_count(vs: &VerbSpace) -> usize {
    vs.dims.iter().map(Dim::cell_count).product()
}

pub fn decode_cell(vs: &VerbSpace, flat: usize) -> Vec<usize> {
    let mut idx = vec![0usize; vs.dims.len()];
    let mut f = flat;
    for i in (0..vs.dims.len()).rev() {
        let n = vs.dims[i].cell_count().max(1);
        idx[i] = f % n;
        f /= n;
    }
    idx
}

pub fn encode_cell(vs: &VerbSpace, idx: &[usize]) -> usize {
    let mut flat = 0usize;
    for (i, d) in vs.dims.iter().enumerate() {
        flat = flat * d.cell_count() + idx.get(i).copied().unwrap_or(0);
    }
    flat
}

/// Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > other).
pub fn cat_cell_of_vals(values: &[CatVal], s: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_len: i64 = -1;
    for (i, v) in values.iter().enumerate() {
        if v.kind == "exact" && v.value == s {
            return Some(i);
        }
        if v.kind == "prefix" && s.starts_with(v.value.as_str()) && (u16len(&v.value) as i64) > best_len {
            best = Some(i);
            best_len = u16len(&v.value) as i64;
        }
    }
    if best.is_some() {
        return best;
    }
    values.iter().position(|v| v.kind == "other")
}

pub fn cat_cell_of(d: &Dim, s: &str) -> Option<usize> {
    match d {
        Dim::Cat { values, .. } => cat_cell_of_vals(values, s),
        _ => None,
    }
}

/// Which cell a concrete value falls in, or None when it is outside the dimension's domain / type.
pub fn cell_of_value(d: &Dim, x: Option<&Value>) -> Option<usize> {
    let x = x?;
    match d {
        Dim::Num { cells, .. } => {
            let f = num(x)?;
            if !f.is_finite() {
                return None;
            }
            cells.iter().position(|(lo, hi)| f >= *lo && f <= *hi)
        }
        Dim::Cat { values, .. } => cat_cell_of_vals(values, x.as_str()?),
    }
}

/// The cell of an outcome `{verb, values}` (None outside the space).
pub fn cell_of(vs: &VerbSpace, o: &Value) -> Option<Vec<usize>> {
    let values = get(o, "values").and_then(Value::as_object);
    let mut idx = vec![];
    for d in &vs.dims {
        let x = values.and_then(|m| m.get(d.path()));
        idx.push(cell_of_value(d, x)?);
    }
    Some(idx)
}

pub fn cat_rep(d: &Dim, i: usize) -> R<String> {
    let values = match d {
        Dim::Cat { values, .. } => values,
        _ => return Err("catRep: not a categorical dimension".into()),
    };
    let v = values.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
    if v.kind == "exact" {
        return Ok(v.value.clone());
    }
    let base = if v.kind == "prefix" { format!("{}x", v.value) } else { "other".to_string() };
    for k in 0..64 {
        let s = if k == 0 { base.clone() } else { format!("{base}{k}") };
        if cat_cell_of(d, &s) == Some(i) {
            return Ok(s);
        }
    }
    Ok(base)
}

pub fn num_rep(d: &Dim, i: usize) -> R<f64> {
    match d {
        Dim::Num { cells, .. } => {
            let (lo, hi) = *cells.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
            Ok(if i > 0 { lo } else { hi })
        }
        _ => Err("numRep: not a numeric dimension".into()),
    }
}

pub fn rep_value(d: &Dim, i: usize) -> R<Value> {
    match d {
        Dim::Num { .. } => Ok(jn(num_rep(d, i)?)),
        Dim::Cat { .. } => Ok(Value::String(cat_rep(d, i)?)),
    }
}

/// A representative outcome of a cell: `{verb, values}`.
pub fn cell_rep(vs: &VerbSpace, idx: &[usize]) -> R<Value> {
    let mut values = Map::new();
    for (i, d) in vs.dims.iter().enumerate() {
        let k = *idx.get(i).ok_or("cellRep: cell index missing")?;
        values.insert(d.path().to_string(), rep_value(d, k)?);
    }
    Ok(obj(vec![("verb", jstr(&vs.verb)), ("values", Value::Object(values))]))
}

// ---- workload and harm (the default harm model) ----------------------------------------------------------------------------

fn point_weight(log: bool, x: f64) -> f64 {
    if log {
        1.0 / (x + 1.0)
    } else {
        1.0
    }
}

fn linear_amount(d: &Dim) -> bool {
    d.is_num() && (d.path() == "amount" || d.path().ends_with(".amount"))
}

/// The default harm model's verb factor `h_v`.
pub fn harm_verb(vs: &VerbSpace) -> f64 {
    match vs.reversibility.as_deref() {
        Some("irreversible") => 10.0,
        Some("rate_limited") => 3.0,
        _ => 1.0,
    }
}

fn harm_dim(d: &Dim, x: Option<f64>) -> f64 {
    match x {
        Some(x) if linear_amount(d) => 1.0 + js_max(0.0, x) / 100.0,
        _ => 1.0,
    }
}

fn harmonic(n: f64) -> f64 {
    if n <= 0.0 {
        return 0.0;
    }
    if n <= EXACT_SPAN {
        let mut s = 0.0;
        let mut k = n.trunc();
        while k >= 1.0 {
            s += 1.0 / k;
            k -= 1.0;
        }
        return s;
    }
    let n2 = n * n;
    crate::detmath::det_ln(n) + EULER_GAMMA + 1.0 / (2.0 * n) - 1.0 / (12.0 * n2) + 1.0 / (120.0 * n2 * n2) - 1.0 / (252.0 * n2 * n2 * n2)
}

/// Sum of the dimension's law over the integers a..b (0 for an empty interval).
pub fn interval_weight(log: bool, a: f64, b: f64) -> f64 {
    if b < a {
        return 0.0;
    }
    if !log {
        return b - a + 1.0;
    }
    if b - a + 1.0 <= EXACT_SPAN {
        let mut s = 0.0;
        let mut x = b.trunc();
        while x >= a {
            s += 1.0 / (x + 1.0);
            x -= 1.0;
        }
        return s;
    }
    harmonic(b + 1.0) - harmonic(a)
}

fn interval_first_moment(log: bool, a: f64, b: f64) -> f64 {
    if b < a {
        return 0.0;
    }
    if !log {
        return ((a + b) * (b - a + 1.0)) / 2.0;
    }
    b - a + 1.0 - interval_weight(log, a, b)
}

fn interval_mean_x(log: bool, a: f64, b: f64, cell_lo: f64) -> f64 {
    let whole = interval_weight(log, cell_lo, b);
    if whole > 0.0 {
        interval_first_moment(log, a, b) / whole
    } else {
        0.0
    }
}

fn dim_total(d: &Dim) -> f64 {
    match d {
        Dim::Num { lo, hi, .. } => interval_weight(d.log(), *lo, *hi),
        _ => 1.0,
    }
}

/// `(mu_d(cell), E[g_d | cell])` of one dimension cell. Categorical values are uniform.
pub fn dim_cell_stats(d: &Dim, i: usize) -> R<(f64, f64)> {
    match d {
        Dim::Cat { values, .. } => {
            if i >= values.len() {
                return Err(format!("cell index {i} out of range"));
            }
            Ok((1.0 / values.len() as f64, 1.0))
        }
        Dim::Num { cells, .. } => {
            let (lo, hi) = *cells.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
            let log = d.log();
            let wm = interval_weight(log, lo, hi);
            let h = if wm > 0.0 {
                if !linear_amount(d) {
                    1.0
                } else {
                    1.0 + js_max(0.0, interval_mean_x(log, js_max(lo, 0.0), hi, lo)) / 100.0
                }
            } else {
                harm_dim(d, Some(lo))
            };
            Ok((wm / dim_total(d), h))
        }
    }
}

/// `(mass, harm)` of a cell.
pub fn cell_stats(vs: &VerbSpace, idx: &[usize]) -> R<(f64, f64)> {
    let mut mass = vs.weight;
    let mut h = harm_verb(vs);
    for (k, d) in vs.dims.iter().enumerate() {
        let (m, g) = dim_cell_stats(d, *idx.get(k).ok_or("cellStats: cell index missing")?)?;
        mass *= m;
        h *= g;
    }
    Ok((mass, h))
}

/// The harm of a concrete outcome.
pub fn harm_of(vs: &VerbSpace, o: &Value) -> f64 {
    let mut h = harm_verb(vs);
    let values = get(o, "values").and_then(Value::as_object);
    for d in &vs.dims {
        let x = values.and_then(|m| m.get(d.path())).and_then(num);
        h *= harm_dim(d, x);
    }
    h
}

/// Upper bound `H_max` of the default harm model over the outcome space (needed by the Hoeffding bound); a categorical dimension without
/// values is refused (`max() arg is an empty sequence`), as `Math.max` over no values is in the reference.
pub fn harm_max(omega: &Omega) -> R<f64> {
    let mut m = 0.0f64;
    for vs in &omega.verbs {
        let mut f = harm_verb(vs);
        for d in &vs.dims {
            match d {
                Dim::Num { lo, hi, .. } => f *= js_max(harm_dim(d, Some(*lo)), harm_dim(d, Some(*hi))),
                Dim::Cat { values, .. } => {
                    if values.is_empty() {
                        return Err("max() arg is an empty sequence".into());
                    }
                    for i in 0..values.len() {
                        cat_rep(d, i)?;
                    }
                }
            }
        }
        m = js_max(m, f);
    }
    Ok(m)
}

/// The seeded PRNG (mulberry32), bit-identical to the reference.
pub struct Rng {
    state: u32,
}

impl Rng {
    pub fn new(seed: f64) -> Rng {
        Rng { state: (seed.trunc() as i64 as u64 & 0xFFFF_FFFF) as u32 }
    }
    pub fn next(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x6D2B_79F5);
        let mut t = self.state;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        ((t ^ (t >> 14)) as f64) / 4294967296.0
    }
}

fn quantile_value(d: &Dim, target: f64) -> f64 {
    let (lo_d, hi_d, cells) = match d {
        Dim::Num { lo, hi, cells, .. } => (*lo, *hi, cells),
        _ => return 0.0,
    };
    let _ = lo_d;
    let log = d.log();
    let mut acc = 0.0;
    for (ci, (lo, hi)) in cells.iter().enumerate() {
        let (lo, hi) = (*lo, *hi);
        let w = interval_weight(log, lo, hi);
        if target < acc + w || ci == cells.len() - 1 {
            let mut r = target - acc;
            if hi - lo + 1.0 <= EXACT_SPAN {
                let mut x = lo;
                while x < hi {
                    r -= point_weight(log, x);
                    if r < 0.0 {
                        return x;
                    }
                    x += 1.0;
                }
                return hi;
            }
            if !log {
                return js_min(hi, lo + r.floor());
            }
            let x = ((lo + 1.0) * crate::detmath::det_exp(r) - 1.0).floor();
            return js_max(lo, js_min(hi, x));
        }
        acc += w;
    }
    hi_d
}

/// Draw an outcome from the workload: `(verb space index, outcome)`.
pub fn sample_outcome<'a>(omega: &'a Omega, rng: &mut Rng) -> R<(&'a VerbSpace, Value)> {
    let mut u = rng.next();
    let mut vs = omega.verbs.last().ok_or("sampleOutcome: no verbs")?;
    for v in &omega.verbs {
        if u < v.weight {
            vs = v;
            break;
        }
        u -= v.weight;
    }
    let mut values = Map::new();
    for d in &vs.dims {
        match d {
            Dim::Cat { values: vals, .. } => {
                let n = vals.len();
                let i = ((n as f64 - 1.0).min((rng.next() * n as f64).floor())).max(0.0) as usize;
                values.insert(d.path().to_string(), Value::String(cat_rep(d, i)?));
            }
            Dim::Num { .. } => {
                let x = quantile_value(d, rng.next() * dim_total(d));
                values.insert(d.path().to_string(), jn(x));
            }
        }
    }
    Ok((vs, obj(vec![("verb", jstr(&vs.verb)), ("values", Value::Object(values))])))
}

// ---- derivation from policies + slots (the compiler pipeline's shared outcome space) -----------------------------------------

#[derive(Default)]
struct FieldLits {
    nums: Vec<f64>,
    exacts: Vec<String>,
    prefixes: Vec<String>,
}

fn push_num(v: &mut Vec<f64>, x: f64) {
    if !v.iter().any(|y| *y == x) {
        v.push(x);
    }
}

fn push_str(v: &mut Vec<String>, x: &str) {
    if !v.iter().any(|y| y == x) {
        v.push(x.to_string());
    }
}

type Lits = Vec<(String, FieldLits)>;

fn lits<'a>(m: &'a mut Lits, path: &str) -> &'a mut FieldLits {
    if let Some(i) = m.iter().position(|(p, _)| p == path) {
        return &mut m[i].1;
    }
    m.push((path.to_string(), FieldLits::default()));
    &mut m.last_mut().unwrap().1
}

fn add_num(f: &mut FieldLits, x: f64) {
    if x.is_finite() {
        push_num(&mut f.nums, x.floor());
        push_num(&mut f.nums, x.ceil());
    }
}

fn collect_cond(c: &Value, m: &mut Lits, approx: &mut BTreeSet<String>) {
    let Some(o) = c.as_object() else { return };
    if crate::predicates::is_group_condition(c) {
        if let Some(Value::Array(a)) = o.get("all_of") {
            for x in a {
                collect_cond(x, m, approx);
            }
        } else if let Some(Value::Array(a)) = o.get("any_of") {
            for x in a {
                collect_cond(x, m, approx);
            }
        } else if let Some(x) = o.get("not") {
            collect_cond(x, m, approx);
        }
        return;
    }
    let Some(field) = o.get("field").and_then(Value::as_str) else { return };
    let op = o.get("op").and_then(Value::as_str);
    if o.get("ref").is_some_and(|r| !r.is_null()) {
        approx.insert(format!("cross-field ref on {field}"));
    }
    if let Some(op) = op {
        if ["like", "matches", "is_a", "member_of"].contains(&op) {
            approx.insert(format!("{op} on {field}"));
        }
    }
    if op == Some("exists") {
        lits(m, field);
        return;
    }
    let f = lits(m, field);
    let value = o.get("value").cloned().unwrap_or(Value::Null);
    let vals: Vec<Value> = match value {
        Value::Array(a) => a,
        v => vec![v],
    };
    for v in &vals {
        if let Some(x) = num(v) {
            add_num(f, x);
        } else if let Some(s) = v.as_str() {
            if op == Some("prefix") {
                push_str(&mut f.prefixes, s);
            } else {
                push_str(&mut f.exacts, s);
            }
        }
    }
}

fn add_resource(r: Option<&str>, m: &mut Lits, approx: &mut BTreeSet<String>) {
    let Some(r) = r else { return };
    if r == "*" {
        return;
    }
    if r.starts_with("re:") {
        approx.insert("re: resource matcher".into());
        return;
    }
    let f = lits(m, "action.resource");
    match r.strip_suffix('*') {
        Some(p) => push_str(&mut f.prefixes, p),
        None => push_str(&mut f.exacts, r),
    }
}

/// `Some(None)` is the wildcard, `Some(Some(list))` explicit verbs.
fn verbs_of(p: &Value) -> Option<Vec<String>> {
    match get(p, "verb") {
        Some(Value::String(s)) => {
            if s == "*" {
                None
            } else {
                Some(vec![s.clone()])
            }
        }
        Some(Value::Array(a)) => {
            if a.iter().any(|x| x.as_str() == Some("*")) {
                None
            } else {
                Some(a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            }
        }
        _ => Some(vec![]),
    }
}

/// The built-in connector catalogue as `(verb, connector, reversibility, amount field, description)`.
pub const BUILTIN: [(&str, &str, &str, Option<&str>, &str); 21] = [
    ("stripe.charge", "stripe", "irreversible", Some("amount"), "Charge a customer. Refundable in practice, but a charge is treated as final."),
    ("stripe.refund", "stripe", "irreversible", Some("amount"), "Returns money for a charge to the customer."),
    ("stripe.payout", "stripe", "irreversible", Some("amount"), "Moves funds from a Stripe balance to a bank account."),
    ("stripe.create_customer", "stripe", "rate_limited", None, "Creates a customer record."),
    ("gmail.send", "gmail", "irreversible", None, "Sends an email to people outside your organisation."),
    ("gmail.draft", "gmail", "reversible", None, "Saves an email draft without sending it."),
    ("gmail.delete", "gmail", "irreversible", None, "Permanently deletes a message."),
    ("github.read", "github", "reversible", None, "Reads files from a repository."),
    ("github.create_pr", "github", "irreversible", None, "Opens a pull request, which is visible to everyone with access to the repository."),
    ("github.comment", "github", "irreversible", None, "Posts a comment, visible to everyone with access to the repository."),
    ("github.merge_pr", "github", "irreversible", None, "Merges a pull request, which can trigger deploys and other downstream effects."),
    ("github.delete_repo", "github", "irreversible", None, "Deletes a repository and everything in it."),
    ("slack.post_message", "slack", "irreversible", None, "Posts a message that members of the channel can read."),
    ("slack.read", "slack", "reversible", None, "Reads the message history of a channel."),
    ("calendar.create_event", "calendar", "irreversible", None, "Creates an event and sends invitations to its attendees."),
    ("calendar.delete_event", "calendar", "rate_limited", None, "Deletes a calendar event."),
    ("files.read", "files", "reversible", None, "Reads files."),
    ("files.write", "files", "rate_limited", None, "Writes or overwrites files."),
    ("files.delete", "files", "irreversible", None, "Deletes files."),
    ("http.get", "http", "reversible", None, "Fetches a URL."),
    ("http.post", "http", "rate_limited", None, "Posts a body to a URL."),
];

fn default_domain(path: &str) -> Option<(f64, f64, &'static str)> {
    match path {
        "action.params.amount" => Some((0.0, 100000.0, "loguniform")),
        "env.hour" => Some((0.0, 23.0, "uniform")),
        "action.params.count" => Some((0.0, 1000.0, "loguniform")),
        _ => None,
    }
}

fn norm_predicates(p: &Value) -> Vec<Value> {
    match get(p, "predicates") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![],
    }
}

fn sorted_u16(mut v: Vec<String>) -> Vec<String> {
    v.sort_by(|a, b| u16cmp(a, b));
    v
}

/// Derive the outcome space from the vocabulary of the policies and the intent slots (`opts` = `{policies, slots?, extraVerbs?, domains?}`;
/// the built-in catalogue). Wildcard verbs expand to the catalogue verbs of every connector that appears anywhere (or all of it).
pub fn derive_omega(opts: &Value) -> R<Omega> {
    let mut approx: BTreeSet<String> = BTreeSet::new();
    let mut preds: Vec<Value> = vec![];
    for p in get(opts, "policies").and_then(Value::as_array).ok_or("deriveOmega: policies must be an array")? {
        preds.extend(norm_predicates(p));
    }
    let slots = get(opts, "slots").filter(|s| s.is_object());
    let mut explicit: Vec<String> = vec![];
    let mut add = |v: &str, e: &mut Vec<String>| {
        if !e.iter().any(|x| x == v) {
            e.push(v.to_string());
        }
    };
    if let Some(Value::Array(a)) = get(opts, "extraVerbs") {
        for v in a {
            if let Some(s) = v.as_str() {
                add(s, &mut explicit);
            }
        }
    }
    let mut wildcard = false;
    for p in &preds {
        match verbs_of(p) {
            None => wildcard = true,
            Some(vs) => {
                for v in vs {
                    add(&v, &mut explicit);
                }
            }
        }
    }
    if let Some(Value::Array(a)) = slots.and_then(|s| get(s, "verbs")) {
        for v in a {
            if let Some(s) = v.as_str() {
                add(s, &mut explicit);
            }
        }
    }
    if wildcard {
        let connectors: BTreeSet<String> = explicit.iter().map(|v| v.split('.').next().unwrap_or("").to_string()).collect();
        for (verb, connector, _, _, _) in BUILTIN.iter() {
            if connectors.is_empty() || connectors.contains(*connector) {
                add(verb, &mut explicit);
            }
        }
    }
    let domains = get(opts, "domains");
    let mut out: Vec<VerbSpace> = vec![];
    for verb in sorted_u16(explicit) {
        let mut m: Lits = vec![];
        for p in &preds {
            if let Some(pv) = verbs_of(p) {
                if !pv.contains(&verb) {
                    continue;
                }
            }
            add_resource(get_str(p, "resource"), &mut m, &mut approx);
            if let Some(Value::Array(w)) = get(p, "where") {
                for c in w {
                    collect_cond(c, &mut m, &mut approx);
                }
            }
        }
        if let Some(Value::Array(cs)) = slots.and_then(|s| get(s, "constraints")) {
            for sc in cs {
                if let Some(v) = opt(sc, "verb") {
                    if v.as_str() != Some(verb.as_str()) {
                        continue;
                    }
                }
                let path = get_str(sc, "path").ok_or("deriveOmega: a slot constraint needs a path")?;
                let f = lits(&mut m, path);
                for k in ["max", "min"] {
                    if let Some(x) = opt(sc, k).and_then(num) {
                        add_num(f, x);
                    }
                }
                for (k, into_prefix) in [("oneOf", false), ("noneOf", false), ("prefixOneOf", true)] {
                    if let Some(Value::Array(a)) = get(sc, k) {
                        for x in a {
                            if let Some(s) = x.as_str() {
                                push_str(if into_prefix { &mut f.prefixes } else { &mut f.exacts }, s);
                            }
                        }
                    }
                }
            }
        }
        let mut dims: Vec<Dim> = vec![];
        let mut paths: Vec<String> = m.iter().map(|(p, _)| p.clone()).collect();
        paths.sort_by(|a, b| u16cmp(a, b));
        for path in paths {
            let f = &m.iter().find(|(p, _)| *p == path).unwrap().1;
            if !f.nums.is_empty() || (f.exacts.is_empty() && f.prefixes.is_empty() && default_domain(&path).is_some()) {
                let mut cuts = f.nums.clone();
                cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
                let dom = domains.and_then(|d| get(d, &path)).filter(|d| !d.is_null());
                let dflt = default_domain(&path);
                let max_cut = cuts.last().copied().unwrap_or(0.0);
                let min_cut = cuts.first().copied().unwrap_or(0.0);
                let dget = |k: &str| dom.and_then(|d| opt(d, k)).and_then(num);
                let lo = match dget("lo").or_else(|| if dom.is_none() { dflt.map(|d| d.0) } else { None }) {
                    Some(x) => x,
                    None => js_min(0.0, min_cut - 1.0),
                };
                let hi = match dget("hi").or_else(|| if dom.is_none() { dflt.map(|d| d.1) } else { None }) {
                    Some(x) => x,
                    None => js_max(js_max(10.0, 2.0 * max_cut), max_cut + 10.0),
                };
                let dist = dom
                    .and_then(|d| opt(d, "dist"))
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or_else(|| if dom.is_none() { dflt.map(|d| d.2.to_string()) } else { None })
                    .unwrap_or_else(|| if lo >= 0.0 { "loguniform".to_string() } else { "uniform".to_string() });
                let kept: Vec<f64> = cuts.into_iter().filter(|c| lo <= *c && *c <= hi).collect();
                dims.push(num_dim(&path, lo, hi, kept, Some(dist)));
            } else {
                let mut values: Vec<CatVal> = vec![];
                for v in sorted_u16(f.exacts.clone()) {
                    values.push(CatVal { kind: "exact".into(), value: v });
                }
                for v in sorted_u16(f.prefixes.clone()) {
                    values.push(CatVal { kind: "prefix".into(), value: v });
                }
                values.push(CatVal { kind: "other".into(), value: OTHER.into() });
                dims.push(Dim::Cat { path: path.clone(), values });
            }
        }
        let reversibility = BUILTIN.iter().find(|b| b.0 == verb).map(|b| b.2.to_string()).unwrap_or_else(|| "irreversible".to_string());
        out.push(VerbSpace { verb, reversibility: Some(reversibility), weight: 0.0, dims });
    }
    let n = out.len() as f64;
    for v in out.iter_mut() {
        v.weight = 1.0 / n;
    }
    Ok(Omega { verbs: out, approximate: sorted_u16(approx.into_iter().collect()) })
}

use std::cmp::Ordering;
