//! Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2): one vote per principal, cell and period; a central
//! (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner. A port of the reference
//! (@atlasauth/pca-wallet, population.ts). Votes, releases and priors are plain JSON with the reference's member names; the randomness
//! source is an injected closure (`Err` ends the call, as a throwing source does in the reference). The transcendental functions are the
//! bit-exact fdlibm ones of [`crate::wallet_omega::fdlibm`].
//!
//! API: [`population_cell_key`], [`crypto_rand`], [`gaussian`], [`gaussian_sigma`], [`PopulationAggregator`] (`contribute`, `release`),
//! [`rr_keep_probability`], [`randomized_response`], [`debias_randomized_response`], [`population_prior`] ([`PopulationPrior`]).
//!
//! shortcut: the Gaussian draw's `cos` is the platform cosine (the fdlibm module has no cosine): it can differ from the reference in the
//! last bit, so a replay compares those numbers with a relative tolerance.
use crate::wallet::{coords_of_cell, is_b64u32, BETA_MAX, POPULATION_VOTE_DOMAIN};
use crate::wallet_omega::{decode_cell, fdlibm, num, verb_cell_count};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::f64::consts::PI;

pub type Rand = Box<dyn FnMut() -> Result<f64, String>>;

/// `Math.round`.
fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

/// `Number.isInteger`.
fn is_integer(v: Option<&Value>) -> bool {
    v.and_then(num).is_some_and(|f| f.is_finite() && f == f.floor())
}

fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// Strict equality of two JSON values as the reference's `===` (numbers by value; an object or array equals nothing).
fn strict_eq(a: Option<&Value>, b: &Value) -> bool {
    match (a, b) {
        (Some(Value::Null), Value::Null) => true,
        (Some(Value::Bool(x)), Value::Bool(y)) => x == y,
        (Some(Value::Number(_)), Value::Number(_)) => num(a.unwrap_or(&Value::Null)) == num(b),
        (Some(Value::String(x)), Value::String(y)) => x == y,
        _ => false,
    }
}

/// The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.
pub fn population_cell_key(schema_digest: &str, vs: &Value, idx: &[usize]) -> Result<String, String> {
    let body = json!({ "d": POPULATION_VOTE_DOMAIN, "s": schema_digest, "v": vs["verb"], "c": coords_of_cell(vs, idx)? });
    crate::hash_canonical_strict(&body).ok_or_else(|| "canonicalize: value outside the strict profile".to_string())
}

/// Uniform in (0, 1) from 53 random bits of the OS CSPRNG.
pub fn crypto_rand() -> Result<f64, String> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|e| format!("no randomness: {e}"))?;
    let hi = (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) >> 5) as f64;
    let lo = (u32::from_be_bytes([b[4], b[5], b[6], b[7]]) >> 6) as f64;
    Ok((hi * 67_108_864.0 + lo + 0.5) / 9_007_199_254_740_992.0)
}

/// A standard normal draw (Box-Muller) from a uniform source.
pub fn gaussian(rand: &mut dyn FnMut() -> Result<f64, String>) -> Result<f64, String> {
    let mut u = rand()?;
    while u <= 0.0 {
        u = rand()?;
    }
    let v = rand()?;
    Ok((-2.0 * fdlibm::log(u)).sqrt() * (2.0 * PI * v).cos())
}

/// Sigma of the Gaussian mechanism for L2 sensitivity (needs epsilon in (0, 1), delta in (0, 1), sensitivity > 0).
pub fn gaussian_sigma(epsilon: f64, delta: f64, l2_sensitivity: f64) -> Result<f64, String> {
    if !(epsilon > 0.0 && epsilon < 1.0) {
        return Err("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)".into());
    }
    if !(delta > 0.0 && delta < 1.0) {
        return Err("gaussianSigma: delta must be in (0, 1)".into());
    }
    if !(l2_sensitivity > 0.0) {
        return Err("gaussianSigma: sensitivity must be > 0".into());
    }
    Ok(l2_sensitivity * (2.0 * fdlibm::log(1.25 / delta)).sqrt() / epsilon)
}

/// One period's votes: one vote per principal and cell, a cap on the cells per principal, a (epsilon, delta)-DP release.
pub struct PopulationAggregator {
    schema_digest: String,
    period: Value,
    max_cells: f64,
    rand: Rand,
    votes: HashMap<String, (f64, f64)>,
    per_principal: HashMap<String, HashSet<String>>,
}

impl PopulationAggregator {
    /// `opts` is `{maxCellsPerPrincipal?}` (default 32); `rand` defaults to [`crypto_rand`].
    pub fn new(schema_digest: &Value, period: &Value, opts: Option<&Value>, rand: Option<Rand>) -> Result<Self, String> {
        if !is_b64u32(schema_digest) {
            return Err("PopulationAggregator: schemaDigest must be a canonical b64u digest".into());
        }
        let mc = opts.and_then(|o| o.get("maxCellsPerPrincipal")).filter(|v| !v.is_null());
        let max_cells = match mc {
            None => 32.0,
            Some(v) if is_integer(Some(v)) && num(v).is_some_and(|f| f > 0.0) => num(v).unwrap_or(32.0),
            Some(_) => return Err("PopulationAggregator: maxCellsPerPrincipal must be a positive integer".into()),
        };
        Ok(Self {
            schema_digest: schema_digest.as_str().unwrap_or("").to_string(),
            period: period.clone(),
            max_cells,
            rand: rand.unwrap_or_else(|| Box::new(crypto_rand)),
            votes: HashMap::new(),
            per_principal: HashMap::new(),
        })
    }

    /// Accept a vote `{principal, schemaDigest, cellKey, y, period}`: `{ok: true}` or `{ok: false, reason}` (a second vote on a cell, a
    /// vote past the per-principal cell cap, a foreign schema or period, a bad y or an anonymous principal).
    pub fn contribute(&mut self, v: &Value) -> Value {
        let no = |r: String| json!({ "ok": false, "reason": r });
        if v.get("schemaDigest").and_then(Value::as_str) != Some(self.schema_digest.as_str()) {
            return no("vote for another schema".into());
        }
        if !strict_eq(v.get("period"), &self.period) {
            return no("vote for another period".into());
        }
        let y = match v.get("y").and_then(num).filter(|y| *y == 0.0 || *y == 1.0) {
            Some(y) if v["y"].is_number() => y,
            _ => return no("y must be 0 or 1".into()),
        };
        let principal = match v.get("principal").and_then(Value::as_str).filter(|p| !p.is_empty()) {
            Some(p) => p.to_string(),
            None => return no("an accountable principal is required".into()),
        };
        let key = match v.get("cellKey") {
            Some(Value::String(s)) => s.clone(),
            other => format!("\u{0}{}", crate::js_stringify(other.unwrap_or(&Value::Null))),
        };
        let mine = self.per_principal.entry(principal).or_default();
        if mine.contains(&key) {
            return no("one vote per principal per cell per period (sensitivity 1)".into());
        }
        if mine.len() as f64 >= self.max_cells {
            return no(format!("at most {} cells per principal per period", crate::intent_v2::js_number_string(self.max_cells)));
        }
        mine.insert(key.clone());
        let c = self.votes.entry(key).or_insert((0.0, 0.0));
        *c = (c.0 + y, c.1 + 1.0);
        json!({ "ok": true })
    }

    /// The (epsilon, delta)-DP release `{epsilon, delta, qMin?, minCount?}`. A cell whose noisy count is below `minCount` is suppressed;
    /// `Err` where the reference throws (a bad epsilon, delta or qMin, or a failing randomness source).
    pub fn release(&mut self, opts: &Value) -> Result<Value, String> {
        let nan_of = |k: &str| opts.get(k).and_then(num).unwrap_or(f64::NAN);
        let sensitivity = (2.0 * self.max_cells).sqrt();
        let sigma = gaussian_sigma(nan_of("epsilon"), nan_of("delta"), sensitivity)?;
        let q_min = match opts.get("qMin").filter(|v| !v.is_null()) {
            None => 0.02,
            Some(v) => num(v).unwrap_or(f64::NAN),
        };
        if !(q_min > 0.0 && q_min < 0.5) {
            return Err("release: qMin must be in (0, 0.5)".into());
        }
        let min_count = match opts.get("minCount").filter(|v| !v.is_null()) {
            None => 3.0 * sigma,
            Some(v) => num(v).unwrap_or(f64::NAN),
        };
        let mut keys: Vec<&String> = self.votes.keys().collect();
        keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let mut cells = Map::new();
        for key in keys {
            let (yes0, total0) = self.votes[key];
            let yes = yes0 + sigma * gaussian(&mut *self.rand)?;
            let total = total0 + sigma * gaussian(&mut *self.rand)?;
            if !(total >= min_count) {
                continue;
            }
            cells.insert(key.clone(), json!({ "q": js_min(1.0 - q_min, js_max(q_min, yes / total)), "n": js_round(total) }));
        }
        Ok(json!({
            "v": 1, "kind": "pca-intent-population-prior", "schema": self.schema_digest, "period": self.period,
            "epsilon": opts.get("epsilon").cloned().unwrap_or(Value::Null), "delta": opts.get("delta").cloned().unwrap_or(Value::Null),
            "sigma": sigma, "sensitivity": sensitivity, "cells": cells
        }))
    }
}

// ---- local DP ------------------------------------------------------------------------------------------------------------------------

/// The probability randomized response keeps the true answer: e^eps / (1 + e^eps).
pub fn rr_keep_probability(epsilon: f64) -> Result<f64, String> {
    if !(epsilon > 0.0 && epsilon.is_finite()) {
        return Err("randomized response: epsilon must be > 0".into());
    }
    Ok(fdlibm::exp(epsilon) / (1.0 + fdlibm::exp(epsilon)))
}

/// epsilon-LDP randomized response: report y with probability e^eps / (1 + e^eps), else 1 - y.
pub fn randomized_response(y: f64, epsilon: f64, rand: &mut dyn FnMut() -> Result<f64, String>) -> Result<f64, String> {
    let r = rand()?;
    Ok(if r < rr_keep_probability(epsilon)? { y } else { 1.0 - y })
}

/// Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1).
pub fn debias_randomized_response(yes_reports: f64, total: f64, epsilon: f64) -> Result<f64, String> {
    let int = |x: f64| x.is_finite() && x == x.floor();
    if !(int(yes_reports) && int(total) && total > 0.0 && yes_reports >= 0.0 && yes_reports <= total) {
        return Err("debias: bad counts".into());
    }
    let p = rr_keep_probability(epsilon)?;
    Ok((yes_reports / total - (1.0 - p)) / (2.0 * p - 1.0))
}

// ---- the mixture prior ---------------------------------------------------------------------------------------------------------------

/// The learner's `priorMix` for a release: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]} over the released
/// cells of the verb (unreleased cells contribute the constant 1/2 and drop out), mixed with weight `beta` <= BETA_MAX < 1.
pub struct PopulationPrior {
    pub beta: f64,
    release: Value,
    /// Per verb: the released flat cell indices with ln q and ln (1 - q).
    tables: HashMap<String, (Vec<usize>, Vec<f64>, Vec<f64>)>,
}

pub fn population_prior(release: &Value, beta: f64) -> Result<PopulationPrior, String> {
    if !(beta >= 0.0 && beta <= BETA_MAX) {
        return Err(format!("populationPrior: beta must be in [0, {}] (full support needs beta < 1)", crate::intent_v2::js_number_string(BETA_MAX)));
    }
    Ok(PopulationPrior { beta, release: release.clone(), tables: HashMap::new() })
}

impl PopulationPrior {
    /// The prior weight of the hypothesis holding exactly the flat cells of `vs` for which `contains` is true.
    pub fn weight(&mut self, vs: &Value, contains: &dyn Fn(usize) -> bool) -> Result<f64, String> {
        let verb = vs["verb"].as_str().unwrap_or("").to_string();
        if !self.tables.contains_key(&verb) {
            let schema = self.release["schema"].as_str().unwrap_or("").to_string();
            let (mut cells, mut lq, mut lnq) = (vec![], vec![], vec![]);
            for c in 0..verb_cell_count(vs) {
                let key = population_cell_key(&schema, vs, &decode_cell(vs, c))?;
                let Some(r) = self.release["cells"].get(&key).filter(|r| crate::wallet_omega::truthy(r)) else { continue };
                let q = r.get("q").and_then(num).unwrap_or(f64::NAN);
                cells.push(c);
                lq.push(fdlibm::log(q));
                lnq.push(fdlibm::log(1.0 - q));
            }
            self.tables.insert(verb.clone(), (cells, lq, lnq));
        }
        let (cells, lq, lnq) = &self.tables[&verb];
        let mut lw = 0.0;
        for i in 0..cells.len() {
            lw += if contains(cells[i]) { lq[i] } else { lnq[i] };
        }
        Ok(fdlibm::exp(lw))
    }
}

// ---- views over a pca-intent learner ---------------------------------------------------------------------------------------------

type LR<T> = Result<T, String>;

/// `learnerView`: the wallet channel's `GrantView` over a learner, with an optional ceiling predicate (`true` = inside every ceiling).
pub struct LearnerView<'a> {
    learner: &'a mut crate::intent_kit::learner::IntentLearner,
    inside_ceiling: Option<&'a dyn Fn(&str, &[usize]) -> bool>,
}

/// `learnerView`.
pub fn learner_view<'a>(
    learner: &'a mut crate::intent_kit::learner::IntentLearner,
    inside_ceiling: Option<&'a dyn Fn(&str, &[usize]) -> bool>,
) -> LearnerView<'a> {
    LearnerView { learner, inside_ceiling }
}

impl LearnerView<'_> {
    fn rep(&self, verb: &str, idx: &[usize]) -> LR<Value> {
        let vs = self.learner.omega.verbs.iter().find(|v| v.verb == verb).ok_or_else(|| format!("learnerView: unknown verb {verb}"))?;
        crate::intent_kit::omega::cell_rep(vs, idx).map_err(|e| e.to_string())
    }

    /// The learner's acceptance probability of the cell.
    pub fn p(&mut self, verb: &str, idx: &[usize]) -> LR<f64> {
        let rep = self.rep(verb, idx)?;
        Ok(self.learner.acceptance(&rep))
    }

    pub fn vetoed(&self, verb: &str, idx: &[usize]) -> LR<bool> {
        Ok(self.learner.is_vetoed(&self.rep(verb, idx)?))
    }

    /// Outside a ceiling: the negation of the supplied predicate (never outside when none is supplied).
    pub fn outside_ceiling(&self, verb: &str, idx: &[usize]) -> bool {
        self.inside_ceiling.is_some_and(|f| !f(verb, idx))
    }

    /// The cells the learner has confirmed into the grant: `(verb, cell)`.
    pub fn confirmed(&mut self) -> Vec<(String, Vec<usize>)> {
        self.learner.cells().into_iter().filter(|c| c.in_grant).map(|c| (c.verb, c.cell)).collect()
    }
}

/// `priorAdmittedPpm`: the mu-mass (ppm) of cells admitted only because of the population prior, that is in the grant with the prior and not
/// without it, after the same observations. Zero at tau = 1 under noise-free answers; the map reports it as `metrics.prior_admitted_ppm`.
/// `opts(false)` are the base learner options without the prior, `opts(true)` the same with the prior mix.
pub fn prior_admitted_ppm(
    omega: &crate::intent_kit::omega::Omega,
    opts: &dyn Fn(bool) -> crate::intent_kit::learner::LearnerOpts,
    observations: &[Value],
) -> LR<f64> {
    use crate::intent_kit::learner::IntentLearner;
    let mut without = IntentLearner::replay(omega, opts(false), observations).map_err(|e| e.to_string())?;
    let mut with = IntentLearner::replay(omega, opts(true), observations).map_err(|e| e.to_string())?;
    let (a, b) = (without.cells(), with.cells());
    let mass: f64 = b.iter().zip(&a).filter(|(c, base)| c.in_grant && !base.in_grant).map(|(c, _)| c.mass).sum();
    Ok((mass * 1_000_000.0).round())
}
