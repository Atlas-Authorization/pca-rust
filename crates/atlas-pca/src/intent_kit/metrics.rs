//! Measuring a grant against an intent: Monte Carlo and exact risk / burden / fidelity (the default harm model).
use super::omega::*;
use super::policy::*;
use super::*;
use crate::wallet_omega::fdlibm;
use serde_json::Value;

/// An acceptability oracle from a policy: 1 when the policy admits the outcome, else 0.
pub struct Acceptability {
    adm: Admitter,
}

impl Acceptability {
    pub fn call(&self, vs: &VerbSpace, o: &Value) -> R<f64> {
        Ok(if self.adm.admits(vs, o)? { 1.0 } else { 0.0 })
    }
}

pub fn acceptability_of(policy: &Value) -> R<Acceptability> {
    Ok(Acceptability { adm: admitter(policy)? })
}

pub fn hoeffding_half_width(range: f64, samples: f64, delta_prime: f64) -> f64 {
    let x = fdlibm::log(2.0 / delta_prime) / (2.0 * samples);
    range * if x.is_nan() || x < 0.0 { f64::NAN } else { x.sqrt() }
}

/// Monte Carlo risk / burden of `grant` against `acc`; `opts` = `{samples?, seed?, hMax?}`.
pub fn measure_grant(omega: &Omega, grant: &Value, acc: &Acceptability, opts: Option<&Value>) -> R<Value> {
    let nul = Value::Null;
    let opts = opts.unwrap_or(&nul);
    let m = opt(opts, "samples").and_then(num).unwrap_or(20000.0);
    let mut rng = Rng::new(opt(opts, "seed").and_then(num).unwrap_or(1.0));
    let g = admitter(grant)?;
    let (mut r, mut b, mut rm, mut h_max) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let mut i = 0.0;
    while i < m {
        let (vs, o) = sample_outcome(omega, &mut rng)?;
        let a = acc.call(vs, &o)?;
        let h = harm_of(vs, &o);
        h_max = js_max(h_max, h);
        if g.admits(vs, &o)? {
            r += (1.0 - a) * h;
        } else {
            b += a;
        }
        rm += (1.0 - a) * h;
        i += 1.0;
    }
    let (r, b, rm) = (r / m, b / m, rm / m);
    let hm = opt(opts, "hMax").and_then(num);
    Ok(obj(vec![
        ("risk", jn(r)),
        ("burden", jn(b)),
        ("riskMax", jn(rm)),
        ("fidelity", jn(if rm > 0.0 { 1.0 - r / rm } else { 1.0 })),
        ("samples", jn(m)),
        ("riskHalfWidth", jn(hoeffding_half_width(hm.unwrap_or(h_max), m, 0.05))),
    ]))
}

/// Exact R, B, R_max, F by summing over the cells (no sampling error).
pub fn measure_grant_exact(omega: &Omega, grant: &Value, acc: &Acceptability) -> R<Value> {
    let g = admitter(grant)?;
    let (mut r, mut b, mut rm, mut eh) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for vs in &omega.verbs {
        for c in 0..verb_cell_count(vs) {
            let idx = decode_cell(vs, c);
            let o = cell_rep(vs, &idx)?;
            let (mass, h) = cell_stats(vs, &idx)?;
            let a = acc.call(vs, &o)?;
            eh += mass * h;
            rm += mass * (1.0 - a) * h;
            if g.admits(vs, &o)? {
                r += mass * (1.0 - a) * h;
            } else {
                b += mass * a;
            }
        }
    }
    Ok(obj(vec![("risk", jn(r)), ("burden", jn(b)), ("riskMax", jn(rm)), ("fidelity", jn(if rm > 0.0 { 1.0 - r / rm } else { 1.0 })), ("meanHarm", jn(eh))]))
}
