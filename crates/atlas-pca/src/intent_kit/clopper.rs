//! Exact Clopper-Pearson upper bounds, computed in integer arithmetic at dyadic points q = a / 2^52 exactly as the formal definition is
//! stated; a floating-point bisection only supplies the starting guess.
use super::R;
use rsa::BigUint;

const GRID_BITS: u32 = 52;
const A: i128 = 1i128 << GRID_BITS;
const TOL_UNITS: i128 = 1i128 << (GRID_BITS - 44);

fn log_factorials(n: usize) -> Vec<f64> {
    let mut lf = vec![0.0f64; n + 1];
    for i in 1..=n {
        lf[i] = lf[i - 1] + (i as f64).ln();
    }
    lf
}

/// P(X <= k) for X ~ Binomial(n, p) in floating point (guesses only, never decisions).
fn binomial_cdf(k: f64, n: f64, p: f64, lf: &[f64]) -> f64 {
    if k >= n {
        return 1.0;
    }
    if k < 0.0 {
        return 0.0;
    }
    if p <= 0.0 {
        return 1.0;
    }
    if p >= 1.0 {
        return 0.0;
    }
    let lp = p.ln();
    let lq = (-p).ln_1p();
    let nn = n as usize;
    let mut s = 0.0;
    for i in 0..=(k.floor() as usize) {
        s += (lf[nn] - lf[i] - lf[nn - i] + i as f64 * lp + (n - i as f64) * lq).exp();
    }
    s.min(1.0)
}

/// The exact binary fraction of a finite double x in (0, 1): x = num / 2^exp.
fn double_to_dyadic(x: f64) -> R<(BigUint, u32)> {
    if !(x.is_finite() && x > 0.0 && x < 1.0) {
        return Err("doubleToDyadic: need 0 < x < 1".into());
    }
    let mut e = 0u32;
    let mut y = x;
    while y.fract() != 0.0 {
        y *= 2.0;
        e += 1;
        if e > 1100 {
            return Err("doubleToDyadic: not reached".into());
        }
    }
    Ok((BigUint::from(y as u64), e))
}

/// The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n).
fn cdf_rec_numerator(n: usize, k: usize, a: i128) -> R<BigUint> {
    if !(0..=A).contains(&a) {
        return Err("cdfRecNumerator: a must be in [0, 2^52]".into());
    }
    let ab = BigUint::from(a as u64);
    let bb = BigUint::from((A - a) as u64);
    let grid = BigUint::from(A as u64);
    let kk = k.min(n);
    let mut row: Vec<BigUint> = vec![BigUint::from(1u32); kk + 1];
    let mut pw = BigUint::from(1u32);
    for m in 0..n {
        let pw_next = &pw * &grid;
        let mut nxt: Vec<BigUint> = Vec::with_capacity(kk + 1);
        for j in 0..=kk {
            if j >= m + 1 {
                nxt.push(pw_next.clone());
            } else {
                let left = if j == 0 { BigUint::from(0u32) } else { row[j - 1].clone() };
                nxt.push(&ab * &left + &bb * &row[j]);
            }
        }
        row = nxt;
        pw = pw_next;
    }
    Ok(row[kk].clone())
}

/// Exactly decides alpha < cdfRec(a / 2^52, n, k).
fn cdf_exceeds(n: usize, k: usize, a: i128, alpha: &(BigUint, u32)) -> R<bool> {
    let nn = cdf_rec_numerator(n, k, a)?;
    let lhs = nn << (alpha.1 as usize);
    let mut rhs = alpha.0.clone();
    let grid = BigUint::from(A as u64);
    for _ in 0..n {
        rhs = rhs * &grid;
    }
    Ok(lhs > rhs)
}

fn float_guess(k: usize, n: usize, alpha: f64) -> f64 {
    let lf = log_factorials(n);
    let mut lo = k as f64 / n as f64;
    let mut hi = 1.0f64;
    let mut it = 0;
    while it < 200 && hi - lo > 1e-13 {
        let mid = (lo + hi) / 2.0;
        if binomial_cdf(k as f64, n as f64, mid, &lf) > alpha {
            lo = mid;
        } else {
            hi = mid;
        }
        it += 1;
    }
    hi
}

fn clamp(a: i128) -> i128 {
    a.clamp(0, A)
}

/// A bracket `(lo, hi)` of at most the tolerance around the point where `exceeds` (antitone) flips, from any start.
fn certify_bracket(start: i128, exceeds: &dyn Fn(i128) -> R<bool>) -> R<(i128, i128)> {
    let mut hi = start;
    let mut step = TOL_UNITS;
    while exceeds(hi)? {
        hi = clamp(hi + step);
        step *= 2;
    }
    let mut lo = clamp(hi - TOL_UNITS);
    step = TOL_UNITS;
    while lo > 0 && !exceeds(lo)? {
        hi = lo;
        lo = clamp(lo - step);
        step *= 2;
    }
    if lo == 0 && !exceeds(0)? {
        return Err("clopperPearsonUpper: unreachable (cdfRec(0) = 1)".into());
    }
    while hi - lo > TOL_UNITS {
        let mid = (lo + hi) / 2;
        if exceeds(mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok((lo, hi))
}

/// The exact one-sided upper bound at level alpha for k successes in n trials.
pub fn clopper_pearson_upper(k: u64, n: u64, alpha: f64) -> R<f64> {
    if k > n {
        return Err("clopperPearsonUpper: need integers 0 <= k <= n".into());
    }
    if !(alpha > 0.0 && alpha < 1.0) {
        return Err("clopperPearsonUpper: alpha must be in (0, 1)".into());
    }
    if n == 0 || k == n {
        return Ok(1.0);
    }
    let (ku, nu) = (k as usize, n as usize);
    let al = double_to_dyadic(alpha)?;
    let guess = float_guess(ku, nu, alpha);
    let start = clamp((guess * (A as f64)).ceil() as i128 + TOL_UNITS);
    let (_lo, hi) = certify_bracket(start, &|a| cdf_exceeds(nu, ku, a, &al))?;
    Ok(hi as f64 / (A as f64))
}
