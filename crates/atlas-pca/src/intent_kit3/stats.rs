//! Exact Clopper-Pearson upper bounds in integer arithmetic at dyadic points q = a / 2^52 (the definition as the formal statement
//! has it), the floating-point binomial CDF used only for starting guesses, the Hoeffding half-width and the Wilson interval.
//! Mirrors `clopper.ts` and the pure parts of `metrics.ts`. Logs / exps are the reference runtime's fdlibm.
use crate::wallet_omega::fdlibm;
use rsa::BigUint;

pub const GRID_BITS: u32 = 52;
const A: u64 = 1u64 << GRID_BITS;
const TOL_UNITS: u64 = 1u64 << (GRID_BITS - 44);

fn big(x: u64) -> BigUint {
    BigUint::from(x)
}

fn log_factorials(n: usize) -> Vec<f64> {
    let mut lf = vec![0.0; n + 1];
    for i in 1..=n {
        lf[i] = lf[i - 1] + fdlibm::log(i as f64);
    }
    lf
}

fn cdf_floats(k: f64, n: usize, p: f64, lf: &[f64]) -> f64 {
    if k >= n as f64 {
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
    let lp = fdlibm::log(p);
    let lq = (-p).ln_1p();
    let mut s = 0.0;
    let mut i = 0usize;
    while (i as f64) <= k {
        s += fdlibm::exp(lf[n] - lf[i] - lf[n - i] + i as f64 * lp + (n - i) as f64 * lq);
        i += 1;
    }
    s.min(1.0)
}

/// P(X <= k) for X ~ Binomial(n, p) in floating point (guesses and diagnostics, never decisions).
pub fn binomial_cdf(k: f64, n: i64, p: f64) -> f64 {
    if k >= n as f64 {
        return 1.0;
    }
    if k < 0.0 {
        return 0.0;
    }
    // n > k >= 0 here, so n is positive
    cdf_floats(k, n as usize, p, &log_factorials(n as usize))
}

/// The exact binary fraction of a finite double x in (0, 1): `(num, exp)` with x = num / 2^exp.
pub fn double_to_dyadic(x: f64) -> Result<(u64, u32), String> {
    if !(x.is_finite() && x > 0.0 && x < 1.0) {
        return Err("doubleToDyadic: need 0 < x < 1".into());
    }
    let bits = x.to_bits();
    let be = ((bits >> 52) & 0x7ff) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    let (mut m, mut e) = if be == 0 { (frac, -1074i64) } else { (frac | (1u64 << 52), be - 1075) };
    let tz = m.trailing_zeros() as i64;
    m >>= tz;
    e += tz;
    // x < 1 so e < 0 after normalisation (m odd)
    Ok((m, (-e).max(0) as u32))
}

/// The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n).
pub fn cdf_rec_numerator(n: usize, k: usize, a: &BigUint) -> Result<BigUint, String> {
    let top = big(A);
    if *a > top {
        return Err("cdfRecNumerator: a must be in [0, 2^52]".into());
    }
    let b = &top - a;
    let kk = k.min(n);
    let mut row: Vec<BigUint> = vec![big(1); kk + 1];
    let mut pw = big(1);
    for m in 0..n {
        let pw_next = &pw * &top;
        let mut next: Vec<BigUint> = Vec::with_capacity(kk + 1);
        for j in 0..=kk {
            if j > m {
                next.push(pw_next.clone());
            } else {
                let left = if j == 0 { big(0) } else { row[j - 1].clone() };
                next.push(a * &left + &b * &row[j]);
            }
        }
        row = next;
        pw = pw_next;
    }
    Ok(row[kk].clone())
}

/// Exactly decides alpha < cdfRec(a / 2^52, n, k), alpha = num / 2^exp.
pub fn cdf_exceeds(n: usize, k: usize, a: &BigUint, num: &BigUint, exp: u32) -> Result<bool, String> {
    let nn = cdf_rec_numerator(n, k, a)?;
    let mut an = big(1);
    for _ in 0..n {
        an = an * big(A);
    }
    Ok(nn * (big(1) << exp as usize) > num * an)
}

fn float_guess(k: i64, n: i64, alpha: f64) -> f64 {
    let lf = log_factorials(n as usize);
    let mut lo = k as f64 / n as f64;
    let mut hi = 1.0;
    let mut it = 0;
    while it < 200 && hi - lo > 1e-13 {
        let mid = (lo + hi) / 2.0;
        if cdf_floats(k as f64, n as usize, mid, &lf) > alpha {
            lo = mid;
        } else {
            hi = mid;
        }
        it += 1;
    }
    hi
}

fn clamp(a: i128) -> u64 {
    a.clamp(0, A as i128) as u64
}

/// A bracket `(hi, lo)` of at most the tolerance around the point where `exceeds` (antitone) flips, from any start.
pub fn certify_bracket(start: u64, exceeds: &dyn Fn(u64) -> bool) -> Result<(u64, u64), String> {
    let tol = TOL_UNITS as i128;
    let mut hi = start;
    let mut step = tol;
    while exceeds(hi) {
        hi = clamp(hi as i128 + step);
        step *= 2;
    }
    let mut lo = clamp(hi as i128 - tol);
    step = tol;
    while lo > 0 && !exceeds(lo) {
        hi = lo;
        lo = clamp(lo as i128 - step);
        step *= 2;
    }
    if lo == 0 && !exceeds(0) {
        return Err("clopperPearsonUpper: unreachable (cdfRec(0) = 1)".into());
    }
    while hi - lo > TOL_UNITS {
        let mid = lo + (hi - lo) / 2;
        if exceeds(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok((hi, lo))
}

/// The bound with its certificate: `(upper, upperUnits, lowerUnits)`.
pub fn clopper_pearson_certified(k: f64, n: f64, alpha: f64) -> Result<(f64, u64, u64), String> {
    if !(k.is_finite() && n.is_finite() && k.fract() == 0.0 && n.fract() == 0.0 && k >= 0.0 && n >= 0.0 && k <= n) {
        return Err("clopperPearsonUpper: need integers 0 <= k <= n".into());
    }
    if !(alpha > 0.0 && alpha < 1.0) {
        return Err("clopperPearsonUpper: alpha must be in (0, 1)".into());
    }
    if n == 0.0 || k == n {
        return Ok((1.0, A, A));
    }
    let (ki, ni) = (k as i64, n as i64);
    let (num, exp) = double_to_dyadic(alpha)?;
    let (bn, bk) = (ni as usize, ki as usize);
    let g = float_guess(ki, ni, alpha);
    let start = clamp(((g * 4_503_599_627_370_496.0).ceil() as i128) + TOL_UNITS as i128);
    let numb = big(num);
    let (hi, lo) = certify_bracket(start, &|a| cdf_exceeds(bn, bk, &big(a), &numb, exp).unwrap_or(false))?;
    Ok((hi as f64 / 4_503_599_627_370_496.0, hi, lo))
}

pub fn clopper_pearson_upper(k: f64, n: f64, alpha: f64) -> Result<f64, String> {
    clopper_pearson_certified(k, n, alpha).map(|c| c.0)
}

/// `range * sqrt(ln(2 / delta) / (2 samples))` (`delta` defaults to 0.05).
pub fn hoeffding_half_width(range: f64, samples: f64, delta_prime: f64) -> f64 {
    range * (fdlibm::log(2.0 / delta_prime) / (2.0 * samples)).sqrt()
}

/// Wilson score interval `(p, lo, hi)` for k/n (default z = 1.959963984540054); `n <= 0` gives (NaN, 0, 1).
pub fn wilson_interval(k: f64, n: f64, z: f64) -> (f64, f64, f64) {
    if !(n > 0.0) {
        return (f64::NAN, 0.0, 1.0);
    }
    let p = k / n;
    let z2 = z * z;
    let den = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / den;
    let half = (z * ((p * (1.0 - p)) / n + z2 / (4.0 * n * n)).sqrt()) / den;
    (p, f64::max(0.0, centre - half), f64::min(1.0, centre + half))
}
