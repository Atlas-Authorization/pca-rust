//! DETERMINISTIC MATH (the rule every language follows; the reference is `detmath.ts` of the intent package). libm's log, exp, log2 and
//! pow are not correctly rounded and differ in the last digit between implementations, which moves a decision that sits on a boundary.
//! These functions use only integer arithmetic: fixed point with 96 fractional bits, TRUNCATING division (toward zero), and one final
//! conversion of the integer to a double with round-to-nearest-even followed by an exact power-of-two scaling.
//!
//! - [`det_ln`]: `x = m * 2^E`, `m = M / 2^52` in [1, 2) (`M` the 53-bit significand); `ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52))`,
//!   atanh summed as `z + z^3/3 + z^5/5 + ...` (z fixed point, `z2 = (z*z) / 2^96` truncated) until a term is 0; `LN2 = 2 * atanh(1/3)`.
//! - [`det_log2`]: the same fixed value divided by `LN2` in fixed point (`(fixed * 2^96) / LN2`, truncating).
//! - [`det_exp`]: `X = trunc(x * 2^96)`; `k = floor((X + LN2/2) / LN2)`; `r = X - k * LN2`; `e^r` is the sum of `r^n / n!` with
//!   `term_0 = 2^96`, `term_n = trunc(trunc(term_{n-1} * r / 2^96) / n)` until a term is 0; the result is `Number(sum) * 2^(k - 96)`.
//! - [`det_pow_int`]: `1` multiplied by `b`, `n` times, in sequence.
//!
//! Big integers are `rsa::BigUint` (the crate's existing big-integer dependency) with a sign carried separately.

use rsa::BigUint;
use std::sync::OnceLock;

const FRAC: usize = 96;

fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

fn one() -> BigUint {
    big(1) << FRAC
}

/// A signed integer: sign and magnitude (zero is never negative).
#[derive(Clone)]
struct Z {
    neg: bool,
    mag: BigUint,
}

impl Z {
    fn new(neg: bool, mag: BigUint) -> Z {
        let z = mag == big(0);
        Z { neg: neg && !z, mag }
    }
    fn pos(mag: BigUint) -> Z {
        Z::new(false, mag)
    }
    fn is_zero(&self) -> bool {
        self.mag == big(0)
    }
    fn add(&self, o: &Z) -> Z {
        if self.neg == o.neg {
            return Z::new(self.neg, &self.mag + &o.mag);
        }
        if self.mag >= o.mag {
            Z::new(self.neg, &self.mag - &o.mag)
        } else {
            Z::new(o.neg, &o.mag - &self.mag)
        }
    }
    fn negate(&self) -> Z {
        Z::new(!self.neg, self.mag.clone())
    }
    fn sub(&self, o: &Z) -> Z {
        self.add(&o.negate())
    }
    fn mul(&self, o: &Z) -> Z {
        Z::new(self.neg != o.neg, &self.mag * &o.mag)
    }
    /// BigInt `/`: truncates toward zero.
    fn div_trunc(&self, o: &Z) -> Z {
        Z::new(self.neg != o.neg, &self.mag / &o.mag)
    }
    /// Floor division by a positive divisor.
    fn div_floor_pos(&self, d: &BigUint) -> Z {
        let q = &self.mag / d;
        let rem = &self.mag - &q * d;
        if self.neg && rem != big(0) {
            Z::new(true, q + big(1))
        } else {
            Z::new(self.neg, q)
        }
    }
}

/// `Number(bigint)`: the magnitude rounded to the nearest double, ties to even.
fn mag_to_f64(n: &BigUint) -> f64 {
    let bits = n.bits();
    if bits <= 64 {
        return low64(n) as f64; // u64 -> f64 rounds to nearest even
    }
    let shift = bits - 64;
    let top = n.clone() >> shift;
    let sticky = (n - (top.clone() << shift)) != big(0);
    // the 64 top bits with the discarded tail folded into the lowest bit: only the 11 bits below a double's 53 matter, and a set
    // sticky bit there turns an exact half into "above half"
    let t = low64(&top) | u64::from(sticky);
    (t as f64) * pow2(shift as i32)
}

fn low64(n: &BigUint) -> u64 {
    n.to_bytes_le().iter().take(8).rev().fold(0u64, |a, b| (a << 8) | u64::from(*b))
}

/// 2^k as a double (exact for -1022 <= k <= 1023; beyond that it saturates to 0 or infinity as IEEE scaling would).
fn pow2(k: i32) -> f64 {
    if k > 1023 {
        f64::INFINITY
    } else if k >= -1022 {
        f64::from_bits(((1023 + k) as u64) << 52)
    } else {
        // subnormal range: two exact steps
        f64::from_bits(1u64 << 52) * pow2(k + 1022) // 2^-1022 * 2^(k+1022)
    }
}

fn to_f64(z: &Z) -> f64 {
    let v = mag_to_f64(&z.mag);
    if z.neg {
        -v
    } else {
        v
    }
}

/// `2 * atanh(num / den)` in fixed point (num, den non-negative).
fn atanh2(num: &BigUint, den: &BigUint) -> BigUint {
    let z = (num.clone() << FRAC) / den;
    let z2 = (&z * &z) >> FRAC;
    let mut term = z;
    let mut sum = big(0);
    let mut i = 1u64;
    while term != big(0) {
        sum += &term / big(i);
        term = (&term * &z2) >> FRAC;
        i += 2;
    }
    sum * big(2)
}

fn ln2() -> &'static BigUint {
    static LN2: OnceLock<BigUint> = OnceLock::new();
    LN2.get_or_init(|| atanh2(&big(1), &big(3)))
}

/// The fixed-point ln of a positive finite double (an integer scaled by 2^96), or `None`.
fn ln_fixed(x: f64) -> Option<Z> {
    if !(x > 0.0) || x == f64::INFINITY {
        return None;
    }
    let (mut y, mut scale) = (x, 0i64);
    if y < f64::MIN_POSITIVE {
        y *= 18_446_744_073_709_551_616.0; // 2^64, exact
        scale = 64;
    }
    let bits = y.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i64 - 1023 - scale;
    let m = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let two52 = big(1u64 << 52);
    let frac = atanh2(&(big(m) - &two52), &(big(m) + &two52));
    let base = Z::new(e < 0, big(e.unsigned_abs()) * ln2());
    Some(base.add(&Z::pos(frac)))
}

/// `ln x`: the same bit pattern on every platform. 0 and -0 give -infinity, x < 0 or NaN gives NaN, +infinity gives +infinity, 1 gives
/// exactly 0.
pub fn det_ln(x: f64) -> f64 {
    if x == 0.0 {
        return f64::NEG_INFINITY; // +0 and -0, as Math.log
    }
    if !(x > 0.0) {
        return f64::NAN;
    }
    if x == f64::INFINITY {
        return x;
    }
    if x == 1.0 {
        return 0.0;
    }
    to_f64(&ln_fixed(x).expect("positive finite")) / pow2(FRAC as i32)
}

/// `log2 x` (an exact power of two gives its exponent exactly).
pub fn det_log2(x: f64) -> f64 {
    if x == 0.0 {
        return f64::NEG_INFINITY; // +0 and -0, as Math.log2
    }
    if !(x > 0.0) {
        return f64::NAN;
    }
    if x == f64::INFINITY {
        return x;
    }
    if x == 1.0 {
        return 0.0;
    }
    let l = ln_fixed(x).expect("positive finite");
    let q = Z::new(l.neg, (l.mag.clone() << FRAC) / ln2());
    to_f64(&q) / pow2(FRAC as i32)
}

/// `e^x`. x > 709.782712893384 gives +infinity, x < -745.2 (and -infinity) gives 0, NaN gives NaN.
pub fn det_exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > 709.782712893384 {
        return f64::INFINITY;
    }
    if x < -745.2 {
        return 0.0;
    }
    if x == 0.0 {
        return 1.0;
    }
    // X = trunc(x * 2^96): |x| * 2^96 = m * 2^sh
    let bits = x.abs().to_bits();
    let be = ((bits >> 52) & 0x7ff) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    let m = if be == 0 { frac } else { frac | (1u64 << 52) };
    let sh = (if be == 0 { 1 } else { be }) - 1075 + FRAC as i64;
    let mag = if sh >= 0 { big(m) << sh as usize } else { big(m) >> (-sh) as usize };
    let xf = Z::new(x < 0.0, mag);
    let ln2 = ln2();
    let k = xf.add(&Z::pos(ln2 / big(2))).div_floor_pos(ln2);
    let r = xf.sub(&k.mul(&Z::pos(ln2.clone())));
    let one_z = Z::pos(one());
    let (mut term, mut sum) = (one_z.clone(), one_z.clone());
    let mut n = 1u64;
    while !term.is_zero() {
        term = term.mul(&r).div_trunc(&one_z).div_trunc(&Z::pos(big(n)));
        sum = sum.add(&term);
        n += 1;
    }
    let kn = if k.neg { -(low64(&k.mag) as i64) } else { low64(&k.mag) as i64 };
    let e = (kn - FRAC as i64) as i32;
    let half = e / 2; // truncating, as Math.trunc(e / 2)
    to_f64(&sum) * pow2(half) * pow2(e - half)
}

/// `b^n` for an integer n >= 0: `1` multiplied by `b`, n times, in sequence (IEEE multiplication is exactly rounded).
pub fn det_pow_int(b: f64, n: u64) -> f64 {
    let mut r = 1.0f64;
    for _ in 0..n {
        r *= b;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_values_and_edge_cases() {
        assert_eq!(det_ln(1.0), 0.0);
        assert_eq!(det_log2(1.0), 0.0);
        assert_eq!(det_exp(0.0), 1.0);
        for k in [-1022i64, -64, -3, -1, 1, 2, 10, 52, 1023] {
            assert_eq!(det_log2(f64::from_bits(((1023 + k) as u64) << 52)), k as f64, "2^{k}");
        }
        assert_eq!(det_log2(f64::from_bits(1)), -1074.0); // the smallest subnormal, 2^-1074
        assert!(det_ln(-1.0).is_nan() && det_ln(f64::NAN).is_nan());
        assert!(det_log2(-1.0).is_nan() && det_log2(f64::NAN).is_nan() && det_log2(f64::NEG_INFINITY).is_nan());
        for z in [0.0f64, -0.0] {
            assert_eq!(det_ln(z), f64::NEG_INFINITY);
            assert_eq!(det_log2(z), f64::NEG_INFINITY);
        }
        assert_eq!(det_exp(f64::NEG_INFINITY), 0.0);
        // a prior-mix cell with q = 0 or q = 1 weighs 0: exp(-infinity)
        assert_eq!(det_exp(det_ln(0.0)), 0.0);
        assert_eq!(det_exp(det_ln(1.0 - 1.0)), 0.0);
        assert_eq!(det_ln(f64::INFINITY), f64::INFINITY);
        assert_eq!(det_exp(710.0), f64::INFINITY);
        assert_eq!(det_exp(-746.0), 0.0);
        assert!(det_exp(f64::NAN).is_nan());
        assert_eq!(det_pow_int(0.5, 3), 0.125);
        assert_eq!(det_pow_int(7.0, 0), 1.0);
    }

    #[test]
    fn within_a_few_ulps_of_libm_and_consistent() {
        let close = |a: f64, b: f64| (a - b).abs() <= 4.0 * f64::EPSILON * b.abs().max(1e-300);
        for x in [0.001, 0.1, 0.5, 0.9, 1.5, 2.0, 3.0, 10.0, 1234.5, 1e10, 1e-10, 1e300] {
            assert!(close(det_ln(x), x.ln()), "ln {x}");
            assert!(close(det_log2(x), x.log2()), "log2 {x}");
        }
        for x in [-700.0, -20.5, -1.0, -0.001, 0.001, 0.5, 1.0, 2.0, 10.0, 100.0, 700.0] {
            assert!(close(det_exp(x), x.exp()), "exp {x}");
        }
        // exp inverts ln to within an ulp or two and ln of e^1 is 1
        assert!(close(det_exp(det_ln(37.0)), 37.0));
        assert!((det_ln(det_exp(1.0)) - 1.0).abs() <= 4.0 * f64::EPSILON);
    }

    #[test]
    fn rounding_of_a_big_integer_is_nearest_even() {
        // 2^64 + 2^11 is exactly half of a double's spacing at 2^64 above 2^64: ties go to the even significand (down); one more is above half
        let tie = (big(1) << 64usize) + (big(1) << 11usize);
        assert_eq!(mag_to_f64(&tie), 18_446_744_073_709_551_616.0);
        let above = tie.clone() + big(1);
        assert_eq!(mag_to_f64(&above), 18_446_744_073_709_551_616.0 + 4096.0);
        let odd_tie = (big(1) << 64usize) + (big(3) << 11usize);
        assert_eq!(mag_to_f64(&odd_tie), 18_446_744_073_709_551_616.0 + 8192.0);
    }
}
