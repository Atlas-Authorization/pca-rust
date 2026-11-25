//! `Math.pow` of the reference runtime: fdlibm's `__ieee754_pow` (e_pow.c), statement for statement with the same constants, plus
//! the reference language's rule that `(+-1) ** +-Infinity` is NaN. Method: `log2(x)` to extra precision as `t1 + t2`,
//! `y * log2(x) = n + y'` with `|y'| <= 0.5`, `x**y = 2**n * exp(y' * ln2)`. No fused multiply-add is used. Constants are given by
//! their bit patterns. Re-exported as [`crate::wallet_omega::fdlibm::pow`].

fn hi(x: f64) -> i32 {
    (x.to_bits() >> 32) as i32
}
fn lo(x: f64) -> i32 {
    x.to_bits() as u32 as i32
}
fn with_hi(x: f64, h: i32) -> f64 {
    f64::from_bits(((h as u32 as u64) << 32) | (x.to_bits() & 0xffff_ffff))
}
fn lo0(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & 0xffff_ffff_0000_0000)
}
fn b(bits: u64) -> f64 {
    f64::from_bits(bits)
}

/// fdlibm `scalbn` for a finite non-zero normal `x` and a result that is subnormal or zero (the only use here).
fn scalbn_down(x: f64, n: i32) -> f64 {
    let hx = hi(x);
    let k = ((hx & 0x7ff0_0000) >> 20).wrapping_add(n);
    if k > 0 {
        return with_hi(x, (hx & 0x800f_ffffu32 as i32) | (k << 20));
    }
    if k <= -54 {
        return if x < 0.0 { -0.0 } else { 0.0 }; // underflow
    }
    with_hi(x, (hx & 0x800f_ffffu32 as i32) | ((k + 54) << 20)) * b(0x3c90_0000_0000_0000)
    // * 2**-54
}

/// `Math.pow(x, y)`.
pub fn pow(x: f64, y: f64) -> f64 {
    const SIGNIF: i32 = 0x7fff_ffff;
    // y == zero: x**0 = 1
    if y == 0.0 {
        return 1.0;
    }
    // NaN propagates
    if x.is_nan() || y.is_nan() {
        return x + y;
    }

    let y_abs = y.abs();
    let mut x_abs = x.abs();
    // special values of y
    if y == 2.0 {
        return x * x;
    } else if y == 0.5 {
        if x >= -f64::MAX {
            return (x + 0.0).sqrt(); // x == -infinity is handled later; + 0.0 for x == -0.0
        }
    } else if y_abs == 1.0 {
        return if y == 1.0 { x } else { 1.0 / x };
    } else if y_abs == f64::INFINITY {
        if x_abs == 1.0 {
            return y - y; // (+-1)**+-inf is NaN
        } else if x_abs > 1.0 {
            return if y >= 0.0 { y } else { 0.0 }; // (|x| > 1)**+-inf = inf, 0
        } else {
            return if y < 0.0 { -y } else { 0.0 }; // (|x| < 1)**-+inf = inf, 0
        }
    }

    let hx = hi(x);
    let mut ix = hx & SIGNIF;

    // y_is_int = 0: y is not an integer, 1: y is an odd integer, 2: y is an even integer (only needed for x < 0)
    let mut y_is_int: i32 = 0;
    if hx < 0 {
        if y_abs >= b(0x4340_0000_0000_0000) {
            y_is_int = 2; // even: ulp(2^53) = 2
        } else if y_abs >= 1.0 {
            let y_abs_as_long = y_abs as i64;
            if y_abs_as_long as f64 == y_abs {
                y_is_int = 2 - (y_abs_as_long & 1) as i32;
            }
        }
    }

    // special values of x
    if x_abs == 0.0 || x_abs == f64::INFINITY || x_abs == 1.0 {
        let mut z = x_abs; // x is +-0, +-inf, +-1
        if y < 0.0 {
            z = 1.0 / z;
        }
        if hx < 0 {
            if (ix.wrapping_sub(0x3ff0_0000) | y_is_int) == 0 {
                z = (z - z) / (z - z); // (-1)**non-int is NaN
            } else if y_is_int == 1 {
                z = -1.0 * z; // (x < 0)**odd = -(|x|**odd)
            }
        }
        return z;
    }

    let mut n: i32 = (hx >> 31).wrapping_add(1);
    // (x < 0)**(non-int) is NaN
    if (n | y_is_int) == 0 {
        return (x - x) / (x - x);
    }

    let mut s = 1.0; // sign of the result: -1 for (negative)**(odd integer)
    if (n | (y_is_int - 1)) == 0 {
        s = -1.0;
    }

    let t1: f64;
    let t2: f64;
    // |y| is huge
    if y_abs > b(0x41e0_0000_ffff_ffff) {
        // |y| > ~2**31
        let inv_ln2 = b(0x3ff7_1547_652b_82fe); // 1.44269504088896338700e+00 = 1/ln2
        let inv_ln2_h = b(0x3ff7_1547_0000_0000); // 1.4426946640014648438 = 21 bits of 1/ln2
        let inv_ln2_l = b(0x3e99_4ae0_bf85_ddf4); // 3.7688749856360991145e-07 = 1/ln2 tail
                                                  // over/underflow if x is not close to one
        if x_abs < b(0x3fef_ffff_0000_0000) {
            return if y < 0.0 { s * f64::INFINITY } else { s * 0.0 };
        }
        if x_abs > b(0x3ff0_0000_ffff_ffff) {
            return if y > 0.0 { s * f64::INFINITY } else { s * 0.0 };
        }
        // now |1 - x| is tiny <= 2**-20: log(x) by x - x^2/2 + x^3/3 - x^4/4
        let t = x_abs - 1.0; // t has 20 trailing zeros
        let w = (t * t) * (0.5 - t * (b(0x3fd5_5555_5555_5555) - t * 0.25));
        let u = inv_ln2_h * t; // inv_ln2_h has 21 significant bits
        let v = t * inv_ln2_l - w * inv_ln2;
        let t1v = lo0(u + v);
        t1 = t1v;
        t2 = v - (t1v - u);
    } else {
        let cp = b(0x3fee_c709_dc3a_03fd); //  9.61796693925975554329e-01 = 2/(3 ln2)
        let cp_h = b(0x3fee_c709_e000_0000); //  9.61796700954437255859e-01 = (float)cp
        let cp_l = b(0xbe3e_2fe0_145b_01f5); // -7.02846165095275826516e-09 = tail of cp_h
        n = 0;
        // subnormal x
        if ix < 0x0010_0000 {
            x_abs *= b(0x4340_0000_0000_0000);
            n -= 53;
            ix = hi(x_abs);
        }
        n += (ix >> 20) - 0x3ff;
        let j = ix & 0x000f_ffff;
        // determine the interval
        ix = j | 0x3ff0_0000; // normalize ix
        let k: i32;
        if j <= 0x3988E {
            k = 0; // |x| < sqrt(3/2)
        } else if j < 0xBB67A {
            k = 1; // |x| < sqrt(3)
        } else {
            k = 0;
            n += 1;
            ix -= 0x0010_0000;
        }
        x_abs = with_hi(x_abs, ix);

        // ss = s_h + s_l = (x - 1)/(x + 1) or (x - 1.5)/(x + 1.5)
        let dp_h = b(0x3fe2_b803_4000_0000); // 5.84962487220764160156e-01
        let dp_l = b(0x3e4c_fdeb_43cf_d006); // 1.35003920212974897128e-08
                                             // polynomial coefficients for (3/2)*(log(x) - 2s - 2/3*s**3)
        let l1 = b(0x3fe3_3333_3333_3303); // 5.99999999999994648725e-01
        let l2 = b(0x3fdb_6db6_db6f_abff); // 4.28571428578550184252e-01
        let l3 = b(0x3fd5_5555_518f_264d); // 3.33333329818377432918e-01
        let l4 = b(0x3fd1_7460_a91d_4101); // 2.72728123808534006489e-01
        let l5 = b(0x3fcd_864a_93c9_db65); // 2.30660745775561754067e-01
        let l6 = b(0x3fca_7e28_4a45_4eef); // 2.06975017800338417784e-01
        let k_d = k as f64;
        let bp_k = 1.0 + 0.5 * k_d; // BP[0] = 1.0, BP[1] = 1.5
        let mut u = x_abs - bp_k;
        let mut v = 1.0 / (x_abs + bp_k);
        let ss = u * v;
        let s_h = lo0(ss);
        // t_h = x_abs + BP[k], high part
        let mut t_h = with_hi(0.0, ((ix >> 1) | 0x2000_0000) + 0x0008_0000 + (k << 18));
        let mut t_l = x_abs - (t_h - bp_k);
        let s_l = v * ((u - s_h * t_h) - s_h * t_l);
        // log(x_abs)
        let mut s2 = ss * ss;
        let mut r = s2 * s2 * (l1 + s2 * (l2 + s2 * (l3 + s2 * (l4 + s2 * (l5 + s2 * l6)))));
        r += s_l * (s_h + ss);
        s2 = s_h * s_h;
        t_h = lo0(3.0 + s2 + r);
        t_l = r - ((t_h - 3.0) - s2);
        // u + v = ss * (1 + ...)
        u = s_h * t_h;
        v = s_l * t_h + t_l * ss;
        // 2/(3 log2) * (ss + ...)
        let p_h = lo0(u + v);
        let p_l = v - (p_h - u);
        let z_h = cp_h * p_h; // cp_h + cp_l = 2/(3 log2)
        let z_l = cp_l * p_h + p_l * cp + dp_l * k_d;
        // log2(x_abs) = (ss + ...) * 2/(3 log2) = n + dp_h + z_h + z_l
        let t = n as f64;
        let t1v = lo0(((z_h + z_l) + dp_h * k_d) + t);
        t1 = t1v;
        t2 = z_l - (((t1v - t) - dp_h * k_d) - z_h);
    }

    // split y into y1 + y2 and compute (y1 + y2) * (t1 + t2)
    let y1 = lo0(y);
    let p_l = (y - y1) * t1 + y * t2;
    let mut p_h = y1 * t1;
    let mut z = p_l + p_h;
    let mut j = hi(z);
    let i = lo(z);
    if j >= 0x4090_0000 {
        // z >= 1024
        if (j.wrapping_sub(0x4090_0000) | i) != 0 {
            return s * f64::INFINITY; // z > 1024: overflow
        } else {
            let ovt = b(0x3c97_1547_652b_82fe); // 8.0085662595372944372e-17 = -(1024 - log2(ovfl + .5ulp))
            if p_l + ovt > z - p_h {
                return s * f64::INFINITY; // overflow
            }
        }
    } else if (j & SIGNIF) >= 0x4090_cc00 {
        // z <= -1075
        if (j.wrapping_sub(0xc090_cc00u32 as i32) | i) != 0 {
            return s * 0.0; // z < -1075: underflow
        } else if p_l <= z - p_h {
            return s * 0.0; // underflow
        }
    }

    // 2**(p_h + p_l)
    let p1 = b(0x3fc5_5555_5555_553e); //  1.66666666666666019037e-01
    let p2 = b(0xbf66_c16c_16be_bd93); // -2.77777777770155933842e-03
    let p3 = b(0x3f11_566a_af25_de2c); //  6.61375632143793436117e-05
    let p4 = b(0xbebb_bd41_c5d2_6bf1); // -1.65339022054652515390e-06
    let p5 = b(0x3e66_3769_72be_a4d0); //  4.13813679705723846039e-08
    let lg2 = b(0x3fe6_2e42_fefa_39ef); //  6.93147180559945286227e-01
    let lg2_h = b(0x3fe6_2e43_0000_0000); //  6.93147182464599609375e-01
    let lg2_l = b(0xbe20_5c61_0ca8_6c39); // -1.90465429995776804525e-09
    let i = j & SIGNIF;
    let mut k = (i >> 20) - 0x3ff;
    n = 0;
    if i > 0x3fe0_0000 {
        // |z| > 0.5: n = [z + 0.5]
        n = j.wrapping_add(0x0010_0000 >> (k + 1));
        k = ((n & SIGNIF) >> 20) - 0x3ff; // new k for n
        let t = with_hi(0.0, n & !(0x000f_ffff >> k));
        n = ((n & 0x000f_ffff) | 0x0010_0000) >> (20 - k);
        if j < 0 {
            n = -n;
        }
        p_h -= t;
    }
    let t = lo0(p_l + p_h);
    let u = t * lg2_h;
    let v = (p_l - (t - p_h)) * lg2 + t * lg2_l;
    z = u + v;
    let w = v - (z - u);
    let t = z * z;
    let t1 = z - t * (p1 + t * (p2 + t * (p3 + t * (p4 + t * p5))));
    let r = (z * t1) / (t1 - 2.0) - (w + z * w);
    z = 1.0 - (r - z);
    j = hi(z).wrapping_add(n.wrapping_shl(20));
    if (j >> 20) <= 0 {
        z = scalbn_down(z, n); // subnormal output
    } else {
        z = with_hi(z, hi(z).wrapping_add(n.wrapping_shl(20)));
    }
    s * z
}

#[cfg(test)]
mod tests {
    use super::pow;

    #[test]
    fn exact_points_and_special_values() {
        assert_eq!(pow(2.0, 10.0), 1024.0);
        assert_eq!(pow(2.0, -20.0), 9.5367431640625e-07);
        assert_eq!(pow(2.0, -1074.0), 5e-324);
        assert_eq!(pow(2.0, -1075.0), 0.0);
        assert_eq!(pow(2.0, 1023.0), 8.98846567431158e307);
        assert_eq!(pow(2.0, 1024.0), f64::INFINITY);
        assert_eq!(pow(0.5, 3.0), 0.125);
        assert_eq!(pow(10.0, 2.0), 100.0);
        assert!(pow(-8.0, 1.0 / 3.0).is_nan());
        assert_eq!(pow(-2.0, 3.0), -8.0);
        assert_eq!(pow(-2.0, 4.0), 16.0);
        assert_eq!(pow(7.0, 0.0), 1.0);
        assert_eq!(pow(f64::NAN, 0.0), 1.0);
        assert!(pow(1.0, f64::INFINITY).is_nan()); // the reference language's rule, unlike C
        assert!(pow(-1.0, f64::NEG_INFINITY).is_nan());
        assert!(pow(2.0, f64::NAN).is_nan());
        assert_eq!(pow(0.5, f64::INFINITY), 0.0);
        assert_eq!(pow(0.5, f64::NEG_INFINITY), f64::INFINITY);
        assert_eq!(pow(0.0, -1.0), f64::INFINITY);
        assert!(pow(-0.0, 3.0).is_sign_negative());
        assert_eq!(pow(4.0, 0.5), 2.0);
        // bit patterns recorded from the reference runtime (general path, huge |y|, subnormal result)
        assert_eq!(pow(0.99609375, 512.0).to_bits(), 0x3fc1_4155_15ff_d9b3);
        assert_eq!(pow(0.5, 1024.0).to_bits(), 0x0004_0000_0000_0000);
        assert_eq!(pow(1.5, -2.5).to_bits(), 0x3fd7_398b_f1d1_ee70);
        assert_eq!(
            pow(3.0, 0.3333333333333333).to_bits(),
            0x3ff7_1374_4912_3ef6
        );
        assert_eq!(pow(1.0000001, 3e9).to_bits(), 0x5afc_05a5_6d67_53a4);
        assert_eq!(pow(0.75, -1030.5).to_bits(), 0x5aa9_ec34_cbe1_5ec8);
        assert_eq!(pow(2.0, -1060.5).to_bits(), 0x0000_0000_0000_2d41);
    }
}
