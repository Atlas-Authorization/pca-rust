//! The outcome space the wallet resolves question cells against (the Omega of the intent layer), the separable harm model and the exact
//! Clopper-Pearson bound, as the wallet needs them. Mirrors the TypeScript reference for the members the wallet uses. Omega, verb spaces
//! (`vs`) and dimensions (`d`) are plain JSON (`&serde_json::Value`). Floats follow the reference operation by operation (IEEE-754
//! doubles); the transcendental functions are the fdlibm ones the reference runtime uses ([`fdlibm`]), so the doubles are identical.
//!
//! Helpers a second wallet module can call: [`is_number`], [`is_finite_number`], [`is_safe_int`], [`is_int`], [`num`], [`truthy`],
//! [`u16len`], [`js_entries`], [`num_cells`], [`cell_count`], [`verb_cell_count`], [`decode_cell`], [`cat_cell_of`], [`cell_of_value`],
//! [`cell_of`], [`cell_rep`], [`cell_stats`], [`label_of`], [`clopper_pearson_upper`], [`fdlibm`].
//!
//! shortcut: only the default harm model (verb factor 10 / 3 / 1, amounts scale as 1 + x/100) is ported; a caller-supplied harm model is not.
//! shortcut: `(^|\.)amount$` is matched as "path == amount or ends with .amount" (the reference regex has no trailing-newline case here).
use rsa::BigUint;
use serde_json::{json, Map, Value};

/// A JSON null to borrow.
pub static NULL: Value = Value::Null;
pub const OTHER: &str = "\u{22a5}";
pub const EXACT_SPAN: i64 = 4096;
const EULER_GAMMA: f64 = 0.577_215_664_901_532_9;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

// ---- fdlibm (the algorithms of the reference runtime's Math.log / exp / sin / log2, with the fused multiply-adds its arm64 build uses) ---------------------------------------------

pub mod fdlibm {
    pub use crate::fdlibm_pow::pow;
    fn hi(x: f64) -> i32 {
        (x.to_bits() >> 32) as i32
    }
    fn lo(x: f64) -> u32 {
        x.to_bits() as u32
    }
    fn with_hi(x: f64, h: i32) -> f64 {
        f64::from_bits(((h as u32 as u64) << 32) | (x.to_bits() & 0xffff_ffff))
    }
    fn with_lo_zero(x: f64) -> f64 {
        f64::from_bits(x.to_bits() & 0xffff_ffff_0000_0000)
    }

    const TWO54: f64 = 1.801_439_850_948_198_4e16;
    const LN2_HI: f64 = 6.931_471_803_691_238_164_90e-01;
    const LN2_LO: f64 = 1.908_214_929_270_587_700_02e-10;
    const LG1: f64 = 6.666_666_666_666_735_130e-01;
    const LG2: f64 = 3.999_999_999_940_941_908e-01;
    const LG3: f64 = 2.857_142_874_366_239_149e-01;
    const LG4: f64 = 2.222_219_843_214_978_396e-01;
    const LG5: f64 = 1.818_357_216_161_805_012e-01;
    const LG6: f64 = 1.531_383_769_920_937_332e-01;
    const LG7: f64 = 1.479_819_860_511_658_591e-01;

    /// `Math.log`.
    pub fn log(x0: f64) -> f64 {
        let mut x = x0;
        let mut hx = hi(x);
        let lx = lo(x);
        let mut k: i32 = 0;
        if hx < 0x0010_0000 {
            if ((hx & 0x7fff_ffff) as u32 | lx) == 0 {
                return f64::NEG_INFINITY;
            }
            if hx < 0 {
                return f64::NAN;
            }
            k -= 54;
            x *= TWO54;
            hx = hi(x);
        }
        if hx >= 0x7ff0_0000 {
            return x + x;
        }
        k += (hx >> 20) - 1023;
        hx &= 0x000f_ffff;
        let mut i = (hx + 0x95f64) & 0x10_0000;
        x = with_hi(x, hx | (i ^ 0x3ff0_0000));
        k += i >> 20;
        let f = x - 1.0;
        if (0x000f_ffff & (2 + hx)) < 3 {
            if f == 0.0 {
                if k == 0 {
                    return 0.0;
                }
                let dk = k as f64;
                return dk.mul_add(LN2_HI, dk * LN2_LO);
            }
            let r = f * f * (-0.333_333_333_333_333_33f64).mul_add(f, 0.5);
            if k == 0 {
                return f - r;
            }
            let dk = k as f64;
            return dk.mul_add(LN2_HI, -((-dk).mul_add(LN2_LO, r) - f));
        }
        let s = f / (2.0 + f);
        let dk = k as f64;
        let z = s * s;
        i = hx - 0x6147a;
        let w = z * z;
        let j = 0x6b851 - hx;
        let t1 = w * w.mul_add(w.mul_add(LG6, LG4), LG2);
        let t2 = z * w.mul_add(w.mul_add(w.mul_add(LG7, LG5), LG3), LG1);
        i |= j;
        let r = t2 + t1;
        if i > 0 {
            let hfsq = 0.5 * f * f;
            if k == 0 {
                f - (-s).mul_add(hfsq + r, hfsq)
            } else {
                dk.mul_add(LN2_HI, -((hfsq - s.mul_add(hfsq + r, dk * LN2_LO)) - f))
            }
        } else if k == 0 {
            (-s).mul_add(f - r, f)
        } else {
            dk.mul_add(LN2_HI, -((s.mul_add(f - r, -(dk * LN2_LO))) - f))
        }
    }

    const O_THRESHOLD: f64 = 7.097_827_128_933_839_730_96e+02;
    const U_THRESHOLD: f64 = -7.451_332_191_019_411_084_20e+02;
    const INVLN2: f64 = 1.442_695_040_888_963_387_00e+00;
    const P1: f64 = 1.666_666_666_666_660_190_37e-01;
    const P2: f64 = -2.777_777_777_701_559_338_42e-03;
    const P3: f64 = 6.613_756_321_437_934_361_17e-05;
    const P4: f64 = -1.653_390_220_546_525_153_90e-06;
    const P5: f64 = 4.138_136_797_057_238_460_39e-08;
    const TWOM1000: f64 = 9.332_636_185_032_188_789_90e-302;

    /// `Math.exp`.
    pub fn exp(x0: f64) -> f64 {
        let mut x = x0;
        let hx0 = hi(x) as u32;
        let xsb = ((hx0 >> 31) & 1) as usize;
        let hx = hx0 & 0x7fff_ffff;
        if hx >= 0x4086_2E42 {
            if hx >= 0x7ff0_0000 {
                if ((hx & 0xfffff) | lo(x)) != 0 {
                    return x + x;
                }
                return if xsb == 0 { x } else { 0.0 };
            }
            if x > O_THRESHOLD {
                return f64::INFINITY;
            }
            if x < U_THRESHOLD {
                return 0.0;
            }
        }
        let ln2hi = [LN2_HI, -LN2_HI];
        let ln2lo = [LN2_LO, -LN2_LO];
        let half = [0.5, -0.5];
        let (mut hi_, mut lo_) = (0.0, 0.0);
        let mut k: i32 = 0;
        if hx > 0x3fd6_2e42 {
            if hx < 0x3FF0_A2B2 {
                hi_ = x - ln2hi[xsb];
                lo_ = ln2lo[xsb];
                k = 1 - (xsb as i32) - (xsb as i32);
            } else {
                k = INVLN2.mul_add(x, half[xsb]) as i32;
                let t = k as f64;
                hi_ = (-t).mul_add(ln2hi[0], x);
                lo_ = t * ln2lo[0];
            }
            x = hi_ - lo_;
        } else if hx < 0x3e30_0000 {
            return 1.0 + x;
        }
        let t = x * x;
        let c = (-t).mul_add(t.mul_add(t.mul_add(t.mul_add(t.mul_add(P5, P4), P3), P2), P1), x);
        if k == 0 {
            return 1.0 - ((x * c) / (c - 2.0) - x);
        }
        let mut y = 1.0 - ((lo_ - (x * c) / (2.0 - c)) - hi_);
        if k >= -1021 {
            if k == 1024 {
                return y * 2.0 * f64::from_bits(0x7fe0_0000_0000_0000);
            }
            y = with_hi(y, hi(y).wrapping_add(k << 20));
            y
        } else {
            y = with_hi(y, hi(y).wrapping_add((k + 1000) << 20));
            y * TWOM1000
        }
    }

    const S1: f64 = -1.666_666_666_666_663_243_48e-01;
    const S2: f64 = 8.333_333_333_322_489_461_24e-03;
    const S3: f64 = -1.984_126_982_985_794_931_34e-04;
    const S4: f64 = 2.755_731_370_707_006_767_89e-06;
    const S5: f64 = -2.505_076_025_340_686_341_95e-08;
    const S6: f64 = 1.589_690_995_211_550_102_21e-10;
    const C1: f64 = 4.166_666_666_666_660_190_37e-02;
    const C2: f64 = -1.388_888_888_887_410_957_49e-03;
    const C3: f64 = 2.480_158_728_947_672_941_78e-05;
    const C4: f64 = -2.755_731_435_139_066_330_35e-07;
    const C5: f64 = 2.087_572_321_298_174_827_90e-09;
    const C6: f64 = -1.135_964_755_778_819_482_65e-11;
    const PIO2_1: f64 = 1.570_796_326_734_125_614_17e+00;
    const PIO2_1T: f64 = 6.077_100_506_506_192_249_32e-11;
    const PIO2_2: f64 = 6.077_100_506_303_965_976_60e-11;
    const PIO2_2T: f64 = 2.022_266_248_795_950_631_54e-21;

    fn kernel_sin(x: f64, y: f64, iy: i32) -> f64 {
        let ix = hi(x) & 0x7fff_ffff;
        if ix < 0x3e40_0000 && (x as i32) == 0 {
            return x;
        }
        let z = x * x;
        let v = z * x;
        let r = z.mul_add(z.mul_add(z.mul_add(z.mul_add(S6, S5), S4), S3), S2);
        if iy == 0 {
            v.mul_add(z.mul_add(r, S1), x)
        } else {
            x - ((-v).mul_add(S1, z.mul_add(0.5f64.mul_add(y, -(v * r)), -y)))
        }
    }

    fn kernel_cos(x: f64, y: f64) -> f64 {
        let ix = hi(x) & 0x7fff_ffff;
        if ix < 0x3e40_0000 && (x as i32) == 0 {
            return 1.0;
        }
        let z = x * x;
        let r = z * z.mul_add(z.mul_add(z.mul_add(z.mul_add(z.mul_add(C6, C5), C4), C3), C2), C1);
        if ix < 0x3FD3_3333 {
            1.0 - 0.5f64.mul_add(z, -z.mul_add(r, -(x * y)))
        } else {
            let qx = if ix > 0x3fe9_0000 { 0.28125 } else { with_lo_zero(with_hi(0.0, ix - 0x0020_0000)) };
            let hz = 0.5f64.mul_add(z, -qx);
            let a = 1.0 - qx;
            a - (hz - z.mul_add(r, -(x * y)))
        }
    }

    /// `Math.sin`. shortcut: arguments beyond 3 pi / 4 in magnitude (the wallet only ever takes sin(pi * x) for x < 1/2) use the
    /// platform sine; upgrade by porting the medium-size and Payne-Hanek reductions.
    pub fn sin(x: f64) -> f64 {
        let ix = hi(x) & 0x7fff_ffff;
        if ix <= 0x3fe9_21fb {
            return kernel_sin(x, 0.0, 0);
        }
        if ix >= 0x7ff0_0000 {
            return x - x;
        }
        if ix < 0x4002_d97c {
            // |x| < 3 pi / 4: n = +-1
            let n: i32;
            let y0: f64;
            let y1: f64;
            if hi(x) > 0 {
                let mut z = x - PIO2_1;
                if ix != 0x3ff9_21fb {
                    y0 = z - PIO2_1T;
                    y1 = (z - y0) - PIO2_1T;
                } else {
                    z -= PIO2_2;
                    y0 = z - PIO2_2T;
                    y1 = (z - y0) - PIO2_2T;
                }
                n = 1;
            } else {
                let mut z = x + PIO2_1;
                if ix != 0x3ff9_21fb {
                    y0 = z + PIO2_1T;
                    y1 = (z - y0) + PIO2_1T;
                } else {
                    z += PIO2_2;
                    y0 = z + PIO2_2T;
                    y1 = (z - y0) + PIO2_2T;
                }
                n = -1;
            }
            return match n & 3 {
                0 => kernel_sin(y0, y1, 1),
                1 => kernel_cos(y0, y1),
                2 => -kernel_sin(y0, y1, 1),
                _ => -kernel_cos(y0, y1),
            };
        }
        x.sin()
    }

    const IVLN2HI: f64 = 1.442_695_040_721_446_275_71e+00;
    const IVLN2LO: f64 = 1.675_171_316_488_651_183_53e-10;

    fn k_log1p(f: f64) -> f64 {
        let s = f / (2.0 + f);
        let z = s * s;
        let w = z * z;
        let t1 = w * w.mul_add(w.mul_add(LG6, LG4), LG2);
        let t2 = z * w.mul_add(w.mul_add(w.mul_add(LG7, LG5), LG3), LG1);
        let r = t2 + t1;
        let hfsq = 0.5 * f * f;
        s * (hfsq + r)
    }

    /// `Math.log2` (the FreeBSD / fdlibm algorithm).
    pub fn log2(x0: f64) -> f64 {
        let mut x = x0;
        let mut hx = hi(x);
        let lx = lo(x);
        let mut k: i32 = 0;
        if hx < 0x0010_0000 {
            if ((hx & 0x7fff_ffff) as u32 | lx) == 0 {
                return f64::NEG_INFINITY;
            }
            if hx < 0 {
                return f64::NAN;
            }
            k -= 54;
            x *= TWO54;
            hx = hi(x);
        }
        if hx >= 0x7ff0_0000 {
            return x + x;
        }
        if hx == 0x3ff0_0000 && lo(x) == 0 {
            return 0.0;
        }
        k += (hx >> 20) - 1023;
        hx &= 0x000f_ffff;
        let i = (hx + 0x95f64) & 0x10_0000;
        x = with_hi(x, hx | (i ^ 0x3ff0_0000));
        k += i >> 20;
        let y = k as f64;
        let f = x - 1.0;
        let hfsq = 0.5 * f * f;
        let r = k_log1p(f);
        let hi_ = with_lo_zero(f - hfsq);
        let lo_ = (f - hi_) - hfsq + r;
        let mut val_hi = hi_ * IVLN2HI;
        let mut val_lo = (lo_ + hi_).mul_add(IVLN2LO, lo_ * IVLN2HI);
        let w = y + val_hi;
        val_lo += (y - w) + val_hi;
        val_hi = w;
        val_lo + val_hi
    }
}

// ---- JavaScript value helpers shared by the wallet modules -----------------------------------------------------------------------

/// A JSON number as an f64 (`None` for any other value).
pub fn num(v: &Value) -> Option<f64> {
    if v.is_number() {
        v.as_f64()
    } else {
        None
    }
}

pub fn is_number(v: &Value) -> bool {
    v.is_number()
}

pub fn is_finite_number(v: &Value) -> bool {
    num(v).is_some_and(f64::is_finite)
}

/// `Number.isSafeInteger` (accepts -0).
pub fn is_safe_int(v: &Value) -> bool {
    num(v).is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE)
}

/// A safe integer that is not -0 (the wire `isInt`).
pub fn is_int(v: &Value) -> bool {
    is_safe_int(v) && !num(v).is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::Number(_) => num(v).is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// JavaScript `String.length` (UTF-16 code units).
pub fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `Object.entries` of a JSON value: objects in JavaScript key order, arrays and strings by index, null throws.
pub fn js_entries(v: &Value) -> Result<Vec<(String, Value)>, String> {
    match v {
        Value::Object(m) => Ok(crate::missing_context::js_keys(m).into_iter().map(|k| (k.clone(), m[&k].clone())).collect()),
        Value::Array(a) => Ok(a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect()),
        Value::String(s) => Ok(s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect()),
        Value::Null => Err("Cannot convert undefined or null to object".into()),
        _ => Ok(vec![]),
    }
}

fn int_of(v: &Value) -> i64 {
    v.as_i64().or_else(|| num(v).map(|f| f as i64)).unwrap_or(0)
}

fn s_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn arr_of(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

// ---- cells -----------------------------------------------------------------------------------------------------------------------

/// The cells of a numeric dimension as inclusive integer ranges `(lo, hi)`.
pub fn num_cells(d: &Value) -> Vec<(i64, i64)> {
    let (lo, hi) = (int_of(&d["lo"]), int_of(&d["hi"]));
    let mut out = vec![];
    let mut cur = lo;
    for c in arr_of(&d["cuts"]) {
        let c = int_of(c);
        if c < lo || c > hi {
            continue;
        }
        if cur <= c - 1 {
            out.push((cur, c - 1));
        }
        out.push((c, c));
        cur = c + 1;
    }
    if cur <= hi {
        out.push((cur, hi));
    }
    out
}

pub fn cell_count(d: &Value) -> usize {
    if s_of(&d["kind"]) == "num" {
        num_cells(d).len()
    } else {
        arr_of(&d["values"]).len()
    }
}

pub fn verb_cell_count(vs: &Value) -> usize {
    arr_of(&vs["dims"]).iter().fold(1usize, |n, d| n.saturating_mul(cell_count(d)))
}

pub fn decode_cell(vs: &Value, flat: usize) -> Vec<usize> {
    let dims = arr_of(&vs["dims"]);
    let mut idx = vec![0usize; dims.len()];
    let mut flat = flat;
    for i in (0..dims.len()).rev() {
        let n = cell_count(&dims[i]).max(1);
        idx[i] = flat % n;
        flat /= n;
    }
    idx
}

/// The categorical cell a string falls in: an exact value, else the longest matching prefix, else "other"; `None` when no cell fits.
pub fn cat_cell_of(d: &Value, s: &str) -> Option<usize> {
    let values = arr_of(&d["values"]);
    let (mut best, mut best_len) = (None, -1i64);
    for (i, v) in values.iter().enumerate() {
        let (kind, val) = (s_of(&v["kind"]), s_of(&v["value"]));
        if kind == "exact" && val == s {
            return Some(i);
        }
        if kind == "prefix" && s.starts_with(val) && (u16len(val) as i64) > best_len {
            best = Some(i);
            best_len = u16len(val) as i64;
        }
    }
    if best.is_some() {
        return best;
    }
    values.iter().position(|v| s_of(&v["kind"]) == "other")
}

/// The cell a concrete value falls in, or `None` outside the dimension's domain or type.
pub fn cell_of_value(d: &Value, x: &Value) -> Option<usize> {
    if s_of(&d["kind"]) == "num" {
        let f = num(x).filter(|f| f.is_finite())?;
        return num_cells(d).iter().position(|&(lo, hi)| f >= lo as f64 && f <= hi as f64);
    }
    cat_cell_of(d, x.as_str()?)
}

/// The cell index vector of an outcome `{verb, values}` in a verb space; `None` when any dimension falls outside it.
pub fn cell_of(vs: &Value, o: &Value) -> Option<Vec<usize>> {
    let values = o.get("values");
    let mut idx = vec![];
    for d in arr_of(&vs["dims"]) {
        let x = values.and_then(Value::as_object).and_then(|m| m.get(s_of(&d["path"]))).unwrap_or(&NULL);
        idx.push(cell_of_value(d, x)?);
    }
    Some(idx)
}

/// A representative string of categorical cell `i`.
pub fn cat_rep(d: &Value, i: usize) -> String {
    let v = &d["values"][i];
    if s_of(&v["kind"]) == "exact" {
        return s_of(&v["value"]).to_string();
    }
    let base = if s_of(&v["kind"]) == "prefix" { format!("{}x", s_of(&v["value"])) } else { "other".to_string() };
    for k in 0..64 {
        let s = if k == 0 { base.clone() } else { format!("{base}{k}") };
        if cat_cell_of(d, &s) == Some(i) {
            return s;
        }
    }
    base
}

pub fn num_rep(d: &Value, i: usize) -> i64 {
    let c = num_cells(d)[i];
    if i > 0 {
        c.0
    } else {
        c.1
    }
}

pub fn rep_value(d: &Value, i: usize) -> Value {
    if s_of(&d["kind"]) == "num" {
        json!(num_rep(d, i))
    } else {
        json!(cat_rep(d, i))
    }
}

/// The representative outcome `{verb, values}` of a cell.
pub fn cell_rep(vs: &Value, idx: &[usize]) -> Value {
    let mut values = Map::new();
    for (i, d) in arr_of(&vs["dims"]).iter().enumerate() {
        values.insert(s_of(&d["path"]).to_string(), rep_value(d, idx[i]));
    }
    json!({ "verb": vs["verb"], "values": values })
}

pub fn label_of(path: &str) -> String {
    if path == "action.resource" {
        return "resource".into();
    }
    path.rsplit('.').next().unwrap_or("").replace('_', " ")
}

// ---- workload and harm (default harm model) --------------------------------------------------------------------------------------

fn harmonic(n: i64) -> f64 {
    if n <= 0 {
        return 0.0;
    }
    if n <= EXACT_SPAN {
        let mut s = 0.0;
        for k in (1..=n).rev() {
            s += 1.0 / k as f64;
        }
        return s;
    }
    let n = n as f64;
    let n2 = n * n;
    fdlibm::log(n) + EULER_GAMMA + 1.0 / (2.0 * n) - 1.0 / (12.0 * n2) + 1.0 / (120.0 * n2 * n2) - 1.0 / (252.0 * n2 * n2 * n2)
}

fn loguniform(d: &Value) -> bool {
    s_of(&d["dist"]) == "loguniform" && num(&d["lo"]).is_some_and(|lo| lo >= 0.0)
}

pub fn interval_weight(d: &Value, a: i64, b: i64) -> f64 {
    if b < a {
        return 0.0;
    }
    if !loguniform(d) {
        return (b - a + 1) as f64;
    }
    if b - a + 1 <= EXACT_SPAN {
        let mut s = 0.0;
        for x in (a..=b).rev() {
            s += 1.0 / (x + 1) as f64;
        }
        return s;
    }
    harmonic(b + 1) - harmonic(a)
}

fn first_moment(d: &Value, a: i64, b: i64) -> f64 {
    if b < a {
        return 0.0;
    }
    if !loguniform(d) {
        return ((a + b) as f64 * (b - a + 1) as f64) / 2.0;
    }
    (b - a + 1) as f64 - interval_weight(d, a, b)
}

fn interval_mean_x(d: &Value, a: i64, b: i64, cell_lo: i64) -> f64 {
    let whole = interval_weight(d, cell_lo, b);
    if whole > 0.0 {
        first_moment(d, a, b) / whole
    } else {
        0.0
    }
}

fn linear_amount(d: &Value) -> bool {
    let p = s_of(&d["path"]);
    s_of(&d["kind"]) == "num" && (p == "amount" || p.ends_with(".amount"))
}

fn default_verb(vs: &Value) -> f64 {
    match s_of(&vs["reversibility"]) {
        "irreversible" => 10.0,
        "rate_limited" => 3.0,
        _ => 1.0,
    }
}

fn default_dim_at(d: &Value, x: f64) -> f64 {
    if linear_amount(d) {
        1.0 + x.max(0.0) / 100.0
    } else {
        1.0
    }
}

fn default_dim_mean(d: &Value, lo: i64, hi: i64) -> f64 {
    if linear_amount(d) {
        1.0 + interval_mean_x(d, lo.max(0), hi, lo).max(0.0) / 100.0
    } else {
        1.0
    }
}

/// Mass and expected harm of one cell of one dimension.
pub fn dim_cell_stats(d: &Value, i: usize) -> (f64, f64) {
    if s_of(&d["kind"]) == "cat" {
        return (1.0 / arr_of(&d["values"]).len() as f64, 1.0);
    }
    let c = num_cells(d)[i];
    let wm = interval_weight(d, c.0, c.1);
    let total = interval_weight(d, int_of(&d["lo"]), int_of(&d["hi"]));
    (wm / total, if wm > 0.0 { default_dim_mean(d, c.0, c.1) } else { default_dim_at(d, c.0 as f64) })
}

/// Exact mu(cell) and E[h | cell] for a whole cell (product measure, separable harm).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CellStats {
    pub mass: f64,
    pub harm: f64,
}

pub fn cell_stats(vs: &Value, idx: &[usize]) -> CellStats {
    let mut mass = num(&vs["weight"]).unwrap_or(f64::NAN);
    let mut h = default_verb(vs);
    for (k, d) in arr_of(&vs["dims"]).iter().enumerate() {
        let (m, hh) = dim_cell_stats(d, idx[k]);
        mass *= m;
        h *= hh;
    }
    CellStats { mass, harm: h }
}

// ---- exact Clopper-Pearson upper bound -------------------------------------------------------------------------------------------

const GRID_BITS: u32 = 52;
const A: u64 = 1u64 << GRID_BITS;
const TOL_UNITS: u64 = 1u64 << (GRID_BITS - 44);

fn log_factorials(n: usize) -> Vec<f64> {
    let mut lf = vec![0.0; n + 1];
    for i in 1..=n {
        lf[i] = lf[i - 1] + fdlibm::log(i as f64);
    }
    lf
}

fn binomial_cdf(k: i64, n: i64, p: f64, lf: &[f64]) -> f64 {
    if k >= n {
        return 1.0;
    }
    if k < 0 {
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
    for i in 0..=(k as usize) {
        let nn = n as usize;
        s += fdlibm::exp(lf[nn] - lf[i] - lf[nn - i] + i as f64 * lp + (nn - i) as f64 * lq);
    }
    s.min(1.0)
}

fn big(x: u64) -> BigUint {
    BigUint::from(x)
}

/// N with cdfRec(a / 2^52, n, k) = N / A^n (integer arithmetic).
fn cdf_rec_numerator(n: usize, k: usize, a: u64) -> BigUint {
    let (ba, bb) = (big(a), big(A - a));
    let kk = k.min(n);
    let mut row: Vec<BigUint> = vec![big(1); kk + 1];
    let mut pw = big(1);
    for m in 0..n {
        let pw_next = pw.clone() * big(A);
        let mut next: Vec<BigUint> = Vec::with_capacity(kk + 1);
        for j in 0..=kk {
            if j > m {
                next.push(pw_next.clone());
            } else {
                let left = if j == 0 { big(0) } else { row[j - 1].clone() };
                next.push(ba.clone() * left + bb.clone() * row[j].clone());
            }
        }
        row = next;
        pw = pw_next;
    }
    row[kk].clone()
}

/// alpha < cdfRec(a / 2^52, n, k), exactly. `alpha = num / 2^exp`.
fn cdf_exceeds(n: usize, k: usize, a: u64, num: u64, exp: usize) -> bool {
    let mut an = big(1);
    for _ in 0..n {
        an = an * big(A);
    }
    cdf_rec_numerator(n, k, a) * (big(1) << exp) > big(num) * an
}

fn float_guess(k: i64, n: i64, alpha: f64) -> f64 {
    let lf = log_factorials(n as usize);
    let mut lo = k as f64 / n as f64;
    let mut hi = 1.0;
    let mut it = 0;
    while it < 200 && hi - lo > 1e-13 {
        let mid = (lo + hi) / 2.0;
        if binomial_cdf(k, n, mid, &lf) > alpha {
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

fn certify_bracket(start: u64, exceeds: &dyn Fn(u64) -> bool) -> Result<u64, String> {
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
    Ok(hi)
}

/// One-sided Clopper-Pearson upper bound after `k` successes in `n`, rounded outward on the 2^-52 grid (exact integer arithmetic).
pub fn clopper_pearson_upper(k: f64, n: f64, alpha: f64) -> Result<f64, String> {
    if !(k.fract() == 0.0 && n.fract() == 0.0 && k >= 0.0 && n >= 0.0 && k <= n && n.is_finite()) {
        return Err("clopperPearsonUpper: need integers 0 <= k <= n".into());
    }
    if !(alpha > 0.0 && alpha < 1.0) {
        return Err("clopperPearsonUpper: alpha must be in (0, 1)".into());
    }
    if n == 0.0 || k == n {
        return Ok(1.0);
    }
    let (ki, ni) = (k as i64, n as i64);
    // alpha = m * 2^-e with m odd (the exact binary fraction)
    let bits = alpha.to_bits();
    let be = ((bits >> 52) & 0x7ff) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    let (mut m, mut e) = if be == 0 { (frac, -1074i64) } else { (frac | (1u64 << 52), be - 1075) };
    let tz = m.trailing_zeros() as i64;
    m >>= tz;
    e += tz;
    let exp = (-e).max(0) as usize;
    let g = float_guess(ki, ni, alpha);
    let start = clamp(((g * 4_503_599_627_370_496.0).ceil() as i128) + TOL_UNITS as i128);
    let hi = certify_bracket(start, &|a| cdf_exceeds(ni as usize, ki as usize, a, m, exp))?;
    Ok(hi as f64 / 4_503_599_627_370_496.0)
}
