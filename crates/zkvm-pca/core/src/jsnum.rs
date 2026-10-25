//! JavaScript number semantics shared by the Intent Layer v2 ports (the TS reference judges numbers by their binary64 VALUE:
//! `Number.isSafeInteger(x) && !Object.is(x, -0)`). serde_json keeps `1e6` / `950000.0` as f64 and `950000` as an integer;
//! these helpers make both forms agree with JS. Artifacts held to the strict canonical profile never contain the float forms,
//! but verifier-side JSON (policy, state) may.
use serde_json::Value;

pub const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// `Number.isSafeInteger(v) && !Object.is(v, -0)`: the integer value, else `None` (non-numbers, fractions, -0, |v| > 2^53-1).
pub fn safe_int(v: &Value) -> Option<i64> {
    let n = match v {
        Value::Number(n) => n,
        _ => return None,
    };
    if let Some(i) = n.as_i64() {
        return (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i).then_some(i);
    }
    if n.as_u64().is_some() {
        return None; // > i64::MAX, certainly unsafe
    }
    let f = n.as_f64()?;
    if !f.is_finite() || f.fract() != 0.0 || f.abs() > MAX_SAFE_INT as f64 || (f == 0.0 && f.is_sign_negative()) {
        return None;
    }
    Some(f as i64)
}

/// A safe integer >= 0 (`isNonNeg` in the TS sources).
pub fn non_neg(v: &Value) -> Option<u64> {
    safe_int(v).filter(|i| *i >= 0).map(|i| i as u64)
}

/// `typeof v === 'number' && Number.isFinite(v)`.
pub fn finite(v: &Value) -> Option<f64> {
    v.as_f64().filter(|f| f.is_finite())
}
