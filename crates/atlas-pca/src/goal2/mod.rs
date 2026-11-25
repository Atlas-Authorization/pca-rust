//! `@atlasauth/pca-goal`, Part 2: interpreters, boundary examples and goal tests, drift, calibration, precedents, review and
//! approval, round-trip checks, trait selectors, the N-version meet, disambiguation and the benchmark. Everything is JSON-valued
//! (`&Value` in, `Result<Value, String>` out), over the Part 1 kernel in [`crate::goal`].
//!
//! shortcut: reads are lenient (a missing member is `null`) except where the reference's throw is observable through the
//! corpus; every function that the reference can throw from returns `Err` there.
use serde_json::Value;

pub mod bench;
pub mod crc;
pub mod disambiguate;
pub mod drift;
pub mod examples;
pub mod interpret;
pub mod nversion;
pub mod precedent;
pub mod review;
pub mod roundtrip;
pub mod selectors;

pub type Res<T> = Result<T, String>;
pub(crate) static NULL: Value = Value::Null;

/// `v[k]`, or `null` when absent (and for a non-object).
pub(crate) fn g<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&NULL)
}
pub(crate) fn st(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
pub(crate) fn arr(v: &Value) -> &[Value] {
    v.as_array().map(|a| a.as_slice()).unwrap_or(&[])
}
/// An array the reference iterates: anything else is a throw.
pub(crate) fn req_arr(v: &Value) -> Res<&[Value]> {
    v.as_array().map(|a| a.as_slice()).ok_or_else(|| "value is not iterable".to_string())
}
pub(crate) fn nm(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}
/// `hashCanonical` (strict profile); a value outside it throws.
pub(crate) fn hc(v: &Value) -> Res<String> {
    crate::hash_canonical_strict(v).ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string())
}
pub(crate) fn jstr(v: &Value) -> String {
    crate::js_stringify(v)
}
pub(crate) fn js_s(v: &Value) -> String {
    crate::goal::js::js_str(Some(v))
}
/// `a === b` on two JSON values (objects and arrays are never identical).
pub(crate) fn seq_eq(a: &Value, b: &Value) -> bool {
    crate::goal::js::strict_eq(Some(a), Some(b))
}
pub(crate) fn includes_v(xs: &[Value], x: &Value) -> bool {
    xs.iter().any(|e| seq_eq(e, x))
}
pub(crate) fn u16lt(a: &str, b: &str) -> bool {
    crate::goal::js::u16cmp(a, b) == std::cmp::Ordering::Less
}
/// `[...new Set(xs)]` over JSON values by `===` (first occurrence order).
pub(crate) fn uniq_v(xs: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for x in xs {
        if !includes_v(&out, x) {
            out.push(x.clone());
        }
    }
    out
}
pub(crate) fn strs(xs: &[Value]) -> Vec<String> {
    xs.iter().map(|x| st(x).to_string()).collect()
}
pub(crate) fn sv(xs: Vec<String>) -> Value {
    Value::Array(xs.into_iter().map(Value::String).collect())
}
/// A JSON number for a double (an integer when it is one).
pub(crate) fn numv(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9e15 {
        serde_json::json!(x as i64)
    } else {
        serde_json::json!(x)
    }
}
