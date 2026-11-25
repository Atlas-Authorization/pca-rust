//! The intent kit, part 1 (`@atlasauth/pca-intent`): the outcome space (omega), policy admission, regions, grant metrics, multi-principal
//! rules and common refinement, exact Clopper-Pearson bounds, the elicitation learner, Intent Map emission, the classifier error fold, the
//! k-compiler pipeline, frame constraints, lazy JIT elicitation and the wallet-side layer lattice.
//!
//! Everything is JSON-valued (`&serde_json::Value` in, `Result<Value, String>` out, the reference's field names); a reference throw is an
//! `Err`. Doubles keep the reference's operation order. shortcut: the default harm model only (no caller-supplied harm functions), the
//! built-in connector catalogue only (no caller catalogue), and callbacks (ceilings, compilers' completions) are chosen by name by the
//! caller of the scenario entry points.

pub mod classifier;
pub mod clopper;
pub mod compilers;
pub mod frames;
pub mod jit;
pub mod layers;
pub mod learner;
pub mod mapkit;
pub mod metrics;
pub mod multi;
pub mod omega;
pub mod policy;
pub mod region;

use serde_json::{Map, Number, Value};
use std::cmp::Ordering;

pub type R<T> = Result<T, String>;

/// A JSON number from a double: an integral value in the safe range is written as an integer; a non-finite one as `{"$num": ...}`.
pub fn jn(f: f64) -> Value {
    if f.is_nan() {
        let mut m = Map::new();
        m.insert("$num".into(), Value::String("NaN".into()));
        return Value::Object(m);
    }
    if f.is_infinite() {
        let mut m = Map::new();
        m.insert("$num".into(), Value::String(if f > 0.0 { "Infinity" } else { "-Infinity" }.into()));
        return Value::Object(m);
    }
    if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        return Value::Number(Number::from(f as i64));
    }
    Value::Number(Number::from_f64(f).unwrap_or_else(|| Number::from(0)))
}

pub fn jstr(s: &str) -> Value {
    Value::String(s.to_string())
}

pub fn jarr_usize(v: &[usize]) -> Value {
    Value::Array(v.iter().map(|x| Value::Number(Number::from(*x as u64))).collect())
}

/// An object built from `(key, value)` pairs in order.
pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// The double a JSON number is (None for anything else; a JSON boolean is not a number).
pub fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

pub fn is_num(v: &Value) -> bool {
    matches!(v, Value::Number(_))
}

pub fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

pub fn get_str<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    get(v, k).and_then(Value::as_str)
}

pub fn get_num(v: &Value, k: &str) -> Option<f64> {
    get(v, k).and_then(num)
}

/// JS `x ?? default` over an object member (null counts as absent).
pub fn opt<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    get(v, k).filter(|x| !x.is_null())
}

pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// JS `Math.round`: the nearest integer, ties toward +infinity.
pub fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

/// UTF-16 code-unit order (JavaScript's default string sort).
pub fn u16cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

pub fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `hashCanonical`: the strict canonical digest; an out-of-profile value is refused.
pub fn hash_strict(v: &Value) -> R<String> {
    crate::hash_canonical_strict(v).ok_or_else(|| "hashCanonical: the value is outside the strict canonical profile".to_string())
}

/// A finite integral JSON number (an integer-valued double).
pub fn is_int_value(v: &Value) -> bool {
    num(v).is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

pub fn as_usize(v: &Value) -> Option<usize> {
    let f = num(v)?;
    if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= 9_007_199_254_740_991.0 {
        Some(f as usize)
    } else {
        None
    }
}
