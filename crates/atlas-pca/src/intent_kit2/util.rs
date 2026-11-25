//! Small JavaScript-flavoured helpers shared by the intent_kit2 modules (JSON numbers, UTF-16 order, member access).
use serde_json::{Map, Value};

pub use crate::intent_kit::{obj, u16cmp, u16len};

pub type R<T> = Result<T, String>;

/// A double as a JSON number the way the reference serialises it: an integral value is an integer, a non-finite one is
/// `{"$num": "NaN" | "Infinity" | "-Infinity"}` (the corpus encoding), `-0` is `0`.
pub fn num(f: f64) -> Value {
    if f.is_nan() {
        return serde_json::json!({"$num": "NaN"});
    }
    if f.is_infinite() {
        return serde_json::json!({"$num": if f > 0.0 { "Infinity" } else { "-Infinity" }});
    }
    if f == f.trunc() && f.abs() < 9_007_199_254_740_992.0 {
        return Value::from(f as i64);
    }
    Value::from(f)
}

/// A JSON number as a double (`None` for every other value, a boolean included).
pub fn fnum(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

pub fn is_number(v: &Value) -> bool {
    v.is_number()
}

pub fn is_finite_number(v: &Value) -> bool {
    fnum(v).is_some_and(f64::is_finite)
}

pub fn sort_u16(xs: &mut [String]) {
    xs.sort_by(|a, b| u16cmp(a, b));
}

/// ECMAScript `String(v)` of a JSON value.
pub fn js_str(v: &Value) -> String {
    crate::intent_v2::js_value_string(v)
}

/// `o.get(k)` of a dict (`None` when `o` is not an object or the member is absent).
pub fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

/// The member when present and not JSON null.
pub fn nn<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    member(v, k).filter(|x| !x.is_null())
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn arr<'a>(v: &'a Value, what: &str) -> R<&'a Vec<Value>> {
    v.as_array().ok_or_else(|| format!("{what} must be a list"))
}

pub fn text<'a>(v: &'a Value, what: &str) -> R<&'a str> {
    v.as_str().ok_or_else(|| format!("{what} must be a string"))
}

/// JS `Object.keys` order: array-index keys ascending first, then insertion order.
pub fn js_keys(m: &Map<String, Value>) -> Vec<String> {
    let idx = |k: &str| -> Option<u32> {
        if k == "0" || (!k.is_empty() && !k.starts_with('0') && k.bytes().all(|b| b.is_ascii_digit())) {
            k.parse::<u32>().ok().filter(|n| *n < u32::MAX)
        } else {
            None
        }
    };
    let mut ints: Vec<(u32, String)> = m.keys().filter_map(|k| idx(k).map(|n| (n, k.clone()))).collect();
    ints.sort_by_key(|x| x.0);
    let mut out: Vec<String> = ints.into_iter().map(|x| x.1).collect();
    out.extend(m.keys().filter(|k| idx(k).is_none()).cloned());
    out
}

/// `Number.isSafeInteger` and not `-0`.
pub fn is_safe_int(v: &Value) -> bool {
    match fnum(v) {
        Some(f) => f.is_finite() && f == f.trunc() && f.abs() <= 9_007_199_254_740_991.0 && !(f == 0.0 && f.is_sign_negative()),
        None => false,
    }
}

/// `===` over JSON scalars of one type (2 === 2.0, "a" === "a", containers never equal).
pub fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Null), Some(Value::Null)) => true,
        _ => false,
    }
}

/// Mapkit `js_round`: the nearest integer, ties toward +infinity; refuses a non-finite input.
pub fn round_half_up(x: f64) -> R<f64> {
    if !x.is_finite() {
        return Err("cannot round a non-finite number".into());
    }
    let f = x.floor();
    Ok(if x - f >= 0.5 { f + 1.0 } else { f })
}
