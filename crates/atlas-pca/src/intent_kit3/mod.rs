//! Intent package part 3: deterministic rendering and witnesses, the schema-derived outcome space, world dimensions, trajectory
//! accumulators, exact binomial statistics, and the signed intent statement. Every function is JSON-valued (`&Value` in,
//! `Result<Value, String>` out, reference messages) except [`stats`], which is typed.
//!
//! Not in this part (they sit on the learner / map / compilers of the other parts): the routing scenarios, the conformance and
//! JIT scenarios, the runtime drift / post-condition engines and the compilers / classifier / frames pieces of the `misc` corpus.
pub mod render;
pub mod schema;
pub mod slots;
pub mod statement;
pub mod stats;
pub mod trajectory;
pub mod world;

use serde_json::{json, Value};

/// A double as the reference corpus prints it: finite numbers as JSON numbers, NaN / +-Infinity as `{"$num": ...}`.
pub fn num_json(x: f64) -> Value {
    if x.is_nan() {
        return json!({ "$num": "NaN" });
    }
    if x.is_infinite() {
        return json!({ "$num": if x > 0.0 { "Infinity" } else { "-Infinity" } });
    }
    if x == x.trunc() && x.abs() < 9_007_199_254_740_992.0 && !(x == 0.0 && x.is_sign_negative()) {
        return json!(x as i64);
    }
    serde_json::Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
}

/// JavaScript `String(x)` of a JSON value (`None` is `undefined`): arrays join with commas (null / undefined as empty), objects are
/// `[object Object]`.
pub fn js_str(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(_)) => crate::js_stringify(v.unwrap()),
        Some(Value::Array(a)) => a.iter().map(|e| if e.is_null() { String::new() } else { js_str(Some(e)) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// JavaScript `Number(x)` of a JSON value (`None` is `undefined`).
pub fn to_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => str_to_number(s),
        Some(Value::Array(_)) => str_to_number(&js_str(v)),
        Some(Value::Object(_)) => f64::NAN,
    }
}

fn str_to_number(s: &str) -> f64 {
    let t = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if t.is_empty() {
        return 0.0;
    }
    for (p, radix) in [("0x", 16), ("0X", 16), ("0b", 2), ("0B", 2), ("0o", 8), ("0O", 8)] {
        if let Some(r) = t.strip_prefix(p) {
            return u64::from_str_radix(r, radix).map(|n| n as f64).unwrap_or(f64::NAN);
        }
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if t.chars().all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E')) && t.chars().any(|c| c.is_ascii_digit()) {
        t.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// `o[k]` of a JSON value: `None` (undefined) for a non-object or a missing member; reading a member of `null` throws.
pub fn member<'a>(o: &'a Value, k: &str) -> Result<Option<&'a Value>, String> {
    match o {
        Value::Null => Err(format!("Cannot read properties of null (reading '{k}')")),
        Value::Object(m) => Ok(m.get(k)),
        _ => Ok(None),
    }
}
