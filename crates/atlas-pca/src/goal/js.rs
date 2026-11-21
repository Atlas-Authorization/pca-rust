//! JavaScript-semantics helpers for the typed layer: the reference reads JSON trees with property access, so a member of an
//! absent or null value throws, a member of any other primitive is `undefined`, and `Object.keys` / default `sort` / truthiness
//! behave as in the language. An absent member is `None`.
use serde_json::Value;
use std::cmp::Ordering;

pub type U<'a> = Option<&'a Value>;

/// `o[k]`: `undefined` for a non-object, a throw for `undefined` / `null`.
pub fn jget<'a>(o: U<'a>, k: &str) -> Result<U<'a>, String> {
    match o {
        None => Err(format!("Cannot read properties of undefined (reading '{k}')")),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{k}')")),
        Some(Value::Object(m)) => Ok(m.get(k)),
        Some(_) => Ok(None),
    }
}
/// `x === "s"` for a string literal.
pub fn is_str(x: U, s: &str) -> bool {
    matches!(x, Some(Value::String(v)) if v == s)
}
pub fn truthy(x: U) -> bool {
    match x {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}
const MAX_SAFE: i64 = 9007199254740991;
/// A JavaScript safe integer that is not `-0`.
pub fn safe_int(x: U) -> Option<i64> {
    match x {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                return (i.abs() <= MAX_SAFE).then_some(i);
            }
            let f = n.as_f64()?;
            (f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64 && !(f == 0.0 && f.is_sign_negative())).then_some(f as i64)
        }
        _ => None,
    }
}
/// Any integral number that fits an `i64` (the tape reader does not range-check what it reads back).
pub fn any_int(x: &Value) -> Option<i64> {
    match x {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 9.2e18).map(|f| f as i64)),
        _ => None,
    }
}
/// UTF-16 code unit order, the default `Array.prototype.sort` / `<` on strings.
pub fn u16cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
/// `Object.keys(o)` for the value kinds a parameter map can take: an object's keys, an array's indices, a string's indices.
pub fn okeys(o: U) -> Result<Vec<String>, String> {
    match o {
        None | Some(Value::Null) => Err("Cannot convert undefined or null to object".into()),
        Some(Value::Object(m)) => Ok(m.keys().cloned().collect()),
        Some(Value::Array(a)) => Ok((0..a.len()).map(|i| i.to_string()).collect()),
        Some(Value::String(s)) => Ok((0..s.encode_utf16().count()).map(|i| i.to_string()).collect()),
        Some(_) => Ok(vec![]),
    }
}
/// `o[k]` for a key of [`okeys`]; a string's characters are strings, never IR values (the caller refuses them).
pub fn oget<'a>(o: U<'a>, k: &str) -> U<'a> {
    match o {
        Some(Value::Object(m)) => m.get(k),
        Some(Value::Array(a)) => k.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    }
}
/// `String(v)` of a JSON value (primitives only; objects and arrays use the JSON text, which differs from JS for arrays).
pub fn js_str(x: U) -> String {
    match x {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => crate::intent_v2::js_number_string(n.as_f64().unwrap_or(0.0)),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(a)) => a.iter().map(|v| if v.is_null() { String::new() } else { js_str(Some(v)) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// Own members in JavaScript key order (array-index keys ascending first, then insertion order).
pub fn key_order(m: &serde_json::Map<String, Value>) -> Vec<&String> {
    fn index_key(k: &str) -> Option<u32> {
        let n: u32 = k.parse().ok()?;
        (n != u32::MAX && n.to_string() == k).then_some(n)
    }
    let mut idx: Vec<(u32, &String)> = m.keys().filter_map(|k| index_key(k).map(|n| (n, k))).collect();
    idx.sort();
    idx.into_iter().map(|(_, k)| k).chain(m.keys().filter(|k| index_key(k).is_none())).collect()
}
/// `===` of two JSON-derived values (objects and arrays are never identical across two reads).
pub fn strict_eq(a: U, b: U) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => match (x, y) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(p), Value::Bool(q)) => p == q,
            (Value::Number(p), Value::Number(q)) => p.as_f64() == q.as_f64(),
            (Value::String(p), Value::String(q)) => p == q,
            _ => false,
        },
        _ => false,
    }
}
/// `xs.includes(x)`: an array's members by `===`, a string's substring.
pub fn includes(xs: U, x: U) -> bool {
    match (xs, x) {
        (Some(Value::Array(a)), _) => a.iter().any(|e| strict_eq(Some(e), x)),
        (Some(Value::String(s)), Some(Value::String(t))) => s.contains(t.as_str()),
        _ => false,
    }
}
/// `for (const x of xs)` / `xs.map(..)`: an array's members, a string's code points as one-character strings (as JavaScript iterates a
/// string); anything else is not iterable (a throw).
pub fn seq(x: U) -> Result<std::borrow::Cow<'_, [Value]>, String> {
    match x {
        Some(Value::Array(a)) => Ok(std::borrow::Cow::Borrowed(a.as_slice())),
        Some(Value::String(t)) => Ok(std::borrow::Cow::Owned(t.chars().map(|c| Value::String(c.to_string())).collect())),
        _ => Err("value is not iterable".into()),
    }
}
/// The members-only form of [`seq`] for a site that keeps the items beyond the iteration (returns them, collects them): every item
/// borrows from the input. A string yields a shared empty-string placeholder per character, because the sites that use this form
/// read only members of an item, and every member of a string is `undefined`. Nothing is allocated or retained per character.
pub fn seq_members<'a>(x: U<'a>) -> Result<Vec<&'a Value>, String> {
    static EMPTY: Value = Value::String(String::new());
    match x {
        Some(Value::Array(a)) => Ok(a.iter().collect()),
        Some(Value::String(t)) => Ok(t.chars().map(|_| &EMPTY).collect()),
        _ => Err("value is not iterable".into()),
    }
}
/// `Object.entries(x)` reads a non-empty string as its characters by index: the same entries as the array of its code points.
pub fn chars_as_array(x: U) -> Option<Value> {
    match x {
        Some(Value::String(t)) if !t.is_empty() => Some(Value::Array(t.chars().map(|c| Value::String(c.to_string())).collect())),
        _ => None,
    }
}
/// `Object.entries(o)` in JavaScript key order; a string's characters are refused (shortcut: no IR value is a bare string map).
pub fn entries(o: U) -> Result<Vec<(String, &Value)>, String> {
    match o {
        None | Some(Value::Null) => Err("Cannot convert undefined or null to object".into()),
        Some(Value::Object(m)) => Ok(key_order(m).into_iter().map(|k| (k.clone(), &m[k.as_str()])).collect()),
        Some(Value::Array(a)) => Ok(a.iter().enumerate().map(|(i, v)| (i.to_string(), v)).collect()),
        Some(Value::String(s)) if !s.is_empty() => Err("shortcut: a non-empty string has no entries the port can read".into()),
        Some(_) => Ok(vec![]),
    }
}
/// An own member of a plain object (a prototype member such as `constructor` is not one); a null object throws.
pub fn own<'a>(o: U<'a>, k: &str) -> Result<U<'a>, String> {
    jget(o, k)
}
/// JavaScript `String.prototype.trim` / `\s`.
pub const JS_WS: &str = "\t\n\u{b}\u{c}\r \u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}";
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| JS_WS.contains(c))
}
