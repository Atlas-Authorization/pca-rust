//! JavaScript-semantics helpers of the policy analyzer. Inputs are JSON trees (`serde_json::Value`). A missing member is the
//! `undefined` marker ([`undef`]), `Value::Null` is `null`; the marker never appears in a result ([`u`] drops it). A number that
//! is not finite travels as `{"$num": "Infinity" | "-Infinity" | "NaN"}` (the corpus encoding), read back by [`jsnum`].
//! A JavaScript throw is a panic carrying [`Throw`] (raised with `resume_unwind`, so no panic hook runs); [`try_js`] turns it
//! into an `Err`.

use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

pub(crate) const REV_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const UNDEF_KEY: &str = "\u{0}undef";
const ABSENT_KEY: &str = "\u{0}absent";

/// A reference throw.
pub(crate) struct Throw(pub String);

pub(crate) fn fail(msg: impl Into<String>) -> ! {
    resume_unwind(Box::new(Throw(msg.into())))
}

/// Run `f`, mapping a reference throw (or any panic) to an `Err`.
pub(crate) fn try_js<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|e| {
        if let Some(t) = e.downcast_ref::<Throw>() {
            t.0.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "internal error".to_string()
        }
    })
}

fn marker(k: &str) -> Value {
    let mut m = Map::new();
    m.insert(k.to_string(), Value::Bool(true));
    Value::Object(m)
}

/// JavaScript `undefined`.
pub(crate) fn undef() -> &'static Value {
    static U: OnceLock<Value> = OnceLock::new();
    U.get_or_init(|| marker(UNDEF_KEY))
}

pub(crate) fn undef_v() -> Value {
    undef().clone()
}

/// "This field is not set" in a probe grid.
pub(crate) fn absent_v() -> Value {
    marker(ABSENT_KEY)
}

pub(crate) fn is_undef(v: &Value) -> bool {
    matches!(v, Value::Object(m) if m.len() == 1 && m.contains_key(UNDEF_KEY))
}

pub(crate) fn is_absent(v: &Value) -> bool {
    matches!(v, Value::Object(m) if m.len() == 1 && m.contains_key(ABSENT_KEY))
}

fn is_marker(m: &Map<String, Value>) -> bool {
    m.len() == 1 && (m.contains_key(UNDEF_KEY) || m.contains_key(ABSENT_KEY) || m.contains_key("$num"))
}

/// A plain object (not one of the markers).
pub(crate) fn obj(v: &Value) -> Option<&Map<String, Value>> {
    match v {
        Value::Object(m) if !is_marker(m) => Some(m),
        _ => None,
    }
}

pub(crate) fn is_obj(v: &Value) -> bool {
    obj(v).is_some()
}

pub(crate) fn is_arr(v: &Value) -> bool {
    v.is_array()
}

/// `o[k]`: undefined for an absent member or a non-object; reading a member of null / undefined throws.
pub(crate) fn get<'a>(o: &'a Value, k: &str) -> &'a Value {
    if o.is_null() || is_undef(o) {
        fail(format!("cannot read properties of {} (reading '{}')", if o.is_null() { "null" } else { "undefined" }, k));
    }
    own(o, k)
}

/// `o?.k`.
pub(crate) fn oget<'a>(o: &'a Value, k: &str) -> &'a Value {
    if o.is_null() || is_undef(o) {
        return undef();
    }
    get(o, k)
}

/// An own member of a plain object, else undefined (never throws).
pub(crate) fn own<'a>(o: &'a Value, k: &str) -> &'a Value {
    match obj(o) {
        Some(m) => m.get(k).unwrap_or(undef()),
        None => undef(),
    }
}

/// A member of a plain map, undefined when absent.
pub(crate) fn mg<'a>(m: &'a Map<String, Value>, k: &str) -> &'a Value {
    m.get(k).unwrap_or(undef())
}

pub(crate) fn has(o: &Value, k: &str) -> bool {
    obj(o).is_some_and(|m| m.contains_key(k))
}

/// `v ?? d`.
pub(crate) fn nn<'a>(v: &'a Value, d: &'a Value) -> &'a Value {
    if v.is_null() || is_undef(v) {
        d
    } else {
        v
    }
}

/// The binary64 of a number value (`{"$num"}` included).
pub(crate) fn jsnum(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Object(m) if m.len() == 1 => match m.get("$num").and_then(Value::as_str) {
            Some("Infinity") => Some(f64::INFINITY),
            Some("-Infinity") => Some(f64::NEG_INFINITY),
            Some(_) => Some(f64::NAN),
            None => None,
        },
        _ => None,
    }
}

/// `typeof v === 'number' && Number.isFinite(v)`.
pub(crate) fn fin(v: &Value) -> Option<f64> {
    jsnum(v).filter(|f| f.is_finite())
}

pub(crate) fn is_fin(v: &Value) -> bool {
    fin(v).is_some()
}

pub(crate) fn is_num(v: &Value) -> bool {
    jsnum(v).is_some()
}

/// A number as a value (a non-finite one as `{"$num"}`, an integral one as an integer).
pub(crate) fn num(f: f64) -> Value {
    if f.is_nan() {
        return serde_json::json!({"$num": "NaN"});
    }
    if f.is_infinite() {
        return serde_json::json!({"$num": if f > 0.0 { "Infinity" } else { "-Infinity" }});
    }
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 && !(f == 0.0 && f.is_sign_negative()) {
        Value::from(f as i64)
    } else {
        Value::Number(Number::from_f64(f).unwrap_or_else(|| Number::from(0)))
    }
}

pub(crate) fn s(x: &str) -> Value {
    Value::String(x.to_string())
}

pub(crate) fn arr_of(xs: Vec<Value>) -> Value {
    Value::Array(xs)
}

pub(crate) fn empty_arr() -> Value {
    Value::Array(vec![])
}

pub(crate) fn empty_obj() -> Value {
    Value::Object(Map::new())
}

/// An array value, else a throw naming what was missing.
pub(crate) fn req_list(x: &Value) -> &Vec<Value> {
    match x {
        Value::Array(l) => l,
        _ => fail("not an array"),
    }
}

/// `xs.includes(x)`; a non-array throws.
pub(crate) fn includes(xs: &Value, x: &Value) -> bool {
    req_list(xs).iter().any(|e| strict_eq(e, x))
}

/// A string value, else a throw.
pub(crate) fn req_str<'a>(v: &'a Value, what: &str) -> &'a str {
    match v.as_str() {
        Some(t) => t,
        None => fail(format!("{what} is not a string")),
    }
}

pub(crate) fn truthy(v: &Value) -> bool {
    if is_undef(v) {
        return false;
    }
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(t) => !t.is_empty(),
        _ => match jsnum(v) {
            Some(f) => f != 0.0 && !f.is_nan(),
            None => true,
        },
    }
}

/// `a === b` over JSON values (objects and arrays by identity).
pub(crate) fn strict_eq(a: &Value, b: &Value) -> bool {
    if is_undef(a) || is_undef(b) {
        return is_undef(a) && is_undef(b);
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        _ => {
            if let (Some(x), Some(y)) = (jsnum(a), jsnum(b)) {
                x == y
            } else if jsnum(a).is_some() || jsnum(b).is_some() {
                false
            } else if matches!(a, Value::Object(_) | Value::Array(_)) {
                std::ptr::eq(a, b)
            } else {
                false
            }
        }
    }
}

/// `Number(v)` of a JSON value.
pub(crate) fn to_number(v: &Value) -> f64 {
    if is_undef(v) {
        return f64::NAN;
    }
    if let Some(f) = jsnum(v) {
        return f;
    }
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::String(t) => crate::actions::js_str_to_number(t),
        Value::Array(a) => match a.len() {
            0 => 0.0,
            1 => to_number(&a[0]),
            _ => f64::NAN,
        },
        _ => f64::NAN,
    }
}

fn units_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `a < b` over UTF-16 code units.
pub(crate) fn unit_less(a: &str, b: &str) -> bool {
    units_cmp(a, b) == std::cmp::Ordering::Less
}

/// `a > b` of JavaScript (two strings compare as strings, anything else as numbers).
pub(crate) fn gt(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return units_cmp(x, y) == std::cmp::Ordering::Greater;
    }
    to_number(a) > to_number(b)
}

pub(crate) fn lt(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return units_cmp(x, y) == std::cmp::Ordering::Less;
    }
    to_number(a) < to_number(b)
}

/// The JavaScript string of a number (-0 prints as 0).
pub(crate) fn num_str(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

/// `String(v)` of a value (an undefined member is "undefined").
pub(crate) fn js(v: &Value) -> String {
    if is_undef(v) {
        return "undefined".to_string();
    }
    if let Some(f) = jsnum(v) {
        return num_str(f);
    }
    crate::intent_v2::js_value_string(v)
}

fn quote(t: &str) -> String {
    serde_json::to_string(t).unwrap_or_else(|_| "\"\"".to_string())
}

/// `JSON.stringify(v)` of a JSON tree (undefined members dropped, -0 as 0, own-key order with index keys first).
pub(crate) fn json_str(v: &Value) -> String {
    if is_undef(v) {
        return "null".to_string();
    }
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(t) => quote(t),
        Value::Array(a) => format!("[{}]", a.iter().map(json_str).collect::<Vec<_>>().join(",")),
        _ => {
            if let Some(f) = jsnum(v) {
                return if f.is_finite() { num_str(f) } else { "null".into() };
            }
            match obj(v) {
                Some(m) => {
                    let parts: Vec<String> =
                        keys(m).into_iter().filter(|k| !is_undef(&m[k.as_str()])).map(|k| format!("{}:{}", quote(&k), json_str(&m[k.as_str()]))).collect();
                    format!("{{{}}}", parts.join(","))
                }
                None => "null".into(),
            }
        }
    }
}

/// `Object.keys`: canonical array-index keys first (ascending), then the rest in insertion order.
pub(crate) fn keys(m: &Map<String, Value>) -> Vec<String> {
    crate::missing_context::js_keys(m)
}

/// An object literal: members whose value is undefined are absent.
pub(crate) fn u(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        if !is_undef(&v) {
            m.insert(k.to_string(), v);
        }
    }
    Value::Object(m)
}

pub(crate) fn u_map(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    match u(pairs) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// `{...o}` (nullish spreads nothing; a string or array spreads its indices).
pub(crate) fn spread(o: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    match o {
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                out.insert(i.to_string(), v.clone());
            }
        }
        Value::String(t) => {
            for (i, c) in char::decode_utf16(t.encode_utf16()).enumerate() {
                out.insert(i.to_string(), Value::String(c.unwrap_or('\u{fffd}').to_string()));
            }
        }
        _ => {
            if let Some(m) = obj(o) {
                for (k, v) in m {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
    }
    out
}

pub(crate) fn is_group_map(m: &Map<String, Value>) -> bool {
    m.contains_key("all_of") || m.contains_key("any_of") || m.contains_key("not")
}

pub(crate) fn is_group(c: &Value) -> bool {
    obj(c).is_some_and(is_group_map)
}

/// A leaf condition: an object with a string `field` and no group member.
pub(crate) fn leaf(c: &Value) -> Option<&Map<String, Value>> {
    let m = obj(c)?;
    if is_group_map(m) {
        return None;
    }
    if m.get("field").is_some_and(Value::is_string) {
        Some(m)
    } else {
        None
    }
}

/// An insertion-ordered string set.
#[derive(Default)]
pub(crate) struct OrdSet {
    pub keys: Vec<String>,
    seen: HashSet<String>,
}

impl OrdSet {
    pub fn add(&mut self, k: &str) {
        if self.seen.insert(k.to_string()) {
            self.keys.push(k.to_string());
        }
    }

    pub fn list(&self) -> Vec<Value> {
        self.keys.iter().map(|k| Value::String(k.clone())).collect()
    }
}

/// An insertion-ordered set of JSON values (keyed by `type:JSON`).
#[derive(Default)]
pub(crate) struct OrdVals {
    pub vals: Vec<Value>,
    seen: HashSet<String>,
}

impl OrdVals {
    pub fn add(&mut self, v: &Value) {
        if self.seen.insert(super::field::value_key(v)) {
            self.vals.push(v.clone());
        }
    }
}

pub(crate) fn str_list(xs: &[Value]) -> Vec<String> {
    xs.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()
}

pub(crate) fn join(xs: &[Value], sep: &str) -> String {
    str_list(xs).join(sep)
}

/// A shallow copy of an object value as a map (a non-object is empty).
pub(crate) fn copy_map(v: &Value) -> Map<String, Value> {
    obj(v).cloned().unwrap_or_default()
}

pub(crate) fn nil_if_undef(v: &Value) -> Value {
    if is_undef(v) {
        Value::Null
    } else {
        v.clone()
    }
}

/// The reversibility index of a class value, or -1.
pub(crate) fn rev_index(v: &Value) -> i64 {
    match v.as_str() {
        Some(t) => REV_ORDER.iter().position(|r| *r == t).map_or(-1, |i| i as i64),
        None => -1,
    }
}

pub(crate) fn rev_list() -> Vec<Value> {
    REV_ORDER.iter().map(|r| s(r)).collect()
}

/// `x.toFixed(digits)`.
pub(crate) fn to_fixed(x: f64, digits: u32) -> String {
    crate::doctor::js_to_fixed(x, digits)
}

/// `Math.max(a, b)`: NaN propagates.
pub(crate) fn jmax(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() {
            b
        } else {
            a
        }
    } else if a > b {
        a
    } else {
        b
    }
}

/// `Math.min(a, b)`: NaN propagates.
pub(crate) fn jmin(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() {
            a
        } else {
            b
        }
    } else if a < b {
        a
    } else {
        b
    }
}

/// Ascending order of numbers with NaN first (as `sort.Float64s`).
pub(crate) fn cmp_f64(a: f64, b: f64) -> std::cmp::Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal),
    }
}

pub(crate) fn sort_f64(xs: &mut [f64]) {
    xs.sort_by(|a, b| cmp_f64(*a, *b));
}

/// An object literal from a map: members whose value is undefined are dropped.
pub(crate) fn u_from_map(m: Map<String, Value>) -> Value {
    Value::Object(m.into_iter().filter(|(_, v)| !is_undef(v)).collect())
}

/// `Array.prototype.sort` of strings by UTF-16 code units (stable).
pub(crate) fn sorted_units(mut xs: Vec<String>) -> Vec<Value> {
    xs.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    xs.into_iter().map(Value::String).collect()
}

/// A stable sort driven by a `less` predicate (the reference's `Array.prototype.sort` comparator), safe for inconsistent comparators.
pub(crate) fn stable_sort_by_less<T>(v: &mut Vec<T>, less: &dyn Fn(&T, &T) -> bool) {
    let mut out: Vec<T> = Vec::with_capacity(v.len());
    for x in v.drain(..) {
        let mut at = out.len();
        while at > 0 && less(&x, &out[at - 1]) {
            at -= 1;
        }
        out.insert(at, x);
    }
    *v = out;
}
