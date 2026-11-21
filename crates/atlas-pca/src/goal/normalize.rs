//! Stable JSON and the canonical Goal order (`normalize.ts`).
use super::js::*;
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// Sorted-key JSON (UTF-16 key order): an in-memory key for maps and sets, NOT a signed encoding.
pub fn stable(v: &Value) -> String {
    match v {
        Value::Array(a) => format!("[{}]", a.iter().map(stable).collect::<Vec<_>>().join(",")),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| u16cmp(a, b));
            let parts: Vec<String> =
                keys.into_iter().map(|k| format!("{}:{}", crate::js_stringify(&Value::String(k.clone())), stable(&m[k.as_str()]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        other => crate::js_stringify(other),
    }
}
fn by_id(a: &Value, b: &Value, key: &str) -> Ordering {
    match (a.get(key), b.get(key)) {
        (Some(Value::String(x)), Some(Value::String(y))) => u16cmp(x, y),
        _ => Ordering::Equal, // `<` / `>` on non-strings of the reference compares nothing meaningful here
    }
}
fn sorted_by_id(g: &Value, field: &str, key: &str) -> Result<Value, String> {
    let mut xs = g.get(field).and_then(Value::as_array).ok_or_else(|| format!("{field} is not iterable"))?.clone();
    xs.sort_by(|a, b| by_id(a, b, key));
    Ok(Value::Array(xs))
}
/// `[...new Set(xs)].sort()` over strings.
fn sorted_unique(xs: Option<&Value>) -> Result<Value, String> {
    let a = xs.and_then(Value::as_array).ok_or("not iterable")?;
    let mut out: Vec<String> = Vec::new();
    for x in a {
        let s = x.as_str().ok_or("shortcut: canonicalize_goal sorts string members only")?;
        if !out.iter().any(|y| y == s) {
            out.push(s.to_string());
        }
    }
    out.sort_by(|a, b| u16cmp(a, b));
    Ok(Value::Array(out.into_iter().map(Value::String).collect()))
}
/// Grants, prohibits, bounds and holes strictly increasing by id (code-unit order), `wildcardAck` / `mayTouch` sorted and
/// de-duplicated. Duplicated ids are NOT merged: they stay and the typechecker refuses them.
pub fn canonicalize_goal(g: &Value) -> Result<Value, String> {
    let mut out: Map<String, Value> = g.as_object().ok_or("goal must be an object")?.clone();
    out.insert("grants".into(), sorted_by_id(g, "grants", "gid")?);
    out.insert("prohibits".into(), sorted_by_id(g, "prohibits", "pid")?);
    out.insert("bounds".into(), sorted_by_id(g, "bounds", "bid")?);
    out.insert("holes".into(), sorted_by_id(g, "holes", "hid")?);
    out.insert("wildcardAck".into(), sorted_unique(g.get("wildcardAck"))?);
    let mut d: Map<String, Value> = g.get("deleg").and_then(Value::as_object).ok_or("deleg must be an object")?.clone();
    d.insert("mayTouch".into(), sorted_unique(d.get("mayTouch"))?);
    out.insert("deleg".into(), Value::Object(d));
    Ok(Value::Object(out))
}
