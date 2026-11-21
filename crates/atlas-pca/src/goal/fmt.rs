//! Rendering helpers for quantities, values and actions (`fmt.ts`). An unknown currency is shown in raw minor units, never guessed.
use super::js::*;
use serde_json::Value;

pub fn ccy_exponent(ccy: &str) -> Option<usize> {
    match ccy {
        "USD" | "EUR" | "GBP" | "CAD" | "AUD" | "CHF" => Some(2),
        "JPY" | "KRW" => Some(0),
        _ => None,
    }
}
pub fn fmt_money(ccy: &str, minor: i64) -> String {
    match ccy_exponent(ccy) {
        None => format!("{ccy} {minor} (minor units)"),
        Some(0) => format!("{ccy} {minor}"),
        Some(e) => {
            // `String(minor).padStart(e + 1, "0")`, split before the last `e` digits
            let mut s = minor.to_string();
            while s.len() < e + 1 {
                s.insert(0, '0');
            }
            let cut = s.len() - e;
            format!("{ccy} {}.{}", &s[..cut], &s[cut..])
        }
    }
}
pub fn fmt_quantity(q: &Value) -> Result<String, String> {
    let u = jget(Some(q), "u")?;
    let n = jget(Some(q), "n")?;
    let ns = js_str(n);
    let kk = jget(u, "k")?;
    if is_str(kk, "money") {
        return match (jget(u, "ccy")?, safe_int(n)) {
            (Some(Value::String(c)), Some(m)) => Ok(fmt_money(c, m)),
            _ => Err("shortcut: money quantities need a string currency and a safe integer".into()),
        };
    }
    for (name, pre, post) in [("count", "", ""), ("duration", "", "ms"), ("instant", "@", ""), ("bytes", "", "B"), ("ratio", "", "ppm")] {
        if is_str(kk, name) {
            return Ok(format!("{pre}{ns}{post}"));
        }
    }
    Err("unknown unit tag".into())
}
pub fn fmt_value(v: &Value) -> Result<String, String> {
    let kk = jget(Some(v), "k")?;
    if is_str(kk, "q") {
        return fmt_quantity(jget(Some(v), "q")?.ok_or("quantity missing")?);
    }
    if is_str(kk, "s") {
        return match jget(Some(v), "s")? {
            Some(s @ Value::String(_)) => Ok(crate::js_stringify(s)),
            _ => Err("string expected".into()),
        };
    }
    let items = jget(Some(v), "items")?.and_then(Value::as_array).ok_or("items must be an array")?;
    let parts: Result<Vec<String>, String> = items.iter().map(fmt_value).collect();
    Ok(format!("{{{}}}", parts?.join(", ")))
}
pub fn fmt_act(a: &Value) -> Result<String, String> {
    let params = jget(Some(a), "params")?;
    let mut keys = okeys(params)?;
    keys.sort_by(|x, y| u16cmp(x, y));
    let mut ps: Vec<String> = Vec::new();
    for k in &keys {
        ps.push(format!("{k}={}", fmt_value(oget(params, k).ok_or("parameter value missing")?)?));
    }
    let ps = ps.join(", ");
    let verb = js_str(jget(Some(a), "verb")?);
    let res = js_str(jget(Some(a), "res")?);
    Ok(if ps.is_empty() { format!("{verb} on {res}") } else { format!("{verb} on {res} ({ps})") })
}
