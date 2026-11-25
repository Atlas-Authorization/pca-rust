//! Import external authorization policy into PCA predicates. Port of the TypeScript reference (`@atlasauth/pca-policy-bridge`).
//!
//! * [`cedar_to_pca`] / [`translate_cedar`]  Cedar `permit` / `forbid` policies
//! * [`rego_to_pca`]                         OPA / Rego `allow`-rule subset
//! * [`openfga_to_pca`]                      OpenFGA / Zanzibar ReBAC model plus relationship tuples
//! * [`cel_to_condition`] / [`cel_to_predicate`] / [`cel_conditions_to_pca`] / [`parse_cel`]  strict CEL
//! * [`decide`]                              deny-overrides-permit over a translation, built on the core predicate evaluator
//!
//! Everything is JSON-valued (`serde_json::Value` in and out). Every translator returns
//! `{predicates, denies, caveats, report: {source, translated, skipped, errors}}`; whatever is not modeled fails closed. Text is read the
//! way JavaScript reads it: the JavaScript whitespace set, ASCII word characters, UTF-16 offsets in the CEL positions and in message
//! truncation.
//!
//! shortcut: a lone UTF-16 surrogate cannot exist in a Rust `String`; an astral character that the reference splits mid-pair in a message
//! (an unexpected-character message, a truncation at 77 units) is reported whole (or dropped) instead.
use crate::oauth::js_str;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::sync::LazyLock;

mod cedar;
mod cel;
mod openfga;
mod rego;

pub use cedar::{cedar_to_pca, translate_cedar};
pub use cel::{cel_conditions_to_pca, cel_to_condition, cel_to_predicate, parse_cel};
pub use openfga::openfga_to_pca;
pub use rego::rego_to_pca;

// ---- JavaScript text semantics -----------------------------------------------------------------------------------------------

/// The reference's `Maximum call stack size exceeded`, raised past this many nested frames (the recursive parsers fail closed).
const STACK: &str = "Maximum call stack size exceeded";
const MAX_FRAMES: usize = 1200;

/// The JavaScript whitespace set (`\s` and `String.prototype.trim`).
fn is_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn trim(s: &str) -> &str {
    s.trim_matches(is_ws)
}

/// Expand the pattern placeholders: `§S` JavaScript whitespace, `§N` anything else, `§W` an ASCII word character, `§D` `.`, `§B` an ASCII
/// word boundary.
fn expand(p: &str) -> String {
    const WS: &str = "\t\n\u{b}\u{c}\r \u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}";
    p.replace("§S", &format!("[{WS}]"))
        .replace("§N", &format!("[^{WS}]"))
        .replace("§W", "[A-Za-z0-9_]")
        .replace("§D", "[^\n\r\u{2028}\u{2029}]")
        .replace("§B", "(?-u:\\b)")
}

fn rx(p: &str) -> Regex {
    Regex::new(&expand(p)).expect("policy_bridge pattern")
}

/// A pattern that must match the whole text (`fullmatch`).
fn rx_full(p: &str) -> Regex {
    rx(&format!("\\A(?:{p})\\z"))
}

static WS_RUN: LazyLock<Regex> = LazyLock::new(|| rx("§S+"));

/// The reference's `truncate`: whitespace runs collapsed, trimmed, at most 80 UTF-16 units (77 plus `...`).
fn truncate(s: &str) -> String {
    let collapsed = WS_RUN.replace_all(s, " ");
    let one = trim(&collapsed);
    if one.encode_utf16().count() > 80 {
        let mut out = String::new();
        let mut u = 0;
        for c in one.chars() {
            if u + c.len_utf16() > 77 {
                break;
            }
            u += c.len_utf16();
            out.push(c);
        }
        out.push_str("...");
        out
    } else {
        one.to_string()
    }
}

/// `Number(s)` of a decimal literal as the JSON number the reference serializes.
fn number(s: &str) -> Value {
    let f: f64 = s.parse().unwrap_or(f64::NAN);
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        return json!(f as i64);
    }
    serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
}

/// JavaScript own-key order: array-index keys ascending, then insertion order.
fn key_order(m: &Map<String, Value>) -> Vec<&String> {
    let is_index = |k: &str| {
        k.len() <= 10
            && !k.is_empty()
            && k.bytes().all(|b| b.is_ascii_digit())
            && (k == "0" || !k.starts_with('0'))
            && k.parse::<u64>().is_ok_and(|n| n < 4_294_967_295)
    };
    let mut idx: Vec<&String> = m.keys().filter(|k| is_index(k.as_str())).collect();
    idx.sort_by_key(|k| k.parse::<u64>().unwrap_or(0));
    idx.extend(m.keys().filter(|k| !is_index(k.as_str())));
    idx
}

/// `Object.entries` of an object or array value; `None` for anything else.
fn entries(o: &Value) -> Option<Vec<(String, &Value)>> {
    match o {
        Value::Object(m) => Some(key_order(m).into_iter().map(|k| (k.clone(), &m[k.as_str()])).collect()),
        Value::Array(a) => Some(a.iter().enumerate().map(|(i, x)| (i.to_string(), x)).collect()),
        _ => None,
    }
}

/// An object or array (the reference's "is an object").
fn is_obj(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

/// UTF-16 code-unit order (the reference's default string sort).
fn cmp16(a: &String, b: &String) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

// ---- bracket and quote aware scanning (every delimiter is ASCII, so byte scanning keeps char boundaries) ---------------------------

fn index_of_top_level(text: &str, token: &str) -> Option<usize> {
    let b = text.as_bytes();
    let tk = token.as_bytes();
    let (mut depth, mut in_str) = (0i64, false);
    for i in 0..b.len() {
        let ch = b[i];
        if in_str {
            if ch == b'"' {
                in_str = false;
            }
            continue;
        }
        if ch == b'"' {
            in_str = true;
            continue;
        }
        if matches!(ch, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(ch, b')' | b']' | b'}') {
            depth -= 1;
        } else if depth == 0 && b[i..].starts_with(tk) {
            return Some(i);
        }
    }
    None
}

fn split_top_level<'a>(text: &'a str, delim: &str) -> Vec<&'a str> {
    let b = text.as_bytes();
    let d = delim.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut in_str) = (0i64, false);
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        let ch = b[i];
        if in_str {
            if ch == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if ch == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if matches!(ch, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(ch, b')' | b']' | b'}') {
            depth -= 1;
        }
        if depth == 0 && b[i..].starts_with(d) {
            out.push(&text[start..i]);
            i += d.len();
            start = i;
            continue;
        }
        i += 1;
    }
    out.push(&text[start..]);
    out
}

fn match_delim(text: &str, open: usize, o: u8, c: u8) -> Option<usize> {
    let b = text.as_bytes();
    let (mut depth, mut in_str) = (0i64, false);
    for (i, &ch) in b.iter().enumerate().skip(open) {
        if in_str {
            if ch == b'"' {
                in_str = false;
            }
            continue;
        }
        if ch == b'"' {
            in_str = true;
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn trimmed_non_empty(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| trim(p)).filter(|t| !t.is_empty()).map(String::from).collect()
}

/// `s.slice(1, -1)`.
fn drop_ends(s: &str) -> &str {
    let mut c = s.chars();
    c.next();
    c.next_back();
    c.as_str()
}

// ---- report ------------------------------------------------------------------------------------------------------------------------

struct Report {
    source: &'static str,
    translated: Vec<String>,
    skipped: Vec<String>,
    errors: Vec<String>,
}

impl Report {
    fn new(source: &'static str) -> Self {
        Report { source, translated: vec![], skipped: vec![], errors: vec![] }
    }

    fn into_value(self) -> Value {
        json!({ "source": self.source, "translated": self.translated, "skipped": self.skipped, "errors": self.errors })
    }
}

fn result(predicates: Vec<Value>, denies: Vec<Value>, report: Report) -> Value {
    json!({ "predicates": predicates, "denies": denies, "caveats": [], "report": report.into_value() })
}

fn exists(field: &str) -> Value {
    json!({ "field": field, "op": "exists" })
}

// ---- decide ------------------------------------------------------------------------------------------------------------------------

/// `x.length` of the reference: `Ok(None)` is `undefined` (a number, boolean or object has none); `undefined` and `null` throw.
fn length(x: Option<&Value>) -> Result<Option<usize>, String> {
    match x {
        None => Err("cannot read properties of undefined (reading 'length')".into()),
        Some(Value::Null) => Err("cannot read properties of null (reading 'length')".into()),
        Some(Value::Array(a)) => Ok(Some(a.len())),
        Some(Value::String(s)) => Ok(Some(s.encode_utf16().count())),
        Some(_) => Ok(None),
    }
}

/// `evaluatePredicates(predicates, ctx)`: `{allowed: true, matched}` or `{allowed: false, reason}`. Never fails: an evaluation error is a denial.
fn evaluate(predicates: Option<&Value>, ctx: &Value) -> Value {
    let list: &[Value] = match predicates {
        Some(Value::Array(a)) => a,
        _ => &[],
    };
    let c = crate::predicates::Ctx::new(ctx);
    let hit = crate::safe_regex::with_regex_budget(|| list.iter().find(|p| crate::predicates::predicate_matches(p, &c)).cloned());
    if let Some(p) = hit {
        return json!({ "allowed": true, "matched": p });
    }
    let reason = crate::safe_regex::with_regex_budget(|| crate::authorize::envelope_predicates_denial(list, ctx))
        .unwrap_or_else(|| "predicate evaluation error (fail closed)".into());
    json!({ "allowed": false, "reason": reason })
}

/// Decide one action under a translation with deny-overrides-permit (Cedar's combining rule), built on the core evaluator. An incomplete
/// translation (`report.errors` non-empty) denies everything. `Err` is where the reference throws (a malformed result object).
pub fn decide(result: &Value, ctx: &Value) -> Result<Value, String> {
    let o = match result {
        Value::Object(o) => o,
        Value::Null => return Err("cannot read properties of null (reading 'report')".into()),
        _ => return Err("cannot read properties of undefined (reading 'length')".into()),
    };
    if let Some(report) = o.get("report").filter(|r| crate::oauth::truthy(Some(r))) {
        let errs = match report {
            Value::Object(r) => r.get("errors"),
            _ => None,
        };
        if length(errs)?.is_some_and(|n| n > 0) {
            return Ok(json!({ "allowed": false, "reason": "translation incomplete (fail closed)" }));
        }
    }
    if length(o.get("denies"))?.is_some_and(|n| n > 0) {
        let denied = evaluate(o.get("denies"), ctx);
        if denied["allowed"] == json!(true) {
            return Ok(json!({ "allowed": false, "matched": denied["matched"], "reason": "forbidden by deny policy" }));
        }
    }
    Ok(evaluate(o.get("predicates"), ctx))
}

/// `String(x)` of an optional member (`undefined` when absent).
fn js_text(x: Option<&Value>) -> String {
    x.map_or_else(|| "undefined".to_string(), js_str)
}
