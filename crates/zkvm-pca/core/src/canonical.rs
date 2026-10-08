//! Strict, language-portable canonical JSON — a faithful Rust port of
//! `packages/pca/src/hash.ts` `canonicalizeStrict` / `ser(..., strict=true)`.
//!
//! Rules reproduced exactly:
//!  - object keys sorted BYTEWISE over their UTF-8 encoding (== Unicode code-point order), recursively;
//!  - no whitespace;
//!  - JSON string escaping identical to `JSON.stringify` (serde_json matches: `\" \\ \b \t \n \f \r`,
//!    other control chars as `\u00XX` lowercase, forward slash NOT escaped, non-ASCII raw UTF-8);
//!  - integer-valued numbers printed without a fractional part (`1.0` -> `1`), matching ECMAScript
//!    `Number::toString`; non-integer numbers printed with the shortest round-trip decimal.
//!
//! Used to derive the sha256 commitments INSIDE the zkVM guest from the structured preimages, so the
//! commitment is PROVEN to equal `sha256(canonical(preimage))` rather than asserted by an honest prover.
//! For the committed fixture the bytes are cross-checked byte-for-byte against the TS reference.

use serde_json::Value;

/// Serialize `v` into the strict canonical JSON string.
pub fn canonicalize(v: &Value) -> String {
    let mut out = String::new();
    ser(v, &mut out);
    out
}

/// Strict canonical bytes (UTF-8 of [`canonicalize`]).
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    canonicalize(v).into_bytes()
}

fn ser(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => ser_number(n, out),
        Value::String(s) => ser_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys bytewise over UTF-8 (serde_json's default Map is a BTreeMap, already
            // byte-lexicographic, but we sort explicitly so the invariant holds regardless of features).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser_string(k, out);
                out.push(':');
                ser(map.get(*k).unwrap(), out);
            }
            out.push('}');
        }
    }
}

fn ser_number(n: &serde_json::Number, out: &mut String) {
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return;
    }
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return;
    }
    let f = n.as_f64().expect("json number must be representable as f64");
    out.push_str(&format_f64(f));
}

/// Format an `f64` the way `JSON.stringify` / ECMAScript `Number::toString` does for the strict
/// profile: an integer-valued double drops the fractional part; otherwise the shortest round-trip
/// decimal (Rust's default `{}` float formatting is shortest round-trip, like V8 for these magnitudes).
fn format_f64(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string(); // normalizes -0.0 -> "0"
    }
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        return (f as i64).to_string();
    }
    let s = format!("{}", f);
    match s.strip_suffix(".0") {
        Some(stripped) => stripped.to_string(),
        None => s,
    }
}

/// JSON string escaping identical to serde_json / `JSON.stringify`.
fn ser_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let code = c as u32;
                for shift in [12u32, 8, 4, 0] {
                    let nyb = (code >> shift) & 0xf;
                    out.push(core::char::from_digit(nyb, 16).unwrap());
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
