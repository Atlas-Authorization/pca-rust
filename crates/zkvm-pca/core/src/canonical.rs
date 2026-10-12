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
    // Safe integers print exactly; every other number is first rounded to the IEEE double a `JSON.parse` yields (an
    // integer beyond 2^53 included), then printed as ECMAScript `Number::toString`. On the strict profile this is
    // byte-identical to `canonicalizeStrict`; outside it (R6-ZK-04: `env` / `subject` are not strict-profiled in the
    // TS reference) it is the lenient `canonicalize` of hash.ts.
    if let Some(u) = n.as_u64() {
        if u <= MAX_SAFE_INTEGER {
            out.push_str(&u.to_string());
            return;
        }
    }
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() <= MAX_SAFE_INTEGER {
            out.push_str(&i.to_string());
            return;
        }
    }
    let f = n.as_f64().expect("json number must be representable as f64");
    out.push_str(&js_number_to_string(f));
}

/// ECMAScript `Number::toString(x)` (radix 10) for a finite double; `-0` prints as `0` (as `JSON.stringify`).
pub fn js_number_to_string(f: f64) -> String {
    if f == 0.0 || !f.is_finite() {
        return "0".to_string();
    }
    if f < 0.0 {
        return format!("-{}", js_number_to_string(-f));
    }
    // Rust's `{:e}` is the shortest round-trip digit string: "d[.ddd]e<exp>".
    let e = format!("{:e}", f);
    let (mant, exp) = e.split_once('e').expect("exponent form");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().expect("exponent") + 1;
    if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let sign = if n - 1 < 0 { '-' } else { '+' };
        let ex = (n - 1).abs();
        if k == 1 {
            format!("{digits}e{sign}{ex}")
        } else {
            format!("{}.{}e{sign}{ex}", &digits[..1], &digits[1..])
        }
    }
}

/// ECMAScript `String(x)` of a JSON value (`None` = `undefined`): what `bindingOf(..., String(caveat.signature_digest),
/// ...)` hashes (R6-ZK-05). Arrays join their elements' strings with `,` (`null` elements print empty), objects print
/// `[object Object]`.
pub fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => {
            if let Some(u) = n.as_u64().filter(|u| *u <= MAX_SAFE_INTEGER) {
                return u.to_string();
            }
            if let Some(i) = n.as_i64().filter(|i| i.unsigned_abs() <= MAX_SAFE_INTEGER) {
                return i.to_string();
            }
            js_number_to_string(n.as_f64().unwrap_or(0.0))
        }
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| if x.is_null() { String::new() } else { js_string(Some(x)) })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_string(),
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

// ---- R5-ZK-03: the STRICT wire profile checks of `hash.ts` `canonicalizeStrict` / `strictNumberError` ----------------------
//
// `canonicalize` above only SERIALIZES; the TS reference additionally THROWS (so every digest/verdict fails closed) on any
// value outside the strict profile. The guest checks the profile on every document it receives before it evaluates anything.

/// `MAX_JSON_DEPTH` (hash.ts): container nesting accepted by the strict profile (the root container is depth 1).
pub const MAX_JSON_DEPTH: usize = 32;
/// `MAX_DECIMAL_DIGITS` (hash.ts): significant digits of a non-integer number.
pub const MAX_DECIMAL_DIGITS: usize = 15;
/// 2^53 - 1.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `strictNumberError` on the f64 a JavaScript `JSON.parse` would produce. `None` = admissible.
pub fn strict_f64_error(f: f64) -> Option<&'static str> {
    if !f.is_finite() {
        return Some("non-finite number");
    }
    if f == 0.0 && f.is_sign_negative() {
        return Some("negative zero");
    }
    if f.fract() == 0.0 {
        return if f.abs() <= MAX_SAFE_INTEGER as f64 { None } else { Some("integer outside the safe range") };
    }
    if f.abs() < 1e-6 {
        return Some("non-integer magnitude below 1e-6");
    }
    // Rust's `{}` for f64 never uses an exponent and is the shortest round-trip decimal (as V8's `String(v)` in this range).
    let s = format!("{}", f.abs());
    let digits = s.replace('.', "");
    let digits = digits.trim_start_matches('0');
    if digits.len() > MAX_DECIMAL_DIGITS {
        return Some("non-integer number has more than 15 significant digits");
    }
    None
}

/// Strict-profile check of one JSON number.
pub fn strict_number_error(n: &serde_json::Number) -> Option<&'static str> {
    if let Some(u) = n.as_u64() {
        return if u <= MAX_SAFE_INTEGER { None } else { Some("integer outside the safe range") };
    }
    if let Some(i) = n.as_i64() {
        return if i.unsigned_abs() <= MAX_SAFE_INTEGER { None } else { Some("integer outside the safe range") };
    }
    match n.as_f64() {
        Some(f) => strict_f64_error(f),
        None => Some("non-finite number"),
    }
}

/// `Some(reason)` iff `canonicalizeStrict(v)` would throw (unsafe integer, exponent / over-precise float, `-0`,
/// nesting deeper than [`MAX_JSON_DEPTH`]). (Lone surrogates cannot occur in a Rust `String`.)
pub fn strict_violation(v: &Value) -> Option<&'static str> {
    strict_walk(v, 1)
}

fn strict_walk(v: &Value, depth: usize) -> Option<&'static str> {
    match v {
        Value::Number(n) => strict_number_error(n),
        Value::Array(a) => {
            if depth > MAX_JSON_DEPTH {
                return Some("nesting too deep");
            }
            a.iter().find_map(|x| strict_walk(x, depth + 1))
        }
        Value::Object(m) => {
            if depth > MAX_JSON_DEPTH {
                return Some("nesting too deep");
            }
            m.values().find_map(|x| strict_walk(x, depth + 1))
        }
        _ => None,
    }
}

struct CountWriter(usize);
impl std::io::Write for CountWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(b.len());
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// UTF-8 byte length of the compact JSON form of `v` (what a verifier measures against `MAX_ARTIFACT_BYTES`).
pub fn json_len(v: &Value) -> usize {
    let mut w = CountWriter(0);
    let _ = serde_json::to_writer(&mut w, v);
    w.0
}
