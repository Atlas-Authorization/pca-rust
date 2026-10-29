//! Small shared helpers of the vendor attestation verifiers: hashing, hex, lenient / strict base64, JSON accessors, time.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
pub fn sha384(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}
pub fn sha512(b: &[u8]) -> Vec<u8> {
    Sha512::digest(b).to_vec()
}
pub fn sha1(b: &[u8]) -> Vec<u8> {
    sha1::Sha1::digest(b).to_vec()
}

/// Lowercase hex.
pub fn hex_lower(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// `^[0-9a-fA-F]+$`
pub fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode an even-length hex string (any case); `None` otherwise.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for p in b.chunks(2) {
        out.push((nib(p[0])? << 4) | nib(p[1])?);
    }
    Some(out)
}

pub fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Node's `Buffer.from(s, 'base64')`: both alphabets, padding optional, characters outside the alphabet skipped,
/// decoding stops at the first `=`.
pub fn b64_lenient(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = match b64_val(c) {
            Some(v) => v,
            None => continue,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Standard base64 (padded) of `b`.
pub fn b64_std(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((b.len() + 2) / 3 * 4);
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Unpadded base64url of `b`.
pub fn b64url_enc(b: &[u8]) -> String {
    b64_std(b).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

/// Strict RFC 4648 standard base64 (padding required to a multiple of four, no whitespace); `None` on any deviation.
pub fn b64_strict(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let n = b.len() / 4;
    for (gi, g) in b.chunks(4).enumerate() {
        let last = gi + 1 == n;
        let pad = g.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut acc: u32 = 0;
        for c in &g[..4 - pad] {
            let v = match *c {
                b'-' | b'_' => return None,
                _ => b64_val(*c)?,
            };
            acc = (acc << 6) | v as u32;
        }
        acc <<= 6 * pad as u32;
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

// ───────────────────────────── JSON accessors (mirror the `asString` / `asRecord` helpers of the TypeScript)

pub fn as_obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}
pub fn get_str<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}
pub fn get_obj<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a Map<String, Value>> {
    m.get(k).and_then(Value::as_object)
}
/// `Array.isArray(x) && x.every(string)` -> the strings.
pub fn str_array(v: &Value) -> Option<Vec<String>> {
    let a = v.as_array()?;
    let mut out = Vec::with_capacity(a.len());
    for x in a {
        out.push(x.as_str()?.to_string());
    }
    Some(out)
}
/// First present non-empty string among `keys`.
pub fn first_string<'a>(m: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(s) = m.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}
pub fn lower_list(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.to_lowercase()).collect()
}

// ───────────────────────────── calendar

/// Days since 1970-01-01 of a proleptic Gregorian civil date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// Epoch milliseconds of a civil UTC date-time; `None` when a field is out of range (no roll-over).
pub fn civil_ms(y: i64, mon: i64, day: i64, h: i64, mi: i64, sec: i64, ms: i64) -> Option<i64> {
    if !(1..=12).contains(&mon) || day < 1 || day > days_in_month(y, mon) || !(0..=23).contains(&h) || !(0..=59).contains(&mi) || !(0..=59).contains(&sec) {
        return None;
    }
    Some(((days_from_civil(y, mon, day) * 24 + h) * 60 + mi) * 60_000 + sec * 1000 + ms)
}

/// JavaScript `Date.parse` restricted to the ISO-8601 forms Intel PCS emits: `YYYY-MM-DDTHH:MM:SS[.fff]Z` (also `+00:00`).
/// `None` (NaN) for anything else or an out-of-range field.
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let dig = |i: usize, n: usize| -> Option<i64> {
        let part = b.get(i..i + n)?;
        if part.iter().all(|c| c.is_ascii_digit()) {
            Some(part.iter().fold(0i64, |a, c| a * 10 + (*c - b'0') as i64))
        } else {
            None
        }
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d, h, mi, se) = (dig(0, 4)?, dig(5, 2)?, dig(8, 2)?, dig(11, 2)?, dig(14, 2)?, dig(17, 2)?);
    let mut i = 19;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
        let mut frac = 0i64;
        for k in 0..3 {
            frac = frac * 10 + b.get(start + k).filter(|_| start + k < j).map_or(0, |c| (*c - b'0') as i64);
        }
        ms = frac;
        i = j;
    }
    let rest = &s[i..];
    if rest != "Z" && rest != "z" && rest != "+00:00" && rest != "-00:00" {
        return None;
    }
    civil_ms(y, mo, d, h, mi, se, ms)
}

/// Round-trip helper: a JSON number that is a non-negative safe integer.
pub fn safe_uint(v: f64) -> bool {
    v.is_finite() && v.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&v)
}
