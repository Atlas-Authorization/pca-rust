//! Trusted-setup provenance for the zero-knowledge circuits: the id of a verifying key ([`vk_id`]), the record that ties a circuit's
//! sources and constraint system to its key ([`circuit_provenance`], [`check_circuit_provenance`]), and the transcript of a
//! multi-party ceremony ([`transcript_sha256`], [`check_transcript`], [`ceremony_of`]). Pure: SHA-256 over strict canonical JSON.
//!
//! A transcript is `{version: 1, circuit, curve: "bn128" | "bls12-381", r1csSha256, ptauSha256, initZkeySha256, minContributions,
//! contributions: [{index, name, prevZkeySha256, zkeySha256}], beacon: {hashHex, iterationsExp, prevZkeySha256, zkeySha256},
//! finalZkeySha256, vkId}`. A key counts as `multi-party` only with a well-formed transcript of at least two chained
//! contributions and a random beacon that names this very key and matches the pinned transcript digest; everything else,
//! any error included, is `single-party` (fail closed to the weaker label).

use crate::canonicalize_strict;
use serde_json::{json, Value};
use std::collections::HashSet;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha_hex(v: &Value) -> Result<String, String> {
    Ok(hex(&crate::sha(canonicalize_strict(v)?.as_bytes())))
}

fn is_h64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// JavaScript `String(value)` of a JSON value (`None` = undefined).
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => crate::intent_v2::js_number_string(n.as_f64().unwrap_or(f64::NAN)),
        Some(Value::Array(a)) => a.iter().map(|x| if x.is_null() { String::new() } else { js_string(Some(x)) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// A member coerced to text is a lower-case SHA-256 hex digest.
fn h64(v: Option<&Value>) -> bool {
    is_h64(&js_string(v))
}

/// JavaScript `===` of two JSON values from separately parsed documents: primitives by value, objects and arrays never.
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::Object(_) | Value::Array(_)), _) | (_, Some(Value::Object(_) | Value::Array(_))) => false,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

fn safe_integer(v: Option<&Value>) -> Option<f64> {
    v.filter(|x| x.is_number()).and_then(Value::as_f64).filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE)
}

/// The id of a verifying key: `vk_` + hex SHA-256 of its strict canonical JSON. `Err` for a key outside the strict profile.
pub fn vk_id(vkey: &Value) -> Result<String, String> {
    Ok(format!("vk_{}", sha_hex(vkey)?))
}

/// The provenance record `{circuit, sourceSha256, r1csSha256, vkId}` of `{circuit, sourceSha256, r1csSha256, vkey}`. Refuses an
/// empty circuit id, a hash that is not a lower-case SHA-256 hex digest and a missing key.
pub fn circuit_provenance(args: &Value) -> Result<Value, String> {
    if !h64(args.get("sourceSha256")) || !h64(args.get("r1csSha256")) || args.get("circuit").and_then(Value::as_str) == Some("") {
        return Err("circuitProvenance: bad circuit id or hash".into());
    }
    let vkey = args.get("vkey").ok_or("canonicalize: unsupported type undefined")?;
    let mut out = json!({"sourceSha256": args["sourceSha256"], "r1csSha256": args["r1csSha256"], "vkId": vk_id(vkey)?});
    if let Some(c) = args.get("circuit") {
        out["circuit"] = c.clone();
    }
    Ok(out)
}

/// Check a provenance record against what the verifier pins (`{circuit, sourceSha256, r1csSha256?, vkey}`): `None` when it
/// matches, else the reason.
pub fn check_circuit_provenance(prov: &Value, expect: &Value) -> Option<String> {
    if !(prov.is_object() || prov.is_array()) {
        return Some("not a provenance record".into());
    }
    if !same(prov.get("circuit"), expect.get("circuit")) {
        return Some("record is for another circuit".into());
    }
    if !same(prov.get("sourceSha256"), expect.get("sourceSha256")) {
        return Some("circuit sources differ from the pinned version".into());
    }
    let r1cs = prov.get("r1csSha256");
    if !r1cs.and_then(Value::as_str).is_some_and(is_h64) || (expect.get("r1csSha256").is_some() && !same(r1cs, expect.get("r1csSha256"))) {
        return Some("constraint system differs".into());
    }
    let recorded = expect.get("vkey").and_then(|k| vk_id(k).ok());
    if recorded.is_none() || prov.get("vkId").and_then(Value::as_str) != recorded.as_deref() {
        return Some("verifying key is not the recorded one".into());
    }
    None
}

/// Hex SHA-256 of a transcript's strict canonical JSON (what a verifier pins).
pub fn transcript_sha256(t: &Value) -> Result<String, String> {
    sha_hex(t)
}

/// `Math.max` operand of a caller option: a number, a numeric string, absent or null (the default), else NaN.
fn number_or(v: Option<&Value>, default: f64) -> f64 {
    match v {
        None | Some(Value::Null) => default,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(f64::NAN),
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        _ => f64::NAN,
    }
}

/// Check a ceremony transcript under `opts` (`{minContributions?, r1csSha256?, circuit?}`): `None` when it is well formed, else
/// the first reason. At least `max(2, opts.minContributions, transcript.minContributions)` contributions, each chained from the
/// previous key with a distinct name and key, then a random beacon applied after the last one whose output is the final key.
pub fn check_transcript(t: &Value, opts: &Value) -> Option<String> {
    if !(t.is_object() || t.is_array()) || !t.get("version").is_some_and(|v| v.as_f64() == Some(1.0) && v.is_number()) {
        return Some("not a version-1 transcript".into());
    }
    if !t.get("circuit").and_then(Value::as_str).is_some_and(|c| !c.is_empty()) {
        return Some("no circuit id".into());
    }
    if opts.get("circuit").is_some() && !same(t.get("circuit"), opts.get("circuit")) {
        return Some("transcript is for another circuit".into());
    }
    if !matches!(t.get("curve").and_then(Value::as_str), Some("bn128" | "bls12-381")) {
        return Some("unknown curve".into());
    }
    for k in ["r1csSha256", "ptauSha256", "initZkeySha256"] {
        if !h64(t.get(k)) {
            return Some(format!("{k} is not a SHA-256"));
        }
    }
    if opts.get("r1csSha256").is_some() && !same(t.get("r1csSha256"), opts.get("r1csSha256")) {
        return Some("transcript is for a different constraint system".into());
    }
    let operands = [2.0, number_or(opts.get("minContributions"), 2.0), safe_integer(t.get("minContributions")).unwrap_or(2.0)];
    let min = if operands.iter().any(|f| f.is_nan()) { f64::NAN } else { operands.iter().fold(f64::NEG_INFINITY, |a, b| a.max(*b)) };
    let cs = match t.get("contributions").and_then(Value::as_array) {
        Some(cs) if !((cs.len() as f64) < min) => cs,
        _ => return Some(format!("fewer than {} contributions", crate::intent_v2::js_number_string(min))),
    };
    let (mut names, mut keys): (HashSet<&str>, HashSet<&str>) = (HashSet::new(), HashSet::new());
    let mut prev = t.get("initZkeySha256");
    for (i, c) in cs.iter().enumerate() {
        let index_ok = c.get("index").is_some_and(|x| x.is_number() && x.as_f64().is_some_and(|f| f == i as f64 && !(f == 0.0 && f.is_sign_negative())));
        let name = c.get("name").and_then(Value::as_str).filter(|n| !n.is_empty());
        let (true, true, Some(name)) = (truthy(Some(c)), index_ok, name) else { return Some(format!("contribution {i} is malformed")) };
        if !h64(c.get("zkeySha256")) || !same(c.get("prevZkeySha256"), prev) {
            return Some(format!("contribution {i} does not chain from the previous key"));
        }
        let key = c.get("zkeySha256").and_then(Value::as_str);
        if names.contains(name) || key.is_some_and(|k| keys.contains(k)) {
            return Some(format!("contribution {i} repeats a name or key"));
        }
        names.insert(name);
        if let Some(k) = key {
            keys.insert(k);
        }
        prev = c.get("zkeySha256");
    }
    let b = t.get("beacon");
    let exp = b.and_then(|b| safe_integer(b.get("iterationsExp")));
    if !truthy(b) || !h64(b.and_then(|b| b.get("hashHex"))) || !exp.is_some_and(|e| (10.0..=63.0).contains(&e)) {
        return Some("no valid random beacon".into());
    }
    let out = b.and_then(|b| b.get("zkeySha256"));
    if !same(b.and_then(|b| b.get("prevZkeySha256")), prev) || !h64(out) {
        return Some("beacon is not applied after the last contribution".into());
    }
    if !same(t.get("finalZkeySha256"), out) {
        return Some("final key is not the beacon output".into());
    }
    let id_ok = t.get("vkId").and_then(Value::as_str).and_then(|v| v.strip_prefix("vk_")).is_some_and(is_h64);
    if !id_ok {
        return Some("no verifying-key id".into());
    }
    None
}

/// `multi-party` when `evidence` (`{transcript, sha256, r1csSha256?, circuit?}`) carries a well-formed transcript whose digest is
/// the pinned `sha256` and whose key id is this key's; else `single-party`.
pub fn ceremony_of(vkey: Option<&Value>, evidence: Option<&Value>) -> &'static str {
    let multi = || -> Option<bool> {
        let (vkey, ev) = (vkey.filter(|k| truthy(Some(k)))?, evidence.filter(|e| truthy(Some(e)))?);
        let t = ev.get("transcript")?;
        let mut opts = serde_json::Map::new();
        for k in ["r1csSha256", "circuit"] {
            if let Some(v) = ev.get(k) {
                opts.insert(k.into(), v.clone());
            }
        }
        if check_transcript(t, &Value::Object(opts)).is_some() {
            return Some(false);
        }
        let digest = transcript_sha256(t).ok()?;
        Some(ev.get("sha256").and_then(Value::as_str) == Some(digest.as_str()) && t.get("vkId").and_then(Value::as_str) == vk_id(vkey).ok().as_deref())
    };
    if multi() == Some(true) {
        "multi-party"
    } else {
        "single-party"
    }
}
