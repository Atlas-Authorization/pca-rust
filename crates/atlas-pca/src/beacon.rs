//! Dead-man liveness beacons v2 (port of `beacons.ts`): an issuer (the grant's principal, or the operator / guardian) signs short-lived
//! beacons; authority is live only while a valid beacon covers the current moment. A beacon binds an `instance`, a `scope` (`*` or a
//! grant ref), an `epoch`, a strictly monotonic `seq`, and a HARD maximum validity. The PCActn commits to one through its signed
//! `freshness.beacon_ref`. Verify paths are total: malformed input is a refusal, never a panic.
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::intent_strict::{artifact_suite_error, verify_artifact_sig};
use crate::kv::AtomicKv;

/// Scope covering every grant of the instance.
pub const GLOBAL_SCOPE: &str = "*";
/// Signing domain of a beacon (the NUL is part of it).
pub const LIVENESS_DOMAIN: &str = "atlas-pca/beacon/v2\0";
/// Length of one beacon epoch.
pub const BEACON_EPOCH_MS: i64 = 60_000;
/// HARD ceiling on `not_after - issued_at`: no issuer can mint a longer-lived beacon.
pub const BEACON_MAX_VALIDITY_MS: i64 = 60 * 60_000;
/// Tolerated clock skew for a beacon issued "in the future".
pub const BEACON_CLOCK_SKEW_MS: i64 = 30_000;

const BODY_KEYS: [&str; 8] = ["v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer"];
const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// `Number.isInteger`: an integral JSON number (an integral float counts).
fn int_of(v: Option<&Value>) -> Option<i64> {
    let n = v?.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= 9.2e18)?;
    Some(n as i64)
}

/// Mint a beacon. `validity_ms` defaults to five epochs; errors carry the reference's RangeError texts.
pub fn issue_liveness_beacon(issuer: &KeyPair, instance: &str, scope: Option<&str>, seq: i64, issued_at: i64, validity_ms: Option<i64>, suite: &Suite) -> Result<Value, String> {
    let validity = validity_ms.unwrap_or(5 * BEACON_EPOCH_MS);
    if seq < 0 {
        return Err("issueLivenessBeacon: seq must be a non-negative integer".into());
    }
    if issued_at < 0 {
        return Err("issueLivenessBeacon: issuedAt must be an integer".into());
    }
    if validity <= 0 || validity > BEACON_MAX_VALIDITY_MS {
        return Err(format!("issueLivenessBeacon: validity must be in (0, {BEACON_MAX_VALIDITY_MS}] ms"));
    }
    let body = json!({"v": 2, "instance": instance, "scope": scope.unwrap_or(GLOBAL_SCOPE), "epoch": issued_at.div_euclid(BEACON_EPOCH_MS), "seq": seq,
        "issued_at": issued_at, "not_after": issued_at + validity, "issuer": issuer.public});
    sign_artifact(LIVENESS_DOMAIN, &body, issuer, suite)
}

/// What the PCActn commits in `freshness.beacon_ref`: b64u(sha256(strictCanonical(beacon))).
pub fn beacon_ref(b: &Value) -> Option<String> {
    crate::hash_canonical_strict(b)
}

/// Signature, pinned issuer, instance + scope binding, the HARD maximum validity and the freshness window. `Err` is the reason.
/// `pq_pins` maps an issuer identity to the PQ key pinned for it (a pure-PQ or hybrid beacon verifies only under it).
pub fn verify_liveness_beacon(b: &Value, issuers: &[String], now: i64, instance: &str, scope: Option<&str>, pq_pins: Option<&Map<String, Value>>) -> Result<(), String> {
    let bad = || "malformed beacon".to_string();
    let o = b.as_object().ok_or_else(bad)?;
    // an unsupported or malformed suite is a malformed beacon (the reference resolves the suite before anything else)
    if int_of(o.get("v")) != Some(2) || artifact_suite_error(o).is_some() {
        return Err(bad());
    }
    if o.get("instance").and_then(Value::as_str) != Some(instance) {
        return Err("wrong instance".into());
    }
    let issuer = o.get("issuer").and_then(Value::as_str).filter(|i| issuers.iter().any(|x| x == i)).ok_or_else(|| "issuer not pinned".to_string())?;
    // the signed body: the eight members, plus the suite members a non-default suite binds (explicit ed25519 binds nothing)
    let mut art = Map::new();
    for k in BODY_KEYS {
        if let Some(v) = o.get(k) {
            art.insert(k.into(), v.clone());
        }
    }
    let default_suite = o.get("alg").and_then(Value::as_str).is_none_or(|a| a == "ed25519");
    if !default_suite {
        for k in ["alg", "pq_pk"] {
            if let Some(v) = o.get(k) {
                art.insert(k.into(), v.clone());
            }
        }
    }
    for k in ["sig", "pq_sig"] {
        if let Some(v) = o.get(k) {
            art.insert(k.into(), v.clone());
        }
    }
    let pin = pq_pins.and_then(|m| m.get(issuer));
    if !verify_artifact_sig(LIVENESS_DOMAIN, &art, issuer, pin) {
        return Err("bad signature".into());
    }
    let (epoch, issued, not_after) = match (int_of(o.get("epoch")), int_of(o.get("seq")), int_of(o.get("issued_at")), int_of(o.get("not_after"))) {
        (Some(e), Some(s), Some(i), Some(n)) if s >= 0 => (e, i, n),
        _ => return Err("malformed window".into()),
    };
    if not_after <= issued || not_after - issued > BEACON_MAX_VALIDITY_MS {
        return Err("validity exceeds the hard maximum".into());
    }
    if epoch != issued.div_euclid(BEACON_EPOCH_MS) {
        return Err("epoch does not match issued_at".into());
    }
    if now + BEACON_CLOCK_SKEW_MS < issued {
        return Err("not yet valid".into());
    }
    if now > not_after {
        return Err("expired".into());
    }
    let bscope = o.get("scope").and_then(Value::as_str);
    if scope.is_some_and(|s| bscope != Some(GLOBAL_SCOPE) && bscope != Some(s)) {
        return Err("scope not covered".into());
    }
    Ok(())
}

/// Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher `seq`. Total.
pub fn accept_beacon(prev_seq: Option<i64>, next: &Value) -> Result<(), String> {
    let seq = match next.get("seq").and_then(|s| int_of(Some(s))) {
        Some(s) if (0..=MAX_SAFE).contains(&s) && !next.get("seq").and_then(Value::as_f64).is_some_and(|f| f == 0.0 && f.is_sign_negative()) => s,
        _ => return Err("malformed beacon".into()),
    };
    match prev_seq {
        Some(p) if seq <= p => Err(format!("replayed beacon: seq {seq} <= {p}")),
        _ => Ok(()),
    }
}

/// Frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze.
pub fn is_frozen_liveness(beacons: &[Value], issuers: &[String], now: i64, instance: &str, scope: Option<&str>, pq_pins: Option<&Map<String, Value>>) -> bool {
    !beacons.iter().any(|b| verify_liveness_beacon(b, issuers, now, instance, scope, pq_pins).is_ok())
}

/// The verified beacon-check decision (`beaconDecision`): `rejected` / `replayed` / `unbound` / `pass` / `not-enforced`.
pub fn beacon_decision(present: bool, ok: bool, replayed: bool, ref_binds: bool) -> &'static str {
    if !present {
        "not-enforced"
    } else if !ok {
        "rejected"
    } else if replayed {
        "replayed"
    } else if ref_binds {
        "pass"
    } else {
        "unbound"
    }
}

/// Durable replay protection: the highest accepted `seq` per (instance, scope, issuer) kept in an atomic key/value store.
pub struct BeaconAcceptor {
    kv: Arc<dyn AtomicKv>,
}

impl BeaconAcceptor {
    pub fn new(kv: Arc<dyn AtomicKv>) -> Self {
        BeaconAcceptor { kv }
    }

    /// Verify `b`, then record its `seq` iff STRICTLY above the highest already accepted. `Err` is the reason; a store that cannot
    /// decide (an error, a malformed stored value) refuses with `beacon state unavailable`.
    pub fn accept(&self, b: &Value, issuers: &[String], now: i64, instance: &str, scope: Option<&str>, pq_pins: Option<&Map<String, Value>>) -> Result<(), String> {
        verify_liveness_beacon(b, issuers, now, instance, scope, pq_pins)?;
        let seq = int_of(b.get("seq")).ok_or_else(|| "malformed beacon".to_string())?;
        let key = format!("beacon-seq/v1/{}", json!([b["instance"], b["scope"], b["issuer"]]));
        let mut junk = false;
        let mut replay_of: Option<i64> = None;
        let r = self.kv.update(&key, &mut |prev| match prev {
            None => Some(json!(seq)),
            Some(p) => match int_of(Some(p)).filter(|n| (0..=MAX_SAFE).contains(n)) {
                None => {
                    junk = true;
                    None
                }
                Some(n) if seq <= n => {
                    replay_of = Some(n);
                    None
                }
                Some(_) => Some(json!(seq)),
            },
        });
        if r.is_err() || junk {
            return Err("beacon state unavailable".into());
        }
        match replay_of {
            Some(n) => Err(format!("replayed beacon: seq {seq} <= {n}")),
            None => Ok(()),
        }
    }
}

// ---- JSON-valued entry points (the reference's loosely typed arguments) -----------------------------------------------------------
//
// The functions below take the verify `check` and the beacons as JSON, with JavaScript's coercions where the reference makes them: a
// clock is compared as a number (a missing or non-finite one makes every window comparison false, a string is read as a number, and
// added to the skew it is concatenated first), `issuers` may be a list or a string (a substring test), a non-integer member is a
// malformed window. A number that is not finite is the `{"$num": "NaN" | "Infinity" | "-Infinity"}` marker of the reference's JSON: it
// has no canonical form, so a beacon carrying one cannot be signed, hashed or verified.

fn marker_of(v: &Value) -> Option<f64> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    match m.get("$num").and_then(Value::as_str)? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

/// `typeof v === 'number'` as a double (a JSON number or the non-finite marker).
fn number_of(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if v.is_number() {
        v.as_f64()
    } else {
        marker_of(v)
    }
}

/// `Number.isInteger(v)`.
fn is_integer(v: Option<&Value>) -> Option<f64> {
    number_of(v).filter(|f| f.is_finite() && f.fract() == 0.0)
}

fn string_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>().ok().filter(|_| !t.contains(['_', 'n', 'N', 'i'])).unwrap_or(f64::NAN)
    }
}

/// ECMAScript `ToNumber` of a JSON value (`undefined` is NaN).
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => string_to_number(s),
        other => number_of(other).unwrap_or(f64::NAN),
    }
}

/// `v + n` for a number `n`: a string operand concatenates (then reads back as a number); `undefined` is NaN.
fn plus(v: Option<&Value>, n: f64) -> f64 {
    match v {
        Some(Value::String(s)) => string_to_number(&format!("{s}{}", crate::intent_v2::js_number_string(n))),
        other => to_number(other) + n,
    }
}

fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => marker_of(x).map_or_else(|| crate::intent_v2::js_value_string(x), crate::intent_v2::js_number_string),
    }
}

fn strict_equal(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Null), Some(Value::Null)) => true,
        _ => false,
    }
}

fn canonical_number(f: f64) -> Result<Value, String> {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        Ok(json!(f as i64))
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).ok_or_else(|| "canonicalize: non-finite number".to_string())
    }
}

/// The signed message of a beacon body: the domain, then the strict canonical `{v, instance, scope, epoch, seq, issued_at, not_after,
/// issuer}` (plus `alg` and `pq_pk` for a non-default suite the dispatch knows). `Err` where the reference throws (a missing member, a
/// non-finite number, a PQ suite without its key).
pub fn liveness_beacon_message(b: &Value) -> Result<Vec<u8>, String> {
    let mut body = Map::new();
    for k in BODY_KEYS {
        let v = b.get(k).ok_or("canonicalize: unsupported type undefined")?;
        if marker_of(v).is_some() {
            return Err("canonicalize: non-finite number".into());
        }
        body.insert(k.into(), v.clone());
    }
    // `bindSuiteFields`: an unknown suite binds nothing, a post-quantum one binds its name and key
    if let Ok(suite) = crate::intent_suite::suite_of(b.get("alg")) {
        if suite.needs_pq_pk {
            body.insert("alg".into(), json!(suite.alg));
            let pk = b.get("pq_pk").ok_or("canonicalize: unsupported type undefined")?;
            body.insert("pq_pk".into(), pk.clone());
        }
    }
    let mut m = LIVENESS_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize_strict(&Value::Object(body))?.as_bytes());
    Ok(m)
}

/// Mint a beacon from `{instance, scope?, seq, issuedAt, validityMs?}` as the reference does (a `null` scope or validity is absent; no
/// type is checked beyond the integer rules). `Err` carries the reference's RangeError texts and its canonicalisation refusals.
pub fn issue_liveness_beacon_value(args: &Value, issuer: &KeyPair, suite: &Suite) -> Result<Value, String> {
    let given = |k: &str| args.get(k).filter(|v| !v.is_null());
    let validity = match given("validityMs") {
        None => 5.0 * BEACON_EPOCH_MS as f64,
        Some(v) => number_of(Some(v)).unwrap_or(f64::NAN),
    };
    let (seq, issued) = (args.get("seq"), args.get("issuedAt"));
    if !is_integer(seq).is_some_and(|s| s >= 0.0) {
        return Err("issueLivenessBeacon: seq must be a non-negative integer".into());
    }
    if !is_integer(issued).is_some_and(|i| i >= 0.0) {
        return Err("issueLivenessBeacon: issuedAt must be an integer".into());
    }
    if !(validity.is_finite() && validity.fract() == 0.0) || validity <= 0.0 || validity > BEACON_MAX_VALIDITY_MS as f64 {
        return Err(format!("issueLivenessBeacon: validity must be in (0, {BEACON_MAX_VALIDITY_MS}] ms"));
    }
    let issued_f = issued.and_then(Value::as_f64).unwrap_or(f64::NAN);
    let mut body = Map::new();
    body.insert("v".into(), json!(2));
    body.insert("instance".into(), args.get("instance").ok_or("canonicalize: unsupported type undefined")?.clone());
    body.insert("scope".into(), given("scope").cloned().unwrap_or_else(|| json!(GLOBAL_SCOPE)));
    body.insert("epoch".into(), canonical_number((issued_f / BEACON_EPOCH_MS as f64).floor())?);
    body.insert("seq".into(), seq.cloned().unwrap_or(Value::Null));
    body.insert("issued_at".into(), issued.cloned().unwrap_or(Value::Null));
    body.insert("not_after".into(), canonical_number(issued_f + validity)?);
    body.insert("issuer".into(), json!(issuer.public));
    sign_artifact(LIVENESS_DOMAIN, &Value::Object(body), issuer, suite)
}

/// `verifyLivenessBeacon(b, check)` with `check` `{issuers, now, instance, scope?, pqPins?}` as JSON. Total: `Err` is the reason. A
/// post-quantum or hybrid beacon verifies only under the key pinned for its issuer in `pqPins` (the reference's unbound opt-out is not
/// offered).
pub fn verify_liveness_beacon_check(b: &Value, check: &Value) -> Result<(), String> {
    let bad = || "malformed beacon".to_string();
    let Some(o) = b.as_object().filter(|_| !b.is_null()) else { return Err(bad()) };
    if o.get("v").and_then(Value::as_f64) != Some(2.0) || (o.get("alg").is_some() && crate::intent_suite::suite_of(o.get("alg")).is_err()) {
        return Err(bad());
    }
    if !strict_equal(o.get("instance"), check.get("instance")) {
        return Err("wrong instance".into());
    }
    let issuer = o.get("issuer");
    let pinned = match check.get("issuers") {
        Some(Value::Array(l)) => l.iter().any(|x| strict_equal(Some(x), issuer)),
        Some(Value::String(s)) => issuer.and_then(Value::as_str).is_some_and(|i| s.contains(i)),
        _ => return Err(bad()), // `undefined.includes` / `null.includes`: a TypeError
    };
    if !pinned {
        return Err("issuer not pinned".into());
    }
    let msg = liveness_beacon_message(b).map_err(|_| bad())?;
    let issuer_s = issuer.and_then(Value::as_str).unwrap_or("");
    let pin = check.get("pqPins").and_then(|p| p.get(issuer_s)).filter(|p| p.is_string()).map(|p| (issuer_s, p));
    let signed = crate::intent_suite::verify_pinned_suite(o.get("alg"), issuer_s, o.get("pq_pk"), &msg, o.get("sig"), o.get("pq_sig"), pin).unwrap_or(false);
    if !signed {
        return Err("bad signature".into());
    }
    let ints: Vec<Option<f64>> = ["epoch", "seq", "issued_at", "not_after"].iter().map(|k| is_integer(o.get(*k))).collect();
    let (Some(epoch), Some(seq), Some(issued), Some(not_after)) = (ints[0], ints[1], ints[2], ints[3]) else { return Err("malformed window".into()) };
    if seq < 0.0 {
        return Err("malformed window".into());
    }
    if not_after <= issued || not_after - issued > BEACON_MAX_VALIDITY_MS as f64 {
        return Err("validity exceeds the hard maximum".into());
    }
    if epoch != (issued / BEACON_EPOCH_MS as f64).floor() {
        return Err("epoch does not match issued_at".into());
    }
    let now = check.get("now");
    // as the reference: "not yet valid" only when the clock is before the window (a NaN clock compares false); a clock that is not
    // within the window, NaN and +infinity included, is "expired"
    if plus(now, BEACON_CLOCK_SKEW_MS as f64) < issued {
        return Err("not yet valid".into());
    }
    if !(to_number(now) <= not_after) {
        return Err("expired".into());
    }
    if let Some(scope) = check.get("scope") {
        let bscope = o.get("scope");
        if !strict_equal(bscope, Some(&json!(GLOBAL_SCOPE))) && !strict_equal(bscope, Some(scope)) {
            return Err("scope not covered".into());
        }
    }
    Ok(())
}

/// `acceptBeacon(prev, next)` over JSON: `prev` (`null` or absent: none) is anything with a `seq`; `next` needs a safe-integer `seq`
/// that is not negative or `-0`, and strictly above `prev.seq`. Total.
pub fn accept_beacon_value(prev: &Value, next: &Value) -> Result<(), String> {
    let seq = next.get("seq");
    let ok = next.is_object() && seq.and_then(Value::as_f64).is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 && f >= 0.0 && !(f == 0.0 && f.is_sign_negative()));
    if !ok {
        return Err("malformed beacon".into());
    }
    let truthy = !matches!(prev, Value::Null | Value::Bool(false)) && prev.as_str() != Some("");
    if truthy && !(to_number(seq) > to_number(prev.get("seq"))) {
        return Err(format!("replayed beacon: seq {} <= {}", js_string(seq), js_string(prev.get("seq"))));
    }
    Ok(())
}

/// `isFrozenLiveness(beacons, check)` over JSON: frozen unless at least one beacon verifies. An absent list is a freeze.
pub fn is_frozen_liveness_check(beacons: &Value, check: &Value) -> bool {
    !beacons.as_array().is_some_and(|l| l.iter().any(|b| verify_liveness_beacon_check(b, check).is_ok()))
}

impl BeaconAcceptor {
    /// [`accept`](Self::accept) with the verify `check` as JSON ([`verify_liveness_beacon_check`]).
    pub fn accept_check(&self, b: &Value, check: &Value) -> Result<(), String> {
        verify_liveness_beacon_check(b, check)?;
        let seq = int_of(b.get("seq")).ok_or_else(|| "malformed beacon".to_string())?;
        let key = format!("beacon-seq/v1/{}", crate::js_stringify(&json!([b["instance"], b["scope"], b["issuer"]])));
        let mut junk = false;
        let mut replay_of: Option<i64> = None;
        let r = self.kv.update(&key, &mut |prev| match prev {
            None => Some(json!(seq)),
            Some(p) => match int_of(Some(p)).filter(|n| (0..=MAX_SAFE).contains(n)) {
                None => {
                    junk = true;
                    None
                }
                Some(n) if seq <= n => {
                    replay_of = Some(n);
                    None
                }
                Some(_) => Some(json!(seq)),
            },
        });
        if r.is_err() || junk {
            return Err("beacon state unavailable".into());
        }
        match replay_of {
            Some(n) => Err(format!("replayed beacon: seq {seq} <= {n}")),
            None => Ok(()),
        }
    }
}
