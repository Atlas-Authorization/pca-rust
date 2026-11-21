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
