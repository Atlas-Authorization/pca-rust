//! Optimistic-path wire checks: the bonded claim, its challenge window, a fraud proof (wire level) and a settlement record.
//! Verify-only. A fraud proof is only CONVINCING because the settlement layer re-runs the Policy VM on the
//! server-held open-time snapshot; that recomputation is TypeScript-only, so [`fraud_proof_wire_check`] says a proof is
//! well-formed and self-consistent, nothing more.
//!
//! Claim and settlement signatures cover the LENIENT canonical JSON ([`crate::canonicalize`]) behind a domain tag.
use crate::{canonicalize, verify_b64u};
use serde_json::{Map, Value};

const CLAIM_DOMAIN: &str = "atlas-pca/optimistic/v1\0";
const SETTLEMENT_DOMAIN: &str = "atlas-pca/bond-settlement/v1\0";
const IRREVERSIBLE_CLASS: &str = "irreversible";
const DEFAULT_R_MARGIN: f64 = 1e-9;

/// Server-authoritative challenge-window bounds (ms).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowPolicy {
    pub min_window_ms: f64,
    pub max_window_ms: f64,
    pub max_skew_ms: f64,
}
/// The default policy: 1 s to 24 h, 5 s skew.
pub const DEFAULT_WINDOW_POLICY: WindowPolicy = WindowPolicy { min_window_ms: 1_000.0, max_window_ms: 86_400_000.0, max_skew_ms: 5_000.0 };

fn finite(v: Option<&Value>) -> Option<f64> {
    v?.as_f64().filter(|f| f.is_finite())
}

/// JavaScript `===` on two JSON values from separately parsed documents: numbers by value (1 === 1.0), objects and arrays
/// by identity (two parsed `[1]` are never `===`), absent is `undefined` (=== only itself).
fn js_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::Object(_) | Value::Array(_)), _) | (_, Some(Value::Object(_) | Value::Array(_))) => false,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn signed(domain: &str, body: &Map<String, Value>) -> Vec<u8> {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(canonicalize(&Value::Object(body.clone())).as_bytes());
    m
}

/// First failing check of a claim, in order: `malformed`, `irreversible`, `digest`, `claimed_r`, `window`, `signature`; `ok` when none.
pub fn claim_check(claim: &Value, expected_pcactn_digest: &str, signer_public: &str, server_now: f64, policy: &WindowPolicy) -> &'static str {
    let empty = Map::new();
    let c = match claim {
        Value::Object(m) => m,
        Value::Array(_) => &empty,
        _ => return "malformed",
    };
    if c.get("reversibility_class").and_then(Value::as_str) == Some(IRREVERSIBLE_CLASS) {
        return "irreversible";
    }
    if c.get("pcactn_digest").and_then(Value::as_str) != Some(expected_pcactn_digest) {
        return "digest";
    }
    if finite(c.get("claimed_r")).is_none() {
        return "claimed_r";
    }
    let (issued, window) = match (finite(c.get("issued_at")), finite(c.get("challenge_window_ms"))) {
        (Some(i), Some(w)) => (i, w),
        _ => return "window",
    };
    if !server_now.is_finite() || !((issued - server_now).abs() <= policy.max_skew_ms) || !(window >= policy.min_window_ms) || !(window <= policy.max_window_ms) {
        return "window";
    }
    let sig = match c.get("sig").and_then(Value::as_str) {
        Some(s) => s,
        None => return "signature",
    };
    let mut body = c.clone();
    body.remove("sig");
    if verify_b64u(signer_public, &signed(CLAIM_DOMAIN, &body), sig) {
        "ok"
    } else {
        "signature"
    }
}

/// `resolveWindow`'s realistic floor: a freshly derived window is never below 30 s.
pub const DEFAULT_MIN_CHALLENGE_WINDOW_MS: f64 = 30_000.0;
/// The window a claim gets when none is requested (5 minutes).
pub const DEFAULT_WINDOW_MS: f64 = 300_000.0;

/// Derive the authoritative window of a new claim: `issued_at = server_now`, the window the requested one (default 5 minutes)
/// clamped into the policy bounds and never below the 30 s floor. `Err` for a non-finite `server_now`.
pub fn resolve_window(policy: &WindowPolicy, server_now: f64, requested_ms: Option<f64>) -> Result<(f64, f64), String> {
    if !server_now.is_finite() {
        return Err("resolveWindow: serverNow must be finite".into());
    }
    let want = requested_ms.filter(|r| r.is_finite()).unwrap_or(DEFAULT_WINDOW_MS);
    let floor = policy.min_window_ms.max(DEFAULT_MIN_CHALLENGE_WINDOW_MS);
    Ok((server_now, policy.max_window_ms.min(floor.max(want))))
}

/// Validate a claim's `(issued_at, window)` against server time and the policy: `None` when fine, else the reason.
pub fn validate_window(issued_at: f64, window_ms: f64, server_now: f64, policy: &WindowPolicy) -> Option<&'static str> {
    if !server_now.is_finite() {
        return Some("server time is not finite");
    }
    if !issued_at.is_finite() || !window_ms.is_finite() {
        return Some("malformed challenge window");
    }
    if !((issued_at - server_now).abs() <= policy.max_skew_ms) {
        return Some("issued_at is outside the allowed skew of server time");
    }
    if !(window_ms >= policy.min_window_ms) {
        return Some("challenge window is below the minimum");
    }
    if !(window_ms <= policy.max_window_ms) {
        return Some("challenge window exceeds the maximum");
    }
    None
}

/// Open an optimistic bonded claim for `pcactn`, signed by the agent-leaf seed `signer_seed`. `opts`: `bondRef`, `claimedR` (finite),
/// and optionally `challengeWindowMs`, `issuedAt`, `serverNow` (default the clock). `Err` for an irreversible action (it must take
/// the full threshold path), a non-finite `claimedR`, or a window outside `policy` (default [`DEFAULT_WINDOW_POLICY`]).
pub fn open_optimistic(pcactn: &Value, opts: &Value, signer_seed: &[u8], policy: Option<&WindowPolicy>) -> Result<Value, String> {
    let rc = pcactn.get("action").and_then(|a| a.get("reversibility_class")).and_then(Value::as_str);
    if rc == Some(IRREVERSIBLE_CLASS) {
        return Err("openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)".into());
    }
    let claimed_r = finite(opts.get("claimedR")).ok_or("openOptimistic: claimedR must be finite")?;
    let policy = policy.unwrap_or(&DEFAULT_WINDOW_POLICY);
    let now_ms = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0);
    let server_now = finite(opts.get("serverNow")).unwrap_or_else(now_ms);
    let issued_at = finite(opts.get("issuedAt")).unwrap_or(server_now);
    let window = match opts.get("challengeWindowMs") {
        None | Some(Value::Null) => DEFAULT_WINDOW_MS,
        Some(v) => finite(Some(v)).unwrap_or(f64::NAN),
    };
    if let Some(bad) = validate_window(issued_at, window, server_now, policy) {
        return Err(format!("openOptimistic: {bad}"));
    }
    let seed: [u8; 32] = signer_seed.try_into().map_err(|_| "an Ed25519 seed is 32 bytes".to_string())?;
    let num = |f: f64| serde_json::Number::from_f64(f).map(Value::Number).ok_or_else(|| "openOptimistic: number out of range".to_string());
    let mut body = Map::new();
    body.insert(
        "pcactn_digest".into(),
        Value::String(crate::hash_canonical_strict(pcactn).ok_or("openOptimistic: the PCActn is outside the strict JSON profile")?),
    );
    body.insert("bond_ref".into(), opts.get("bondRef").cloned().unwrap_or(Value::Null));
    body.insert("claimed_r".into(), num(claimed_r)?);
    body.insert("reversibility_class".into(), Value::String(rc.unwrap_or("unknown").into()));
    body.insert("issued_at".into(), num(issued_at)?);
    body.insert("challenge_window_ms".into(), num(window)?);
    let sig = crate::b64_encode(&crate::agent::KeyPair::from_seed(&seed).sign(&signed(CLAIM_DOMAIN, &body)));
    body.insert("sig".into(), Value::String(sig));
    Ok(Value::Object(body))
}

/// Epoch-ms at which the challenge window closes (`issued_at + challenge_window_ms`, inclusive).
pub fn challenge_window_end(issued_at: f64, challenge_window_ms: f64) -> f64 {
    issued_at + challenge_window_ms
}
/// True while challenges are accepted: `now <= issued_at + challenge_window_ms`.
pub fn within_challenge_window(issued_at: f64, challenge_window_ms: f64, now: f64) -> bool {
    now.is_finite() && now <= challenge_window_end(issued_at, challenge_window_ms)
}
/// `open` while challenges are accepted, else `finalized`. A clock or window that is not a finite time is refused (`finalized` opens settlement).
pub fn claim_status(issued_at: f64, challenge_window_ms: f64, now: f64) -> Result<&'static str, String> {
    if !now.is_finite() || !challenge_window_end(issued_at, challenge_window_ms).is_finite() {
        return Err("claimStatus: the clock and the challenge window must be finite times".into());
    }
    Ok(if within_challenge_window(issued_at, challenge_window_ms, now) { "open" } else { "finalized" })
}

/// Wire-level check of a fraud proof against the claim it names, in order: `malformed`, `digest`, `bond`, `claimed_r`, `kind`,
/// `consistency`; `ok` when none. The decision a kind needs: `policy-denied` a denial, `optimistic-not-allowed` an allowed
/// release with the fast path refused, `risk-understated` a real `r` above `claimed_r + r_margin`, `irreversible` an
/// irreversible class on the claim or in the snapshot evidence.
pub fn fraud_proof_wire_check(claim: &Value, proof: &Value) -> &'static str {
    // an array claim is a JS object with no fields (typeof [] === 'object'); an array proof has no `decision` either way
    let empty = Map::new();
    let claim = match claim {
        Value::Object(m) => m,
        Value::Array(_) => &empty,
        _ => return "malformed",
    };
    let proof = match proof.as_object() {
        Some(p) => p,
        None => return "malformed",
    };
    let d = match proof.get("decision").and_then(Value::as_object) {
        Some(d) => d,
        None => return "malformed",
    };
    let (share, allowed, r) =
        match (d.get("releaseGuardianShare").and_then(Value::as_bool), d.get("optimisticAllowed").and_then(Value::as_bool), finite(d.get("r"))) {
            (Some(s), Some(a), Some(r)) => (s, a, r),
            _ => return "malformed",
        };
    if !["pcactn_digest", "bond_ref", "reason"].iter().all(|k| proof.get(*k).is_some_and(Value::is_string)) {
        return "malformed";
    }
    if !js_eq(proof.get("pcactn_digest"), claim.get("pcactn_digest")) {
        return "digest";
    }
    if !js_eq(proof.get("bond_ref"), claim.get("bond_ref")) {
        return "bond";
    }
    if !js_eq(proof.get("claimed_r"), claim.get("claimed_r")) {
        return "claimed_r";
    }
    let kind = match proof.get("kind").and_then(Value::as_str) {
        Some(k @ ("policy-denied" | "risk-understated" | "optimistic-not-allowed" | "irreversible")) => k,
        _ => return "kind",
    };
    let margin = finite(proof.get("r_margin")).map_or(DEFAULT_R_MARGIN, |m| m.max(0.0));
    let ev_class =
        proof.get("evidence").and_then(|e| e.get("action")).and_then(|a| a.get("action")).and_then(|a| a.get("reversibility_class")).and_then(Value::as_str);
    let holds = match kind {
        "irreversible" => claim.get("reversibility_class").and_then(Value::as_str) == Some(IRREVERSIBLE_CLASS) || ev_class == Some(IRREVERSIBLE_CLASS),
        "policy-denied" => !share,
        "optimistic-not-allowed" => share && !allowed,
        // JS `r > claimed_r + margin`: null / booleans coerce to 0 / 1; a string concatenates (never a finite claim) and stays refused
        _ => {
            let c = match claim.get("claimed_r") {
                Some(Value::Null) => Some(0.0),
                Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
                other => finite(other),
            };
            share && allowed && c.is_some_and(|c| r > c + margin)
        }
    };
    if holds {
        "ok"
    } else {
        "consistency"
    }
}

fn non_empty(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}
fn non_neg(v: Option<&Value>) -> Option<f64> {
    finite(v).filter(|f| *f >= 0.0)
}

/// Wire-level check of a settlement record, in order: `malformed`, `suite`, `shape`, `split`, `signature`; `ok` when none.
/// `shape`: the fields its `action` requires (`evidenceDigest` empty and `split` absent unless the action is `slash`, then
/// both present); `split`: it conserves the amount, `(challengerReward + victimCompensation) + treasuryRemainder == amount`
/// in IEEE doubles, its treasury is the record's destination, and an anonymous split pays the treasury everything.
/// A suite this build lacks is `suite`; a PQ / hybrid record verifies only under the pin for the guardian (see
/// [`settlement_wire_check_pinned`]; this form pins nothing).
pub fn settlement_wire_check(record: &Value, guardian_public: &str) -> &'static str {
    settlement_wire_check_pinned(record, guardian_public, None)
}

/// [`settlement_wire_check`] with `pins` (`{ed25519 b64u: PQ public key b64u}`; `None` pins nothing).
pub fn settlement_wire_check_pinned(record: &Value, guardian_public: &str, pins: Option<&Value>) -> &'static str {
    let r = match record {
        Value::Object(m) => m,
        _ => return "malformed",
    };
    if crate::intent_suite::suite_of(r.get("alg")).is_err() {
        return "suite";
    }
    let slash = r.get("action").and_then(Value::as_str) == Some("slash");
    let amount = finite(r.get("amount")).filter(|a| *a > 0.0);
    let evidence = r.get("evidenceDigest").and_then(Value::as_str);
    let epoch_ok =
        r.get("guardian_epoch").is_none_or(|e| non_neg(Some(e)).is_some_and(|f| f.fract() == 0.0 && f.is_sign_positive() && f <= 9_007_199_254_740_991.0));
    let shape = non_empty(r.get("claimId"))
        && matches!(r.get("action").and_then(Value::as_str), Some("open" | "release" | "slash"))
        && amount.is_some()
        && non_empty(r.get("from"))
        && non_empty(r.get("to"))
        && finite(r.get("at")).is_some()
        && evidence.is_some_and(|e| e.is_empty() != slash)
        && (if slash { r.get("split").is_some_and(|s| s.is_object() || s.is_array()) } else { !r.contains_key("split") })
        && r.get("sig").is_some_and(Value::is_string)
        && epoch_ok;
    if !shape {
        return "shape";
    }
    if slash {
        // an array split is a JS object with no fields: it fails conservation as `split`
        let empty = Map::new();
        let sp = r["split"].as_object().unwrap_or(&empty);
        let amount = amount.expect("checked");
        let (c, v, t) = (non_neg(sp.get("challengerReward")), non_neg(sp.get("victimCompensation")), non_neg(sp.get("treasuryRemainder")));
        let conserved = js_eq(sp.get("amount"), r.get("amount"))
            && matches!((c, v, t), (Some(c), Some(v), Some(t)) if c + v + t == amount)
            && non_empty(sp.get("victimAccount"))
            && js_eq(sp.get("treasuryAccount"), r.get("to"))
            && match sp.get("challengerAccount") {
                Some(Value::Null) => c == Some(0.0) && v == Some(0.0) && t == Some(amount),
                other => non_empty(other),
            };
        if !conserved {
            return "split";
        }
    }
    let mut body = r.clone();
    body.remove("sig");
    body.remove("pq_sig");
    // the pin policy is `{pqPins: {<identity>: <pq key>}}`, as the reference reads it
    let pin = pins.and_then(|p| p.get("pqPins")).and_then(|m| m.get(guardian_public)).map(|v| (guardian_public, v));
    let msg = signed(SETTLEMENT_DOMAIN, &body);
    if crate::intent_suite::verify_pinned_suite(r.get("alg"), guardian_public, r.get("pq_pk"), &msg, r.get("sig"), r.get("pq_sig"), pin).unwrap_or(false) {
        "ok"
    } else {
        "signature"
    }
}

#[cfg(test)]
#[path = "base_optimistic_test.rs"]
mod base_test;

#[cfg(test)]
mod open_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_opened_claim_passes_claim_check_and_refuses_the_irreversible() {
        let seed = [7u8; 32];
        let kp = crate::agent::KeyPair::from_seed(&seed);
        let a = json!({"action": {"verb": "charge", "reversibility_class": "reversible"}, "counter": 1});
        let c = open_optimistic(&a, &json!({"bondRef": "bond1", "claimedR": 0.1, "serverNow": 1_000_000.0}), &seed, None).unwrap();
        let d = crate::hash_canonical_strict(&a).unwrap();
        assert_eq!(claim_check(&c, &d, &kp.public, 1_000_000.0, &DEFAULT_WINDOW_POLICY), "ok");
        assert_eq!(claim_check(&c, "other", &kp.public, 1_000_000.0, &DEFAULT_WINDOW_POLICY), "digest");
        let irr = json!({"action": {"reversibility_class": "irreversible"}});
        assert!(open_optimistic(&irr, &json!({"claimedR": 0.1}), &seed, None).is_err());
        assert!(open_optimistic(&a, &json!({"claimedR": f64::NAN.to_string()}), &seed, None).is_err());
        assert!(open_optimistic(&a, &json!({"claimedR": 0.1, "serverNow": 5.0, "issuedAt": 99999.0}), &seed, None).is_err());
        assert_eq!(resolve_window(&DEFAULT_WINDOW_POLICY, 10.0, Some(1.0)), Ok((10.0, 30_000.0)));
        assert_eq!(resolve_window(&DEFAULT_WINDOW_POLICY, 10.0, Some(1e12)), Ok((10.0, 86_400_000.0)));
    }
}
