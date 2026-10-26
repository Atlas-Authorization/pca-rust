//! Optimistic-path wire checks: the bonded claim, its challenge window, a fraud proof (wire level) and a settlement record.
//! Verify-only and Ed25519 only. A fraud proof is only CONVINCING because the settlement layer re-runs the Policy VM on the
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

/// JavaScript `===` on two JSON values (1 === 1.0).
fn js_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
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
    if !server_now.is_finite() || (issued - server_now).abs() > policy.max_skew_ms || window < policy.min_window_ms || window > policy.max_window_ms {
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

/// Epoch-ms at which the challenge window closes (`issued_at + challenge_window_ms`, inclusive).
pub fn challenge_window_end(issued_at: f64, challenge_window_ms: f64) -> f64 {
    issued_at + challenge_window_ms
}
/// True while challenges are accepted: `now <= issued_at + challenge_window_ms`.
pub fn within_challenge_window(issued_at: f64, challenge_window_ms: f64, now: f64) -> bool {
    now.is_finite() && now <= challenge_window_end(issued_at, challenge_window_ms)
}
/// `open` while challenges are accepted, else `finalized`.
pub fn claim_status(issued_at: f64, challenge_window_ms: f64, now: f64) -> &'static str {
    if within_challenge_window(issued_at, challenge_window_ms, now) {
        "open"
    } else {
        "finalized"
    }
}

/// Wire-level check of a fraud proof against the claim it names, in order: `malformed`, `digest`, `bond`, `claimed_r`, `kind`,
/// `consistency`; `ok` when none. The decision a kind needs: `policy-denied` a denial, `optimistic-not-allowed` an allowed
/// release with the fast path refused, `risk-understated` a real `r` above `claimed_r + r_margin`, `irreversible` an
/// irreversible class on the claim or in the snapshot evidence.
pub fn fraud_proof_wire_check(claim: &Value, proof: &Value) -> &'static str {
    let (claim, proof) = match (claim.as_object(), proof.as_object()) {
        (Some(c), Some(p)) => (c, p),
        _ => return "malformed",
    };
    let d = match proof.get("decision").and_then(Value::as_object) {
        Some(d) => d,
        None => return "malformed",
    };
    let (share, allowed, r) = match (d.get("releaseGuardianShare").and_then(Value::as_bool), d.get("optimisticAllowed").and_then(Value::as_bool), finite(d.get("r"))) {
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
    let ev_class = proof.get("evidence").and_then(|e| e.get("action")).and_then(|a| a.get("action")).and_then(|a| a.get("reversibility_class")).and_then(Value::as_str);
    let holds = match kind {
        "irreversible" => claim.get("reversibility_class").and_then(Value::as_str) == Some(IRREVERSIBLE_CLASS) || ev_class == Some(IRREVERSIBLE_CLASS),
        "policy-denied" => !share,
        "optimistic-not-allowed" => share && !allowed,
        _ => share && allowed && finite(claim.get("claimed_r")).is_some_and(|c| r > c + margin),
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
/// Only `alg` absent or `ed25519` is verified (any other suite is `suite`).
pub fn settlement_wire_check(record: &Value, guardian_public: &str) -> &'static str {
    let r = match record {
        Value::Object(m) => m,
        _ => return "malformed",
    };
    if r.get("alg").is_some_and(|a| a.as_str() != Some("ed25519")) {
        return "suite";
    }
    let slash = r.get("action").and_then(Value::as_str) == Some("slash");
    let amount = finite(r.get("amount")).filter(|a| *a > 0.0);
    let evidence = r.get("evidenceDigest").and_then(Value::as_str);
    let epoch_ok = r.get("guardian_epoch").is_none_or(|e| non_neg(Some(e)).is_some_and(|f| f.fract() == 0.0 && f <= 9_007_199_254_740_991.0));
    let shape = non_empty(r.get("claimId"))
        && matches!(r.get("action").and_then(Value::as_str), Some("open" | "release" | "slash"))
        && amount.is_some()
        && non_empty(r.get("from"))
        && non_empty(r.get("to"))
        && finite(r.get("at")).is_some()
        && evidence.is_some_and(|e| e.is_empty() != slash)
        && (if slash { r.get("split").is_some_and(Value::is_object) } else { !r.contains_key("split") })
        && r.get("sig").is_some_and(Value::is_string)
        && epoch_ok;
    if !shape {
        return "shape";
    }
    if slash {
        let sp = r["split"].as_object().expect("checked");
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
    if verify_b64u(guardian_public, &signed(SETTLEMENT_DOMAIN, &body), r["sig"].as_str().expect("checked")) {
        "ok"
    } else {
        "signature"
    }
}
