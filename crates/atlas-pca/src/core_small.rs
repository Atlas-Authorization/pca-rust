//! Small reference helpers: the salted ledger commitment of a PCActn and its opening, the principal's capability-revocation
//! message, and the objective-risk commitment a grant's envelope carries.

use crate::{canonicalize_strict, hash_canonical_strict, serde_json::json};
use serde_json::Value;

const REVOKE_DOMAIN: &str = "atlas-pca/revoke/v1\0";

/// `entryCommit(salt, pcactn)` = hashCanonical({salt, pcactn_digest: hashCanonical(pcactn)}): the salted commitment of a PCActn.
/// `Err` where the reference throws (a PCActn outside the strict profile).
pub fn entry_commit(salt: &str, pcactn: &Value) -> Result<String, String> {
    let digest = hash_canonical_strict(pcactn).ok_or("entryCommit: the PCActn is not canonicalizable")?;
    hash_canonical_strict(&json!({"salt": salt, "pcactn_digest": digest})).ok_or_else(|| "entryCommit: not canonicalizable".to_string())
}

/// `verifyOpening(commit, opening)`: true when the opening `{salt, pcactn}` reproduces the commit; false on any malformed input.
pub fn verify_opening(commit: &str, opening: &Value) -> bool {
    match (opening.get("salt").and_then(Value::as_str), opening.get("pcactn")) {
        (Some(salt), Some(p)) => entry_commit(salt, p).is_ok_and(|c| c == commit),
        _ => false,
    }
}

/// `revokeMessage(grantRef, revokedCapId)`: the domain-separated bytes a PRINCIPAL signs to revoke a capability under their grant,
/// `"atlas-pca/revoke/v1\0" || strictCanonical({grant_ref, revoked_cap_id})`.
pub fn revoke_message(grant_ref: &str, revoked_cap_id: &str) -> Result<Vec<u8>, String> {
    let mut m = REVOKE_DOMAIN.as_bytes().to_vec();
    m.extend(canonicalize_strict(&json!({"grant_ref": grant_ref, "revoked_cap_id": revoked_cap_id}))?.into_bytes());
    Ok(m)
}

/// `readObjectiveCommitment(grant)`: the `objective_risk` member of a grant's envelope. `{}` = not committed; `{commitment}` =
/// well-formed; `{malformed: reason}` otherwise (the caller then fails closed or falls back as the grant says).
pub fn read_objective_commitment(grant: &Value) -> Value {
    let raw = match crate::authorize::read_envelope(grant).and_then(|e| e.get("objective_risk").cloned()) {
        Some(r) => r,
        None => return json!({}),
    };
    let bad = |m: &str| json!({"malformed": m});
    let obj = |v: Option<&Value>| v.is_some_and(Value::is_object);
    let nes = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let o = match raw.as_object() {
        Some(o) if o.get("v").and_then(Value::as_i64) == Some(1) => o,
        _ => return bad("objective_risk: unsupported shape/version"),
    };
    let emb = o.get("embedder").and_then(Value::as_object);
    if !emb.is_some_and(|e| e.get("scheme").and_then(Value::as_str) == Some("native") && nes(e.get("model_id")) && obj(e.get("config"))) {
        return bad("objective_risk.embedder must be { scheme: \"native\", model_id, config }");
    }
    if !o.get("goal").and_then(Value::as_object).is_some_and(|g| nes(g.get("commit"))) {
        return bad("objective_risk.goal must be a goal commitment");
    }
    if !nes(o.get("registry_digest")) || !nes(o.get("graph_digest")) {
        return bad("objective_risk needs registry_digest and graph_digest");
    }
    if o.get("calibration_digest").is_some_and(|c| !nes(Some(c))) {
        return bad("objective_risk.calibration_digest must be a string");
    }
    if !o.get("authorized_kinds").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string)) {
        return bad("objective_risk.authorized_kinds must be string[]");
    }
    if o.get("denominations").is_some_and(|d| !d.is_array()) {
        return bad("objective_risk.denominations must be an array");
    }
    if o.get("on_mismatch").is_some_and(|m| !matches!(m.as_str(), Some("deny" | "heuristic"))) {
        return bad("objective_risk.on_mismatch must be \"deny\" or \"heuristic\"");
    }
    json!({"commitment": raw})
}

/// The type of a carried budget-allocation caveat.
pub const BUDGET_ALLOC_CAVEAT: &str = "budget_alloc";

/// `budgetAllocCaveat(limit)`: the signed carried-allocation caveat `{type: "budget_alloc", limit}` of a delegation hop.
pub fn budget_alloc_caveat(limit: f64) -> Value {
    json!({"type": BUDGET_ALLOC_CAVEAT, "limit": crate::bond_store::num(limit)})
}

/// Default revocation freshness bound in seconds for payment tiers.
pub const DEFAULT_REVOCATION_MAX_AGE_PAYMENT_S: u32 = 60;
/// Default revocation freshness bound in seconds for every other tier.
pub const DEFAULT_REVOCATION_MAX_AGE_DEFAULT_S: u32 = 300;

/// `profileRevocationScope(profileId)`: the revocation scope of a standing profile.
pub fn profile_revocation_scope(profile_id: &str) -> String {
    format!("pca-intent-profile:{profile_id}")
}

/// `revocationExposureEnd(tRevoked, maxAgeMs, skewMs)`: a verifier that enforces `max_age_ms` can still accept an action after a
/// revocation at `t_revoked` only until this time (`skew_ms` defaults to 60 s).
pub fn revocation_exposure_end(t_revoked: f64, max_age_ms: f64, skew_ms: Option<f64>) -> f64 {
    t_revoked + max_age_ms + skew_ms.unwrap_or(60_000.0)
}

/// `parseIntentGoalV2(goal)`: `(session, map_digest)` of a `pca-intent:v2:<session>:<mapDigest>` goal (both canonical base64url,
/// 32 bytes); `None` for anything else.
pub fn parse_intent_goal_v2(goal: &str) -> Option<(String, String)> {
    let mut parts = goal.strip_prefix("pca-intent:v2:")?.split(':');
    let (session, map_digest) = (parts.next()?, parts.next()?);
    let b32 = |s: &str| crate::decode_b64u_strict(s, Some(32)).is_some();
    (parts.next().is_none() && b32(session) && b32(map_digest)).then(|| (session.to_string(), map_digest.to_string()))
}
