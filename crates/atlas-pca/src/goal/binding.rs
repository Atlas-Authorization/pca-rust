//! The decision-to-effect binding (W14) and the claimed-fidelity gate (W2) of goal-to-decision (`binding.ts`), plus the hiding goal
//! commitment (goal binding v3).
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Digest of exactly the action that was decided: verb, resource and every parameter (strict canonical JSON).
pub fn action_digest(a: &Value) -> Result<String, String> {
    crate::hash_canonical_strict(&json!({"d": "atlas-pca/goal-action/v1", "act": a}))
        .ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string())
}
/// Bind a decision to the action it was made for: `{decision, action_digest}`.
pub fn bind_decision(a: &Value, decision: &str) -> Result<Value, String> {
    Ok(json!({"decision": decision, "action_digest": action_digest(a)?}))
}
/// Run guard: true only for an `allow` bound to exactly this action (swapped params or verb, `escalate`, `deny` all refuse). Total.
pub fn guard_execute(b: &Value, executed: &Value) -> bool {
    if b.get("decision").and_then(Value::as_str) != Some("allow") {
        return false;
    }
    match (b.get("action_digest").and_then(Value::as_str), action_digest(executed)) {
        (Some(x), Ok(y)) => ct_eq(x.as_bytes(), y.as_bytes()),
        _ => false,
    }
}
/// An agent-claimed fidelity never moves the outcome; only a fidelity the verifier replayed from the committed map and found below
/// the minimum can, and only downward (escalate, via the tighten-only meet). A NaN replay is unconfirmed: it tightens.
pub fn claim_gate<'a>(base: &'a str, min_ppm: f64, replayed_ppm: Option<f64>) -> &'a str {
    match replayed_ppm {
        Some(r) if !(r >= min_ppm) => {
            if base == "allow" {
                "escalate"
            } else {
                base
            }
        }
        _ => base,
    }
}
/// Hiding goal commitment: sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url. Matches the shared conformance vectors.
pub fn goal_commit(goal_digest: &str, policy_digest: &str, salt: &str) -> String {
    b64u(&Sha256::digest(format!("pca-goal:v3:commit:{goal_digest}:{policy_digest}:{salt}").as_bytes()))
}
/// Constant-time check that `commit` opens to (goal, policy, salt).
pub fn open_commit(commit: &str, goal_digest: &str, policy_digest: &str, salt: &str) -> bool {
    ct_eq(commit.as_bytes(), goal_commit(goal_digest, policy_digest, salt).as_bytes())
}
