//! The ONE signer of the goal-to-decision flow (`sign.ts`): artifacts (approvals, test sets, policy pins, precedents) signed with
//! the suite-agile artifact signer of the crate under a per-kind domain, over STRICT canonical bytes. Nothing here rolls its own
//! signature. Signing here is Ed25519 (the default suite); a post-quantum suite goes through [`crate::agent::sign_artifact`] directly.
use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::intent_strict::{artifact_suite_error, verify_artifact_sig};
use serde_json::{json, Value};

/// Domain separation: an artifact of one kind never verifies as another kind.
pub fn goal_domain(kind: &str) -> String {
    format!("atlas-pca/goal/{kind}/v1\0")
}
/// Sign a flat artifact body (it must already carry its signer identity member). Refuses a non-canonical body.
pub fn sign_goal_artifact(kind: &str, body: &Value, secret: &KeyPair) -> Result<Value, String> {
    sign_artifact(&goal_domain(kind), body, secret, &Suite::default())
}
/// Verify a signed artifact against the caller's PINNED signers (a string key id, or `{pk, pq_pk?}`): the pin whose `pk` equals the
/// artifact's own `signer_field` member must verify. Total.
pub fn verify_goal_artifact(kind: &str, artifact: &Value, signer_field: &str, pins: &[Value]) -> bool {
    let a = match artifact.as_object() {
        Some(a) => a,
        None => return false,
    };
    if artifact_suite_error(a).is_some() {
        return false;
    }
    let who = match a.get(signer_field).and_then(Value::as_str) {
        Some(w) => w,
        None => return false,
    };
    for p in pins {
        let (pk, pq) = match p {
            Value::String(s) => (Some(s.as_str()), None),
            Value::Object(m) => (m.get("pk").and_then(Value::as_str), m.get("pq_pk")),
            _ => (None, None), // `p.pk` of a null / number pin: the reference throws and the check is false
        };
        if p.is_null() {
            return false;
        }
        if pk == Some(who) {
            return verify_artifact_sig(&goal_domain(kind), a, who, pq);
        }
    }
    false
}
/// A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents.
pub fn sign_payload(kind: &str, payload: &Value, secret: &KeyPair) -> Result<Value, String> {
    sign_goal_artifact(kind, &json!({"v": 1, "kind": kind, "signer": secret.public, "payload": payload}), secret)
}
pub fn verify_payload(s: &Value, kind: &str, pins: &[Value]) -> bool {
    s.is_object() && s.get("v") == Some(&json!(1)) && s.get("kind").and_then(Value::as_str) == Some(kind) && verify_goal_artifact(kind, s, "signer", pins)
}
