//! The content digests of the goal-to-decision flow (`digests.ts`): strict canonical JSON, safe integers only. An out-of-profile
//! value (a float outside the plain-decimal profile, an unsafe integer, too deep) is refused.
use super::js::u16cmp;
use serde_json::{json, Value};

fn strict(v: Value) -> Result<String, String> {
    crate::hash_canonical_strict(&v).ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string())
}
/// Digest of the whole signed Goal.
pub fn goal_digest(goal: &Value) -> Result<String, String> {
    strict(json!({"d": "atlas-pca/goal-ir/v1", "goal": goal}))
}
/// Digest of the instruction text a goal was interpreted from (what `Goal.nlDigest` must equal).
pub fn nl_digest(instruction: &Value) -> Result<String, String> {
    strict(json!({"d": "atlas-pca/goal-nl/v1", "text": instruction}))
}
/// Digest of the model set that produced a goal: sorted (UTF-16 order), de-duplicated ids.
pub fn model_set_digest(models: &[String]) -> Result<String, String> {
    let mut m: Vec<String> = Vec::new();
    for x in models {
        if !m.contains(x) {
            m.push(x.clone());
        }
    }
    m.sort_by(|a, b| u16cmp(a, b));
    strict(json!({"d": "atlas-pca/goal-model-set/v1", "models": m}))
}
/// Digest of an approval's covered fields: any changed member changes it.
pub fn approval_digest(body: &Value) -> Result<String, String> {
    strict(json!({"d": "atlas-pca/goal-approval-body/v1", "body": body}))
}
