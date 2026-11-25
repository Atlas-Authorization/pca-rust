//! The review flow of the import pipeline (import/review.ts): the attestation verdict, review status, stale revert, the review queue and
//! view, and the producer side (`confirm_def`). The logic lives in `actions_kit_ops::review` (shared with the action kit); this module
//! is the import-side surface: the reference's error behaviour (a def without a `review` member is a TypeError) and `R<T>` results.

use super::common::{kerr, type_err, ActionKitError, R};
use crate::actions::Registry;
use crate::actions_kit_ops::review as ops;
use serde_json::Value;

pub use ops::{attestation_verifier, confirm_def, review_opts_of, review_priority, review_queue_order, verify_attestation_verdict};

/// `verifyAttestation(def, {pins, registry})`: `{ok: true, kid}` or `{ok: false, reason, detail}`. Never fails.
pub fn verify_attestation(d: &Value, reg: &Registry, pins: &Value) -> Value {
    ops::verify_attestation_verdict(d, reg, pins)
}

fn need_review(d: &Value) -> R<()> {
    if d.get("review").is_some_and(Value::is_object) {
        Ok(())
    } else {
        Err(type_err("the def has no review member"))
    }
}

/// The state that counts: a `confirmed` def with an invalid attestation is `stale`.
pub fn review_status(d: &Value, reg: &Registry, pins: &Value) -> R<String> {
    need_review(d)?;
    Ok(ops::review_status(d, reg, pins))
}

/// Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped).
pub fn revert_stale(d: &Value, reg: &Registry, pins: &Value) -> R<Value> {
    need_review(d)?;
    Ok(ops::revert_stale(d, reg, pins))
}

/// What the reviewer is shown (facts, the traits once signed, the policy card, what changed against `previous`).
pub fn prepare_review(d: &Value, reg: &Registry, previous: Option<&Value>) -> R<Value> {
    need_review(d)?;
    ops::prepare_review(d, reg, previous).map_err(|m| kerr("error", m))
}

/// Keeps the error type in this module's namespace for callers that match on it.
pub type ReviewError = ActionKitError;
