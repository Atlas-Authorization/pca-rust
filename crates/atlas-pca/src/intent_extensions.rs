//! The reference's `INTENT_WIRE_EXTENSION` and `INTENT_EXTENSIONS`: the Intent Layer as a set of plain function values. This verifier always
//! has the intent layer loaded (the core verifier runs these very functions); they are exported so a caller can run the same checks on its own
//! or compare against the reference. Each wire validator answers `None` when the slot is well formed, else a short reason.

use serde_json::Value;

use crate::fresh_at::{decide_fresh_at, validate_fresh_at_wire, FreshAtCheck, FreshAtPolicy};
use crate::{decide_intent_v2, IntentPolicy, IntentV2Context, IntentV2Decision};

/// The Intent Layer's wire validators (`INTENT_WIRE_EXTENSION`).
#[derive(Clone, Copy)]
pub struct IntentWireExtension {
    /// `intent` slot.
    pub intent: fn(&Value) -> Option<String>,
    /// `intent_session` slot.
    pub intent_session: fn(&Value) -> Option<String>,
    /// `fresh_at` slot.
    pub fresh_at: fn(&Value) -> Option<String>,
}

/// The full extension set (`INTENT_EXTENSIONS`): the wire validators and the three decisions the core verifier runs after `counter_format`.
#[derive(Clone, Copy)]
pub struct IntentExtensions {
    pub wire: IntentWireExtension,
    /// The `intent` check: `None` when it is not reported (no `intent` slot and no active policy), else pass / the reason.
    pub intent_binding: fn(Option<&Value>, &Value, Option<&IntentPolicy>, Option<(&str, bool)>) -> Option<Result<(), String>>,
    /// The Intent v2 checks (`schema`, `intent_session`, `accumulators`, ...).
    pub intent_v2: fn(&Value, &Value, Option<&IntentV2Context>, i64) -> IntentV2Decision,
    /// The `fresh_at` consistency-token check.
    pub fresh_at: fn(Option<&Value>, Option<&FreshAtPolicy>, i64) -> FreshAtCheck,
}

fn intent_slot(v: &Value) -> Option<String> {
    crate::validate_intent_wire(v).err()
}

fn intent_session_slot(v: &Value) -> Option<String> {
    crate::intent_session::validate_intent_session_wire(v).err()
}

/// `INTENT_WIRE_EXTENSION`.
pub const INTENT_WIRE_EXTENSION: IntentWireExtension = IntentWireExtension { intent: intent_slot, intent_session: intent_session_slot, fresh_at: validate_fresh_at_wire };

/// `INTENT_EXTENSIONS`.
pub const INTENT_EXTENSIONS: IntentExtensions = IntentExtensions {
    wire: INTENT_WIRE_EXTENSION,
    intent_binding: crate::decide_intent,
    intent_v2: decide_intent_v2,
    fresh_at: decide_fresh_at,
};
