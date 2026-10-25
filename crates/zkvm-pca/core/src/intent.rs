//! PCA 0.4.2 Intent Layer M2: the signed `intent` slot of a PCActn (`packages/pca/src/intent-binding.ts`, NORMATIVE for every
//! verifier including this guest; conformance rule 12, vectors `intent-*`).
//!
//! Split between the guest and the verifier exactly along what each can know:
//! * IN THE GUEST (proved): the wire rules of the slot (`validateIntentWire`) and rule 2, the ROOT GRANT BINDING: `ref`,
//!   `map_digest` and `goal_salt` must open the root grant's goal commitment (the FIRST object caveat with
//!   `type == "envelope"`, its string `goal_commit`). A malformed slot or a binding that does not open denies the action.
//!   The claimed `fidelity_ppm` / `residual_risk_ppm` (and `ref`, `map_digest`) are committed to the journal
//!   (`Context::intent`).
//! * IN THE VERIFIER ([`crate::context::check_context`], from the journal): the relying party's own policy, rules 0, 1, 3
//!   and 4 (`decideIntentBinding`): misconfigured thresholds fail closed, an ACTIVE policy refuses a journal without an
//!   intent, `fidelity_ppm >= min_fidelity_ppm`, `residual_risk_ppm <= max_residual_risk_ppm`.

use crate::commit::hash_canonical;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const INTENT_GOAL_PREFIX: &str = "pca-intent:v1:";
/// Domain of the grant's salted goal commitment (envelope.ts `goalCommitOf`).
pub const INTENT_GOAL_COMMIT_DOMAIN: &str = "atlas-pca/goal/v1\0";
pub const PPM_ONE: u64 = 1_000_000;
pub const MAX_INTENT_GOAL_SALT_LEN: usize = 128;
/// Closed member set of the `intent` slot (all required).
pub const ENVELOPE_INTENT_FIELDS: [&str; 5] = ["ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"];
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// The intent claims a proved decision commits to (the slot minus `goal_salt`, whose only role is the in-guest binding).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentClaim {
    /// b64u(32): the IntentStatement content address.
    pub intent_ref: String,
    /// b64u(32): the Intent Map content address.
    pub map_digest: String,
    /// Integer ppm in [0, 1e6]: the map's fidelity estimate (a signed claim of the leaf holder).
    pub fidelity_ppm: u64,
    /// Integer ppm >= 0 (harm-units x 1e6, may exceed 1e6): the map's residual-risk estimate (a signed claim).
    pub residual_risk_ppm: u64,
}

/// A well-formed `intent` slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeIntent {
    pub claim: IntentClaim,
    pub goal_salt: String,
}

/// The relying party's intent policy (`IntentPolicy`); checked by the verifier against the journal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntentPolicy {
    /// Require every proved decision to carry a bound intent.
    pub require: bool,
    /// Deny when the claimed `fidelity_ppm` is below this. Setting it implies `require`.
    pub min_fidelity_ppm: Option<u64>,
    /// Deny when the claimed `residual_risk_ppm` is above this. Setting it implies `require`.
    pub max_residual_risk_ppm: Option<u64>,
}

impl IntentPolicy {
    /// `intentPolicyActive`: the check runs (and refuses an absent intent) iff `require` or a threshold is set.
    pub fn active(&self) -> bool {
        self.require || self.min_fidelity_ppm.is_some() || self.max_residual_risk_ppm.is_some()
    }
}

/// Why a journal's intent does not satisfy the relying party's policy (`decideIntentBinding` rules 0, 1, 3, 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentPolicyFailure {
    /// Rule 0: a threshold outside the safe-integer range (fail closed).
    Misconfigured,
    /// Rule 1: an active policy, and the proved decision carries no intent.
    Missing,
    /// Rule 3: `fidelity_ppm < min_fidelity_ppm`.
    Fidelity { claimed: u64, minimum: u64 },
    /// Rule 4: `residual_risk_ppm > max_residual_risk_ppm`.
    ResidualRisk { claimed: u64, maximum: u64 },
}

/// The goal string that binds a grant to an intent statement and an Intent Map (`intentGoal(ref, map_digest)`).
pub fn intent_goal(intent_ref: &str, map_digest: &str) -> String {
    let mut g = String::from(INTENT_GOAL_PREFIX);
    g.push_str(intent_ref);
    if !map_digest.is_empty() {
        g.push(':');
        g.push_str(map_digest);
    }
    g
}

/// Intent Layer v2 session grants (G_0 and the deltas D_k): `pca-intent:v2:<session>:<map_digest>` (rule 13 amends rule 12).
pub const INTENT_GOAL_V2_PREFIX: &str = "pca-intent:v2:";

/// The goal commitment an intent slot claims the root grant carries (`intentGoalCommit`, v1 goal).
pub fn intent_goal_commit(intent_ref: &str, map_digest: &str, goal_salt: &str) -> String {
    intent_goal_commit_in(intent_ref, map_digest, goal_salt, None)
}

/// `intentGoalCommit(i, session)`: with a session (the PCActn carries `intent_session`) the goal is the v2 session goal
/// `"pca-intent:v2:" + session + ":" + map_digest`; `ref` is then bound through the session root (rule 13 step 3).
pub fn intent_goal_commit_in(intent_ref: &str, map_digest: &str, goal_salt: &str, session: Option<&str>) -> String {
    let goal = match session {
        Some(s) => format!("{INTENT_GOAL_V2_PREFIX}{s}:{map_digest}"),
        None => intent_goal(intent_ref, map_digest),
    };
    hash_canonical(&json!({ "d": INTENT_GOAL_COMMIT_DOMAIN, "goal": goal, "salt": goal_salt }))
}

/// The root grant's goal commitment (`rootGoalCommit`): the FIRST caveat that is an OBJECT with `type == "envelope"`, its
/// `goal_commit` when that is a string; else `None`.
pub fn root_goal_commit(grant: &Value) -> Option<&str> {
    let env = grant
        .get("caveats")?
        .as_array()?
        .iter()
        .find(|c| c.is_object() && c.get("type").and_then(|t| t.as_str()) == Some("envelope"))?;
    env.get("goal_commit")?.as_str()
}

fn safe_nonneg(v: &Value) -> Option<u64> {
    let n = v.as_i64()?;
    (0..=MAX_SAFE_INT).contains(&n).then_some(n as u64)
}

/// `validateIntentWire`: the slot must be an object with EXACTLY the five members, `ref` / `map_digest` canonical base64url
/// of 32 bytes, `goal_salt` a non-empty string of at most 128 UTF-8 bytes, `fidelity_ppm` a safe integer in [0, 1e6],
/// `residual_risk_ppm` a non-negative safe integer. `Err` names the first rule broken (in the TS order).
pub fn validate_intent_wire(v: &Value) -> Result<EnvelopeIntent, &'static str> {
    let o = v.as_object().ok_or("'intent' must be an object")?;
    if o.keys().any(|k| !ENVELOPE_INTENT_FIELDS.contains(&k.as_str())) {
        return Err("unknown field in 'intent'");
    }
    if ENVELOPE_INTENT_FIELDS.iter().any(|k| !o.contains_key(*k)) {
        return Err("missing field in 'intent'");
    }
    let b32 = |k: &str| o.get(k).and_then(|x| x.as_str()).filter(|s| crate::chain::decode_b64u_strict(s, 32).is_some());
    let intent_ref = b32("ref").ok_or("'intent.ref' is not canonical base64url (32 bytes)")?;
    let map_digest = b32("map_digest").ok_or("'intent.map_digest' is not canonical base64url (32 bytes)")?;
    let goal_salt = o
        .get("goal_salt")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty() && s.len() <= MAX_INTENT_GOAL_SALT_LEN)
        .ok_or("'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)")?;
    let fidelity_ppm = o
        .get("fidelity_ppm")
        .and_then(safe_nonneg)
        .filter(|f| *f <= PPM_ONE)
        .ok_or("'intent.fidelity_ppm' must be a safe integer in [0, 1000000]")?;
    let residual_risk_ppm =
        o.get("residual_risk_ppm").and_then(safe_nonneg).ok_or("'intent.residual_risk_ppm' must be a non-negative safe integer")?;
    Ok(EnvelopeIntent {
        claim: IntentClaim { intent_ref: intent_ref.to_string(), map_digest: map_digest.to_string(), fidelity_ppm, residual_risk_ppm },
        goal_salt: goal_salt.to_string(),
    })
}

/// IN-GUEST part of the `intent` check for a PCActn: `Ok(None)` when the PCActn carries no `intent`; `Ok(Some(claim))` when
/// the slot is well formed AND opens the root grant's goal commitment (rule 2); `Err` otherwise (deny).
pub fn bind_intent(pcactn: &Value, grant: &Value) -> Result<Option<IntentClaim>, &'static str> {
    let slot = match pcactn.get("intent") {
        None => return Ok(None),
        Some(s) => s,
    };
    let i = validate_intent_wire(slot)?;
    let commit = root_goal_commit(grant).ok_or("the root grant carries no envelope goal commitment to bind the intent to")?;
    // rule 13 amends step 2: with `intent_session` the root is a SESSION grant and the goal is the v2 session goal (the
    // member's wire validity is checked with the rest of the PCActn; a non-string session cannot open any commitment)
    let session = match pcactn.get("intent_session") {
        None => None,
        Some(is) => Some(is.get("session").and_then(|s| s.as_str()).ok_or("intent_session.session is not a string")?),
    };
    if intent_goal_commit_in(&i.claim.intent_ref, &i.claim.map_digest, &i.goal_salt, session) != commit {
        return Err("intent ref / map_digest / goal_salt do not open the root grant's goal commitment");
    }
    Ok(Some(i.claim))
}

/// VERIFIER part (rules 0, 1, 3, 4): the relying party's policy against the proved intent claim (`None` = the decision
/// carried no intent). An inactive policy accepts anything (the binding itself was proved in the guest).
pub fn check_intent_policy(claim: Option<&IntentClaim>, policy: &IntentPolicy) -> Result<(), IntentPolicyFailure> {
    if !policy.active() {
        return Ok(());
    }
    let ok_bound = |x: Option<u64>| x.is_none_or(|v| v <= MAX_SAFE_INT as u64);
    if !ok_bound(policy.min_fidelity_ppm) || !ok_bound(policy.max_residual_risk_ppm) {
        return Err(IntentPolicyFailure::Misconfigured);
    }
    let c = claim.ok_or(IntentPolicyFailure::Missing)?;
    if let Some(min) = policy.min_fidelity_ppm {
        if c.fidelity_ppm < min {
            return Err(IntentPolicyFailure::Fidelity { claimed: c.fidelity_ppm, minimum: min });
        }
    }
    if let Some(max) = policy.max_residual_risk_ppm {
        if c.residual_risk_ppm > max {
            return Err(IntentPolicyFailure::ResidualRisk { claimed: c.residual_risk_ppm, maximum: max });
        }
    }
    Ok(())
}
