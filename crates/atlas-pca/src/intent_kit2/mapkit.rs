//! The Intent Map, JSON-valued view (deprecated): every function here delegates to [`crate::intent_kit::mapkit`], the single implementation
//! shared with the flagship's design (`createLearner(omega, options)`, `emitIntentMap`, `verifyIntentMap`, `learnerFromMap`, typed
//! [`crate::intent_kit::omega::Omega`]). The wrappers keep the older signatures (omegas as plain JSON, a [`Learner`] view) so existing callers
//! compile unchanged; new code should call `intent_kit::mapkit` directly.
use super::learner::*;
use super::omega::*;
use super::util::*;
use crate::intent_kit::mapkit as base;
use serde_json::{json, Value};

pub use crate::intent_kit::mapkit::INTENT_MAP_DOMAIN;
pub const PPM: f64 = 1_000_000.0;

/// `ppm(x)` = round(x * 1e6), an integer-valued double.
pub fn ppm(x: f64) -> R<f64> {
    round_half_up(x * PPM)
}

fn typed(o: &Value) -> R<crate::intent_kit::omega::Omega> {
    let om = Omega::parse(o)?;
    for vs in &om.verbs {
        vs.weight_of()?;
    }
    Ok(om.to_core())
}

pub fn omega_to_json(o: &Value) -> R<Value> {
    Ok(base::omega_to_json(&typed(o)?))
}

pub fn omega_from_json(j: &Value) -> R<Value> {
    Ok(base::omega_from_json(j)?.to_json())
}

pub fn grant_digest(g: &Value) -> R<String> {
    base::grant_digest(g)
}

/// Content address of an Intent Map.
pub fn intent_map_digest(m: &Value) -> R<String> {
    base::intent_map_digest(m)
}

/// Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). `o` is the reference's `MapLearnerOptions`
/// (null or absent = defaults).
pub fn create_learner(omega: &Value, o: &Value) -> R<Learner> {
    let core = base::create_learner(&typed(omega)?, if o.is_null() { None } else { Some(o) })?;
    Learner::from_core(omega.clone(), core)
}

pub fn emit_intent_map(l: &mut Learner, intent_ref: Option<&str>) -> R<Value> {
    base::emit_intent_map(l.core_mut(), intent_ref)
}

/// The learner parameters a map records (inverse of what [`emit_intent_map`] writes).
pub fn map_learner_options(m: &Value) -> R<Value> {
    base::map_learner_options(m)
}

/// Rebuild the learner a map describes (omega + prior + observations).
pub fn learner_from_map(m: &Value) -> R<Learner> {
    Learner::from_core(omega_from_json(&m["omega"])?, base::learner_from_map(m)?)
}

/// Replay a single-principal map and check every number, every cell and the grant: `{ok, problems}`.
pub fn verify_intent_map(m: &Value) -> Value {
    base::verify_intent_map(m)
}

/// A runtime divergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good.
pub fn apply_divergence(l: &mut Learner, outcome: &Value, y: f64) -> R<Value> {
    let before = l.cells().iter().filter(|c| c.in_grant).count();
    l.observe(outcome, y, "runtime", None)?;
    let after = l.cells().iter().filter(|c| c.in_grant).count();
    Ok(json!({"before": before, "after": after, "grant": l.synthesize()?}))
}
