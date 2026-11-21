//! Intent kit, part 4: the runtime half of `@atlasauth/pca-intent`: bond sizing and the signed semantic judge panel (split-conformal
//! calibration, the k-of-n threshold), routing an admitted action by the map's posterior, the judge input and the intent-conformance
//! attestation, just-in-time consent, question cards, and the committed (Merkle, salted) form of an Intent Map.
//!
//! Everything is JSON-valued (`&serde_json::Value` in, `Result<Value, String>` out, the reference's field names) except the learner,
//! which is the part-2 [`crate::intent_kit2::learner::Learner`]. A reference throw is an `Err`. shortcut: the attested-judge gate of the
//! semantic threshold is not ported (the hardware-attestation predicate is injected in the reference and is not exercised).

pub mod commit;
pub mod routing;
pub mod semantic;
pub mod ux;

use serde_json::Value;

pub type R<T> = Result<T, String>;

/// `String(x)` of a double (`NaN`, `Infinity`, `-Infinity`, else the shortest round-trip form).
pub fn js_num(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return (if f > 0.0 { "Infinity" } else { "-Infinity" }).into();
    }
    crate::intent_kit3::js_str(Some(&crate::intent_kit3::num_json(f)))
}

/// The double of a JSON number (`NaN` for anything else: the reference's `undefined` / non-number in arithmetic).
pub fn dbl(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

/// A typeof-number JSON member that is a finite double.
pub fn finite(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}
