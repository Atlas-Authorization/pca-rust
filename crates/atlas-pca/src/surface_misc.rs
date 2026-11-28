//! Small public constants and helpers of the satellite packages (pca-authzen, pca-bbs, pca-ratchet, pca-policy-ci, pca-payments,
//! pca-intent, pca-goal, pca-vdf, pca-signals), under the reference's names in snake case. The TypeScript is authoritative; each item
//! forwards to the code that already implements it where one exists.
use crate::vdf::{rsa_2048_challenge_modulus, vdf_verify_canonical_detailed, vdf_verify_detailed, Int};
use rsa::BigUint;
use serde_json::{json, Value};

// ---- pca (core) -----------------------------------------------------------------------------------------------------------------

/// The closed top-level field sets of a ver-2 PCActn (`wire.ts`); `validate_wire` is `validateWireV2`.
pub const PCACTN_REQUIRED_FIELDS: [&str; 14] =
    ["ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig"];
pub const PCACTN_OPTIONAL_FIELDS: [&str; 15] = [
    "nonce",
    "caution",
    "rationale_commitment",
    "progress_step",
    "prohibition_evidence",
    "tool_binding",
    "threshold",
    "zk_compliance",
    "bond_ref",
    "alg",
    "pq_pk",
    "pq_sig",
    "intent",
    "intent_session",
    "fresh_at",
];

/// `artifactTooLarge`: the raw wire size of a PCActn document exceeds [`crate::MAX_ARTIFACT_BYTES`] UTF-8 bytes.
pub fn artifact_too_large(s: &str) -> bool {
    s.len() > crate::MAX_ARTIFACT_BYTES
}

/// `isBudgetAllocCaveat`: `{type: "budget_alloc", limit}` with a finite, non-negative numeric `limit`.
pub fn is_budget_alloc_caveat(cv: &Value) -> bool {
    cv.get("type").and_then(Value::as_str) == Some("budget_alloc") && cv.get("limit").and_then(Value::as_f64).is_some_and(|l| l.is_finite() && l >= 0.0)
}

/// `encodeKey`: base64url without padding.
pub fn encode_key(bytes: &[u8]) -> String {
    crate::b64_encode(bytes)
}

/// `decodeSig`: base64url (padding tolerated) to bytes; `None` for any other character.
pub fn decode_sig(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

// ---- pca-authzen / pca-bbs ------------------------------------------------------------------------------------------------------

/// The largest page a search request may ask for.
pub const MAX_SEARCH_LIMIT: usize = 1000;

// ---- pca-ratchet ----------------------------------------------------------------------------------------------------------------

/// The largest provable spend ceiling: `2^N_BITS - 1`.
pub const MAX_PROVABLE_CEILING: u64 = (1u64 << crate::ratchet::RATCHET_N_BITS) - 1;
/// The deepest ratchet tree.
pub const MAX_RATCHET_DEPTH: usize = crate::ratchet::RATCHET_MAX_DEPTH;

// ---- pca-policy-ci --------------------------------------------------------------------------------------------------------------

/// `info` 1, `warn` 2, `error` 3; `None` for any other name.
pub fn severity_rank(severity: &str) -> Option<u8> {
    ["info", "warn", "error"].iter().position(|s| *s == severity).map(|i| i as u8 + 1)
}

// ---- pca-payments ---------------------------------------------------------------------------------------------------------------

/// `^mcc\.c(\d{4})$`: an action-kit trait that names one merchant category.
pub const MCC_TRAIT_RE: &str = r"^mcc\.c(\d{4})$";

/// The four-digit MCC a trait names (`mcc.c5734` gives `5734`), or `None` for any other trait.
pub fn mcc_of_trait(t: &str) -> Option<&str> {
    t.strip_prefix("mcc.c").filter(|d| d.len() == 4 && d.bytes().all(|b| b.is_ascii_digit()))
}

// ---- pca-intent -----------------------------------------------------------------------------------------------------------------

/// The Clopper-Pearson grid width in bits and the tolerance the bound is rounded outward by (`2^-44`).
pub const CP_GRID_BITS: u32 = 52;
pub const CP_TOLERANCE: f64 = 1.0 / (1u64 << 44) as f64;
/// Pieces of the harm-quadrature rule.
pub const HARM_QUADRATURE_PIECES: usize = 1024;

/// The built-in numeric domains for common fields: `{field: {lo, hi, dist}}` (others are derived from their literals).
pub fn default_domains() -> Value {
    json!({
        "action.params.amount": {"lo": 0, "hi": 100_000, "dist": "loguniform"},
        "env.hour": {"lo": 0, "hi": 23, "dist": "uniform"},
        "action.params.count": {"lo": 0, "hi": 1_000, "dist": "loguniform"},
    })
}

// ---- pca-intent (learner) -------------------------------------------------------------------------------------------------------

/// `learnerOptionsOf`: the serialisable parameters a learner was built with. `Err` for a learner that was not built from map parameters.
pub fn learner_options_of(l: &crate::intent_kit::learner::IntentLearner) -> Result<&Value, String> {
    l.map_params.as_ref().ok_or_else(|| "pca-intent: build the learner with createLearner() so its parameters are serialisable".to_string())
}

// ---- pca-goal -------------------------------------------------------------------------------------------------------------------

/// `^[0-9A-Za-z_]{1,64}$`: the grammar of a selector id.
pub const SEL_ID_RE: &str = "^[0-9A-Za-z_]{1,64}$";

pub fn is_sel_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `renderCond` / `renderQuantity`: the goal card's condition and quantity renderers.
pub use crate::goal::card::{cond as render_cond, quantity as render_quantity};

/// The names of the shipped intent ontologies (the keys of the reference's `ALL_ONTOLOGIES`).
pub const ALL_ONTOLOGY_NAMES: [&str; 5] = ["payments", "email", "calendar_travel", "code_repos", "data_access"];

/// `ALL_ONTOLOGIES`: `{name: ontology}` of the shipped domains.
pub fn all_ontologies() -> Value {
    let mut m = serde_json::Map::new();
    for n in ALL_ONTOLOGY_NAMES {
        if let Some(o) = crate::goal::ontologies::shipped_ontology(n) {
            m.insert(n.into(), o);
        }
    }
    Value::Object(m)
}

/// `signOntology`: the ontology as a signed `ontology` payload (the suite-agile goal signer, Ed25519).
pub fn sign_ontology(o: &Value, secret: &crate::agent::KeyPair) -> Result<Value, String> {
    crate::goal::sign::sign_payload("ontology", o, secret)
}

/// `verifyOntology`: whether `s` is an `ontology` payload signed by one of the pinned signers.
pub fn verify_ontology(s: &Value, pins: &[Value]) -> bool {
    crate::goal::sign::verify_payload(s, "ontology", pins)
}

// ---- pca-vdf --------------------------------------------------------------------------------------------------------------------

/// `DEFAULT_MODULUS`: the RSA-2048 challenge modulus.
pub fn default_modulus() -> BigUint {
    rsa_2048_challenge_modulus()
}

/// `vdfVerify`: whether (y, pi) is a valid Wesolowski proof for x over `t` squarings modulo `n`.
pub fn vdf_verify(x: &Int, y: &Int, pi: &Int, t: f64, n: &Int) -> bool {
    vdf_verify_detailed(x, y, pi, t, n).is_ok()
}

/// `vdfVerifyCanonical`: as [`vdf_verify`], also requiring the canonical (smaller-half) y and pi.
pub fn vdf_verify_canonical(x: &Int, y: &Int, pi: &Int, t: f64, n: &Int) -> bool {
    vdf_verify_canonical_detailed(x, y, pi, t, n).is_ok()
}

/// What [`calibrate_steps`] measured.
#[derive(Debug, Clone, PartialEq)]
pub struct Calibration {
    pub steps: u64,
    pub measured_squarings_per_second: f64,
    pub assumed_adversary_squarings_per_second: f64,
}

/// Turn a desired cooling-off into a `steps` count by timing squarings modulo `n` on this machine, scaled by a conservative
/// `adversary_advantage` (>= 1) so the real delay is a floor. `now_ms` is the clock (default the system clock). An operator helper,
/// not part of verification. Defaults: 50_000 squarings, advantage 10.
pub fn calibrate_steps(
    n: &BigUint,
    desired_seconds: f64,
    sample_squarings: Option<u64>,
    adversary_advantage: Option<f64>,
    now_ms: Option<&dyn Fn() -> f64>,
) -> Result<Calibration, String> {
    if *n <= BigUint::from(3u8) {
        return Err("calibrateSteps: modulus N must be a bigint > 3".into());
    }
    if !desired_seconds.is_finite() || desired_seconds <= 0.0 {
        return Err("calibrateSteps: desiredSeconds must be > 0".into());
    }
    let sample = sample_squarings.unwrap_or(50_000);
    let advantage = adversary_advantage.unwrap_or(10.0);
    if sample < 1 {
        return Err("calibrateSteps: sampleSquarings must be a safe integer >= 1".into());
    }
    if !advantage.is_finite() || advantage < 1.0 {
        return Err("calibrateSteps: adversaryAdvantage must be >= 1".into());
    }
    let sys = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0);
    let clock: &dyn Fn() -> f64 = match now_ms {
        Some(f) => f,
        None => &sys,
    };
    let mut y = BigUint::from(2u8) % n;
    let t0 = clock();
    for _ in 0..sample {
        y = (&y * &y) % n;
    }
    let t1 = clock();
    if !(t0.is_finite() && t1.is_finite()) {
        return Err("calibrateSteps: the clock must return finite times".into());
    }
    let elapsed_ms = (t1 - t0).max(f64::EPSILON);
    // keep the optimiser from dropping the loop
    if y == *n {
        return Err("unreachable".into());
    }
    let measured = sample as f64 / elapsed_ms * 1000.0;
    let assumed = measured * advantage;
    let steps = ((assumed * desired_seconds).ceil()).max(1.0) as u64;
    Ok(Calibration { steps, measured_squarings_per_second: measured, assumed_adversary_squarings_per_second: assumed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_and_matchers() {
        assert_eq!(PCACTN_REQUIRED_FIELDS.len() + PCACTN_OPTIONAL_FIELDS.len(), 29);
        assert!(artifact_too_large(&"a".repeat(524_289)) && !artifact_too_large(&"a".repeat(524_288)));
        assert!(
            is_budget_alloc_caveat(&json!({"type": "budget_alloc", "limit": 0}))
                && !is_budget_alloc_caveat(&json!({"type": "budget_alloc", "limit": -1}))
                && !is_budget_alloc_caveat(&json!({"type": "x", "limit": 1}))
        );
        assert_eq!(decode_sig(&encode_key(&[1, 2, 3, 250])), Some(vec![1, 2, 3, 250]));
        assert_eq!(decode_sig("a b"), None);
        assert_eq!(MAX_PROVABLE_CEILING, 4_294_967_295);
        assert_eq!(MAX_RATCHET_DEPTH, 20);
        assert_eq!((severity_rank("info"), severity_rank("error"), severity_rank("fatal")), (Some(1), Some(3), None));
        assert_eq!((mcc_of_trait("mcc.c5734"), mcc_of_trait("mcc.c573"), mcc_of_trait("mcc.cabcd"), mcc_of_trait("x.c5734")), (Some("5734"), None, None, None));
        assert!(is_sel_id("a_Z9") && !is_sel_id("") && !is_sel_id("a-b") && !is_sel_id(&"a".repeat(65)) && is_sel_id(&"a".repeat(64)));
        assert_eq!(CP_TOLERANCE, 2f64.powi(-44));
        assert_eq!(default_domains()["env.hour"]["hi"], 23);
        assert_eq!(all_ontologies().as_object().map(|m| m.len()), Some(5));
        let k = crate::agent::KeyPair::generate().unwrap();
        let o = crate::goal::ontologies::shipped_ontology("email").unwrap();
        let signed = sign_ontology(&o, &k).unwrap();
        assert!(verify_ontology(&signed, &[json!(k.public)]));
        assert!(!verify_ontology(&signed, &[json!("other")]));
    }

    #[test]
    fn calibration_floors_and_refuses() {
        let n = default_modulus();
        // a fake clock advancing 1 s per call: 1000 squarings in 1 s = 1000/s, x10 advantage, 2 s wanted => 20000 steps
        let tick = std::cell::Cell::new(-1000.0);
        let clock = || {
            tick.set(tick.get() + 1000.0);
            tick.get()
        };
        let c = calibrate_steps(&n, 2.0, Some(1000), None, Some(&clock)).unwrap();
        assert_eq!(c.steps, 20_000);
        assert!(calibrate_steps(&BigUint::from(3u8), 1.0, None, None, None).is_err());
        assert!(calibrate_steps(&n, 0.0, None, None, None).is_err());
        assert!(calibrate_steps(&n, 1.0, None, Some(0.5), None).is_err());
    }
}
