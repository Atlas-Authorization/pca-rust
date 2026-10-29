//! Signed agent passport verification (wire level), the native counterpart of `verifyPassport` in `@atlasauth/pca`.
//! Same reason codes and check order; the reason text is not part of the contract. Every signature suite this crate
//! implements for PCActns (`supported_suites()`) is accepted, the post-quantum ones only under a PQ key pinned for the
//! issuer (`pq_pins`); a suite it does not implement is refused with `unsupported_suite`. Hardware evidence: the age rule,
//! the binding handed to the verifier and the identity comparison are enforced here, but the crate ships no vendor
//! attestation verifier: supply one as `attest`. Without it a `hardware_rooted` passport that passes every other check
//! is refused with `hardware_verifier_missing` (fail closed, never a software pass).

use super::attest::{Binding, HardwareVerifier};
use super::{canonicalize_strict, hash_canonical_strict, pinned, resolve_sig_alg, safe_int, verify_suite};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

const SIG_DOMAIN: &[u8] = b"atlas-pca/passport-sig/v1\0";
const DEFAULT_EVIDENCE_AGE_MS: i64 = 24 * 3_600_000;
const MAX_SKEW_MS: i64 = 60_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// What the quote's bound value must equal: holder = the subject key, grant = `passport:<id>`, epoch 0.
pub struct PassportBinding {
    pub holder_pub: String,
    pub grant_ref: String,
    pub epoch: i64,
    pub nonce: String,
}

/// A hardware verifier's answer. `measured` holds `model_id`, `operator`, `weights_digest`, `weights_measured`,
/// `runtime_measurement`, `system_prompt_digest` and `tool_manifest_digest` as the hardware measured them.
pub struct PassportAttestation {
    pub ok: bool,
    pub bound: bool,
    pub measured: Option<Map<String, Value>>,
}

pub type AttestFn<'a> = &'a dyn Fn(&Value, &PassportBinding) -> Result<PassportAttestation, ()>;

pub struct PassportOptions<'a> {
    pub trusted_issuers: &'a [String],
    pub now_ms: i64,
    pub clock_skew_ms: Option<i64>,
    pub max_evidence_age_ms: Option<i64>,
    /// When set, must equal the passport's `sub`.
    pub subject: Option<&'a str>,
    /// PQ public keys pinned per issuer key (required for every non-Ed25519 suite).
    pub pq_pins: Option<&'a HashMap<String, String>>,
    /// An integrator-supplied hardware-attestation verifier. It wins over `default_verifier`.
    pub attest: Option<AttestFn<'a>>,
    /// The crate's own vendor verifier, used for a hardware-rooted passport when `attest` is `None`. Build it with
    /// `attest::verifier_from_config(vendor, config)` and give it the evidence with `with_evidence`; `None` means none.
    pub default_verifier: Option<&'a HardwareVerifier>,
    /// `Some(Ok(true))` = revoked; `None` (no source) or `Err` = `revocation_unavailable`.
    pub revoked: Option<&'a dyn Fn(&str, &str, &str) -> Result<bool, ()>>,
}

fn nonempty(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty())
}

/// `Ok(())` when the passport verifies, else the reason code.
pub fn verify_passport(sp: &Value, o: &PassportOptions) -> Result<(), &'static str> {
    let s = sp.as_object().ok_or("malformed")?;
    let p = s.get("passport").and_then(Value::as_object);
    if s.get("typ").and_then(Value::as_str) != Some("atlas-pca/passport") || p.is_none() {
        return Err("malformed");
    }
    let p = p.unwrap();
    if s.get("ver").and_then(safe_int) != Some(1) {
        return Err("unsupported_version");
    }
    if resolve_sig_alg(s.get("alg")).is_none() {
        return Err("unsupported_suite");
    }
    let (iss, sub, id) = match (s.get("iss").and_then(nonempty), s.get("sub").and_then(nonempty), s.get("sig").and_then(nonempty), p.get("id").and_then(nonempty)) {
        (Some(a), Some(b), Some(_), Some(d)) => (a, b, d),
        _ => return Err("malformed"),
    };
    let hw = p.get("hardware_rooted").and_then(Value::as_bool);
    if p.get("model_id").and_then(nonempty).is_none() || p.get("operator").and_then(nonempty).is_none() || hw.is_none() {
        return Err("malformed");
    }
    let hw = hw.unwrap();
    let (nbf, exp, iat) = (s.get("nbf").and_then(safe_int), s.get("exp").and_then(safe_int), s.get("iat").and_then(safe_int));
    match (nbf, exp, iat) {
        (Some(nbf), Some(exp), Some(_)) if exp > nbf && o.now_ms.abs() <= MAX_SAFE => {}
        _ => return Err("malformed"),
    }
    let (nbf, exp) = (nbf.unwrap(), exp.unwrap());
    if !o.trusted_issuers.iter().any(|t| t == iss) {
        return Err("unknown_issuer");
    }
    let mut body = s.clone();
    body.remove("sig");
    body.remove("pq_sig");
    let canon = canonicalize_strict(&Value::Object(body)).map_err(|_| "malformed")?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(canon.as_bytes());
    let pq = pinned::resolve_pq_key(Some(iss), s.get("pq_pk"), None, o.pq_pins, None);
    if !verify_suite(s.get("alg"), iss, pq.as_ref(), &msg, s.get("sig"), s.get("pq_sig")) {
        return Err("bad_signature");
    }
    let get = |k: &str| p.get(k).cloned().unwrap_or(Value::Null);
    let fp = json!({
        "d": "atlas-pca/passport/v1", "model_id": get("model_id"), "weights_digest": get("weights_digest"),
        "system_prompt_digest": get("system_prompt_digest"), "tool_manifest_digest": get("tool_manifest_digest"),
        "runtime_measurement": get("runtime_measurement"), "operator": get("operator"), "hardware_rooted": hw,
    });
    if hash_canonical_strict(&fp).as_deref() != Some(id) {
        return Err("id_mismatch");
    }
    let skew = o.clock_skew_ms.map_or(0, |k| k.clamp(0, MAX_SKEW_MS));
    if o.now_ms + skew < nbf {
        return Err("not_yet_valid");
    }
    if o.now_ms - skew >= exp {
        return Err("expired");
    }
    if let Some(want) = o.subject {
        if want != sub {
            return Err("subject_mismatch");
        }
    }
    match o.revoked {
        None => return Err("revocation_unavailable"),
        Some(f) => match f(id, iss, sub) {
            Err(()) => return Err("revocation_unavailable"),
            Ok(true) => return Err("revoked"),
            Ok(false) => {}
        },
    }
    if hw {
        let ev = s.get("evidence").and_then(Value::as_object);
        let nonce = ev.and_then(|e| e.get("document")).and_then(Value::as_object).and_then(|d| d.get("nonce")).and_then(nonempty);
        let at = ev.and_then(|e| e.get("at")).and_then(safe_int);
        let (Some(nonce), Some(at)) = (nonce, at) else { return Err("hardware_evidence_missing") };
        let max_age = o.max_evidence_age_ms.unwrap_or(DEFAULT_EVIDENCE_AGE_MS);
        if max_age < 0 || o.now_ms - at > max_age || at - o.now_ms > skew {
            return Err("hardware_evidence_stale");
        }
        if o.attest.is_none() && o.default_verifier.is_none() {
            return Err("hardware_verifier_missing");
        }
        let doc = ev.and_then(|e| e.get("document")).unwrap();
        let binding = PassportBinding { holder_pub: sub.to_string(), grant_ref: format!("passport:{id}"), epoch: 0, nonce: nonce.to_string() };
        let answer = match (o.attest, o.default_verifier) {
            (Some(attest), _) => attest(doc, &binding),
            (None, Some(v)) => Ok(run_default(v, &binding, o.now_ms)),
            (None, None) => return Err("hardware_verifier_missing"),
        };
        match answer {
            Ok(r) if r.ok && r.bound => {
                if !identity_matches(p, r.measured.as_ref()) {
                    return Err("hardware_identity_mismatch");
                }
            }
            _ => return Err("hardware_attestation_failed"),
        }
    }
    Ok(())
}

/// Run the crate's default vendor verifier for a passport binding (holder = the subject key, grant = `passport:<id>`, epoch 0).
fn run_default(v: &HardwareVerifier, b: &PassportBinding, now_ms: i64) -> PassportAttestation {
    let bind = Binding { holder_pub: b.holder_pub.clone(), grant_ref: b.grant_ref.clone(), epoch: b.epoch as f64, nonce: b.nonce.clone() };
    let r = v.verify(now_ms, &bind);
    PassportAttestation { ok: r.ok, bound: r.bound == Some(true), measured: r.measured }
}

/// The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
/// measurement when the passport states them; measured weights when it claims them).
fn identity_matches(p: &Map<String, Value>, m: Option<&Map<String, Value>>) -> bool {
    let Some(m) = m else { return false };
    let eq = |k: &str| matches!((p.get(k).and_then(Value::as_str), m.get(k).and_then(Value::as_str)), (Some(a), Some(b)) if a == b);
    if !eq("model_id") || !eq("operator") {
        return false;
    }
    for k in ["weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"] {
        if p.contains_key(k) && !eq(k) {
            return false;
        }
    }
    !(p.get("weights_measured") == Some(&Value::Bool(true)) && m.get("weights_measured") != Some(&Value::Bool(true)))
}
