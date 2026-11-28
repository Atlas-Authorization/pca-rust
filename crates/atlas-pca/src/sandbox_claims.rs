//! Runtime-class claim signing (the verification side is `runtime_claim`) and the passport / evidence digests a claim binds to.
//! Natives match the strict form: `verified_runtime_class_trust` refuses negative times and empty or over-128-character digests
//! (see `runtime_claim`). JSON-valued like the reference.
use crate::grants::sign_body;
use crate::runtime_claim::{verified_runtime_class, RUNTIME_CLAIM_DOMAIN};
use crate::{b64_encode, hash_canonical_strict};
use serde_json::{json, Map, Value};

/// `{v: 1, ...c, attestor: b64u(public)}` signed by the 32-byte Ed25519 seed `secret` over `domain || strictCanonical(unsigned)`.
/// `Err` for a seed that is not 32 bytes, a `c` that is not an object, or a body outside the strict JSON profile. The class and
/// times are NOT checked here (the reference does not; the verifier refuses them).
pub fn sign_runtime_claim(secret: &[u8], public: &[u8], c: &Value) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| format!("private key of length 32 expected, got {}", secret.len()))?;
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.extend(c.as_object().ok_or("runtime claim must be an object")?.iter().map(|(k, v)| (k.clone(), v.clone())));
    m.insert("attestor".into(), json!(b64_encode(public)));
    let sig = sign_body(RUNTIME_CLAIM_DOMAIN, &Value::Object(m.clone()), &seed)?;
    m.insert("sig".into(), json!(sig));
    Ok(Value::Object(m))
}

/// `verified_runtime_class` over the reference's trust object `{pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}`.
/// Anything missing or mistyped in the trust (or `now` not a non-negative safe integer) is `"none"`.
pub fn verified_runtime_class_trust(claim: &Value, trust: &Value) -> &'static str {
    let strings = |k: &str| trust.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>());
    let (Some(pinned), Some(pd), Some(ev)) =
        (strings("pinnedAttestors"), trust.get("passportDigest").and_then(Value::as_str), strings("verifiedEvidenceDigests"))
    else {
        return "none";
    };
    match trust.get("now").and_then(crate::safe_int) {
        Some(now) if now >= 0 => verified_runtime_class(claim, &pinned, pd, &ev, now),
        _ => "none",
    }
}

fn digest(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "canonicalize: value is outside the strict JSON profile".to_string())
}

/// `hashCanonical` of a signed passport.
pub fn passport_digest(signed_passport: &Value) -> Result<String, String> {
    digest(signed_passport)
}

/// The digest a claim's `evidence_digest` must equal for this attestation document.
pub fn evidence_digest(document: &Value) -> Result<String, String> {
    digest(document)
}

/// `trustFromAttestation`: the trust a runtime claim is checked against, built from a hardware attestation verdict. `verdict` is what
/// the caller's vendor verifier returned for `document` (`Err` for a throw). Only an `ok` and `bound` verdict admits the document's
/// digest into `verifiedEvidenceDigests`; anything else (an error, not bound, a document outside the strict profile) leaves the list
/// empty, so every claim verifies as `none`.
pub fn trust_from_attestation(verdict: Result<crate::attest::AttResult, String>, document: &Value, pinned_attestors: &[String], passport_digest: &str, now_ms: i64) -> Value {
    let admitted = matches!(&verdict, Ok(v) if v.ok && v.bound == Some(true));
    let evidence: Vec<String> = if admitted { evidence_digest(document).into_iter().collect() } else { vec![] };
    json!({"pinnedAttestors": pinned_attestors, "passportDigest": passport_digest, "verifiedEvidenceDigests": evidence, "now": now_ms})
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    use crate::attest::AttResult;

    #[test]
    fn only_an_ok_and_bound_verdict_admits_the_evidence() {
        let doc = json!({"quote": "q"});
        let pins = vec!["k".to_string()];
        let ok = AttResult { ok: true, bound: Some(true), ..Default::default() };
        let t = trust_from_attestation(Ok(ok), &doc, &pins, "pd", 5);
        assert_eq!(t["verifiedEvidenceDigests"], json!([evidence_digest(&doc).unwrap()]));
        assert_eq!((t["now"].as_i64(), t["passportDigest"].as_str()), (Some(5), Some("pd")));
        for v in [Ok(AttResult { ok: true, bound: Some(false), ..Default::default() }), Ok(AttResult { ok: true, bound: None, ..Default::default() }), Ok(AttResult::default()), Err("boom".to_string())] {
            assert_eq!(trust_from_attestation(v, &doc, &pins, "pd", 5)["verifiedEvidenceDigests"], json!([]));
        }
    }
}
