//! Differential replay of test-data/ref-safety-certificate.json.gz (written by the TypeScript reference): the constants, the check
//! row validator, the bound and its statement, the signed message, issuing (Ed25519, ML-DSA-65 and the hybrid), verification with
//! its pins, age policy and required checks, the wire form and the compliance row. A case the reference refuses must be refused
//! here; reason strings are compared exactly.
mod common;
use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::safety_certificate::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::{replay, skip, thrown};

/// A double of the corpus: a JSON number, or `{"$num": "NaN" | "Infinity" | "-Infinity"}`.
fn double(v: &Value) -> Option<f64> {
    match v.get("$num").and_then(Value::as_str) {
        Some("NaN") => Some(f64::NAN),
        Some("Infinity") => Some(f64::INFINITY),
        Some("-Infinity") => Some(f64::NEG_INFINITY),
        _ => v.as_f64(),
    }
}

fn options(v: &Value) -> SafetyCertificateOptions {
    SafetyCertificateOptions {
        guardian: v.get("guardian").and_then(Value::as_str).map(String::from),
        require_checks: v
            .get("requireChecks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.as_str().map(String::from))
            .collect(),
        max_age_ms: v.get("maxAgeMs").and_then(double),
        now: v.get("now").and_then(double),
        pq_pins: v.get("pqPins").cloned(),
    }
}

fn issue(a: &Value) -> Result<Value, String> {
    let guardian = KeyPair::from_seed_b64u(a["guardianSecret"]["$bytes"].as_str().ok_or("not a key")?)?;
    let pq = match a["suite"]["pqSeed"]["$bytes"].as_str() {
        Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &atlas_pca::decode_b64u_strict(seed, None).ok_or("pqSeed")?)?),
        None => None,
    };
    issue_safety_certificate(
        a,
        &guardian,
        &Suite {
            alg: a["suite"]["alg"].as_str(),
            pq: pq.as_ref(),
        },
    )
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => {
            json!({"SAFETY_CERT_DOMAIN": SAFETY_CERT_DOMAIN, "SAFETY_CERT_VERSION": SAFETY_CERT_VERSION, "SAFETY_CERT_SCOPE": SAFETY_CERT_SCOPE, "MAX_SAFETY_CHECKS": MAX_SAFETY_CHECKS})
        }
        "safetyCertificateBound" => {
            let n = |k: &str| a[0].get(k).and_then(double).unwrap_or(f64::NAN);
            match safety_certificate_bound(n("bMax"), n("kappa")) {
                b if b.is_nan() => json!({"$num": "NaN"}),
                b if b.is_infinite() => json!({"$num": if b > 0.0 { "Infinity" } else { "-Infinity" }}),
                b => atlas_pca::prohibitions::num_value(b),
            }
        }
        "safetyCertificateStatement" => json!(safety_certificate_statement(double(&a[0]).unwrap_or(f64::NAN))),
        "validateSafetyChecks" => json!(validate_safety_checks(&a[0])),
        "safetyCertificateMessage" => json!({"$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(safety_certificate_message(&a[0]))}),
        // a non-finite issue time is not a JSON value: the reference refuses it in its canonical form, here it cannot be given
        "issueSafetyCertificate" if a[0]["issuedAt"].is_object() => skip("a non-finite issue time"),
        "issueSafetyCertificate" => issue(&a[0]).unwrap_or_else(thrown),
        "verifySafetyCertificate" if a[0]["issued_at"].is_object() => skip("a non-finite issue time"),
        // the reference's legacy `allowUnboundPq` opt-out is not ported: those cases (accepted by the reference only through it) must be refused
        "verifySafetyCertificate" if a[1]["allowUnboundPq"] == true => {
            assert_eq!(verify_safety_certificate(&a[0], &options(&a[1]))["ok"], false, "an unbound post-quantum key must be refused");
            skip("allowUnboundPq is not ported; the unbound key is refused")
        }
        "verifySafetyCertificate" => verify_safety_certificate(&a[0], &options(&a[1])),
        "encodeSafetyCertificate" => json!(encode_safety_certificate(&a[0])),
        "decodeSafetyCertificate" => a[0].as_str().and_then(decode_safety_certificate).unwrap_or(Value::Null),
        "safetyCertificateForCompliance" => safety_certificate_for_compliance(&a[0], &options(&a[1])).unwrap_or(Value::Null),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_safety_certificate_matches_the_reference() {
    // 2 cases carry a non-finite issue time (one issued, one verified); 2 are accepted by the reference only through its legacy
    // `allowUnboundPq` opt-out and are asserted REFUSED here
    replay("safety-certificate", 262, 4, run);
}
