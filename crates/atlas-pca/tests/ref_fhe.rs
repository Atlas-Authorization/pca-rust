//! Differential replay of the pure parts of the homomorphic risk gate (quantization, gate policy, claim binding, plaintext
//! verdict, signed claims, replay guard, verdict attestation) against the TypeScript reference (test-data/ref-fhe.json.gz).
//! A reference throw only requires a refusal. Skipped (counted, must stay under 10%): cases holding a lone UTF-16 surrogate.
//! The BFV evaluation (SEAL) is not in the corpus and not ported (see src/fhe.rs).
mod common;
use atlas_pca::fhe::*;
use atlas_pca::serde_json::Value;
use std::collections::HashSet;

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&Value::Null)
}

fn scale(a: &[Value], i: usize) -> f64 {
    match a.get(i) {
        None => DEFAULT_SCALE,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(_) => f64::NAN,
    }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(|s| s.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default()
}

/// A signing seed is a base64url string (the wrong-length key cases are plain too).
fn seed(v: &Value) -> Vec<u8> {
    atlas_pca::decode_b64u_strict(v.as_str().unwrap_or(""), None).unwrap_or_default()
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "transformedInputs" => numbers_json(&transformed_inputs(arg(a, 0))?),
        "quantizeRiskInputs" => numbers_json(&quantize_risk_inputs(arg(a, 0), scale(a, 1))?),
        "weightVector" => numbers_json(&weight_vector(arg(a, 0))?),
        "fheRiskPolicy" => fhe_risk_policy(arg(a, 0), arg(a, 1), scale(a, 2)),
        "plaintextVerdict" => plaintext_verdict(arg(a, 0), arg(a, 1), arg(a, 2)),
        "fromActn" => numbers_json(&transformed_inputs(&risk_inputs_from_pcactn(arg(a, 0))?)?),
        "binding" => binding_from_pcactn(arg(a, 0)),
        "sign" => {
            let nonce = atlas_pca::decode_b64u_strict(arg(a, 3)["$bytes"].as_str().unwrap_or(""), None).unwrap_or_default();
            sign_risk_claim(arg(a, 0), &seed(arg(a, 1)), arg(a, 2).as_str().ok_or("context must be a string")?, &nonce)
        }
        "claimDigest" => signed_claim_digest(arg(a, 0)).map(Value::String),
        "verifyClaim" => {
            let exp = arg(a, 1);
            let mut used: HashSet<String> = strs(&exp["used"]).into_iter().collect();
            let max = exp["max"].as_u64().unwrap_or(0) as usize;
            let mut guard = |k: &str| {
                if used.contains(k) || used.len() >= max {
                    return false;
                }
                used.insert(k.to_string());
                true
            };
            let signers = strs(&exp["trustedSigners"]);
            let mut e = ClaimExpectations {
                trusted_signers: &signers,
                context: exp["context"].as_str().unwrap_or(""),
                binding: &exp["binding"],
                policy: &exp["policy"],
                nonces: &mut guard,
            };
            Ok(verify_signed_risk_claim(arg(a, 0), &mut e))
        }
        "attest" => attest_verdict(&seed(arg(a, 0)), arg(a, 1), arg(a, 2), arg(a, 3).as_bool().unwrap_or(false)),
        "verifyAttest" => {
            let exp = arg(a, 1);
            let gate = exp.get("gate").filter(|g| g.is_object());
            Ok(verify_verdict_attestation(arg(a, 0), &strs(&exp["trustedHolders"]), exp["claimDigest"].as_str().unwrap_or(""), gate))
        }
        "nonceGuard" => {
            let mut g = memory_nonce_guard(arg(a, 0).as_u64().unwrap_or(0) as usize);
            Ok(Value::Array(strs(arg(a, 1)).iter().map(|k| Value::Bool(g.claim(k))).collect()))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn fhe_vectors() {
    let cases = common::ref_cases_seeded("fhe");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn signing_refuses_a_bad_key_and_a_zero_nonce() {
    let claim = atlas_pca::serde_json::json!({ "binding": {}, "encInputs": "x", "policy": {} });
    let n = [7u8; 16];
    assert!(sign_risk_claim(&claim, &[0u8; 31], "ctx", &n).unwrap_err().contains("32-byte"));
    assert!(sign_risk_claim(&claim, &[1u8; 32], "ctx", &[0u8; 16]).is_err());
    assert!(sign_risk_claim(&claim, &[1u8; 32], "", &n).is_err());
}
