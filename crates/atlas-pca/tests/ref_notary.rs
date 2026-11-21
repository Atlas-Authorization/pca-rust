//! Differential replay of the notary (witnessed HTTP facts, salted Merkle body commitment, selective disclosure, PCActn binding,
//! the attested_fact caveat and its policy) against the TypeScript reference (test-data/ref-notary.json.gz). Salts are the
//! reference oracle's: salt_i = sha256("notary-oracle-salt/" + i)[..16], the counter reset per notarizeResponse call.
//! A reference throw only requires a refusal. Cases with a lone surrogate (no Rust string) are skipped.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::notary::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i).cloned().unwrap_or(Value::Null);
    match f {
        "constants" => Ok(json!({ "BODY_COMMIT_ALG": BODY_COMMIT_ALG, "ATTESTED_FACT_CAVEAT": ATTESTED_FACT_CAVEAT })),
        "notaryMessage" => notary_message(&a[0]).map(|m| json!({ "$bytes": b64u(&m) })),
        "notarizeResponse" => {
            let o = &a[1];
            let seed = o["notaryKey"]["secretKey"]["$bytes"].as_str().ok_or("notaryKey")?;
            let key = KeyPair::from_seed_b64u(seed)?;
            let mut i = 0u32;
            let mut salts = || {
                let h = Sha256::digest(format!("notary-oracle-salt/{i}").as_bytes());
                i += 1;
                Ok::<_, String>(h[..16].to_vec())
            };
            if !a[0].is_object() {
                return Err("input".into());
            }
            notarize_response(&a[0]["request"], &a[0]["response"], &key, o.get("observedAt"), o.get("textChunkSize"), &mut salts)
        }
        "discloseField" => disclose_field(&a[0], &a[1], &a[2]),
        "verifyNotaryAttestation" => Ok(json!(verify_notary_attestation(&a[0], &a[1]))),
        "verifyDisclosedField" => Ok(json!(verify_disclosed_field(&a[0], &a[1], &a[2]))),
        "factRef" => fact_ref(&a[0]).map(Value::String),
        "bindFactToPcActn" => bind_fact_to_pc_actn(&a[0], &a[1]),
        "factMatchesPcActn" => Ok(json!(fact_matches_pc_actn(&a[0], &a[1]))),
        "requireAttestedFact" => require_attested_fact(&a[0]),
        "isAttestedFactCaveat" => Ok(json!(is_attested_fact_caveat(&a[0]))),
        "notaryKeyUsable" => Ok(json!(notary_key_usable(&a[0], &a[1], &a[2]))),
        "evaluateAttestedFactCaveat" => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64;
            Ok(evaluate_attested_fact_caveat(&a[0], &a[1], a.get(2), now))
        }
        f => panic!("unknown fn {f} {:?}", arg(0)),
    }
}

#[test]
fn notary_vectors() {
    let cases = common::ref_cases("notary");
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
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
