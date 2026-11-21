//! Differential replay of test-data/ref-attest-pq-software.json.gz (written by the TypeScript reference): statement minting under the
//! post-quantum and hybrid suites (byte exact), attestor construction, and the verifier's scenarios and construction refusals. Keys are label
//! seeds (an Ed25519 secret and the ML-DSA keygen seed; SLH-DSA statements are verify-only inputs). Every function of the corpus has a
//! handler and the per-function totals are asserted. A reference refusal must be a refusal here. The corpus carries only the seed of each
//! key, so the key family follows the label the seed came from (as in the generator): the case `wrong-key-family` hands ML-DSA-65 key
//! material to an ML-DSA-87 attestor.
mod common;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use atlas_pca::agent::{KeyPair, PqKeyPair};
use atlas_pca::attest::pq_software::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::thrown;
use sha2::{Digest, Sha256};

const ALGS: [&str; 10] = [
    "ml-dsa-65",
    "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65",
    "ml-dsa-87",
    "hybrid-ed25519-ml-dsa-87",
    "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f",
    "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s",
    "ed25519",
];

fn family_of(alg: &str) -> Option<&'static str> {
    if alg.contains("ml-dsa-65") {
        Some("ML-DSA-65")
    } else if alg.contains("ml-dsa-87") {
        Some("ML-DSA-87")
    } else {
        None
    }
}

/// seed (base64url) -> the family of the label alg it was derived for
fn seed_families() -> HashMap<String, &'static str> {
    ALGS.iter()
        .filter_map(|a| {
            let d = Sha256::digest(format!("atlas-pca-conformance/pq-software/{a}/pq").as_bytes());
            family_of(a).map(|f| (base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d), f))
        })
        .collect()
}

fn keys_of(spec: &Value) -> (Option<&str>, Option<PqKeyPair>, Option<KeyPair>) {
    let alg = spec.get("alg").and_then(Value::as_str);
    let ed = spec.get("edSecret").and_then(Value::as_str).map(|s| KeyPair::from_seed_b64u(s).unwrap());
    let pq = spec.get("seed").and_then(Value::as_str).and_then(|s| {
        let family = seed_families().get(s).copied().or_else(|| alg.and_then(family_of))?;
        Some(PqKeyPair::from_seed(family, &common::b64d(s)).unwrap())
    });
    (alg, pq, ed)
}

fn attestor_json(t: &PqSoftwareAttestor) -> Value {
    let mut o = json!({"pqPublicKey": t.pq_public_key});
    if let Some(e) = &t.ed25519_public_key {
        o["ed25519PublicKey"] = json!(e);
    }
    o
}

fn verifier(config: &Value, evidence: &Value, seam: bool) -> Result<Arc<atlas_pca::attestation::HardwareVerifierFn>, String> {
    let ev = if evidence.is_null() { None } else { Some(evidence.clone()) };
    let resolve: Option<Arc<PqEvidenceFn>> = seam.then(|| Arc::new(move |_: &Value, _: &Value| Ok(ev.clone())) as Arc<PqEvidenceFn>);
    create_pq_software_verifier(config, resolve)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"PQ_ATTEST_DOMAIN": PQ_ATTEST_DOMAIN}),
        "attest" | "buildAttestor" => {
            let (alg, pq, ed) = keys_of(&a[0]);
            match create_pq_software_attestor(alg, pq, ed) {
                Err(e) => thrown(e),
                Ok(t) if f == "buildAttestor" => attestor_json(&t),
                Ok(t) => match t.attest(&a[1]) {
                    Ok(st) => {
                        let mut o = attestor_json(&t);
                        o["statement"] = st;
                        o
                    }
                    Err(e) => thrown(e),
                },
            }
        }
        "verifyPq" => {
            let sc = &a[0];
            let mut config = sc["config"].clone();
            let seam = config.as_object_mut().and_then(|c| c.remove("noEvidenceSeam")) != Some(json!(true));
            let v = match verifier(&config, &sc["evidence"], seam) {
                Ok(v) => v,
                Err(e) => return thrown(e),
            };
            let mut input = json!({"document": {}, "ctx": {}, "nowMs": sc["input"]["nowMs"]});
            if let Some(e) = sc["input"].get("expected").filter(|e| !e.is_null()) {
                input["expected"] = e.clone();
            }
            v(&input).unwrap_or_else(thrown)
        }
        "buildVerifier" => match verifier(&a[0], &Value::Null, true) {
            Ok(_) => json!({"built": true}),
            Err(e) => thrown(e),
        },
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn pq_software_replay() {
    let cases = common::ref_cases_seeded("attest-pq-software");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [("verifyPq", 90), ("attest", 29), ("buildAttestor", 9), ("buildVerifier", 8), ("constants", 1)]
        .iter()
        .map(|(k, n)| (k.to_string(), *n))
        .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 137);
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got)
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
