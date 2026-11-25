//! Feature `fhe-seal`: BFV on Microsoft SEAL. The corpus replay needs the node-seal corpus (generated in CI, never committed; the
//! path comes from PCA_FHE_SEAL_CORPUS): the native evaluation of the reference's ciphertexts must equal the reference's results byte
//! for byte once both are re-saved uncompressed. The round-trip tests need only libsealc.
#![cfg(feature = "fhe-seal")]

use atlas_pca::fhe_seal::*;
use serde_json::Value;
use std::sync::OnceLock;

fn i64s(v: &Value) -> Vec<i64> {
    v.as_array().expect("array").iter().map(|x| x.as_i64().expect("integer")).collect()
}

fn policy_of(v: &Value) -> Policy {
    Policy {
        scale: v["scale"].as_i64().expect("scale"),
        dim: v["dim"].as_i64().expect("dim"),
        weights_scaled: i64s(&v["weightsScaled"]),
        kappa_weights_scaled: i64s(&v["kappaWeightsScaled"]),
        budget_scaled: v["budgetScaled"].as_i64().expect("budgetScaled"),
        kappa: v["kappa"].as_f64().expect("kappa"),
    }
}

#[test]
fn evaluates_the_reference_ciphertexts_to_the_reference_results() {
    let Some(path) = std::env::var_os("PCA_FHE_SEAL_CORPUS") else {
        eprintln!("PCA_FHE_SEAL_CORPUS is not set: skipping the node-seal corpus replay (CI generates the corpus)");
        return;
    };
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "gzip failed on the corpus");
    let c: Value = serde_json::from_slice(&o.stdout).expect("corpus json");
    assert_eq!(c["seal"]["polyModulusDegree"].as_u64(), Some(POLY_MODULUS_DEGREE));
    assert_eq!(c["seal"]["plainModulus"].as_u64(), Some(PLAIN_MODULUS));
    let cases = c["cases"].as_array().expect("cases");
    assert!(cases.len() >= 6, "expected at least 6 cases, got {}", cases.len());
    let s = |k: &str| c[k].as_str().expect("key").to_string();
    let keys = EvalKeys { public_key: s("publicKey"), relin_keys: s("relinKeys"), galois_keys: s("galoisKeys") };
    for cs in cases {
        let name = cs["name"].as_str().unwrap_or("?");
        let gate = eval_risk_gate(&keys, cs["encInputs"].as_str().expect("encInputs"), &policy_of(&cs["policy"])).unwrap_or_else(|e| panic!("{name}: {e}"));
        for (want, got) in [(cs["encRiskRaw"].as_str().expect("encRiskRaw"), &gate.enc_risk_raw), (cs["encSlack"].as_str().expect("encSlack"), &gate.enc_slack)]
        {
            let w = canonical_cipher(want).unwrap_or_else(|e| panic!("{name}: canonical: {e}"));
            let g = canonical_cipher(got).unwrap_or_else(|e| panic!("{name}: canonical: {e}"));
            assert!(w == g, "{name}: evaluated ciphertext differs from the reference");
        }
    }
}

fn make_policy(kappa: f64, budget: f64) -> Policy {
    let w = [0.25, 0.2, 0.2, 0.2, 0.1, 0.05];
    Policy {
        scale: 1000,
        dim: 6,
        weights_scaled: w.iter().map(|v| (v * 1000.0 + 0.5) as i64).collect(),
        kappa_weights_scaled: w.iter().map(|v| (kappa * v * 1000.0 + 0.5) as i64).collect(),
        budget_scaled: (budget * 1e6 + 0.5) as i64,
        kappa,
    }
}

/// Two key sets, generated once (a full Galois key set is slow to make).
fn keys() -> &'static (Keyset, Keyset) {
    static K: OnceLock<(Keyset, Keyset)> = OnceLock::new();
    K.get_or_init(|| (keygen().expect("keygen a"), keygen().expect("keygen b")))
}

fn eval_keys(k: &Keyset) -> EvalKeys {
    EvalKeys { public_key: k.public_key.clone(), relin_keys: k.relin_keys.clone(), galois_keys: k.galois_keys.clone() }
}

#[test]
fn native_round_trip_matches_plaintext_arithmetic() {
    let k = &keys().0;
    for (x, kappa, budget) in [([100, 900, 100, 100, 100, 100], 1.0, 0.6), ([1000; 6], 1.0, 0.5), ([0; 6], 1.5, 0.25)] {
        let p = make_policy(kappa, budget);
        let enc = encrypt_risk_inputs(&k.public_key, &x).expect("encrypt");
        let gate = eval_risk_gate(&eval_keys(k), &enc, &p).expect("eval");
        let v = decrypt_verdict(&k.secret_key, &gate.enc_risk_raw, &gate.enc_slack, &p).expect("decrypt");
        let raw: i64 = x.iter().zip(&p.weights_scaled).map(|(a, b)| a * b).sum();
        let kr: i64 = x.iter().zip(&p.kappa_weights_scaled).map(|(a, b)| a * b).sum();
        assert_eq!((v.r_scaled, v.slack, v.admit), (raw, p.budget_scaled - kr, p.budget_scaled - kr >= 0));
    }
}

#[test]
fn all_zero_weights_evaluate_to_zero() {
    let k = &keys().0;
    let p = Policy { scale: 1000, dim: 6, weights_scaled: vec![0; 6], kappa_weights_scaled: vec![0; 6], budget_scaled: 5000, kappa: 1.0 };
    let enc = encrypt_risk_inputs(&k.public_key, &[5; 6]).expect("encrypt");
    let gate = eval_risk_gate(&eval_keys(k), &enc, &p).expect("eval");
    let v = decrypt_verdict(&k.secret_key, &gate.enc_risk_raw, &gate.enc_slack, &p).expect("decrypt");
    assert_eq!(v, Verdict { r_scaled: 0, slack: 5000, admit: true });
}

#[test]
fn wrong_key_fails_closed() {
    let (a, b) = keys();
    let p = make_policy(1.0, 0.6);
    let enc = encrypt_risk_inputs(&a.public_key, &[1, 2, 3, 4, 5, 6]).expect("encrypt");
    let gate = eval_risk_gate(&eval_keys(a), &enc, &p).expect("eval");
    let e = decrypt_verdict(&b.secret_key, &gate.enc_risk_raw, &gate.enc_slack, &p).expect_err("must refuse");
    assert!(e.contains("noise budget"), "{e}");
}

#[test]
fn malformed_blobs_and_policies_are_refused() {
    let k = &keys().0;
    let good = encrypt_risk_inputs(&k.public_key, &[1, 2, 3, 4, 5, 6]).expect("encrypt");
    let zeros = "A".repeat(64);
    for (name, blob) in [("truncated", good[..good.len() - 8].to_string()), ("padded", format!("{good}AAAA")), ("short", "AAAA".to_string()), ("zeros", zeros)]
    {
        assert!(assert_seal_blob(&blob, name).is_err(), "{name}: accepted");
    }
    assert!(assert_seal_blob(&good, "good").is_ok());
    let base = Policy { scale: 1000, dim: 6, weights_scaled: vec![0; 6], kappa_weights_scaled: vec![0; 6], budget_scaled: 0, kappa: 1.0 };
    let bad = [
        Policy { dim: 5, ..base.clone() },
        Policy { budget_scaled: SIGNED_BOUND, ..base.clone() },
        Policy { scale: 0, ..base.clone() },
        Policy { weights_scaled: vec![0; 5], ..base.clone() },
    ];
    for (i, p) in bad.iter().enumerate() {
        assert!(require_policy(p).is_err(), "policy {i} accepted");
    }
    assert!(require_policy(&base).is_ok());
    assert!(encrypt_risk_inputs("x", &[-1, 0, 0, 0, 0, 0]).is_err(), "negative input accepted");
    assert!(encrypt_risk_inputs(&k.public_key, &[1, 2]).is_err(), "short input accepted");
}
