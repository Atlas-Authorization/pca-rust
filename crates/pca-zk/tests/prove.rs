//! prove -> verify round trips. They need circom build outputs, so each test skips unless its inputs exist (PCA_ZK_REQUIRE=1 makes a
//! missing input a failure, as CI sets):
//!   policyvm: PCA_ZK_ZKEY / PCA_ZK_WASM, default packages/pca/circuits/build/{policyvm_final.zkey,policyvm_js/policyvm.wasm}
//!             (gitignored outputs of packages/pca/circuits/policyvm.setup.sh)
//!   mul:      PCA_ZK_MUL_DIR holding mul.wasm and mul_{bn254,bls12381}.zkey / _vkey.json (tests/circuits/mul.circom, built by CI)
use pca_zk::{prove, verify, Curve};
use serde_json::Value;
use std::path::PathBuf;

fn need(p: &PathBuf) -> bool {
    if p.exists() {
        return true;
    }
    assert!(std::env::var("PCA_ZK_REQUIRE").is_err(), "{} is missing", p.display());
    eprintln!("skipped: {} is missing", p.display());
    false
}

fn circuits() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../pca/circuits")
}

fn check(curve: Curve, wasm: &PathBuf, zkey: &PathBuf, vkey: &PathBuf, input: &PathBuf) -> Value {
    let (w, z, i) = (
        std::fs::read(wasm).unwrap(),
        std::fs::read(zkey).unwrap(),
        std::fs::read(input).unwrap(),
    );
    let out = prove(curve, &w, &z, &i, Some([7u8; 32])).unwrap_or_else(|e| panic!("prove failed: {e:?}"));
    // the same seed gives the same proof, a different one a different proof
    assert_eq!(out, prove(curve, &w, &z, &i, Some([7u8; 32])).unwrap());
    assert_ne!(out, prove(curve, &w, &z, &i, Some([8u8; 32])).unwrap());
    let v: Value = serde_json::from_str(&out).unwrap();
    let vk = std::fs::read(vkey).unwrap();
    let (pr, sg) = (
        serde_json::to_vec(&v["proof"]).unwrap(),
        serde_json::to_vec(&v["publicSignals"]).unwrap(),
    );
    verify(curve, 0, &vk, &pr, &sg).expect("strict verify of our proof");
    // a changed public signal must not verify
    let mut bad = v["publicSignals"].clone();
    bad[0] = Value::String("1".into());
    assert!(verify(curve, 0, &vk, &pr, &serde_json::to_vec(&bad).unwrap()).is_err());
    v
}

#[test]
fn policyvm_bn254_round_trip() {
    let c = circuits();
    let zkey = std::env::var("PCA_ZK_ZKEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| c.join("build/policyvm_final.zkey"));
    let wasm = std::env::var("PCA_ZK_WASM")
        .map(PathBuf::from)
        .unwrap_or_else(|_| c.join("build/policyvm_js/policyvm.wasm"));
    if !need(&zkey) || !need(&wasm) {
        return;
    }
    let v = check(
        Curve::Bn254,
        &wasm,
        &zkey,
        &c.join("policyvm_vkey.json"),
        &c.join("policyvm_sample_input.json"),
    );
    let sample: Value = serde_json::from_slice(&std::fs::read(c.join("policyvm_sample_proof.json")).unwrap()).unwrap();
    assert_eq!(v["publicSignals"], sample["publicSignals"], "public signals of the sample input");
}

#[test]
fn mul_round_trip_both_curves() {
    let Ok(dir) = std::env::var("PCA_ZK_MUL_DIR").map(PathBuf::from) else {
        assert!(std::env::var("PCA_ZK_REQUIRE").is_err(), "PCA_ZK_MUL_DIR is not set");
        eprintln!("skipped: PCA_ZK_MUL_DIR is not set");
        return;
    };
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/circuits/mul.input.json");
    for (curve, tag) in [(Curve::Bn254, "bn254"), (Curve::Bls12381, "bls12381")] {
        let v = check(
            curve,
            &dir.join(format!("mul_{tag}.wasm")),
            &dir.join(format!("mul_{tag}.zkey")),
            &dir.join(format!("mul_{tag}_vkey.json")),
            &input,
        );
        assert_eq!(v["publicSignals"], serde_json::json!(["33", "11"]), "{tag}");
    }
}
