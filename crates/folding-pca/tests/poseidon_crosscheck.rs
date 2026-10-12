//! Cross-checks the in-library chain hash against an independent Python Poseidon (HADES)
//! implementation (`tools/poseidon_reference.py`), which is itself validated against the published
//! IAIK hadeshash test vectors. See fixtures/poseidon_crosscheck.json for provenance.

use ff::PrimeField;
use pca_folding_ivc::{hash2_native, Scalar};
use std::path::PathBuf;

fn hex_to_scalar(s: &str) -> Scalar {
    let h = s.strip_prefix("0x").expect("0x prefix");
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    let mut be: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    be.reverse();
    be.resize(32, 0);
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&be);
    Option::<Scalar>::from(Scalar::from_repr(repr)).expect("canonical field element")
}

fn doc() -> serde_json::Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/poseidon_crosscheck.json");
    serde_json::from_slice(&std::fs::read(p).expect("fixture")).expect("json")
}

#[test]
fn field_modulus_matches_the_reference_field() {
    let d = doc();
    let want = d["field_modulus_hex"].as_str().unwrap().trim_start_matches("0x").to_string();
    let got = Scalar::MODULUS.trim_start_matches("0x").to_string();
    assert_eq!(got, want);
}

#[test]
fn chain_hash_equals_independent_reference_on_all_vectors() {
    let d = doc();
    let vs = d["vectors"].as_array().unwrap();
    assert!(vs.len() >= 32);
    for v in vs {
        let l = hex_to_scalar(v["left"].as_str().unwrap());
        let r = hex_to_scalar(v["right"].as_str().unwrap());
        let want = hex_to_scalar(v["hash"].as_str().unwrap());
        assert_eq!(hash2_native(l, r), want, "mismatch for left={} right={}", v["left"], v["right"]);
    }
}

#[test]
fn reference_vectors_are_not_degenerate() {
    let d = doc();
    let vs = d["vectors"].as_array().unwrap();
    let mut hs: Vec<&str> = vs.iter().map(|v| v["hash"].as_str().unwrap()).collect();
    hs.sort();
    hs.dedup();
    assert_eq!(hs.len(), vs.len(), "all outputs distinct");
    // order sensitivity
    let a = hash2_native(Scalar::from(1u64), Scalar::from(2u64));
    let b = hash2_native(Scalar::from(2u64), Scalar::from(1u64));
    assert_ne!(a, b);
}
