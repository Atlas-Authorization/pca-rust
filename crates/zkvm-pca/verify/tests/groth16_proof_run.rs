//! Verifier-side tests for the Groth16 receipt of the H100 proving run (verification only: no guest toolchain,
//! no proving, no GPU, no docker). The receipt was produced by `host/src/bin/prove_run.rs`; provenance (RISC Zero
//! version, image id, hosts, date, sha256 of every artifact) is in `fixtures/proof_run/PROVENANCE.json`.
//!
//! Also re-derives the on-chain-style verifier equation directly with arkworks (no RISC Zero verifier code) and
//! checks it agrees with the RISC Zero verifier on the genuine receipt and on every single-bit seal mutation.

use pca_zkvm_core::Decision;
use risc0_zkvm::sha::{Digest, Digestible, Impl, Sha256};
use risc0_zkvm::{Groth16ReceiptVerifierParameters, InnerReceipt, Receipt};
use serde_json::Value;
use std::collections::BTreeMap;

fn run_fx(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/proof_run").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn image_id() -> Digest {
    let v: Value = serde_json::from_slice(&run_fx("image_id.json")).unwrap();
    let w = v["image_id_words"].as_array().unwrap();
    Digest::from(core::array::from_fn::<u32, 8, _>(|i| w[i].as_u64().unwrap() as u32))
}

fn groth16() -> Receipt {
    bincode::deserialize(&run_fx("receipt_groth16.bin")).expect("committed groth16 receipt decodes")
}

fn succinct() -> Receipt {
    bincode::deserialize(&run_fx("receipt_succinct.bin")).expect("committed succinct receipt decodes")
}

fn kind<E: std::fmt::Display>(e: &E) -> String {
    e.to_string()
        .split_whitespace()
        .filter(|t| !(t.len() >= 32 && t.trim_end_matches(';').chars().all(|c| c.is_ascii_hexdigit())))
        .collect::<Vec<_>>()
        .join(" ")
}

fn seal_of(r: &mut Receipt) -> &mut Vec<u8> {
    match &mut r.inner {
        InnerReceipt::Groth16(g) => &mut g.seal,
        _ => panic!("groth16 receipt expected"),
    }
}

fn seal_len(r: &Receipt) -> usize {
    match &r.inner {
        InnerReceipt::Groth16(g) => g.seal.len(),
        _ => 0,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn provenance_artifact_hashes_match_the_files() {
    use sha2::{Digest as _, Sha256 as S};
    let p: Value = serde_json::from_slice(&run_fx("PROVENANCE.json")).unwrap();
    for (name, want) in p["artifacts_sha256"].as_object().unwrap() {
        let got = hex(&S::digest(run_fx(name)));
        assert_eq!(&got, want.as_str().unwrap(), "{name}");
    }
    assert_eq!(p["image_id_hex"], serde_json::from_slice::<Value>(&run_fx("image_id.json")).unwrap()["image_id_hex"]);
}

#[test]
fn groth16_receipt_verifies_against_the_committed_image_id() {
    let r = groth16();
    assert!(matches!(r.inner, InnerReceipt::Groth16(_)));
    r.verify(image_id()).expect("committed groth16 receipt must verify");
    // constant-size seal: 2 G1 points + 1 G2 point = 64 + 128 + 64 bytes
    assert_eq!(seal_len(&r), 256);
}

#[test]
fn groth16_and_succinct_receipts_make_the_same_statement() {
    let (g, s) = (groth16(), succinct());
    assert_eq!(g.journal.bytes, s.journal.bytes);
    assert_eq!(g.claim().unwrap().digest(), s.claim().unwrap().digest());
    s.verify(image_id()).expect("committed succinct receipt of the same run verifies");
    let d: Decision = g.journal.decode().unwrap();
    assert_eq!((d.allow, d.tier, d.chain_verified), (1, 1, 1));
    let want: Value = serde_json::from_slice(&run_fx("journal.json")).unwrap();
    assert_eq!(serde_json::to_value(&d).unwrap(), want);
    // and equals what the pure decision logic computes from the committed input
    let input = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/decide_input.sample.json"),
    )
    .unwrap();
    assert_eq!(pca_zkvm_core::decide_from_str(&input), d);
}

#[test]
fn verifier_parameters_are_the_published_default() {
    let r = groth16();
    let InnerReceipt::Groth16(g) = &r.inner else { panic!() };
    assert_eq!(g.verifier_parameters, Groth16ReceiptVerifierParameters::default().digest());
    // pinned in risc0-zkvm's own test-suite: the digest of the default parameters
    assert_eq!(
        hex(g.verifier_parameters.as_bytes()),
        "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc"
    );
}

#[test]
fn wrong_image_id_is_rejected_with_a_claim_mismatch() {
    let r = groth16();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for word in 0..8 {
        for bit in [0u32, 7, 31] {
            let mut w: [u32; 8] = image_id().into();
            w[word] ^= 1 << bit;
            let e = r.verify(Digest::from(w)).expect_err("wrong image id must be rejected");
            *seen.entry(kind(&e)).or_default() += 1;
        }
    }
    eprintln!("wrong image id: {seen:?}");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen.keys().next().unwrap().contains("claim digest does not match"), "{seen:?}");
}

#[test]
fn mutated_or_resized_journal_is_rejected_with_a_claim_mismatch() {
    let r = groth16();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for i in 0..r.journal.bytes.len() {
        let mut t = r.clone();
        t.journal.bytes[i] ^= 0x01;
        *seen.entry(kind(&t.verify(image_id()).expect_err("mutated journal"))).or_default() += 1;
    }
    let mut t = r.clone();
    t.journal.bytes.push(0);
    *seen.entry(kind(&t.verify(image_id()).expect_err("extended"))).or_default() += 1;
    let mut t = r.clone();
    t.journal.bytes.pop();
    *seen.entry(kind(&t.verify(image_id()).expect_err("truncated"))).or_default() += 1;
    let mut t = r.clone();
    t.journal.bytes.clear();
    *seen.entry(kind(&t.verify(image_id()).expect_err("empty"))).or_default() += 1;
    eprintln!("journal mutations: {seen:?}");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen.keys().next().unwrap().contains("claim digest does not match"), "{seen:?}");
}

/// Positions where the RISC Zero Rust verifier (arkworks `deserialize_uncompressed`) IGNORES the flag bits that
/// share the most significant byte of each curve point's y coordinate: flipping bit 7 of byte 32 (A.y),
/// byte 128 (B.y) or byte 224 (C.y) yields a different byte string for the SAME points, which still verifies.
/// This is seal malleability, not unsoundness (the statement and the points are unchanged): never use a hash
/// of the seal as a unique receipt identifier. A canonical (EVM-precompile style) decoder rejects them; see
/// `independent_onchain_style_verification_agrees_with_risc0`.
const FLAG_BIT_POSITIONS: [(usize, u8); 3] = [(32, 7), (128, 7), (224, 7)];

#[test]
fn every_single_bit_flip_of_the_seal_is_rejected_except_ignored_encoding_flags() {
    let r = groth16();
    assert_eq!(seal_len(&r), 256);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut accepted = Vec::new();
    for byte in 0..256 {
        for bit in 0..8u8 {
            let mut t = r.clone();
            seal_of(&mut t)[byte] ^= 1 << bit;
            match t.verify(image_id()) {
                Ok(()) => accepted.push((byte, bit)),
                Err(e) => *seen.entry(kind(&e)).or_default() += 1,
            }
        }
    }
    eprintln!("seal bit flips (2048): rejected {seen:?}; accepted {accepted:?}");
    assert_eq!(accepted, FLAG_BIT_POSITIONS.to_vec(), "only the ignored flag bits may still verify");
    for k in seen.keys() {
        assert!(
            k.contains("invalid receipt format") || k.contains("proof is invalid"),
            "unexpected rejection reason: {k}"
        );
    }
    assert_eq!(seen.values().sum::<usize>(), 2048 - 3);
}

#[test]
fn resized_seal_is_a_format_error() {
    let r = groth16();
    for resize in [|s: &mut Vec<u8>| s.push(0), |s: &mut Vec<u8>| { s.pop(); }, |s: &mut Vec<u8>| s.clear()] {
        let mut t = r.clone();
        resize(seal_of(&mut t));
        let e = t.verify(image_id()).expect_err("resized seal");
        assert!(kind(&e).contains("invalid receipt format"), "{e}");
    }
}

#[test]
fn mutated_verifier_parameters_and_zero_seal_are_rejected() {
    let r = groth16();
    let mut t = r.clone();
    if let InnerReceipt::Groth16(g) = &mut t.inner {
        let mut w: [u32; 8] = g.verifier_parameters.into();
        w[3] ^= 1;
        g.verifier_parameters = Digest::from(w);
    }
    let e = t.verify(image_id()).expect_err("mutated verifier parameters");
    // RISC Zero reports a verifier-parameters mismatch with the generic receipt-format message
    assert_eq!(e.to_string(), "invalid receipt format");
    let mut t = r.clone();
    *seal_of(&mut t) = vec![0u8; 256];
    assert!(t.verify(image_id()).is_err(), "all-zero seal");
}

#[test]
fn groth16_receipt_serialization_flips_are_rejected() {
    let good = run_fx("receipt_groth16.bin");
    let orig = groth16();
    let (mut dec, mut ver) = (0, 0);
    for off in 0..good.len() {
        let mut b = good.clone();
        b[off] ^= 0x01;
        match bincode::deserialize::<Receipt>(&b) {
            Err(_) => dec += 1,
            Ok(rc) => match rc.verify(image_id()) {
                Err(_) => ver += 1,
                Ok(()) => assert_eq!(rc.journal.bytes, orig.journal.bytes, "accepted mutation changed the journal at {off}"),
            },
        }
    }
    eprintln!("groth16 receipt byte flips: {dec} rejected at decode, {ver} at verify (of {})", good.len());
    assert!(dec + ver > good.len() * 9 / 10);
}

// ---------------------------------------------------------------------------------------------------------
// Independent re-derivation of the on-chain verifier equation (RiscZeroGroth16Verifier.sol semantics) with
// arkworks directly. Public inputs: control root halves, claim digest halves, BN254 control id. The check is
//   e(A, B) = e(alpha, beta) * e(IC0 + sum(x_i * IC_i), gamma) * e(C, delta)
// with canonical field-element decoding (coordinates must be < p, points on-curve and in the subgroup).
// It does not call the RISC Zero verifier.
// ---------------------------------------------------------------------------------------------------------
mod onchain_style {
    use super::*;
    use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::VerifyingKey;
    use ark_serialize::CanonicalDeserialize;

    fn fq(b: &[u8]) -> Option<Fq> {
        let x = Fq::from_be_bytes_mod_order(b);
        // reject non-canonical (>= p) encodings like the EVM precompile does
        (x.into_bigint().to_bytes_be() == b).then_some(x)
    }

    fn g1(b: &[u8]) -> Option<G1Affine> {
        let p = G1Affine::new_unchecked(fq(&b[..32])?, fq(&b[32..64])?);
        (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
    }

    // Solidity layout: b = [[x_im, x_re], [y_im, y_re]]
    fn g2(b: &[u8]) -> Option<G2Affine> {
        let x = Fq2::new(fq(&b[32..64])?, fq(&b[0..32])?);
        let y = Fq2::new(fq(&b[96..128])?, fq(&b[64..96])?);
        let p = G2Affine::new_unchecked(x, y);
        (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
    }

    /// Solidity `splitDigest`: reverse the 32 bytes, low 128 bits first.
    fn split(d: &[u8]) -> (Fr, Fr) {
        let rev: Vec<u8> = d.iter().rev().cloned().collect();
        (Fr::from_be_bytes_mod_order(&rev[16..]), Fr::from_be_bytes_mod_order(&rev[..16]))
    }

    fn vk() -> VerifyingKey<Bn254> {
        // the default RISC Zero Groth16 verifying key, via its serde impl (len-prefixed arkworks bytes)
        let bytes = bincode::serialize(&risc0_groth16::verifying_key()).unwrap();
        VerifyingKey::<Bn254>::deserialize_uncompressed(&bytes[8..]).unwrap()
    }

    /// true iff the seal verifies for (default control root, claim_digest, default bn254 control id)
    pub fn verify(seal: &[u8], claim_digest: &[u8]) -> bool {
        if seal.len() != 256 {
            return false;
        }
        let (Some(a), Some(b), Some(c)) = (g1(&seal[..64]), g2(&seal[64..192]), g1(&seal[192..])) else { return false };
        let params = Groth16ReceiptVerifierParameters::default();
        let (r0, r1) = split(params.control_root.as_bytes());
        let (c0, c1) = split(claim_digest);
        let id_rev: Vec<u8> = params.bn254_control_id.as_bytes().iter().rev().cloned().collect();
        let id = Fr::from_be_bytes_mod_order(&id_rev);
        let vk = vk();
        let inputs = [r0, r1, c0, c1, id];
        let mut acc = vk.gamma_abc_g1[0].into_group();
        for (i, x) in inputs.iter().enumerate() {
            acc += vk.gamma_abc_g1[i + 1] * x;
        }
        let lhs = Bn254::pairing(a, b);
        let rhs = Bn254::multi_pairing([vk.alpha_g1, acc.into_affine(), c], [vk.beta_g2, vk.gamma_g2, vk.delta_g2]);
        lhs == rhs
    }
}

#[test]
fn independent_onchain_style_verification_agrees_with_risc0() {
    let r = groth16();
    let claim = r.claim().unwrap().digest();
    let InnerReceipt::Groth16(g) = &r.inner else { panic!() };
    assert!(onchain_style::verify(&g.seal, claim.as_bytes()), "genuine receipt must satisfy the pairing equation");
    // the claim digest of a different statement (flipped word) must not satisfy it
    let mut w: [u32; 8] = claim.into();
    w[0] ^= 1;
    assert!(!onchain_style::verify(&g.seal, Digest::from(w).as_bytes()));
    // every single-bit seal flip: the independent canonical check must reject ALL 2048; the RISC Zero verifier
    // agrees on all but the three ignored encoding-flag bits (where it is more permissive).
    let mut agree = 0;
    let mut risc0_more_permissive = Vec::new();
    for byte in 0..256 {
        for bit in 0..8u8 {
            let mut s = g.seal.clone();
            s[byte] ^= 1 << bit;
            let ours = onchain_style::verify(&s, claim.as_bytes());
            let mut t = r.clone();
            *seal_of(&mut t) = s;
            let theirs = t.verify(image_id()).is_ok();
            assert!(!ours, "canonical check accepted a mutated seal at byte {byte} bit {bit}");
            if theirs {
                risc0_more_permissive.push((byte, bit));
            } else {
                agree += 1;
            }
        }
    }
    assert_eq!(risc0_more_permissive, FLAG_BIT_POSITIONS.to_vec());
    eprintln!("independent check agreed on {agree}/2048 mutated seals; RISC Zero more permissive at {risc0_more_permissive:?}");
    let _ = Impl::hash_bytes(&[]); // keep the Sha256 trait import used
}
