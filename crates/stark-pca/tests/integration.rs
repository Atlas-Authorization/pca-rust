//! Conformance tests for the PCA release-gate STARK.
//!
//! (1) a compliant witness proves + verifies OK;
//! (2) a non-compliant witness (r>budget, or predicate_match=0) cannot produce a
//!     verifying `allow` proof;
//! (3) a tampered proof / tampered public input is rejected.

use stark_pca::{prove_release, verify_release, PolicyParams, Witness};
use winterfell::Proof;

/// Attempt to prove, tolerating a debug-mode panic from Winterfell's trace validation.
/// Returns `Some(proof)` only if proving actually succeeded.
fn try_prove(w: &Witness, p: &PolicyParams) -> Option<Proof> {
    let w = w.clone();
    let p = p.clone();
    match std::panic::catch_unwind(move || prove_release(&w, &p)) {
        Ok(Ok(proof)) => Some(proof),
        _ => None,
    }
}

#[test]
fn compliant_witness_proves_and_verifies() {
    let policy = PolicyParams::default_policy();
    let witness = Witness::compliant();

    let proof = prove_release(&witness, &policy).expect("compliant witness must prove");
    // round-trip through bytes (as the fixtures are stored)
    let bytes = proof.to_bytes();
    let proof2 = Proof::from_bytes(&bytes).expect("proof must deserialize");

    verify_release(proof2, &policy).expect("compliant proof must verify as OK");
}

#[test]
fn non_compliant_risk_cannot_prove_allow() {
    // r > theta1 and B < kappa*r  → the tier & budget range gadgets are unsatisfiable.
    let policy = PolicyParams::default_policy();
    let witness = Witness::non_compliant_risk();

    // Suppress the expected debug-mode panic noise.
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = try_prove(&witness, &policy);
    let _ = std::panic::take_hook();

    match outcome {
        None => { /* proving correctly rejected the deny witness */ }
        Some(proof) => {
            // If a (necessarily invalid) proof was produced, it must fail verification.
            assert!(
                verify_release(proof, &policy).is_err(),
                "a deny witness must never yield a verifying allow proof"
            );
        }
    }
}

#[test]
fn non_compliant_predicate_cannot_prove_allow() {
    // predicate_match = 0  → allow = 0, but allow is asserted == 1.
    let policy = PolicyParams::default_policy();
    let witness = Witness::non_compliant_predicate();

    std::panic::set_hook(Box::new(|_| {}));
    let outcome = try_prove(&witness, &policy);
    let _ = std::panic::take_hook();

    match outcome {
        None => {}
        Some(proof) => {
            assert!(
                verify_release(proof, &policy).is_err(),
                "pm=0 must never yield a verifying allow proof"
            );
        }
    }
}

#[test]
fn committed_fixture_proof_verifies() {
    // The sample proof checked into fixtures/ must verify against the default policy.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return, // fixtures not present in this checkout; skip
    };
    let proof = Proof::from_bytes(&bytes).expect("fixture proof must deserialize");
    verify_release(proof, &PolicyParams::default_policy())
        .expect("committed fixture proof must verify as OK");
}

#[test]
fn tampered_proof_is_rejected() {
    let policy = PolicyParams::default_policy();
    let proof = prove_release(&Witness::compliant(), &policy).unwrap();
    let mut bytes = proof.to_bytes();

    // Flip a byte in the middle of the proof.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;

    match Proof::from_bytes(&bytes) {
        Err(_) => { /* corruption caught at deserialization */ }
        Ok(tampered) => {
            assert!(
                verify_release(tampered, &policy).is_err(),
                "a tampered proof must not verify"
            );
        }
    }
}

#[test]
fn tampered_public_input_is_rejected() {
    // A valid proof must not verify against different public inputs (commitment binding).
    let policy = PolicyParams::default_policy();
    let proof = prove_release(&Witness::compliant(), &policy).unwrap();

    let mut other = policy.clone();
    other.action_commitment = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into();

    assert!(
        verify_release(proof, &other).is_err(),
        "proof bound to one action_commitment must not verify under another"
    );
}

#[test]
fn tampered_policy_weight_is_rejected() {
    // Changing a public weight changes the AIR's r_raw definition → proof must not verify.
    let policy = PolicyParams::default_policy();
    let proof = prove_release(&Witness::compliant(), &policy).unwrap();

    let mut other = policy.clone();
    other.weights[0] += 1;

    assert!(
        verify_release(proof, &other).is_err(),
        "proof must not verify under a different risk weight"
    );
}
