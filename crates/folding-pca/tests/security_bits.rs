//! Concrete security level of the folding construction, asserted against stated floors.
//!
//! Arithmetic (also written out in `docs/pca/security/audit-proof-systems.md`). Nova has no FRI-style query
//! parameter, so there is no "queries x blow-up" term; its soundness rests on
//!
//! * the discrete-log hardness of the Pallas/Vesta cycle (the commitments and the IPA are Pedersen/IPA over
//!   these curves): the group orders are ~2^254, so Pollard's rho costs about sqrt(pi*q/4) = 2^(254/2 - 0.17)
//!   = ~2^126.8 group operations;
//! * the Schwartz-Zippel / Fiat-Shamir error of the folding and Spartan sum-checks, each bounded by
//!   (degree x rounds) / |F| with |F| ~ 2^254, i.e. well below 2^-200 (negligible against the other terms);
//! * the Poseidon chain hash (t = 3, quintic S-box, 255-bit field): collision resistance is bounded by the
//!   capacity, here one 255-bit element, i.e. ~2^127.5 against generic birthday attacks, and the round
//!   numbers must clear the Poseidon-paper bounds for M = 128.
//!
//! Security level asserted = min(group, hash) >= 120 bits, in the random-oracle model, classical adversary.
//! The scheme is NOT post-quantum (Shor breaks the discrete log), which the test also pins as a fact.

use ff::PrimeField;
use pca_folding_ivc::Scalar;

fn modulus_bits() -> u32 {
    // Scalar::NUM_BITS is the bit length of the modulus
    Scalar::NUM_BITS
}

#[test]
fn group_and_hash_security_meet_the_stated_floors() {
    let n = modulus_bits() as f64;
    assert_eq!(Scalar::NUM_BITS, 255);
    // the modulus is 2^254 + small: log2 is 254 + epsilon
    let log2_q = 254.0;
    let rho = log2_q / 2.0 + (std::f64::consts::PI / 4.0).sqrt().log2();
    eprintln!("folding: modulus {n} bits; Pollard-rho on the cycle ~ 2^{rho:.2}");
    assert!(rho >= 126.0, "group security {rho}");

    // Poseidon: field 255 bits, t = 3, alpha = 5, M = 128. Round numbers come from the independent
    // reference's fixture, which `poseidon_crosscheck.rs` ties to the implementation's output.
    let fx: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/poseidon_crosscheck.json")).unwrap(),
    )
    .unwrap();
    let (t, alpha) = (fx["t"].as_u64().unwrap(), fx["alpha"].as_u64().unwrap());
    let (rf, rp) = (fx["full_rounds"].as_u64().unwrap(), fx["partial_rounds"].as_u64().unwrap());
    assert_eq!((t, alpha, rf, rp), (3, 5, 8, 55));
    let m = 128.0f64;
    let log_alpha_2 = 2f64.ln() / (alpha as f64).ln();
    // Poseidon paper, Sec. 5.5.1: statistical bound R_F >= 6 (alpha = 5, M <= (n - C)(t + 1) with C = 2)
    assert!(m <= (n - 2.0) * (t as f64 + 1.0));
    assert!(rf >= 6, "full rounds below the statistical bound");
    // interpolation bound: R_F + R_P > ceil(log_alpha(2) * min(M, n)) + ceil(log_alpha(t))
    let interp = (log_alpha_2 * m).ceil() + ((t as f64).ln() / (alpha as f64).ln()).ceil();
    eprintln!("poseidon: R_F + R_P = {} against interpolation bound {interp}", rf + rp);
    assert!((rf + rp) as f64 > interp, "round numbers below the interpolation bound");
    // generic collision bound from the capacity (one 255-bit element)
    let collision = (n - 1.0) / 2.0 * 1.0;
    assert!(collision >= 127.0 && collision.min(rho) >= 120.0, "min(group, hash) = {}", collision.min(rho));
}

#[test]
fn the_scheme_is_not_post_quantum_and_says_so() {
    // A fact pinned as a test so a README edit cannot silently claim otherwise: the commitments are
    // discrete-log based. The README and the crate docs state the same.
    let readme = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    assert!(readme.contains("not post-quantum"), "README must keep the not-post-quantum statement");
}
