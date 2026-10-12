//! Concrete security level of the pinned proof options, asserted against stated floors.
//!
//! The arithmetic (also written out in `docs/pca/security/audit-proof-systems.md`):
//!
//! * base field `f128`: modulus 2^128 - 45*2^40 + 1, so 128 bits; no field extension => the
//!   challenge field is the base field => 128 bits of field security.
//! * FRI: blowup 8 => 3 bits per query (conjectured, ethSTARK Conjecture 1); 37 queries => 111 bits.
//! * grinding: 0 bits are configured, and Winterfell credits grinding only when the query security is
//!   already >= 80 bits.
//! * hash: Blake3-256 => 128-bit collision resistance.
//! * conjectured level = min( min(field, query) - 1, collision ) = min(min(128, 111) - 1, 128) = 110.
//!
//! The *proven* level (Theorems 2 and 3 of ePrint 2024/1553, list-decoding and unique-decoding
//! regimes) is lower; it is computed by Winterfell from the same options and asserted below so a
//! change of options cannot lower it unnoticed.

mod common;
use common::*;
use stark_pca::{proof_options, prove_release, verify_release, PolicyParams, Witness, MIN_SECURITY_BITS};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::{fields::f128::BaseElement, StarkField};

/// Floors asserted by this test. Conjectured: the verifier's own acceptance floor. Proven: the value
/// measured at audit time; the test fails if a change makes it smaller.
const CONJECTURED_FLOOR: u32 = 100;
const PROVEN_LDR_FLOOR: u32 = 54;
const PROVEN_UDR_FLOOR: u32 = 30;

#[test]
fn pinned_options_meet_the_stated_floors() {
    let o = proof_options();
    let field_bits = BaseElement::MODULUS.ilog2() + 1;
    assert_eq!(field_bits, 128);
    assert_eq!(o.field_extension().degree(), 1, "no extension: challenge field = base field");
    let per_query = o.blowup_factor().ilog2();
    assert_eq!((o.num_queries(), o.blowup_factor(), o.grinding_factor()), (37, 8, 0));
    let query_security = per_query * o.num_queries() as u32;
    assert_eq!(query_security, 111);
    let conjectured_by_hand = std::cmp::min(std::cmp::min(field_bits, query_security) - 1, 128);
    assert_eq!(conjectured_by_hand, 110);

    let proof = prove_release(&Witness::compliant(), &PolicyParams::default_policy()).unwrap();
    let c = proof.conjectured_security::<Blake3_256<BaseElement>>().bits();
    let p = proof.proven_security::<Blake3_256<BaseElement>>();
    eprintln!("stark-pca (Winterfell): conjectured {c} bits, proven list-decoding {} bits, proven unique-decoding {} bits", p.ldr_bits(), p.udr_bits());
    assert_eq!(c, conjectured_by_hand, "library's conjectured level must match the hand computation");
    assert!(c >= CONJECTURED_FLOOR && MIN_SECURITY_BITS <= c);
    assert!(p.ldr_bits() >= PROVEN_LDR_FLOOR, "proven (list decoding) fell to {}", p.ldr_bits());
    assert!(p.udr_bits() >= PROVEN_UDR_FLOOR, "proven (unique decoding) fell to {}", p.udr_bits());
}

#[test]
fn verifier_rejects_valid_proofs_made_with_weaker_options() {
    // A proof generated with fewer queries / smaller blowup / smaller FRI folding is a perfectly valid
    // STARK for the AIR, but the verifier pins the exact options, so none of them is accepted.
    use winterfell::{BatchingMethod, FieldExtension, ProofOptions};
    let mut policy = PolicyParams::default_policy();
    let cols = build_cols(&Row0::compliant(), &policy);
    commit_to_trace(&cols, &mut policy);
    let lin = BatchingMethod::Linear;
    let weaker = [
        ("32 queries (the previous pinned count, 95 bits)", ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31, lin, lin)),
        ("blowup 4", ProofOptions::new(37, 4, 0, FieldExtension::None, 8, 31, lin, lin)),
        ("FRI folding 4", ProofOptions::new(37, 8, 0, FieldExtension::None, 4, 31, lin, lin)),
        ("FRI remainder 15", ProofOptions::new(37, 8, 0, FieldExtension::None, 8, 15, lin, lin)),
    ];
    for (name, o) in weaker {
        assert_ne!(o, proof_options());
        let proof = prove_cols_with_options(&cols, &policy, o).unwrap_or_else(|| panic!("{name}: weaker proof should exist"));
        let bits = proof.conjectured_security::<Blake3_256<BaseElement>>().bits();
        let r = verify_release(proof, &policy);
        eprintln!("weaker options '{name}' ({bits} bits conjectured): {r:?}");
        assert!(r.is_err(), "{name}: weaker-option proof verified");
    }
}
