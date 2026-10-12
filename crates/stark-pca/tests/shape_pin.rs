//! Each field of the release-gate trace shape is pinned independently by `verify_release`: a proof whose ONLY deviation is one
//! header field (width, length, trace metadata) must be rejected with the shape error, not slip through
//! to a later check. (Kills the `||` -> `&&` mutants of the shape guard in `verify_release`.)
use stark_pca::{proof_from_bytes, verify_release, PolicyParams, TRACE_LEN, WIDTH};
use winterfell::VerifierError;

const SHAPE_MSG: &str = "proof trace shape does not match the release-gate AIR";

fn fixture() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin")).unwrap()
}

fn shape_rejected(bytes: &[u8]) {
    let proof = proof_from_bytes(bytes).expect("header-only tamper must still decode");
    match verify_release(proof, &PolicyParams::default_policy()) {
        Err(VerifierError::ProofDeserializationError(m)) => assert_eq!(m, SHAPE_MSG),
        other => panic!("expected the shape rejection, got {other:?}"),
    }
}

#[test]
fn untouched_fixture_has_expected_header() {
    let b = fixture();
    assert_eq!(b[0] as usize, WIDTH);
    assert_eq!(b[1], 0, "aux width");
    assert_eq!(b[2], 0, "aux rands");
    assert_eq!(1usize << b[3], TRACE_LEN);
    assert_eq!(&b[4..6], &[0, 0], "no trace meta");
}

#[test]
fn width_alone_is_rejected() {
    let mut b = fixture();
    b[0] -= 1;
    shape_rejected(&b);
    let mut b = fixture();
    b[0] += 1;
    shape_rejected(&b);
}

#[test]
fn length_alone_is_rejected() {
    let mut b = fixture();
    b[3] += 1;
    shape_rejected(&b);
    let mut b = fixture();
    b[3] -= 1;
    shape_rejected(&b);
}

#[test]
fn trace_meta_alone_is_rejected() {
    let mut b = fixture();
    b[4] = 1; // meta length (u16 LE) = 1
    b.insert(6, 0xAA);
    shape_rejected(&b);
}
