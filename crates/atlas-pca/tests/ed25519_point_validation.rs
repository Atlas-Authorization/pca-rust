//! Point validation refuses a mixed-order point, the order-2 point, the identity and a non-canonical encoding, and accepts -B.
use atlas_pca::frost::frost_decode_safe_point;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::CompressedEdwardsY;

#[test]
fn frost_decode_safe_point_refuses_torsion() {
    let mut t2 = [0xffu8; 32]; // (0, -1), order 2
    t2[0] = 0xec;
    t2[31] = 0x7f;
    let t = CompressedEdwardsY(t2).decompress().expect("order-2 point");
    let mixed = (B + t).compress().to_bytes();
    let mut ident = [0u8; 32];
    ident[0] = 1;
    let mut non_canonical = [0xffu8; 32]; // y = p + 1
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    let mut neg = B.compress().to_bytes();
    neg[31] |= 0x80;
    assert!(frost_decode_safe_point(&B.compress().to_bytes()).is_ok());
    assert!(frost_decode_safe_point(&neg).is_ok());
    for bad in [mixed, t2, ident, [0u8; 32], non_canonical] {
        assert!(frost_decode_safe_point(&bad).is_err());
    }
}
