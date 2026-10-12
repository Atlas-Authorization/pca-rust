//! R6-ALIAS-06: a 256-bit commitment has exactly one accepted spelling: 64 LOWERCASE hex digits.
//! `is_ascii_hexdigit` also admitted 'A'-'F', so "AB.." and "ab.." named the same commitment.

use stark_pca::hex256_limbs;

const LOWER: &str = "00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210";

#[test]
fn lowercase_is_accepted() {
    assert!(hex256_limbs(LOWER).is_ok());
}

#[test]
fn uppercase_and_mixed_case_are_rejected() {
    assert!(hex256_limbs(&LOWER.to_ascii_uppercase()).is_err(), "uppercase must be refused");
    let mixed = LOWER.replacen("aa", "Aa", 1);
    assert_ne!(mixed, LOWER);
    assert!(hex256_limbs(&mixed).is_err(), "mixed case must be refused");
    assert!(hex256_limbs(&LOWER.replacen('f', "F", 1)).is_err());
}

#[test]
fn other_shapes_stay_rejected() {
    assert!(hex256_limbs(&LOWER[..63]).is_err());
    assert!(hex256_limbs(&format!("{LOWER}0")).is_err());
    assert!(hex256_limbs(&LOWER.replacen('0', "g", 1)).is_err());
    assert!(hex256_limbs(&format!("+{}", &LOWER[1..])).is_err());
}
