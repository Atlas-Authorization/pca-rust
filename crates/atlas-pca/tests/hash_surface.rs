//! The public hash helpers (`atlas_pca::hash`): suite dispatch, lengths, canonical base64url and the strict number profile.
use atlas_pca::hash::*;
use atlas_pca::serde_json::json;

#[test]
fn suites_dispatch_and_default_matches_the_protocol_digest() {
    assert_eq!(DEFAULT_HASH_SUITE, HashSuite::Sha256);
    assert!(is_hash_suite("sha256") && is_hash_suite("sha384"));
    assert!(!is_hash_suite("SHA256") && !is_hash_suite("sha512") && !is_hash_suite(""));
    assert_eq!((HashSuite::Sha256.len(), HashSuite::Sha384.len()), (32, 48));
    assert_eq!(hash_with_suite(b"abc", HashSuite::Sha256).len(), 32);
    assert_eq!(hash_with_suite(b"abc", HashSuite::Sha384).len(), 48);
    // FIPS 180 test vectors
    assert_eq!(hash_with_suite(b"abc", HashSuite::Sha256)[..4], [0xba, 0x78, 0x16, 0xbf]);
    assert_eq!(hash_with_suite(b"abc", HashSuite::Sha384)[..4], [0xcb, 0x00, 0x75, 0x3f]);
    let v = json!({"b": 1, "a": [true, null, "x"]});
    assert_eq!(hash_canonical_with(&v, HashSuite::Sha256).unwrap(), atlas_pca::hash_canonical_strict(&v).unwrap());
    assert_ne!(hash_canonical_with(&v, HashSuite::Sha384).unwrap(), hash_canonical_with(&v, HashSuite::Sha256).unwrap());
    assert_eq!(hash_canonical_with(&v, HashSuite::Sha384).unwrap().len(), b64u_len(48));
    assert!(hash_canonical_with(&json!({"n": 1e300}), HashSuite::Sha256).is_err());
}

#[test]
fn base64url_lengths_and_canonicality() {
    assert_eq!([b64u_len(0), b64u_len(1), b64u_len(2), b64u_len(3), b64u_len(32), b64u_len(64)], [0, 2, 3, 4, 43, 86]);
    assert!(is_canonical_b64u("", None));
    assert!(is_canonical_b64u(&"A".repeat(43), Some(32)));
    assert!(!is_canonical_b64u(&"A".repeat(43), Some(31)), "decoded length must match");
    assert!(!is_canonical_b64u("AB==", None), "padding is refused");
    assert!(!is_canonical_b64u("AB", None), "non-zero trailing bits are refused");
    assert!(!is_canonical_b64u("A", None), "length mod 4 == 1");
    assert!(!is_canonical_b64u("a+b/", None), "standard alphabet is refused");
}

#[test]
fn strict_numbers_and_canonical_bytes() {
    assert_eq!(strict_number_error(1.0), None);
    assert_eq!(strict_number_error(0.5), None);
    assert!(strict_number_error(f64::NAN).is_some());
    assert!(strict_number_error(f64::INFINITY).is_some());
    assert!(strict_number_error(-0.0).unwrap().contains("negative zero"));
    assert!(strict_number_error(9_007_199_254_740_992.0).unwrap().contains("safe range"));
    assert!(strict_number_error(1e-7).unwrap().contains("below 1e-6"));
    assert!(strict_number_error(0.1234567890123456).unwrap().contains("15 significant digits"));
    let v = json!({"b": 1, "a": 2});
    assert_eq!(canonical_bytes_strict(&v).unwrap(), br#"{"a":2,"b":1}"#.to_vec());
    assert_eq!(canonical_bytes_lenient(&v), br#"{"a":2,"b":1}"#.to_vec());
    assert!(canonical_bytes_strict(&json!({"x": 1e-7})).is_err());
    assert!(!has_lone_surrogate("\u{1F600}"));
}
