//! The RSA public-key rule at the key constructor every verify path goes through: bitlen(n) in [512, 16384], e odd, 3 <= e, bitlen(e) <= 32.
use super::{bit_len, rsa_key, rsa_key_ok, rsa_pkcs1_verify, Hash};

/// A big-endian integer of exactly `bits` bits (top bit set), odd.
fn int_of_bits(bits: usize) -> Vec<u8> {
    let len = bits.div_ceil(8);
    let mut v = vec![0xffu8; len];
    v[0] = 1u8 << ((bits - 1) % 8);
    if len == 1 {
        v[0] |= 1;
    } else {
        *v.last_mut().unwrap() = 0x01;
    }
    v
}

const E: [u8; 3] = [1, 0, 1];

#[test]
fn bit_len_counts_from_the_first_set_bit() {
    assert_eq!(bit_len(&[]), 0);
    assert_eq!(bit_len(&[0, 0]), 0);
    assert_eq!(bit_len(&[1]), 1);
    assert_eq!(bit_len(&[0, 1]), 1);
    assert_eq!(bit_len(&[0x80]), 8);
    assert_eq!(bit_len(&[0, 0x80, 0]), 16);
    assert_eq!(bit_len(&[1, 0]), 9);
    assert_eq!(bit_len(&int_of_bits(512)), 512);
    assert_eq!(bit_len(&int_of_bits(513)), 513);
}

#[test]
fn the_modulus_must_have_512_to_16384_bits() {
    for (bits, ok) in [(256usize, false), (511, false), (512, true), (513, true), (2048, true), (16384, true), (16385, false), (20000, false)] {
        let n = int_of_bits(bits);
        assert_eq!(rsa_key_ok(&n, &E), ok, "{bits} bits");
        // the constructor agrees (and the `rsa` crate's own checks accept every in-range odd modulus here)
        assert_eq!(rsa_key(&n, &E).is_some(), ok, "{bits} bits via rsa_key");
    }
    assert!(!rsa_key_ok(&[], &E), "no modulus");
    assert!(!rsa_key_ok(&[0, 0], &E), "a zero modulus");
}

#[test]
fn the_exponent_must_be_odd_at_least_3_and_at_most_32_bits() {
    let n = int_of_bits(2048);
    for (e, ok, why) in [
        (vec![], false, "empty"),
        (vec![0], false, "zero"),
        (vec![1], false, "e = 1"),
        (vec![2], false, "e = 2 (even)"),
        (vec![3], true, "e = 3"),
        (vec![4], false, "e = 4 (even)"),
        (vec![1, 0, 1], true, "e = 65537"),
        (vec![1, 0, 2], false, "even, 17 bits"),
        (vec![0xff, 0xff, 0xff, 0xff], true, "32 bits, odd"),
        (vec![0xff, 0xff, 0xff, 0xfe], false, "32 bits, even"),
        (vec![1, 0, 0, 0, 1], false, "33 bits, odd"),
        (vec![0, 0, 1, 0, 1], true, "leading zeros do not count"),
        (vec![1, 0xff, 0xff, 0xff, 0xff], false, "33 bits, odd, all ones below"),
    ] {
        assert_eq!(rsa_key_ok(&n, &e), ok, "{why}");
        assert_eq!(rsa_key(&n, &e).is_some(), ok, "{why} via rsa_key");
    }
}

#[test]
fn a_refused_key_never_verifies() {
    let sig = vec![0u8; 64];
    assert!(!rsa_pkcs1_verify(&int_of_bits(256), &E, Hash::Sha256, b"m", &sig));
    assert!(!rsa_pkcs1_verify(&int_of_bits(2048), &[1], Hash::Sha256, b"m", &sig));
    assert!(!rsa_pkcs1_verify(&int_of_bits(2048), &[0xff, 0xff, 0xff, 0xff, 0xff], Hash::Sha256, b"m", &sig));
}
