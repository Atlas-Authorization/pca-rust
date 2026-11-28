//! The byte-level Ed25519 surface of `keys.ts`: round trip, strict verification and the base64url helpers.
use atlas_pca::keys::*;

#[test]
fn sign_and_verify_round_trip() {
    let k = generate_key_pair().unwrap();
    assert_eq!(public_key_of(&*k.secret_key).unwrap(), k.public_key);
    let sig = sign(&*k.secret_key, b"msg").unwrap();
    assert!(verify(&k.public_key, b"msg", &sig));
    assert!(!verify(&k.public_key, b"other", &sig));
    assert!(verify_b64u(&encode_key(&k.public_key), b"msg", &encode_sig(&sig)));
    assert!(!verify_b64u(&encode_key(&k.public_key), b"msg", &format!("{}=", encode_sig(&sig))));
}

#[test]
fn verification_is_strict_and_total() {
    let k = generate_key_pair().unwrap();
    let sig = sign(&*k.secret_key, b"m").unwrap();
    assert!(!verify(&k.public_key[..31], b"m", &sig) && !verify(&k.public_key, b"m", &sig[..63]) && !verify(&[], b"m", &[]));
    // a small-order key (the identity point) with an all-zero signature is refused
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(!verify(&identity, b"m", &[0u8; 64]));
    // S >= L is refused
    let mut high = sig;
    high[32..].fill(0xff);
    assert!(!verify(&k.public_key, b"m", &high));
    assert!(sign(&[0u8; 31], b"m").is_err() && public_key_of(&[0u8; 33]).is_err());
}

#[test]
fn base64url_helpers() {
    assert_eq!(decode_key(&encode_key(&[251, 255, 190])).unwrap(), [251, 255, 190]);
    assert_eq!(encode_key(&[251, 255, 190]), "-_--");
    assert!(decode_key("AA==").is_err() && decode_sig("A+/").is_err());
}
