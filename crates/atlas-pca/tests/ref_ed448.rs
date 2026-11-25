//! Ed448 (RFC 8032) JWS signing and verification through OpenSSL 3, behind the `ed448` feature; without it Ed448 stays refused.
#![cfg(feature = "ed448")]
use atlas_pca::jose::{ed448_public_jwk, import_public_jwk, sign_ed448_jws, verify_jws_signature};
use atlas_pca::serde_json::json;
use base64::Engine;

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

#[test]
fn ed448_jws_round_trip_and_tamper() {
    let seed = [7u8; 57];
    let jwk = ed448_public_jwk(&seed).expect("public key");
    let jws = sign_ed448_jws(&json!({"alg": "EdDSA", "typ": "JWT"}), &json!({"sub": "a"}), &seed).expect("signs");
    let parts: Vec<&str> = jws.split('.').collect();
    let input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64d(parts[2]);
    assert_eq!(sig.len(), 114);
    let key = import_public_jwk(&jwk, "EdDSA").expect("imports");
    assert!(verify_jws_signature("EdDSA", &key, input.as_bytes(), &sig));
    let mut bad = sig.clone();
    bad[10] ^= 1;
    assert!(!verify_jws_signature("EdDSA", &key, input.as_bytes(), &bad));
    assert!(!verify_jws_signature("EdDSA", &key, b"other", &sig));
    assert!(!verify_jws_signature("EdDSA", &key, input.as_bytes(), &sig[..113]));
    // another key never verifies it
    let other = import_public_jwk(&ed448_public_jwk(&[8u8; 57]).expect("other"), "EdDSA").expect("imports");
    assert!(!verify_jws_signature("EdDSA", &other, input.as_bytes(), &sig));
}

#[test]
fn a_malformed_ed448_key_is_refused() {
    assert!(import_public_jwk(&json!({"kty": "OKP", "crv": "Ed448", "x": "AAAA"}), "EdDSA").is_err());
    assert!(import_public_jwk(&json!({"kty": "OKP", "crv": "Ed448", "x": "AAAA", "d": "AAAA"}), "EdDSA").is_err());
}
