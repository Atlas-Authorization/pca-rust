//! O2: the Ed25519 seed buffers are wrapped in `Zeroizing` (wiped on drop); the observable behaviour of the constructors is unchanged.
use atlas_pca::agent::KeyPair;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;

#[test]
fn a_seed_in_base64url_builds_the_same_key_as_the_raw_seed() {
    let seed = [7u8; 32];
    let a = KeyPair::from_seed(&seed);
    let b = KeyPair::from_seed_b64u(&B64.encode(seed)).unwrap();
    assert_eq!(a.public, b.public);
    assert_eq!(a.sign(b"m"), b.sign(b"m"));
    assert_ne!(a.public, KeyPair::from_seed(&[8u8; 32]).public);
}

#[test]
fn a_malformed_seed_is_refused_with_the_same_text() {
    const WHY: &str = "an Ed25519 seed is 32 canonical base64url bytes";
    for bad in ["", "AAAA", &B64.encode([1u8; 31]), &B64.encode([1u8; 33]), &format!("{}=", B64.encode([1u8; 32]))] {
        assert_eq!(KeyPair::from_seed_b64u(bad).err().as_deref(), Some(WHY), "{bad}");
    }
}

#[test]
fn a_generated_key_is_a_fresh_valid_identity() {
    let (a, b) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    assert_ne!(a.public, b.public);
    assert_eq!(a.sign(b"m").len(), 64);
}
