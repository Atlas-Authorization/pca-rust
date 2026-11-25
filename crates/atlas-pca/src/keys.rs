//! `keys.ts`: Ed25519 key pairs as raw bytes, signing, and STRICT RFC 8032 verification (canonical point encodings, canonical S, no small-order
//! or mixed-order key or `R`). [`crate::agent::KeyPair`] is the same primitive behind a base64url identity; these are the byte-level functions.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

pub use crate::verify_b64u;

/// An Ed25519 key pair: the 32-byte seed (`secret_key`, wiped on drop) and the 32-byte public key.
pub struct RawKeyPair {
    pub secret_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

fn signing_key(secret_key: &[u8]) -> Result<SigningKey, String> {
    <[u8; 32]>::try_from(secret_key).map(|s| SigningKey::from_bytes(&s)).map_err(|_| "an Ed25519 secret key is 32 bytes".to_string())
}

/// `generateKeyPair`: a fresh key pair from the OS CSPRNG.
pub fn generate_key_pair() -> Result<RawKeyPair, String> {
    let secret_key = Zeroizing::new(crate::agent::rand_bytes::<32>()?);
    let public_key = SigningKey::from_bytes(&secret_key).verifying_key().to_bytes();
    Ok(RawKeyPair { secret_key, public_key })
}

/// `publicKeyOf`: the public key of a 32-byte secret key.
pub fn public_key_of(secret_key: &[u8]) -> Result<[u8; 32], String> {
    Ok(signing_key(secret_key)?.verifying_key().to_bytes())
}

/// `sign`: the 64-byte Ed25519 signature of `msg` under a 32-byte secret key.
pub fn sign(secret_key: &[u8], msg: &[u8]) -> Result<[u8; 64], String> {
    Ok(signing_key(secret_key)?.sign(msg).to_bytes())
}

/// `verify`: strict verification; `false` (never a panic) for a key or signature of the wrong length or any deviation.
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match (<[u8; 32]>::try_from(public_key), <[u8; 64]>::try_from(sig)) {
        (Ok(pk), Ok(sg)) => crate::verify_ed25519_strict(&pk, msg, &sg),
        _ => false,
    }
}

/// `encodeKey` / `encodeSig`: unpadded base64url.
pub fn encode_key(key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// `encodeSig`.
pub fn encode_sig(sig: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sig)
}

/// `decodeKey` / `decodeSig`: unpadded base64url; `Err` for any other alphabet or padding.
pub fn decode_key(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())
}

/// `decodeSig`.
pub fn decode_sig(s: &str) -> Result<Vec<u8>, String> {
    decode_key(s)
}
