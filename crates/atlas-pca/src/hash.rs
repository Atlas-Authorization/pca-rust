//! The public hash helpers of the reference `hash.ts`: the hash-suite selector (SHA-256 default, optional SHA-384 for cryptographic
//! agility), the canonical base64url length and canonicality checks, and the strict / lenient canonical byte forms.
//!
//! SHA-384 is margin, not a fix: `sha256` is the default everywhere a suite is threaded and an ABSENT `hash_suite` member must be read
//! as `sha256`, so every pre-existing digest stays byte-identical. A Rust `str` is always well-formed UTF-8 (and `serde_json` refuses a
//! lone `\ud800` escape), so the reference's lone-surrogate guard has no input here: [`has_lone_surrogate`] is `false` by construction.
use crate::{canonicalize, canonicalize_strict, decode_b64u_strict, number_error};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256, Sha384};

/// The hash suites of the reference (`HashSuite`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HashSuite {
    #[default]
    Sha256,
    Sha384,
}

/// The DEFAULT suite: an absent `hash_suite` member MUST be read as this.
pub const DEFAULT_HASH_SUITE: HashSuite = HashSuite::Sha256;

impl HashSuite {
    /// The wire name (`sha256` | `sha384`).
    pub fn name(self) -> &'static str {
        match self {
            HashSuite::Sha256 => "sha256",
            HashSuite::Sha384 => "sha384",
        }
    }
    /// The digest length in bytes (32 | 48).
    pub fn len(self) -> usize {
        match self {
            HashSuite::Sha256 => 32,
            HashSuite::Sha384 => 48,
        }
    }
    /// The suite a wire name selects; `None` for anything else (the caller must fail closed).
    pub fn parse(s: &str) -> Option<HashSuite> {
        match s {
            "sha256" => Some(HashSuite::Sha256),
            "sha384" => Some(HashSuite::Sha384),
            _ => None,
        }
    }
}

/// `true` iff `s` is a known hash suite name. Anything else MUST fail closed at the caller.
pub fn is_hash_suite(s: &str) -> bool {
    HashSuite::parse(s).is_some()
}

/// A raw-byte hash over the selected suite (the default is byte-identical to a bare SHA-256).
pub fn hash_with_suite(bytes: &[u8], suite: HashSuite) -> Vec<u8> {
    match suite {
        HashSuite::Sha256 => Sha256::digest(bytes).to_vec(),
        HashSuite::Sha384 => Sha384::digest(bytes).to_vec(),
    }
}

/// The encoded (unpadded base64url) length of `n` bytes.
pub fn b64u_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// `true` iff `s` is canonical base64url (optionally of an exact decoded byte length).
pub fn is_canonical_b64u(s: &str, len: Option<usize>) -> bool {
    decode_b64u_strict(s, len).is_some()
}

/// Strict-profile check of one number: `None` when acceptable, else the reason.
pub fn strict_number_error(v: f64) -> Option<String> {
    match Number::from_f64(v) {
        Some(n) => number_error(&n),
        None => Some("non-finite number".into()),
    }
}

/// A Rust string cannot hold an unpaired surrogate: always `false`.
pub fn has_lone_surrogate(_s: &str) -> bool {
    false
}

/// The STRICT canonical bytes of `value` (what every protocol digest hashes). `Err` for a value outside the strict profile.
pub fn canonical_bytes_strict(value: &Value) -> Result<Vec<u8>, String> {
    canonicalize_strict(value).map(String::into_bytes)
}

/// The LENIENT canonical bytes of `value`: SERVER-ONLY, never a protocol digest input (it tolerates exponent and long-digit numbers the
/// strict profile forbids).
pub fn canonical_bytes_lenient(value: &Value) -> Vec<u8> {
    canonicalize(value).into_bytes()
}

/// base64url(H(strictCanonical(value))) under `suite`. The default suite equals [`crate::hash_canonical_strict`].
pub fn hash_canonical_with(value: &Value, suite: HashSuite) -> Result<String, String> {
    Ok(URL_SAFE_NO_PAD.encode(hash_with_suite(&canonical_bytes_strict(value)?, suite)))
}
