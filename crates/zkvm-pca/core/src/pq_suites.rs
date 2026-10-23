//! Signature suites in the guest (`packages/pca/src/pq.ts` `verifyWithSuite`, SIG_SUITES). PCA 0.4.2: the guest verifies every
//! suite it can with pure-Rust FIPS implementations that build for the zkVM target, and fails CLOSED with the reason
//! `unsupported_suite: <alg>` otherwise.
//!
//! | alg                                   | guest                                                                   |
//! | ed25519 (absent alg)                  | strict Ed25519 ([`crate::chain::ed25519_verify_b64u`])                   |
//! | ml-dsa-65, ml-dsa-87                  | `fips204` (FIPS 204, empty context; = @noble/post-quantum, circl)        |
//! | hybrid-ed25519-ml-dsa-{65,87}         | Ed25519 `sig` over msg AND ML-DSA `pq_sig` over msg                      |
//! | hybrid-nested-ed25519-ml-dsa-65       | Ed25519 `sig` over msg AND ML-DSA `pq_sig` over msg ‖ ed25519 sig bytes  |
//! | slh-dsa-sha2-{128f,256s}              | `fips205` (FIPS 205, empty context)                                      |
//! | hybrid-ed25519-slh-dsa-sha2-{128f,256s} | Ed25519 `sig` over msg AND SLH-DSA `pq_sig` over msg                   |
//! | fn-dsa-512, fn-dsa-1024                | `fn-dsa-vrfy` 0.4 (FIPS 206 draft, DOMAIN_NONE + HASH_ID_RAW; = the TS reference's wasm, rust-pca) |
//! | less-cat1, hybrid-ed25519-less-cat1, anything else | `unsupported_suite` (fail closed) |
//!
//! As in the TS, the cheap Ed25519 half of a hybrid is checked first, the PQ key is the VERIFIER-RESOLVED key (the caller passes
//! the pinned / bound `pq_pk`, never one read from the artifact unless the artifact's rule says so), and every byte field is
//! strict canonical base64url of its exact suite length.
use crate::chain::{decode_b64u_strict, ed25519_verify_b64u};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuiteError {
    /// The suite is not implemented in the guest (or unknown): fail closed.
    Unsupported(String),
    /// A required field is missing or not the suite's exact canonical encoding.
    Malformed(String),
    /// The signature does not verify.
    BadSignature(String),
}

impl core::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SuiteError::Unsupported(a) => write!(f, "unsupported_suite: {a}"),
            SuiteError::Malformed(m) => write!(f, "malformed signature: {m}"),
            SuiteError::BadSignature(m) => write!(f, "bad signature: {m}"),
        }
    }
}

pub const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pq {
    MlDsa65,
    MlDsa87,
    Slh128f,
    Slh256s,
    FnDsa512,
    FnDsa1024,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Ed25519,
    Pure(Pq),
    Hybrid(Pq),
    Nested(Pq),
}

fn shape(alg: Option<&str>) -> Option<Shape> {
    Some(match alg {
        None | Some("ed25519") => Shape::Ed25519,
        Some("ml-dsa-65") => Shape::Pure(Pq::MlDsa65),
        Some("ml-dsa-87") => Shape::Pure(Pq::MlDsa87),
        Some("hybrid-ed25519-ml-dsa-65") => Shape::Hybrid(Pq::MlDsa65),
        Some("hybrid-ed25519-ml-dsa-87") => Shape::Hybrid(Pq::MlDsa87),
        Some("hybrid-nested-ed25519-ml-dsa-65") => Shape::Nested(Pq::MlDsa65),
        Some("slh-dsa-sha2-128f") => Shape::Pure(Pq::Slh128f),
        Some("slh-dsa-sha2-256s") => Shape::Pure(Pq::Slh256s),
        Some("hybrid-ed25519-slh-dsa-sha2-128f") => Shape::Hybrid(Pq::Slh128f),
        Some("hybrid-ed25519-slh-dsa-sha2-256s") => Shape::Hybrid(Pq::Slh256s),
        Some("fn-dsa-512") => Shape::Pure(Pq::FnDsa512),
        Some("fn-dsa-1024") => Shape::Pure(Pq::FnDsa1024),
        _ => return None,
    })
}

/// True iff the guest implements `alg` (absent = ed25519).
pub fn suite_supported(alg: Option<&str>) -> bool {
    shape(alg).is_some()
}

/// True iff the suite carries a PQ public key (every supported suite but ed25519).
pub fn suite_needs_pq_pk(alg: Option<&str>) -> bool {
    !matches!(shape(alg), Some(Shape::Ed25519) | None)
}

/// (public key bytes, signature bytes) of a PQ primitive.
fn lens(pq: Pq) -> (usize, usize) {
    match pq {
        Pq::MlDsa65 => (fips204::ml_dsa_65::PK_LEN, fips204::ml_dsa_65::SIG_LEN),
        Pq::MlDsa87 => (fips204::ml_dsa_87::PK_LEN, fips204::ml_dsa_87::SIG_LEN),
        Pq::Slh128f => (fips205::slh_dsa_sha2_128f::PK_LEN, fips205::slh_dsa_sha2_128f::SIG_LEN),
        Pq::Slh256s => (fips205::slh_dsa_sha2_256s::PK_LEN, fips205::slh_dsa_sha2_256s::SIG_LEN),
        Pq::FnDsa512 => (897, 666),
        Pq::FnDsa1024 => (1793, 1280),
    }
}

/// Exact-length PQ primitive verification (empty context). Total.
fn pq_verify(pq: Pq, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // fips204 `try_from_bytes` takes the key array by value, fips205 by reference (`$by_ref`).
    macro_rules! dsa {
        ($m:path, $($by_ref:tt)?) => {{
            use $m as m;
            let (Ok(pk), Ok(sig)) = (<[u8; m::PK_LEN]>::try_from(pk), <[u8; m::SIG_LEN]>::try_from(sig)) else { return false };
            match m::PublicKey::try_from_bytes($($by_ref)? pk) {
                Ok(vk) => vk.verify(msg, &sig, &[]),
                Err(_) => false,
            }
        }};
    }
    match pq {
        Pq::MlDsa65 => {
            use fips204::traits::{SerDes, Verifier};
            dsa!(fips204::ml_dsa_65,)
        }
        Pq::MlDsa87 => {
            use fips204::traits::{SerDes, Verifier};
            dsa!(fips204::ml_dsa_87,)
        }
        Pq::Slh128f => {
            use fips205::traits::{SerDes, Verifier};
            dsa!(fips205::slh_dsa_sha2_128f, &)
        }
        Pq::Slh256s => {
            use fips205::traits::{SerDes, Verifier};
            dsa!(fips205::slh_dsa_sha2_256s, &)
        }
        Pq::FnDsa512 => {
            use fn_dsa_vrfy::VerifyingKey;
            fn_dsa_vrfy::VerifyingKey512::decode(pk).is_some_and(|vk| vk.verify(sig, &fn_dsa_vrfy::DOMAIN_NONE, &fn_dsa_vrfy::HASH_ID_RAW, msg))
        }
        Pq::FnDsa1024 => {
            use fn_dsa_vrfy::VerifyingKey;
            fn_dsa_vrfy::VerifyingKey1024::decode(pk).is_some_and(|vk| vk.verify(sig, &fn_dsa_vrfy::DOMAIN_NONE, &fn_dsa_vrfy::HASH_ID_RAW, msg))
        }
    }
}

fn pq_verify_b64u(pq: Pq, pk_b64u: Option<&str>, msg: &[u8], sig_b64u: Option<&str>) -> Result<(), SuiteError> {
    let (pk_len, sig_len) = lens(pq);
    let pk = pk_b64u.and_then(|p| decode_b64u_strict(p, pk_len)).ok_or_else(|| SuiteError::Malformed("pq_pk".into()))?;
    let sig = sig_b64u.and_then(|s| decode_b64u_strict(s, sig_len)).ok_or_else(|| SuiteError::Malformed("pq signature".into()))?;
    if pq_verify(pq, &pk, msg, &sig) {
        Ok(())
    } else {
        Err(SuiteError::BadSignature("post-quantum half".into()))
    }
}

fn ed_verify(ed_pk_b64u: Option<&str>, msg: &[u8], sig_b64u: Option<&str>) -> Result<(), SuiteError> {
    match (ed_pk_b64u, sig_b64u) {
        (Some(pk), Some(sig)) if ed25519_verify_b64u(pk, msg, sig) => Ok(()),
        _ => Err(SuiteError::BadSignature("ed25519".into())),
    }
}

/// `verifyWithSuite(alg, {edPub, pq}, msg, {sig, pq_sig})`: `ed_pk_b64u` is the Ed25519 identity key, `pq_pk_b64u` the
/// VERIFIER-RESOLVED PQ key (`resolvePqVerifyKey`); `sig` / `pq_sig` as carried. Absent `alg` = ed25519. Total.
pub fn verify_with_suite(
    alg: Option<&str>,
    msg: &[u8],
    ed_pk_b64u: Option<&str>,
    sig_b64u: Option<&str>,
    pq_pk_b64u: Option<&str>,
    pq_sig_b64u: Option<&str>,
) -> Result<(), SuiteError> {
    let s = shape(alg).ok_or_else(|| SuiteError::Unsupported(alg.unwrap_or("ed25519").to_string()))?;
    match s {
        Shape::Ed25519 => ed_verify(ed_pk_b64u, msg, sig_b64u),
        Shape::Pure(pq) => pq_verify_b64u(pq, pq_pk_b64u, msg, sig_b64u),
        Shape::Hybrid(pq) => {
            ed_verify(ed_pk_b64u, msg, sig_b64u)?;
            pq_verify_b64u(pq, pq_pk_b64u, msg, pq_sig_b64u)
        }
        Shape::Nested(pq) => {
            ed_verify(ed_pk_b64u, msg, sig_b64u)?;
            let ed_sig = sig_b64u.and_then(|s| decode_b64u_strict(s, ED25519_SIGNATURE_BYTES)).ok_or_else(|| SuiteError::Malformed("sig".into()))?;
            let mut nested = msg.to_vec();
            nested.extend_from_slice(&ed_sig);
            pq_verify_b64u(pq, pq_pk_b64u, &nested, pq_sig_b64u)
        }
    }
}

/// `verifyPinnedSuite(alg, identity, artifactPqPk, msg, {sig, pq_sig}, {pqPins})` (pq.ts): Ed25519 under `identity`; any other
/// suite needs a VERIFIER pin for `identity` (`pin` = `pqPins[identity]`, when the verifier has one) that equals the artifact's
/// own `pq_pk` (`resolvePqVerifyKey` step 2; no pin = no authority = refuse). Total.
pub fn verify_pinned_suite(
    alg: Option<&str>,
    identity: &str,
    artifact_pq_pk: Option<&str>,
    msg: &[u8],
    sig_b64u: Option<&str>,
    pq_sig_b64u: Option<&str>,
    pin: Option<&str>,
) -> Result<(), SuiteError> {
    let s = shape(alg).ok_or_else(|| SuiteError::Unsupported(alg.unwrap_or("ed25519").to_string()))?;
    if s == Shape::Ed25519 {
        return ed_verify(Some(identity), msg, sig_b64u);
    }
    let pk = match (artifact_pq_pk, pin) {
        (Some(a), Some(p)) if !a.is_empty() && a == p => a,
        _ => return Err(SuiteError::BadSignature("no verifier pin for the post-quantum key".into())),
    };
    verify_with_suite(alg, msg, Some(identity), sig_b64u, Some(pk), pq_sig_b64u)
}
