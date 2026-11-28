//! The public post-quantum signature surface of the reference `pq.ts`: size constants, deterministic keygen from a seed, raw and
//! base64url sign / verify per primitive (ML-DSA-65 / -87, SLH-DSA-SHA2-128f / -256s, FN-DSA-512 / -1024, LESS), the public-key
//! encoders and key checks, the opaque pinned-key resolution ([`resolve_pq_verify_key`], [`holder_pq_key`]) and the LAMPS composite
//! signature (ML-DSA-65 + Ed25519). Every verify is total (a wrong length or a malformed input is `false`); every sign / keygen
//! refuses a wrong-sized seed or key with `Err`. ML-DSA and SLH-DSA sign deterministically (the reference's vectors reproduce);
//! FN-DSA signing needs the `fndsa-sign` feature and LESS needs the `less` feature, otherwise they are an `Err` (verify: `false`).
//! The reference's `allowUnboundPq` opt-out does not exist here: an artifact's own key is never enough.
use crate::agent::KeyPair;
use crate::{decode_b64u_strict, holder_pq_commitment, pinned, pq_verify, verify_b64u, Pq, PQ_PK_LENGTHS, REGISTERED_SUITES};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use fips204::traits::{KeyGen, SerDes, Signer as PqSigner};
use fips205::traits::{KeyGen as SlhKeyGen, SerDes as SlhSerDes, Signer as SlhSigner};
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub use crate::pinned::PinnedPq;
pub use crate::ML_DSA_65_PUBLIC_KEY_BYTES;
pub use crate::ML_DSA_65_SIGNATURE_BYTES;

pub const ML_DSA_65_SEED_BYTES: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
pub const ML_DSA_87_SEED_BYTES: usize = 32;
pub const SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES: usize = 32;
pub const SLH_DSA_SHA2_128F_SECRET_KEY_BYTES: usize = 64;
pub const SLH_DSA_SHA2_128F_SIGNATURE_BYTES: usize = 17088;
pub const SLH_DSA_SHA2_128F_SEED_BYTES: usize = 48;
pub const SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES: usize = 64;
pub const SLH_DSA_SHA2_256S_SECRET_KEY_BYTES: usize = 128;
pub const SLH_DSA_SHA2_256S_SIGNATURE_BYTES: usize = 29792;
pub const SLH_DSA_SHA2_256S_SEED_BYTES: usize = 96;
pub const FN_DSA_512_PUBLIC_KEY_BYTES: usize = 897;
pub const FN_DSA_512_SECRET_KEY_BYTES: usize = 1345;
pub const FN_DSA_512_SIGNATURE_BYTES: usize = 666;
pub const FN_DSA_1024_PUBLIC_KEY_BYTES: usize = 1793;
pub const FN_DSA_1024_SECRET_KEY_BYTES: usize = 2369;
pub const FN_DSA_1024_SIGNATURE_BYTES: usize = 1280;
pub const FN_DSA_SEED_BYTES: usize = 32;
pub const LESS_CAT1_PUBLIC_KEY_BYTES: usize = 97484;
pub const LESS_CAT1_SECRET_KEY_BYTES: usize = 32;
pub const LESS_CAT1_SIGNATURE_MAX_BYTES: usize = 1329;
pub const LESS_CAT1_SIGNATURE_MIN_BYTES: usize = 1153;
pub const LESS_CAT1_SIGNATURE_STEP_BYTES: usize = 16;
pub const LESS_SEED_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// The suite an artifact without `alg` uses.
pub const DEFAULT_SIG_ALG: &str = "ed25519";

/// The LAMPS composite-signature prefix (ASCII "CompositeAlgorithmSignatures2025").
pub const COMPOSITE_PREFIX: &str = "CompositeAlgorithmSignatures2025";
/// The per-combination label of id-MLDSA65-Ed25519-SHA512.
pub const COMPOSITE_LABEL: &str = "COMPSIG-MLDSA65-Ed25519-SHA512";
/// ML-DSA-65 signature then Ed25519 signature.
pub const COMPOSITE_SIGNATURE_BYTES: usize = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;

/// A raw key pair: `secret_key` is wiped when dropped.
pub struct RawKeyPair {
    pub secret_key: Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn seed_of<'a>(name: &str, seed: &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if seed.len() == n {
        Ok(seed)
    } else {
        Err(format!("{name}: seed must be {n} bytes"))
    }
}

/// `true` when `x` is a registered signature suite name (`ed25519` included).
pub fn is_known_sig_alg(x: &str) -> bool {
    REGISTERED_SUITES.contains(&x)
}

/// `true` when `pq` is canonical base64url of a byte string with the public-key length of a registered PQ suite.
pub fn is_well_formed_pq_public_key(pq: &str) -> bool {
    decode_b64u_strict(pq, None).is_some_and(|b| PQ_PK_LENGTHS.contains(&b.len()))
}

// ---- ML-DSA / SLH-DSA (fips204 / fips205) ----------------------------------------------------------------------------------

macro_rules! ml_dsa {
    ($keygen:ident, $sign:ident, $verify:ident, $verify_b64u:ident, $m:ident, $pq:expr, $name:expr, $seed:expr, $pk:expr, $sig:expr) => {
        /// Deterministic keygen from a 32-byte seed (FIPS 204 key generation).
        pub fn $keygen(seed: &[u8]) -> Result<RawKeyPair, String> {
            let seed: [u8; 32] = seed_of($name, seed, $seed)?.try_into().map_err(|_| "seed")?;
            let (pk, sk) = fips204::$m::KG::keygen_from_seed(&seed);
            Ok(RawKeyPair { secret_key: Zeroizing::new(sk.into_bytes().to_vec()), public_key: pk.into_bytes().to_vec() })
        }
        /// Deterministic sign (FIPS 204 rnd = 0^32, empty context) with the raw secret key.
        pub fn $sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
            let sk: [u8; fips204::$m::SK_LEN] = secret_key.try_into().map_err(|_| format!("{}: bad secret key length", $name))?;
            let sk = fips204::$m::PrivateKey::try_from_bytes(sk).map_err(|e| e.to_string())?;
            sk.try_sign_with_seed(&[0u8; 32], msg, &[]).map(|s| s.to_vec()).map_err(|e| e.to_string())
        }
        /// Verify over raw bytes; never panics, any wrong length is `false`.
        pub fn $verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            pq_verify($pq, public_key, msg, sig)
        }
        /// Verify over canonical base64url key and signature; `false` on any decoding error.
        pub fn $verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
            match (decode_b64u_strict(public_key_b64u, Some($pk)), decode_b64u_strict(sig_b64u, Some($sig))) {
                (Some(pk), Some(sg)) => $verify(&pk, msg, &sg),
                _ => false,
            }
        }
    };
}

ml_dsa!(
    ml_dsa_65_keygen,
    ml_dsa_65_sign,
    ml_dsa_65_verify,
    ml_dsa_65_verify_b64u,
    ml_dsa_65,
    Pq::MlDsa65,
    "ml_dsa_65_keygen",
    ML_DSA_65_SEED_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES
);
ml_dsa!(
    ml_dsa_87_keygen,
    ml_dsa_87_sign,
    ml_dsa_87_verify,
    ml_dsa_87_verify_b64u,
    ml_dsa_87,
    Pq::MlDsa87,
    "ml_dsa_87_keygen",
    ML_DSA_87_SEED_BYTES,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES
);

/// Deterministic SLH-DSA-SHA2-128f keygen from a 48-byte seed (SK.seed || SK.prf || PK.seed).
pub fn slh_dsa_128f_keygen(seed: &[u8]) -> Result<RawKeyPair, String> {
    let s = seed_of("slh_dsa_128f_keygen", seed, SLH_DSA_SHA2_128F_SEED_BYTES)?;
    let part = |i: usize| -> [u8; 16] { s[i * 16..(i + 1) * 16].try_into().unwrap_or([0u8; 16]) };
    let (a, b, c) = (Zeroizing::new(part(0)), Zeroizing::new(part(1)), part(2));
    let (pk, sk) = fips205::slh_dsa_sha2_128f::KG::keygen_with_seeds(&*a, &*b, &c);
    Ok(RawKeyPair { secret_key: Zeroizing::new(sk.into_bytes().to_vec()), public_key: pk.into_bytes().to_vec() })
}

/// Deterministic SLH-DSA-SHA2-256s keygen from a 96-byte seed (SK.seed || SK.prf || PK.seed).
pub fn slh_dsa_256s_keygen(seed: &[u8]) -> Result<RawKeyPair, String> {
    let s = seed_of("slh_dsa_256s_keygen", seed, SLH_DSA_SHA2_256S_SEED_BYTES)?;
    let part = |i: usize| -> [u8; 32] { s[i * 32..(i + 1) * 32].try_into().unwrap_or([0u8; 32]) };
    let (a, b, c) = (Zeroizing::new(part(0)), Zeroizing::new(part(1)), part(2));
    let (pk, sk) = fips205::slh_dsa_sha2_256s::KG::keygen_with_seeds(&*a, &*b, &c);
    Ok(RawKeyPair { secret_key: Zeroizing::new(sk.into_bytes().to_vec()), public_key: pk.into_bytes().to_vec() })
}

macro_rules! slh_dsa {
    ($sign:ident, $verify:ident, $verify_b64u:ident, $m:ident, $pq:expr, $name:expr, $pk:expr, $sig:expr) => {
        /// Deterministic sign (FIPS 205 opt_rand = PK.seed, empty context) with the raw secret key.
        pub fn $sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
            let sk: [u8; fips205::$m::SK_LEN] = secret_key.try_into().map_err(|_| format!("{}: bad secret key length", $name))?;
            let sk = fips205::$m::PrivateKey::try_from_bytes(&sk).map_err(|e| e.to_string())?;
            sk.try_sign(msg, &[], false).map(|s| s.to_vec()).map_err(|e| e.to_string())
        }
        /// Verify over raw bytes; never panics, any wrong length is `false`.
        pub fn $verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            pq_verify($pq, public_key, msg, sig)
        }
        /// Verify over canonical base64url key and signature; `false` on any decoding error.
        pub fn $verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
            match (decode_b64u_strict(public_key_b64u, Some($pk)), decode_b64u_strict(sig_b64u, Some($sig))) {
                (Some(pk), Some(sg)) => $verify(&pk, msg, &sg),
                _ => false,
            }
        }
    };
}

slh_dsa!(
    slh_dsa_128f_sign,
    slh_dsa_128f_verify,
    slh_dsa_128f_verify_b64u,
    slh_dsa_sha2_128f,
    Pq::Slh128f,
    "slh_dsa_128f_sign",
    SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES,
    SLH_DSA_SHA2_128F_SIGNATURE_BYTES
);
slh_dsa!(
    slh_dsa_256s_sign,
    slh_dsa_256s_verify,
    slh_dsa_256s_verify_b64u,
    slh_dsa_sha2_256s,
    Pq::Slh256s,
    "slh_dsa_256s_sign",
    SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES,
    SLH_DSA_SHA2_256S_SIGNATURE_BYTES
);

// ---- FN-DSA ---------------------------------------------------------------------------------------------------------------

/// FN-DSA verifying and signing key.
pub struct FnDsaKeyPair {
    pub verifying_key: Vec<u8>,
    pub signing_key: Zeroizing<Vec<u8>>,
}

fn fn_dsa_keygen(family: &str, seed: &[u8]) -> Result<FnDsaKeyPair, String> {
    #[cfg(feature = "fndsa-sign")]
    {
        let seed = seed_of("fn_dsa_keygen", seed, FN_DSA_SEED_BYTES)?;
        let kp = crate::agent::PqKeyPair::from_seed(family, seed)?;
        let sk = kp.fn_dsa_signing_key().ok_or("not an FN-DSA key")?;
        let pk = decode_b64u_strict(&kp.public, None).ok_or("internal: FN-DSA public key")?;
        Ok(FnDsaKeyPair { verifying_key: pk, signing_key: Zeroizing::new(sk) })
    }
    #[cfg(not(feature = "fndsa-sign"))]
    {
        let _ = (family, seed);
        Err("FN-DSA keygen needs the `fndsa-sign` feature".into())
    }
}

/// Deterministic FN-DSA-512 keygen from a 32-byte seed. `Err` without the `fndsa-sign` feature.
pub fn fn_dsa_512_keygen(seed: &[u8]) -> Result<FnDsaKeyPair, String> {
    fn_dsa_keygen("FN-DSA-512", seed)
}

/// Deterministic FN-DSA-1024 keygen from a 32-byte seed. `Err` without the `fndsa-sign` feature.
pub fn fn_dsa_1024_keygen(seed: &[u8]) -> Result<FnDsaKeyPair, String> {
    fn_dsa_keygen("FN-DSA-1024", seed)
}

fn fn_dsa_sign(name: &str, sk_len: usize, signing_key: &[u8], msg: &[u8], seed: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(feature = "fndsa-sign")]
    {
        if signing_key.len() != sk_len {
            return Err(format!("{name}: bad signing key length"));
        }
        crate::agent::fn_dsa_sign_raw(signing_key, msg, seed_of(name, seed, FN_DSA_SEED_BYTES)?)
    }
    #[cfg(not(feature = "fndsa-sign"))]
    {
        let _ = (name, sk_len, signing_key, msg, seed);
        Err("FN-DSA signing needs the `fndsa-sign` feature".into())
    }
}

/// FN-DSA-512 sign over raw `msg` (no pre-hash) with a 32-byte RNG seed. `Err` without the `fndsa-sign` feature.
pub fn fn_dsa_512_sign(signing_key: &[u8], msg: &[u8], seed: &[u8]) -> Result<Vec<u8>, String> {
    fn_dsa_sign("fn_dsa_512_sign", FN_DSA_512_SECRET_KEY_BYTES, signing_key, msg, seed)
}

/// FN-DSA-1024 sign over raw `msg` (no pre-hash) with a 32-byte RNG seed. `Err` without the `fndsa-sign` feature.
pub fn fn_dsa_1024_sign(signing_key: &[u8], msg: &[u8], seed: &[u8]) -> Result<Vec<u8>, String> {
    fn_dsa_sign("fn_dsa_1024_sign", FN_DSA_1024_SECRET_KEY_BYTES, signing_key, msg, seed)
}

/// FN-DSA-512 verify over raw bytes (total).
pub fn fn_dsa_512_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    pq_verify(Pq::FnDsa512, public_key, msg, sig)
}

/// FN-DSA-1024 verify over raw bytes (total).
pub fn fn_dsa_1024_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    pq_verify(Pq::FnDsa1024, public_key, msg, sig)
}

/// [`fn_dsa_512_verify`] over canonical base64url key and signature.
pub fn fn_dsa_512_verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
    match (decode_b64u_strict(public_key_b64u, Some(FN_DSA_512_PUBLIC_KEY_BYTES)), decode_b64u_strict(sig_b64u, Some(FN_DSA_512_SIGNATURE_BYTES))) {
        (Some(pk), Some(sg)) => fn_dsa_512_verify(&pk, msg, &sg),
        _ => false,
    }
}

/// [`fn_dsa_1024_verify`] over canonical base64url key and signature.
pub fn fn_dsa_1024_verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
    match (decode_b64u_strict(public_key_b64u, Some(FN_DSA_1024_PUBLIC_KEY_BYTES)), decode_b64u_strict(sig_b64u, Some(FN_DSA_1024_SIGNATURE_BYTES))) {
        (Some(pk), Some(sg)) => fn_dsa_1024_verify(&pk, msg, &sg),
        _ => false,
    }
}

// ---- LESS (feature `less`) ------------------------------------------------------------------------------------------------

/// Availability of the LESS backend; `reason` says why it is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LessBackendStatus {
    pub available: bool,
    pub reason: Option<String>,
}

/// Whether the LESS suites are compiled in (the `less` feature).
pub fn is_less_backend_active() -> bool {
    cfg!(feature = "less")
}

/// Availability and reason for LESS; never fails.
pub fn less_backend_status() -> LessBackendStatus {
    if is_less_backend_active() {
        LessBackendStatus { available: true, reason: None }
    } else {
        LessBackendStatus { available: false, reason: Some("this build has no LESS backend (enable the `less` cargo feature)".into()) }
    }
}

/// A LESS key pair: the 97,484-byte public key and the 32-byte secret seed.
pub struct LessKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "less")]
extern "C" {
    fn atlas_less_cat1_keygen(pk: *mut u8, pk_cap: usize, sk: *mut u8, sk_cap: usize, seed: *const u8, seed_len: usize) -> core::ffi::c_int;
    fn atlas_less_cat1_sign(
        sk: *const u8,
        sk_len: usize,
        msg: *const u8,
        msg_len: usize,
        seed: *const u8,
        seed_len: usize,
        sig: *mut u8,
        sig_cap: usize,
        sig_len: *mut usize,
    ) -> core::ffi::c_int;
}

/// Deterministic LESS keygen from a 32-byte seed. `Err` without the `less` feature.
pub fn less_cat1_keygen(seed: &[u8]) -> Result<LessKeyPair, String> {
    #[cfg(feature = "less")]
    {
        let seed = seed_of("less_cat1_keygen", seed, LESS_SEED_BYTES)?;
        let mut pk = vec![0u8; LESS_CAT1_PUBLIC_KEY_BYTES];
        let mut sk = Zeroizing::new(vec![0u8; LESS_CAT1_SECRET_KEY_BYTES]);
        // SAFETY: every pointer is valid for the capacity passed with it; the C side writes only within them.
        let ok = unsafe { atlas_less_cat1_keygen(pk.as_mut_ptr(), pk.len(), sk.as_mut_ptr(), sk.len(), seed.as_ptr(), seed.len()) };
        if ok != 1 {
            return Err("less_cat1_keygen: the LESS backend refused".into());
        }
        Ok(LessKeyPair { public_key: pk, secret_key: sk })
    }
    #[cfg(not(feature = "less"))]
    {
        let _ = seed;
        Err(less_backend_status().reason.unwrap_or_default())
    }
}

/// LESS detached signature (1153..1329 bytes) with an explicit 32-byte RNG seed. `Err` without the `less` feature.
pub fn less_cat1_sign(secret_key: &[u8], msg: &[u8], seed: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(feature = "less")]
    {
        let seed = seed_of("less_cat1_sign", seed, LESS_SEED_BYTES)?;
        if secret_key.len() != LESS_CAT1_SECRET_KEY_BYTES {
            return Err("less_cat1_sign: bad secret key length".into());
        }
        let mut sig = vec![0u8; LESS_CAT1_SIGNATURE_MAX_BYTES];
        let mut n = 0usize;
        // SAFETY: every pointer is valid for the length passed with it; `n` receives the written length.
        let ok = unsafe {
            atlas_less_cat1_sign(secret_key.as_ptr(), secret_key.len(), msg.as_ptr(), msg.len(), seed.as_ptr(), seed.len(), sig.as_mut_ptr(), sig.len(), &mut n)
        };
        if ok != 1 || n > sig.len() {
            return Err("less_cat1_sign: the LESS backend refused".into());
        }
        sig.truncate(n);
        Ok(sig)
    }
    #[cfg(not(feature = "less"))]
    {
        let _ = (secret_key, msg, seed);
        Err(less_backend_status().reason.unwrap_or_default())
    }
}

fn less_sig_len_ok(n: usize) -> bool {
    (LESS_CAT1_SIGNATURE_MIN_BYTES..=LESS_CAT1_SIGNATURE_MAX_BYTES).contains(&n) && (LESS_CAT1_SIGNATURE_MAX_BYTES - n) % LESS_CAT1_SIGNATURE_STEP_BYTES == 0
}

/// LESS verify over raw bytes (total). Without the `less` feature: `false` (fail closed).
pub fn less_cat1_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if public_key.len() != LESS_CAT1_PUBLIC_KEY_BYTES || !less_sig_len_ok(sig.len()) {
        return false;
    }
    #[cfg(feature = "less")]
    {
        pq_verify(Pq::LessCat1, public_key, msg, sig)
    }
    #[cfg(not(feature = "less"))]
    {
        let _ = msg;
        false
    }
}

/// [`less_cat1_verify`] over canonical base64url key and signature.
pub fn less_cat1_verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
    match (decode_b64u_strict(public_key_b64u, Some(LESS_CAT1_PUBLIC_KEY_BYTES)), decode_b64u_strict(sig_b64u, None)) {
        (Some(pk), Some(sg)) => less_cat1_verify(&pk, msg, &sg),
        _ => false,
    }
}

// ---- public-key encoders (b64u of the raw key, the `pq_pk` field) -------------------------------------------------------------

/// base64url of an ML-DSA-65 public key.
pub fn encode_ml_dsa_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}
/// base64url of an ML-DSA-87 public key.
pub fn encode_ml_dsa_87_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}
/// base64url of an SLH-DSA-SHA2-128f public key.
pub fn encode_slh_dsa_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}
/// base64url of an SLH-DSA-SHA2-256s public key.
pub fn encode_slh_dsa_256s_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}
/// base64url of an FN-DSA verifying key (either variant).
pub fn encode_fn_dsa_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}
/// base64url of a LESS public key.
pub fn encode_less_public_key(public_key: &[u8]) -> String {
    b64(public_key)
}

// ---- pinned PQ key resolution -------------------------------------------------------------------------------------------------

/// Where a verifier's authorisation for a PQ key comes from (`PqKeySource`).
#[derive(Debug, Clone, Default)]
pub struct PqKeySource {
    /// Pinned PQ public keys by Ed25519 identity.
    pub pq_pins: Option<HashMap<String, String>>,
    /// The holder's `holder_pq` commitment: the artifact's `pq_pk` must hash to it.
    pub holder_pq: Option<String>,
    /// A PQ key the verifier itself configured; the artifact's own `pq_pk` is then not consulted.
    pub trusted_pk: Option<String>,
}

/// THE PQ key choke point: the key to verify under, or `None` (refuse) when no verifier-side authority vouches for the artifact's
/// `pq_pk` (`trusted_pk`, then the identity's pin, then the `holder_pq` commitment).
pub fn resolve_pq_verify_key(identity: &str, artifact_pk: Option<&str>, src: Option<&PqKeySource>) -> Option<PinnedPq> {
    let src = src?;
    let pk = artifact_pk.map(|s| Value::String(s.to_string()));
    let holder_pq = src.holder_pq.as_ref().map(|s| Value::String(s.clone()));
    pinned::resolve_pq_key(Some(identity), pk.as_ref(), holder_pq.as_ref(), src.pq_pins.as_ref(), src.trusted_pk.as_deref())
}

/// The PQ verify key of a chain-leaf / threshold-share signature from its holder's `holder_pq` commitment. `None` for an ed25519
/// artifact (no key needed) and when the artifact's `pq_pk` is not the committed key (the signature check then fails closed).
pub fn holder_pq_key(alg: Option<&str>, holder: &str, artifact_pq_pk: Option<&str>, holder_pq: Option<&str>) -> Option<PinnedPq> {
    let needs = match alg {
        None => false,
        Some(a) => REGISTERED_SUITES.contains(&a) && a != DEFAULT_SIG_ALG,
    };
    if !needs {
        return None;
    }
    let src = PqKeySource { holder_pq: holder_pq.map(str::to_string), ..Default::default() };
    resolve_pq_verify_key(holder, artifact_pq_pk, Some(&src))
}

/// The `holder_pq` commitment of a holder whose PQ public key is `pq_public_key_b64u`.
pub fn holder_pq_commitment_of(pq_public_key_b64u: &str) -> String {
    holder_pq_commitment(pq_public_key_b64u)
}

/// Verify `sig` / `pq_sig` over `msg` under the suite `alg` (absent = ed25519): the Ed25519 half under `ed_pub`, the PQ half
/// ONLY under the pinned key `pq`. FAIL CLOSED: an unknown or unimplemented suite, a missing component, or any invalid one is
/// `false`. Total.
pub fn verify_with_suite(alg: Option<&Value>, ed_pub: &str, pq: Option<&PinnedPq>, msg: &[u8], sig: Option<&Value>, pq_sig: Option<&Value>) -> bool {
    crate::verify_suite(alg, ed_pub, pq, msg, sig, pq_sig)
}

/// [`verify_with_suite`] for a leaf (holder) signature: the single agility seam of the PCActn leaf and threshold shares.
pub fn verify_leaf_suite(alg: Option<&Value>, holder: &str, pq: Option<&PinnedPq>, message: &[u8], sig: Option<&Value>, pq_sig: Option<&Value>) -> bool {
    verify_with_suite(alg, holder, pq, message, sig, pq_sig)
}

// ---- LAMPS composite signature (ML-DSA-65 + Ed25519) ---------------------------------------------------------------------------

/// `M' = Prefix || Label || len(ctx) || ctx || SHA-512(message)`. `Err` when `ctx` exceeds 255 bytes.
pub fn composite_representative(message: &[u8], ctx: &[u8]) -> Result<Vec<u8>, String> {
    if ctx.len() > 255 {
        return Err("compositeRepresentative: ctx exceeds 255 bytes".into());
    }
    let mut m = COMPOSITE_PREFIX.as_bytes().to_vec();
    m.extend_from_slice(COMPOSITE_LABEL.as_bytes());
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(&Sha512::digest(message));
    Ok(m)
}

/// A composite signature `ml-dsa-65 signature || Ed25519 signature` over `M'` (3373 bytes).
pub fn composite_sign(ed25519_seed: &[u8; 32], ml_dsa_secret_key: &[u8], message: &[u8], ctx: &[u8]) -> Result<Vec<u8>, String> {
    let m = composite_representative(message, ctx)?;
    let mut sig = ml_dsa_65_sign(ml_dsa_secret_key, &m)?;
    sig.extend_from_slice(&KeyPair::from_seed(ed25519_seed).sign(&m));
    Ok(sig)
}

/// Verify a composite signature: BOTH halves over the same `M'` must verify. Total; a wrong length or an over-long `ctx` is `false`.
pub fn composite_verify(ed25519_pub: &[u8], ml_dsa_pub: &[u8], message: &[u8], signature: &[u8], ctx: &[u8]) -> bool {
    if signature.len() != COMPOSITE_SIGNATURE_BYTES || ed25519_pub.len() != 32 {
        return false;
    }
    let Ok(m) = composite_representative(message, ctx) else { return false };
    let (ml, ed) = signature.split_at(ML_DSA_65_SIGNATURE_BYTES);
    ml_dsa_65_verify(ml_dsa_pub, &m, ml) & verify_b64u(&b64(ed25519_pub), &m, &b64(ed))
}
