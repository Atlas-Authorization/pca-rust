//! Hybrid key encapsulation. Three KEMs that each establish a 32-byte shared secret (no cipher is shipped):
//!
//! 1. X25519 + ML-KEM-768 with an HKDF-SHA256 combiner, suite [`HYBRID_KEM_SUITE`]: [`hybrid_kem_keygen`], [`hybrid_encapsulate`],
//!    [`hybrid_decapsulate`];
//! 2. the same at ML-KEM-1024 under its own domain separator, suite [`HYBRID1024_KEM_SUITE`]: the `*_1024` functions;
//! 3. X-Wing (draft-connolly-cfrg-xwing-kem-09, SHA3-256 combiner), suite [`XWING_SUITE`], byte-interoperable with other X-Wing
//!    implementations: [`xwing_keygen`], [`xwing_encapsulate`], [`xwing_decapsulate`];
//!
//! plus the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM keys ([`ml_kem_encapsulation_key_check`],
//! [`ml_kem_decapsulation_key_check`]) and the base64url text forms.
//!
//! Layouts. Hybrid: public key = X25519 (32) || ML-KEM encapsulation key; ciphertext = ephemeral X25519 public key (32) || ML-KEM
//! ciphertext; secret key = X25519 secret (32) || expanded ML-KEM decapsulation key. X-Wing is the other way round: public key =
//! ML-KEM-768 encapsulation key (1184) || X25519 (32), ciphertext = ML-KEM ciphertext (1088) || X25519 (32), secret key = the
//! 32-byte seed.
//!
//! Every primitive comes from a vetted crate: ML-KEM from `ml-kem`, X25519 from `curve25519-dalek`, SHA3 / SHAKE from `sha3`,
//! HMAC-SHA256 (for HKDF, RFC 5869) from `hmac`. FAILS CLOSED: a key or ciphertext of the wrong length, an ML-KEM encapsulation
//! key with a coefficient outside the field (FIPS 203 modulus check) and an X25519 peer that yields the all-zero shared secret (a
//! low-order point) are refused. Decapsulation of a well-sized but tampered ciphertext does not fail: ML-KEM answers with its
//! implicit-rejection secret, so the two sides simply do not agree.

use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, MlKem768, MlKem768Params, B32};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256};
use zeroize::Zeroizing;

const X25519_LEN: usize = 32;
const SS_LEN: usize = 32;

pub const HYBRID_PUBLIC_KEY_LEN: usize = 1216;
pub const HYBRID_CIPHERTEXT_LEN: usize = 1120;
pub const HYBRID_SHARED_SECRET_LEN: usize = SS_LEN;
pub const HYBRID_KEM_SUITE: &str = "x25519-ml-kem-768";
pub const HYBRID1024_PUBLIC_KEY_LEN: usize = 1600;
pub const HYBRID1024_CIPHERTEXT_LEN: usize = 1600;
pub const HYBRID1024_SHARED_SECRET_LEN: usize = SS_LEN;
pub const HYBRID1024_KEM_SUITE: &str = "x25519-ml-kem-1024";
pub const XWING_SUITE: &str = "xwing";
pub const XWING_SEED_LEN: usize = 32;
pub const XWING_SECRET_KEY_LEN: usize = XWING_SEED_LEN;
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
pub const XWING_SHARED_SECRET_LEN: usize = SS_LEN;
pub const XWING_ESEED_LEN: usize = 64;
/// The X-Wing combiner label, the ASCII text `\.//^\`.
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

const DOMAIN_768: &[u8] = b"atlas-pca/kem/x25519-ml-kem-768/v1\0";
const DOMAIN_1024: &[u8] = b"atlas-pca/kem/x25519-ml-kem-1024/v1\0";
/// The ML-KEM field modulus.
const Q: u16 = 3329;

/// A KEM key pair. The secret key is wiped when dropped.
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// The sender's half of an encapsulation: the ciphertext to send and the 32-byte shared secret.
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

// ---- the primitives (vetted crates only) -------------------------------------------------------------------------------------------

macro_rules! mlkem_level {
    ($name:ident, $kem:ty, $params:ty) => {
        mod $name {
            use super::*;
            type Dk = DecapsulationKey<$params>;
            type Ek = EncapsulationKey<$params>;

            /// Key generation from the FIPS 203 seed halves `d` and `z` (32 bytes each): `(ek, expanded dk)`.
            pub(super) fn keygen(d: &[u8], z: &[u8]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
                let (mut dd, mut zz) = (B32::default(), B32::default());
                dd.copy_from_slice(d);
                zz.copy_from_slice(z);
                let (dk, ek) = <$kem>::generate_deterministic(&dd, &zz);
                (ek.as_bytes().to_vec(), Zeroizing::new(dk.as_bytes().to_vec()))
            }

            /// Encapsulation to `ek` with the 32-byte message `m`: `(ciphertext, shared secret)`.
            pub(super) fn encaps(ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
                let enc = Encoded::<Ek>::try_from(ek).map_err(|_| "ML-KEM encapsulation key has the wrong length".to_string())?;
                let key = Ek::from_bytes(&enc);
                let mut mm = B32::default();
                mm.copy_from_slice(m);
                let (ct, ss) = key.encapsulate_deterministic(&mm).map_err(|_| "ML-KEM encapsulation failed".to_string())?;
                let mut out = [0u8; 32];
                out.copy_from_slice(ss.as_slice());
                Ok((ct.to_vec(), out))
            }

            /// Decapsulation with an EXPANDED decapsulation key (implicit rejection on a tampered ciphertext).
            pub(super) fn decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; 32], String> {
                let enc = Encoded::<Dk>::try_from(dk).map_err(|_| "ML-KEM decapsulation key has the wrong length".to_string())?;
                let key = Dk::from_bytes(&enc);
                let mut c = ml_kem::Ciphertext::<$kem>::default();
                if c.len() != ct.len() {
                    return Err("ML-KEM ciphertext has the wrong length".into());
                }
                c.copy_from_slice(ct);
                let ss = key.decapsulate(&c).map_err(|_| "ML-KEM decapsulation failed".to_string())?;
                let mut out = [0u8; 32];
                out.copy_from_slice(ss.as_slice());
                Ok(out)
            }
        }
    };
}
mlkem_level!(k768, MlKem768, MlKem768Params);
mlkem_level!(k1024, MlKem1024, MlKem1024Params);

#[derive(Clone, Copy, PartialEq)]
enum Level {
    L768,
    L1024,
}

impl Level {
    fn of(level: u32) -> Result<Level, String> {
        match level {
            768 => Ok(Level::L768),
            1024 => Ok(Level::L1024),
            other => Err(format!("unknown ML-KEM level {other} (768 or 1024)")),
        }
    }
    /// The module rank k.
    fn k(self) -> usize {
        if self == Level::L768 {
            3
        } else {
            4
        }
    }
    fn ek_len(self) -> usize {
        384 * self.k() + 32
    }
    fn dk_len(self) -> usize {
        768 * self.k() + 96
    }
    fn ct_len(self) -> usize {
        if self == Level::L768 {
            1088
        } else {
            1568
        }
    }
    fn domain(self) -> &'static [u8] {
        if self == Level::L768 {
            DOMAIN_768
        } else {
            DOMAIN_1024
        }
    }
    fn keygen(self, d: &[u8], z: &[u8]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        match self {
            Level::L768 => k768::keygen(d, z),
            Level::L1024 => k1024::keygen(d, z),
        }
    }
    fn encaps(self, ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
        match self {
            Level::L768 => k768::encaps(ek, m),
            Level::L1024 => k1024::encaps(ek, m),
        }
    }
    fn decaps(self, dk: &[u8], ct: &[u8]) -> Result<[u8; 32], String> {
        if dk.len() != self.dk_len() {
            return Err("ML-KEM decapsulation key has the wrong length".into());
        }
        match self {
            Level::L768 => k768::decaps(dk, ct),
            Level::L1024 => k1024::decaps(dk, ct),
        }
    }
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

/// The X25519 public key of a raw 32-byte secret (clamped by the scalar multiplication, RFC 7748).
fn x25519_public(secret: &[u8]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(arr32(secret)).to_bytes()
}

/// The X25519 shared secret. An all-zero result (the peer sent a low-order point) is refused.
fn x25519_shared(secret: &[u8], peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let ss = Zeroizing::new(MontgomeryPoint(arr32(peer)).mul_clamped(arr32(secret)).to_bytes());
    if ss.iter().fold(0u8, |acc, b| acc | b) == 0 {
        return Err("X25519: the peer key is a low-order point (all-zero shared secret)".into());
    }
    Ok(ss)
}

/// HKDF-SHA256 (RFC 5869) with no salt and a 32-byte output: extract under the all-zero salt, then one expand block.
fn hkdf_sha256_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).expect("hmac accepts any key length");
    Mac::update(&mut extract, ikm);
    let prk = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk[..]).expect("hmac accepts any key length");
    Mac::update(&mut expand, info);
    Mac::update(&mut expand, &[1u8]);
    expand.finalize().into_bytes().into()
}

fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    <Sha3_256 as sha3::Digest>::digest(parts.concat()).into()
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    crate::agent::rand_bytes::<N>().map(Zeroizing::new)
}

// ---- FIPS 203 key checks -----------------------------------------------------------------------------------------------------------

/// Every 12-bit coefficient of the encoded polynomial vector is below the field modulus.
fn coefficients_reduced(ek: &[u8], k: usize) -> bool {
    ek[..384 * k].chunks_exact(3).all(|c| {
        let lo = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let hi = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        lo < Q && hi < Q
    })
}

/// The FIPS 203 section 7.2 encapsulation key check for an imported ML-KEM key: the length for `level` (768 or 1024) and the
/// modulus check. `Err` for an unknown level.
pub fn ml_kem_encapsulation_key_check(level: u32, ek: &[u8]) -> Result<bool, String> {
    let l = Level::of(level)?;
    Ok(ek.len() == l.ek_len() && coefficients_reduced(ek, l.k()))
}

/// The FIPS 203 section 7.3 decapsulation key check for an imported EXPANDED ML-KEM key: the length for `level`, the embedded
/// hash against SHA3-256 of the embedded encapsulation key, and that key's own check. `Err` for an unknown level.
pub fn ml_kem_decapsulation_key_check(level: u32, dk: &[u8]) -> Result<bool, String> {
    let l = Level::of(level)?;
    if dk.len() != l.dk_len() {
        return Ok(false);
    }
    let k = l.k();
    let (ek, h) = (&dk[384 * k..768 * k + 32], &dk[768 * k + 32..768 * k + 64]);
    let want = sha3_256(&[ek]);
    let diff = want.iter().zip(h).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    Ok(diff == 0 && coefficients_reduced(ek, k))
}

/// The expanded FIPS 203 decapsulation key of the seed `d || z` (test support: it is how a corpus names a secret key).
#[doc(hidden)]
pub fn ml_kem_expanded_dk(level: u32, d: &[u8], z: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let l = Level::of(level)?;
    if d.len() != 32 || z.len() != 32 {
        return Err("the ML-KEM seed halves d and z are 32 bytes each".into());
    }
    Ok(l.keygen(d, z).1)
}

// ---- hybrid X25519 + ML-KEM --------------------------------------------------------------------------------------------------------

fn combine(l: Level, ss_mlkem: &[u8], ss_x: &[u8], eph_pub: &[u8], recip_x: &[u8]) -> [u8; 32] {
    let ikm = Zeroizing::new([ss_mlkem, ss_x, eph_pub, recip_x].concat());
    hkdf_sha256_32(&ikm, l.domain())
}

/// `rng` = X25519 secret (32) || d (32) || z (32).
fn hybrid_keygen(l: Level, rng: &[u8]) -> Result<KemKeyPair, String> {
    if rng.len() != 96 {
        return Err("hybrid keygen needs 96 bytes of randomness".into());
    }
    let (x, d, z) = (&rng[..32], &rng[32..64], &rng[64..]);
    let (ek, dk) = l.keygen(d, z);
    let mut sk = Zeroizing::new(Vec::with_capacity(32 + dk.len()));
    sk.extend_from_slice(x);
    sk.extend_from_slice(&dk);
    Ok(KemKeyPair { public_key: [&x25519_public(x)[..], &ek[..]].concat(), secret_key: sk })
}

/// `rng` = ephemeral X25519 secret (32) || ML-KEM message (32).
fn hybrid_encaps(l: Level, who: &str, public_key: &[u8], rng: &[u8]) -> Result<Encapsulation, String> {
    let want = X25519_LEN + l.ek_len();
    if public_key.len() != want {
        return Err(format!("{who}: public key must be {want} bytes (got {})", public_key.len()));
    }
    if rng.len() != 64 {
        return Err(format!("{who}: encapsulation needs 64 bytes of randomness"));
    }
    let (recip_x, recip_mlkem) = public_key.split_at(X25519_LEN);
    let (eph, m) = rng.split_at(32);
    let eph_pub = x25519_public(eph);
    let ss_x = x25519_shared(eph, recip_x).map_err(|e| format!("{who}: {e}"))?;
    if !coefficients_reduced(recip_mlkem, l.k()) {
        return Err(format!("{who}: ML-KEM encapsulation key fails the FIPS 203 modulus check"));
    }
    let (ct, ss_mlkem) = l.encaps(recip_mlkem, m).map_err(|e| format!("{who}: {e}"))?;
    let ss_mlkem = Zeroizing::new(ss_mlkem);
    Ok(Encapsulation { ciphertext: [&eph_pub[..], &ct[..]].concat(), shared_secret: combine(l, &ss_mlkem[..], &ss_x[..], &eph_pub, recip_x) })
}

fn hybrid_decaps(l: Level, who: &str, ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], String> {
    let want = X25519_LEN + l.ct_len();
    if ciphertext.len() != want {
        return Err(format!("{who}: ciphertext must be {want} bytes (got {})", ciphertext.len()));
    }
    if secret_key.len() <= X25519_LEN {
        return Err(format!("{who}: malformed secret key"));
    }
    let (eph_pub, mlkem_ct) = ciphertext.split_at(X25519_LEN);
    let (x_priv, mlkem_priv) = secret_key.split_at(X25519_LEN);
    let ss_x = x25519_shared(x_priv, eph_pub).map_err(|e| format!("{who}: {e}"))?;
    let ss_mlkem = Zeroizing::new(l.decaps(mlkem_priv, mlkem_ct).map_err(|e| format!("{who}: {e}"))?);
    Ok(combine(l, &ss_mlkem[..], &ss_x[..], eph_pub, &x25519_public(x_priv)))
}

/// A fresh X25519 + ML-KEM-768 key pair (1216-byte public key, 2432-byte secret key).
pub fn hybrid_kem_keygen() -> Result<KemKeyPair, String> {
    hybrid_keygen(Level::L768, &random::<96>()?[..])
}

/// [`hybrid_kem_keygen`] from caller-supplied randomness `x (32) || d (32) || z (32)` (test support).
#[doc(hidden)]
pub fn hybrid_kem_keygen_derand(rng: &[u8]) -> Result<KemKeyPair, String> {
    hybrid_keygen(Level::L768, rng)
}

/// Encapsulate to a recipient's X25519 + ML-KEM-768 public key: the 1120-byte ciphertext and the shared secret.
pub fn hybrid_encapsulate(recipient_public_key: &[u8]) -> Result<Encapsulation, String> {
    hybrid_encaps(Level::L768, "hybridEncapsulate", recipient_public_key, &random::<64>()?[..])
}

/// [`hybrid_encapsulate`] from caller-supplied randomness `ephemeral X25519 secret (32) || ML-KEM message (32)` (test support).
#[doc(hidden)]
pub fn hybrid_encapsulate_derand(recipient_public_key: &[u8], rng: &[u8]) -> Result<Encapsulation, String> {
    hybrid_encaps(Level::L768, "hybridEncapsulate", recipient_public_key, rng)
}

/// Recover the shared secret of an X25519 + ML-KEM-768 ciphertext with the recipient's secret key.
pub fn hybrid_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], String> {
    hybrid_decaps(Level::L768, "hybridDecapsulate", ciphertext, secret_key)
}

/// A fresh X25519 + ML-KEM-1024 key pair (1600-byte public key, 3200-byte secret key).
pub fn hybrid_kem_1024_keygen() -> Result<KemKeyPair, String> {
    hybrid_keygen(Level::L1024, &random::<96>()?[..])
}

/// [`hybrid_kem_1024_keygen`] from caller-supplied randomness `x (32) || d (32) || z (32)` (test support).
#[doc(hidden)]
pub fn hybrid_kem_1024_keygen_derand(rng: &[u8]) -> Result<KemKeyPair, String> {
    hybrid_keygen(Level::L1024, rng)
}

/// Encapsulate to a recipient's X25519 + ML-KEM-1024 public key: the 1600-byte ciphertext and the shared secret.
pub fn hybrid_encapsulate_1024(recipient_public_key: &[u8]) -> Result<Encapsulation, String> {
    hybrid_encaps(Level::L1024, "hybridEncapsulate1024", recipient_public_key, &random::<64>()?[..])
}

/// [`hybrid_encapsulate_1024`] from caller-supplied randomness `ephemeral X25519 secret (32) || ML-KEM message (32)` (test support).
#[doc(hidden)]
pub fn hybrid_encapsulate_1024_derand(recipient_public_key: &[u8], rng: &[u8]) -> Result<Encapsulation, String> {
    hybrid_encaps(Level::L1024, "hybridEncapsulate1024", recipient_public_key, rng)
}

/// Recover the shared secret of an X25519 + ML-KEM-1024 ciphertext with the recipient's secret key.
pub fn hybrid_decapsulate_1024(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], String> {
    hybrid_decaps(Level::L1024, "hybridDecapsulate1024", ciphertext, secret_key)
}

// ---- X-Wing ------------------------------------------------------------------------------------------------------------------------

struct XWingExpanded {
    mlkem_secret: Zeroizing<Vec<u8>>,
    mlkem_public: Vec<u8>,
    x_secret: Zeroizing<[u8; 32]>,
    x_public: [u8; 32],
}

/// SHAKE256(seed, 96) = d (32) || z (32) || X25519 secret (32).
fn expand_xwing_key(seed: &[u8]) -> Result<XWingExpanded, String> {
    if seed.len() != XWING_SEED_LEN {
        return Err(format!("expandXWingKey: seed must be {XWING_SEED_LEN} bytes (got {})", seed.len()));
    }
    let mut xof = Shake256::default();
    Update::update(&mut xof, seed);
    let mut expanded = Zeroizing::new([0u8; 96]);
    xof.finalize_xof().read(&mut expanded[..]);
    let (mlkem_public, mlkem_secret) = Level::L768.keygen(&expanded[..32], &expanded[32..64]);
    let x_secret = Zeroizing::new(arr32(&expanded[64..]));
    let x_public = x25519_public(&x_secret[..]);
    Ok(XWingExpanded { mlkem_secret, mlkem_public, x_secret, x_public })
}

fn xwing_combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    sha3_256(&[ss_m, ss_x, ct_x, pk_x, &XWING_LABEL])
}

/// An X-Wing key pair from a 32-byte seed (`None`: a fresh random seed). The secret key IS the seed.
pub fn xwing_keygen(seed: Option<&[u8]>) -> Result<KemKeyPair, String> {
    let sk = match seed {
        Some(s) => Zeroizing::new(s.to_vec()),
        None => Zeroizing::new(random::<32>()?.to_vec()),
    };
    let ex = expand_xwing_key(&sk)?;
    Ok(KemKeyPair { public_key: [&ex.mlkem_public[..], &ex.x_public[..]].concat(), secret_key: sk })
}

/// X-Wing encapsulation from the 64-byte encapsulation seed `ML-KEM message (32) || ephemeral X25519 secret (32)` (the draft's
/// derandomised form; reproduces its test vectors).
pub fn xwing_encapsulate_derand(recipient_public_key: &[u8], eseed: &[u8]) -> Result<Encapsulation, String> {
    if recipient_public_key.len() != XWING_PUBLIC_KEY_LEN {
        return Err(format!("xwingEncapsulateDerand: public key must be {XWING_PUBLIC_KEY_LEN} bytes (got {})", recipient_public_key.len()));
    }
    if eseed.len() != XWING_ESEED_LEN {
        return Err(format!("xwingEncapsulateDerand: eseed must be {XWING_ESEED_LEN} bytes (got {})", eseed.len()));
    }
    let (pk_m, pk_x) = recipient_public_key.split_at(Level::L768.ek_len());
    let (m, ek_x) = eseed.split_at(32);
    if !coefficients_reduced(pk_m, 3) {
        return Err("xwingEncapsulateDerand: ML-KEM encapsulation key fails the FIPS 203 modulus check".into());
    }
    let (ct_m, ss_m) = Level::L768.encaps(pk_m, m).map_err(|e| format!("xwingEncapsulateDerand: {e}"))?;
    let ss_m = Zeroizing::new(ss_m);
    let ct_x = x25519_public(ek_x);
    let ss_x = x25519_shared(ek_x, pk_x).map_err(|e| format!("xwingEncapsulateDerand: {e}"))?;
    Ok(Encapsulation { ciphertext: [&ct_m[..], &ct_x[..]].concat(), shared_secret: xwing_combiner(&ss_m[..], &ss_x[..], &ct_x, pk_x) })
}

/// Encapsulate to a recipient's X-Wing public key: the 1120-byte ciphertext and the shared secret.
pub fn xwing_encapsulate(recipient_public_key: &[u8]) -> Result<Encapsulation, String> {
    xwing_encapsulate_derand(recipient_public_key, &random::<64>()?[..])
}

/// Recover the shared secret of an X-Wing ciphertext with the recipient's 32-byte secret key (the seed).
pub fn xwing_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], String> {
    if ciphertext.len() != XWING_CIPHERTEXT_LEN {
        return Err(format!("xwingDecapsulate: ciphertext must be {XWING_CIPHERTEXT_LEN} bytes (got {})", ciphertext.len()));
    }
    let ex = expand_xwing_key(secret_key)?;
    let (ct_m, ct_x) = ciphertext.split_at(Level::L768.ct_len());
    let ss_m = Zeroizing::new(Level::L768.decaps(&ex.mlkem_secret, ct_m).map_err(|e| format!("xwingDecapsulate: {e}"))?);
    let ss_x = x25519_shared(&ex.x_secret[..], ct_x).map_err(|e| format!("xwingDecapsulate: {e}"))?;
    Ok(xwing_combiner(&ss_m[..], &ss_x[..], ct_x, &ex.x_public))
}

// ---- text forms --------------------------------------------------------------------------------------------------------------------

fn decode(s: &str) -> Result<Vec<u8>, String> {
    crate::decode_b64u_strict(s, None).ok_or_else(|| "not canonical unpadded base64url".to_string())
}

/// Unpadded base64url of a hybrid public key (no length check).
pub fn encode_hybrid_public_key(k: &[u8]) -> String {
    crate::b64_encode(k)
}
/// The bytes of a base64url hybrid public key. STRICT: padding, the standard alphabet, whitespace and non-zero trailing bits are
/// refused; the decoded length is not checked.
pub fn decode_hybrid_public_key(s: &str) -> Result<Vec<u8>, String> {
    decode(s)
}
/// Unpadded base64url of a hybrid ciphertext (no length check).
pub fn encode_hybrid_ciphertext(c: &[u8]) -> String {
    crate::b64_encode(c)
}
/// The bytes of a base64url hybrid ciphertext (strict, see [`decode_hybrid_public_key`]).
pub fn decode_hybrid_ciphertext(s: &str) -> Result<Vec<u8>, String> {
    decode(s)
}
/// Unpadded base64url of an X-Wing public key (no length check).
pub fn encode_xwing_public_key(k: &[u8]) -> String {
    crate::b64_encode(k)
}
/// The bytes of a base64url X-Wing public key (strict, see [`decode_hybrid_public_key`]).
pub fn decode_xwing_public_key(s: &str) -> Result<Vec<u8>, String> {
    decode(s)
}
/// Unpadded base64url of an X-Wing ciphertext (no length check).
pub fn encode_xwing_ciphertext(c: &[u8]) -> String {
    crate::b64_encode(c)
}
/// The bytes of a base64url X-Wing ciphertext (strict, see [`decode_hybrid_public_key`]).
pub fn decode_xwing_ciphertext(s: &str) -> Result<Vec<u8>, String> {
    decode(s)
}
