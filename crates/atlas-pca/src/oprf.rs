//! RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 plus the PCA private-revocation and private-rate-limit layer
//! (`@atlasauth/pca-oprf`). The group and scalars are curve25519-dalek's vetted `RistrettoPoint` / `Scalar` (constant-time
//! multiplication and inversion; no branching on a secret except the reference's own refusal of the zero scalar); only the RFC's
//! protocol steps (expand_message_xmd, DLEQ proofs, finalize hashes) are written here.
//!
//! Native-stricter than the reference: an unknown mode, or `poprf` on the non-POPRF entry points, is refused (the reference silently
//! takes the verifiable path). Every refusal is an `Err(String)`; nothing here panics on hostile input.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rsa::BigUint;
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const SUITE_ID: &str = "ristretto255-SHA512";
/// Serialized element / scalar length (`Ne`, `Ns`) and OPRF output length (`Nh`).
pub const ELEMENT_BYTES: usize = 32;
pub const SCALAR_BYTES: usize = 32;
pub const OUTPUT_BYTES: usize = 64;
const MAX_FRAMED: usize = 0xFFFF;

fn mode_byte(mode: &str) -> Result<u8, String> {
    match mode {
        "oprf" => Ok(0),
        "voprf" => Ok(1),
        "poprf" => Ok(2),
        m => Err(format!("unknown OPRF mode {m:?}")),
    }
}

/// `"OPRFV1-" || I2OSP(mode, 1) || "-" || identifier`.
fn context(mode: &str) -> Result<Vec<u8>, String> {
    let mut c = b"OPRFV1-".to_vec();
    c.push(mode_byte(mode)?);
    c.extend_from_slice(format!("-{SUITE_ID}").as_bytes());
    Ok(c)
}

fn server_mode(mode: &str) -> Result<(), String> {
    if mode == "oprf" || mode == "voprf" {
        Ok(())
    } else {
        Err(format!("mode must be 'oprf' or 'voprf', got {mode:?}"))
    }
}

fn framed(b: &[u8], what: &str) -> Result<(), String> {
    if b.len() > MAX_FRAMED {
        return Err(format!("{what}: {} bytes exceeds the {MAX_FRAMED}-byte limit (RFC 9497 2-byte length framing)", b.len()));
    }
    Ok(())
}

fn i2osp2(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

/// The reference multiply: it refuses the zero scalar.
fn mul(p: &RistrettoPoint, k: &Scalar) -> Result<RistrettoPoint, String> {
    if *k == Scalar::ZERO {
        return Err("expected valid scalar: 1 <= n < group order".into());
    }
    Ok(*p * *k)
}

fn base_mult(k: &Scalar) -> Result<RistrettoPoint, String> {
    mul(&G, k)
}

fn is_identity(p: &RistrettoPoint) -> bool {
    *p == RistrettoPoint::identity()
}

fn enc(p: &RistrettoPoint) -> Vec<u8> {
    p.compress().to_bytes().to_vec()
}

/// RFC 9380 expand_message_xmd with SHA-512 for the 64-byte output every suite step needs (a single block).
fn expand_xmd(msg: &[u8], dst: &[u8]) -> [u8; 64] {
    let dst: Vec<u8> = if dst.len() > 255 {
        let mut h = Sha512::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        h.finalize().to_vec()
    } else {
        dst.to_vec()
    };
    let mut dst_prime = dst.clone();
    dst_prime.push(dst.len() as u8);
    let mut h0 = Sha512::new();
    h0.update([0u8; 128]);
    h0.update(msg);
    h0.update([0u8, 64, 0]);
    h0.update(&dst_prime);
    let b0 = h0.finalize();
    let mut h1 = Sha512::new();
    h1.update(b0);
    h1.update([1u8]);
    h1.update(&dst_prime);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h1.finalize());
    out
}

fn hash_to_scalar_dst(data: &[u8], dst: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&expand_xmd(data, dst))
}

fn hash_to_scalar(data: &[u8], mode: &str) -> Result<Scalar, String> {
    let mut dst = b"HashToScalar-".to_vec();
    dst.extend_from_slice(&context(mode)?);
    Ok(hash_to_scalar_dst(data, &dst))
}

/// Modular inverse of a SECRET scalar (dalek's constant-time Fermat inversion).
fn invert(s: &Scalar) -> Result<Scalar, String> {
    if *s == Scalar::ZERO {
        return Err("scalarInvert: inverse of zero".into());
    }
    Ok(s.invert())
}

fn scalar_from(b: &[u8]) -> Result<Scalar, String> {
    let arr: [u8; 32] = b.try_into().map_err(|_| format!("DeserializeScalar: expected 32 bytes, got {}", b.len()))?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| "DeserializeScalar: non-canonical scalar (value >= group order)".to_string())
}

fn element(b: &[u8]) -> Result<RistrettoPoint, String> {
    let c = CompressedRistretto::from_slice(b).map_err(|_| "DeserializeElement: expected 32 bytes".to_string())?;
    let p = c.decompress().ok_or_else(|| "DeserializeElement: invalid ristretto255 encoding".to_string())?;
    if is_identity(&p) {
        return Err("DeserializeElement: identity element is not a valid input".into());
    }
    Ok(p)
}

fn random_scalar() -> Result<Scalar, String> {
    // Bounded: a healthy CSPRNG yields zero with probability ~2^-252, so repeated zeros mean a broken entropy source.
    for _ in 0..8 {
        let mut b = [0u8; 64];
        getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
        let s = Scalar::from_bytes_mod_order_wide(&b);
        if s != Scalar::ZERO {
            return Ok(s);
        }
    }
    Err("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue".into())
}

// ---- encodings

fn group_order() -> BigUint {
    BigUint::parse_bytes(b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16).expect("order")
}

/// `n mod L` as 32 little-endian bytes, `n` an integer in decimal text (optional leading `-`).
pub fn serialize_scalar_decimal(n: &str) -> Result<Vec<u8>, String> {
    let (neg, digits) = match n.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, n),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("serializeScalar: not an integer: {n:?}"));
    }
    let l = group_order();
    let mut r = &BigUint::parse_bytes(digits.as_bytes(), 10).ok_or("serializeScalar: not an integer")? % &l;
    if neg && r != BigUint::from(0u8) {
        r = &l - &r;
    }
    let mut out = r.to_bytes_le();
    out.resize(32, 0);
    Ok(out)
}

/// `n mod L` as 32 little-endian bytes.
pub fn serialize_scalar(n: &BigUint) -> Vec<u8> {
    let mut out = (n % &group_order()).to_bytes_le();
    out.resize(32, 0);
    out
}

/// A canonical 32-byte little-endian scalar below the group order.
pub fn deserialize_scalar(b: &[u8]) -> Result<BigUint, String> {
    Ok(BigUint::from_bytes_le(&scalar_from(b)?.to_bytes()))
}

/// A canonical ristretto255 element (the identity is refused), re-serialised.
pub fn deserialize_element(b: &[u8]) -> Result<Vec<u8>, String> {
    Ok(enc(&element(b)?))
}

fn h2g(data: &[u8], mode: &str) -> Result<RistrettoPoint, String> {
    framed(data, "HashToGroup")?;
    let mut dst = b"HashToGroup-".to_vec();
    dst.extend_from_slice(&context(mode)?);
    Ok(RistrettoPoint::from_uniform_bytes(&expand_xmd(data, &dst)))
}

/// The serialised `HashToGroup` element of `input`.
pub fn hash_to_group(input: &[u8], mode: &str) -> Result<Vec<u8>, String> {
    Ok(enc(&h2g(input, mode)?))
}

// ---- keys

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// RFC 9497 `DeriveKeyPair`: the serialised key pair of a 32-byte seed and info.
pub fn derive_key_pair(seed: &[u8], info: &[u8], mode: &str) -> Result<KeyPair, String> {
    if seed.len() != 32 {
        return Err("DeriveKeyPair: seed must be exactly 32 bytes".into());
    }
    framed(info, "DeriveKeyPair(info)")?;
    let mut dst = b"DeriveKeyPair".to_vec();
    dst.extend_from_slice(&context(mode)?);
    let mut input = seed.to_vec();
    input.extend_from_slice(&i2osp2(info.len()));
    input.extend_from_slice(info);
    for counter in 0..=255u8 {
        let mut m = input.clone();
        m.push(counter);
        let sk = hash_to_scalar_dst(&m, &dst);
        if sk != Scalar::ZERO {
            return Ok(KeyPair { secret_key: sk.to_bytes().to_vec(), public_key: enc(&base_mult(&sk)?) });
        }
    }
    Err("DeriveKeyPair: failed to derive a non-zero key after 256 attempts".into())
}

/// A fresh random key pair.
pub fn random_key_pair() -> Result<KeyPair, String> {
    let sk = random_scalar()?;
    Ok(KeyPair { secret_key: sk.to_bytes().to_vec(), public_key: enc(&base_mult(&sk)?) })
}

/// The serialised public key of a secret key.
pub fn public_key_for(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    Ok(enc(&base_mult(&scalar_from(secret_key)?)?))
}

// ---- DLEQ proofs (RFC 9497 section 2.2.1)

fn composites(b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint, mode: &str) -> Result<(RistrettoPoint, RistrettoPoint), String> {
    let ctx = context(mode)?;
    let mut seed_dst = b"Seed-".to_vec();
    seed_dst.extend_from_slice(&ctx);
    let b_ser = enc(b);
    let mut h = Sha512::new();
    h.update(i2osp2(b_ser.len()));
    h.update(&b_ser);
    h.update(i2osp2(seed_dst.len()));
    h.update(&seed_dst);
    let seed = h.finalize();
    let (c_ser, d_ser) = (enc(c), enc(d));
    let mut t = Vec::new();
    t.extend_from_slice(&i2osp2(seed.len()));
    t.extend_from_slice(&seed);
    t.extend_from_slice(&i2osp2(0));
    t.extend_from_slice(&i2osp2(c_ser.len()));
    t.extend_from_slice(&c_ser);
    t.extend_from_slice(&i2osp2(d_ser.len()));
    t.extend_from_slice(&d_ser);
    t.extend_from_slice(b"Composite");
    let coeff = hash_to_scalar(&t, mode)?;
    Ok((*c * coeff, *d * coeff))
}

fn challenge(b: &RistrettoPoint, m: &RistrettoPoint, z: &RistrettoPoint, t2: &RistrettoPoint, t3: &RistrettoPoint, mode: &str) -> Result<Scalar, String> {
    let mut parts = Vec::new();
    for p in [b, m, z, t2, t3] {
        let ser = enc(p);
        parts.extend_from_slice(&i2osp2(ser.len()));
        parts.extend_from_slice(&ser);
    }
    parts.extend_from_slice(b"Challenge");
    hash_to_scalar(&parts, mode)
}

fn generate_proof(
    k: &Scalar,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c: &RistrettoPoint,
    d: &RistrettoPoint,
    mode: &str,
    fixed: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let (m, _) = composites(b, c, d, mode)?;
    let z = mul(&m, k)?;
    let r = match fixed {
        None => random_scalar()?,
        Some(f) => scalar_from(f)?,
    };
    let t2 = mul(a, &r)?;
    let t3 = mul(&m, &r)?;
    let cc = challenge(b, &m, &z, &t2, &t3, mode)?;
    let s = r - cc * *k;
    let mut out = cc.to_bytes().to_vec();
    out.extend_from_slice(&s.to_bytes());
    Ok(out)
}

fn verify_proof(a: &RistrettoPoint, b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint, proof: &[u8], mode: &str) -> Result<bool, String> {
    if proof.len() != 64 {
        return Ok(false);
    }
    let cc = scalar_from(&proof[..32])?;
    let s = scalar_from(&proof[32..])?;
    let (m, z) = composites(b, c, d, mode)?;
    let t2 = *a * s + *b * cc;
    let t3 = m * s + z * cc;
    let expected = challenge(b, &m, &z, &t2, &t3, mode)?;
    Ok(expected == cc)
}

fn finalize_hash(input: &[u8], info: Option<&[u8]>, issued: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(i2osp2(input.len()));
    h.update(input);
    if let Some(info) = info {
        h.update(i2osp2(info.len()));
        h.update(info);
    }
    h.update(i2osp2(issued.len()));
    h.update(issued);
    h.update(b"Finalize");
    h.finalize().to_vec()
}

// ---- OPRF / VOPRF

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindResult {
    /// The secret blinding scalar (keep it; finalize needs it).
    pub blind: Vec<u8>,
    pub blinded_element: Vec<u8>,
}

/// A server blind-evaluation: the evaluated element and (VOPRF/POPRF) the DLEQ proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluated {
    pub evaluated_element: Vec<u8>,
    pub proof: Option<Vec<u8>>,
}

/// Client step 1. `fixed_blind` pins the blind (test vectors only); `None` draws a random one.
pub fn blind(input: &[u8], mode: &str, fixed_blind: Option<&[u8]>) -> Result<BlindResult, String> {
    framed(input, "Blind(input)")?;
    let r = match fixed_blind {
        None => random_scalar()?,
        Some(f) => scalar_from(f)?,
    };
    let el = h2g(input, mode)?;
    if is_identity(&el) {
        return Err("Blind: input maps to identity".into());
    }
    let bl = mul(&el, &r)?;
    Ok(BlindResult { blind: r.to_bytes().to_vec(), blinded_element: enc(&bl) })
}

/// Server step: the evaluated element and, for voprf, the DLEQ proof. `public_key` None = derived from the key;
/// `proof_randomness` None = random (pin it for test vectors only).
pub fn blind_evaluate(
    secret_key: &[u8],
    blinded_element: &[u8],
    mode: &str,
    public_key: Option<&[u8]>,
    proof_randomness: Option<&[u8]>,
) -> Result<Evaluated, String> {
    server_mode(mode)?;
    let sk = scalar_from(secret_key)?;
    let r = element(blinded_element)?;
    let ev = mul(&r, &sk)?;
    if mode == "oprf" {
        return Ok(Evaluated { evaluated_element: enc(&ev), proof: None });
    }
    // the public key is the caller's to supply (the reference decodes it unconditionally); it is never silently derived here
    let pk = element(public_key.ok_or("DeserializeElement: expected a Uint8Array")?)?;
    let proof = generate_proof(&sk, &G, &pk, &r, &ev, "voprf", proof_randomness)?;
    Ok(Evaluated { evaluated_element: enc(&ev), proof: Some(proof) })
}

/// Client's last step. For voprf the proof, public key and blinded element are required and the DLEQ proof is verified first.
pub fn finalize(
    input: &[u8],
    blind: &[u8],
    evaluated_element: &[u8],
    mode: &str,
    proof: Option<&[u8]>,
    public_key: Option<&[u8]>,
    blinded_element: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    framed(input, "Finalize(input)")?;
    server_mode(mode)?;
    let r = scalar_from(blind)?;
    let ev = element(evaluated_element)?;
    if mode == "voprf" {
        let (Some(proof), Some(public_key), Some(blinded_element)) = (proof, public_key, blinded_element) else {
            return Err("Finalize(voprf): proof, publicKey and blindedElement are required".into());
        };
        let pk = element(public_key)?;
        let bl = element(blinded_element)?;
        if !verify_proof(&G, &pk, &bl, &ev, proof, "voprf")? {
            return Err("Finalize(voprf): DLEQ proof verification failed".into());
        }
    }
    let n = mul(&ev, &invert(&r)?)?;
    Ok(finalize_hash(input, None, &enc(&n)))
}

/// The server's direct evaluation of `input` (no blinding).
pub fn evaluate(secret_key: &[u8], input: &[u8], mode: &str) -> Result<Vec<u8>, String> {
    framed(input, "Evaluate(input)")?;
    server_mode(mode)?;
    let sk = scalar_from(secret_key)?;
    let el = h2g(input, mode)?;
    if is_identity(&el) {
        return Err("Evaluate: input maps to identity".into());
    }
    Ok(finalize_hash(input, None, &enc(&mul(&el, &sk)?)))
}

// ---- POPRF (the public info is bound into the evaluation)

fn info_scalar(info: &[u8]) -> Result<Scalar, String> {
    framed(info, "info")?;
    let mut t = b"Info".to_vec();
    t.extend_from_slice(&i2osp2(info.len()));
    t.extend_from_slice(info);
    hash_to_scalar(&t, "poprf")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoprfBlindResult {
    pub blind: Vec<u8>,
    pub blinded_element: Vec<u8>,
    /// `m*G + pkS`: the tweaked key the client verifies the proof against.
    pub tweaked_key: Vec<u8>,
}

/// POPRF client blind step.
pub fn blind_poprf(input: &[u8], info: &[u8], public_key: &[u8], fixed_blind: Option<&[u8]>) -> Result<PoprfBlindResult, String> {
    framed(input, "Blind(input)")?;
    let m = info_scalar(info)?;
    let pk = element(public_key)?;
    let tweaked = base_mult(&m)? + pk;
    if is_identity(&tweaked) {
        return Err("Blind(poprf): tweaked key is identity".into());
    }
    let b = blind(input, "poprf", fixed_blind)?;
    Ok(PoprfBlindResult { blind: b.blind, blinded_element: b.blinded_element, tweaked_key: enc(&tweaked) })
}

/// POPRF server step: the evaluated element and its DLEQ proof.
pub fn blind_evaluate_poprf(secret_key: &[u8], blinded_element: &[u8], info: &[u8], proof_randomness: Option<&[u8]>) -> Result<Evaluated, String> {
    let sk = scalar_from(secret_key)?;
    let m = info_scalar(info)?;
    let t = sk + m;
    if t == Scalar::ZERO {
        return Err("BlindEvaluate(poprf): inverse of zero (bad info/key)".into());
    }
    let blinded = element(blinded_element)?;
    let ev = mul(&blinded, &invert(&t)?)?;
    let tweaked = base_mult(&t)?;
    let proof = generate_proof(&t, &G, &tweaked, &ev, &blinded, "poprf", proof_randomness)?;
    Ok(Evaluated { evaluated_element: enc(&ev), proof: Some(proof) })
}

/// POPRF client's last step; the DLEQ proof is always verified.
pub fn finalize_poprf(
    input: &[u8],
    blind: &[u8],
    evaluated_element: &[u8],
    info: &[u8],
    proof: &[u8],
    blinded_element: &[u8],
    tweaked_key: &[u8],
) -> Result<Vec<u8>, String> {
    framed(input, "Finalize(input)")?;
    framed(info, "info")?;
    let r = scalar_from(blind)?;
    let ev = element(evaluated_element)?;
    let bl = element(blinded_element)?;
    let tk = element(tweaked_key)?;
    if !verify_proof(&G, &tk, &ev, &bl, proof, "poprf")? {
        return Err("Finalize(poprf): DLEQ proof verification failed".into());
    }
    let n = mul(&ev, &invert(&r)?)?;
    Ok(finalize_hash(input, Some(info), &enc(&n)))
}

/// The server's direct POPRF evaluation of `input` under a public `info`.
pub fn evaluate_poprf(secret_key: &[u8], input: &[u8], info: &[u8]) -> Result<Vec<u8>, String> {
    framed(input, "Evaluate(input)")?;
    let sk = scalar_from(secret_key)?;
    let m = info_scalar(info)?;
    let t = sk + m;
    if t == Scalar::ZERO {
        return Err("Evaluate(poprf): inverse of zero (bad info/key)".into());
    }
    let el = h2g(input, "poprf")?;
    if is_identity(&el) {
        return Err("Evaluate(poprf): input maps to identity".into());
    }
    Ok(finalize_hash(input, Some(info), &enc(&mul(&el, &invert(&t)?)?)))
}

// ---- utilities

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Byte equality that does not exit early on the first difference (unequal lengths are unequal).
pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

// ---- PCA layer: private revocation

/// A server blind-evaluation oracle: the only thing that crosses the client to service boundary.
pub type BlindEvaluator = Box<dyn Fn(&[u8]) -> Result<Evaluated, String> + Send + Sync>;

/// A published private-revocation set: the lowercase-hex OPRF outputs of the revoked capability ids, the mode that produced them and
/// (voprf) the service public key.
#[derive(Clone, Debug)]
pub struct RevocationSet {
    pub outputs: HashSet<String>,
    pub mode: String,
    pub public_key: Option<Vec<u8>>,
}

/// Precomputes the private-revocation set from the secret key and the revoked capability ids.
pub fn build_revocation_set(secret_key: &[u8], revoked: &[String], mode: &str) -> Result<RevocationSet, String> {
    server_mode(mode)?;
    let mut outputs = HashSet::new();
    for id in revoked {
        outputs.insert(to_hex(&evaluate(secret_key, id.as_bytes(), mode)?));
    }
    let public_key = if mode == "voprf" { Some(public_key_for(secret_key)?) } else { None };
    Ok(RevocationSet { outputs, mode: mode.to_string(), public_key })
}

/// The service's blind-evaluation oracle; it cannot recover the capability id.
pub fn make_revocation_evaluator(secret_key: &[u8], mode: &str) -> Result<BlindEvaluator, String> {
    server_mode(mode)?;
    let pk = if mode == "voprf" { Some(public_key_for(secret_key)?) } else { None };
    let (sk, mode) = (secret_key.to_vec(), mode.to_string());
    Ok(Box::new(move |blinded: &[u8]| blind_evaluate(&sk, blinded, &mode, pk.as_deref(), None)))
}

/// Client side: is `cap_id` in the published set, learned obliviously? A voprf set verifies the service's DLEQ proof, so a lying
/// service is refused rather than making every capability look non-revoked.
pub fn is_revoked_private(cap_id: &str, blind_eval: &dyn Fn(&[u8]) -> Result<Evaluated, String>, set: &RevocationSet) -> Result<bool, String> {
    let input = cap_id.as_bytes();
    let b = blind(input, &set.mode, None)?;
    let res = blind_eval(&b.blinded_element)?;
    let out = if set.mode == "voprf" {
        let (Some(proof), Some(pk)) = (res.proof.as_deref(), set.public_key.as_deref()) else {
            return Err("isRevokedPrivate(voprf): missing DLEQ proof or service public key".into());
        };
        finalize(input, &b.blind, &res.evaluated_element, "voprf", Some(proof), Some(pk), Some(&b.blinded_element))?
    } else {
        finalize(input, &b.blind, &res.evaluated_element, "oprf", None, None, None)?
    };
    Ok(set.outputs.contains(&to_hex(&out)))
}

// ---- PCA layer: private rate limiting

/// The POPRF oracle for rate tokens: the window is the public info tag.
pub type RateBlindEvaluator = Box<dyn Fn(&[u8], &str) -> Result<Evaluated, String> + Send + Sync>;

/// The deterministic rate token for (identifier, window): `POPRF.Evaluate(sk, identifier, info = window)`.
pub fn rate_token(secret_key: &[u8], identifier: &str, window: &str) -> Result<Vec<u8>, String> {
    evaluate_poprf(secret_key, identifier.as_bytes(), window.as_bytes())
}

/// Lowercase hex of [`rate_token`]: a stable, identifier-free counting key.
pub fn rate_token_hex(secret_key: &[u8], identifier: &str, window: &str) -> Result<String, String> {
    Ok(to_hex(&rate_token(secret_key, identifier, window)?))
}

/// The server's POPRF blind-evaluation oracle.
pub fn make_rate_evaluator(secret_key: &[u8]) -> RateBlindEvaluator {
    let sk = secret_key.to_vec();
    Box::new(move |blinded: &[u8], window: &str| blind_evaluate_poprf(&sk, blinded, window.as_bytes(), None))
}

/// The rate token for (identifier, window) without revealing the identifier; equals [`rate_token`] for the same key. The server's DLEQ
/// proof is verified.
pub fn private_rate_token(
    identifier: &str,
    window: &str,
    blind_eval: &dyn Fn(&[u8], &str) -> Result<Evaluated, String>,
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let (id, info) = (identifier.as_bytes(), window.as_bytes());
    let b = blind_poprf(id, info, public_key, None)?;
    let res = blind_eval(&b.blinded_element, window)?;
    let Some(proof) = res.proof.as_deref() else {
        return Err("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof".into());
    };
    finalize_poprf(id, &b.blind, &res.evaluated_element, info, proof, &b.blinded_element, &b.tweaked_key)
}

/// Counts hits per rate token with a per-window limit (in memory; swap in a shared store for a fleet).
pub struct RateWindowCounter {
    limit: u64,
    counts: Mutex<HashMap<String, u64>>,
}

impl RateWindowCounter {
    /// `limit` must be a positive integer.
    pub fn new(limit: i64) -> Result<Self, String> {
        if limit < 1 {
            return Err("RateWindowCounter: limit must be a positive integer".into());
        }
        Ok(Self { limit: limit as u64, counts: Mutex::new(HashMap::new()) })
    }

    /// Counts one use of `token`; returns the new count and whether it is within the limit.
    pub fn hit(&self, token: &[u8]) -> (u64, bool) {
        let mut m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let c = m.entry(to_hex(token)).or_insert(0);
        *c += 1;
        (*c, *c <= self.limit)
    }

    /// Hits of `token` so far (0 if unseen).
    pub fn count(&self, token: &[u8]) -> u64 {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).get(&to_hex(token)).copied().unwrap_or(0)
    }

    /// Starts a new window.
    pub fn reset(&self) {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}
