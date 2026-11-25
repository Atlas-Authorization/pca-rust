//! Oblivious transfer for the MPC no-dealer offline phase.
//!
//! (1) A maliciously secure Chou-Orlandi base OT over the Ed25519 prime-order subgroup: the sender proves knowledge of its discrete
//! log with a Schnorr NIZK, every received point is validated (on curve, not the identity, `[L]P = O`), and the core runs as a random
//! OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating receiver is caught
//! and the protocol aborts). (3) The ML-KEM-768 base OT (semi-honest, and the commit-then-open malicious-secure variant) and the
//! hybrid base OT that folds the elliptic-curve and ML-KEM secrets into every transfer key. Both roles run in one process; the
//! functions take both parties' inputs and return the receiver's outputs plus an inspectable transcript. Randomness is the OS CSPRNG
//! ([`OtRng::Secure`]) unless a SplitMix64 seed is given (tests only).
//!
//! The group arithmetic is curve25519-dalek's (constant time); the AES-128 PRG / correlation-robust hash runs on RustCrypto `aes`
//! (re-exported by `aes-gcm`), SHAKE256 and SHA-2 on RustCrypto, ML-KEM-768 on the vetted `ml-kem` crate (deterministic key
//! generation and encapsulation from the seeded stream). Nothing here is a hand-rolled primitive.
//!
//! shortcut: dalek exposes no affine coordinates, so the affine `(x, y)` of a point (the OT key-derivation encoding, the wire form
//! of the transcripts) is rebuilt from the compressed point with a small 255-bit field type (`Fe`, schoolbook multiply with the
//! `2^256 = 38` fold) that only does the square root recovery and the on-curve check of caller-supplied extended coordinates; the
//! group law itself never leaves dalek. The secure scalar source reduces 64 random bytes mod L (bias below 2^-250) instead of the
//! reference's rejection loop.
use crate::mpc::{gf128_mul, low_u64};
use aes_gcm::aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes_gcm::aes::Aes128;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, B32};
use rsa::BigUint;
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::fmt;
use std::sync::OnceLock;

pub mod rounds;

// ---- errors --------------------------------------------------------------------------------------------------------------------

/// A refusal of the OT layer. Each abort kind of the reference is its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtError {
    /// A malformed argument or a failed local check.
    Invalid(String),
    /// A received point failed on-curve / subgroup / identity validation.
    PointValidation(String),
    /// A base OT aborted: a cheating sender (bad proof or inconsistent ciphertext).
    BaseOtAbort(String),
    /// The KOS correlation check failed: a cheating OT-extension receiver.
    MalOtAbort(String),
    /// The opened ML-KEM keys do not match the receiver's commitment.
    KemBaseOtAbort(String),
    /// The sender's hybrid ciphertext is inconsistent with its commitment.
    HybridOtAbort(String),
}

impl fmt::Display for OtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtError::Invalid(m)
            | OtError::PointValidation(m)
            | OtError::BaseOtAbort(m)
            | OtError::MalOtAbort(m)
            | OtError::KemBaseOtAbort(m)
            | OtError::HybridOtAbort(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for OtError {}

pub type OtResult<T> = Result<T, OtError>;

fn inv<T>(m: impl Into<String>) -> OtResult<T> {
    Err(OtError::Invalid(m.into()))
}

fn pve<T>(m: impl Into<String>) -> OtResult<T> {
    Err(OtError::PointValidation(m.into()))
}

// ---- randomness ----------------------------------------------------------------------------------------------------------------

/// The OT randomness source: the OS CSPRNG, or the reproducible SplitMix64 stream of a seed (tests and verifiers only).
#[derive(Debug, Clone)]
pub enum OtRng {
    Secure,
    Seeded(u64),
}

impl OtRng {
    /// The seeded stream of the low 64 bits of a decimal integer of any size.
    pub fn from_decimal(seed: &str) -> OtResult<OtRng> {
        low_u64(seed).map(OtRng::Seeded).map_err(|e| OtError::Invalid(e.to_string()))
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            OtRng::Seeded(s) => {
                *s = s.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = *s;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^ (z >> 31)
            }
            OtRng::Secure => {
                let mut b = [0u8; 8];
                getrandom::getrandom(&mut b).expect("operating-system randomness unavailable");
                u64::from_le_bytes(b)
            }
        }
    }

    /// `n` random bytes (the seeded stream emits each draw little-endian).
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        if let OtRng::Secure = self {
            let mut out = vec![0u8; n];
            getrandom::getrandom(&mut out).expect("operating-system randomness unavailable");
            return out;
        }
        let mut out = Vec::with_capacity(n + 8);
        while out.len() < n {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(n);
        out
    }

    /// A uniform scalar in `[1, L)`.
    pub fn scalar(&mut self) -> Scalar {
        if let OtRng::Secure = self {
            loop {
                let mut w = [0u8; 64];
                getrandom::getrandom(&mut w).expect("operating-system randomness unavailable");
                let s = Scalar::from_bytes_mod_order_wide(&w);
                if s != Scalar::ZERO {
                    return s;
                }
            }
        }
        for _ in 0..8 {
            let (d0, d1, d2, d3) = (self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64());
            // acc = d0 * 2^192 + d1 * 2^128 + d2 * 2^64 + d3 (the reference's big-endian accumulation), reduced mod L.
            let mut le = [0u8; 32];
            le[0..8].copy_from_slice(&d3.to_le_bytes());
            le[8..16].copy_from_slice(&d2.to_le_bytes());
            le[16..24].copy_from_slice(&d1.to_le_bytes());
            le[24..32].copy_from_slice(&d0.to_le_bytes());
            let s = Scalar::from_bytes_mod_order(le);
            if s != Scalar::ZERO {
                return s;
            }
        }
        panic!("mpc: otRandom: entropy stream returned zero scalars repeatedly (RNG failure)");
    }
}

fn sha256(chunks: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for c in chunks {
        Digest::update(&mut h, c);
    }
    h.finalize().to_vec()
}

fn u32be(x: u64) -> [u8; 4] {
    (x as u32).to_be_bytes()
}

fn xor_bytes(a: &[u8], b: &[u8]) -> OtResult<Vec<u8>> {
    if a.len() > b.len() {
        return inv("OT: XOR length mismatch");
    }
    Ok(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// A pair of byte strings, slot 0 and slot 1.
pub type OtPair = [Vec<u8>; 2];

// ---- the field of the curve ----------------------------------------------------------------------------------------------------

const Q_LIMBS: [u64; 4] = [0xffff_ffff_ffff_ffed, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff];

fn curve_q_big() -> BigUint {
    (BigUint::from(1u8) << 255usize) - BigUint::from(19u8)
}

/// The prime order L of the base-point subgroup, as 32 little-endian bytes.
pub fn ec_l_bytes() -> [u8; 32] {
    let l = (BigUint::from(1u8) << 252usize) + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).expect("L");
    let mut b = l.to_bytes_le();
    b.resize(32, 0);
    b.try_into().expect("32 bytes")
}

/// An element of GF(2^255 - 19), always canonical in `[0, q)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fe([u64; 4]);

fn ge_q(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != Q_LIMBS[i] {
            return a[i] > Q_LIMBS[i];
        }
    }
    true
}

fn sub_q(a: &mut [u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(Q_LIMBS[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 | b2) as u64;
    }
}

impl Fe {
    const ZERO: Fe = Fe([0; 4]);
    const ONE: Fe = Fe([1, 0, 0, 0]);

    fn from_u64(x: u64) -> Fe {
        Fe([x, 0, 0, 0])
    }

    fn canon(mut a: [u64; 4]) -> Fe {
        while ge_q(&a) {
            sub_q(&mut a);
        }
        Fe(a)
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    fn add(self, o: Fe) -> Fe {
        let mut r = [0u64; 4];
        let mut c = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s2, c2) = s1.overflowing_add(c);
            r[i] = s2;
            c = (c1 | c2) as u64;
        }
        Fe::canon(r) // both operands are below q < 2^255, so the sum never reaches 2^256
    }

    fn neg(self) -> Fe {
        if self.is_zero() {
            return self;
        }
        let mut r = Q_LIMBS;
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = r[i].overflowing_sub(self.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r[i] = d2;
            borrow = (b1 | b2) as u64;
        }
        Fe(r)
    }

    fn sub(self, o: Fe) -> Fe {
        self.add(o.neg())
    }

    fn mul(self, o: Fe) -> Fe {
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur = t[i + j] as u128 + (self.0[i] as u128) * (o.0[j] as u128) + carry;
                t[i + j] = cur as u64;
                carry = cur >> 64;
            }
            t[i + 4] = carry as u64;
        }
        // 2^256 = 38 (mod q): fold the high half in, twice.
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let cur = t[i] as u128 + (t[i + 4] as u128) * 38 + carry;
            r[i] = cur as u64;
            carry = cur >> 64;
        }
        let mut c = carry * 38;
        for limb in r.iter_mut() {
            let cur = *limb as u128 + c;
            *limb = cur as u64;
            c = cur >> 64;
        }
        if c > 0 {
            r[0] = r[0].wrapping_add(38); // the value wrapped past 2^256, so it is tiny now
        }
        Fe::canon(r)
    }

    fn pow(self, e: &[u64; 4]) -> Fe {
        let mut acc = Fe::ONE;
        for i in (0..4).rev() {
            for b in (0..64).rev() {
                acc = acc.mul(acc);
                if (e[i] >> b) & 1 == 1 {
                    acc = acc.mul(self);
                }
            }
        }
        acc
    }

    fn inv(self) -> Fe {
        self.pow(&[0xffff_ffff_ffff_ffeb, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff])
        // q - 2
    }

    fn parity(self) -> u8 {
        (self.0[0] & 1) as u8
    }

    fn to_le(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[8 * i..8 * i + 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        b
    }

    /// The 32 little-endian bytes as an integer below 2^256, reduced mod q.
    fn from_le(b: &[u8; 32]) -> Fe {
        let mut l = [0u64; 4];
        for i in 0..4 {
            l[i] = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes"));
        }
        Fe::canon(l)
    }

    fn from_big(v: &BigUint) -> Fe {
        let mut b = (v % curve_q_big()).to_bytes_le();
        b.resize(32, 0);
        Fe::from_le(&b.try_into().expect("32 bytes"))
    }

    fn from_dec(s: &str) -> OtResult<Fe> {
        match BigUint::parse_bytes(s.as_bytes(), 10) {
            Some(v) if !s.is_empty() => Ok(Fe::from_big(&v)),
            _ => inv("not a non-negative decimal integer"),
        }
    }

    fn to_dec(self) -> String {
        BigUint::from_bytes_le(&self.to_le()).to_str_radix(10)
    }
}

fn curve_d() -> Fe {
    static D: OnceLock<Fe> = OnceLock::new();
    *D.get_or_init(|| Fe::from_u64(121665).neg().mul(Fe::from_u64(121666).inv()))
}

fn sqrt_m1() -> Fe {
    static S: OnceLock<Fe> = OnceLock::new();
    // 2^((q-1)/4)
    *S.get_or_init(|| Fe::from_u64(2).pow(&[0xffff_ffff_ffff_fffb, u64::MAX, u64::MAX, 0x1fff_ffff_ffff_ffff]))
}

/// The affine x of the curve point with the given y and x-parity (None when y is not on the curve).
fn recover_x(y: Fe, sign: u8) -> Option<Fe> {
    let y2 = y.mul(y);
    let u = y2.sub(Fe::ONE);
    let v = curve_d().mul(y2).add(Fe::ONE);
    let v3 = v.mul(v).mul(v);
    let v7 = v3.mul(v3).mul(v);
    // (q - 5) / 8 = 2^252 - 3
    let mut x = u.mul(v3).mul(u.mul(v7).pow(&[0xffff_ffff_ffff_fffd, u64::MAX, u64::MAX, 0x0fff_ffff_ffff_ffff]));
    let vx2 = v.mul(x.mul(x));
    if vx2 != u {
        if vx2 == u.neg() {
            x = x.mul(sqrt_m1());
        } else {
            return None;
        }
    }
    if x.parity() != sign {
        x = x.neg();
    }
    Some(x)
}

// ---- the group -----------------------------------------------------------------------------------------------------------------

/// The standard base point B.
pub fn ec_base() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
}

/// The neutral element.
pub fn ec_identity() -> EdwardsPoint {
    EdwardsPoint::identity()
}

/// `k mod L` as a scalar, for a decimal integer of any size and sign.
pub fn ec_scalar_from_decimal(s: &str) -> OtResult<Scalar> {
    let (neg, d) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = match BigUint::parse_bytes(d.as_bytes(), 10) {
        Some(v) if !d.is_empty() => v,
        _ => return inv("not a decimal integer"),
    };
    let l = BigUint::from_bytes_le(&ec_l_bytes());
    let mut b = (v % l).to_bytes_le();
    b.resize(32, 0);
    let sc = Scalar::from_bytes_mod_order(b.try_into().expect("32 bytes"));
    Ok(if neg { -sc } else { sc })
}

/// The decimal value of a canonical scalar.
pub fn ec_scalar_to_decimal(s: &Scalar) -> String {
    BigUint::from_bytes_le(&s.to_bytes()).to_str_radix(10)
}

/// `[k]B`.
pub fn ec_mul_base(k: &Scalar) -> EdwardsPoint {
    ED25519_BASEPOINT_POINT * k
}

/// `[k]P` (`k = 0` gives the identity).
pub fn ec_mul(k: &Scalar, p: &EdwardsPoint) -> EdwardsPoint {
    p * k
}

pub fn ec_is_identity(p: &EdwardsPoint) -> bool {
    *p == EdwardsPoint::identity()
}

/// The affine `(x, y)` of a point as canonical decimal strings (the identity is `(0, 1)`).
pub fn ec_to_affine_dec(p: &EdwardsPoint) -> (String, String) {
    let (x, y) = affine(p);
    (x.to_dec(), y.to_dec())
}

fn affine(p: &EdwardsPoint) -> (Fe, Fe) {
    let c = p.compress().to_bytes();
    let sign = c[31] >> 7;
    let mut yb = c;
    yb[31] &= 0x7f;
    let y = Fe::from_le(&yb);
    // dalek only ever compresses a valid point, so the root exists.
    let x = recover_x(y, sign).expect("a dalek point is on the curve");
    (x, y)
}

/// The canonical 64-byte encoding of a point (affine x then y, little-endian), the OT key-derivation input.
pub fn ec_encode_point(p: &EdwardsPoint) -> Vec<u8> {
    let (x, y) = affine(p);
    let mut out = x.to_le().to_vec();
    out.extend_from_slice(&y.to_le());
    out
}

/// The canonical 32-byte compressed encoding.
pub fn ec_compress(p: &EdwardsPoint) -> Vec<u8> {
    p.compress().to_bytes().to_vec()
}

/// Decode a canonical compressed encoding: a non-canonical `y` (>= q), a non-canonical sign or an off-curve `y` is refused.
pub fn ec_decompress(b: &[u8]) -> OtResult<EdwardsPoint> {
    let arr: [u8; 32] = match b.try_into() {
        Ok(a) => a,
        Err(_) => return pve("decompressPoint: expected 32 bytes"),
    };
    let p = match CompressedEdwardsY(arr).decompress() {
        Some(p) => p,
        None => return pve("decompressPoint: not on curve"),
    };
    if p.compress().to_bytes() != arr {
        return pve("decompressPoint: non-canonical encoding");
    }
    Ok(p)
}

/// A point from decimal extended coordinates `(X, Y, Z, T)` (x = X/Z, y = Y/Z, T = XY/Z) mod q; `Z = 0`, a wrong `T` or an
/// off-curve point is refused.
pub fn ec_from_extended_dec(c: &[String]) -> OtResult<EdwardsPoint> {
    if c.len() != 4 {
        return pve("not on curve");
    }
    let f: Vec<Fe> = c.iter().map(|s| Fe::from_dec(s).or_else(|_| pve("not on curve"))).collect::<OtResult<_>>()?;
    ec_from_extended([f[0], f[1], f[2], f[3]])
}

fn ec_from_extended(c: [Fe; 4]) -> OtResult<EdwardsPoint> {
    let [x_, y_, z, t] = c;
    if z.is_zero() || t.mul(z) != x_.mul(y_) {
        return pve("not on curve");
    }
    let zi = z.inv();
    let (x, y) = (x_.mul(zi), y_.mul(zi));
    let (x2, y2) = (x.mul(x), y.mul(y));
    if y2.sub(x2) != Fe::ONE.add(curve_d().mul(x2).mul(y2)) {
        return pve("not on curve");
    }
    let mut enc = y.to_le();
    if x.parity() == 1 {
        enc[31] |= 0x80;
    }
    match CompressedEdwardsY(enc).decompress() {
        Some(p) => Ok(p),
        None => pve("not on curve"),
    }
}

/// The projective identity test on raw decimal coordinates (an off-curve point can still carry the identity's coordinates).
pub fn ec_raw_identity(c: &[String]) -> bool {
    match c.iter().map(|s| Fe::from_dec(s)).collect::<OtResult<Vec<Fe>>>() {
        Ok(f) if f.len() == 4 => f[0].is_zero() && f[1] == f[2],
        _ => false,
    }
}

/// The cofactor check `[L]P = O` (true for the identity too).
pub fn ec_has_prime_order(p: &EdwardsPoint) -> bool {
    p.is_torsion_free()
}

/// A valid non-identity point of the prime-order subgroup.
pub fn ec_is_in_subgroup(p: &EdwardsPoint) -> bool {
    !ec_is_identity(p) && ec_has_prime_order(p)
}

/// Refuse the identity and every small-order or mixed-order point.
pub fn ec_assert_in_subgroup(p: &EdwardsPoint, label: &str) -> OtResult<()> {
    if ec_is_identity(p) {
        return pve(format!("{label}: identity element (forbidden here)"));
    }
    if !ec_has_prime_order(p) {
        return pve(format!("{label}: not in the prime-order subgroup (small-order/cofactor)"));
    }
    Ok(())
}

// ---- Schnorr proof of knowledge ------------------------------------------------------------------------------------------------

/// Proof of knowledge of `y` with `S = y*B`: commitment `U = r*B` and `z = r + e*y` (32 little-endian bytes; verification refuses
/// a `z` that is not canonical, i.e. >= L).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrProof {
    pub u: EdwardsPoint,
    pub z: [u8; 32],
}

const TAG_SCHNORR: &[u8] = b"atlas-pca-mpc/schnorr-dlog";

fn base_encoding() -> &'static Vec<u8> {
    static B: OnceLock<Vec<u8>> = OnceLock::new();
    B.get_or_init(|| ec_encode_point(&ec_base()))
}

/// `e = SHA-512(tag, len(ctx), ctx, B, S, U) mod L` (the digest read big-endian); `ctx` is the session binding.
fn schnorr_challenge(s: &EdwardsPoint, u: &EdwardsPoint, ctx: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    Digest::update(&mut h, TAG_SCHNORR);
    Digest::update(&mut h, u32be(ctx.len() as u64));
    Digest::update(&mut h, ctx);
    Digest::update(&mut h, base_encoding());
    Digest::update(&mut h, ec_encode_point(s));
    Digest::update(&mut h, ec_encode_point(u));
    let mut d: [u8; 64] = h.finalize().into();
    d.reverse();
    Scalar::from_bytes_mod_order_wide(&d)
}

/// Prove knowledge of `y` for `s`, bound to a non-empty session binding `ctx`; `nonce` is the secret commitment scalar.
pub fn schnorr_prove(y: &Scalar, s: &EdwardsPoint, nonce: &Scalar, ctx: &[u8]) -> OtResult<SchnorrProof> {
    if ctx.is_empty() {
        return inv("schnorrProve: a non-empty session binding is required");
    }
    if *nonce == Scalar::ZERO {
        return inv("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof");
    }
    let u = ec_mul_base(nonce);
    let e = schnorr_challenge(s, &u, ctx);
    Ok(SchnorrProof { u, z: (nonce + e * y).to_bytes() })
}

/// Check `z` is canonical, `U` is a valid subgroup point and `z*B = U + e*S`.
pub fn schnorr_verify(s: &EdwardsPoint, proof: &SchnorrProof, ctx: &[u8]) -> bool {
    if ctx.is_empty() {
        return false;
    }
    let z = match Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.z)) {
        Some(z) => z,
        None => return false,
    };
    if !ec_is_in_subgroup(&proof.u) {
        return false;
    }
    let e = schnorr_challenge(s, &proof.u, ctx);
    ec_mul_base(&z) == proof.u + s * e
}

// ---- word-array kernels of the extension hot path ------------------------------------------------------------------------------

/// The number of bit columns of the IKNP matrix (the security parameter kappa).
pub const OT_COLS: usize = 128;
/// The IKNP security parameter (number of base OTs / width of the selector).
pub const OT_KAPPA: usize = 128;
/// The KOS statistical parameter: extra random check rows beyond kappa that mask the revealed combination.
pub const OT_SSEC: usize = 128;
const OT_SEED_BYTES: usize = OT_KAPPA / 8;

const TAG_PRG_KEY: &[u8] = b"atlas-pca-mpc/ot-prg-aes";
const TAG_CRH_KEY: &[u8] = b"atlas-pca-mpc/ot-crh-aes-fixed-key";
const TAG_TWEAK_DOMAIN: &[u8] = b"atlas-pca-mpc/ot-crh-tweak-domain/v2";

fn aes128(key16: &[u8]) -> Aes128 {
    Aes128::new(GenericArray::from_slice(&key16[..16]))
}

fn aes_ecb(c: &Aes128, buf: &[u8]) -> Vec<u8> {
    let mut out = buf.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        c.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    out
}

fn le_words(b: &[u8], n: usize) -> Vec<u32> {
    (0..n).map(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().expect("4 bytes"))).collect()
}

fn le_bytes(w: &[u32], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * n);
    for x in &w[..n] {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// The low `n` little-endian bytes of a non-negative integer.
pub fn otx_big_to_bytes(v: &BigUint, n: usize) -> Vec<u8> {
    let mut b = v.to_bytes_le();
    b.resize(n, 0);
    b
}

/// The integer with the given little-endian bytes.
pub fn otx_bytes_to_big(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(b)
}

/// `nwords` u32 words of the PRG stream of `seed` from AES block `start_block` (AES-128-CTR; the unused high bits are not masked).
pub fn otx_prg_column(seed: &[u8], start_block: u64, nwords: usize) -> Vec<u32> {
    let key = sha256(&[TAG_PRG_KEY, seed]);
    let c = aes128(&key);
    let nblocks = (nwords * 4).div_ceil(16);
    let mut ks = Vec::with_capacity(nblocks * 16);
    for k in 0..nblocks {
        let mut blk = (start_block as u128 + k as u128).to_be_bytes();
        c.encrypt_block(GenericArray::from_mut_slice(&mut blk));
        ks.extend_from_slice(&blk);
    }
    le_words(&ks, nwords)
}

/// Clear the bits at positions >= `nbits` in a little-endian word column.
pub fn otx_mask_tail(col: &mut [u32], nbits: usize) {
    let full = nbits >> 5;
    let rem = nbits & 31;
    if rem != 0 && full < col.len() {
        col[full] &= (1u32 << rem) - 1;
    }
    let start = if rem != 0 { full + 1 } else { full };
    for x in col.iter_mut().skip(start) {
        *x = 0;
    }
}

/// Transpose in place the 32x32 bit matrix held as 32 words from `off`.
pub fn otx_transpose32(a: &mut [u32], off: usize) {
    let mut m: u32 = 0x0000_ffff;
    let mut j: usize = 16;
    while j != 0 {
        let mut k = 0usize;
        while k < 32 {
            let t = ((a[off + k] >> j) ^ a[off + k + j]) & m;
            a[off + k] ^= t << j;
            a[off + k + j] ^= t;
            k = (k + j + 1) & !j;
        }
        j >>= 1;
        m ^= m << j;
    }
}

/// Turn `OT_COLS` bit-columns (each `w` words, concatenated) into rows of four words: bit i of row j is bit j of column i.
pub fn otx_transpose_cols(cols: &[u32], w: usize, rows: usize) -> OtResult<Vec<u32>> {
    if cols.len() < OT_COLS * w || rows.div_ceil(32) > w {
        return inv("transposeCols: columns too short for the requested rows");
    }
    let mut out = vec![0u32; rows * 4];
    let mut tmp = [0u32; 32];
    for rb in 0..rows.div_ceil(32) {
        for cb in 0..4 {
            for (c, t) in tmp.iter_mut().enumerate() {
                *t = cols[(cb * 32 + c) * w + rb];
            }
            otx_transpose32(&mut tmp, 0);
            let lim = 32.min(rows - rb * 32);
            for (r, t) in tmp.iter().enumerate().take(lim) {
                out[(rb * 32 + r) * 4 + cb] = *t;
            }
        }
    }
    Ok(out)
}

/// `acc ^= ` the four-word element at `v[vo..]`.
pub fn otx_gf_xor_into(acc: &mut [u32], v: &[u32], vo: usize) {
    for i in 0..4 {
        acc[i] ^= v[vo + i];
    }
}

/// `acc *= x` in GF(2^128) (x^128 = x^7 + x^2 + x + 1).
pub fn otx_gf_mul_x(acc: &mut [u32]) {
    let carry = acc[3] >> 31;
    acc[3] = (acc[3] << 1) | (acc[2] >> 31);
    acc[2] = (acc[2] << 1) | (acc[1] >> 31);
    acc[1] = (acc[1] << 1) | (acc[0] >> 31);
    acc[0] <<= 1;
    if carry != 0 {
        acc[0] ^= 0x87;
    }
}

/// XOR into `acc` `chi[j]` (four words) for every set bit `j` of the word column `col`.
pub fn otx_accum_column(col: &[u32], chi: &[u32], acc: &mut [u32]) {
    for (w, &word) in col.iter().enumerate() {
        let base = w << 5;
        let mut x = word;
        while x != 0 {
            let o = (base + x.trailing_zeros() as usize) << 2;
            for i in 0..4 {
                acc[i] ^= chi[o + i];
            }
            x &= x - 1;
        }
    }
}

/// `sum_i x^i * (sum_{j in col_i} chi_j)` by Horner over the `OT_COLS` columns of `w` words.
pub fn otx_kos_combine(cols: &[u32], w: usize, chi: &[u32]) -> OtResult<Vec<u32>> {
    // the challenges cover the rows that exist (4 words each), not the padded word count: a tail of the last word past the last row is
    // zero in every column the protocol builds, and a set bit there is refused rather than read out of range
    let rows = chi.len() / 4;
    if cols.len() < OT_COLS * w || rows == 0 || rows > 32 * w {
        return inv("kosCombine: columns or challenges too short");
    }
    for c in 0..OT_COLS {
        for (j, word) in cols[c * w..(c + 1) * w].iter().enumerate() {
            let first = j * 32;
            let live = rows.saturating_sub(first).min(32);
            let dead_mask = if live >= 32 { 0 } else { !0u32 << live };
            if word & dead_mask != 0 {
                return inv("kosCombine: columns or challenges too short");
            }
        }
    }
    let mut acc = vec![0u32; 4];
    for i in (0..OT_COLS).rev() {
        otx_gf_mul_x(&mut acc);
        let mut part = [0u32; 4];
        otx_accum_column(&cols[i * w..(i + 1) * w], chi, &mut part);
        otx_gf_xor_into(&mut acc, &part, 0);
    }
    Ok(acc)
}

/// A 128-bit integer from / to its four little-endian words.
pub fn otx_gf_from_u128(v: u128) -> Vec<u32> {
    (0..4).map(|i| (v >> (32 * i)) as u32).collect()
}

pub fn otx_gf_to_u128(w: &[u32]) -> u128 {
    (0..4).fold(0u128, |a, i| a | ((w[i] as u128) << (32 * i)))
}

/// The 64-bit session domain of a channel: `SHA-256(tag, binding)[0:8]` as two little-endian words.
pub fn otx_tweak_domain(binding: &[u8]) -> [u32; 2] {
    let d = sha256(&[TAG_TWEAK_DOMAIN, binding]);
    [u32::from_le_bytes(d[0..4].try_into().expect("4")), u32::from_le_bytes(d[4..8].try_into().expect("4"))]
}

/// `H(tweak, row_j)` for `n` rows of four words (batched tweakable correlation-robust hash `pi(pi(x) ^ t) ^ pi(x)` with a fixed-key
/// AES-128): two u32 words (the low 64 bits) per row. `offset` is the channel-global row offset (a non-negative safe integer).
pub fn otx_tmmo_crh(rows: &[u32], n: usize, offset: i64, domain: &[u32]) -> OtResult<Vec<u32>> {
    if !(0..=(1i64 << 53) - 1).contains(&offset) {
        return inv("tmmoCrh: tweak offset must be a non-negative safe integer");
    }
    if domain.len() != 2 {
        return inv("tmmoCrh: tweak domain must be 2 words");
    }
    if rows.len() < n * 4 {
        return inv("tmmoCrh: rows too short");
    }
    let c = aes128(&sha256(&[TAG_CRH_KEY]));
    let a = aes_ecb(&c, &le_bytes(rows, n * 4));
    let aw = le_words(&a, n * 4);
    let mut b = vec![0u32; n * 4];
    for j in 0..n {
        let o = j * 4;
        let v = offset as u64 + j as u64;
        b[o] = aw[o] ^ v as u32;
        b[o + 1] = aw[o + 1] ^ (v >> 32) as u32;
        b[o + 2] = aw[o + 2] ^ domain[0];
        b[o + 3] = aw[o + 3] ^ domain[1];
    }
    let cw = le_words(&aes_ecb(&c, &le_bytes(&b, n * 4)), n * 4);
    let mut out = vec![0u32; n * 2];
    for j in 0..n {
        out[2 * j] = cw[4 * j] ^ aw[4 * j];
        out[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1];
    }
    Ok(out)
}

/// The 64-bit value of the two words at index `j` of an [`otx_tmmo_crh`] output.
pub fn otx_word64(h: &[u32], j: usize) -> u64 {
    ((h[2 * j + 1] as u64) << 32) | h[2 * j] as u64
}

// ---- base OT: bindings, transcript hash, KDF -----------------------------------------------------------------------------------

/// The session binding of one base OT: who runs it, in which session and round (indices are uint32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseOtBinding {
    pub session_id: Vec<u8>,
    pub sender_index: i64,
    pub receiver_index: i64,
    pub round: String,
}

const TAG_BINDING: &[u8] = b"atlas-pca-mpc/base-ot-binding";
const TAG_TRANSCRIPT: &[u8] = b"atlas-pca-mpc/base-ot-transcript";
const TAG_OT_KDF: &[u8] = b"atlas-pca-mpc/ot-kdf";
const TAG_KOS: &[u8] = b"atlas-pca-mpc/ot-kos";
const TAG_OT_COMMIT: &[u8] = b"atlas-pca-mpc/ot-msg-commit";

/// The canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input).
pub fn binding_bytes(b: &BaseOtBinding) -> OtResult<Vec<u8>> {
    if b.session_id.len() < 8 || b.session_id.len() > 64 {
        return inv("base-OT binding: sessionId must be 8..64 bytes");
    }
    if !(0..=0xffff_ffff).contains(&b.sender_index) {
        return inv("base-OT binding: senderIndex must be a uint32");
    }
    if !(0..=0xffff_ffff).contains(&b.receiver_index) {
        return inv("base-OT binding: receiverIndex must be a uint32");
    }
    if b.sender_index == b.receiver_index {
        return inv("base-OT binding: sender and receiver must be different parties");
    }
    let round = b.round.as_bytes();
    if round.is_empty() || round.len() > 64 {
        return inv("base-OT binding: round label must be 1..64 bytes");
    }
    let mut out = TAG_BINDING.to_vec();
    out.extend_from_slice(&u32be(b.session_id.len() as u64));
    out.extend_from_slice(&b.session_id);
    out.extend_from_slice(&u32be(b.sender_index as u64));
    out.extend_from_slice(&u32be(b.receiver_index as u64));
    out.extend_from_slice(&u32be(round.len() as u64));
    out.extend_from_slice(round);
    Ok(out)
}

/// A fresh binding for an in-process OT (sender 0, receiver 1): a random 16-byte session id.
pub fn random_binding(rng: &mut OtRng, round: &str) -> BaseOtBinding {
    BaseOtBinding { session_id: rng.bytes(16), sender_index: 0, receiver_index: 1, round: round.to_string() }
}

/// Hash the whole base-OT transcript: the binding, S and every receiver point, in order.
pub fn base_ot_transcript_hash(binding: &BaseOtBinding, s: &EdwardsPoint, r: &[EdwardsPoint]) -> OtResult<Vec<u8>> {
    let bb = binding_bytes(binding)?;
    let mut parts: Vec<Vec<u8>> = vec![TAG_TRANSCRIPT.to_vec(), bb, ec_encode_point(s), u32be(r.len() as u64).to_vec()];
    for p in r {
        parts.push(ec_encode_point(p));
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(sha256(&refs))
}

/// `H("ot-kdf" || H(transcript) || index || R_i || P)`, 16 bytes.
pub fn base_ot_kdf(transcript_hash: &[u8], index: usize, ri: &EdwardsPoint, p: &EdwardsPoint) -> Vec<u8> {
    sha256(&[TAG_OT_KDF, transcript_hash, &u32be(index as u64), &ec_encode_point(ri), &ec_encode_point(p)])[..OT_SEED_BYTES].to_vec()
}

/// The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of `u` (given as
/// the canonical `ceil(m_ext / 8)`-byte encodings).
pub fn kos_chi_words_bytes(binding: &[u8], round: usize, cols: &[Vec<u8>], m_ext: usize) -> Vec<u32> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, TAG_KOS);
    Update::update(&mut xof, &u32be(binding.len() as u64));
    Update::update(&mut xof, binding);
    Update::update(&mut xof, &u32be(round as u64));
    Update::update(&mut xof, &u32be(m_ext as u64));
    Update::update(&mut xof, &u32be(cols.len() as u64));
    for c in cols {
        Update::update(&mut xof, c);
    }
    let mut out = vec![0u8; m_ext * 16];
    xof.finalize_xof().read(&mut out);
    le_words(&out, m_ext * 4)
}

/// [`kos_chi_words_bytes`] over columns given as integers.
pub fn kos_chi_words(binding: &[u8], round: usize, u: &[BigUint], m_ext: usize) -> Vec<u32> {
    let cb = m_ext.div_ceil(8);
    let cols: Vec<Vec<u8>> = u.iter().map(|c| otx_big_to_bytes(c, cb)).collect();
    kos_chi_words_bytes(binding, round, &cols, m_ext)
}

/// The KOS row-weights as GF(2^128) integers.
pub fn kos_challenges(binding: &[u8], round: usize, u: &[BigUint], m_ext: usize) -> Vec<u128> {
    let w = kos_chi_words(binding, round, u, m_ext);
    (0..m_ext).map(|j| otx_gf_to_u128(&w[4 * j..4 * j + 4])).collect()
}

// ---- base OT --------------------------------------------------------------------------------------------------------------------

/// TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (`None` = honest).
#[derive(Default)]
pub struct BaseOtTamper {
    pub tamper_s: Option<Box<dyn Fn(&EdwardsPoint) -> EdwardsPoint>>,
    pub tamper_proof: Option<Box<dyn Fn(&SchnorrProof) -> SchnorrProof>>,
    pub tamper_r: Option<Box<dyn Fn(&mut Vec<EdwardsPoint>)>>,
    pub tamper_ciphertext: Option<Box<dyn Fn(&mut Vec<OtPair>)>>,
}

/// The base-OT transcript; `ct` and `com` hold `[i][slot]` byte strings.
#[derive(Debug, Clone)]
pub struct BaseOtTranscript {
    pub s: EdwardsPoint,
    pub proof: SchnorrProof,
    pub r: Vec<EdwardsPoint>,
    pub ct: Vec<OtPair>,
    pub com: Vec<OtPair>,
}

#[derive(Debug, Clone)]
pub struct BaseOtResult {
    pub received: Vec<Vec<u8>>,
    pub transcript: BaseOtTranscript,
}

/// A pluggable chosen-message base OT: `messages[i] = [m0, m1]`; it returns the receiver's recovered messages.
pub type BaseOtFn = fn(&[OtPair], &[i64], &mut OtRng) -> OtResult<Vec<Vec<u8>>>;

/// The output of the malicious-secure random base OT: validated points and the two pads per index.
#[derive(Debug, Clone)]
pub struct MalRandomOtResult {
    pub s: EdwardsPoint,
    pub proof: SchnorrProof,
    pub r: Vec<EdwardsPoint>,
    pub sender_pads: Vec<OtPair>,
    pub recv_pads: Vec<Vec<u8>>,
}

fn ot_commit(i: usize, b: i64, msg: &[u8], pad: &[u8]) -> Vec<u8> {
    sha256(&[TAG_OT_COMMIT, &u32be(i as u64), &[(b & 1) as u8], msg, pad])
}

/// The sender's first message and secret: `y`, `T = y*S`, `S = y*B` and the Schnorr proof of `y`.
pub struct BaseOtSenderSetup {
    pub y: Scalar,
    pub t: EdwardsPoint,
    pub s: EdwardsPoint,
    pub proof: SchnorrProof,
}

pub fn mal_base_ot_sender_setup(rng: &mut OtRng, binding: &BaseOtBinding) -> OtResult<BaseOtSenderSetup> {
    let ctx = binding_bytes(binding)?;
    let y = rng.scalar();
    let s = ec_mul_base(&y);
    let t = ec_mul(&y, &s);
    let nonce = rng.scalar();
    let proof = schnorr_prove(&y, &s, &nonce, &ctx)?;
    Ok(BaseOtSenderSetup { y, t, s, proof })
}

/// Validate `S` and its proof, then answer each choice with `R_i = x_i*B` (`+ S` when the choice is 1).
pub fn mal_base_ot_receiver_respond(
    s: &EdwardsPoint,
    proof: &SchnorrProof,
    choices: &[i64],
    rng: &mut OtRng,
    binding: &BaseOtBinding,
) -> OtResult<(Vec<EdwardsPoint>, Vec<Vec<u8>>)> {
    let ctx = binding_bytes(binding)?;
    ec_assert_in_subgroup(s, "base-OT S (received by receiver)")?;
    if !schnorr_verify(s, proof, &ctx) {
        return Err(OtError::BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting".into()));
    }
    let mut r = Vec::with_capacity(choices.len());
    let mut xs = Vec::with_capacity(choices.len());
    for c in choices {
        let x = rng.scalar();
        let mut ri = ec_mul_base(&x);
        if c & 1 == 1 {
            ri += s;
        }
        r.push(ri);
        xs.push(x);
    }
    let th = base_ot_transcript_hash(binding, s, &r)?;
    let pads = (0..choices.len()).map(|i| base_ot_kdf(&th, i, &r[i], &ec_mul(&xs[i], s))).collect();
    Ok((r, pads))
}

/// Validate every `R_i` and derive the two pads of each index.
pub fn mal_base_ot_sender_derive(y: &Scalar, t: &EdwardsPoint, r: &[EdwardsPoint], s: &EdwardsPoint, binding: &BaseOtBinding) -> OtResult<Vec<OtPair>> {
    for (i, p) in r.iter().enumerate() {
        ec_assert_in_subgroup(p, &format!("base-OT R_{i} (received by sender)"))?;
    }
    let th = base_ot_transcript_hash(binding, s, r)?;
    Ok(r.iter()
        .enumerate()
        .map(|(i, p)| {
            let yr = ec_mul(y, p);
            [base_ot_kdf(&th, i, p, &yr), base_ot_kdf(&th, i, p, &(yr - t))]
        })
        .collect())
}

/// Run the random base OT with both roles in process. A `None` binding is a fresh random one.
pub fn mal_base_random_ot(choices: &[i64], rng: &mut OtRng, tamper: Option<&BaseOtTamper>, binding: Option<&BaseOtBinding>) -> OtResult<MalRandomOtResult> {
    let b = match binding {
        Some(b) => b.clone(),
        None => random_binding(rng, "base-ot"),
    };
    let setup = mal_base_ot_sender_setup(rng, &b)?;
    let mut s = setup.s;
    let mut proof = setup.proof.clone();
    if let Some(f) = tamper.and_then(|t| t.tamper_s.as_ref()) {
        s = f(&s);
    }
    if let Some(f) = tamper.and_then(|t| t.tamper_proof.as_ref()) {
        proof = f(&proof);
    }
    let (mut r, recv_pads) = mal_base_ot_receiver_respond(&s, &proof, choices, rng, &b)?;
    if let Some(f) = tamper.and_then(|t| t.tamper_r.as_ref()) {
        f(&mut r);
    }
    let sender_pads = mal_base_ot_sender_derive(&setup.y, &setup.t, &r, &s, &b)?;
    Ok(MalRandomOtResult { s, proof, r, sender_pads, recv_pads })
}

/// One-time-pad the messages under the sender pads and commit to each (message, pad).
pub fn base_ot_sender_encrypt(messages: &[OtPair], sender_pads: &[OtPair]) -> OtResult<(Vec<OtPair>, Vec<OtPair>)> {
    if messages.len() != sender_pads.len() {
        return inv("baseOT: messages/pads length mismatch");
    }
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() > OT_SEED_BYTES || m[1].len() > OT_SEED_BYTES || m[0].len() != m[1].len() {
            return inv(format!("baseOT: message pair {i} must be equal length and at most {OT_SEED_BYTES} bytes (pad width)"));
        }
    }
    let mut ct = Vec::with_capacity(messages.len());
    let mut com = Vec::with_capacity(messages.len());
    for (i, m) in messages.iter().enumerate() {
        let (p0, p1) = (&sender_pads[i][0], &sender_pads[i][1]);
        ct.push([xor_bytes(&m[0], p0)?, xor_bytes(&m[1], p1)?]);
        com.push([ot_commit(i, 0, &m[0], p0), ot_commit(i, 1, &m[1], p1)]);
    }
    Ok((ct, com))
}

/// Recover the chosen messages, aborting on any ciphertext inconsistent with its commitment.
pub fn base_ot_receiver_decrypt(choices: &[i64], recv_pads: &[Vec<u8>], ct: &[OtPair], com: &[OtPair]) -> OtResult<Vec<Vec<u8>>> {
    if ct.len() != choices.len() || com.len() != choices.len() || recv_pads.len() != choices.len() {
        return Err(OtError::BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting".into()));
    }
    let mut received = Vec::with_capacity(choices.len());
    for (i, ch) in choices.iter().enumerate() {
        let ci = (ch & 1) as usize;
        if ct[i][0].len() != ct[i][1].len() || ct[i][0].len() > OT_SEED_BYTES || recv_pads[i].len() < ct[i][ci].len() {
            return Err(OtError::BaseOtAbort(format!("base OT (index {i}): malformed ciphertext shape; aborting")));
        }
        let m = xor_bytes(&ct[i][ci], &recv_pads[i])?;
        if !ct_eq(&ot_commit(i, ci as i64, &m, &recv_pads[i]), &com[i][ci]) {
            return Err(OtError::BaseOtAbort(format!("base OT (index {i}): sender ciphertext inconsistent with its commitment; aborting")));
        }
        received.push(m);
    }
    Ok(received)
}

/// A chosen-message 1-of-2 OT for `choices.len()` transfers, built over the random base OT.
pub fn base_ot(
    messages: &[OtPair],
    choices: &[i64],
    rng: &mut OtRng,
    tamper: Option<&BaseOtTamper>,
    binding: Option<&BaseOtBinding>,
) -> OtResult<BaseOtResult> {
    let b = match binding {
        Some(b) => b.clone(),
        None => random_binding(rng, "base-ot"),
    };
    if messages.len() != choices.len() {
        return inv("baseOT: messages/choices length mismatch");
    }
    let ro = mal_base_random_ot(choices, rng, tamper, Some(&b))?;
    let (mut ct, com) = base_ot_sender_encrypt(messages, &ro.sender_pads)?;
    if let Some(f) = tamper.and_then(|t| t.tamper_ciphertext.as_ref()) {
        f(&mut ct);
    }
    let received = base_ot_receiver_decrypt(choices, &ro.recv_pads, &ct, &com)?;
    Ok(BaseOtResult { received, transcript: BaseOtTranscript { s: ro.s, proof: ro.proof, r: ro.r, ct, com } })
}

// ---- OT extension (IKNP + KOS) -------------------------------------------------------------------------------------------------

/// A non-negative-or-not integer column of the `u` matrix as it travels on the wire (a malicious receiver may send anything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UCol {
    pub neg: bool,
    pub v: BigUint,
}

impl UCol {
    pub fn new(v: BigUint) -> UCol {
        UCol { neg: false, v }
    }

    /// The decimal text (`-` for a negative column).
    pub fn to_decimal(&self) -> String {
        format!("{}{}", if self.neg { "-" } else { "" }, self.v.to_str_radix(10))
    }

    fn in_range(&self, m_ext: usize) -> bool {
        !self.neg && self.v.bits() <= m_ext
    }
}

/// TEST-ONLY hook that mutates the `u` columns on the wire (a malicious extension receiver); the second argument is the round.
pub type TamperU = Box<dyn FnMut(&mut Vec<UCol>, usize)>;

/// The receiver's extension-round message: the `u` columns and the KOS values `(x, t)`.
#[derive(Debug, Clone)]
pub struct ExtRoundMsg {
    pub u: Vec<UCol>,
    pub x: u128,
    pub t_comb: u128,
}

/// The receiver's per-round state between `begin` and `finish`.
#[derive(Debug, Clone)]
pub struct ExtPending {
    m: usize,
    choice_bits: Vec<i64>,
    t: Vec<u32>,
    w: usize,
    row_offset: i64,
}

fn check_choices(c: &[i64]) -> OtResult<()> {
    for (j, b) in c.iter().enumerate() {
        if *b != 0 && *b != 1 {
            return inv(format!("OtChannel.extend: choice bit {j} must be 0 or 1"));
        }
    }
    Ok(())
}

/// The extension receiver (base-OT sender): it makes the seed pairs, then per round the `u` matrix and the KOS values.
pub struct OtExtReceiver {
    kos_binding: Vec<u8>,
    seed0: Vec<Vec<u8>>,
    seed1: Vec<Vec<u8>>,
    blk0: [u64; OT_KAPPA],
    blk1: [u64; OT_KAPPA],
    round: usize,
    rows_done: i64,
    tweak_domain: [u32; 2],
    pub ready: bool,
}

impl OtExtReceiver {
    pub fn new(kos_binding: Vec<u8>) -> Self {
        let tweak_domain = otx_tweak_domain(&kos_binding);
        OtExtReceiver {
            kos_binding,
            seed0: vec![],
            seed1: vec![],
            blk0: [0; OT_KAPPA],
            blk1: [0; OT_KAPPA],
            round: 0,
            rows_done: 0,
            tweak_domain,
            ready: false,
        }
    }

    /// The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices.
    pub fn make_seeds(&mut self, rng: &mut OtRng) -> Vec<OtPair> {
        let mut messages = Vec::with_capacity(OT_KAPPA);
        for _ in 0..OT_KAPPA {
            let k0 = rng.bytes(OT_SEED_BYTES);
            let k1 = rng.bytes(OT_SEED_BYTES);
            self.seed0.push(k0.clone());
            self.seed1.push(k1.clone());
            messages.push([k0, k1]);
        }
        self.ready = true;
        messages
    }

    /// One round's `u` columns and KOS values for the choice bits.
    pub fn begin(&mut self, rng: &mut OtRng, choice_bits: &[i64], tamper: Option<&mut TamperU>) -> OtResult<(ExtRoundMsg, ExtPending)> {
        if !self.ready {
            return inv("OtExtReceiver: base OT not done");
        }
        check_choices(choice_bits)?;
        let m = choice_bits.len();
        let round_idx = self.round;
        self.round += 1;
        let row_offset = self.rows_done;
        self.rows_done += m as i64;
        let pad = OT_KAPPA + OT_SSEC;
        let m_ext = m + pad;
        let w = m_ext.div_ceil(32);
        let col_bytes = m_ext.div_ceil(8);
        let mut bvec = vec![0u32; w];
        for (j, c) in choice_bits.iter().enumerate() {
            if c & 1 != 0 {
                bvec[j >> 5] |= 1 << (j & 31);
            }
        }
        let pad_bytes = rng.bytes(pad);
        for (p, b) in pad_bytes.iter().enumerate() {
            if b & 1 != 0 {
                let j = m + p;
                bvec[j >> 5] |= 1 << (j & 31);
            }
        }
        let blocks = w.div_ceil(4) as u64;
        let mut t = vec![0u32; OT_COLS * w];
        let mut u: Vec<UCol> = Vec::with_capacity(OT_COLS);
        let mut uw = vec![0u32; w];
        for i in 0..OT_KAPPA {
            let mut ti = otx_prg_column(&self.seed0[i], self.blk0[i], w);
            let mut gi = otx_prg_column(&self.seed1[i], self.blk1[i], w);
            self.blk0[i] += blocks;
            self.blk1[i] += blocks;
            otx_mask_tail(&mut ti, m_ext);
            otx_mask_tail(&mut gi, m_ext);
            t[i * w..(i + 1) * w].copy_from_slice(&ti);
            for k in 0..w {
                uw[k] = gi[k] ^ ti[k] ^ bvec[k];
            }
            u.push(UCol::new(otx_bytes_to_big(&le_bytes(&uw, w)[..col_bytes])));
        }
        if let Some(f) = tamper {
            (**f)(&mut u, round_idx);
        }
        let pending = ExtPending { m, choice_bits: choice_bits.to_vec(), t, w, row_offset };
        if u.len() != OT_COLS || u.iter().any(|c| !c.in_range(m_ext)) {
            return Ok((ExtRoundMsg { u, x: 0, t_comb: 0 }, pending));
        }
        let cols: Vec<Vec<u8>> = u.iter().map(|c| otx_big_to_bytes(&c.v, col_bytes)).collect();
        let chi = kos_chi_words_bytes(&self.kos_binding, round_idx, &cols, m_ext);
        let mut x = [0u32; 4];
        otx_accum_column(&bvec, &chi, &mut x);
        let t_comb = otx_kos_combine(&pending.t, w, &chi)?;
        Ok((ExtRoundMsg { u, x: otx_gf_to_u128(&x), t_comb: otx_gf_to_u128(&t_comb) }, pending))
    }

    /// The receiver's output `m_{c_j}` for every row `j`, from the sender's ciphertexts.
    pub fn finish(&mut self, p: &ExtPending, y0: &[u64], y1: &[u64]) -> OtResult<Vec<u64>> {
        let m = p.m;
        if y0.len() != m || y1.len() != m {
            return Err(OtError::MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting".into()));
        }
        let rows = otx_transpose_cols(&p.t, p.w, m)?;
        let h = otx_tmmo_crh(&rows, m, p.row_offset, &self.tweak_domain)?;
        Ok((0..m).map(|j| (if p.choice_bits[j] == 1 { y1[j] } else { y0[j] }) ^ otx_word64(&h, j)).collect())
    }
}

/// The extension sender (base-OT receiver): it holds the secret selector `s` and answers each round after the KOS check.
pub struct OtExtSender {
    kos_binding: Vec<u8>,
    s: Vec<i64>,
    s_bits: u128,
    seeds: Vec<Vec<u8>>,
    blk: Vec<u64>,
    round: usize,
    rows_done: i64,
    tweak_domain: [u32; 2],
    pub ready: bool,
}

impl OtExtSender {
    pub fn new(kos_binding: Vec<u8>) -> Self {
        let tweak_domain = otx_tweak_domain(&kos_binding);
        OtExtSender { kos_binding, s: vec![], s_bits: 0, seeds: vec![], blk: vec![], round: 0, rows_done: 0, tweak_domain, ready: false }
    }

    pub fn make_selector(&mut self, rng: &mut OtRng) -> Vec<i64> {
        self.s = (0..OT_KAPPA).map(|_| (rng.bytes(1)[0] & 1) as i64).collect();
        self.s.clone()
    }

    pub fn set_seeds(&mut self, seeds: Vec<Vec<u8>>) -> OtResult<()> {
        if seeds.len() != OT_KAPPA || self.s.len() != OT_KAPPA {
            return inv("OtExtSender: wrong base-OT output size");
        }
        self.seeds = seeds;
        self.blk = vec![0; OT_KAPPA];
        self.s_bits = (0..OT_KAPPA).fold(0u128, |a, i| if self.s[i] == 1 { a | (1u128 << i) } else { a });
        self.ready = true;
        Ok(())
    }

    /// The selector `s` as an integer, bit `i` = `s[i]`.
    pub fn selector(&self) -> u128 {
        self.s_bits
    }

    fn kos_abort(round: usize, why: &str) -> OtError {
        OtError::MalOtAbort(format!("KOS check (round {round}): {why}; a cheating OT-extension receiver was detected; aborting"))
    }

    /// Run the KOS check on the receiver's message and, when it holds, answer with the two ciphertext vectors.
    pub fn respond(&mut self, msg: &ExtRoundMsg, msg0: &[u64], msg1: &[u64]) -> OtResult<(Vec<u64>, Vec<u64>)> {
        if !self.ready {
            return inv("OtExtSender: base OT not done");
        }
        let m = msg0.len();
        if msg1.len() != m {
            return inv("OtChannel.extend: length mismatch");
        }
        let round_idx = self.round;
        self.round += 1;
        let row_offset = self.rows_done;
        self.rows_done += m as i64;
        let m_ext = m + OT_KAPPA + OT_SSEC;
        if msg.u.len() != OT_COLS {
            return Err(Self::kos_abort(round_idx, "wrong number of u columns"));
        }
        for (i, c) in msg.u.iter().enumerate() {
            if !c.in_range(m_ext) {
                return Err(Self::kos_abort(round_idx, &format!("malformed u column {i}")));
            }
        }
        let w = m_ext.div_ceil(32);
        let col_bytes = m_ext.div_ceil(8);
        let blocks = w.div_ceil(4) as u64;
        let mut q = vec![0u32; OT_COLS * w];
        let mut ubytes: Vec<Vec<u8>> = Vec::with_capacity(OT_COLS);
        for i in 0..OT_KAPPA {
            ubytes.push(otx_big_to_bytes(&msg.u[i].v, col_bytes));
            let mut ks = otx_prg_column(&self.seeds[i], self.blk[i], w);
            self.blk[i] += blocks;
            otx_mask_tail(&mut ks, m_ext);
            if self.s[i] == 1 {
                let mut ub = vec![0u8; 4 * w];
                ub[..col_bytes].copy_from_slice(&ubytes[i]);
                let uw = le_words(&ub, w);
                for k in 0..w {
                    ks[k] ^= uw[k];
                }
            }
            q[i * w..(i + 1) * w].copy_from_slice(&ks);
        }
        let chi = kos_chi_words_bytes(&self.kos_binding, round_idx, &ubytes, m_ext);
        let comb = otx_kos_combine(&q, w, &chi)?;
        let expected = msg.t_comb ^ gf128_mul(msg.x, self.s_bits);
        if otx_gf_to_u128(&comb) != expected {
            return Err(Self::kos_abort(round_idx, "correlation check FAILED"));
        }
        let mut rows = otx_transpose_cols(&q, w, m)?;
        let h0 = otx_tmmo_crh(&rows, m, row_offset, &self.tweak_domain)?;
        let sw = otx_gf_from_u128(self.s_bits);
        for j in 0..m {
            otx_gf_xor_into(&mut rows[4 * j..4 * j + 4], &sw, 0);
        }
        let h1 = otx_tmmo_crh(&rows, m, row_offset, &self.tweak_domain)?;
        let y0 = (0..m).map(|j| msg0[j] ^ otx_word64(&h0, j)).collect();
        let y1 = (0..m).map(|j| msg1[j] ^ otx_word64(&h1, j)).collect();
        Ok((y0, y1))
    }
}

/// One extension's receiver output and the receiver's `u` matrix.
#[derive(Debug, Clone)]
pub struct OtExtended {
    pub received: Vec<u64>,
    pub u_matrix: Vec<UCol>,
}

/// An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later `extend`. The base OT is
/// the EC base OT unless a [`BaseOtFn`] supplies another (for example a post-quantum one).
pub struct OtChannel {
    rng: OtRng,
    base_ot_fn: Option<BaseOtFn>,
    binding: Option<BaseOtBinding>,
    recv: Option<OtExtReceiver>,
    send: Option<OtExtSender>,
    /// The EC base-OT transcript of the kappa setup transfers (`None` when a custom base OT is used).
    pub base_transcript: Option<BaseOtTranscript>,
    /// TEST-ONLY: mutates the extension receiver's `u` matrix.
    pub tamper_u: Option<TamperU>,
}

impl OtChannel {
    /// A channel; `binding` (optional) supplies the session id and party indices (its round is ignored).
    pub fn new(rng: OtRng, base_ot_fn: Option<BaseOtFn>, binding: Option<BaseOtBinding>) -> Self {
        OtChannel { rng, base_ot_fn, binding, recv: None, send: None, base_transcript: None, tamper_u: None }
    }

    fn setup(&mut self) -> OtResult<()> {
        let base = match &self.binding {
            Some(b) => b.clone(),
            None => random_binding(&mut self.rng, "x"),
        };
        let kos = binding_bytes(&BaseOtBinding { round: "iknp-kos".into(), ..base.clone() })?;
        let mut r = OtExtReceiver::new(kos.clone());
        let mut sd = OtExtSender::new(kos);
        let messages = r.make_seeds(&mut self.rng);
        let sel = sd.make_selector(&mut self.rng);
        let seeds = match self.base_ot_fn {
            Some(f) => f(&messages, &sel, &mut self.rng)?,
            None => {
                let b = BaseOtBinding { round: "iknp-kappa-setup".into(), ..base };
                let res = base_ot(&messages, &sel, &mut self.rng, None, Some(&b))?;
                self.base_transcript = Some(res.transcript);
                res.received
            }
        };
        sd.set_seeds(seeds)?;
        self.recv = Some(r);
        self.send = Some(sd);
        Ok(())
    }

    fn ensure_ready(&mut self) -> OtResult<()> {
        if self.recv.is_none() {
            self.setup()?;
        }
        Ok(())
    }

    /// The sender's secret selector (running the setup on first use).
    pub fn selector(&mut self) -> OtResult<u128> {
        self.ensure_ready()?;
        Ok(self.send.as_ref().expect("ready").selector())
    }

    /// Transfer `choice_bits.len()` OTs: the receiver learns `msg_{c_j}[j]` for every row `j`. Messages are 64-bit.
    pub fn extend(&mut self, choice_bits: &[i64], msg0: &[u64], msg1: &[u64]) -> OtResult<OtExtended> {
        self.ensure_ready()?;
        let m = choice_bits.len();
        if msg0.len() != m || msg1.len() != m {
            return inv("OtChannel.extend: length mismatch");
        }
        if m == 0 {
            return Ok(OtExtended { received: vec![], u_matrix: vec![] });
        }
        check_choices(choice_bits)?;
        let (recv, send) = (self.recv.as_mut().expect("ready"), self.send.as_mut().expect("ready"));
        let (msg, pending) = recv.begin(&mut self.rng, choice_bits, self.tamper_u.as_mut())?;
        let (y0, y1) = send.respond(&msg, msg0, msg1)?;
        let received = recv.finish(&pending, &y0, &y1)?;
        Ok(OtExtended { received, u_matrix: msg.u })
    }
}

// ---- ML-KEM-768 base OT --------------------------------------------------------------------------------------------------------

const KEM_MSG_BYTES: usize = 32;
const KEM_SEED_BYTES: usize = 64;
const KEM_NONCE_BYTES: usize = 32;
/// The width of the random-OT secrets of the malicious KEM OT.
pub const KEM_OT_SECRET_BYTES: usize = 32;

const TAG_KEM_PAD: &[u8] = b"atlas-pca-mpc/kem-ot-pad";
const TAG_KEM_COMMIT: &[u8] = b"atlas-pca-mpc/kem-ot-commit";
const TAG_KEM_SID: &[u8] = b"atlas-pca-mpc/kem-ot-sid";
const TAG_KEM_MAL_PAD: &[u8] = b"atlas-pca-mpc/kem-ot-mal-pad";
const TAG_KEM_MAL_SECRET: &[u8] = b"atlas-pca-mpc/kem-ot-mal-secret";

type KemDk = DecapsulationKey<MlKem768Params>;
type KemEk = EncapsulationKey<MlKem768Params>;

/// ML-KEM-768 key generation from the 64-byte seed `d || z` (FIPS 203): the public key bytes and the decapsulation key.
fn kem_keygen(rng: &mut OtRng) -> (Vec<u8>, KemDk) {
    let seed = rng.bytes(KEM_SEED_BYTES);
    let (mut d, mut z) = (B32::default(), B32::default());
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    (ek.as_bytes().to_vec(), dk)
}

/// Encapsulate to `pubkey` with the 32-byte message drawn from `rng`, returning `(ciphertext, shared secret)`. A public key whose
/// encoding is not canonical (a coefficient >= q) is refused (the FIPS 203 modulus check, by re-encoding).
fn kem_encaps(pubkey: &[u8], rng: &mut OtRng) -> OtResult<(Vec<u8>, Vec<u8>)> {
    let enc = match Encoded::<KemEk>::try_from(pubkey) {
        Ok(e) => e,
        Err(_) => return inv("kem-ot: bad ML-KEM public key length"),
    };
    let ek = KemEk::from_bytes(&enc);
    if ek.as_bytes().as_slice() != pubkey {
        return inv("kem-ot: ML-KEM public key is not a canonical encoding");
    }
    let mut m = B32::default();
    m.copy_from_slice(&rng.bytes(KEM_MSG_BYTES));
    match ek.encapsulate_deterministic(&m) {
        Ok((ct, ss)) => Ok((ct.to_vec(), ss.to_vec())),
        Err(_) => inv("kem-ot: ML-KEM encapsulation failed"),
    }
}

fn kem_decaps(dk: &KemDk, ct: &[u8]) -> OtResult<Vec<u8>> {
    let mut c = ml_kem::Ciphertext::<MlKem768>::default();
    if c.len() != ct.len() {
        return inv("kem-ot: bad ML-KEM ciphertext length");
    }
    c.copy_from_slice(ct);
    match dk.decapsulate(&c) {
        Ok(ss) => Ok(ss.to_vec()),
        Err(_) => inv("kem-ot: ML-KEM decapsulation failed"),
    }
}

/// SHA-256 in counter mode over tag, prefix, index, slot, counter and the shared secret.
fn kem_expand(tag: &[u8], prefix: &[&[u8]], index: usize, slot: usize, secret: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut ctr = 0u64;
    while out.len() < n {
        let (i, c) = (u32be(index as u64), u32be(ctr));
        let sl = [(slot & 1) as u8];
        let mut parts: Vec<&[u8]> = vec![tag];
        parts.extend_from_slice(prefix);
        parts.extend_from_slice(&[&i[..], &sl[..], &c[..], secret]);
        out.extend_from_slice(&sha256(&parts));
        ctr += 1;
    }
    out.truncate(n);
    out
}

/// A pad of `n` bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode.
pub fn kem_ot_pad(index: usize, slot: usize, shared_secret: &[u8], n: usize) -> OtResult<Vec<u8>> {
    if n > 1 << 20 {
        return inv("kemOtPad: length must be an integer in [0, 1 MiB]");
    }
    Ok(kem_expand(TAG_KEM_PAD, &[], index, slot, shared_secret, n))
}

/// The semi-honest transcript; every field is `[i][slot]`.
#[derive(Debug, Clone)]
pub struct KemBaseOtTranscript {
    pub public_keys: Vec<OtPair>,
    pub ciphertexts: Vec<OtPair>,
    pub encrypted: Vec<OtPair>,
}

#[derive(Debug, Clone)]
pub struct KemBaseOtResult {
    pub received: Vec<Vec<u8>>,
    pub transcript: KemBaseOtTranscript,
}

struct KemReceiverState {
    choices: Vec<usize>,
    keys: Vec<KemDk>,
}

fn kem_receive(choices: &[i64], rng: &mut OtRng) -> (Vec<OtPair>, KemReceiverState) {
    let mut pks = Vec::with_capacity(choices.len());
    let mut st = KemReceiverState { choices: vec![], keys: vec![] };
    for ch in choices {
        let c = (ch & 1) as usize;
        let (chosen_pk, chosen_sk) = kem_keygen(rng);
        let (other_pk, _) = kem_keygen(rng);
        pks.push(if c == 0 { [chosen_pk, other_pk] } else { [other_pk, chosen_pk] });
        st.choices.push(c);
        st.keys.push(chosen_sk);
    }
    (pks, st)
}

/// The semi-honest KEM base OT (both roles in process).
pub fn kem_base_ot(messages: &[OtPair], choices: &[i64], rng: &mut OtRng) -> OtResult<KemBaseOtResult> {
    if messages.len() != choices.len() {
        return inv("kemBaseOT: messages/choices length mismatch");
    }
    let (pks, st) = kem_receive(choices, rng);
    let mut cts: Vec<OtPair> = Vec::with_capacity(messages.len());
    let mut enc: Vec<OtPair> = Vec::with_capacity(messages.len());
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("kemBaseOtSend (index {i}): the two messages must be equal length"));
        }
        let mut ct_pair: OtPair = [vec![], vec![]];
        let mut enc_pair: OtPair = [vec![], vec![]];
        for s in 0..2 {
            let (ct, ss) = kem_encaps(&pks[i][s], rng)?;
            let pad = kem_ot_pad(i, s, &ss, m[s].len())?;
            ct_pair[s] = ct;
            enc_pair[s] = xor_bytes(&m[s], &pad)?;
        }
        cts.push(ct_pair);
        enc.push(enc_pair);
    }
    let mut received = Vec::with_capacity(choices.len());
    for i in 0..choices.len() {
        let c = st.choices[i];
        let ss = kem_decaps(&st.keys[i], &cts[i][c])?;
        let pad = kem_ot_pad(i, c, &ss, enc[i][c].len())?;
        received.push(xor_bytes(&enc[i][c], &pad)?);
    }
    Ok(KemBaseOtResult { received, transcript: KemBaseOtTranscript { public_keys: pks, ciphertexts: cts, encrypted: enc } })
}

/// The semi-honest KEM OT as a pluggable base OT for [`OtChannel`].
pub fn with_kem_base_ot(m: &[OtPair], c: &[i64], r: &mut OtRng) -> OtResult<Vec<Vec<u8>>> {
    Ok(kem_base_ot(m, c, r)?.received)
}

fn kem_mal_commit(rn: &[u8], index: usize, pk0: &[u8], pk1: &[u8]) -> Vec<u8> {
    sha256(&[TAG_KEM_COMMIT, rn, &u32be(index as u64), pk0, pk1])
}

fn kem_mal_sid(rn: &[u8], sn: &[u8]) -> Vec<u8> {
    sha256(&[TAG_KEM_SID, rn, sn])
}

fn kem_mal_pad(sid: &[u8], com: &[u8], index: usize, slot: usize, ss: &[u8], n: usize) -> Vec<u8> {
    kem_expand(TAG_KEM_MAL_PAD, &[sid, com], index, slot, ss, n)
}

fn kem_mal_secret(sid: &[u8], com: &[u8], index: usize, slot: usize, ss: &[u8]) -> Vec<u8> {
    sha256(&[TAG_KEM_MAL_SECRET, sid, com, &u32be(index as u64), &[(slot & 1) as u8], ss])[..KEM_OT_SECRET_BYTES].to_vec()
}

/// TEST-ONLY injection points for a malicious sender or receiver in the KEM OT (`None` = honest).
#[derive(Default)]
pub struct KemMalTamper {
    pub tamper_opened_keys: Option<Box<dyn Fn(&mut Vec<OtPair>)>>,
    pub tamper_receiver_sid: Option<Box<dyn Fn(&[u8]) -> Vec<u8>>>,
}

/// The transcript of the malicious KEM OT; `encrypted` is empty in the random-OT form.
#[derive(Debug, Clone)]
pub struct KemMalTranscript {
    pub rn: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
    pub sn: Vec<u8>,
    pub public_keys: Vec<OtPair>,
    pub ciphertexts: Vec<OtPair>,
    pub encrypted: Vec<OtPair>,
}

#[derive(Debug, Clone)]
pub struct KemBaseOtMalResult {
    pub received: Vec<Vec<u8>>,
    pub transcript: KemMalTranscript,
}

/// The receiver's committed state and the sender's view of one commit-then-open run.
struct KemMalSession {
    rn: Vec<u8>,
    commitments: Vec<Vec<u8>>,
    pks: Vec<OtPair>,
    st: KemReceiverState,
    sn: Vec<u8>,
    sid: Vec<u8>,
    opened: Vec<OtPair>,
}

fn kem_mal_start(choices: &[i64], rng: &mut OtRng, tamper: Option<&KemMalTamper>) -> KemMalSession {
    let rn = rng.bytes(KEM_NONCE_BYTES);
    let (pks, st) = kem_receive(choices, rng);
    let commitments: Vec<Vec<u8>> = (0..choices.len()).map(|i| kem_mal_commit(&rn, i, &pks[i][0], &pks[i][1])).collect();
    let sn = rng.bytes(KEM_NONCE_BYTES);
    let mut opened = pks.clone();
    if let Some(f) = tamper.and_then(|t| t.tamper_opened_keys.as_ref()) {
        f(&mut opened);
    }
    let sid = kem_mal_sid(&rn, &sn);
    KemMalSession { rn, commitments, pks, st, sn, sid, opened }
}

type KemEncaps = (Vec<OtPair>, Vec<Vec<u8>>, Vec<OtPair>);

impl KemMalSession {
    /// Check the opened keys against the commitments and encapsulate to both slots of each index.
    fn encaps(&self, rng: &mut OtRng) -> OtResult<KemEncaps> {
        let mut cts = Vec::with_capacity(self.opened.len());
        let mut coms = Vec::with_capacity(self.opened.len());
        let mut sss = Vec::with_capacity(self.opened.len());
        for (i, pk) in self.opened.iter().enumerate() {
            let com = kem_mal_commit(&self.rn, i, &pk[0], &pk[1]);
            if !ct_eq(&com, &self.commitments[i]) {
                return Err(OtError::KemBaseOtAbort(format!("kem base OT (index {i}): opened public keys do not match the receiver's commitment; aborting")));
            }
            let (c0, s0) = kem_encaps(&pk[0], rng)?;
            let (c1, s1) = kem_encaps(&pk[1], rng)?;
            cts.push([c0, c1]);
            sss.push([s0, s1]);
            coms.push(com);
        }
        Ok((cts, coms, sss))
    }

    fn receiver_sid(&self, tamper: Option<&KemMalTamper>) -> Vec<u8> {
        match tamper.and_then(|t| t.tamper_receiver_sid.as_ref()) {
            Some(f) => f(&self.sid),
            None => self.sid.clone(),
        }
    }

    fn transcript(&self, ciphertexts: Vec<OtPair>, encrypted: Vec<OtPair>) -> KemMalTranscript {
        KemMalTranscript {
            rn: self.rn.clone(),
            commitments: self.commitments.clone(),
            sn: self.sn.clone(),
            public_keys: self.opened.clone(),
            ciphertexts,
            encrypted,
        }
    }
}

/// The commit-then-open malicious-secure KEM base OT (both roles in process).
pub fn kem_base_ot_mal(messages: &[OtPair], choices: &[i64], rng: &mut OtRng, tamper: Option<&KemMalTamper>) -> OtResult<KemBaseOtMalResult> {
    if messages.len() != choices.len() {
        return inv("kemBaseOtMal: messages/choices length mismatch");
    }
    let s = kem_mal_start(choices, rng, tamper);
    let n = messages.len();
    if n != s.opened.len() || s.commitments.len() != n {
        return inv("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch");
    }
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("kemBaseOtMalSend (index {i}): the two messages must be equal length"));
        }
    }
    let (cts, coms, sss) = s.encaps(rng)?;
    let mut enc: Vec<OtPair> = Vec::with_capacity(n);
    for (i, m) in messages.iter().enumerate() {
        let mut pair: OtPair = [vec![], vec![]];
        for sl in 0..2 {
            pair[sl] = xor_bytes(&m[sl], &kem_mal_pad(&s.sid, &coms[i], i, sl, &sss[i][sl], m[sl].len()))?;
        }
        enc.push(pair);
    }
    let sid = s.receiver_sid(tamper);
    let mut received = Vec::with_capacity(n);
    for i in 0..n {
        let c = s.st.choices[i];
        let ss = kem_decaps(&s.st.keys[i], &cts[i][c])?;
        let com = kem_mal_commit(&s.rn, i, &s.pks[i][0], &s.pks[i][1]);
        received.push(xor_bytes(&enc[i][c], &kem_mal_pad(&sid, &com, i, c, &ss, enc[i][c].len()))?);
    }
    Ok(KemBaseOtMalResult { received, transcript: s.transcript(cts, enc) })
}

/// The malicious-secure KEM OT as a pluggable base OT for [`OtChannel`].
pub fn with_kem_base_ot_mal(m: &[OtPair], c: &[i64], r: &mut OtRng) -> OtResult<Vec<Vec<u8>>> {
    Ok(kem_base_ot_mal(m, c, r, None)?.received)
}

/// The random-OT form of the malicious KEM OT: fixed-width secrets for the hybrid base OT.
#[derive(Debug, Clone)]
pub struct KemBaseOtMalRandomResult {
    pub sender_secrets: Vec<OtPair>,
    pub recv_secrets: Vec<Vec<u8>>,
    pub sid: Vec<u8>,
    pub transcript: KemMalTranscript,
}

/// The commit-then-open KEM OT as a random OT (both roles in process).
pub fn kem_base_ot_mal_random(choices: &[i64], rng: &mut OtRng, tamper: Option<&KemMalTamper>) -> OtResult<KemBaseOtMalRandomResult> {
    let s = kem_mal_start(choices, rng, tamper);
    let (cts, coms, sss) = s.encaps(rng)?;
    let n = choices.len();
    let sender_secrets: Vec<OtPair> =
        (0..n).map(|i| [kem_mal_secret(&s.sid, &coms[i], i, 0, &sss[i][0]), kem_mal_secret(&s.sid, &coms[i], i, 1, &sss[i][1])]).collect();
    let sid = s.receiver_sid(tamper);
    let mut recv_secrets = Vec::with_capacity(n);
    for i in 0..n {
        let c = s.st.choices[i];
        let ss = kem_decaps(&s.st.keys[i], &cts[i][c])?;
        let com = kem_mal_commit(&s.rn, i, &s.pks[i][0], &s.pks[i][1]);
        recv_secrets.push(kem_mal_secret(&sid, &com, i, c, &ss));
    }
    let transcript = s.transcript(cts, vec![]);
    Ok(KemBaseOtMalRandomResult { sender_secrets, recv_secrets, sid: s.sid.clone(), transcript })
}

// ---- hybrid base OT: both the EC and the ML-KEM secret fold into every transfer key --------------------------------------------

const TAG_HYBRID_SID: &[u8] = b"atlas-pca-mpc/hybrid-ot-sid";
const TAG_HYBRID_KEY: &[u8] = b"atlas-pca-mpc/hybrid-ot-transfer-key";
const TAG_HYBRID_COMMIT: &[u8] = b"atlas-pca-mpc/hybrid-ot-msg-commit";

/// `n` bytes (at most 1 MiB) of the transfer key of one `(index, slot)` from both secrets.
pub fn hybrid_transfer_key(sid: &[u8], index: usize, slot: usize, ss_ec: &[u8], ss_kem: &[u8], n: usize) -> OtResult<Vec<u8>> {
    if n > 1 << 20 {
        return inv("hybridTransferKey: length must be an integer in [0, 1 MiB]");
    }
    let mut out = Vec::with_capacity(n + 32);
    let mut ctr = 0u64;
    while out.len() < n {
        out.extend_from_slice(&sha256(&[TAG_HYBRID_KEY, sid, &u32be(index as u64), &[(slot & 1) as u8], &u32be(ctr), ss_ec, ss_kem]));
        ctr += 1;
    }
    out.truncate(n);
    Ok(out)
}

fn hybrid_commit(sid: &[u8], index: usize, slot: usize, msg: &[u8], key: &[u8]) -> Vec<u8> {
    sha256(&[TAG_HYBRID_COMMIT, sid, &u32be(index as u64), &[(slot & 1) as u8], msg, key])
}

/// TEST-ONLY injection points of the hybrid OT (`None` = honest).
#[derive(Default)]
pub struct HybridBaseOtTamper {
    pub ec: Option<BaseOtTamper>,
    pub kem: Option<KemMalTamper>,
    pub tamper_encrypted: Option<Box<dyn Fn(&mut Vec<OtPair>)>>,
}

#[derive(Debug, Clone)]
pub struct HybridBaseOtTranscript {
    pub sid: Vec<u8>,
    pub ec_s: EdwardsPoint,
    pub kem_sid: Vec<u8>,
    pub encrypted: Vec<OtPair>,
    pub commitments: Vec<OtPair>,
}

#[derive(Debug, Clone)]
pub struct HybridBaseOtResult {
    pub received: Vec<Vec<u8>>,
    pub transcript: HybridBaseOtTranscript,
}

/// Run the EC and ML-KEM random OTs side by side and transfer the messages under keys derived from both.
pub fn hybrid_base_ot(messages: &[OtPair], choices: &[i64], rng: &mut OtRng, tamper: Option<&HybridBaseOtTamper>) -> OtResult<HybridBaseOtResult> {
    if messages.len() != choices.len() {
        return inv("hybridBaseOT: messages/choices length mismatch");
    }
    let ec = mal_base_random_ot(choices, rng, tamper.and_then(|t| t.ec.as_ref()), None)?;
    let kem = kem_base_ot_mal_random(choices, rng, tamper.and_then(|t| t.kem.as_ref()))?;
    let sid = sha256(&[TAG_HYBRID_SID, &kem.sid, &ec_encode_point(&ec.s)]);
    let mut enc: Vec<OtPair> = Vec::with_capacity(messages.len());
    let mut com: Vec<OtPair> = Vec::with_capacity(messages.len());
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("hybridSenderEncrypt (index {i}): the two messages must be equal length"));
        }
        let mut e: OtPair = [vec![], vec![]];
        let mut c: OtPair = [vec![], vec![]];
        for sl in 0..2 {
            let k = hybrid_transfer_key(&sid, i, sl, &ec.sender_pads[i][sl], &kem.sender_secrets[i][sl], m[sl].len())?;
            e[sl] = xor_bytes(&m[sl], &k)?;
            c[sl] = hybrid_commit(&sid, i, sl, &m[sl], &k);
        }
        enc.push(e);
        com.push(c);
    }
    if let Some(f) = tamper.and_then(|t| t.tamper_encrypted.as_ref()) {
        f(&mut enc);
    }
    let mut received = Vec::with_capacity(choices.len());
    for (i, ch) in choices.iter().enumerate() {
        let c = (ch & 1) as usize;
        let key = hybrid_transfer_key(&sid, i, c, &ec.recv_pads[i], &kem.recv_secrets[i], enc[i][c].len())?;
        let m = xor_bytes(&enc[i][c], &key)?;
        if !ct_eq(&hybrid_commit(&sid, i, c, &m, &key), &com[i][c]) {
            return Err(OtError::HybridOtAbort(format!("hybrid base OT (index {i}): sender ciphertext inconsistent with its commitment; aborting")));
        }
        received.push(m);
    }
    Ok(HybridBaseOtResult { received, transcript: HybridBaseOtTranscript { sid, ec_s: ec.s, kem_sid: kem.sid, encrypted: enc, commitments: com } })
}

/// The hybrid base OT as a pluggable base OT for [`OtChannel`].
pub fn with_hybrid_base_ot(m: &[OtPair], c: &[i64], r: &mut OtRng) -> OtResult<Vec<Vec<u8>>> {
    Ok(hybrid_base_ot(m, c, r, None)?.received)
}

/// `isOnCurve`: whether decimal extended coordinates `(X, Y, Z, T)` describe a point of the curve (`Z != 0`, `T*Z = X*Y` and the curve
/// equation). Total: malformed input is not on the curve.
pub fn ec_is_on_curve(c: &[String]) -> bool {
    ec_from_extended_dec(c).is_ok()
}

/// `modFq`: the canonical representative in `[0, q)` (`q = 2^255 - 19`) of a signed decimal integer, as a decimal string.
pub fn mod_fq_dec(x: &str) -> OtResult<String> {
    let (neg, digits) = match x.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, x),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return inv("modFq: not a decimal integer");
    }
    let q = curve_q_big();
    let r = BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(|| OtError::Invalid("modFq: not a decimal integer".into()))? % &q;
    let r = if neg && r != BigUint::from(0u8) { &q - r } else { r };
    Ok(r.to_string())
}
