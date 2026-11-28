//! BBS signatures over BLS12-381 (draft-irtf-cfrg-bbs-signatures, ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`), the
//! selective-disclosure proofs, and the PCA capability-credential layer (the `@atlasauth/pca-bbs` surface), on the audited
//! `blst` library: signatures and generators in G1 (48 bytes), public keys in G2 (96 bytes), scalars 32 bytes big-endian.
//!
//! Every group operation, hash-to-curve and scalar-field operation is a `blst` call (`blst_fr_*`, `blst_p1_mult`,
//! `blst_hash_to_g1`, `blst_miller_loop`, ...): nothing here implements field or pairing arithmetic. Secret scalars (the
//! signing key, `1/(SK+e)`, the prover's blinding scalars) only meet `blst`'s constant-time `blst_fr_*` and point
//! multiplication; the intermediate byte buffers that carry them are zeroized. Every deserialized point is subgroup-checked
//! and must be the exact canonical encoding (fail closed).
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A thin safe layer over blst's raw scalar-field, G1/G2 and GT API, shared by the BBS and ABE modules.
pub mod ec {
    use blst::*;
    use zeroize::Zeroize;

    /// The subgroup order r, big-endian.
    pub const R_BE: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff,
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    ];

    /// An element of the scalar field Fr (order r), in blst's Montgomery form; every operation is a constant-time blst call.
    #[derive(Clone, Copy)]
    pub struct Fr(blst_fr);

    impl Zeroize for Fr {
        fn zeroize(&mut self) {
            self.0.l.zeroize();
        }
    }

    impl Fr {
        pub fn zero() -> Fr {
            Fr::from_u64(0)
        }

        pub fn from_u64(v: u64) -> Fr {
            let mut r = blst_fr::default();
            let a = [v, 0, 0, 0];
            unsafe { blst_fr_from_uint64(&mut r, a.as_ptr()) };
            Fr(r)
        }

        fn from_scalar(s: &blst_scalar) -> Fr {
            let mut r = blst_fr::default();
            unsafe { blst_fr_from_scalar(&mut r, s) };
            Fr(r)
        }

        /// OS2IP of an arbitrary-length big-endian string, reduced mod r.
        pub fn from_be_reduce(bytes: &[u8]) -> Fr {
            if bytes.is_empty() {
                return Fr::zero();
            }
            let mut s = blst_scalar::default();
            unsafe { blst_scalar_from_be_bytes(&mut s, bytes.as_ptr(), bytes.len()) };
            let r = Fr::from_scalar(&s);
            s.b.zeroize();
            r
        }

        /// A 32-byte big-endian scalar, `None` unless it is strictly below r.
        pub fn from_canonical(bytes: &[u8]) -> Option<Fr> {
            if bytes.len() != 32 {
                return None;
            }
            let mut s = blst_scalar::default();
            unsafe { blst_scalar_from_bendian(&mut s, bytes.as_ptr()) };
            let ok = unsafe { blst_scalar_fr_check(&s) };
            let r = ok.then(|| Fr::from_scalar(&s));
            s.b.zeroize();
            r
        }

        /// Lowercase or uppercase hex of at most 64 digits, reduced mod r.
        pub fn from_hex(h: &str) -> Option<Fr> {
            if h.is_empty() || h.len() > 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let padded = format!("{h:0>64}");
            let mut b = [0u8; 32];
            for (i, o) in b.iter_mut().enumerate() {
                *o = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(Fr::from_be_reduce(&b))
        }

        pub fn to_be_bytes(&self) -> [u8; 32] {
            let mut s = blst_scalar::default();
            unsafe { blst_scalar_from_fr(&mut s, &self.0) };
            let mut out = [0u8; 32];
            unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), &s) };
            s.b.zeroize();
            out
        }

        pub fn to_hex(&self) -> String {
            self.to_be_bytes().iter().map(|b| format!("{b:02x}")).collect()
        }

        fn to_scalar(self) -> blst_scalar {
            let mut s = blst_scalar::default();
            unsafe { blst_scalar_from_fr(&mut s, &self.0) };
            s
        }

        pub fn is_zero(&self) -> bool {
            self.to_be_bytes().iter().fold(0u8, |a, b| a | b) == 0
        }

        pub fn add(&self, o: &Fr) -> Fr {
            let mut r = blst_fr::default();
            unsafe { blst_fr_add(&mut r, &self.0, &o.0) };
            Fr(r)
        }

        pub fn sub(&self, o: &Fr) -> Fr {
            let mut r = blst_fr::default();
            unsafe { blst_fr_sub(&mut r, &self.0, &o.0) };
            Fr(r)
        }

        pub fn mul(&self, o: &Fr) -> Fr {
            let mut r = blst_fr::default();
            unsafe { blst_fr_mul(&mut r, &self.0, &o.0) };
            Fr(r)
        }

        pub fn neg(&self) -> Fr {
            let mut r = blst_fr::default();
            unsafe { blst_fr_cneg(&mut r, &self.0, true) };
            Fr(r)
        }

        /// The multiplicative inverse; `None` for zero.
        pub fn inv(&self) -> Option<Fr> {
            if self.is_zero() {
                return None;
            }
            let mut r = blst_fr::default();
            unsafe { blst_fr_inverse(&mut r, &self.0) };
            Some(Fr(r))
        }

        pub fn ct_eq(&self, o: &Fr) -> bool {
            self.to_be_bytes().iter().zip(o.to_be_bytes().iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
        }
    }

    /// A point of G1 (projective; the identity is the all-zero value).
    #[derive(Clone, Copy)]
    pub struct G1(pub(crate) blst_p1);

    impl G1 {
        pub fn identity() -> G1 {
            G1(blst_p1::default())
        }

        pub fn generator() -> G1 {
            G1(unsafe { *blst_p1_generator() })
        }

        pub fn is_identity(&self) -> bool {
            unsafe { blst_p1_is_inf(&self.0) }
        }

        pub fn add(&self, o: &G1) -> G1 {
            let mut r = blst_p1::default();
            unsafe { blst_p1_add_or_double(&mut r, &self.0, &o.0) };
            G1(r)
        }

        pub fn neg(&self) -> G1 {
            let mut r = self.0;
            unsafe { blst_p1_cneg(&mut r, true) };
            G1(r)
        }

        /// Scalar multiplication (constant time in the scalar).
        pub fn mul(&self, k: &Fr) -> G1 {
            if k.is_zero() {
                return G1::identity();
            }
            let mut s = k.to_scalar();
            let mut r = blst_p1::default();
            unsafe { blst_p1_mult(&mut r, &self.0, s.b.as_ptr(), 255) };
            s.b.zeroize();
            G1(r)
        }

        pub fn to_bytes(&self) -> [u8; 48] {
            let mut out = [0u8; 48];
            unsafe { blst_p1_compress(out.as_mut_ptr(), &self.0) };
            out
        }

        /// The exact canonical compressed encoding of a prime-order G1 point (the identity included).
        pub fn from_bytes_strict(b: &[u8]) -> Option<G1> {
            if b.len() != 48 || b[0] & 0x80 == 0 {
                return None;
            }
            let mut a = blst_p1_affine::default();
            if unsafe { blst_p1_uncompress(&mut a, b.as_ptr()) } != BLST_ERROR::BLST_SUCCESS || !unsafe { blst_p1_affine_in_g1(&a) } {
                return None;
            }
            let mut back = [0u8; 48];
            unsafe { blst_p1_affine_compress(back.as_mut_ptr(), &a) };
            if back.as_slice() != b {
                return None;
            }
            let mut p = blst_p1::default();
            unsafe { blst_p1_from_affine(&mut p, &a) };
            Some(G1(p))
        }

        /// hash_to_curve (random-oracle, SSWU) to G1.
        pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G1 {
            let mut p = blst_p1::default();
            unsafe { blst_hash_to_g1(&mut p, msg.as_ptr(), msg.len(), dst.as_ptr(), dst.len(), core::ptr::null(), 0) };
            G1(p)
        }

        fn affine(&self) -> blst_p1_affine {
            let mut a = blst_p1_affine::default();
            unsafe { blst_p1_to_affine(&mut a, &self.0) };
            a
        }
    }

    /// A point of G2.
    #[derive(Clone, Copy)]
    pub struct G2(pub(crate) blst_p2);

    impl G2 {
        pub fn identity() -> G2 {
            G2(blst_p2::default())
        }

        pub fn generator() -> G2 {
            G2(unsafe { *blst_p2_generator() })
        }

        pub fn is_identity(&self) -> bool {
            unsafe { blst_p2_is_inf(&self.0) }
        }

        pub fn add(&self, o: &G2) -> G2 {
            let mut r = blst_p2::default();
            unsafe { blst_p2_add_or_double(&mut r, &self.0, &o.0) };
            G2(r)
        }

        pub fn neg(&self) -> G2 {
            let mut r = self.0;
            unsafe { blst_p2_cneg(&mut r, true) };
            G2(r)
        }

        pub fn mul(&self, k: &Fr) -> G2 {
            if k.is_zero() {
                return G2::identity();
            }
            let mut s = k.to_scalar();
            let mut r = blst_p2::default();
            unsafe { blst_p2_mult(&mut r, &self.0, s.b.as_ptr(), 255) };
            s.b.zeroize();
            G2(r)
        }

        pub fn to_bytes(&self) -> [u8; 96] {
            let mut out = [0u8; 96];
            unsafe { blst_p2_compress(out.as_mut_ptr(), &self.0) };
            out
        }

        pub fn from_bytes_strict(b: &[u8]) -> Option<G2> {
            if b.len() != 96 || b[0] & 0x80 == 0 {
                return None;
            }
            let mut a = blst_p2_affine::default();
            if unsafe { blst_p2_uncompress(&mut a, b.as_ptr()) } != BLST_ERROR::BLST_SUCCESS || !unsafe { blst_p2_affine_in_g2(&a) } {
                return None;
            }
            let mut back = [0u8; 96];
            unsafe { blst_p2_affine_compress(back.as_mut_ptr(), &a) };
            if back.as_slice() != b {
                return None;
            }
            let mut p = blst_p2::default();
            unsafe { blst_p2_from_affine(&mut p, &a) };
            Some(G2(p))
        }

        fn affine(&self) -> blst_p2_affine {
            let mut a = blst_p2_affine::default();
            unsafe { blst_p2_to_affine(&mut a, &self.0) };
            a
        }
    }

    /// An element of the pairing target group GT inside Fp12 (a raw blst value).
    #[derive(Clone, Copy)]
    pub struct Gt(pub(crate) blst_fp12);

    /// The 12 Fp coordinates in tower order c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1 (the blst_fp12 struct walked in
    /// memory order; this is NOT blst_bendian_from_fp12's order), each 48 bytes big-endian: 576 bytes.
    pub const GT_BYTES: usize = 576;

    fn coord(x: &mut blst_fp12, i: usize) -> &mut blst_fp {
        &mut x.fp6[i / 6].fp2[(i % 6) / 2].fp[i % 2]
    }

    impl Gt {
        pub fn one() -> Gt {
            Gt(unsafe { *blst_fp12_one() })
        }

        pub fn is_one(&self) -> bool {
            unsafe { blst_fp12_is_one(&self.0) }
        }

        pub fn mul(&self, o: &Gt) -> Gt {
            let mut r = blst_fp12::default();
            unsafe { blst_fp12_mul(&mut r, &self.0, &o.0) };
            Gt(r)
        }

        pub fn sqr(&self) -> Gt {
            let mut r = blst_fp12::default();
            unsafe { blst_fp12_sqr(&mut r, &self.0) };
            Gt(r)
        }

        pub fn to_bytes(&self) -> [u8; GT_BYTES] {
            let mut x = self.0;
            let mut out = [0u8; GT_BYTES];
            for i in 0..12 {
                unsafe { blst_bendian_from_fp(out.as_mut_ptr().add(48 * i), coord(&mut x, i)) };
            }
            out
        }

        /// Strict decoding: every coordinate must be canonical (< p), checked by re-encoding through blst.
        pub fn from_bytes(b: &[u8]) -> Option<Gt> {
            if b.len() != GT_BYTES {
                return None;
            }
            let mut x = blst_fp12::default();
            let mut ok = true;
            for i in 0..12 {
                let mut back = [0u8; 48];
                unsafe {
                    blst_fp_from_bendian(coord(&mut x, i), b.as_ptr().add(48 * i));
                    blst_bendian_from_fp(back.as_mut_ptr(), coord(&mut x, i));
                }
                ok &= back.as_slice() == &b[48 * i..48 * i + 48];
            }
            ok.then_some(Gt(x))
        }

        /// x^k for a 32-byte big-endian exponent: a Montgomery ladder over all 256 bits with a branch-free byte-masked swap, so
        /// the exponent steers neither control flow nor memory access (constant time as far as blst's Fp12 mul/sqr are).
        pub fn pow(&self, k: &[u8; 32]) -> Gt {
            fn cswap(a: &mut Gt, b: &mut Gt, bit: u8) {
                let mask = 0u8.wrapping_sub(bit);
                let n = core::mem::size_of::<blst_fp12>();
                let (pa, pb) = (a as *mut Gt as *mut u8, b as *mut Gt as *mut u8);
                for i in 0..n {
                    unsafe {
                        let t = (*pa.add(i) ^ *pb.add(i)) & mask;
                        *pa.add(i) ^= t;
                        *pb.add(i) ^= t;
                    }
                }
            }
            let (mut r0, mut r1) = (Gt::one(), *self);
            for i in 0..256 {
                let bit = (k[i / 8] >> (7 - i % 8)) & 1;
                cswap(&mut r0, &mut r1, bit);
                r1 = r0.mul(&r1);
                r0 = r0.sqr();
                cswap(&mut r0, &mut r1, bit);
            }
            r0
        }

        /// A non-identity element of the order-r subgroup.
        pub fn is_element(&self) -> bool {
            !self.is_one() && self.pow(&R_BE).is_one()
        }
    }

    /// prod_i e(P_i, Q_i) with one shared final exponentiation. `None` when the lists differ in length, are empty, or any point
    /// is the identity (a degenerate pairing is refused, never silently 1).
    pub fn pairing_product(g1s: &[G1], g2s: &[G2]) -> Option<Gt> {
        if g1s.is_empty() || g1s.len() != g2s.len() {
            return None;
        }
        let mut acc = Gt::one();
        for (p, q) in g1s.iter().zip(g2s) {
            if p.is_identity() || q.is_identity() {
                return None;
            }
            let (pa, qa) = (p.affine(), q.affine());
            let mut ml = blst_fp12::default();
            unsafe { blst_miller_loop(&mut ml, &qa, &pa) };
            acc = acc.mul(&Gt(ml));
        }
        let mut out = blst_fp12::default();
        unsafe { blst_final_exp(&mut out, &acc.0) };
        Some(Gt(out))
    }

    /// e(a1, a2) == e(b1, b2) over non-identity points; `false` when any point is the identity.
    pub fn pairing_eq(a1: &G1, a2: &G2, b1: &G1, b2: &G2) -> bool {
        match pairing_product(&[*a1, b1.neg()], &[*a2, *b2]) {
            Some(g) => g.is_one(),
            None => false,
        }
    }
}

pub use ec::Fr;
use ec::{G1, G2};

/// Implementation limit on the messages in one credential (a verifier derives the count from attacker-supplied proof length).
pub const MAX_MESSAGES: usize = 1024;

const API_ID: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
const H2S_DST: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_H2S_";
const MAP_DST: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MAP_MSG_TO_SCALAR_AS_HASH_";
const SEED_DST: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
const GEN_DST: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_DST_";
const GEN_SEED: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MESSAGE_GENERATOR_SEED";
const KEYGEN_DST: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_KEYGEN_DST_";
const SCALAR_LEN: usize = 32;
const POINT_LEN: usize = 48;
const EXPAND_LEN: usize = 48;
/// The published fixed G1 generator P1 of the ciphersuite (draft section 7.2.2).
const P1_HEX: &str = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64u(s: &str) -> Option<Vec<u8>> {
    crate::decode_b64u_strict(s, None)
}

fn p1() -> G1 {
    let b: Vec<u8> = (0..P1_HEX.len() / 2).map(|i| u8::from_str_radix(&P1_HEX[2 * i..2 * i + 2], 16).expect("hex")).collect();
    G1::from_bytes_strict(&b).expect("P1 is a valid G1 point")
}

// ---- expand_message_xmd (RFC 9380 5.3.1, SHA-256) --------------------------------------------------------------------

fn expand_xmd(msg: &[u8], dst: &str, n: usize) -> Vec<u8> {
    let mut dst_prime = dst.as_bytes().to_vec();
    dst_prime.push(dst.len() as u8);
    let ell = n.div_ceil(32);
    let mut h = Sha256::new();
    h.update([0u8; 64]);
    h.update(msg);
    h.update([(n >> 8) as u8, n as u8, 0]);
    h.update(&dst_prime);
    let b0 = h.finalize_reset();
    h.update(b0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut prev = h.finalize_reset();
    let mut out = prev.to_vec();
    for i in 2..=ell {
        let x: Vec<u8> = b0.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        h.update(&x);
        h.update([i as u8]);
        h.update(&dst_prime);
        prev = h.finalize_reset();
        out.extend_from_slice(&prev);
    }
    out.truncate(n);
    out
}

/// hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r.
pub fn hash_to_scalar(msg: &[u8], dst: &str) -> Fr {
    Fr::from_be_reduce(&expand_xmd(msg, dst, EXPAND_LEN))
}

/// Maps one message octet string to one scalar.
pub fn map_message_to_scalar_as_hash(message: &[u8]) -> Fr {
    hash_to_scalar(message, MAP_DST)
}

fn messages_to_scalars(msgs: &[Vec<u8>]) -> Vec<Fr> {
    msgs.iter().map(|m| map_message_to_scalar_as_hash(m)).collect()
}

fn i2osp8(n: usize) -> [u8; 8] {
    (n as u64).to_be_bytes()
}

fn is_inf_encoding(b: &[u8]) -> bool {
    b[0] & 0x40 != 0
}

// ---- generators ------------------------------------------------------------------------------------------------------

fn generators(count: i64) -> Result<Vec<G1>, String> {
    if count < 0 {
        return Err("bbs: generator count must be a non-negative integer".into());
    }
    let count = count as usize;
    if count > MAX_MESSAGES + 1 {
        return Err(format!("bbs: at most {MAX_MESSAGES} messages are supported"));
    }
    let mut gens = Vec::with_capacity(count);
    let mut v = expand_xmd(GEN_SEED.as_bytes(), SEED_DST, EXPAND_LEN);
    for i in 1..=count {
        let mut input = v.clone();
        input.extend_from_slice(&i2osp8(i));
        v = expand_xmd(&input, SEED_DST, EXPAND_LEN);
        gens.push(G1::hash_to_curve(&v, GEN_DST.as_bytes()));
    }
    Ok(gens)
}

/// create_generators(count): the deterministic compressed generators (Q_1, H_1, ...).
pub fn create_generators(count: i64) -> Result<Vec<Vec<u8>>, String> {
    Ok(generators(count)?.iter().map(|g| g.to_bytes().to_vec()).collect())
}

// ---- keys ------------------------------------------------------------------------------------------------------------

/// Derives a secret scalar from at least 32 octets of key material and optional info (draft 3.4.1).
pub fn key_gen(key_material: &[u8], key_info: &[u8]) -> Result<Fr, String> {
    if key_material.len() < 32 {
        return Err("bbs: key material must be at least 32 octets".into());
    }
    if key_info.len() > 65535 {
        return Err("bbs: key info must be at most 65535 octets".into());
    }
    let mut input = key_material.to_vec();
    input.extend_from_slice(&(key_info.len() as u16).to_be_bytes());
    input.extend_from_slice(key_info);
    let sk = hash_to_scalar(&input, KEYGEN_DST);
    input.zeroize();
    if sk.is_zero() {
        return Err("bbs: derived SK is zero (retry with different key material)".into());
    }
    Ok(sk)
}

/// The compressed G2 public key SK * BP2.
pub fn sk_to_pk(sk: &Fr) -> Result<Vec<u8>, String> {
    if sk.is_zero() {
        return Err("bbs: secret key is zero".into());
    }
    Ok(G2::generator().mul(sk).to_bytes().to_vec())
}

/// A fresh key pair `(sk, pk)` from the system CSPRNG.
pub fn generate_key_pair() -> Result<(Fr, Vec<u8>), String> {
    let mut ikm = [0u8; 32];
    getrandom::getrandom(&mut ikm).map_err(|e| format!("bbs: {e}"))?;
    if ikm == [0u8; 32] {
        return Err("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key".into());
    }
    let sk = key_gen(&ikm, &[])?;
    ikm.zeroize();
    let pk = sk_to_pk(&sk)?;
    Ok((sk, pk))
}

// ---- signature octets ------------------------------------------------------------------------------------------------

fn octets_to_signature(sig: &[u8]) -> Result<(G1, Fr), String> {
    if sig.len() != POINT_LEN + SCALAR_LEN {
        return Err("bbs: signature must be 80 octets".into());
    }
    let a = G1::from_bytes_strict(&sig[..POINT_LEN]).ok_or("bbs: non-canonical or invalid G1 encoding")?;
    if is_inf_encoding(sig) {
        return Err("bbs: signature point A is the identity".into());
    }
    let e = Fr::from_canonical(&sig[POINT_LEN..]).ok_or("bbs: signature scalar e out of range")?;
    if e.is_zero() {
        return Err("bbs: signature scalar e out of range".into());
    }
    Ok((a, e))
}

fn calculate_domain(pk: &[u8], q1: &G1, h: &[G1], header: &[u8]) -> Fr {
    let mut dom = i2osp8(h.len()).to_vec();
    dom.extend_from_slice(&q1.to_bytes());
    for g in h {
        dom.extend_from_slice(&g.to_bytes());
    }
    dom.extend_from_slice(API_ID.as_bytes());
    let mut input = pk.to_vec();
    input.extend_from_slice(&dom);
    input.extend_from_slice(&i2osp8(header.len()));
    input.extend_from_slice(header);
    hash_to_scalar(&input, H2S_DST)
}

fn compute_b(q1: &G1, h: &[G1], domain: &Fr, msgs: &[Fr]) -> G1 {
    let mut b = p1().add(&q1.mul(domain));
    for (i, m) in msgs.iter().enumerate() {
        b = b.add(&h[i].mul(m));
    }
    b
}

/// The 80-octet BBS signature over the ordered message vector.
pub fn sign(sk: &Fr, pk: &[u8], header: &[u8], messages: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if sk.is_zero() {
        return Err("bbs: secret key is zero".into());
    }
    let msgs = messages_to_scalars(messages);
    let gens = generators(msgs.len() as i64 + 1)?;
    let (q1, h) = (&gens[0], &gens[1..]);
    let domain = calculate_domain(pk, q1, h, header);
    let mut es = sk.to_be_bytes().to_vec();
    for m in &msgs {
        es.extend_from_slice(&m.to_be_bytes());
    }
    es.extend_from_slice(&domain.to_be_bytes());
    let e = hash_to_scalar(&es, H2S_DST);
    es.zeroize();
    let b = compute_b(q1, h, &domain, &msgs);
    let mut denom = sk.add(&e);
    let inv = denom.inv();
    denom.zeroize();
    let mut inv = inv.ok_or("bbs: inverse of zero")?;
    let a = b.mul(&inv);
    inv.zeroize();
    let mut out = a.to_bytes().to_vec();
    out.extend_from_slice(&e.to_be_bytes());
    Ok(out)
}

/// Verifies a signature over exactly these messages; `Err(reason)` (a stable reason string) on any failure.
pub fn verify_detailed(pk: &[u8], signature: &[u8], header: &[u8], messages: &[Vec<u8>]) -> Result<(), String> {
    let (a, e) = octets_to_signature(signature).map_err(|_| "malformed-signature".to_string())?;
    let w = match G2::from_bytes_strict(pk) {
        Some(w) if !is_inf_encoding(pk) => w,
        _ => return Err("malformed-public-key".into()),
    };
    if messages.len() > MAX_MESSAGES {
        return Err("disclosed-length-mismatch".into());
    }
    let msgs = messages_to_scalars(messages);
    let gens = generators(msgs.len() as i64 + 1).map_err(|_| "disclosed-length-mismatch".to_string())?;
    let (q1, h) = (&gens[0], &gens[1..]);
    let domain = calculate_domain(pk, q1, h, header);
    let b = compute_b(q1, h, &domain, &msgs);
    // e(A, W + BP2*e) == e(B, BP2)
    if !ec::pairing_eq(&a, &w.add(&G2::generator().mul(&e)), &b, &G2::generator()) {
        return Err("pairing-mismatch".into());
    }
    Ok(())
}

/// Whether the signature covers exactly these messages.
pub fn verify(pk: &[u8], signature: &[u8], header: &[u8], messages: &[Vec<u8>]) -> bool {
    verify_detailed(pk, signature, header, messages).is_ok()
}

// ---- challenge / proof octets ----------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn calculate_challenge(abar: &G1, bbar: &G1, d: &G1, t1: &G1, t2: &G1, idx: &[usize], msgs: &[Fr], domain: &Fr, ph: &[u8]) -> Fr {
    let mut s = i2osp8(idx.len()).to_vec();
    for (k, i) in idx.iter().enumerate() {
        s.extend_from_slice(&i2osp8(*i));
        s.extend_from_slice(&msgs[k].to_be_bytes());
    }
    for p in [abar, bbar, d, t1, t2] {
        s.extend_from_slice(&p.to_bytes());
    }
    s.extend_from_slice(&domain.to_be_bytes());
    s.extend_from_slice(&i2osp8(ph.len()));
    s.extend_from_slice(ph);
    hash_to_scalar(&s, H2S_DST)
}

struct Proof {
    abar: G1,
    bbar: G1,
    d: G1,
    e_hat: Fr,
    r1_hat: Fr,
    r3_hat: Fr,
    m_hat: Vec<Fr>,
    c: Fr,
}

fn octets_to_proof(proof: &[u8]) -> Result<Proof, String> {
    let fixed = 3 * POINT_LEN + 4 * SCALAR_LEN;
    if proof.len() < fixed || (proof.len() - fixed) % SCALAR_LEN != 0 {
        return Err("bbs: malformed proof length".into());
    }
    let mut pts = Vec::with_capacity(3);
    for i in 0..3 {
        let b = &proof[i * POINT_LEN..(i + 1) * POINT_LEN];
        let g = G1::from_bytes_strict(b).ok_or("bbs: non-canonical or invalid G1 encoding")?;
        if is_inf_encoding(b) {
            return Err("bbs: proof contains the identity point".into());
        }
        pts.push(g);
    }
    let scalar = |off: usize| Fr::from_canonical(&proof[off..off + SCALAR_LEN]).ok_or_else(|| "bbs: proof scalar out of range".to_string());
    let mut o = 3 * POINT_LEN;
    let e_hat = scalar(o)?;
    o += SCALAR_LEN;
    let r1_hat = scalar(o)?;
    o += SCALAR_LEN;
    let r3_hat = scalar(o)?;
    o += SCALAR_LEN;
    let u = (proof.len() - fixed) / SCALAR_LEN;
    let mut m_hat = Vec::with_capacity(u);
    for _ in 0..u {
        m_hat.push(scalar(o)?);
        o += SCALAR_LEN;
    }
    let c = scalar(o)?;
    Ok(Proof { abar: pts[0], bbar: pts[1], d: pts[2], e_hat, r1_hat, r3_hat, m_hat, c })
}

fn proof_to_octets(p: &Proof) -> Vec<u8> {
    let mut out = p.abar.to_bytes().to_vec();
    out.extend_from_slice(&p.bbar.to_bytes());
    out.extend_from_slice(&p.d.to_bytes());
    for v in [&p.e_hat, &p.r1_hat, &p.r3_hat].into_iter().chain(p.m_hat.iter()).chain([&p.c]) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

fn validate_indexes(idx: &[i64], l: usize) -> Result<Vec<usize>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(idx.len());
    for &i in idx {
        if i < 0 || i as u64 >= l as u64 {
            return Err(format!("bbs: disclosed index {i} out of range [0, {l})"));
        }
        if !seen.insert(i) {
            return Err(format!("bbs: duplicate disclosed index {i}"));
        }
        out.push(i as usize);
    }
    Ok(out)
}

fn undisclosed_ascending(disclosed: &std::collections::HashSet<usize>, l: usize) -> Vec<usize> {
    (0..l).filter(|i| !disclosed.contains(i)).collect()
}

fn random_scalar() -> Result<Fr, String> {
    let mut buf = [0u8; EXPAND_LEN];
    getrandom::getrandom(&mut buf).map_err(|e| format!("bbs: {e}"))?;
    let r = Fr::from_be_reduce(&buf);
    buf.zeroize();
    Ok(r)
}

/// A zero-knowledge proof of knowledge of the signature, disclosing the messages at `disclosed_indexes`; `ph` binds the proof
/// to a context. `fixed_random_scalars` (5 + undisclosed scalars) pins the randomness for test vectors ONLY: reusing it across
/// proofs breaks zero-knowledge and unlinkability; pass `None` in production.
pub fn proof_gen(
    pk: &[u8],
    signature: &[u8],
    header: &[u8],
    ph: &[u8],
    messages: &[Vec<u8>],
    disclosed_indexes: &[i64],
    fixed_random_scalars: Option<&[Fr]>,
) -> Result<Vec<u8>, String> {
    let (a, e) = octets_to_signature(signature)?;
    let msgs = messages_to_scalars(messages);
    let l = msgs.len();
    let mut disclosed = validate_indexes(disclosed_indexes, l)?;
    disclosed.sort_unstable();
    let dset: std::collections::HashSet<usize> = disclosed.iter().copied().collect();
    let undisclosed = undisclosed_ascending(&dset, l);
    let u = undisclosed.len();
    let gens = generators(l as i64 + 1)?;
    let (q1, h) = (&gens[0], &gens[1..]);
    let domain = calculate_domain(pk, q1, h, header);
    let b = compute_b(q1, h, &domain, &msgs);

    let mut rs: Vec<Fr> = match fixed_random_scalars {
        Some(f) => f.to_vec(),
        None => (0..5 + u).map(|_| random_scalar()).collect::<Result<_, _>>()?,
    };
    if rs.len() != 5 + u {
        return Err(format!("bbs: expected {} random scalars, got {}", 5 + u, rs.len()));
    }
    if rs[0].is_zero() || rs[1].is_zero() {
        return Err("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)".into());
    }
    let (r1, r2, e_tilde, r1_tilde, r3_tilde) = (rs[0], rs[1], rs[2], rs[3], rs[4]);
    let m_tilde = &rs[5..];

    let d = b.mul(&r2);
    let abar = a.mul(&r1.mul(&r2));
    let bbar = d.mul(&r1).add(&abar.mul(&e).neg());
    let t1 = abar.mul(&e_tilde).add(&d.mul(&r1_tilde));
    let mut t2 = d.mul(&r3_tilde);
    for (k, j) in undisclosed.iter().enumerate() {
        t2 = t2.add(&h[*j].mul(&m_tilde[k]));
    }
    let dmsgs: Vec<Fr> = disclosed.iter().map(|i| msgs[*i]).collect();
    let c = calculate_challenge(&abar, &bbar, &d, &t1, &t2, &disclosed, &dmsgs, &domain, ph);
    let mut r3 = r2.inv().ok_or("bbs: inverse of zero")?;
    let p = Proof {
        abar,
        bbar,
        d,
        c,
        e_hat: e_tilde.add(&e.mul(&c)),
        r1_hat: r1_tilde.sub(&r1.mul(&c)),
        r3_hat: r3_tilde.sub(&r3.mul(&c)),
        m_hat: undisclosed.iter().enumerate().map(|(k, j)| m_tilde[k].add(&msgs[*j].mul(&c))).collect(),
    };
    for s in rs.iter_mut() {
        s.zeroize();
    }
    r3.zeroize();
    Ok(proof_to_octets(&p))
}

/// Verifies a proof; `disclosed_messages[k]` corresponds to `disclosed_indexes[k]`. `Err(reason)` on any failure.
pub fn proof_verify_detailed(
    pk: &[u8],
    proof: &[u8],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Vec<u8>],
    disclosed_indexes: &[i64],
) -> Result<(), String> {
    let p = octets_to_proof(proof).map_err(|_| "malformed-proof".to_string())?;
    let w = match G2::from_bytes_strict(pk) {
        Some(w) if !is_inf_encoding(pk) => w,
        _ => return Err("malformed-public-key".into()),
    };
    if disclosed_messages.len() != disclosed_indexes.len() {
        return Err("disclosed-length-mismatch".into());
    }
    let u = p.m_hat.len();
    let l = disclosed_indexes.len() + u;
    if l > MAX_MESSAGES {
        return Err("malformed-proof".into());
    }
    let idx = validate_indexes(disclosed_indexes, l).map_err(|_| "invalid-disclosed-indexes".to_string())?;
    let scal = messages_to_scalars(disclosed_messages);
    let mut disclosed: Vec<(usize, Fr)> = idx.into_iter().zip(scal).collect();
    disclosed.sort_by_key(|d| d.0);
    let dset: std::collections::HashSet<usize> = disclosed.iter().map(|d| d.0).collect();
    let idxs: Vec<usize> = disclosed.iter().map(|d| d.0).collect();
    let msgs: Vec<Fr> = disclosed.iter().map(|d| d.1).collect();
    let undisclosed = undisclosed_ascending(&dset, l);

    let gens = generators(l as i64 + 1).map_err(|_| "malformed-proof".to_string())?;
    let (q1, h) = (&gens[0], &gens[1..]);
    let domain = calculate_domain(pk, q1, h, header);

    let t1 = p.bbar.mul(&p.c).add(&p.abar.mul(&p.e_hat)).add(&p.d.mul(&p.r1_hat));
    let mut bv = p1().add(&q1.mul(&domain));
    for (i, m) in &disclosed {
        bv = bv.add(&h[*i].mul(m));
    }
    let mut t2 = bv.mul(&p.c).add(&p.d.mul(&p.r3_hat));
    for (k, j) in undisclosed.iter().enumerate() {
        t2 = t2.add(&h[*j].mul(&p.m_hat[k]));
    }
    let cv = calculate_challenge(&p.abar, &p.bbar, &p.d, &t1, &t2, &idxs, &msgs, &domain, ph);
    if !cv.ct_eq(&p.c) {
        return Err("challenge-mismatch".into());
    }
    // e(Abar, W) == e(Bbar, BP2)
    if !ec::pairing_eq(&p.abar, &w, &p.bbar, &G2::generator()) {
        return Err("pairing-mismatch".into());
    }
    Ok(())
}

/// Whether the proof is valid.
pub fn proof_verify(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_messages: &[Vec<u8>], disclosed_indexes: &[i64]) -> bool {
    proof_verify_detailed(pk, proof, header, ph, disclosed_messages, disclosed_indexes).is_ok()
}

// ---- capability credentials ------------------------------------------------------------------------------------------
//
// A PCA capability as a multi-message BBS credential, presented with selective disclosure and unlinkable proofs. The message
// vector is: index 0 = iss (issuer key), 1 = sub (holder key), 2.. = one message per caveat, named cav:<i>:<type>, whose value
// is the strict-canonical JSON of the caveat. Each message's octets are utf8(name) || 0x00 || utf8(value). Credentials and
// presentations are generic JSON values, so hostile shapes are refused, never trusted.

struct Attr {
    index: i64,
    name: String,
    value: String,
}

fn encode_attribute(a: &Attr) -> Result<Vec<u8>, String> {
    if a.name.contains('\0') {
        return Err("attribute name must not contain NUL".into());
    }
    let mut out = a.name.as_bytes().to_vec();
    out.push(0);
    out.extend_from_slice(a.value.as_bytes());
    Ok(out)
}

fn encode_all(attrs: &[Attr]) -> Result<Vec<Vec<u8>>, String> {
    attrs.iter().map(encode_attribute).collect()
}

fn attr_of(v: &Value) -> Option<Attr> {
    let m = v.as_object()?;
    Some(Attr { index: m.get("index")?.as_i64()?, name: m.get("name")?.as_str()?.to_string(), value: m.get("value")?.as_str()?.to_string() })
}

fn attrs_of(v: &Value) -> Option<Vec<Attr>> {
    v.as_array()?.iter().map(attr_of).collect()
}

fn attr_json(i: i64, name: &str, value: &str) -> Value {
    let mut m = Map::new();
    m.insert("index".into(), i.into());
    m.insert("name".into(), name.into());
    m.insert("value".into(), value.into());
    Value::Object(m)
}

/// The ordered attribute vector for a capability `{issuer, holder, caveats}`.
pub fn capability_attributes(capability: &Value) -> Result<Value, String> {
    let (Some(issuer), Some(holder)) = (capability.get("issuer").and_then(Value::as_str), capability.get("holder").and_then(Value::as_str)) else {
        return Err("capability issuer and holder must be strings".into());
    };
    let mut out = vec![attr_json(0, "iss", issuer), attr_json(1, "sub", holder)];
    let empty = Vec::new();
    let caveats = capability.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
    for (i, cv) in caveats.iter().enumerate() {
        // a caveat without a type is named as the reference stringifies it
        let typ = match cv.get("type") {
            None => "undefined".to_string(),
            Some(t) => t.as_str().ok_or("caveat type must be a string")?.to_string(),
        };
        let canon = crate::canonicalize_strict(cv)?;
        out.push(attr_json(i as i64 + 2, &format!("cav:{i}:{typ}"), &canon));
    }
    Ok(Value::Array(out))
}

/// Signs a capability's attributes as a BBS credential; `header` is bound into the signature.
pub fn issue_capability_credential(capability: &Value, sk: &Fr, pk: &[u8], header: &[u8]) -> Result<Value, String> {
    let attrs = capability_attributes(capability)?;
    let parsed = attrs_of(&attrs).ok_or("malformed attributes")?;
    let sig = sign(sk, pk, header, &encode_all(&parsed)?)?;
    let mut m = Map::new();
    m.insert("issuerPublicKey".into(), b64u(pk).into());
    m.insert("header".into(), b64u(header).into());
    m.insert("attributes".into(), attrs);
    m.insert("signature".into(), b64u(&sig).into());
    Ok(Value::Object(m))
}

fn str_of<'a>(m: &'a Value, k: &str) -> Option<&'a str> {
    m.get(k)?.as_str()
}

/// Verifies a whole credential against its issuer key. Never panics; `false` on any malformed input.
pub fn verify_credential(cred: &Value) -> bool {
    let (Some(pks), Some(hs), Some(ss)) = (str_of(cred, "issuerPublicKey"), str_of(cred, "header"), str_of(cred, "signature")) else { return false };
    let (Some(pk), Some(header), Some(sig)) = (unb64u(pks), unb64u(hs), unb64u(ss)) else { return false };
    let Some(attrs) = cred.get("attributes").and_then(attrs_of) else { return false };
    match encode_all(&attrs) {
        Ok(msgs) => verify(&pk, &sig, &header, &msgs),
        Err(_) => false,
    }
}

/// The verifier's own expectations for [`verify_presentation`]; every field is optional (`None` = take the presentation's).
#[derive(Default, Clone)]
pub struct PresentOptions {
    pub public_key: Option<Vec<u8>>,
    /// The exact attributes required (a JSON array of `{index, name, value}`).
    pub disclosed: Option<Value>,
    pub presentation_header: Option<Vec<u8>>,
}

fn same_disclosure(a: &[Attr], b: &[Attr]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let key = |x: &Attr| format!("{}\0{}\0{}", x.index, x.name, x.value);
    let (mut ka, mut kb): (Vec<String>, Vec<String>) = (a.iter().map(key).collect(), b.iter().map(key).collect());
    ka.sort();
    kb.sort();
    ka == kb
}

/// Checks a selective-disclosure proof; `opts` asserts the verifier's own expectations (a pinned issuer key, the exact
/// attributes required, the action digest the proof must be bound to).
pub fn verify_presentation(pres: &Value, opts: &PresentOptions) -> bool {
    let (Some(pks), Some(hs), Some(prs)) = (str_of(pres, "issuerPublicKey"), str_of(pres, "header"), str_of(pres, "proof")) else { return false };
    let pk = match &opts.public_key {
        Some(k) => k.clone(),
        None => match unb64u(pks) {
            Some(k) => k,
            None => return false,
        },
    };
    let (Some(header), Some(proof)) = (unb64u(hs), unb64u(prs)) else { return false };
    // a pinned issuer key must be the one the presentation claims
    if opts.public_key.is_some() && b64u(&pk) != pks {
        return false;
    }
    let phs = str_of(pres, "presentationHeader").unwrap_or("");
    let ph = match &opts.presentation_header {
        Some(p) => p.clone(),
        // the reference refuses a presentation without its own header string when the verifier pins none
        None => match str_of(pres, "presentationHeader").and_then(unb64u) {
            Some(p) => p,
            None => return false,
        },
    };
    if opts.presentation_header.as_ref().is_some_and(|p| !p.is_empty()) && b64u(&ph) != phs {
        return false;
    }
    let Some(shown) = pres.get("disclosed").and_then(attrs_of) else { return false };
    let disclosed = match &opts.disclosed {
        Some(pv) => {
            let Some(pinned) = attrs_of(pv) else { return false };
            if !same_disclosure(&pinned, &shown) {
                return false;
            }
            pinned
        }
        None => shown,
    };
    let Some(n) = pres.get("messageCount").and_then(Value::as_i64) else { return false };
    let mut sorted = disclosed;
    sorted.sort_by_key(|a| a.index);
    let Ok(msgs) = encode_all(&sorted) else { return false };
    if sorted.iter().any(|a| a.index >= n || a.index < 0) {
        return false;
    }
    let idxs: Vec<i64> = sorted.iter().map(|a| a.index).collect();
    proof_verify(&pk, &proof, &header, &ph, &msgs, &idxs)
}

/// Produces a selective-disclosure presentation revealing only the named attributes; `presentation_header` binds the proof
/// to a context (for example a PCActn action digest). Randomized (fresh blinding scalars every call: unlinkable).
pub fn present_credential(cred: &Value, disclose: &[&str], presentation_header: &[u8]) -> Result<Value, String> {
    let pk = unb64u(str_of(cred, "issuerPublicKey").ok_or("malformed credential")?).ok_or("malformed credential")?;
    let header = unb64u(str_of(cred, "header").ok_or("malformed credential")?).ok_or("malformed credential")?;
    let signature = unb64u(str_of(cred, "signature").ok_or("malformed credential")?).ok_or("malformed credential")?;
    let attrs = cred.get("attributes").and_then(attrs_of).ok_or("malformed credential")?;
    let messages = encode_all(&attrs)?;
    let (mut idxs, mut shown) = (Vec::new(), Vec::new());
    for (a, raw) in attrs.iter().zip(cred["attributes"].as_array().expect("array")) {
        if disclose.contains(&a.name.as_str()) {
            idxs.push(a.index);
            shown.push(raw.clone());
        }
    }
    let missing: Vec<&&str> = disclose.iter().filter(|n| !attrs.iter().any(|a| a.name == **n)).collect();
    if !missing.is_empty() {
        return Err(format!("presentCredential: unknown attribute(s): {}", missing.iter().map(|s| **s).collect::<Vec<_>>().join(", ")));
    }
    let proof = proof_gen(&pk, &signature, &header, presentation_header, &messages, &idxs, None)?;
    let mut m = Map::new();
    m.insert("issuerPublicKey".into(), cred["issuerPublicKey"].clone());
    m.insert("header".into(), cred["header"].clone());
    m.insert("presentationHeader".into(), b64u(presentation_header).into());
    m.insert("messageCount".into(), (attrs.len() as i64).into());
    m.insert("disclosed".into(), Value::Array(shown));
    m.insert("proof".into(), b64u(&proof).into());
    Ok(Value::Object(m))
}

/// `CIPHERSUITE_ID` of the reference.
pub const CIPHERSUITE_ID: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// `skFromBytes`: a 32-octet big-endian secret scalar; zero and values at or above the subgroup order are refused.
pub fn sk_from_bytes(bytes: &[u8]) -> Result<Fr, String> {
    if bytes.len() != 32 {
        return Err("bbs: SK must be 32 octets".into());
    }
    match Fr::from_canonical(bytes) {
        Some(sk) if !sk.is_zero() => Ok(sk),
        _ => Err("bbs: SK out of range".into()),
    }
}
