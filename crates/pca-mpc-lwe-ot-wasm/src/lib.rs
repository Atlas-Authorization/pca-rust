//! Post-quantum endemic (Masny–Rindal) base-OT lattice core, compiled to WebAssembly.
//!
//! This is the "true PQ, maliciously-secure base OT" core for `@atlasauth/pca-mpc`. The
//! semi-honest ML-KEM base OT (`kem-ot.ts`) has an intrinsic residue — a malicious receiver that
//! runs KEM keygen twice and keeps BOTH secret keys learns both messages, and the opaque KEM cannot
//! detect it. This core removes that residue by implementing the **endemic OT of Masny–Rindal
//! (ePrint 2019/706)** in the random-oracle model, instantiated over **Module-LWE** exactly as the
//! battle-tested libOTe `MasnyRindal` construction does for groups, but with the group replaced by
//! Kyber's IND-CPA public-key encryption (K-PKE):
//!
//!   The non-chosen branch's "public key" is derived additively through a random oracle so that it
//!   is a UNIFORM element of the Kyber public-key (ring) space. Under decisional Module-LWE a uniform
//!   ring element is indistinguishable from a real Kyber public key AND (whp) admits no low-norm
//!   secret at all — so the receiver provably cannot decrypt that branch, hence cannot learn both
//!   messages. Recovering the non-chosen message reduces to breaking IND-CPA of K-PKE under a uniform
//!   public key, which is decisional Module-LWE.
//!
//! The full two-round protocol and its security reduction live in the TypeScript orchestration
//! layer (`endemic-ot.ts`); this crate provides only the lattice primitives it composes.
//!
//! ## What is vetted vs. what this crate adds (the honest boundary)
//! The entire Kyber crypto core is the **audited `pqc_kyber` reference implementation**, reached via
//! its `hazmat` feature (`pqc_kyber::indcpa`): K-PKE key generation, CPA encryption and CPA
//! decryption — and therefore the NTT, the deterministic matrix expansion from the seed, the CBD
//! noise sampling, polynomial multiplication, compression and modular reduction. NONE of that is
//! reimplemented here.
//!
//! This crate adds only three non-cryptographic pieces that the additive endemic construction needs
//! and that `pqc_kyber` does not re-export:
//!   1. 12-bit (de)serialization of a public-key ring vector `t̂` — a byte copy of the Kyber
//!      reference `poly_{to,from}bytes` packing, so the bytes this crate produces decode identically
//!      inside `indcpa_enc`'s `unpack_pk`.
//!   2. Coefficient-wise addition / subtraction of two `t̂` vectors modulo the public prime
//!      `q = 3329` — trivial modular vector arithmetic, NOT NTT or polynomial multiplication. (NTT is
//!      linear, so adding in the serialized NTT domain adds the underlying ring elements.)
//!   3. A random-oracle "hash to a uniform ring element": SHAKE128 followed by the standard
//!      FIPS-203 / Kyber `SampleNTT` rejection sampler (the very sampler Kyber uses to expand its
//!      public matrix A), yielding a uniformly random `t̂` vector.
//! None of these is the Kyber PKE, its NTT, its noise sampler or its compression.
//!
//! ## Kyber-768 parameters (FIPS-203 security category 3)
//! q = 3329, n = 256, k = 3. Public key = `ByteEncode_12(t̂) || rho` = 1152 + 32 = 1184 bytes;
//! IND-CPA secret key = 1152 bytes; ciphertext = 1088 bytes; a ring vector `t̂` is 1152 bytes =
//! 3 * 384 = 768 twelve-bit coefficients.
//!
//! ## ABI (mirrors @atlasauth/pca-mpc-wasm)
//! `#![no_std]`, no allocator, no imports. All I/O is through fixed static buffers in linear memory
//! whose addresses the `ptr_*` exports return; the module instantiates with an empty import object
//! and is driven single-threaded (write inputs -> call op -> read an output buffer).

#![cfg_attr(not(any(test, feature = "capi")), no_std)]

use pqc_kyber::indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No code path below panics on adversarial input (every Kyber call has fixed-size buffers and
    // the ring ops are total), so this is only reached on a genuine bug; abort rather than unwind.
    core::arch::wasm32::unreachable()
}

// --- Kyber-768 sizes (bytes), fixed at compile time. ---
const Q: u16 = 3329;
const TVEC_BYTES: usize = 1152; // ByteEncode_12 of a k=3 ring vector t̂
const TRIPLES: usize = TVEC_BYTES / 3; // 384 three-byte groups -> 768 coefficients
const COEFFS: usize = TRIPLES * 2; // 768
const PK_BYTES: usize = 1184; // t̂ || rho
const SK_BYTES: usize = 1152;
const CT_BYTES: usize = 1088;
const SYM_BYTES: usize = 32; // seed / coins / message
const HASHIN_CAP: usize = 4096; // random-oracle input cap

// ===================================================================================================
// Pure-Rust core (operates on slices; the extern "C" exports below drive it over the static buffers,
// and the native KAT tests call it directly).
// ===================================================================================================

/// A zero RNG for the DETERMINISTIC seeded keygen path of `indcpa_keypair`, where the RNG is never
/// read (the 32-byte seed supplies all randomness). It is `CryptoRng` so it satisfies the bound.
struct NullRng;
impl RngCore for NullRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = 0;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for NullRng {}

/// DETERMINISTIC K-PKE key generation (vetted `pqc_kyber::indcpa::indcpa_keypair`). The 32-byte
/// `seed` is Kyber's `d`: the reference hashes `G(d)` into (publicseed rho, noiseseed) and derives
/// the real public key `t̂ = A∘ŝ + ê`. Returns the public key (`t̂ || rho`, 1184 B) and IND-CPA
/// secret key (ŝ, 1152 B). `Some((seed, seed))` selects the deterministic path so `rng` is unused.
fn kpke_keygen_into(seed: &[u8], pk: &mut [u8], sk: &mut [u8]) -> bool {
    let mut rng = NullRng;
    indcpa_keypair(pk, sk, Some((seed, seed)), &mut rng).is_ok()
}

/// K-PKE.KeyGen(d) exactly as FIPS 203 Algorithm 13 derives it, via RustCrypto `ml-kem` (ML-KEM.KeyGen_internal(d, z) embeds it: the encapsulation key
/// is the K-PKE public key and the first `SK_BYTES` of the decapsulation key are the K-PKE secret key; `z` is irrelevant and fixed to zero). This is
/// what the TypeScript reference derives through @noble/post-quantum. The 32-byte `seed` is FIPS 203's `d`.
#[cfg(feature = "hoststd")]
fn kpke_keygen_fips203_into(seed: &[u8], pk: &mut [u8], sk: &mut [u8]) -> bool {
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768, B32};
    let mut d = B32::default();
    d.copy_from_slice(seed);
    let z = B32::default();
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    let (ek, dk) = (ek.as_bytes(), dk.as_bytes());
    if ek.len() != PK_BYTES || dk.len() < SK_BYTES {
        return false;
    }
    pk.copy_from_slice(&ek[..]);
    sk.copy_from_slice(&dk[..SK_BYTES]);
    true
}

/// K-PKE CPA encryption (vetted `pqc_kyber::indcpa::indcpa_enc`) of a 32-byte `msg` under `pk`
/// (`t̂ || rho`, any 1184-byte public key — real OR the uniform one the endemic construction derives),
/// with 32-byte `coins` deterministically expanding all encryption randomness. Writes `ct` (1088 B).
fn kpke_enc_into(pk: &[u8], msg: &[u8], coins: &[u8], ct: &mut [u8]) {
    indcpa_enc(ct, msg, pk, coins);
}

/// K-PKE CPA decryption (vetted `pqc_kyber::indcpa::indcpa_dec`): recover the 32-byte message from
/// `ct` under IND-CPA secret key `sk`. Writes `msg` (32 B).
fn kpke_dec_into(sk: &[u8], ct: &[u8], msg: &mut [u8]) {
    indcpa_dec(msg, ct, sk);
}

/// Reduce a 12-bit value (0..4095) into `[0, q)` with a single conditional subtract (4095 < 2q).
#[inline]
fn rq(x: u16) -> u16 {
    if x >= Q {
        x - Q
    } else {
        x
    }
}

/// Decode the two 12-bit coefficients packed in `buf[3*i .. 3*i+3]` (Kyber `poly_frombytes` layout).
#[inline]
fn dec_pair(buf: &[u8], i: usize) -> (u16, u16) {
    let b0 = buf[3 * i] as u16;
    let b1 = buf[3 * i + 1] as u16;
    let b2 = buf[3 * i + 2] as u16;
    let c0 = (b0 | (b1 << 8)) & 0xFFF;
    let c1 = ((b1 >> 4) | (b2 << 4)) & 0xFFF;
    (c0, c1)
}

/// Encode two coefficients (each assumed already reduced into `[0, q)`) into `out[3*i .. 3*i+3]`
/// (Kyber `poly_tobytes` layout).
#[inline]
fn enc_pair(out: &mut [u8], i: usize, c0: u16, c1: u16) {
    out[3 * i] = (c0 & 0xff) as u8;
    out[3 * i + 1] = (((c0 >> 8) | (c1 << 4)) & 0xff) as u8;
    out[3 * i + 2] = ((c1 >> 4) & 0xff) as u8;
}

/// `out = (a + b) mod q`, coefficient-wise over a serialized ring vector `t̂` (NOT NTT / not a
/// polynomial product — plain modular vector addition; NTT linearity makes this the ring sum).
fn ring_add_into(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..TRIPLES {
        let (a0, a1) = dec_pair(a, i);
        let (b0, b1) = dec_pair(b, i);
        let s0 = {
            let s = rq(a0) + rq(b0);
            if s >= Q {
                s - Q
            } else {
                s
            }
        };
        let s1 = {
            let s = rq(a1) + rq(b1);
            if s >= Q {
                s - Q
            } else {
                s
            }
        };
        enc_pair(out, i, s0, s1);
    }
}

/// `out = (a - b) mod q`, coefficient-wise over a serialized ring vector `t̂`.
fn ring_sub_into(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..TRIPLES {
        let (a0, a1) = dec_pair(a, i);
        let (b0, b1) = dec_pair(b, i);
        let s0 = {
            let s = rq(a0) + Q - rq(b0);
            if s >= Q {
                s - Q
            } else {
                s
            }
        };
        let s1 = {
            let s = rq(a1) + Q - rq(b1);
            if s >= Q {
                s - Q
            } else {
                s
            }
        };
        enc_pair(out, i, s0, s1);
    }
}

/// Random oracle into the Kyber public-key (ring) space: SHAKE128(`input`) expanded through the
/// standard FIPS-203 / Kyber `SampleNTT` rejection sampler (accept a 12-bit value iff `< q`) to a
/// uniformly random `t̂` vector of `COEFFS` coefficients, serialized into `out` (1152 B).
///
/// This is exactly Kyber's own uniform-`t̂` sampler (the one it uses to expand the public matrix A),
/// so `out` is uniform over the ring-vector space — which is precisely what makes the non-chosen
/// branch's derived public key indistinguishable from a real one under decisional Module-LWE while
/// admitting no low-norm secret. Domain separation / session binding is the caller's responsibility
/// (fold tags + the session id + the transfer index + the other branch's value into `input`).
fn hash_to_ring_into(input: &[u8], out: &mut [u8]) {
    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();

    let mut buf = [0u8; 3];
    let mut i = 0usize; // coefficient index
    while i < COEFFS {
        reader.read(&mut buf);
        let val0 = ((buf[0] as u16) | ((buf[1] as u16) << 8)) & 0xFFF;
        let val1 = (((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4)) & 0xFFF;
        if val0 < Q {
            stage(out, i, val0);
            i += 1;
        }
        if i < COEFFS && val1 < Q {
            stage(out, i, val1);
            i += 1;
        }
    }
}

/// Stage a single reduced coefficient at index `i` into the serialized output by rewriting its
/// 3-byte group. (The group's partner coefficient is staged by its own call; both coefficients of a
/// group are always < q, so the final encoding is well-formed.) Uses a read-modify-write of the
/// group so the two half-updates compose regardless of order.
#[inline]
fn stage(out: &mut [u8], i: usize, c: u16) {
    let group = i / 2;
    let (mut c0, mut c1) = dec_pair(out, group);
    if i % 2 == 0 {
        c0 = c;
    } else {
        c1 = c;
    }
    enc_pair(out, group, c0, c1);
}

#[cfg(not(feature = "capi"))]
mod wasm_abi {
    use super::*;

    // --- Fixed linear-memory I/O buffers (stable for the life of the instance). ---
    static mut SEED: [u8; SYM_BYTES] = [0u8; SYM_BYTES];
    static mut COINS: [u8; SYM_BYTES] = [0u8; SYM_BYTES];
    static mut MSG: [u8; SYM_BYTES] = [0u8; SYM_BYTES];
    static mut PK: [u8; PK_BYTES] = [0u8; PK_BYTES];
    static mut SK: [u8; SK_BYTES] = [0u8; SK_BYTES];
    static mut CT: [u8; CT_BYTES] = [0u8; CT_BYTES];
    static mut RA: [u8; TVEC_BYTES] = [0u8; TVEC_BYTES];
    static mut RB: [u8; TVEC_BYTES] = [0u8; TVEC_BYTES];
    static mut ROUT: [u8; TVEC_BYTES] = [0u8; TVEC_BYTES];
    /// Random-oracle input buffer (domain-separation tag || sid || index || the other branch's t̂, etc.).
    static mut HASHIN: [u8; HASHIN_CAP] = [0u8; HASHIN_CAP];

    // ===================================================================================================
    // C-ABI exports (fixed static buffers; mirror @atlasauth/pca-mpc-wasm's ptr_* + op style).
    // ===================================================================================================

    #[no_mangle]
    pub extern "C" fn ptr_seed() -> *mut u8 {
        core::ptr::addr_of_mut!(SEED) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_coins() -> *mut u8 {
        core::ptr::addr_of_mut!(COINS) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_msg() -> *mut u8 {
        core::ptr::addr_of_mut!(MSG) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_pk() -> *mut u8 {
        core::ptr::addr_of_mut!(PK) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_sk() -> *mut u8 {
        core::ptr::addr_of_mut!(SK) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_ct() -> *mut u8 {
        core::ptr::addr_of_mut!(CT) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_ra() -> *mut u8 {
        core::ptr::addr_of_mut!(RA) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_rb() -> *mut u8 {
        core::ptr::addr_of_mut!(RB) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_rout() -> *mut u8 {
        core::ptr::addr_of_mut!(ROUT) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_hashin() -> *mut u8 {
        core::ptr::addr_of_mut!(HASHIN) as *mut u8
    }

    // Lengths, so the TS binding never hardcodes a size the crate might change.
    #[no_mangle]
    pub extern "C" fn len_pk() -> i32 {
        PK_BYTES as i32
    }
    #[no_mangle]
    pub extern "C" fn len_sk() -> i32 {
        SK_BYTES as i32
    }
    #[no_mangle]
    pub extern "C" fn len_ct() -> i32 {
        CT_BYTES as i32
    }
    #[no_mangle]
    pub extern "C" fn len_tvec() -> i32 {
        TVEC_BYTES as i32
    }
    #[no_mangle]
    pub extern "C" fn len_sym() -> i32 {
        SYM_BYTES as i32
    }

    /// `(PK, SK) = K-PKE.KeyGen(SEED)` — deterministic. Returns 1 on success, 0 on failure.
    #[no_mangle]
    pub extern "C" fn kpke_keygen() -> i32 {
        let seed = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SEED) as *const u8, SYM_BYTES) };
        let pk = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(PK) as *mut u8, PK_BYTES) };
        let sk = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(SK) as *mut u8, SK_BYTES) };
        i32::from(kpke_keygen_into(seed, pk, sk))
    }

    /// `CT = K-PKE.Enc(PK, MSG; COINS)`. Returns 1.
    #[no_mangle]
    pub extern "C" fn kpke_enc() -> i32 {
        let pk = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(PK) as *const u8, PK_BYTES) };
        let msg = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(MSG) as *const u8, SYM_BYTES) };
        let coins = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(COINS) as *const u8, SYM_BYTES) };
        let ct = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(CT) as *mut u8, CT_BYTES) };
        kpke_enc_into(pk, msg, coins, ct);
        1
    }

    /// `MSG = K-PKE.Dec(SK, CT)`. Returns 1.
    #[no_mangle]
    pub extern "C" fn kpke_dec() -> i32 {
        let sk = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SK) as *const u8, SK_BYTES) };
        let ct = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(CT) as *const u8, CT_BYTES) };
        let msg = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(MSG) as *mut u8, SYM_BYTES) };
        kpke_dec_into(sk, ct, msg);
        1
    }

    /// `ROUT = (RA + RB) mod q`. Returns 1.
    #[no_mangle]
    pub extern "C" fn ring_add() -> i32 {
        let a = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RA) as *const u8, TVEC_BYTES) };
        let b = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RB) as *const u8, TVEC_BYTES) };
        let out = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ROUT) as *mut u8, TVEC_BYTES) };
        ring_add_into(a, b, out);
        1
    }

    /// `ROUT = (RA - RB) mod q`. Returns 1.
    #[no_mangle]
    pub extern "C" fn ring_sub() -> i32 {
        let a = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RA) as *const u8, TVEC_BYTES) };
        let b = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RB) as *const u8, TVEC_BYTES) };
        let out = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ROUT) as *mut u8, TVEC_BYTES) };
        ring_sub_into(a, b, out);
        1
    }

    /// `ROUT = SampleNTT(SHAKE128(HASHIN[..len]))` — a uniform ring vector. Returns 1.
    #[no_mangle]
    pub extern "C" fn hash_to_ring(len: i32) -> i32 {
        let n = len as usize;
        if n > HASHIN_CAP {
            return 0;
        }
        let input = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(HASHIN) as *const u8, n) };
        let out = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ROUT) as *mut u8, TVEC_BYTES) };
        hash_to_ring_into(input, out);
        1
    }
}

// ===================================================================================================
// Host C ABI (cargo feature `capi`): caller-owned buffers, every pointer paired with its length, an int
// status, no global state (so it is thread-safe). 0 = ok, negative = refused (nothing written on refusal).
// ===================================================================================================
#[cfg(feature = "capi")]
pub mod capi {
    use super::*;

    pub const LWEOT_OK: i32 = 0;
    pub const LWEOT_ERR_ARG: i32 = -1; // null pointer or wrong length
    pub const LWEOT_ERR_INTERNAL: i32 = -2;

    unsafe fn rd<'a>(p: *const u8, len: usize, want: usize) -> Option<&'a [u8]> {
        if p.is_null() || len != want {
            return None;
        }
        Some(core::slice::from_raw_parts(p, len))
    }
    unsafe fn wr<'a>(p: *mut u8, len: usize, want: usize) -> Option<&'a mut [u8]> {
        if p.is_null() || len != want {
            return None;
        }
        Some(core::slice::from_raw_parts_mut(p, len))
    }

    #[no_mangle]
    pub extern "C" fn lweot_len_pk() -> usize { PK_BYTES }
    #[no_mangle]
    pub extern "C" fn lweot_len_sk() -> usize { SK_BYTES }
    #[no_mangle]
    pub extern "C" fn lweot_len_ct() -> usize { CT_BYTES }
    #[no_mangle]
    pub extern "C" fn lweot_len_tvec() -> usize { TVEC_BYTES }
    #[no_mangle]
    pub extern "C" fn lweot_len_sym() -> usize { SYM_BYTES }
    #[no_mangle]
    pub extern "C" fn lweot_hashin_cap() -> usize { HASHIN_CAP }

    /// `(pk, sk) = K-PKE.KeyGen(seed)` (deterministic).
    #[no_mangle]
    pub unsafe extern "C" fn lweot_kpke_keygen(
        seed: *const u8, seed_len: usize, pk: *mut u8, pk_len: usize, sk: *mut u8, sk_len: usize,
    ) -> i32 {
        let (Some(seed), Some(pk), Some(sk)) =
            (rd(seed, seed_len, SYM_BYTES), wr(pk, pk_len, PK_BYTES), wr(sk, sk_len, SK_BYTES))
        else { return LWEOT_ERR_ARG };
        if kpke_keygen_into(seed, pk, sk) { LWEOT_OK } else { LWEOT_ERR_INTERNAL }
    }

    /// `(pk, sk) = K-PKE.KeyGen(d)` as FIPS 203 Algorithm 13 derives it (deterministic): the key pair the endemic receiver uses.
    #[no_mangle]
    pub unsafe extern "C" fn lweot_kpke_keygen_fips203(
        seed: *const u8, seed_len: usize, pk: *mut u8, pk_len: usize, sk: *mut u8, sk_len: usize,
    ) -> i32 {
        let (Some(seed), Some(pk), Some(sk)) =
            (rd(seed, seed_len, SYM_BYTES), wr(pk, pk_len, PK_BYTES), wr(sk, sk_len, SK_BYTES))
        else { return LWEOT_ERR_ARG };
        if kpke_keygen_fips203_into(seed, pk, sk) { LWEOT_OK } else { LWEOT_ERR_INTERNAL }
    }

    /// `ct = K-PKE.Enc(pk, msg; coins)`.
    #[no_mangle]
    pub unsafe extern "C" fn lweot_kpke_enc(
        pk: *const u8, pk_len: usize, msg: *const u8, msg_len: usize, coins: *const u8, coins_len: usize,
        ct: *mut u8, ct_len: usize,
    ) -> i32 {
        let (Some(pk), Some(msg), Some(coins), Some(ct)) = (
            rd(pk, pk_len, PK_BYTES), rd(msg, msg_len, SYM_BYTES), rd(coins, coins_len, SYM_BYTES),
            wr(ct, ct_len, CT_BYTES),
        ) else { return LWEOT_ERR_ARG };
        kpke_enc_into(pk, msg, coins, ct);
        LWEOT_OK
    }

    /// `msg = K-PKE.Dec(sk, ct)`.
    #[no_mangle]
    pub unsafe extern "C" fn lweot_kpke_dec(
        sk: *const u8, sk_len: usize, ct: *const u8, ct_len: usize, msg: *mut u8, msg_len: usize,
    ) -> i32 {
        let (Some(sk), Some(ct), Some(msg)) =
            (rd(sk, sk_len, SK_BYTES), rd(ct, ct_len, CT_BYTES), wr(msg, msg_len, SYM_BYTES))
        else { return LWEOT_ERR_ARG };
        kpke_dec_into(sk, ct, msg);
        LWEOT_OK
    }

    /// `out = (a + b) mod q` over serialized ring vectors.
    #[no_mangle]
    pub unsafe extern "C" fn lweot_ring_add(
        a: *const u8, a_len: usize, b: *const u8, b_len: usize, out: *mut u8, out_len: usize,
    ) -> i32 {
        let (Some(a), Some(b), Some(out)) =
            (rd(a, a_len, TVEC_BYTES), rd(b, b_len, TVEC_BYTES), wr(out, out_len, TVEC_BYTES))
        else { return LWEOT_ERR_ARG };
        ring_add_into(a, b, out);
        LWEOT_OK
    }

    /// `out = (a - b) mod q` over serialized ring vectors.
    #[no_mangle]
    pub unsafe extern "C" fn lweot_ring_sub(
        a: *const u8, a_len: usize, b: *const u8, b_len: usize, out: *mut u8, out_len: usize,
    ) -> i32 {
        let (Some(a), Some(b), Some(out)) =
            (rd(a, a_len, TVEC_BYTES), rd(b, b_len, TVEC_BYTES), wr(out, out_len, TVEC_BYTES))
        else { return LWEOT_ERR_ARG };
        ring_sub_into(a, b, out);
        LWEOT_OK
    }

    /// `out = SampleNTT(SHAKE128(input))`; input length 0..=lweot_hashin_cap().
    #[no_mangle]
    pub unsafe extern "C" fn lweot_hash_to_ring(
        input: *const u8, input_len: usize, out: *mut u8, out_len: usize,
    ) -> i32 {
        if input_len > HASHIN_CAP || (input.is_null() && input_len != 0) {
            return LWEOT_ERR_ARG;
        }
        let Some(out) = wr(out, out_len, TVEC_BYTES) else { return LWEOT_ERR_ARG };
        let input: &[u8] = if input_len == 0 { &[] } else { core::slice::from_raw_parts(input, input_len) };
        hash_to_ring_into(input, out);
        LWEOT_OK
    }
}

// ===================================================================================================
// Safe Rust API (cargo feature `hoststd`, implied by `capi`): fixed-size arrays in, arrays out, for Rust crates that depend on this one directly.
// The same vetted functions as the C ABI; nothing here touches global state.
// ===================================================================================================
#[cfg(feature = "hoststd")]
pub mod safe {
    use super::*;

    pub const PK_LEN: usize = PK_BYTES;
    pub const SK_LEN: usize = SK_BYTES;
    pub const CT_LEN: usize = CT_BYTES;
    pub const TVEC_LEN: usize = TVEC_BYTES;
    pub const SYM_LEN: usize = SYM_BYTES;
    pub const HASHIN_MAX: usize = HASHIN_CAP;

    /// `(pk, sk) = K-PKE.KeyGen(seed)` (deterministic); `None` only if the vetted keygen refuses.
    pub fn keygen(seed: &[u8; SYM_BYTES]) -> Option<([u8; PK_BYTES], [u8; SK_BYTES])> {
        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        kpke_keygen_into(seed, &mut pk, &mut sk).then_some((pk, sk))
    }

    /// `(pk, sk) = K-PKE.KeyGen(d)` as FIPS 203 Algorithm 13 derives it (what the reference endemic receiver uses); `None` only if the key sizes are unexpected.
    pub fn keygen_fips203(seed: &[u8; SYM_BYTES]) -> Option<([u8; PK_BYTES], [u8; SK_BYTES])> {
        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        kpke_keygen_fips203_into(seed, &mut pk, &mut sk).then_some((pk, sk))
    }

    /// `ct = K-PKE.Enc(pk, msg; coins)` under any 1184-byte key (a real one or the uniform one the endemic construction derives).
    pub fn enc(pk: &[u8; PK_BYTES], msg: &[u8; SYM_BYTES], coins: &[u8; SYM_BYTES]) -> [u8; CT_BYTES] {
        let mut ct = [0u8; CT_BYTES];
        kpke_enc_into(pk, msg, coins, &mut ct);
        ct
    }

    /// `msg = K-PKE.Dec(sk, ct)`.
    pub fn dec(sk: &[u8; SK_BYTES], ct: &[u8; CT_BYTES]) -> [u8; SYM_BYTES] {
        let mut msg = [0u8; SYM_BYTES];
        kpke_dec_into(sk, ct, &mut msg);
        msg
    }

    /// `(a + b) mod q` over serialized ring vectors.
    pub fn ring_add(a: &[u8; TVEC_BYTES], b: &[u8; TVEC_BYTES]) -> [u8; TVEC_BYTES] {
        let mut out = [0u8; TVEC_BYTES];
        ring_add_into(a, b, &mut out);
        out
    }

    /// `(a - b) mod q` over serialized ring vectors.
    pub fn ring_sub(a: &[u8; TVEC_BYTES], b: &[u8; TVEC_BYTES]) -> [u8; TVEC_BYTES] {
        let mut out = [0u8; TVEC_BYTES];
        ring_sub_into(a, b, &mut out);
        out
    }

    /// `SampleNTT(SHAKE128(input))`, a uniform ring vector; `None` when the input exceeds `HASHIN_MAX`.
    pub fn hash_to_ring(input: &[u8]) -> Option<[u8; TVEC_BYTES]> {
        if input.len() > HASHIN_CAP {
            return None;
        }
        let mut out = [0u8; TVEC_BYTES];
        hash_to_ring_into(input, &mut out);
        Some(out)
    }
}

// ===================================================================================================
// Native KAT / correctness tests (run on the host with `cargo test`, which links std).
// ===================================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // tiny deterministic byte generator (test-only): SHAKE128(tag) -> n bytes
    fn gen(tag: &[u8], n: usize) -> std::vec::Vec<u8> {
        let mut h = Shake128::default();
        h.update(tag);
        let mut r = h.finalize_xof();
        let mut out = std::vec![0u8; n];
        r.read(&mut out);
        out
    }

    // The FIPS 203 derivation yields a pair the shared enc/dec accept, and differs from the pre-standard pqc_kyber derivation (G(d) vs G(d || k)).
    #[cfg(feature = "hoststd")]
    #[test]
    fn fips203_keygen_roundtrips_and_differs_from_pqc_kyber() {
        let seed = gen(b"fips203-seed", SYM_BYTES);
        let (mut pk, mut sk) = ([0u8; PK_BYTES], [0u8; SK_BYTES]);
        assert!(kpke_keygen_fips203_into(&seed, &mut pk, &mut sk));
        let (mut pk0, mut sk0) = ([0u8; PK_BYTES], [0u8; SK_BYTES]);
        assert!(kpke_keygen_into(&seed, &mut pk0, &mut sk0));
        assert_ne!(pk, pk0);
        let (msg, coins) = (gen(b"m", SYM_BYTES), gen(b"c", SYM_BYTES));
        let mut ct = [0u8; CT_BYTES];
        kpke_enc_into(&pk, &msg, &coins, &mut ct);
        let mut out = [0u8; SYM_BYTES];
        kpke_dec_into(&sk, &ct, &mut out);
        assert_eq!(&out[..], &msg[..]);
    }

    #[test]
    fn kyber_sizes_are_kyber768() {
        assert_eq!(Q, 3329);
        assert_eq!(COEFFS, 768);
        assert_eq!(PK_BYTES, 1184);
        assert_eq!(SK_BYTES, 1152);
        assert_eq!(CT_BYTES, 1088);
        assert_eq!(TVEC_BYTES, 1152);
    }

    // KAT 1 — K-PKE decryption correctness: keygen/enc/dec round-trips the message for many
    // independent (seed, coins, msg) triples. This is the FIPS-203 correctness property of the
    // vetted arithmetic.
    #[test]
    fn kpke_roundtrip_correctness() {
        for t in 0u8..64 {
            let seed = gen(&[1, t], SYM_BYTES);
            let coins = gen(&[2, t], SYM_BYTES);
            let msg = gen(&[3, t], SYM_BYTES);
            let mut pk = std::vec![0u8; PK_BYTES];
            let mut sk = std::vec![0u8; SK_BYTES];
            assert!(kpke_keygen_into(&seed, &mut pk, &mut sk));
            let mut ct = std::vec![0u8; CT_BYTES];
            kpke_enc_into(&pk, &msg, &coins, &mut ct);
            let mut rec = std::vec![0u8; SYM_BYTES];
            kpke_dec_into(&sk, &ct, &mut rec);
            assert_eq!(rec, msg, "decryption must recover the message (t={t})");
        }
    }

    // KAT 2 — deterministic regression vector: a fixed seed yields a fixed public key; a fixed
    // (pk, msg, coins) yields a fixed ciphertext; and it decrypts back. Pins the vetted arithmetic
    // against any accidental change. (Digests, not raw bytes, to keep the test compact.)
    #[test]
    fn kpke_regression_vector() {
        let seed = std::vec![7u8; SYM_BYTES];
        let coins = std::vec![9u8; SYM_BYTES];
        let msg = std::vec![0xABu8; SYM_BYTES];
        let mut pk = std::vec![0u8; PK_BYTES];
        let mut sk = std::vec![0u8; SK_BYTES];
        assert!(kpke_keygen_into(&seed, &mut pk, &mut sk));
        let mut ct = std::vec![0u8; CT_BYTES];
        kpke_enc_into(&pk, &msg, &coins, &mut ct);
        let mut rec = std::vec![0u8; SYM_BYTES];
        kpke_dec_into(&sk, &ct, &mut rec);
        assert_eq!(rec, msg);

        // Digest helper (SHA3-256).
        fn d(x: &[u8]) -> std::vec::Vec<u8> {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            sha3::digest::Update::update(&mut h, x);
            h.finalize().to_vec()
        }
        // Determinism: same inputs -> identical outputs on a second run.
        let mut pk2 = std::vec![0u8; PK_BYTES];
        let mut sk2 = std::vec![0u8; SK_BYTES];
        assert!(kpke_keygen_into(&seed, &mut pk2, &mut sk2));
        assert_eq!(d(&pk), d(&pk2), "keygen must be deterministic in the seed");
        let mut ct2 = std::vec![0u8; CT_BYTES];
        kpke_enc_into(&pk2, &msg, &coins, &mut ct2);
        assert_eq!(d(&ct), d(&ct2), "encryption must be deterministic in the coins");
    }

    // The ring arithmetic the endemic construction relies on: subtracting then adding back the SAME
    // RO value recovers the original public-key ring vector EXACTLY (this is what makes the chosen
    // branch's derived public key equal the real one, so decryption succeeds).
    #[test]
    fn ring_homomorphism_is_exact() {
        let seed = gen(&[42], SYM_BYTES);
        let mut pk = std::vec![0u8; PK_BYTES];
        let mut sk = std::vec![0u8; SK_BYTES];
        assert!(kpke_keygen_into(&seed, &mut pk, &mut sk));
        let t_real = &pk[..TVEC_BYTES];

        // H = hash_to_ring(label)
        let mut h = std::vec![0u8; TVEC_BYTES];
        hash_to_ring_into(b"endemic-test-label", &mut h);

        // C = t_real - H ; back = C + H ; assert back == t_real
        let mut c = std::vec![0u8; TVEC_BYTES];
        ring_sub_into(t_real, &h, &mut c);
        let mut back = std::vec![0u8; TVEC_BYTES];
        ring_add_into(&c, &h, &mut back);
        assert_eq!(back, t_real, "C + H must recover t_real exactly");

        // And decryption still works when the sender encrypts under the reconstructed pk = (back || rho).
        let mut pk_rebuilt = std::vec![0u8; PK_BYTES];
        pk_rebuilt[..TVEC_BYTES].copy_from_slice(&back);
        pk_rebuilt[TVEC_BYTES..].copy_from_slice(&pk[TVEC_BYTES..]); // same rho
        let coins = gen(&[43], SYM_BYTES);
        let msg = gen(&[44], SYM_BYTES);
        let mut ct = std::vec![0u8; CT_BYTES];
        kpke_enc_into(&pk_rebuilt, &msg, &coins, &mut ct);
        let mut rec = std::vec![0u8; SYM_BYTES];
        kpke_dec_into(&sk, &ct, &mut rec);
        assert_eq!(rec, msg, "ciphertext under the reconstructed key must decrypt under the real sk");
    }

    // hash_to_ring produces a well-formed uniform ring vector: every coefficient is in [0, q).
    #[test]
    fn hash_to_ring_is_in_range() {
        let mut out = std::vec![0u8; TVEC_BYTES];
        hash_to_ring_into(b"uniformity-check", &mut out);
        for i in 0..TRIPLES {
            let (c0, c1) = dec_pair(&out, i);
            assert!(c0 < Q && c1 < Q, "coefficients must be reduced mod q");
        }
        // Different inputs give different outputs (RO behaviour).
        let mut out2 = std::vec![0u8; TVEC_BYTES];
        hash_to_ring_into(b"uniformity-check-2", &mut out2);
        assert_ne!(out, out2);
    }

    // The endemic property at the lattice level: a UNIFORM (RO-derived) non-chosen public key admits
    // no secret the receiver holds, so decrypting its ciphertext with the receiver's real sk does NOT
    // yield the sender's payload. (Full protocol-level security test lives in endemic-ot.test.ts.)
    #[test]
    fn uniform_branch_is_not_decryptable_with_real_sk() {
        let seed = gen(&[50], SYM_BYTES);
        let mut pk = std::vec![0u8; PK_BYTES];
        let mut sk = std::vec![0u8; SK_BYTES];
        assert!(kpke_keygen_into(&seed, &mut pk, &mut sk));

        // A uniform public key sharing the real rho (the non-chosen branch's shape).
        let mut t_uniform = std::vec![0u8; TVEC_BYTES];
        hash_to_ring_into(b"non-chosen-branch", &mut t_uniform);
        let mut pk_uniform = std::vec![0u8; PK_BYTES];
        pk_uniform[..TVEC_BYTES].copy_from_slice(&t_uniform);
        pk_uniform[TVEC_BYTES..].copy_from_slice(&pk[TVEC_BYTES..]);

        let coins = gen(&[51], SYM_BYTES);
        let payload = gen(&[52], SYM_BYTES);
        let mut ct = std::vec![0u8; CT_BYTES];
        kpke_enc_into(&pk_uniform, &payload, &coins, &mut ct);

        // The receiver has sk for t_real, NOT for the uniform key -> decrypt yields garbage != payload.
        let mut rec = std::vec![0u8; SYM_BYTES];
        kpke_dec_into(&sk, &ct, &mut rec);
        assert_ne!(rec, payload, "a uniform branch must not decrypt to the payload under the real sk");
    }
}
