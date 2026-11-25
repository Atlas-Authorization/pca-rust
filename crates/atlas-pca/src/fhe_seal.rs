//! Feature `fhe-seal`: the BFV half of the homomorphic risk gate (`@atlasauth/pca-fhe`) on Microsoft SEAL, through SEAL's own C
//! export API (the one SEAL.NET binds) declared by hand below, so the build needs no bindgen. Wire-compatible with the reference
//! (node-seal bundles SEAL 4.1.x): the evaluation is deterministic, so the evaluated ciphertexts equal the reference's byte for byte
//! once both are re-saved uncompressed. BFV is never reimplemented here: every lattice operation is SEAL.
//!
//! With the feature `fhe-seal-vendored` there is nothing to build by hand: the crate builds libsealc from the SEAL 4.1.2 sources it
//! ships and links it. Otherwise build libsealc from the pinned SEAL tag first and point `ATLAS_PCA_SEAL_LIB` at its directory (build.rs links it; at run time
//! the loader must find it too: the build adds an rpath, or set `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`).
//!
//! Every native handle is owned by a [`Scope`] and released in reverse order on every exit path; every length is checked before
//! it reaches C; bad input is an `Err`, never a panic.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::os::raw::{c_int, c_long, c_void};
use std::ptr::null_mut;

pub const POLY_MODULUS_DEGREE: u64 = 8192;
pub const PLAIN_MODULUS_BITS: i32 = 30;
pub const PLAIN_MODULUS: u64 = 1_073_692_673;
pub const SIGNED_BOUND: i64 = (PLAIN_MODULUS / 2) as i64;
pub const RISK_DIM: usize = 6;

const MIN_NOISE_BUDGET_BITS: c_int = 16;
const SCHEME_BFV: u8 = 1;
const SEC_LEVEL_TC128: c_int = 128;
const COMPR_NONE: u8 = 0;
const COMPR_ZSTD: u8 = 2;
/// Upper bound on any single serialized object we are willing to allocate (the biggest, a full Galois key set, is ~6 MB).
const MAX_SAVE: i64 = 1 << 31;

type P = *mut c_void;
type Destroy = unsafe extern "C" fn(P) -> c_long;

#[allow(non_snake_case)]
extern "C" {
    fn EncParams_Create1(scheme: u8, enc_params: *mut P) -> c_long;
    fn EncParams_Destroy(p: P) -> c_long;
    fn EncParams_SetPolyModulusDegree(p: P, degree: u64) -> c_long;
    fn EncParams_SetCoeffModulus(p: P, length: u64, coeffs: *mut P) -> c_long;
    fn EncParams_SetPlainModulus1(p: P, modulus: P) -> c_long;
    fn CoeffModulus_BFVDefault(degree: u64, sec_level: c_int, length: *mut u64, coeffs: *mut P) -> c_long;
    fn CoeffModulus_Create1(degree: u64, length: u64, bit_sizes: *mut c_int, coeffs: *mut P) -> c_long;
    fn Modulus_Destroy(p: P) -> c_long;
    fn Modulus_Value(p: P, value: *mut u64) -> c_long;
    fn SEALContext_Create(params: P, expand_mod_chain: bool, sec_level: c_int, context: *mut P) -> c_long;
    fn SEALContext_Destroy(p: P) -> c_long;
    fn SEALContext_ParametersSet(p: P, params_set: *mut bool) -> c_long;
    fn BatchEncoder_Create(context: P, encoder: *mut P) -> c_long;
    fn BatchEncoder_Destroy(p: P) -> c_long;
    fn BatchEncoder_Encode2(p: P, count: u64, values: *mut i64, destination: P) -> c_long;
    fn BatchEncoder_Decode2(p: P, plain: P, count: *mut u64, destination: *mut i64, pool: P) -> c_long;
    fn BatchEncoder_GetSlotCount(p: P, slot_count: *mut u64) -> c_long;
    fn KeyGenerator_Create1(context: P, generator: *mut P) -> c_long;
    fn KeyGenerator_Destroy(p: P) -> c_long;
    fn KeyGenerator_SecretKey(p: P, secret_key: *mut P) -> c_long;
    fn KeyGenerator_CreatePublicKey(p: P, save_seed: bool, public_key: *mut P) -> c_long;
    fn KeyGenerator_CreateRelinKeys(p: P, save_seed: bool, relin_keys: *mut P) -> c_long;
    fn KeyGenerator_CreateGaloisKeysAll(p: P, save_seed: bool, galois_keys: *mut P) -> c_long;
    fn PublicKey_Create1(out: *mut P) -> c_long;
    fn PublicKey_Destroy(p: P) -> c_long;
    fn PublicKey_SaveSize(p: P, compr: u8, result: *mut i64) -> c_long;
    fn PublicKey_Save(p: P, out: *mut u8, size: u64, compr: u8, out_bytes: *mut i64) -> c_long;
    fn PublicKey_Load(p: P, context: P, inp: *mut u8, size: u64, in_bytes: *mut i64) -> c_long;
    fn SecretKey_Create1(out: *mut P) -> c_long;
    fn SecretKey_Destroy(p: P) -> c_long;
    fn SecretKey_SaveSize(p: P, compr: u8, result: *mut i64) -> c_long;
    fn SecretKey_Save(p: P, out: *mut u8, size: u64, compr: u8, out_bytes: *mut i64) -> c_long;
    fn SecretKey_Load(p: P, context: P, inp: *mut u8, size: u64, in_bytes: *mut i64) -> c_long;
    fn KSwitchKeys_Create1(out: *mut P) -> c_long;
    fn KSwitchKeys_Destroy(p: P) -> c_long;
    fn KSwitchKeys_SaveSize(p: P, compr: u8, result: *mut i64) -> c_long;
    fn KSwitchKeys_Save(p: P, out: *mut u8, size: u64, compr: u8, out_bytes: *mut i64) -> c_long;
    fn KSwitchKeys_Load(p: P, context: P, inp: *mut u8, size: u64, in_bytes: *mut i64) -> c_long;
    fn Ciphertext_Create1(pool: P, out: *mut P) -> c_long;
    fn Ciphertext_Create2(copy: P, out: *mut P) -> c_long;
    fn Ciphertext_Destroy(p: P) -> c_long;
    fn Ciphertext_SaveSize(p: P, compr: u8, result: *mut i64) -> c_long;
    fn Ciphertext_Save(p: P, out: *mut u8, size: u64, compr: u8, out_bytes: *mut i64) -> c_long;
    fn Ciphertext_Load(p: P, context: P, inp: *mut u8, size: u64, in_bytes: *mut i64) -> c_long;
    fn Plaintext_Create1(pool: P, out: *mut P) -> c_long;
    fn Plaintext_Destroy(p: P) -> c_long;
    fn Encryptor_Create(context: P, public_key: P, secret_key: P, out: *mut P) -> c_long;
    fn Encryptor_Encrypt(p: P, plaintext: P, destination: P, pool: P) -> c_long;
    fn Encryptor_Destroy(p: P) -> c_long;
    fn Decryptor_Create(context: P, secret_key: P, out: *mut P) -> c_long;
    fn Decryptor_Destroy(p: P) -> c_long;
    fn Decryptor_Decrypt(p: P, encrypted: P, destination: P) -> c_long;
    fn Decryptor_InvariantNoiseBudget(p: P, encrypted: P, budget: *mut c_int) -> c_long;
    fn Evaluator_Create(context: P, out: *mut P) -> c_long;
    fn Evaluator_Destroy(p: P) -> c_long;
    fn Evaluator_Negate(p: P, encrypted: P, destination: P) -> c_long;
    fn Evaluator_Add(p: P, a: P, b: P, destination: P) -> c_long;
    fn Evaluator_AddPlain(p: P, encrypted: P, plain: P, destination: P) -> c_long;
    fn Evaluator_MultiplyPlain(p: P, encrypted: P, plain: P, destination: P, pool: P) -> c_long;
    fn Evaluator_RotateRows(p: P, encrypted: P, steps: c_int, galois_keys: P, destination: P, pool: P) -> c_long;
    fn Evaluator_RotateColumns(p: P, encrypted: P, galois_keys: P, destination: P, pool: P) -> c_long;
}

/// The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2).
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub scale: i64,
    pub dim: i64,
    pub weights_scaled: Vec<i64>,
    pub kappa_weights_scaled: Vec<i64>,
    pub budget_scaled: i64,
    pub kappa: f64,
}

/// Full key material (base64 SEAL streams); the key holder keeps `secret_key`.
#[derive(Clone)]
pub struct Keyset {
    pub secret_key: String,
    pub public_key: String,
    pub relin_keys: String,
    pub galois_keys: String,
}

/// What an evaluator is given (no secret key).
#[derive(Clone)]
pub struct EvalKeys {
    pub public_key: String,
    pub relin_keys: String,
    pub galois_keys: String,
}

/// The two encrypted gate outputs (base64 SEAL streams).
#[derive(Clone, Debug)]
pub struct EncryptedGate {
    pub enc_risk_raw: String,
    pub enc_slack: String,
}

/// The opened verdict: `r_scaled` is r at scale S^2 clamped to [0, S^2]; `admit` is slack >= 0.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub r_scaled: i64,
    pub slack: i64,
    pub admit: bool,
}

fn chk(op: &str, hr: c_long) -> Result<(), String> {
    if hr < 0 {
        // SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
        return Err(format!("seal {op} failed: 0x{:08x}", hr as u32));
    }
    Ok(())
}

/// Owns native handles; releases them in reverse order of registration on drop (every exit path, including `?`).
struct Scope(Vec<(Destroy, P)>);

impl Scope {
    fn own(&mut self, p: P, d: Destroy) -> P {
        self.0.push((d, p));
        p
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        while let Some((d, p)) = self.0.pop() {
            if !p.is_null() {
                // SAFETY: p was produced by the matching create call and is destroyed exactly once.
                unsafe { d(p) };
            }
        }
    }
}

struct Ctx {
    context: P,
    encoder: P,
    slots: usize,
}

/// Rejects anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size equal to the
/// length) before SEAL parses it, and returns the raw bytes.
pub fn assert_seal_blob(blob: &str, what: &str) -> Result<Vec<u8>, String> {
    let body = blob.trim_end_matches('=');
    let pad = blob.len() - body.len();
    let alphabet = body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/');
    if blob.len() < 24 || blob.len() % 4 != 0 || pad > 2 || !alphabet {
        return Err(format!("{what}: not a serialized SEAL object (bad encoding)"));
    }
    let b = STANDARD.decode(blob).map_err(|_| format!("{what}: not a serialized SEAL object (bad encoding)"))?;
    if b.len() < 16 || b[0] != 0x5e || b[1] != 0xa1 || b[2] != 16 || b[5] > 2 || b[6] != 0 || b[7] != 0 {
        return Err(format!("{what}: not a serialized SEAL object (bad header)"));
    }
    let size = u64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
    if size != b.len() as u64 {
        return Err(format!("{what}: truncated or padded SEAL object (declared {size} bytes, got {})", b.len()));
    }
    Ok(b)
}

/// Validates a policy that crossed a trust boundary exactly as the policy builder would have produced it.
pub fn require_policy(p: &Policy) -> Result<(), String> {
    if p.scale <= 0 {
        return Err("policy.scale must be a positive integer".into());
    }
    let coeffs = std::iter::once(&p.budget_scaled).chain(&p.weights_scaled).chain(&p.kappa_weights_scaled);
    for v in coeffs {
        if *v <= -SIGNED_BOUND || *v >= SIGNED_BOUND {
            return Err("policy coefficients must be integers with |value| < SIGNED_BOUND".into());
        }
    }
    if p.dim != RISK_DIM as i64 {
        return Err(format!("policy.dim must be {RISK_DIM}"));
    }
    if p.weights_scaled.len() != RISK_DIM || p.kappa_weights_scaled.len() != RISK_DIM {
        return Err(format!("policy weight vectors must have length {RISK_DIM}"));
    }
    Ok(())
}

/// The deterministic BFV context (N=8192, BFVDefault 128-bit coefficient modulus, batching plain modulus of 30 bits).
fn new_ctx(s: &mut Scope) -> Result<Ctx, String> {
    // SAFETY (whole fn): every out-pointer is a live local; every handle passed in was created above and is owned by `s`.
    unsafe {
        let mut parms: P = null_mut();
        chk("EncParams_Create", EncParams_Create1(SCHEME_BFV, &mut parms))?;
        s.own(parms, EncParams_Destroy);
        chk("SetPolyModulusDegree", EncParams_SetPolyModulusDegree(parms, POLY_MODULUS_DEGREE))?;
        let mut n: u64 = 0;
        chk("BFVDefault(length)", CoeffModulus_BFVDefault(POLY_MODULUS_DEGREE, SEC_LEVEL_TC128, &mut n, null_mut()))?;
        if n == 0 || n > 64 {
            return Err(format!("seal BFVDefault reported {n} coefficient moduli"));
        }
        let mut coeffs: Vec<P> = vec![null_mut(); n as usize];
        let hr = CoeffModulus_BFVDefault(POLY_MODULUS_DEGREE, SEC_LEVEL_TC128, &mut n, coeffs.as_mut_ptr());
        for m in &coeffs {
            s.own(*m, Modulus_Destroy); // owned even when the call failed part way (null entries are skipped)
        }
        chk("BFVDefault", hr)?;
        chk("SetCoeffModulus", EncParams_SetCoeffModulus(parms, n, coeffs.as_mut_ptr()))?;
        let mut bits: c_int = PLAIN_MODULUS_BITS;
        let mut plain: P = null_mut();
        chk("PlainModulus.Batching", CoeffModulus_Create1(POLY_MODULUS_DEGREE, 1, &mut bits, &mut plain))?;
        // CoeffModulus_Create1 fills an array of `length` handles; with length 1 that is `plain` itself.
        s.own(plain, Modulus_Destroy);
        let mut live: u64 = 0;
        chk("Modulus_Value", Modulus_Value(plain, &mut live))?;
        if live != PLAIN_MODULUS {
            return Err(format!("plain modulus drift: live {live} != documented {PLAIN_MODULUS}"));
        }
        chk("SetPlainModulus", EncParams_SetPlainModulus1(parms, plain))?;
        let mut context: P = null_mut();
        chk("SEALContext_Create", SEALContext_Create(parms, true, SEC_LEVEL_TC128, &mut context))?;
        s.own(context, SEALContext_Destroy);
        let mut ok = false;
        chk("ParametersSet", SEALContext_ParametersSet(context, &mut ok))?;
        if !ok {
            return Err("SEAL rejected the BFV parameters".into());
        }
        let mut encoder: P = null_mut();
        chk("BatchEncoder_Create", BatchEncoder_Create(context, &mut encoder))?;
        s.own(encoder, BatchEncoder_Destroy);
        let mut sc: u64 = 0;
        chk("SlotCount", BatchEncoder_GetSlotCount(encoder, &mut sc))?;
        if sc == 0 || sc > (1 << 20) {
            return Err(format!("implausible slot count {sc}"));
        }
        Ok(Ctx { context, encoder, slots: sc as usize })
    }
}

fn new_plain(s: &mut Scope) -> Result<P, String> {
    let mut p: P = null_mut();
    // SAFETY: out-pointer is a live local; a null pool selects SEAL's global pool.
    chk("Plaintext_Create", unsafe { Plaintext_Create1(null_mut(), &mut p) })?;
    Ok(s.own(p, Plaintext_Destroy))
}

fn new_cipher(s: &mut Scope) -> Result<P, String> {
    let mut p: P = null_mut();
    // SAFETY: as in new_plain.
    chk("Ciphertext_Create", unsafe { Ciphertext_Create1(null_mut(), &mut p) })?;
    Ok(s.own(p, Ciphertext_Destroy))
}

fn copy_cipher(s: &mut Scope, src: P) -> Result<P, String> {
    let mut p: P = null_mut();
    // SAFETY: src is a live ciphertext handle owned by the caller's scope.
    chk("Ciphertext_Create2", unsafe { Ciphertext_Create2(src, &mut p) })?;
    Ok(s.own(p, Ciphertext_Destroy))
}

fn encode(c: &Ctx, s: &mut Scope, values: &[i64]) -> Result<P, String> {
    if values.len() > c.slots {
        return Err("too many values to encode".into());
    }
    let mut slots = vec![0i64; c.slots];
    slots[..values.len()].copy_from_slice(values);
    let pt = new_plain(s)?;
    // SAFETY: `slots` holds exactly `c.slots` elements, the count passed.
    chk("Encode", unsafe { BatchEncoder_Encode2(c.encoder, slots.len() as u64, slots.as_mut_ptr(), pt) })?;
    Ok(pt)
}

/// Object kinds sharing the save/load plumbing (GaloisKeys and RelinKeys are KSwitchKeys in the C API, as in SEAL.NET).
#[derive(Clone, Copy)]
enum Kind {
    Public,
    Secret,
    Keys,
    Cipher,
}

fn new_obj(s: &mut Scope, k: Kind) -> Result<P, String> {
    let mut p: P = null_mut();
    // SAFETY: out-pointer is a live local.
    let (hr, d): (c_long, Destroy) = unsafe {
        match k {
            Kind::Public => (PublicKey_Create1(&mut p), PublicKey_Destroy as Destroy),
            Kind::Secret => (SecretKey_Create1(&mut p), SecretKey_Destroy as Destroy),
            Kind::Keys => (KSwitchKeys_Create1(&mut p), KSwitchKeys_Destroy as Destroy),
            Kind::Cipher => return new_cipher(s),
        }
    };
    chk("create", hr)?;
    Ok(s.own(p, d))
}

fn load_obj(c: &Ctx, s: &mut Scope, k: Kind, blob: &str, what: &str) -> Result<P, String> {
    let mut raw = assert_seal_blob(blob, what)?;
    let p = new_obj(s, k)?;
    let (inp, sz) = (raw.as_mut_ptr(), raw.len() as u64);
    let mut used: i64 = 0;
    // SAFETY: `raw` is a live buffer of `sz` bytes (>= 16, checked above); p is a fresh object of the matching kind.
    let hr = unsafe {
        match k {
            Kind::Public => PublicKey_Load(p, c.context, inp, sz, &mut used),
            Kind::Secret => SecretKey_Load(p, c.context, inp, sz, &mut used),
            Kind::Keys => KSwitchKeys_Load(p, c.context, inp, sz, &mut used),
            Kind::Cipher => Ciphertext_Load(p, c.context, inp, sz, &mut used),
        }
    };
    chk(&format!("load {what}"), hr)?;
    Ok(p)
}

fn save_obj(k: Kind, p: P, compr: u8) -> Result<String, String> {
    let mut size: i64 = 0;
    // SAFETY: p is a live object of kind k.
    let hr = unsafe {
        match k {
            Kind::Public => PublicKey_SaveSize(p, compr, &mut size),
            Kind::Secret => SecretKey_SaveSize(p, compr, &mut size),
            Kind::Keys => KSwitchKeys_SaveSize(p, compr, &mut size),
            Kind::Cipher => Ciphertext_SaveSize(p, compr, &mut size),
        }
    };
    chk("save size", hr)?;
    if size <= 0 || size > MAX_SAVE {
        return Err(format!("implausible SEAL save size {size}"));
    }
    let mut buf = vec![0u8; size as usize];
    let (out, mut n) = (buf.as_mut_ptr(), 0i64);
    // SAFETY: `buf` is `size` bytes, the capacity passed.
    let hr = unsafe {
        match k {
            Kind::Public => PublicKey_Save(p, out, size as u64, compr, &mut n),
            Kind::Secret => SecretKey_Save(p, out, size as u64, compr, &mut n),
            Kind::Keys => KSwitchKeys_Save(p, out, size as u64, compr, &mut n),
            Kind::Cipher => Ciphertext_Save(p, out, size as u64, compr, &mut n),
        }
    };
    chk("save", hr)?;
    if n < 0 || n > size {
        return Err("SEAL reported more bytes than it was given room for".into());
    }
    Ok(STANDARD.encode(&buf[..n as usize]))
}

/// Generates the key material (the secret key stays with the policy owner).
pub fn keygen() -> Result<Keyset, String> {
    let mut s = Scope(Vec::new());
    let c = new_ctx(&mut s)?;
    // SAFETY: out-pointers are live locals; every handle is owned by `s` right after creation.
    unsafe {
        let (mut kg, mut sk, mut pk, mut rk, mut gk) = (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
        chk("KeyGenerator_Create", KeyGenerator_Create1(c.context, &mut kg))?;
        s.own(kg, KeyGenerator_Destroy);
        chk("SecretKey", KeyGenerator_SecretKey(kg, &mut sk))?;
        s.own(sk, SecretKey_Destroy);
        chk("CreatePublicKey", KeyGenerator_CreatePublicKey(kg, false, &mut pk))?;
        s.own(pk, PublicKey_Destroy);
        chk("CreateRelinKeys", KeyGenerator_CreateRelinKeys(kg, false, &mut rk))?;
        s.own(rk, KSwitchKeys_Destroy);
        chk("CreateGaloisKeys", KeyGenerator_CreateGaloisKeysAll(kg, false, &mut gk))?;
        s.own(gk, KSwitchKeys_Destroy);
        Ok(Keyset {
            secret_key: save_obj(Kind::Secret, sk, COMPR_ZSTD)?,
            public_key: save_obj(Kind::Public, pk, COMPR_ZSTD)?,
            relin_keys: save_obj(Kind::Keys, rk, COMPR_ZSTD)?,
            galois_keys: save_obj(Kind::Keys, gk, COMPR_ZSTD)?,
        })
    }
}

/// BFV-encrypts the quantized risk-input vector (length 6, each a non-negative integer below the signed bound).
pub fn encrypt_risk_inputs(public_key: &str, inputs_scaled: &[i64]) -> Result<String, String> {
    if inputs_scaled.len() != RISK_DIM {
        return Err(format!("inputs_scaled must have length {RISK_DIM}"));
    }
    if inputs_scaled.iter().any(|v| *v < 0 || *v >= SIGNED_BOUND) {
        return Err("each scaled input must be a non-negative integer below the signed bound".into());
    }
    let mut s = Scope(Vec::new());
    let c = new_ctx(&mut s)?;
    let pk = load_obj(&c, &mut s, Kind::Public, public_key, "publicKey")?;
    let mut enc: P = null_mut();
    // SAFETY: context and public key are live; a null secret key selects public-key encryption.
    chk("Encryptor_Create", unsafe { Encryptor_Create(c.context, pk, null_mut(), &mut enc) })?;
    s.own(enc, Encryptor_Destroy);
    let pt = encode(&c, &mut s, inputs_scaled)?;
    let ct = new_cipher(&mut s)?;
    // SAFETY: all handles live in `s`.
    chk("Encrypt", unsafe { Encryptor_Encrypt(enc, pt, ct, null_mut()) })?;
    save_obj(Kind::Cipher, ct, COMPR_ZSTD)
}

/// sumElements for BFV: rotateColumns + add, then rotateRows(steps), rotateColumns, add for steps N/4 .. 1.
fn sum_elements(s: &mut Scope, ev: P, gk: P, prod: P) -> Result<P, String> {
    let temp = copy_cipher(s, prod)?;
    let dest = new_cipher(s)?;
    // SAFETY: every handle is live in `s`; in-place operands (temp, dest) are allowed by SEAL's evaluator.
    unsafe {
        chk("RotateColumns", Evaluator_RotateColumns(ev, temp, gk, dest, null_mut()))?;
        chk("Add", Evaluator_Add(ev, temp, dest, temp))?;
        let mut steps = (POLY_MODULUS_DEGREE / 4) as c_int;
        while steps >= 1 {
            chk("RotateRows", Evaluator_RotateRows(ev, temp, steps, gk, dest, null_mut()))?;
            chk("RotateColumns", Evaluator_RotateColumns(ev, dest, gk, dest, null_mut()))?;
            chk("Add", Evaluator_Add(ev, temp, dest, temp))?;
            steps /= 2;
        }
    }
    Ok(temp)
}

/// Evaluates the gate blind, with the reference's operation order: multiplyPlain, sumElements, negate, addPlain. It never
/// constructs a decryptor.
pub fn eval_risk_gate(keys: &EvalKeys, enc_inputs: &str, policy: &Policy) -> Result<EncryptedGate, String> {
    require_policy(policy)?;
    let mut s = Scope(Vec::new());
    let c = new_ctx(&mut s)?;
    let gk = load_obj(&c, &mut s, Kind::Keys, &keys.galois_keys, "galoisKeys")?;
    let pk = load_obj(&c, &mut s, Kind::Public, &keys.public_key, "publicKey")?;
    let (mut ev, mut enc): (P, P) = (null_mut(), null_mut());
    // SAFETY: context and public key are live; out-pointers are live locals.
    unsafe {
        chk("Evaluator_Create", Evaluator_Create(c.context, &mut ev))?;
        s.own(ev, Evaluator_Destroy);
        chk("Encryptor_Create", Encryptor_Create(c.context, pk, null_mut(), &mut enc))?;
        s.own(enc, Encryptor_Destroy);
    }
    let x = load_obj(&c, &mut s, Kind::Cipher, enc_inputs, "encInputs")?;

    // SEAL refuses multiplyPlain by an all-zero plaintext (transparent result); the dot product is then a fresh encryption of zero.
    let dot = |s: &mut Scope, coeffs: &[i64]| -> Result<P, String> {
        if coeffs.iter().all(|v| *v == 0) {
            let z = encode(&c, s, &[])?;
            let ct = new_cipher(s)?;
            // SAFETY: handles are live in the scope.
            chk("Encrypt", unsafe { Encryptor_Encrypt(enc, z, ct, null_mut()) })?;
            return Ok(ct);
        }
        let pt = encode(&c, s, coeffs)?;
        let prod = new_cipher(s)?;
        // SAFETY: handles are live in the scope.
        chk("MultiplyPlain", unsafe { Evaluator_MultiplyPlain(ev, x, pt, prod, null_mut()) })?;
        sum_elements(s, ev, gk, prod)
    };
    let risk_raw = dot(&mut s, &policy.weights_scaled)?;
    let kappa_risk = dot(&mut s, &policy.kappa_weights_scaled)?;
    let neg = new_cipher(&mut s)?;
    // SAFETY: handles are live in the scope.
    chk("Negate", unsafe { Evaluator_Negate(ev, kappa_risk, neg) })?;
    let budget = encode(&c, &mut s, &[policy.budget_scaled])?;
    let slack = new_cipher(&mut s)?;
    // SAFETY: as above.
    chk("AddPlain", unsafe { Evaluator_AddPlain(ev, neg, budget, slack) })?;
    Ok(EncryptedGate { enc_risk_raw: save_obj(Kind::Cipher, risk_raw, COMPR_ZSTD)?, enc_slack: save_obj(Kind::Cipher, slack, COMPR_ZSTD)? })
}

/// Decrypts the gate outputs and reads the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or
/// foreign ciphertext).
pub fn decrypt_verdict(secret_key: &str, enc_risk_raw: &str, enc_slack: &str, policy: &Policy) -> Result<Verdict, String> {
    require_policy(policy)?;
    let cp = policy.scale.checked_mul(policy.scale).ok_or("policy.scale is too large")?;
    let mut s = Scope(Vec::new());
    let c = new_ctx(&mut s)?;
    let sk = load_obj(&c, &mut s, Kind::Secret, secret_key, "secretKey")?;
    let mut dec: P = null_mut();
    // SAFETY: context and secret key are live.
    chk("Decryptor_Create", unsafe { Decryptor_Create(c.context, sk, &mut dec) })?;
    s.own(dec, Decryptor_Destroy);
    let ct_r = load_obj(&c, &mut s, Kind::Cipher, enc_risk_raw, "encRiskRaw")?;
    let ct_s = load_obj(&c, &mut s, Kind::Cipher, enc_slack, "encSlack")?;
    for ct in [ct_r, ct_s] {
        let mut nb: c_int = 0;
        // SAFETY: both handles are live.
        chk("InvariantNoiseBudget", unsafe { Decryptor_InvariantNoiseBudget(dec, ct, &mut nb) })?;
        if nb < MIN_NOISE_BUDGET_BITS {
            return Err("decrypt_verdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)".into());
        }
    }
    let mut first = |ct: P| -> Result<i64, String> {
        let pt = new_plain(&mut s)?;
        // SAFETY: handles are live in the scope; the decode buffer has exactly the slot count SEAL reported.
        unsafe {
            chk("Decrypt", Decryptor_Decrypt(dec, ct, pt))?;
            // SEAL's C export refuses a null destination, so the buffer is sized from the slot count the context reported (the
            // decode always yields exactly that many) and the count SEAL writes back is checked against it
            let mut out = vec![0i64; c.slots];
            let mut n: u64 = c.slots as u64;
            chk("Decode", BatchEncoder_Decode2(c.encoder, pt, &mut n, out.as_mut_ptr(), null_mut()))?;
            if n as usize != c.slots {
                return Err("decode returned an unexpected slot count".into());
            }
            Ok(out[0])
        }
    };
    let raw = first(ct_r)?;
    let slack = first(ct_s)?;
    Ok(Verdict { r_scaled: raw.clamp(0, cp), slack, admit: slack >= 0 })
}

/// Re-saves a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build.
pub fn canonical_cipher(blob: &str) -> Result<String, String> {
    let mut s = Scope(Vec::new());
    let c = new_ctx(&mut s)?;
    let ct = load_obj(&c, &mut s, Kind::Cipher, blob, "ciphertext")?;
    save_obj(Kind::Cipher, ct, COMPR_NONE)
}

// ---- the signed-claim path ------------------------------------------------------------------------------------------------------

/// A gate policy that crossed a trust boundary as JSON (`{scale, dim, weightsScaled, kappaWeightsScaled, budgetScaled, kappa}`),
/// validated by [`require_policy`]. `None` when a member is missing or not a number.
pub fn policy_from_value(v: &serde_json::Value) -> Option<Policy> {
    let int = |k: &str| v.get(k).and_then(serde_json::Value::as_f64).filter(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).map(|f| f as i64);
    let ints = |k: &str| v.get(k)?.as_array()?.iter().map(|x| x.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).map(|f| f as i64)).collect::<Option<Vec<i64>>>();
    let p = Policy { scale: int("scale")?, dim: int("dim")?, weights_scaled: ints("weightsScaled")?, kappa_weights_scaled: ints("kappaWeightsScaled")?, budget_scaled: int("budgetScaled")?, kappa: v.get("kappa")?.as_f64()? };
    require_policy(&p).ok().map(|_| p)
}

/// `evalSignedRiskClaim`: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the signature, signer,
/// context, binding, policy and nonce all check out. Returns `{ok: true, gate: {encRiskRaw, encSlack}, claimDigest}` or
/// `{ok: false, reason}`. The unsigned [`eval_risk_gate`] stays a low-level primitive; the PCA claim path has no unsigned entry.
pub fn eval_signed_risk_claim(keys: &EvalKeys, signed: &serde_json::Value, exp: &mut crate::fhe::ClaimExpectations<'_>) -> serde_json::Value {
    use serde_json::json;
    let chk = crate::fhe::verify_signed_risk_claim(signed, exp);
    if chk["ok"] != true {
        return chk;
    }
    let claim = &chk["claim"];
    let (Some(enc), Some(policy)) = (claim["encInputs"].as_str(), policy_from_value(&claim["policy"])) else {
        return json!({"ok": false, "reason": "evaluation failed: the signed policy is not a valid gate policy"});
    };
    match eval_risk_gate(keys, enc, &policy) {
        Ok(g) => json!({"ok": true, "gate": {"encRiskRaw": g.enc_risk_raw, "encSlack": g.enc_slack}, "claimDigest": chk["digest"]}),
        Err(e) => json!({"ok": false, "reason": format!("evaluation failed: {e}")}),
    }
}
