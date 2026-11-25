//! Host C ABI (cargo feature "capi", libpcazk): caller-owned input buffers, library-owned output buffers released with
//! `pca_zk_free`, no global state (thread-safe), no panic crosses the boundary (a panic becomes PCA_ZK_ERR_INTERNAL). See pca_zk.h.
use crate::prove::{prove, ProveKind};
use crate::verify::{verify, verify_snarkjs, Curve, Reason, FLAG_SNARKJS_COMPAT};
use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const PCA_ZK_VALID: i32 = 1;
pub const PCA_ZK_INVALID: i32 = 0;
pub const PCA_ZK_OK: i32 = 0;
/// `curve` of `pca_zk_verify` only, and only with the compat flag: the curve is the one the key names.
pub const PCA_ZK_CURVE_FROM_KEY: i32 = 2;
pub const PCA_ZK_ERR_ARG: i32 = -1;
pub const PCA_ZK_ERR_INTERNAL: i32 = -2;
pub const PCA_ZK_ERR_PROVE: i32 = -3;
pub const PCA_ZK_ERR_WITNESS: i32 = -4;
pub const PCA_ZK_ERR_ZKEY: i32 = -5;
pub const PCA_ZK_ERR_INPUT: i32 = -6;

static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

unsafe fn rd<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(p, len))
}

/// The library version, a static NUL-terminated string.
#[no_mangle]
pub extern "C" fn pca_zk_version() -> *const c_char {
    VERSION_C.as_ptr().cast()
}

/// A static NUL-terminated description of a verification reason code (see PCA_ZK_REASON_*); "unknown" for any other value.
#[no_mangle]
pub extern "C" fn pca_zk_reason_text(reason: i32) -> *const c_char {
    const T: [&str; 11] = [
        "ok\0",
        "input is not valid JSON\0",
        "protocol is not groth16\0",
        "curve is missing, unknown or does not match\0",
        "field element is not a canonical decimal below the modulus\0",
        "point is not on the curve or not in the prime-order subgroup\0",
        "point is not affine (z is not 1)\0",
        "a field is missing or has the wrong shape\0",
        "public signal count does not match the key\0",
        "key has fewer IC entries than signals + 1\0",
        "pairing equation does not hold\0",
    ];
    match usize::try_from(reason).ok().and_then(|i| T.get(i)) {
        Some(s) => s.as_ptr().cast(),
        None => "unknown\0".as_ptr().cast(),
    }
}

/// Releases a buffer returned by `pca_zk_prove` (pointer and length exactly as returned). A null pointer is ignored.
///
/// # Safety
/// `ptr`/`len` must be a buffer returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn pca_zk_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// Groth16 verification. Returns 1 valid, 0 invalid (`*reason` says why), negative on refused arguments (nothing is read).
/// `reason` may be NULL. `flags` bit 0 = PCA_ZK_FLAG_SNARKJS_COMPAT; other bits must be 0. `curve` may be PCA_ZK_CURVE_FROM_KEY
/// with the compat flag (the key's own curve name decides, read as snarkjs reads it); without the flag that is a refused argument.
///
/// # Safety
/// Every pointer must be valid for its length (a zero length may use any non-null pointer).
#[no_mangle]
pub unsafe extern "C" fn pca_zk_verify(
    curve: i32,
    flags: u32,
    vkey: *const u8,
    vkey_len: usize,
    proof: *const u8,
    proof_len: usize,
    signals: *const u8,
    signals_len: usize,
    reason: *mut i32,
) -> i32 {
    let set = |r: Reason| {
        if !reason.is_null() {
            *reason = r as i32;
        }
    };
    let from_key = curve == PCA_ZK_CURVE_FROM_KEY && flags == FLAG_SNARKJS_COMPAT;
    let c = Curve::from_code(curve);
    if !(from_key || c.is_some()) || flags & !FLAG_SNARKJS_COMPAT != 0 {
        return PCA_ZK_ERR_ARG;
    }
    let (Some(v), Some(p), Some(s)) = (rd(vkey, vkey_len), rd(proof, proof_len), rd(signals, signals_len)) else {
        return PCA_ZK_ERR_ARG;
    };
    let run = || match c {
        Some(c) => verify(c, flags, v, p, s),
        None => verify_snarkjs(v, p, s),
    };
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(())) => {
            set(Reason::Ok);
            PCA_ZK_VALID
        }
        Ok(Err(e)) => {
            set(e.reason);
            PCA_ZK_INVALID
        }
        Err(_) => PCA_ZK_ERR_INTERNAL,
    }
}

/// Groth16 proving from a circom witness wasm and a snarkjs zkey. On return 0, `*out`/`*out_len` hold the UTF-8 JSON
/// `{"proof":...,"publicSignals":[...]}`; on any other return except PCA_ZK_ERR_ARG they hold a UTF-8 error message. Either way the
/// buffer is the library's and is released with `pca_zk_free`. `seed` is 32 bytes making the blinding deterministic (tests
/// only), or NULL (with seed_len 0) for operating-system randomness: production callers pass NULL.
///
/// # Safety
/// Every input pointer must be valid for its length; `out` and `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn pca_zk_prove(
    curve: i32,
    wasm: *const u8,
    wasm_len: usize,
    zkey: *const u8,
    zkey_len: usize,
    input: *const u8,
    input_len: usize,
    seed: *const u8,
    seed_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() {
        return PCA_ZK_ERR_ARG;
    }
    *out = std::ptr::null_mut();
    *out_len = 0;
    let Some(c) = Curve::from_code(curve) else { return PCA_ZK_ERR_ARG };
    let (Some(w), Some(z), Some(i)) = (rd(wasm, wasm_len), rd(zkey, zkey_len), rd(input, input_len)) else {
        return PCA_ZK_ERR_ARG;
    };
    let seed = if seed.is_null() {
        if seed_len != 0 {
            return PCA_ZK_ERR_ARG;
        }
        None
    } else if seed_len == 32 {
        Some(<[u8; 32]>::try_from(std::slice::from_raw_parts(seed, 32)).expect("32 bytes"))
    } else {
        return PCA_ZK_ERR_ARG;
    };
    let (rc, bytes) = match catch_unwind(AssertUnwindSafe(|| prove(c, w, z, i, seed))) {
        Ok(Ok(json)) => (PCA_ZK_OK, json.into_bytes()),
        Ok(Err(e)) => (
            match e.kind {
                ProveKind::Input => PCA_ZK_ERR_INPUT,
                ProveKind::Witness => PCA_ZK_ERR_WITNESS,
                ProveKind::Zkey => PCA_ZK_ERR_ZKEY,
                ProveKind::Prove => PCA_ZK_ERR_PROVE,
            },
            e.msg.into_bytes(),
        ),
        Err(_) => (PCA_ZK_ERR_INTERNAL, b"internal error (panic)".to_vec()),
    };
    let b = bytes.into_boxed_slice();
    *out_len = b.len();
    *out = Box::into_raw(b).cast::<u8>();
    rc
}
