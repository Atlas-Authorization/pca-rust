//! FN-DSA suite registry, wire framing, leaf binding and hybrid composition (`@atlasauth/pca-fndsa`).
//!
//! The Falcon math itself is not in this module: it sits behind [`FalconBackend`], exactly as in the reference (whose wasm backend
//! wraps the same `fn-dsa-vrfy` this crate links). [`NativeBackend`] is that vetted verifier (FIPS 206 DOMAIN_NONE + HASH_ID_RAW,
//! the `pq_verify` the core uses); [`MockBackend`] is the reference's deterministic hash-derived test double, which is what the
//! differential corpus runs through. What is real and tested here: the four-suite registry, exact padded-length enforcement BEFORE
//! the backend is reached, the domain-separated leaf message, pure and hybrid (Ed25519 + FN-DSA, BOTH required) signing and
//! verification, and the KAT table precedence.
//!
//! shortcut: the backend is passed explicitly (the reference keeps a process-global one), so there is no `setFalconBackend`;
//! signing with real keys goes through the agent side (`PqKeyPair`, feature `fndsa-sign`), not through this seam.
use crate::{b64_encode, decode_b64u_strict, pq_verify, sha, threshold_message, verify_b64u, Pq};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const FN_DSA_512_PUBLIC_KEY_BYTES: usize = 897;
pub const FN_DSA_512_SIGNATURE_BYTES: usize = 666;
pub const FN_DSA_1024_PUBLIC_KEY_BYTES: usize = 1793;
pub const FN_DSA_1024_SIGNATURE_BYTES: usize = 1280;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const FN_DSA_LEAF_DOMAIN: &[u8] = b"atlas-pca/fn-dsa/leaf/v1\0";
pub const NO_FN_DSA_BACKEND_MESSAGE: &str = "no FN-DSA backend registered: supply a backend (NativeBackend verifies)";
const VERIFY_ONLY_MESSAGE: &str = "fndsaSign: FN-DSA backend is verify-only (no sign())";
const MOCK_SK_TAG: &[u8] = b"atlas-pca/fn-dsa/mock-sk/v1\0";

/// One suite's wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FnDsaSuite {
    pub alg: &'static str,
    pub variant: &'static str,
    pub has_ed25519: bool,
    pub sig_bytes: usize,
    pub needs_pq_pk: bool,
    pub pq_pk_bytes: usize,
    pub needs_pq_sig: bool,
    pub pq_sig_bytes: usize,
    pub fn_sig_bytes: usize,
}

impl FnDsaSuite {
    /// The reference's object form (camelCase members).
    pub fn to_json(&self) -> Value {
        json!({
            "alg": self.alg, "variant": self.variant, "hasEd25519": self.has_ed25519, "sigBytes": self.sig_bytes, "needsPqPk": self.needs_pq_pk,
            "pqPkBytes": self.pq_pk_bytes, "needsPqSig": self.needs_pq_sig, "pqSigBytes": self.pq_sig_bytes, "fnSigBytes": self.fn_sig_bytes,
        })
    }
}

const fn pure(alg: &'static str, pk: usize, sig: usize) -> FnDsaSuite {
    FnDsaSuite {
        alg,
        variant: alg,
        has_ed25519: false,
        sig_bytes: sig,
        needs_pq_pk: true,
        pq_pk_bytes: pk,
        needs_pq_sig: false,
        pq_sig_bytes: 0,
        fn_sig_bytes: sig,
    }
}

const fn hybrid(alg: &'static str, variant: &'static str, pk: usize, sig: usize) -> FnDsaSuite {
    FnDsaSuite {
        alg,
        variant,
        has_ed25519: true,
        sig_bytes: ED25519_SIGNATURE_BYTES,
        needs_pq_pk: true,
        pq_pk_bytes: pk,
        needs_pq_sig: true,
        pq_sig_bytes: sig,
        fn_sig_bytes: sig,
    }
}

/// The closed registry.
pub const FN_DSA_SUITES: [FnDsaSuite; 4] = [
    pure("fn-dsa-512", FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES),
    pure("fn-dsa-1024", FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES),
    hybrid("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES),
    hybrid("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES),
];

/// The suite for an exact registered id; `None` (fail closed) for an unknown name or a non-string.
pub fn resolve_fndsa_alg(alg: &Value) -> Option<FnDsaSuite> {
    let a = alg.as_str()?;
    FN_DSA_SUITES.iter().find(|s| s.alg == a).copied()
}

pub fn is_known_fndsa_alg(x: &Value) -> bool {
    resolve_fndsa_alg(x).is_some()
}

pub fn is_fndsa_variant(v: &Value) -> bool {
    matches!(v.as_str(), Some("fn-dsa-512" | "fn-dsa-1024"))
}

fn variant_sizes(variant: &str) -> Option<(usize, usize)> {
    match variant {
        "fn-dsa-512" => Some((FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES)),
        "fn-dsa-1024" => Some((FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES)),
        _ => None,
    }
}

// ---- the backend seam ------------------------------------------------------------------------------------------------

/// The FN-DSA primitive. `verify` must return `Ok(false)` (not `Err`) for a bad signature; an `Err` is a backend fault and is
/// never swallowed. `sign` is optional: the default is a verify-only backend.
pub trait FalconBackend {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String>;
    fn sign(&self, _sk: &[u8], _msg: &[u8]) -> Result<Vec<u8>, String> {
        Err(VERIFY_ONLY_MESSAGE.to_string())
    }
}

/// The default of the reference: every use fails loudly.
pub struct NoBackend;

impl FalconBackend for NoBackend {
    fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool, String> {
        Err(NO_FN_DSA_BACKEND_MESSAGE.to_string())
    }
    fn sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Err(NO_FN_DSA_BACKEND_MESSAGE.to_string())
    }
}

/// The vetted verifier (`fn-dsa-vrfy`, the primitive of the core's `fn-dsa-*` suites); the variant follows the key length.
/// Verify-only.
pub struct NativeBackend;

impl FalconBackend for NativeBackend {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        let p = match pk.len() {
            FN_DSA_512_PUBLIC_KEY_BYTES => Pq::FnDsa512,
            FN_DSA_1024_PUBLIC_KEY_BYTES => Pq::FnDsa1024,
            _ => return Ok(false),
        };
        Ok(pq_verify(p, pk, msg, sig))
    }
}

/// SHA-256 counter-mode stretch of `seed` to exactly `out_len` bytes: the mock / KAT derivation function (NOT Falcon).
pub fn hash_kat(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut block_in = seed.to_vec();
        block_in.extend_from_slice(&counter.to_be_bytes());
        let block = sha(&block_in);
        let take = block.len().min(out_len - out.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// A deterministic MOCK key pair `(pk, sk)` for a variant (NOT real Falcon keys): `pk` is a stretch of `variant/ + seed` to the
/// variant's key size and `sk` is the mock tag followed by `pk`. Err for an unknown variant.
pub fn mock_keypair(variant: &str, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk_len, _) = variant_sizes(variant).ok_or_else(|| format!("mockKeypair: unknown FN-DSA variant '{variant}'"))?;
    let mut input = format!("{variant}/").into_bytes();
    input.extend_from_slice(seed);
    let pk = hash_kat(&input, pk_len);
    let mut sk = MOCK_SK_TAG.to_vec();
    sk.extend_from_slice(&pk);
    Ok((pk, sk))
}

fn derive_mock_sig(pk: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let sig_len = match pk.len() {
        FN_DSA_512_PUBLIC_KEY_BYTES => FN_DSA_512_SIGNATURE_BYTES,
        FN_DSA_1024_PUBLIC_KEY_BYTES => FN_DSA_1024_SIGNATURE_BYTES,
        _ => return None,
    };
    let mut input = b"fn-dsa/mock-sig/v1\0".to_vec();
    input.extend_from_slice(pk);
    input.extend_from_slice(msg);
    Some(hash_kat(&input, sig_len))
}

/// The reference's deterministic test double: explicit `(pk, msg) -> sig` vectors take precedence, otherwise a reproducible
/// hash-derived signature, so sign and verify round-trip. A TEST double: never use it where a real verifier belongs.
#[derive(Default)]
pub struct MockBackend {
    table: HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
}

impl MockBackend {
    pub fn new(vectors: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> MockBackend {
        MockBackend { table: vectors.iter().map(|(pk, msg, sig)| ((pk.clone(), msg.clone()), sig.clone())).collect() }
    }
}

impl FalconBackend for MockBackend {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        let expected = match self.table.get(&(pk.to_vec(), msg.to_vec())) {
            Some(s) => Some(s.clone()),
            None => derive_mock_sig(pk, msg),
        };
        Ok(expected.is_some_and(|e| ct_eq(sig, &e)))
    }
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let pk = match sk.strip_prefix(MOCK_SK_TAG) {
            Some(pk) if !pk.is_empty() => pk,
            _ => return Err("mock FN-DSA backend: secret key was not minted by mockKeypair()".into()),
        };
        if let Some(s) = self.table.get(&(pk.to_vec(), msg.to_vec())) {
            return Ok(s.clone());
        }
        derive_mock_sig(pk, msg).ok_or_else(|| "mock FN-DSA backend: public key length matches no FN-DSA variant".to_string())
    }
}

/// Constant-time byte equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

// ---- primitive wrappers ----------------------------------------------------------------------------------------------

/// FN-DSA sign through `backend`. Err on an unknown variant, an empty `sk`, a verify-only backend, a backend fault, or a signature
/// that is not exactly the variant's padded length.
pub fn fndsa_sign(backend: &dyn FalconBackend, variant: &str, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let (_, sig_len) = variant_sizes(variant).ok_or_else(|| format!("fndsaSign: unknown FN-DSA variant '{variant}'"))?;
    if sk.is_empty() {
        return Err("fndsaSign: secret key must be a non-empty Uint8Array".into());
    }
    let sig = backend.sign(sk, msg)?;
    if sig.len() != sig_len {
        return Err(format!("fndsaSign: FN-DSA backend returned a {} signature; expected padded {sig_len} bytes for '{variant}'", sig.len()));
    }
    Ok(sig)
}

/// FN-DSA verify. The key and signature LENGTHS are enforced here, BEFORE the backend is reached (a wrong length is `Ok(false)`);
/// a backend fault is an `Err`.
pub fn fndsa_verify(backend: &dyn FalconBackend, variant: &str, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    match variant_sizes(variant) {
        Some((pk_len, sig_len)) if pk.len() == pk_len && sig.len() == sig_len => backend.verify(pk, msg, sig),
        _ => Ok(false),
    }
}

// ---- PCA leaf framing ------------------------------------------------------------------------------------------------

/// The exact bytes a leaf / hop signature covers: `thresholdMessage(leaf) || "atlas-pca/fn-dsa/leaf/v1\0" || alg || 0x00 ||
/// pq_pk(b64u text)`, binding the suite and the PQ key (a downgrade or key swap changes the signed bytes).
pub fn fndsa_leaf_message(leaf: &Value, alg: &str, pq_pk_b64u: &str) -> Result<Vec<u8>, String> {
    let mut out = threshold_message(leaf.as_object().ok_or("fndsaLeafMessage: leaf must be an object")?)?;
    out.extend_from_slice(FN_DSA_LEAF_DOMAIN);
    out.extend_from_slice(alg.as_bytes());
    out.push(0);
    out.extend_from_slice(pq_pk_b64u.as_bytes());
    Ok(out)
}

/// Inputs of [`sign_pca_with_fndsa`]; a `None` key is a missing or mistyped one (the reference throws).
pub struct SignPcaInput<'a> {
    pub alg: &'a Value,
    pub leaf: &'a Value,
    pub pk: Option<&'a [u8]>,
    pub sk: Option<&'a [u8]>,
    /// Ed25519 leaf-holder seed (32 bytes): required for a `hybrid-*` suite, ignored for a pure one.
    pub ed_secret: Option<&'a [u8]>,
}

/// `{sig, alg, pq_pk, pq_sig?}`: pure => `sig` is the FN-DSA signature; hybrid => `sig` is Ed25519 and `pq_sig` the FN-DSA one,
/// both over the same leaf message. Fails closed on an unknown suite, a wrong-length key, no secret material, a hybrid suite with
/// no 32-byte Ed25519 seed, or a missing / limited backend.
pub fn sign_pca_with_fndsa(backend: &dyn FalconBackend, input: &SignPcaInput) -> Result<Value, String> {
    let suite = resolve_fndsa_alg(input.alg).ok_or("signPcaWithFndsa: unknown FN-DSA alg")?;
    let pk = input
        .pk
        .filter(|p| p.len() == suite.pq_pk_bytes)
        .ok_or_else(|| format!("signPcaWithFndsa: '{}' requires a {}-byte FN-DSA public key", suite.alg, suite.pq_pk_bytes))?;
    let sk = input.sk.filter(|s| !s.is_empty()).ok_or_else(|| format!("signPcaWithFndsa: '{}' requires FN-DSA secret-key material", suite.alg))?;
    let pq_pk = b64_encode(pk);
    let msg = fndsa_leaf_message(input.leaf, suite.alg, &pq_pk)?;
    let fn_sig = b64_encode(&fndsa_sign(backend, suite.variant, sk, &msg)?);
    if !suite.has_ed25519 {
        return Ok(json!({ "sig": fn_sig, "alg": suite.alg, "pq_pk": pq_pk }));
    }
    let seed: [u8; 32] = input
        .ed_secret
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| format!("signPcaWithFndsa: '{}' requires edSecret (a 32-byte Ed25519 leaf-holder seed)", suite.alg))?;
    let ed_sig = SigningKey::from_bytes(&seed).sign(&msg).to_bytes();
    Ok(json!({ "sig": b64_encode(&ed_sig), "alg": suite.alg, "pq_pk": pq_pk, "pq_sig": fn_sig }))
}

/// Verify an FN-DSA leaf / hop signature. `input` carries `alg`, `leaf`, `pq_pk`, `sig` and (hybrid) `holder` and `pq_sig`, all
/// untrusted. Fail closed: an unknown suite, a missing / mistyped / wrong-length / non-canonical field, a tampered leaf or a
/// downgraded suite or key is `Ok(false)`; a hybrid needs BOTH the Ed25519 and the FN-DSA half. A backend fault is an `Err`.
pub fn verify_pca_fndsa(backend: &dyn FalconBackend, input: &Value) -> Result<bool, String> {
    let get = |k: &str| input.as_object().and_then(|m| m.get(k));
    let Some(suite) = resolve_fndsa_alg(get("alg").unwrap_or(&Value::Null)) else { return Ok(false) };
    let Some(pq_pk) = get("pq_pk").and_then(Value::as_str) else { return Ok(false) };
    let Some(pk) = decode_b64u_strict(pq_pk, Some(suite.pq_pk_bytes)) else { return Ok(false) };
    let msg = fndsa_leaf_message(get("leaf").unwrap_or(&Value::Null), suite.alg, pq_pk)?;
    if !suite.has_ed25519 {
        let Some(sig) = get("sig").and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, Some(suite.sig_bytes))) else { return Ok(false) };
        return fndsa_verify(backend, suite.variant, &pk, &msg, &sig);
    }
    let (Some(holder), Some(sig)) = (get("holder").and_then(Value::as_str), get("sig").and_then(Value::as_str)) else { return Ok(false) };
    if decode_b64u_strict(sig, Some(suite.sig_bytes)).is_none() {
        return Ok(false);
    }
    let ed_ok = verify_b64u(holder, &msg, sig);
    let Some(fn_sig) = get("pq_sig").and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, Some(suite.pq_sig_bytes))) else { return Ok(false) };
    let pq_ok = fndsa_verify(backend, suite.variant, &pk, &msg, &fn_sig)?;
    Ok(ed_ok && pq_ok)
}
