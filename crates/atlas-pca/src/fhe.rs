//! The pure, scheme-independent parts of the homomorphic risk gate (`@atlasauth/pca-fhe`): risk-input transformation and
//! fixed-point quantization, the public gate policy, the risk-claim binding read from a signed action, the plaintext reference
//! verdict, and the origin layer (signed claims, replay guard, verdict attestation). JSON-valued: inputs are
//! [`serde_json::Value`]s, a non-number is NaN (the fail-closed worst case), and a reference throw is an `Err`.
//!
//! NOT here: the BFV evaluation itself (key generation, encryption of the risk inputs, the homomorphic weighted sum and slack,
//! decryption of the verdict). The reference runs it on Microsoft SEAL; there is no vetted Rust binding for SEAL, and a lattice
//! scheme on another library would not interoperate with the reference's ciphertexts, so no RLWE/NTT kernel is written here.
//! The signed-claim layer is scheme independent: this verifier can check a claim produced by the reference and attest a
//! verdict over a ciphertext it never opens.
//!
//! shortcut: a context or claim holding a lone UTF-16 surrogate cannot be represented by a Rust string; a claim member that is
//! missing where the reference would serialize `undefined` is refused (`Err`) rather than silently dropped.
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, hash_canonical_strict, sha, verify_ed25519_strict};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Number, Value};
use std::collections::HashSet;

pub const POLY_MODULUS_DEGREE: u32 = 8192;
pub const PLAIN_MODULUS_BITS: u32 = 30;
pub const PLAIN_MODULUS: u64 = 1_073_692_673;
pub const SIGNED_BOUND: u64 = PLAIN_MODULUS / 2;
pub const DEFAULT_SCALE: f64 = 1000.0;
pub const RISK_DIM: usize = 6;

const INPUT_FIELDS: [&str; 6] = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"];
const CLAIM_DOMAIN: &str = "atlas-pca-fhe/signed-claim/v1\0";
const VERDICT_DOMAIN: &str = "atlas-pca-fhe/verdict-attestation/v1\0";
const NONCE_BYTES: usize = 16;
const MAX_CONTEXT_LEN: usize = 512;

// ---- JS number helpers -----------------------------------------------------------------------------------------------

/// A JSON number as f64; anything else is NaN (so `Number.isFinite` is false for it).
fn num_of(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

/// A number as the JSON value the reference would serialize; a non-finite number has no JSON form and is refused.
fn jnum(f: f64) -> Result<Value, String> {
    if !f.is_finite() {
        return Err("non-finite number".into());
    }
    if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_992.0 {
        return Ok(Value::from(f as i64));
    }
    Number::from_f64(f).map(Value::Number).ok_or_else(|| "non-finite number".into())
}

fn numbers(a: &[f64]) -> Result<Value, String> {
    a.iter().map(|f| jnum(*f)).collect::<Result<Vec<_>, _>>().map(Value::Array)
}

/// The JSON array of a float vector (as the reference serializes it); `Err` on a non-finite entry.
pub fn numbers_json(a: &[f64]) -> Result<Value, String> {
    numbers(a)
}

/// JavaScript `Math.round` (ties toward +infinity).
fn js_round(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn clamp01(x: f64) -> f64 {
    if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

fn unit(x: f64, worst: f64) -> f64 {
    if x.is_finite() {
        clamp01(x)
    } else {
        worst
    }
}

fn wt(x: f64) -> f64 {
    if x.is_finite() && x > 0.0 {
        x
    } else {
        0.0
    }
}

/// Member `k` of `v` as a number: reading a member of null/undefined throws in the reference; a non-object has no such member.
fn field(v: Option<&Value>, k: &str) -> Result<f64, String> {
    match v {
        None | Some(Value::Null) => Err("cannot read a member of null or undefined".into()),
        Some(Value::Object(m)) => Ok(m.get(k).map(num_of).unwrap_or(f64::NAN)),
        Some(_) => Ok(f64::NAN),
    }
}

fn require_scale(s: f64) -> Result<(), String> {
    if !s.is_finite() || s != s.trunc() || s <= 0.0 {
        return Err("scale must be a positive integer".into());
    }
    Ok(())
}

// ---- quantization / policy ---------------------------------------------------------------------------------------------

/// `[d, 1 - rev, bl, taint, 1 - conf, age]`, each through `unit` with the worst case of the risk score.
pub fn transformed_inputs(inputs: &Value) -> Result<Vec<f64>, String> {
    let f = |k: &str| field(Some(inputs), k);
    Ok(vec![
        unit(f(INPUT_FIELDS[0])?, 1.0),
        1.0 - unit(f(INPUT_FIELDS[1])?, 0.0),
        unit(f(INPUT_FIELDS[2])?, 1.0),
        unit(f(INPUT_FIELDS[3])?, 1.0),
        1.0 - unit(f(INPUT_FIELDS[4])?, 0.0),
        unit(f(INPUT_FIELDS[5])?, 1.0),
    ])
}

fn weight_vector_of(w: Option<&Value>) -> Result<Vec<f64>, String> {
    ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"].iter().map(|k| field(w, k).map(wt)).collect()
}

/// The weight vector of the risk score in canonical order with its clamp applied.
pub fn weight_vector(w: &Value) -> Result<Vec<f64>, String> {
    weight_vector_of(Some(w))
}

/// `round(x_i * scale)` for each transformed input: the integer vector the agent encrypts.
pub fn quantize_risk_inputs(inputs: &Value, scale: f64) -> Result<Vec<f64>, String> {
    require_scale(scale)?;
    Ok(transformed_inputs(inputs)?.into_iter().map(|x| js_round(x * scale)).collect())
}

/// The public gate policy from a risk policy `{weights, kappa}` and the trust budget B at fixed-point scale S: weights
/// `round(w_i S)`, kappa-weighted weights `round(kappa w_i S)`, budget `round(B S^2)`. Refuses a policy whose scaled values
/// could overflow the signed plain-modulus range (a wrap would silently corrupt the verdict).
pub fn fhe_risk_policy(core: &Value, budget: &Value, scale: f64) -> Result<Value, String> {
    require_scale(scale)?;
    let b = num_of(budget);
    if !(b.is_finite() && b >= 0.0) {
        return Err("budget must be finite and >= 0".into());
    }
    let kappa = field(Some(core), "kappa")?;
    if !(kappa.is_finite() && kappa > 0.0) {
        return Err("policy.kappa must be finite and > 0".into());
    }
    let w = weight_vector_of(core.get("weights"))?;
    let ws: Vec<f64> = w.iter().map(|v| js_round(v * scale)).collect();
    let kws: Vec<f64> = w.iter().map(|v| js_round(kappa * v * scale)).collect();
    let budget_scaled = js_round(b * scale * scale);
    let (sum_w, sum_k): (f64, f64) = (ws.iter().sum(), kws.iter().sum());
    let bound = SIGNED_BOUND as f64;
    if sum_w * scale >= bound || sum_k * scale >= bound || budget_scaled >= bound {
        return Err("policy/scale overflow the plain modulus: lower the scale or the weights/budget".into());
    }
    Ok(json!({
        "scale": jnum(scale)?, "dim": RISK_DIM, "weightsScaled": numbers(&ws)?, "kappaWeightsScaled": numbers(&kws)?,
        "budgetScaled": jnum(budget_scaled)?, "kappa": jnum(kappa)?,
    }))
}

/// The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is left out (non-finite when
/// read, so the transform maps it to its fail-closed worst case).
pub fn risk_inputs_from_pcactn(p: &Value) -> Result<Value, String> {
    let rc = p.get("risk_claim").filter(|v| !v.is_null()).ok_or("cannot read inputs of an action without a risk claim")?;
    let src = rc.get("inputs").filter(|v| !v.is_null()).ok_or("cannot read a member of null or undefined")?;
    let mut out = Map::new();
    for k in INPUT_FIELDS {
        if let Some(v @ Value::Number(_)) = src.get(k) {
            out.insert(k.to_string(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// The replay binding of a signed action: audience, action digest (`actionRef`), counter and the optional nonce.
pub fn binding_from_pcactn(p: &Value) -> Result<Value, String> {
    let act = p.get("action").filter(|v| !v.is_null()).ok_or("cannot read params_digest of an action without an action")?;
    let mut out = Map::new();
    for (to, from, src) in [("aud", "aud", p), ("actionRef", "params_digest", act), ("counter", "counter", p), ("nonce", "nonce", p)] {
        if let Some(v) = src.get(from) {
            out.insert(to.to_string(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// The plaintext reference verdict `{r, admit}`: `r` the risk score, admit iff `kappa * r <= budget`.
pub fn plaintext_verdict(inputs: &Value, core: &Value, budget: &Value) -> Result<Value, String> {
    if core.is_null() {
        return Err("cannot read a member of null or undefined".into());
    }
    let w = weight_vector_of(core.get("weights"))?;
    let t = transformed_inputs(inputs)?;
    let mut sum = 0.0;
    for i in 0..w.len() {
        sum += w[i] * t[i];
    }
    let r = clamp01(sum);
    let kappa = core.get("kappa").map(num_of).unwrap_or(f64::NAN);
    let k = if kappa.is_finite() && kappa > 0.0 { kappa } else { 0.0 };
    let cost = k * clamp01(r);
    Ok(json!({ "r": jnum(r)?, "admit": num_of(budget).is_finite() && cost <= num_of(budget) }))
}

// ---- origin: signed claims, replay guard, verdict attestation -----------------------------------------------------------

fn bytes_digest(s: &str) -> String {
    b64_encode(&sha(s.as_bytes()))
}

fn prefixed(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    let c = canonicalize_strict(body)?;
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(c.as_bytes());
    Ok(m)
}

fn claim_statement(claim: &Map<String, Value>, context: &str, nonce: &str, signer: &str) -> Result<Vec<u8>, String> {
    let enc = claim.get("encInputs").and_then(Value::as_str).ok_or("claim.encInputs must be a string")?;
    let policy = hash_canonical_strict(claim.get("policy").ok_or("claim.policy is missing")?).ok_or("claim.policy is not canonicalizable")?;
    let binding = claim.get("binding").ok_or("claim.binding is missing")?;
    prefixed(
        CLAIM_DOMAIN,
        &json!({ "v": 1, "context": context, "nonce": nonce, "signer": signer, "binding": binding, "policy": policy, "enc_inputs": bytes_digest(enc) }),
    )
}

/// The content digest of a signed claim (what the key holder's attestation commits to).
pub fn signed_claim_digest(signed: &Value) -> Result<String, String> {
    hash_canonical_strict(signed).ok_or_else(|| "signed claim is not canonicalizable".to_string())
}

fn key_of(secret: &[u8]) -> Result<(SigningKey, String), String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "signing key must be a 32-byte Ed25519 secret key".to_string())?;
    let k = SigningKey::from_bytes(&seed);
    let pk = b64_encode(&k.verifying_key().to_bytes());
    Ok((k, pk))
}

/// Sign an encrypted risk claim `{binding, encInputs, policy}` with the caller's one-time `nonce` (16 random bytes; the
/// reference draws them itself, so the caller supplies the RNG output; an all-zero nonce is refused as an RNG failure).
pub fn sign_risk_claim(claim: &Value, signer_secret_key: &[u8], context: &str, nonce: &[u8]) -> Result<Value, String> {
    let n = context.encode_utf16().count();
    if n == 0 || n > MAX_CONTEXT_LEN {
        return Err(format!("context must be a non-empty string of at most {MAX_CONTEXT_LEN} characters"));
    }
    if nonce.len() != NONCE_BYTES || nonce.iter().all(|b| *b == 0) {
        return Err("signRiskClaim: random source returned all zeros (RNG failure)".into());
    }
    let (key, signer) = key_of(signer_secret_key)?;
    let cm = claim.as_object().ok_or("claim must be an object")?;
    let nonce = b64_encode(nonce);
    let stmt = claim_statement(cm, context, &nonce, &signer)?;
    let sig = b64_encode(&key.sign(&stmt).to_bytes());
    Ok(json!({ "claim": claim, "context": context, "nonce": nonce, "signer": signer, "sig": sig }))
}

/// Single-use tracking for claim nonces. `claim` is true the first time a key is seen, false when it was seen or the guard
/// cannot record it. A closure `FnMut(&str) -> bool` is a guard.
pub trait NonceGuard {
    fn claim(&mut self, key: &str) -> bool;
}

impl<F: FnMut(&str) -> bool> NonceGuard for F {
    fn claim(&mut self, key: &str) -> bool {
        self(key)
    }
}

/// In-memory guard holding at most `max_entries` keys. It FAILS CLOSED when full (it never evicts: eviction would re-open
/// replay).
pub struct MemoryNonceGuard {
    seen: HashSet<String>,
    max: usize,
}

pub fn memory_nonce_guard(max_entries: usize) -> MemoryNonceGuard {
    MemoryNonceGuard { seen: HashSet::new(), max: max_entries }
}

impl NonceGuard for MemoryNonceGuard {
    fn claim(&mut self, key: &str) -> bool {
        if self.seen.contains(key) || self.seen.len() >= self.max {
            return false;
        }
        self.seen.insert(key.to_string());
        true
    }
}

/// What the verifier expects, from its OWN view of the grant: trusted encryptor keys (b64u), the grant context, the action
/// binding, the gate policy and the replay guard.
pub struct ClaimExpectations<'a> {
    pub trusted_signers: &'a [String],
    pub context: &'a str,
    pub binding: &'a Value,
    pub policy: &'a Value,
    pub nonces: &'a mut dyn NonceGuard,
}

fn fail(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

fn is_container(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(_)) | Some(Value::Array(_)))
}

/// Verify a signed claim; never panics. `{ok:true, claim, digest}` or `{ok:false, reason}`. Order: shape, pinned signer,
/// signature, context / binding / policy equality, and only then the nonce is consumed (so unauthenticated junk cannot burn
/// nonces).
pub fn verify_signed_risk_claim(s: &Value, exp: &mut ClaimExpectations<'_>) -> Value {
    const ENVELOPE: &str = "claim is not signed: malformed envelope";
    const MALFORMED: &str = "claim could not be verified (malformed)";
    let Some(c) = s.as_object() else { return fail(ENVELOPE) };
    let claim = c.get("claim").and_then(Value::as_object);
    let (context, nonce, signer, sig) = (
        c.get("context").and_then(Value::as_str),
        c.get("nonce").and_then(Value::as_str),
        c.get("signer").and_then(Value::as_str),
        c.get("sig").and_then(Value::as_str),
    );
    let (Some(claim), Some(context), Some(nonce), Some(signer), Some(sig)) = (claim, context, nonce, signer, sig) else {
        return fail(ENVELOPE);
    };
    if claim.get("encInputs").and_then(Value::as_str).is_none() || !is_container(claim.get("binding")) || !is_container(claim.get("policy")) {
        return fail(ENVELOPE);
    }
    if decode_b64u_strict(nonce, Some(NONCE_BYTES)).is_none() {
        return fail("malformed nonce");
    }
    let signer_bytes = decode_b64u_strict(signer, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok());
    let sig_bytes = decode_b64u_strict(sig, Some(64)).and_then(|b| <[u8; 64]>::try_from(b).ok());
    let (Some(signer_bytes), Some(sig_bytes)) = (signer_bytes, sig_bytes) else {
        return fail("malformed signer key or signature");
    };
    if !exp.trusted_signers.iter().any(|t| t == signer) {
        return fail("signer is not a trusted encryptor");
    }
    let Ok(stmt) = claim_statement(claim, context, nonce, signer) else { return fail(MALFORMED) };
    if !verify_ed25519_strict(&signer_bytes, &stmt, &sig_bytes) {
        return fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)");
    }
    if context != exp.context {
        return fail("context mismatch: claim was signed for a different grant/policy");
    }
    let (Some(hb), Some(eb)) = (hash_canonical_strict(&claim["binding"]), hash_canonical_strict(exp.binding)) else { return fail(MALFORMED) };
    if hb != eb {
        return fail("binding mismatch: claim is bound to a different action");
    }
    let (Some(hp), Some(ep)) = (hash_canonical_strict(&claim["policy"]), hash_canonical_strict(exp.policy)) else { return fail(MALFORMED) };
    if hp != ep {
        return fail("policy mismatch: claim was signed for a different gate policy");
    }
    if !exp.nonces.claim(&format!("{signer}:{nonce}")) {
        return fail("replay: nonce already used (or the replay window is full)");
    }
    match signed_claim_digest(s) {
        Ok(digest) => json!({ "ok": true, "claim": claim, "digest": digest }),
        Err(_) => fail(MALFORMED),
    }
}

fn verdict_statement(claim_digest: &str, gate_digest: &Value, admit: bool, holder: &str) -> Result<Vec<u8>, String> {
    prefixed(VERDICT_DOMAIN, &json!({ "v": 1, "claim": claim_digest, "gate": gate_digest, "admit": admit, "holder": holder }))
}

/// The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output
/// `{encRiskRaw, encSlack}`. Only `admit` is signed, never the slack or the risk.
pub fn attest_verdict(holder_secret_key: &[u8], signed: &Value, gate: &Value, admit: bool) -> Result<Value, String> {
    let g = |k: &str| gate.get(k).and_then(Value::as_str).map(bytes_digest).ok_or_else(|| format!("gate.{k} must be a string"));
    let gd = json!({ "encRiskRaw": g("encRiskRaw")?, "encSlack": g("encSlack")? });
    let cd = signed_claim_digest(signed)?;
    let (key, holder) = key_of(holder_secret_key)?;
    let stmt = verdict_statement(&cd, &gd, admit, &holder)?;
    let sig = b64_encode(&key.sign(&stmt).to_bytes());
    Ok(json!({ "claimDigest": cd, "gateDigest": gd, "admit": admit, "holder": holder, "sig": sig }))
}

/// Verify an attestation: trusted holder, signature, the expected claim digest and (when `gate` is given) the expected gate
/// output. Never panics. `{ok:true, admit}` or `{ok:false, reason}`.
pub fn verify_verdict_attestation(a: &Value, trusted_holders: &[String], claim_digest: &str, gate: Option<&Value>) -> Value {
    const MALFORMED: &str = "malformed attestation";
    let Some(x) = a.as_object() else { return fail(MALFORMED) };
    let gd = x.get("gateDigest").filter(|g| g.is_object());
    let (cd, holder_s, sig_s, admit) = (
        x.get("claimDigest").and_then(Value::as_str),
        x.get("holder").and_then(Value::as_str),
        x.get("sig").and_then(Value::as_str),
        x.get("admit").and_then(Value::as_bool),
    );
    let (Some(cd), Some(holder_s), Some(sig_s), Some(admit), Some(gd)) = (cd, holder_s, sig_s, admit, gd) else { return fail(MALFORMED) };
    let (Some(g_raw), Some(g_slack)) = (gd.get("encRiskRaw").and_then(Value::as_str), gd.get("encSlack").and_then(Value::as_str)) else {
        return fail(MALFORMED);
    };
    if !trusted_holders.iter().any(|t| t == holder_s) {
        return fail("attestation holder is not trusted");
    }
    let holder = decode_b64u_strict(holder_s, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok());
    let sig = decode_b64u_strict(sig_s, Some(64)).and_then(|b| <[u8; 64]>::try_from(b).ok());
    let (Some(holder), Some(sig)) = (holder, sig) else { return fail("malformed holder key or signature") };
    let Ok(stmt) = verdict_statement(cd, gd, admit, holder_s) else { return fail("attestation could not be verified (malformed)") };
    if !verify_ed25519_strict(&holder, &stmt, &sig) {
        return fail("attestation signature does not verify");
    }
    if cd != claim_digest {
        return fail("attestation is for a different claim");
    }
    if let Some(g) = gate {
        let (Some(raw), Some(slack)) = (g.get("encRiskRaw").and_then(Value::as_str), g.get("encSlack").and_then(Value::as_str)) else {
            return fail("attestation could not be verified (malformed)");
        };
        if g_raw != bytes_digest(raw) || g_slack != bytes_digest(slack) {
            return fail("attestation is for a different gate output");
        }
    }
    json!({ "ok": true, "admit": admit })
}
