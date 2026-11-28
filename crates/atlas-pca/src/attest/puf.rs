//! The PUF (physical unclonable function) attestation root (port of `attest-puf.ts`): an unclonable-device identity derived from a noisy
//! hardware response by a fuzzy extractor (a code-offset secure sketch over a repetition code plus an HKDF-SHA-256 strong extractor), a
//! TPM endorsement-key provider over an INJECTED `tpm2-tools` runner, enrollment, a device-side attestor, an enrollment registry and a
//! verifier that plugs into the same seam as the hardware roots.
//!
//! HONEST SCOPE: unclonability is a CLASSICAL property of the device and a different axis from quantum resistance; the key the extractor
//! derives can itself carry a post-quantum suite (ML-DSA), which composes with the PQ software root. A PUF root attests an unclonable DEVICE
//! IDENTITY, not a silicon measurement of the loaded weights: the identity it yields has `weights_measured: false`. The simulated PUF is
//! trivially clonable (its response is a pure function of a seed) and exists so enrollment and reproduction run without hardware.
//!
//! JSON-valued where the reference's shapes are (`serde_json::Value` in, the reference's member names out); a reference throw is an `Err`.
//! A PUF response is a byte array with ONE 0 / 1 value per bit.
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use hkdf::Hkdf;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::agent::{sign_with_suite, KeyPair, PqKeyPair, Suite};
use crate::attestation::{attestation_binding, attestation_binding_b64u, HardwareVerifierFn};
use crate::intent_strict::js_opt_string;
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, hash_canonical_strict};

/// Domain separator for the HKDF strong extractor (PUF response to key).
pub const PUF_EXTRACT_INFO: &str = "atlas-pca/puf-extract/v1";
/// Domain separator for the signed PUF attestation statement body.
pub const PUF_ATTEST_DOMAIN: &str = "atlas-pca/attest-puf/v1\0";
/// The derived key length in bytes: it seeds the PUF-derived signing key.
pub const PUF_KEY_BYTES: usize = 32;
/// HKDF domain separator binding a TPM endorsement-key public area to the device-unique, stable response.
pub const TPM_EK_PUF_DOMAIN: &str = "atlas-pca/puf-tpm-ek/v1";

// ---- the fuzzy extractor ---------------------------------------------------------------------------------------------------------

/// A JavaScript `Number.isInteger` read of a JSON member.
fn integer(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite() && f.fract() == 0.0)
}

/// The per-block Hamming correction bound of a repetition code, `floor((rep - 1) / 2)`.
pub fn repetition_correction_bound(rep: f64) -> i64 {
    ((rep - 1.0) / 2.0).floor() as i64
}

fn assert_bits(b: &[u8], wher: &str) -> Result<(), String> {
    if b.iter().any(|x| *x > 1) {
        return Err(format!("{wher}: response must be a 0/1 bit array"));
    }
    Ok(())
}

fn xor_bits(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x ^ y) & 1).collect()
}

fn rep_encode(message: &[u8], rep: usize) -> Vec<u8> {
    message.iter().flat_map(|m| std::iter::repeat(m & 1).take(rep)).collect()
}

fn rep_decode(code: &[u8], rep: usize) -> Vec<u8> {
    code.chunks(rep).map(|c| u8::from(c.iter().map(|b| (b & 1) as usize).sum::<usize>() * 2 > rep)).collect()
}

fn pack_bits(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if b & 1 == 1 {
            out[i >> 3] |= 1 << (i & 7);
        }
    }
    out
}

fn unpack_bits(packed: &[u8], n: usize) -> Vec<u8> {
    (0..n).map(|i| (packed[i >> 3] >> (i & 7)) & 1).collect()
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut okm).expect("the output is at most 255 hash blocks");
    okm
}

fn extract_key(response_bits: &[u8], salt: &[u8]) -> Vec<u8> {
    hkdf_sha256(&pack_bits(response_bits), salt, PUF_EXTRACT_INFO.as_bytes(), PUF_KEY_BYTES)
}

/// What an enrollment yields: the stable key (it seeds the device key: never persisted) and the PUBLIC helper data
/// `{sketch, salt, rep, messageBits, n}`.
pub struct FuzzyEnrolled {
    pub key: Vec<u8>,
    pub helper: Value,
}

/// ENROLL a PUF response into a stable key plus public helper data. `params` is `{rep, messageBits}`; `random(n)` supplies the random codeword
/// message (its low bits) and the salt. `Err` on a malformed response or parameters. The key depends only on the response.
pub fn fuzzy_enroll(response_bits: &[u8], params: &Value, random: &mut dyn FnMut(usize) -> Vec<u8>) -> Result<FuzzyEnrolled, String> {
    let rep =
        integer(params.get("rep")).filter(|r| *r >= 1.0 && r % 2.0 != 0.0).ok_or("fuzzyEnroll: rep must be an odd positive integer")?;
    let mb = integer(params.get("messageBits")).filter(|m| *m >= 1.0).ok_or("fuzzyEnroll: messageBits must be a positive integer")?;
    let n = rep * mb;
    if response_bits.len() as f64 != n {
        return Err(format!("fuzzyEnroll: response length {} != rep*messageBits {}", response_bits.len(), n));
    }
    assert_bits(response_bits, "fuzzyEnroll")?;
    let (rep, mb, n) = (rep as usize, mb as usize, n as usize);
    let mr = random(mb);
    let m: Vec<u8> = (0..mb).map(|i| mr.get(i).copied().unwrap_or(0) & 1).collect();
    let sketch = xor_bits(&rep_encode(&m, rep), response_bits);
    let salt = random(32);
    let key = extract_key(response_bits, &salt);
    let helper = json!({"sketch": b64_encode(&pack_bits(&sketch)), "salt": b64_encode(&salt), "rep": rep, "messageBits": mb, "n": n});
    Ok(FuzzyEnrolled { key, helper })
}

/// REPRODUCE the key from a noisy response and the public helper data: within the per-block correction bound the key is bit-identical to
/// enrollment, beyond it a DIFFERENT key comes back (fail closed: the downstream signature then fails). `Err` only on a structurally
/// malformed helper or response.
pub fn fuzzy_reproduce(response_bits: &[u8], helper: &Value) -> Result<Vec<u8>, String> {
    let malformed = || "fuzzyReproduce: malformed helper params".to_string();
    let rep = integer(helper.get("rep")).ok_or_else(malformed)?;
    let mb = integer(helper.get("messageBits")).ok_or_else(malformed)?;
    if rep < 1.0 || rep % 2.0 == 0.0 {
        return Err(malformed());
    }
    let n = rep * mb;
    if helper.get("n").and_then(Value::as_f64) != Some(n) {
        return Err("fuzzyReproduce: helper.n inconsistent with rep*messageBits".into());
    }
    if response_bits.len() as f64 != n {
        return Err(format!("fuzzyReproduce: response length {} != {}", response_bits.len(), n));
    }
    assert_bits(response_bits, "fuzzyReproduce")?;
    let (rep, n) = (rep as usize, n as usize);
    let (Some(sketch), Some(salt)) = (helper.get("sketch").and_then(Value::as_str), helper.get("salt").and_then(Value::as_str)) else {
        return Err("fuzzyReproduce: helper data missing sketch or salt".into());
    };
    let (Some(packed), Some(salt)) = (decode_b64u_strict(sketch, None), decode_b64u_strict(salt, None)) else {
        return Err("fuzzyReproduce: helper sketch or salt is not canonical base64url".into());
    };
    if packed.len() != n.div_ceil(8) {
        return Err("fuzzyReproduce: helper sketch has the wrong length".into());
    }
    if salt.len() != 32 {
        return Err("fuzzyReproduce: helper salt has the wrong length".into());
    }
    let sketch_bits = unpack_bits(&packed, n);
    let corrupted = xor_bits(response_bits, &sketch_bits);
    let m_hat = rep_decode(&corrupted, rep);
    let w_rec = xor_bits(&rep_encode(&m_hat, rep), &sketch_bits);
    Ok(extract_key(&w_rec, &salt))
}

// ---- providers -------------------------------------------------------------------------------------------------------------------

/// A source of PUF responses for a device: a noisy bit reading per challenge (successive reads differ by a bounded Hamming distance,
/// which the extractor corrects). Production backends are an SRAM PUF, a TPM 2.0 endorsement key or a vendor PUF block.
pub trait PufProvider {
    /// The stable device / provider id (the enrollment is looked up by it).
    fn id(&self) -> &str;
    /// Read the (noisy) response bits for a challenge; `Err` fails closed.
    fn response(&self, challenge: &[u8]) -> Result<Vec<u8>, String>;
}

/// The counter-mode SHA-256 stream of `prefix` as `length` 0 / 1 bits (one bit per output bit position, little-endian within a byte).
fn prg_bits(prefix: &[&[u8]], length: usize, at_least_one_block: bool) -> Vec<u8> {
    let bytes_needed = length.div_ceil(8);
    let mut nblocks = bytes_needed.div_ceil(32);
    if at_least_one_block {
        nblocks = nblocks.max(1);
    }
    let mut stream = Vec::with_capacity(nblocks * 32);
    for blk in 0..nblocks {
        let mut h = Sha256::new();
        for p in prefix {
            h.update(p);
        }
        h.update((blk as u32).to_be_bytes());
        stream.extend_from_slice(&h.finalize());
    }
    (0..length).map(|i| (stream[i >> 3] >> (i & 7)) & 1).collect()
}

/// A DETERMINISTIC SIMULATED PUF, FOR TESTS ONLY: its response is a pure function of (`seed`, challenge), so it is trivially clonable and
/// NOT a real root of trust. `flip` injects deterministic bit noise (a SET of positions to toggle).
pub struct SimulatedPuf {
    id: String,
    seed: Vec<u8>,
    length: usize,
    flips: BTreeSet<i64>,
}

/// Build the simulated PUF.
pub fn create_simulated_puf(id: &str, seed: &[u8], length: usize, flip: &[i64]) -> SimulatedPuf {
    SimulatedPuf { id: id.to_string(), seed: seed.to_vec(), length, flips: flip.iter().copied().collect() }
}

impl PufProvider for SimulatedPuf {
    fn id(&self) -> &str {
        &self.id
    }
    fn response(&self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let mut bits = prg_bits(&[self.seed.as_slice(), challenge], self.length, false);
        for pos in &self.flips {
            if *pos >= 0 && (*pos as usize) < bits.len() {
                bits[*pos as usize] ^= 1;
            }
        }
        Ok(bits)
    }
}

/// The result of one `tpm2-tools` invocation as the provider sees it.
#[derive(Clone, Debug, Default)]
pub struct TpmCommandResult {
    /// Process exit status (0 = success); `None` when the process could not run or was signalled.
    pub status: Option<i64>,
    /// Raw bytes written to stdout (the DER EK public area); `None` when the runner returned something that is not bytes.
    pub stdout: Option<Vec<u8>>,
    /// Captured stderr, if any.
    pub stderr: Option<String>,
    /// Set when the tool could not be SPAWNED at all (tpm2-tools not installed): fail closed.
    pub error: Option<String>,
}

/// An injected `tpm2-tools` runner: runs `command` with `args`. `Err` is a throw; `Ok(None)` is a runner that returned nothing.
pub type TpmCommandRunner = dyn Fn(&str, &[String]) -> Result<Option<TpmCommandResult>, String> + Send + Sync;

/// A [`PufProvider`] backed by a TPM 2.0 endorsement key: each response reads the device's EK public area through the injected runner and
/// derives a STABLE, device-unique bit response (the EK read is deterministic, so there is no noise). FAIL CLOSED: any tooling or TPM
/// failure is an `Err`. No default runner is bundled.
pub struct TpmEkPufProvider {
    id: String,
    length: usize,
    run: Arc<TpmCommandRunner>,
    tool: String,
    args: Vec<String>,
    min_ek_bytes: usize,
}

impl TpmEkPufProvider {
    /// Build the provider from `{id, length, tool?, ekHandle?, args?, minEkBytes?}`.
    pub fn new(opts: &Value, run: Arc<TpmCommandRunner>) -> Result<Self, String> {
        let id =
            opts.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).ok_or("TpmEkPufProvider: id must be a non-empty string")?;
        let length = integer(opts.get("length"))
            .filter(|l| *l >= 1.0)
            .ok_or("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)")?;
        let min_ek_bytes = match opts.get("minEkBytes") {
            None => 64.0,
            Some(m) => integer(Some(m)).filter(|m| *m >= 1.0).ok_or("TpmEkPufProvider: minEkBytes must be a positive integer")?,
        };
        let text = |k: &str| opts.get(k).and_then(Value::as_str).filter(|t| !t.is_empty());
        let handle = text("ekHandle").unwrap_or("0x81010001");
        let args = match opts.get("args").and_then(Value::as_array) {
            Some(a) => a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect(),
            None => ["-c", handle, "-f", "der", "-o", "/dev/stdout", "-Q"].iter().map(|s| s.to_string()).collect(),
        };
        Ok(Self {
            id: id.to_string(),
            length: length as usize,
            run,
            tool: text("tool").unwrap_or("tpm2_readpublic").to_string(),
            args,
            min_ek_bytes: min_ek_bytes as usize,
        })
    }

    /// Read the device-unique, stable EK public area (fail closed). Only PUBLIC material.
    pub fn read_ek_public(&self) -> Result<Vec<u8>, String> {
        let res = match (self.run)(&self.tool, &self.args) {
            Err(e) => {
                return Err(format!(
                    "TpmEkPufProvider: tpm2-tools invocation threw (fail closed): {}",
                    if e.is_empty() { "unknown" } else { &e }
                ))
            }
            Ok(None) => return Err("TpmEkPufProvider: command runner returned no result (fail closed)".into()),
            Ok(Some(r)) => r,
        };
        if let Some(e) = res.error.as_deref().filter(|e| !e.is_empty()) {
            return Err(format!("TpmEkPufProvider: tpm2-tools unavailable (fail closed): {e}"));
        }
        if res.status != Some(0) {
            let status = res.status.map_or("null".to_string(), |s| s.to_string());
            let stderr = res.stderr.as_deref().filter(|s| !s.is_empty()).map(|s| format!(": {}", s.trim())).unwrap_or_default();
            return Err(format!("TpmEkPufProvider: '{}' exited with status {status} (fail closed){stderr}", self.tool));
        }
        match res.stdout {
            Some(ek) if ek.len() >= self.min_ek_bytes => Ok(ek),
            other => Err(format!(
                "TpmEkPufProvider: EK public too short ({} < {} bytes) \u{2014} TPM unavailable or wrong handle (fail closed)",
                other.map_or(0, |e| e.len()),
                self.min_ek_bytes
            )),
        }
    }
}

impl PufProvider for TpmEkPufProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn response(&self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let ek = self.read_ek_public()?;
        // device-unique stable secret: HKDF over the EK public area, challenge-bound (salt = domain, info = challenge)
        let secret = hkdf_sha256(&ek, TPM_EK_PUF_DOMAIN.as_bytes(), challenge, 32);
        Ok(prg_bits(&[secret.as_slice()], self.length, true))
    }
}

// ---- the PUF-derived signing key -------------------------------------------------------------------------------------------------

/// The PUF-derived suites: each seeds deterministically from the 32-byte extractor output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PufSuite {
    Ed25519,
    MlDsa65,
    MlDsa87,
}

impl PufSuite {
    pub fn name(self) -> &'static str {
        match self {
            PufSuite::Ed25519 => "ed25519",
            PufSuite::MlDsa65 => "ml-dsa-65",
            PufSuite::MlDsa87 => "ml-dsa-87",
        }
    }
    fn parse(v: &Value) -> Result<Self, String> {
        match v.as_str() {
            Some("ed25519") => Ok(PufSuite::Ed25519),
            Some("ml-dsa-65") => Ok(PufSuite::MlDsa65),
            Some("ml-dsa-87") => Ok(PufSuite::MlDsa87),
            _ => Err(format!(
                "PUF root: unsupported derived suite '{}' (use ed25519, ml-dsa-65 or ml-dsa-87)",
                crate::intent_v2::js_value_string(v)
            )),
        }
    }
}

struct PufSigner {
    alg: PufSuite,
    public: String,
    ed: Option<KeyPair>,
    pq: Option<PqKeyPair>,
}

impl PufSigner {
    fn from_seed(alg: PufSuite, seed: &[u8]) -> Result<Self, String> {
        match alg {
            PufSuite::Ed25519 => {
                let arr: [u8; 32] = seed.try_into().map_err(|_| "the PUF key is 32 bytes".to_string())?;
                let kp = KeyPair::from_seed(&arr);
                Ok(Self { alg, public: kp.public.clone(), ed: Some(kp), pq: None })
            }
            PufSuite::MlDsa65 | PufSuite::MlDsa87 => {
                let family = if alg == PufSuite::MlDsa65 { "ML-DSA-65" } else { "ML-DSA-87" };
                let kp = PqKeyPair::from_seed(family, seed)?;
                Ok(Self { alg, public: kp.public.clone(), ed: None, pq: Some(kp) })
            }
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<(String, Option<String>), String> {
        sign_with_suite(&Suite { alg: Some(self.alg.name()), pq: self.pq.as_ref() }, self.ed.as_ref(), msg)
    }
}

fn statement_message(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = PUF_ATTEST_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

// ---- enrollment, attestor, registry ----------------------------------------------------------------------------------------------

/// ENROLL a PUF device: read its response under `challenge`, run the extractor, derive the signing key and return the PUBLIC enrolled
/// identity `{providerId, challenge, alg, publicKey, helper, helperCommitment}`. `opts` is `{rep, messageBits, alg?}` (default suite
/// `ml-dsa-65`). The secret never leaves this function. `Err` on malformed input.
pub fn enroll_puf(
    provider: &dyn PufProvider,
    challenge: &[u8],
    opts: &Value,
    random: &mut dyn FnMut(usize) -> Vec<u8>,
) -> Result<Value, String> {
    let alg = PufSuite::parse(opts.get("alg").filter(|a| !a.is_null()).unwrap_or(&json!("ml-dsa-65")))?;
    let bits = provider.response(challenge)?;
    let enrolled = fuzzy_enroll(&bits, opts, random)?;
    let signer = PufSigner::from_seed(alg, &enrolled.key)?;
    let commitment = hash_canonical_strict(&enrolled.helper).ok_or("canonicalize: the helper is not strictly canonical")?;
    Ok(json!({
        "providerId": provider.id(),
        "challenge": b64_encode(challenge),
        "alg": alg.name(),
        "publicKey": signer.public,
        "helper": enrolled.helper,
        "helperCommitment": commitment,
    }))
}

/// A device-side attestor that reproduces the PUF key from a fresh reading and signs statements.
pub struct PufAttestor<'a> {
    provider: &'a dyn PufProvider,
    helper: Value,
    alg: PufSuite,
    challenge: Vec<u8>,
}

/// Build the device-side attestor for an enrollment. `Err` for an unsupported suite or a challenge that is not canonical base64url.
pub fn create_puf_attestor<'a>(provider: &'a dyn PufProvider, enrollment: &Value) -> Result<PufAttestor<'a>, String> {
    let alg = PufSuite::parse(enrollment.get("alg").unwrap_or(&Value::Null))?;
    let challenge = enrollment
        .get("challenge")
        .and_then(Value::as_str)
        .and_then(|c| decode_b64u_strict(c, None))
        .ok_or("unb64u: the enrollment challenge is not canonical base64url")?;
    Ok(PufAttestor { provider, helper: enrollment.get("helper").cloned().unwrap_or(Value::Null), alg, challenge })
}

impl PufAttestor<'_> {
    /// Mint a signed statement over `claims` (`measurement`, `holder_pub`, `grant_ref`, `epoch`, `nonce`; optional `weights_digest`):
    /// `{provider_id, measurement, binding, alg, weights_digest?, sig, pq_sig?}`. `Err` for claims that are no valid binding or have no
    /// canonical form, and for a reading too noisy to decode into a well-formed helper.
    pub fn attest(&self, claims: &Value) -> Result<Value, String> {
        let bits = self.provider.response(&self.challenge)?;
        let key = fuzzy_reproduce(&bits, &self.helper)?;
        let signer = PufSigner::from_seed(self.alg, &key)?;
        let mut expected = Map::new();
        for (to, from) in [("holderPub", "holder_pub"), ("grantRef", "grant_ref"), ("epoch", "epoch"), ("nonce", "nonce")] {
            if let Some(v) = claims.get(from) {
                expected.insert(to.into(), v.clone());
            }
        }
        let binding = attestation_binding_b64u(&Value::Object(expected))?;
        let mut body = Map::new();
        body.insert("provider_id".into(), json!(self.provider.id()));
        body.insert("measurement".into(), claims.get("measurement").ok_or("canonicalize: unsupported type undefined")?.clone());
        body.insert("binding".into(), json!(binding));
        body.insert("alg".into(), json!(self.alg.name()));
        if let Some(w) = claims.get("weights_digest") {
            body.insert("weights_digest".into(), w.clone());
        }
        let body = Value::Object(body);
        let (sig, pq_sig) = signer.sign(&statement_message(&body)?)?;
        let mut out = body;
        out["sig"] = json!(sig);
        if let Some(p) = pq_sig {
            out["pq_sig"] = json!(p);
        }
        Ok(out)
    }
}

/// An in-memory registry of enrolled PUF identities keyed by provider id (a later duplicate overwrites an earlier one; revocation is
/// permanent: registering again does not un-revoke).
#[derive(Default)]
pub struct PufEnrollmentRegistry {
    by_id: HashMap<String, Value>,
    revoked: HashSet<String>,
}

fn keyed(e: &Value) -> Option<&str> {
    e.get("providerId").and_then(Value::as_str)
}

/// Build the registry from `enrollments` (anything that is not an array is empty; an entry without a string `providerId` is skipped).
pub fn create_puf_enrollment_registry(enrollments: &Value) -> PufEnrollmentRegistry {
    let mut r = PufEnrollmentRegistry::default();
    for e in enrollments.as_array().into_iter().flatten() {
        r.register(e);
    }
    r
}

impl PufEnrollmentRegistry {
    pub fn register(&mut self, enrollment: &Value) {
        if let Some(id) = keyed(enrollment) {
            self.by_id.insert(id.to_string(), enrollment.clone());
        }
    }
    /// The enrollment of `provider_id`; none when it is unknown or revoked.
    pub fn lookup(&self, provider_id: &str) -> Option<Value> {
        if self.revoked.contains(provider_id) {
            return None;
        }
        self.by_id.get(provider_id).cloned()
    }
    pub fn revoke(&mut self, provider_id: &str) {
        self.revoked.insert(provider_id.to_string());
    }
    pub fn is_revoked(&self, provider_id: &str) -> bool {
        self.revoked.contains(provider_id)
    }
}

// ---- the verifier ----------------------------------------------------------------------------------------------------------------

/// Resolve the enrolled identity of a statement's provider id: `(provider_id, document, ctx)`.
pub type PufResolveEnrollment = dyn Fn(&str, &Value, &Value) -> Result<Option<Value>, String> + Send + Sync;
/// The evidence seam: the attestation document and verifier context in, the signed PUF statement (or `None`) out.
pub type PufResolveEvidence = dyn Fn(&Value, &Value) -> Result<Option<Value>, String> + Send + Sync;
/// Revocation check by provider id.
pub type PufIsRevoked = dyn Fn(&str) -> Result<bool, String> + Send + Sync;
/// Map a verified statement and its enrollment into the `MeasuredIdentity` the agent binding is checked against.
pub type PufDeriveIdentity = dyn Fn(&Value, &Value) -> Value + Send + Sync;

/// The seams of [`create_puf_verifier`].
#[derive(Default)]
pub struct PufVerifierSeams {
    /// REQUIRED: construction fails without it.
    pub resolve_enrollment: Option<Arc<PufResolveEnrollment>>,
    /// Without it every verification fails closed.
    pub resolve_evidence: Option<Arc<PufResolveEvidence>>,
    pub is_revoked: Option<Arc<PufIsRevoked>>,
    /// Default: `weights_measured: false`, the statement's measurement and weights digest.
    pub derive_identity: Option<Arc<PufDeriveIdentity>>,
}

fn default_identity(st: &Value) -> Value {
    json!({
        "model_id": "",
        "weights_digest": st.get("weights_digest").and_then(Value::as_str).unwrap_or(""),
        "weights_measured": false,
        "runtime_measurement": st.get("measurement").cloned().unwrap_or(Value::Null),
        "operator": "",
    })
}

/// Build the verifier. `config` is `{policy: {measurements, weightsMeasurements?}, requirePq?}`. `Err` at construction for an empty
/// measurement allowlist (no accept-all) or a missing enrollment resolver.
///
/// A verification: the statement is resolved (evidence seam); a revoked device says so before it can look unknown; the enrollment is
/// resolved and unexpired; its helper commitment holds; the statement suite equals the enrolled suite and satisfies `requirePq`; the
/// signature verifies under the ENROLLED public key (never one from the statement); the binding equals `attestationBinding(expected)`; the
/// measurement (and weights digest, when that list is non-empty) is in the policy. The verdict is `{ok, bound, measured, hostAsserted:
/// {provider_id, suite}}` or `{ok: false, reason}`; the identity has `weights_measured: false` by default.
pub fn create_puf_verifier(config: &Value, seams: PufVerifierSeams) -> Result<Arc<HardwareVerifierFn>, String> {
    let policy = config.get("policy");
    let measurements: Vec<Value> = match policy.and_then(|p| p.get("measurements")).and_then(Value::as_array) {
        Some(m) if !m.is_empty() => m.clone(),
        _ => return Err("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)".into()),
    };
    let Some(resolve_enrollment) = seams.resolve_enrollment else { return Err("createPufVerifier: resolveEnrollment is required".into()) };
    let weights: Option<Vec<Value>> = policy.and_then(|p| p.get("weightsMeasurements")).and_then(Value::as_array).cloned();
    let require_pq = config.get("requirePq") == Some(&json!(true));
    let (resolve_evidence, is_revoked, derive_identity) = (seams.resolve_evidence, seams.is_revoked, seams.derive_identity);
    Ok(Arc::new(move |input: &Value| {
        let fail = |reason: String| Ok(json!({"ok": false, "reason": reason}));
        let error = |e: String| fail(format!("puf verification error (fail closed): {}", if e.is_empty() { "unknown" } else { &e }));
        let Some(resolve) = &resolve_evidence else { return fail("no PUF evidence resolver configured (fail closed)".into()) };
        let (document, ctx) = (input.get("document").unwrap_or(&Value::Null), input.get("ctx").unwrap_or(&Value::Null));
        let st = match resolve(document, ctx) {
            Ok(s) => s,
            Err(e) => return error(e),
        };
        let Some(st) = st
            .filter(|s| s.is_object() && s.get("provider_id").is_some_and(Value::is_string) && s.get("alg").is_some_and(Value::is_string))
        else {
            return fail("no PUF attestation statement for this action".into());
        };
        let pid = st["provider_id"].as_str().unwrap_or("");
        // revocation first: a revoked device must say so, not look merely unknown
        if let Some(rev) = &is_revoked {
            match rev(pid) {
                Ok(true) => return fail(format!("PUF enrollment for provider '{pid}' is revoked")),
                Ok(false) => {}
                Err(e) => return error(e),
            }
        }
        let enr = match resolve_enrollment(pid, document, ctx) {
            Ok(Some(e)) => e,
            Ok(None) => return fail(format!("no PUF enrollment registered for provider '{pid}'")),
            Err(e) => return error(e),
        };
        if let Some(not_after) = enr.get("notAfter") {
            let now = input.get("nowMs").and_then(Value::as_f64).unwrap_or(f64::NAN);
            if !(now.is_finite() && now < not_after.as_f64().unwrap_or(f64::NAN)) {
                return fail("PUF enrollment has expired".into());
            }
        }
        // (1) helper integrity
        let commitment_ok = match enr.get("helperCommitment").and_then(Value::as_str) {
            None => false,
            Some(c) => match canonicalize_strict(enr.get("helper").unwrap_or(&Value::Null)) {
                Ok(canon) => c == b64_encode(&crate::sha(canon.as_bytes())),
                Err(e) => return error(e),
            },
        };
        if !commitment_ok {
            return fail("PUF enrollment helper commitment mismatch (helper tampered)".into());
        }
        // (2) suite agreement
        let st_alg = st["alg"].as_str().unwrap_or("");
        if enr.get("alg") != st.get("alg") {
            return fail(format!("PUF statement suite '{st_alg}' does not match the enrolled suite '{}'", js_opt_string(enr.get("alg"))));
        }
        let Some(suite) = crate::resolve_sig_alg(Some(&json!(st_alg))) else {
            return fail(format!("PUF statement declares an unknown signature alg '{st_alg}'"));
        };
        let suite_has_pq = matches!(suite.pq, Some(crate::Pq::MlDsa65 | crate::Pq::MlDsa87 | crate::Pq::Slh128f | crate::Pq::Slh256s));
        if require_pq && !suite_has_pq {
            return fail(format!("PQ required: PUF-derived suite '{}' is classical", suite.alg));
        }
        // (3) the signature under the ENROLLED public key (another PUF derives another key and fails here)
        let mut body = st.as_object().cloned().unwrap_or_default();
        body.remove("sig");
        body.remove("pq_sig");
        let message = match statement_message(&Value::Object(body)) {
            Ok(m) => m,
            Err(e) => return error(e),
        };
        let enrolled_pk = enr.get("publicKey").and_then(Value::as_str).unwrap_or("");
        // the enrolled key (verifier-side registry) is the PQ key for pure-PQ PUF suites
        let pq_key = if suite.pq.is_some() { crate::pinned::PinnedPq::caller_vouched(enrolled_pk) } else { None };
        let verified =
            crate::verify_suite(Some(&json!(suite.alg)), enrolled_pk, pq_key.as_ref(), &message, st.get("sig"), st.get("pq_sig"));
        if !verified || (suite.pq.is_some() && pq_key.is_none()) {
            return fail(
                "PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)".into(),
            );
        }
        // (4) the binding
        let Some(expected) = input.get("expected").filter(|e| !e.is_null()) else {
            return fail("no expected attestation binding supplied".into());
        };
        let expected_b64u = match attestation_binding(expected) {
            Ok(b) => b64_encode(&b),
            Err(e) => return fail(format!("binding not constructible: {}", if e.is_empty() { "invalid" } else { &e })),
        };
        if st.get("binding").and_then(Value::as_str) != Some(expected_b64u.as_str()) {
            return fail("PUF statement binding mismatch (holder/grant/epoch/nonce)".into());
        }
        // (5) the policy
        if !st.get("measurement").is_some_and(|m| measurements.contains(m)) {
            return fail("measurement not in policy allowlist".into());
        }
        if let Some(w) = weights.as_ref().filter(|w| !w.is_empty()) {
            if !st.get("weights_digest").is_some_and(|d| d.is_string() && w.contains(d)) {
                return fail("measured weights digest not in policy allowlist".into());
            }
        }
        let measured = match &derive_identity {
            Some(d) => d(&st, &enr),
            None => default_identity(&st),
        };
        Ok(json!({"ok": true, "bound": true, "measured": measured, "hostAsserted": {"provider_id": pid, "suite": suite.alg}}))
    }))
}
