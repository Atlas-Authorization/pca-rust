//! Networked FROST(Ed25519) signing (port of `frost-net.ts`): the ALLOW TOKEN (a policy authority's Ed25519 signature over the canonical JSON of
//! a body that binds sha256(message), the group key and an optional window), the signer PROOF OF POSSESSION (a Schnorr proof under the
//! verification share, domain `pca.frost.signer-pop.v1`, that gates enrollment and stops a rogue key), the EQUIVOCATION GUARD (a second different
//! message for the same session / round / signer is refused), the strict wire decoders, the guardian SIGNER SERVICE and the NETWORK COORDINATOR.
//!
//! A guardian answers round 1 with a fresh nonce commitment and its proof of possession; it signs round 2 ONLY when the request names its group
//! key, carries a valid allow token from the trusted policy authority for exactly this message, lists its own round-1 commitment unchanged, and
//! the session is neither stale nor already signed. A nonce pair signs once: the store records it spent BEFORE the share is computed, so a crash
//! cannot lose the one-shot guard. The coordinator trusts no response: a signer counts only with a valid proof of possession under the
//! verification share on record, its commitments and shares are equivocation-checked, every share is verified before aggregation, and it
//! fails unless t shares aggregate to a signature that verifies under the group key. Transports (in-process, HTTP) are adapters behind
//! [`SignerTransport`]; none is bundled. Randomness (a default allow-token nonce, the proof-of-possession nonce, the round-1 nonces) comes from
//! a [`RandomBytes`] seam; the clock is injected.
//!
//! JSON-valued where the reference's wire shapes are (requests and responses are `serde_json::Value`).
use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};

use crate::agent::KeyPair;
use crate::attest::allowlist::JsNum;
use crate::frost::{
    frost_aggregate, frost_commit, frost_decode_safe_point, frost_is_canonical_scalar, frost_sign, frost_verifying_share, FrostCommitment, FrostNonces,
    FrostParticipantShare, FrostSigShare, FrostSignOpts, FrostVerificationShare,
};
use crate::frost_nonce_store::{NonceRecord, NonceStore};
use crate::intent_strict::js_opt_string;
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict};

pub const ALLOW_TOKEN_TYP: &str = "pca.frost.allow.v1";
pub const SIGNER_POP_DST: &str = "pca.frost.signer-pop.v1";
/// The most commitments or verification shares a request may carry.
pub const MAX_FROST_SIGNING_SET: usize = 256;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// The randomness seam: `n` random bytes.
pub type RandomBytes = Arc<dyn Fn(usize) -> Vec<u8> + Send + Sync>;
/// How a body is turned into the bytes an allow token signs (the strict canonical JSON by default).
pub type CanonFn = fn(&Value) -> Result<Vec<u8>, String>;

/// The OS CSPRNG.
pub fn os_random() -> RandomBytes {
    Arc::new(|n| {
        let mut b = vec![0u8; n];
        getrandom::getrandom(&mut b).expect("the OS random source is available");
        b
    })
}

fn strict_bytes(v: &Value) -> Result<Vec<u8>, String> {
    canonicalize_strict(v).map(String::into_bytes)
}

/// A positive safe integer (a JSON number; never a boolean or a string).
fn id_of(v: &Value) -> Option<i64> {
    v.as_f64().filter(|f| v.is_number() && f.fract() == 0.0 && *f > 0.0 && *f <= MAX_SAFE).map(|f| f as i64)
}

fn bytes32(b: Option<&[u8]>) -> bool {
    b.is_some_and(|b| b.len() == 32)
}

/// A typed failure of this module.
#[derive(Clone, Debug)]
pub enum FrostNetError {
    /// An ordinary refusal (a thrown `Error` / `RangeError` / `TypeError`).
    Message(String),
    /// An enrollment refused: `identifier` names the signer when one is to blame.
    PoP { message: String, identifier: Option<i64> },
    /// A signer sent two different messages for the same session and round.
    Equivocation { message: String, session_id: String, round: i64, identifier: i64, previous_digest: String, offending_digest: String },
    /// A signing session that could not reach the threshold: each signer's refusal `{identifier, reason}`.
    Coordinator { message: String, refusals: Vec<Value> },
    /// The session did not reach the threshold inside its window.
    Timeout { message: String, timeout_ms: f64, refusals: Vec<Value> },
}

impl FrostNetError {
    pub fn message(&self) -> &str {
        match self {
            FrostNetError::Message(m) => m,
            FrostNetError::PoP { message, .. }
            | FrostNetError::Equivocation { message, .. }
            | FrostNetError::Coordinator { message, .. }
            | FrostNetError::Timeout { message, .. } => message,
        }
    }
}

impl std::fmt::Display for FrostNetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

fn msg(m: impl Into<String>) -> FrostNetError {
    FrostNetError::Message(m.into())
}

// ---- allow token -----------------------------------------------------------------------------------------------------------------

/// `base64url(sha256(message))`: what an allow token authorises.
pub fn frost_action_digest(message: &[u8]) -> String {
    b64_encode(&Sha256::digest(message))
}

/// What an allow token is issued for.
#[derive(Default)]
pub struct IssueAllowOpts {
    pub message: Option<Vec<u8>>,
    pub frost_action_digest: Option<String>,
    /// REQUIRED (`None` is refused).
    pub group_public_key: Option<Vec<u8>>,
    /// How the body is canonicalised for the signature (default the strict canonical JSON).
    pub canonical: Option<CanonFn>,
    /// The token nonce (default: one 32-byte draw from the random seam, base64url).
    pub nonce: Option<String>,
    pub not_before: Option<Value>,
    pub expires_at: Option<Value>,
}

/// An allow token signed by the policy authority: `{body: {typ, action_digest, group_pk, nonce, not_before?, expires_at?}, authority, sig}`.
/// `Err` without a message or digest, for a secret that is not 32 bytes, or for a body outside the strict canonical profile.
pub fn issue_allow_token(policy_secret: &[u8], opts: &IssueAllowOpts, random: &RandomBytes) -> Result<Value, String> {
    let digest = match (&opts.frost_action_digest, &opts.message) {
        (Some(d), _) => d.clone(),
        (None, Some(m)) => frost_action_digest(m),
        _ => String::new(),
    };
    if digest.is_empty() {
        return Err("issueAllowToken: provide message or frostActionDigest".into());
    }
    let mut body = Map::new();
    body.insert("typ".into(), json!(ALLOW_TOKEN_TYP));
    body.insert("action_digest".into(), json!(digest));
    let group_key = opts.group_public_key.as_ref().ok_or("b64u: expected a Uint8Array")?;
    body.insert("group_pk".into(), json!(b64_encode(group_key)));
    body.insert("nonce".into(), json!(opts.nonce.clone().unwrap_or_else(|| b64_encode(&random(32)))));
    if let Some(n) = &opts.not_before {
        body.insert("not_before".into(), n.clone());
    }
    if let Some(e) = &opts.expires_at {
        body.insert("expires_at".into(), e.clone());
    }
    let seed: [u8; 32] = policy_secret.try_into().map_err(|_| "bad secret key size".to_string())?;
    let key = KeyPair::from_seed(&seed);
    let body = Value::Object(body);
    let sig = key.sign(&opts.canonical.unwrap_or(strict_bytes)(&body)?);
    Ok(json!({"body": body, "authority": key.public, "sig": b64_encode(&sig)}))
}

/// What a verifier expects of an allow token (a member that is not usable bytes or a number is `None` / not a number: the check then fails
/// closed).
pub struct VerifyAllowExpect<'a> {
    pub policy_authority_public_key: Option<&'a [u8]>,
    pub group_public_key: Option<&'a [u8]>,
    pub message: Option<&'a [u8]>,
    pub now: JsNum,
    /// How the body is canonicalised for the signature (default the strict canonical JSON).
    pub canonical: Option<CanonFn>,
}

/// JavaScript `a < b` where `b` is a JSON value (a number, `null` as 0, a numeric string, anything else NaN).
fn js_number_of(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::String(s) => crate::actions::js_str_to_number(s),
        _ => f64::NAN,
    }
}

/// Check an allow token under the TRUSTED policy authority key (never under `token.authority`): shape, typ, signature, group key, action
/// digest, time window. `{ok: true}` or `{ok: false, reason}`; never fails.
pub fn verify_allow_token(token: &Value, expect: &VerifyAllowExpect) -> Value {
    let no = |reason: String| json!({"ok": false, "reason": reason});
    if !(token.is_object() || token.is_array()) {
        return no("allow token missing or malformed".into());
    }
    let body = token.get("body").filter(|b| b.is_object() || b.is_array());
    let Some(body) = body else { return no("allow token has no body".into()) };
    if body.get("typ") != Some(&json!(ALLOW_TOKEN_TYP)) {
        return no(format!("allow token wrong typ ({})", js_opt_string(body.get("typ"))));
    }
    let Some(sig_text) = token.get("sig").and_then(Value::as_str) else { return no("allow token missing signature".into()) };
    let Some(sig) = decode_b64u_strict(sig_text, Some(64)) else { return no("allow token signature not canonical base64url".into()) };
    let canon = expect.canonical.unwrap_or(strict_bytes);
    let bytes = match canon(body) {
        Ok(b) => b,
        Err(e) => return no(format!("allow token verification error (fail closed): {}", if e.is_empty() { "unknown" } else { &e })),
    };
    let closed = |why: &str| no(format!("allow token verification error (fail closed): {why}"));
    // edVerify answers false for a missing or malformed key, never a throw
    let signed = expect.policy_authority_public_key.is_some_and(|policy| crate::verify_b64u(&b64_encode(policy), &bytes, &b64_encode(&sig)));
    if !signed {
        return no("allow token not signed by the trusted policy authority".into());
    }
    let Some(group_key) = expect.group_public_key else { return closed("expected a Uint8Array") };
    if body.get("group_pk").and_then(Value::as_str) != Some(b64_encode(group_key).as_str()) {
        return no("allow token authorizes a different group key".into());
    }
    let Some(message) = expect.message else { return closed("frostActionDigest: message must be bytes") };
    if body.get("action_digest").and_then(Value::as_str) != Some(frost_action_digest(message).as_str()) {
        return no("allow token authorizes a different action digest".into());
    }
    let JsNum::Num(now) = expect.now else { return no("invalid verification time".into()) };
    if !now.is_finite() {
        return no("invalid verification time".into());
    }
    if let Some(nb) = body.get("not_before") {
        if !(now >= js_number_of(nb)) {
            return no("allow token not yet valid".into());
        }
    }
    if let Some(ex) = body.get("expires_at") {
        if !(now < js_number_of(ex)) {
            return no("allow token expired".into());
        }
    }
    json!({"ok": true})
}

// ---- signer proof of possession --------------------------------------------------------------------------------------------------

fn scalar_of(b: &[u8]) -> Result<Scalar, String> {
    if b.len() > 64 {
        return Err("frost: scalar input longer than 64 bytes".into());
    }
    let mut w = [0u8; 64];
    w[..b.len()].copy_from_slice(b);
    Ok(Scalar::from_bytes_mod_order_wide(&w))
}

fn pop_challenge(group_public_key: &[u8], identifier: i64, pk: &[u8], r: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(SIGNER_POP_DST.as_bytes());
    h.update(group_public_key);
    h.update(Scalar::from(identifier as u64).to_bytes());
    h.update(pk);
    h.update(r);
    let mut w = [0u8; 64];
    w.copy_from_slice(&h.finalize());
    let e = Scalar::from_bytes_mod_order_wide(&w);
    if e == Scalar::ZERO {
        Scalar::ONE
    } else {
        e
    }
}

fn point_of(b: &[u8]) -> Result<EdwardsPoint, String> {
    frost_decode_safe_point(b)?;
    let arr: [u8; 32] = b.try_into().map_err(|_| "frost: point must be 32 bytes".to_string())?;
    CompressedEdwardsY(arr).decompress().ok_or_else(|| "frost: point is not on the curve".to_string())
}

/// The signer's proof of possession of its verification share's secret: `{identifier, publicKey, R, s}` (base64url). `nonce` is a fixed
/// nonce for reproducible vectors; otherwise it is drawn from `random` (redrawn while it reduces to zero). `Err` on an invalid argument.
pub fn create_signer_pop(
    identifier: &Value,
    share: Option<&[u8]>,
    group_public_key: Option<&[u8]>,
    nonce: Option<&[u8]>,
    random: &RandomBytes,
) -> Result<Value, String> {
    let id = id_of(identifier).ok_or("createSignerPoP: identifier must be a positive integer")?;
    let share = share.filter(|s| s.len() == 32).ok_or("createSignerPoP: share must be 32 bytes")?;
    let gpk = group_public_key.filter(|s| s.len() == 32).ok_or("createSignerPoP: groupPublicKey must be 32 bytes")?;
    let x = scalar_of(share)?;
    let pk = (ED25519_BASEPOINT_POINT * x).compress().to_bytes();
    let mut k = match nonce {
        Some(n) => scalar_of(n)?,
        None => Scalar::ZERO,
    };
    while k == Scalar::ZERO {
        k = scalar_of(&random(32))?;
    }
    let r = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
    let e = pop_challenge(gpk, id, &pk, &r);
    let s = k + e * x;
    Ok(json!({"identifier": identifier, "publicKey": b64_encode(&pk), "R": b64_encode(&r), "s": b64_encode(&s.to_bytes())}))
}

/// Verify a proof of possession against the group key: strict point decoding of the key and R, a canonical s, then `s*B == R + e*PK`. Never
/// fails.
pub fn verify_signer_pop(pop: &Value, group_public_key: Option<&[u8]>) -> bool {
    (|| {
        let id = id_of(pop.get("identifier")?)?;
        let gpk = group_public_key.filter(|g| g.len() == 32)?;
        let dec = |k: &str| decode_b64u_strict(pop.get(k)?.as_str()?, Some(32));
        let (pk, rb, sb) = (dec("publicKey")?, dec("R")?, dec("s")?);
        let (pk_pt, r_pt) = (point_of(&pk).ok()?, point_of(&rb).ok()?);
        if !frost_is_canonical_scalar(&sb) {
            return None; // s and s + L must not both verify
        }
        let e = pop_challenge(gpk, id, &pk, &rb);
        let lhs = ED25519_BASEPOINT_POINT * scalar_of(&sb).ok()?;
        let rhs = r_pt + pk_pt * e;
        Some(lhs == rhs)
    })()
    .unwrap_or(false)
}

/// One signer's enrollment as the coordinator receives it (`identifier` any JSON value; `public_key` `None` when it is not 32-byte material).
pub struct EnrollmentIn<'a> {
    pub identifier: &'a Value,
    pub public_key: Option<&'a [u8]>,
    pub pop: &'a Value,
}

fn pop_err(m: impl Into<String>, identifier: Option<i64>) -> FrostNetError {
    FrostNetError::PoP { message: m.into(), identifier }
}

/// The verification shares of a signer set, each admitted only with a valid proof of possession (a rogue key is refused). `None` stands for
/// an enrollment list that is not a list.
pub fn enroll_verification_shares(enrollments: Option<&[EnrollmentIn]>, group_public_key: Option<&[u8]>) -> Result<Vec<(i64, Vec<u8>)>, FrostNetError> {
    let list = enrollments.filter(|l| !l.is_empty()).ok_or_else(|| pop_err("enrollVerificationShares: no signer enrollments", None))?;
    let gpk = group_public_key.filter(|g| g.len() == 32).ok_or_else(|| pop_err("enrollVerificationShares: groupPublicKey must be 32 bytes", None))?;
    let mut out = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    for e in list {
        let i = id_of(e.identifier).ok_or_else(|| pop_err("enrollVerificationShares: enrollment with invalid identifier", None))?;
        if !seen.insert(i) {
            return Err(pop_err(format!("enrollVerificationShares: duplicate enrollment for signer {i}"), Some(i)));
        }
        let Some(pk) = e.public_key.filter(|k| k.len() == 32) else {
            return Err(pop_err(format!("enrollVerificationShares: signer {i} verification share must be 32 bytes"), Some(i)));
        };
        let matched = e.pop.is_object() && id_of(&e.pop["identifier"]) == Some(i) && e.pop["publicKey"].as_str() == Some(b64_encode(pk).as_str());
        if !matched {
            return Err(pop_err(format!("enrollVerificationShares: signer {i} missing or mismatched proof-of-possession (rogue key rejected)"), Some(i)));
        }
        if !verify_signer_pop(e.pop, Some(gpk)) {
            return Err(pop_err(format!("enrollVerificationShares: signer {i} invalid proof-of-possession (rogue key rejected)"), Some(i)));
        }
        out.push((i, pk.to_vec()));
    }
    Ok(out)
}

// ---- equivocation guard ----------------------------------------------------------------------------------------------------------

/// Remembers the digest of the first message seen per (session, round, signer): the same message again is fine, a different one fails and stays
/// refused. `forget` clears a finished session.
#[derive(Default)]
pub struct EquivocationGuard {
    seen: HashMap<String, String>,
}

impl EquivocationGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `message` for (`session_id`, `round`, `identifier`); `Err(Equivocation)` for a different message than the first one seen.
    pub fn observe(&mut self, session_id: &Value, round: &Value, identifier: &Value, message: &Value) -> Result<(), FrostNetError> {
        let sid = session_id.as_str().filter(|s| !s.is_empty()).ok_or_else(|| msg("EquivocationGuard: session_id must be a non-empty string"))?;
        let rnd = round.as_f64().filter(|r| round.is_number() && r.fract() == 0.0 && *r >= 1.0 && *r <= MAX_SAFE);
        let rnd = rnd.ok_or_else(|| msg("EquivocationGuard: round must be a positive integer"))? as i64;
        let id = id_of(identifier).ok_or_else(|| msg("EquivocationGuard: identifier must be a positive integer"))?;
        let key = format!("{sid}\u{0}{rnd}\u{0}{id}");
        let digest = b64_encode(&Sha256::digest(strict_bytes(message).map_err(msg)?));
        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, digest);
                Ok(())
            }
            Some(prev) if *prev != digest => Err(FrostNetError::Equivocation {
                message: format!("equivocation: signer {id} sent two different messages for session '{sid}' round {rnd}"),
                session_id: sid.to_string(),
                round: rnd,
                identifier: id,
                previous_digest: prev.clone(),
                offending_digest: digest,
            }),
            Some(_) => Ok(()),
        }
    }

    pub fn forget(&mut self, session_id: &str) {
        let prefix = format!("{session_id}\u{0}");
        self.seen.retain(|k, _| !k.starts_with(&prefix));
    }
}

// ---- wire decoding ---------------------------------------------------------------------------------------------------------------

/// A round-1 commitment from its wire form `{identifier, hiding, binding}` (base64url, 32 bytes each; not validated as points here).
pub fn decode_commitment(w: &Value) -> Result<FrostCommitment, String> {
    if !w.is_object() {
        return Err("bad commitment".into());
    }
    let dec = |k: &str| w.get(k).and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, Some(32)));
    let (hiding, binding) = (dec("hiding"), dec("binding"));
    let identifier = w.get("identifier").and_then(id_of).ok_or("bad commitment identifier")?;
    match (hiding, binding) {
        (Some(hiding), Some(binding)) => Ok(FrostCommitment { identifier, hiding, binding }),
        _ => Err("bad commitment point encoding".into()),
    }
}

pub fn decode_commitments(list: &Value) -> Result<Vec<FrostCommitment>, String> {
    let l = list.as_array().ok_or("commitments must be a list")?;
    if l.len() > MAX_FROST_SIGNING_SET {
        return Err("commitments list exceeds the maximum signing set".into());
    }
    l.iter().map(decode_commitment).collect()
}

pub fn decode_verification_shares(list: &Value) -> Result<Vec<FrostVerificationShare>, String> {
    let l = list.as_array().ok_or("verification_shares must be a list")?;
    if l.len() > MAX_FROST_SIGNING_SET {
        return Err("verification_shares list exceeds the maximum signing set".into());
    }
    let mut out = Vec::new();
    for v in l {
        if !v.is_object() {
            return Err("bad verification share".into());
        }
        let pk = v.get("publicKey").and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, Some(32)));
        let identifier = v.get("identifier").and_then(id_of).ok_or("bad verification-share identifier")?;
        out.push(FrostVerificationShare { identifier, public_key: pk.ok_or("bad verification-share key encoding")? });
    }
    Ok(out)
}

fn encode_commitment(c: &FrostCommitment) -> Value {
    json!({"identifier": c.identifier, "hiding": b64_encode(&c.hiding), "binding": b64_encode(&c.binding)})
}

// ---- guardian signer service -----------------------------------------------------------------------------------------------------

/// The construction arguments of a [`GuardianSignerService`]; every field is read as the reference reads it (a byte field that is not 32
/// bytes is `None` or the wrong length, an identifier or threshold is any JSON value).
pub struct SignerConfig<'a> {
    pub identifier: &'a Value,
    pub share: Option<&'a [u8]>,
    pub group_public_key: Option<&'a [u8]>,
    pub threshold: &'a Value,
    pub policy_authority_public_key: Option<&'a [u8]>,
    pub session_ttl_ms: JsNum,
    pub now: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub nonce_store: Option<Arc<dyn NonceStore>>,
    pub random: RandomBytes,
    /// How an allow token's body is canonicalised (default the strict canonical JSON).
    pub canonical: Option<CanonFn>,
}

struct Session {
    nonces: FrostNonces,
    commitment: FrostCommitment,
    created_at: f64,
}

/// One guardian's side of a two-round FROST signing session. Every failure is a refusal value (`{ok: false, ..., reason}`), never an `Err`.
pub struct GuardianSignerService {
    pub identifier: i64,
    pub verification_share: Vec<u8>,
    share: Vec<u8>,
    gpk: Vec<u8>,
    threshold: i64,
    policy: Vec<u8>,
    ttl: Option<f64>,
    now: Arc<dyn Fn() -> f64 + Send + Sync>,
    store: Option<Arc<dyn NonceStore>>,
    random: RandomBytes,
    canonical: Option<CanonFn>,
    sessions: Mutex<HashMap<String, Session>>,
    spent: Mutex<HashSet<String>>,
    pop: Value,
}

impl GuardianSignerService {
    /// Build the service. `Err` for an invalid argument; the proof-of-possession nonce is one draw from the random seam.
    pub fn new(cfg: SignerConfig) -> Result<Self, String> {
        let identifier = id_of(cfg.identifier).ok_or("GuardianSignerService: identifier must be a positive integer")?;
        let share = cfg.share.filter(|s| s.len() == 32).ok_or("GuardianSignerService: share must be 32 bytes")?;
        let gpk = cfg.group_public_key.filter(|s| s.len() == 32).ok_or("GuardianSignerService: groupPublicKey must be 32 bytes")?;
        let threshold = cfg.threshold.as_f64().filter(|t| cfg.threshold.is_number() && t.fract() == 0.0 && *t >= 1.0 && *t <= MAX_SAFE);
        let threshold = threshold.ok_or("GuardianSignerService: threshold must be a positive integer")? as i64;
        let policy = cfg.policy_authority_public_key.filter(|s| s.len() == 32).ok_or("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes")?;
        let ttl = match cfg.session_ttl_ms {
            JsNum::Undefined => None,
            JsNum::Num(t) if t.is_finite() && t > 0.0 => Some(t),
            _ => return Err("GuardianSignerService: sessionTtlMs must be a positive finite number".into()),
        };
        let verification_share = frost_verifying_share(share)?;
        let pop = create_signer_pop(cfg.identifier, Some(share), Some(gpk), None, &cfg.random)?;
        Ok(GuardianSignerService {
            identifier,
            verification_share,
            share: share.to_vec(),
            gpk: gpk.to_vec(),
            threshold,
            policy: policy.to_vec(),
            ttl,
            now: cfg.now,
            store: cfg.nonce_store,
            random: cfg.random,
            canonical: cfg.canonical,
            sessions: Mutex::new(HashMap::new()),
            spent: Mutex::new(HashSet::new()),
            pop,
        })
    }

    pub fn proof_of_possession(&self) -> &Value {
        &self.pop
    }

    /// What the coordinator enrolls: `{identifier, publicKey (bytes), pop}`.
    pub fn enrollment(&self) -> (i64, Vec<u8>, Value) {
        (self.identifier, self.verification_share.clone(), self.pop.clone())
    }

    fn is_spent(&self, sid: &str) -> Result<bool, String> {
        if self.spent.lock().unwrap().contains(sid) {
            return Ok(true);
        }
        match &self.store {
            Some(s) => s.is_spent(sid),
            None => Ok(false),
        }
    }

    /// Round 1: a fresh nonce pair kept in the session (and the store) and the commitment with the proof of possession.
    pub fn round1(&self, req: &Value) -> Value {
        let no = |reason: String| json!({"ok": false, "identifier": self.identifier, "reason": reason});
        let run = || -> Result<Value, String> {
            let sid = req.get("session_id").and_then(Value::as_str).filter(|s| !s.is_empty());
            let sid = match (req.get("typ") == Some(&json!("pca.frost.round1.v1")), sid) {
                (true, Some(s)) if req.is_object() => s,
                _ => return Ok(no("malformed round-1 request".into())),
            };
            if self.is_spent(sid)? {
                return Ok(no("session already signed".into()));
            }
            let live = self.sessions.lock().unwrap().contains_key(sid);
            if live || self.store.as_ref().map_or(Ok(false), |s| s.load(sid).map(|r| r.is_some()))? {
                return Ok(no("duplicate round-1 for session".into()));
            }
            let me = FrostParticipantShare { identifier: self.identifier, share: self.share.clone(), public_key: self.verification_share.clone() };
            let (hr, br) = ((self.random)(32), (self.random)(32));
            let c = frost_commit(&me, Some(&hr), Some(&br))?;
            let created_at = (self.now)();
            if let Some(s) = &self.store {
                s.create(
                    sid,
                    &NonceRecord {
                        hiding: c.hiding_nonce.clone(),
                        binding: c.binding_nonce.clone(),
                        hiding_commitment: c.commitment.hiding.clone(),
                        binding_commitment: c.commitment.binding.clone(),
                        created_at,
                    },
                )?;
            }
            let wire = encode_commitment(&c.commitment);
            self.sessions.lock().unwrap().insert(
                sid.to_string(),
                Session { nonces: FrostNonces { hiding: c.hiding_nonce, binding: c.binding_nonce }, commitment: c.commitment, created_at },
            );
            Ok(json!({"ok": true, "identifier": self.identifier, "commitment": wire, "pop": self.pop}))
        };
        run().unwrap_or_else(|e| no(if e.is_empty() { "round-1 error".to_string() } else { e }))
    }

    /// Round 2: this signer's signature share, or a refusal (`{ok: false, identifier, refused: true, reason}`).
    pub fn round2(&self, req: &Value) -> Value {
        let refuse = |reason: String| json!({"ok": false, "identifier": self.identifier, "refused": true, "reason": reason});
        let run = || -> Result<Result<Value, String>, String> {
            let sid = req.get("session_id").and_then(Value::as_str);
            let sid = match (req.is_object() && req.get("typ") == Some(&json!("pca.frost.round2.v1")), sid) {
                (true, Some(s)) => s,
                _ => return Ok(Err("malformed round-2 request".into())),
            };
            if self.is_spent(sid)? {
                return Ok(Err("session already signed (one-shot)".into()));
            }
            let in_memory = self.sessions.lock().unwrap().contains_key(sid);
            if !in_memory {
                if let Some(store) = &self.store {
                    if let Some(rec) = store.load(sid)? {
                        let state = Session {
                            nonces: FrostNonces { hiding: rec.hiding, binding: rec.binding },
                            commitment: FrostCommitment { identifier: self.identifier, hiding: rec.hiding_commitment, binding: rec.binding_commitment },
                            created_at: rec.created_at,
                        };
                        self.sessions.lock().unwrap().insert(sid.to_string(), state);
                    }
                }
            }
            let (nonces, own_commitment, created_at) = match self.sessions.lock().unwrap().get(sid) {
                Some(s) => (FrostNonces { hiding: s.nonces.hiding.clone(), binding: s.nonces.binding.clone() }, s.commitment.clone(), s.created_at),
                None => return Ok(Err("no round-1 state for this session".into())),
            };
            if let Some(ttl) = self.ttl {
                let age = (self.now)() - created_at;
                if !(age.is_finite() && age <= ttl) {
                    self.sessions.lock().unwrap().remove(sid);
                    if let Some(s) = &self.store {
                        s.drop_session(sid)?;
                    }
                    return Ok(Err(format!("session expired (stale-session guard: round-1 older than {}ms)", crate::intent_v2::js_number_string(ttl))));
                }
            }
            let Some(message) = req.get("message").and_then(Value::as_str).and_then(|m| decode_b64u_strict(m, None)) else {
                return Ok(Err("message not canonical base64url".into()));
            };
            if req.get("group_pk").and_then(Value::as_str) != Some(b64_encode(&self.gpk).as_str()) {
                return Ok(Err("request names a different group key".into()));
            }
            let allow = verify_allow_token(
                req.get("allow").unwrap_or(&Value::Null),
                &VerifyAllowExpect {
                    policy_authority_public_key: Some(&self.policy),
                    group_public_key: Some(&self.gpk),
                    message: Some(&message),
                    now: JsNum::Num((self.now)()),
                    canonical: self.canonical,
                },
            );
            if allow["ok"] != json!(true) {
                return Ok(Err(format!("policy authorization failed: {}", allow["reason"].as_str().unwrap_or(""))));
            }
            let wire_commitments = req.get("commitments").filter(|c| !c.is_null()).cloned().unwrap_or_else(|| json!([]));
            let commitments = decode_commitments(&wire_commitments)?;
            if (commitments.len() as i64) < self.threshold {
                return Ok(Err(format!("signing set below threshold t={}", self.threshold)));
            }
            let Some(own) = commitments.iter().find(|c| c.identifier == self.identifier) else {
                return Ok(Err("our commitment is not in the signing set".into()));
            };
            if own.hiding != own_commitment.hiding || own.binding != own_commitment.binding {
                return Ok(Err("equivocation detected: our commitment in the signing set differs from our round-1 commitment".into()));
            }
            let vshares = decode_verification_shares(req.get("verification_shares").unwrap_or(&Value::Null))?;
            if let Some(s) = &self.store {
                s.spend(sid)?;
            }
            let opts = FrostSignOpts {
                threshold: Some(self.threshold),
                verification_share: Some(self.verification_share.clone()),
                verification_shares: Some(vshares),
            };
            let sig = frost_sign(self.identifier, &self.share, &self.gpk, &nonces, &message, &commitments, &opts)?;
            self.sessions.lock().unwrap().remove(sid);
            self.spent.lock().unwrap().insert(sid.to_string());
            Ok(Ok(json!({"ok": true, "identifier": self.identifier, "sig_share": b64_encode(&sig.sig_share)})))
        };
        match run() {
            Ok(Ok(v)) => v,
            Ok(Err(reason)) | Err(reason) => refuse(if reason.is_empty() { "round-2 error".to_string() } else { reason }),
        }
    }
}

// ---- coordinator -----------------------------------------------------------------------------------------------------------------

/// A signer as the coordinator reaches it: a request in, the wire response out; `Err` is an unreachable signer (counted as a refusal).
pub trait SignerTransport: Send + Sync {
    fn identifier(&self) -> i64;
    fn round1(&self, req: &Value) -> Result<Value, String>;
    fn round2(&self, req: &Value) -> Result<Value, String>;
}

/// An in-process transport over a service.
pub struct InProcessTransport(pub Arc<GuardianSignerService>);

impl SignerTransport for InProcessTransport {
    fn identifier(&self) -> i64 {
        self.0.identifier
    }
    fn round1(&self, req: &Value) -> Result<Value, String> {
        Ok(self.0.round1(req))
    }
    fn round2(&self, req: &Value) -> Result<Value, String> {
        Ok(self.0.round2(req))
    }
}

/// The result of a signing session.
pub struct SignOutput {
    pub signature: Vec<u8>,
    pub session_id: String,
    /// The identifiers of the signing set, as the commitments carried them.
    pub signers: Vec<Value>,
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

/// Drives two-round FROST signing across signer transports.
pub struct NetworkCoordinator {
    gpk: Vec<u8>,
    threshold: i64,
    signers: Vec<Arc<dyn SignerTransport>>,
    vshares: Vec<(i64, Vec<u8>)>,
    pk_by_id: HashMap<i64, String>,
    equivocation: Mutex<EquivocationGuard>,
    new_session_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
    timeout_ms: Option<f64>,
}

impl NetworkCoordinator {
    /// Build the coordinator. The verification shares come from `enroll` (each with its proof of possession) or are given directly. A
    /// constructor `timeout_ms` bounds every session; `new_session_id` mints session ids.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_public_key: Option<&[u8]>,
        threshold: &Value,
        signers: Vec<Arc<dyn SignerTransport>>,
        verification_shares: Option<Vec<(i64, Vec<u8>)>>,
        enroll: Option<Option<&[EnrollmentIn]>>,
        timeout_ms: JsNum,
        new_session_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
    ) -> Result<Self, FrostNetError> {
        let gpk = group_public_key.filter(|g| g.len() == 32).ok_or_else(|| msg("NetworkCoordinator: groupPublicKey must be 32 bytes"))?;
        let threshold = threshold.as_f64().filter(|t| threshold.is_number() && t.fract() == 0.0 && *t >= 1.0 && *t <= MAX_SAFE);
        let threshold = threshold.ok_or_else(|| msg("NetworkCoordinator: threshold must be a positive integer"))? as i64;
        let timeout = match timeout_ms {
            JsNum::Undefined => None,
            JsNum::Num(t) if t.is_finite() && t > 0.0 => Some(t),
            _ => return Err(msg("NetworkCoordinator: timeoutMs must be a positive finite number")),
        };
        let vshares = match (enroll, verification_shares) {
            (Some(e), _) => enroll_verification_shares(e, Some(gpk))?,
            (None, Some(v)) => v,
            (None, None) => return Err(msg("NetworkCoordinator: provide verificationShares or enroll")),
        };
        let pk_by_id = vshares.iter().map(|(i, pk)| (*i, b64_encode(pk))).collect();
        Ok(NetworkCoordinator {
            gpk: gpk.to_vec(),
            threshold,
            signers,
            vshares,
            pk_by_id,
            equivocation: Mutex::new(EquivocationGuard::new()),
            new_session_id,
            timeout_ms: timeout,
        })
    }

    /// Sign `message` under the allow token `allow` with the signers `signer_ids` (default: the first t). A call `timeout_ms` (or the
    /// constructor's) bounds the whole session; NaN, infinity or a non-positive window means no deadline. A timed-out session fails with
    /// [`FrostNetError::Timeout`] and a late signer response is ignored.
    pub fn sign(
        self: &Arc<Self>,
        message: Option<&[u8]>,
        allow: &Value,
        signer_ids: Option<&[Value]>,
        timeout_ms: JsNum,
    ) -> Result<SignOutput, FrostNetError> {
        let window = match timeout_ms {
            JsNum::Undefined => self.timeout_ms.map_or(JsNum::Undefined, JsNum::Num),
            other => other,
        };
        let deadline = match window {
            JsNum::Num(w) if w > 0.0 && w < f64::INFINITY => Some(w),
            _ => None,
        };
        let Some(window) = deadline else { return self.drive(message, allow, signer_ids) };
        let (tx, rx) = mpsc::channel();
        let me = Arc::clone(self);
        let (message, allow, ids) = (message.map(<[u8]>::to_vec), allow.clone(), signer_ids.map(<[Value]>::to_vec));
        std::thread::spawn(move || {
            let _ = tx.send(me.drive(message.as_deref(), &allow, ids.as_deref()));
        });
        match rx.recv_timeout(Duration::from_secs_f64((window / 1000.0).min(3.0e9))) {
            Ok(r) => r,
            Err(_) => Err(FrostNetError::Timeout {
                message: format!("coordinator: signing session did not reach threshold within {}ms", crate::intent_v2::js_number_string(window)),
                timeout_ms: window,
                refusals: Vec::new(),
            }),
        }
    }

    fn call(f: &dyn Fn() -> Result<Value, String>, identifier: i64, refused: bool) -> Value {
        match f() {
            Ok(v) => v,
            Err(e) => {
                let mut out = json!({"ok": false, "identifier": identifier});
                if refused {
                    out["refused"] = json!(true);
                }
                out["reason"] = json!(if e.is_empty() { "unreachable".to_string() } else { e });
                out
            }
        }
    }

    /// Equivocation-check a response member; an absent member is not canonical (the reference throws on `undefined`).
    fn observe(&self, sid: &str, round: i64, rid: &Value, message: Option<&Value>) -> Result<(), String> {
        let Some(message) = message else { return Err("equivocation check failed".into()) };
        match self.equivocation.lock().unwrap().observe(&json!(sid), &json!(round), rid, message) {
            Ok(()) => Ok(()),
            Err(FrostNetError::Equivocation { message, .. }) => Err(message),
            Err(_) => Err("equivocation check failed".into()),
        }
    }

    fn drive(&self, message: Option<&[u8]>, allow: &Value, signer_ids: Option<&[Value]>) -> Result<SignOutput, FrostNetError> {
        let message = message.ok_or_else(|| msg("coordinator.sign: message must be bytes"))?;
        let chosen: Vec<Arc<dyn SignerTransport>> = match signer_ids {
            Some(ids) => self.signers.iter().filter(|s| ids.iter().any(|i| id_of(i) == Some(s.identifier()))).cloned().collect(),
            None => self.signers.iter().take(self.threshold as usize).cloned().collect(),
        };
        if (chosen.len() as i64) < self.threshold {
            return Err(FrostNetError::Coordinator {
                message: format!("coordinator: only {} signer(s) selected, need t={}", chosen.len(), self.threshold),
                refusals: Vec::new(),
            });
        }
        let sid = (self.new_session_id)().map_err(msg)?;
        let req1 = json!({"typ": "pca.frost.round1.v1", "session_id": sid});
        let r1: Vec<Value> = std::thread::scope(|sc| {
            let hs: Vec<_> = chosen.iter().map(|s| sc.spawn(|| Self::call(&|| s.round1(&req1), s.identifier(), false))).collect();
            hs.into_iter().map(|h| h.join().unwrap_or_else(|_| json!({"ok": false, "reason": "unreachable"}))).collect()
        });
        let mut refusals: Vec<Value> = Vec::new();
        let mut committed: Vec<(Arc<dyn SignerTransport>, Value)> = Vec::new();
        for (s, resp) in chosen.iter().zip(&r1) {
            if !truthy(resp.get("ok")) {
                refusals.push(json!({"identifier": resp.get("identifier").cloned().unwrap_or(Value::Null), "reason": resp.get("reason").cloned().unwrap_or(Value::Null)}));
                continue;
            }
            let rid = resp.get("identifier").cloned().unwrap_or(Value::Null);
            let expected = id_of(&rid).and_then(|i| self.pk_by_id.get(&i));
            let Some(expected) = expected else {
                refusals.push(json!({"identifier": rid, "reason": "no verification share on record for this signer"}));
                continue;
            };
            let pop = resp.get("pop").cloned().unwrap_or(Value::Null);
            if !pop.is_object() || pop.get("identifier") != Some(&rid) || pop.get("publicKey").and_then(Value::as_str) != Some(expected.as_str()) || !verify_signer_pop(&pop, Some(&self.gpk)) {
                refusals.push(json!({"identifier": rid, "reason": "invalid or missing proof-of-possession (rogue-key defense)"}));
                continue;
            }
            if let Err(reason) = self.observe(&sid, 1, &rid, resp.get("commitment")) {
                refusals.push(json!({"identifier": rid, "reason": reason}));
                continue;
            }
            committed.push((Arc::clone(s), resp["commitment"].clone()));
        }
        if (committed.len() as i64) < self.threshold {
            return Err(FrostNetError::Coordinator {
                message: format!("coordinator: round 1 produced {} commitment(s), need t={}", committed.len(), self.threshold),
                refusals,
            });
        }
        let chosen_set: Vec<&(Arc<dyn SignerTransport>, Value)> = committed.iter().take(self.threshold as usize).collect();
        let commitments: Vec<Value> = chosen_set.iter().map(|(_, c)| c.clone()).collect();
        let set_ids: Vec<Option<i64>> = commitments.iter().map(|c| c.get("identifier").and_then(id_of)).collect();
        let vshares: Vec<Value> =
            self.vshares.iter().filter(|(i, _)| set_ids.contains(&Some(*i))).map(|(i, pk)| json!({"identifier": i, "publicKey": b64_encode(pk)})).collect();
        if vshares.len() != chosen_set.len() {
            return Err(FrostNetError::Coordinator { message: "coordinator: missing a verification share for a signer in the set".into(), refusals: Vec::new() });
        }
        let req2 = json!({
            "typ": "pca.frost.round2.v1", "session_id": sid, "message": b64_encode(message), "group_pk": b64_encode(&self.gpk),
            "commitments": commitments, "verification_shares": vshares, "allow": allow,
        });
        let r2: Vec<Value> = std::thread::scope(|sc| {
            let hs: Vec<_> = chosen_set.iter().map(|(s, _)| sc.spawn(|| Self::call(&|| s.round2(&req2), s.identifier(), true))).collect();
            hs.into_iter().map(|h| h.join().unwrap_or_else(|_| json!({"ok": false, "refused": true, "reason": "unreachable"}))).collect()
        });
        let mut shares: Vec<FrostSigShare> = Vec::new();
        for resp in &r2 {
            if !truthy(resp.get("ok")) {
                refusals.push(json!({"identifier": resp.get("identifier").cloned().unwrap_or(Value::Null), "reason": resp.get("reason").cloned().unwrap_or(Value::Null)}));
                continue;
            }
            let rid = resp.get("identifier").cloned().unwrap_or(Value::Null);
            let sig_share = resp.get("sig_share").cloned();
            let observed = match &sig_share {
                Some(s) => self.observe(&sid, 2, &rid, Some(&json!({"sig_share": s}))),
                None => Err("equivocation check failed".to_string()),
            };
            if let Err(reason) = observed {
                refusals.push(json!({"identifier": rid, "reason": reason}));
                continue;
            }
            let sb = sig_share.as_ref().and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, Some(32)));
            match (sb, id_of(&rid)) {
                (Some(sb), Some(i)) => shares.push(FrostSigShare { identifier: i, sig_share: sb }),
                _ => refusals.push(json!({"identifier": rid, "reason": "malformed signature share"})),
            }
        }
        if (shares.len() as i64) < self.threshold {
            return Err(FrostNetError::Coordinator {
                message: format!("coordinator: round 2 produced {} share(s), need t={}", shares.len(), self.threshold),
                refusals,
            });
        }
        let agg_commitments: Vec<FrostCommitment> = commitments.iter().map(decode_commitment).collect::<Result<_, _>>().map_err(msg)?;
        let agg_shares: Vec<FrostVerificationShare> =
            self.vshares.iter().filter(|(i, _)| set_ids.contains(&Some(*i))).map(|(i, pk)| FrostVerificationShare { identifier: *i, public_key: pk.clone() }).collect();
        let signature = frost_aggregate(message, &agg_commitments, &shares, &self.gpk, Some(&agg_shares), Some(self.threshold)).map_err(msg)?;
        Ok(SignOutput { signature, session_id: sid, signers: commitments.iter().map(|c| c.get("identifier").cloned().unwrap_or(Value::Null)).collect() })
    }
}
