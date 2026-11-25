//! BLS12-381 signatures with aggregation (proof-of-possession ciphersuite), on the audited `blst` library: public keys in G1
//! (48 bytes), signatures in G2 (96 bytes), the rogue-key-safe key registry, the BLS capability chain and the transparency
//! witness cosignatures (the `@atlasauth/pca-aggsig` surface).
//!
//! Rogue-key safety by construction: [`aggregate_verify`] and [`fast_aggregate_verify`] only accept [`RegisteredKey`]s, whose
//! constructor is private to this module and only reachable through [`register_key`] / [`KeyRegistry::register`], and both run
//! KeyValidate plus a proof-of-possession check first. Every deserialized point is subgroup-checked and re-encoded (canonical
//! encodings only); every verification fails closed.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Hash-to-curve domain separation tag for signatures.
pub const SIG_DST: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Distinct tag for proofs of possession (a PoP can never be replayed as a message signature).
pub const POP_DST: &str = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const PUBLIC_KEY_LENGTH: usize = 48;
pub const SIGNATURE_LENGTH: usize = 96;
/// The suite tag every BLS capability hop and cosignature carries.
pub const BLS_SUITE: &str = "bls12-381-pop";
/// Longest delegation chain accepted.
pub const MAX_CHAIN_DEPTH: usize = 16;

const CAP_BLS_DOMAIN: &[u8] = b"atlas-pca/cap-bls/v1\0";
const STH_WITNESS_BLS_DOMAIN: &[u8] = b"atlas-pca/sth-witness-bls/v1\0";

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64u(s: &str) -> Option<Vec<u8>> {
    crate::decode_b64u_strict(s, None)
}

fn is_compressed(b: &[u8], n: usize) -> bool {
    b.len() == n && b[0] & 0x80 != 0
}

fn pk_of(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::uncompress(bytes).ok()
}

fn sig_of(bytes: &[u8]) -> Option<Signature> {
    Signature::uncompress(bytes).ok()
}

/// A 96-byte compressed G2 point whose bytes are exactly the re-encoding of the point they decode to (one accepted encoding
/// per signature). The subgroup check happens where the signature is used.
pub fn is_canonical_signature(sig: &[u8]) -> bool {
    is_compressed(sig, SIGNATURE_LENGTH) && sig_of(sig).is_some_and(|s| s.compress().as_slice() == sig)
}

/// KeyValidate: a canonical compressed G1 point, not the identity, in the prime-order subgroup. Never panics.
pub fn key_validate(public_key: &[u8]) -> bool {
    if !is_compressed(public_key, PUBLIC_KEY_LENGTH) {
        return false;
    }
    match PublicKey::key_validate(public_key) {
        Ok(p) => p.compress().as_slice() == public_key,
        Err(_) => false,
    }
}

fn secret_of(sk: &[u8]) -> Result<SecretKey, String> {
    if sk.len() != 32 {
        return Err("invalid private key: expected 32 bytes".into());
    }
    // refuses 0 and values >= r
    SecretKey::from_bytes(sk).map_err(|_| "invalid private key: expected 1 <= n < r".to_string())
}

/// The compressed G1 public key of a 32-byte big-endian secret scalar.
pub fn public_key_of(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    Ok(secret_of(secret_key)?.sk_to_pk().compress().to_vec())
}

/// A fresh key pair `(secret, public)`; refuses the degenerate scalar 1 (a stuck-at-zero entropy source).
pub fn key_gen() -> Result<(Vec<u8>, Vec<u8>), String> {
    loop {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| format!("keyGen: {e}"))?;
        b[0] &= 0x7f; // < 2^255; r is just under 2^255, so most draws are in range and the rest retry
        if secret_of(&b).is_err() {
            continue;
        }
        let mut one = [0u8; 32];
        one[31] = 1;
        if b == one {
            return Err("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue".into());
        }
        let pk = public_key_of(&b)?;
        return Ok((b.to_vec(), pk));
    }
}

fn sign_with(secret_key: &[u8], msg: &[u8], dst: &str) -> Result<Vec<u8>, String> {
    // blst signs in constant time with respect to the scalar
    Ok(secret_of(secret_key)?.sign(msg, dst.as_bytes(), &[]).compress().to_vec())
}

/// CoreSign: H(msg) in G2 under [`SIG_DST`] times the secret scalar.
pub fn sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    sign_with(secret_key, msg, SIG_DST)
}

fn verify_with(public_key: &[u8], msg: &[u8], sig: &[u8], dst: &str) -> bool {
    if !is_canonical_signature(sig) || !key_validate(public_key) {
        return false;
    }
    let (Some(p), Some(s)) = (pk_of(public_key), sig_of(sig)) else { return false };
    // signature subgroup-checked; the key was just KeyValidate'd
    s.verify(true, msg, dst.as_bytes(), &[], &p, false) == BLST_ERROR::BLST_SUCCESS
}

/// CoreVerify of one signature. Never panics.
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_with(public_key, msg, sig, SIG_DST)
}

/// Sum G2 signatures into one 96-byte aggregate (order independent); at least one is required.
pub fn aggregate(sigs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if sigs.is_empty() {
        return Err("aggregate: need at least one signature".into());
    }
    let mut ps = Vec::with_capacity(sigs.len());
    for sg in sigs {
        if !is_canonical_signature(sg) {
            return Err("aggregate: every signature must be a 96-byte compressed G2 point".into());
        }
        ps.push(sig_of(sg).ok_or("aggregate: bad signature")?);
    }
    let refs: Vec<&Signature> = ps.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true).map_err(|_| "aggregate: a signature is not in the prime-order subgroup".to_string())?;
    Ok(agg.to_signature().compress().to_vec())
}

/// Sum G1 public keys into one 48-byte key.
pub fn aggregate_public_keys(public_keys: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if public_keys.is_empty() {
        return Err("aggregatePublicKeys: need at least one key".into());
    }
    let mut ps = Vec::with_capacity(public_keys.len());
    for pk in public_keys {
        if !is_compressed(pk, PUBLIC_KEY_LENGTH) {
            return Err("aggregatePublicKeys: bad key".into());
        }
        ps.push(pk_of(pk).ok_or("aggregatePublicKeys: bad key")?);
    }
    let refs: Vec<&PublicKey> = ps.iter().collect();
    let agg = AggregatePublicKey::aggregate(&refs, true).map_err(|_| "aggregatePublicKeys: a key is not in the prime-order subgroup".to_string())?;
    Ok(agg.to_public_key().compress().to_vec())
}

/// PopProve: sign one's own public key under [`POP_DST`].
pub fn pop_prove(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let pk = public_key_of(secret_key)?;
    sign_with(secret_key, &pk, POP_DST)
}

/// PopVerify: `pop` is a valid PoP-DST signature by `public_key` over `public_key`. Never panics.
pub fn pop_verify(public_key: &[u8], pop: &[u8]) -> bool {
    verify_with(public_key, public_key, pop, POP_DST)
}

fn distinct<T: std::hash::Hash + Eq>(xs: impl IntoIterator<Item = T>) -> bool {
    let mut seen = HashSet::new();
    xs.into_iter().all(|x| seen.insert(x))
}

fn raw_aggregate_verify(pks: &[Vec<u8>], msgs: &[Vec<u8>], agg_sig: &[u8]) -> bool {
    if !is_canonical_signature(agg_sig) || pks.is_empty() || pks.len() != msgs.len() || !distinct(msgs.iter()) {
        return false;
    }
    let mut ps = Vec::with_capacity(pks.len());
    for pk in pks {
        if !key_validate(pk) {
            return false;
        }
        match pk_of(pk) {
            Some(p) => ps.push(p),
            None => return false,
        }
    }
    let Some(s) = sig_of(agg_sig) else { return false };
    let pr: Vec<&PublicKey> = ps.iter().collect();
    let mr: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    s.aggregate_verify(true, &mr, SIG_DST.as_bytes(), &pr, false) == BLST_ERROR::BLST_SUCCESS
}

fn raw_fast_aggregate_verify(pks: &[Vec<u8>], msg: &[u8], agg_sig: &[u8]) -> bool {
    if !is_canonical_signature(agg_sig) || pks.is_empty() || !pks.iter().all(|p| key_validate(p)) {
        return false;
    }
    // the aggregate must itself pass KeyValidate: {P, -P} sums to the identity, for which the identity "signature" verifies anything
    match aggregate_public_keys(pks) {
        Ok(agg) if key_validate(&agg) => verify_with(&agg, msg, agg_sig, SIG_DST),
        _ => false,
    }
}

/// A public key whose proof of possession was verified. Only [`register_key`] and [`KeyRegistry::register`] produce one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredKey {
    bytes: [u8; PUBLIC_KEY_LENGTH],
}

impl RegisteredKey {
    /// The 48-byte compressed key.
    pub fn bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.bytes
    }
}

/// Admit a key: it must pass KeyValidate and carry a valid PoP. The error text is the refusal reason.
pub fn register_key(public_key: &[u8], pop: &[u8]) -> Result<RegisteredKey, String> {
    if !key_validate(public_key) {
        return Err("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)".into());
    }
    if pop.len() != SIGNATURE_LENGTH {
        return Err("proof of possession is not a 96-byte compressed G2 signature".into());
    }
    if !pop_verify(public_key, pop) {
        return Err("proof of possession does not verify for this key".into());
    }
    let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
    bytes.copy_from_slice(public_key);
    Ok(RegisteredKey { bytes })
}

/// A verifier's pinned set of admitted keys, indexed by key bytes.
#[derive(Default, Debug)]
pub struct KeyRegistry {
    keys: HashMap<Vec<u8>, RegisteredKey>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify the PoP and admit the key (idempotent).
    pub fn register(&mut self, public_key: &[u8], pop: &[u8]) -> Result<RegisteredKey, String> {
        let k = register_key(public_key, pop)?;
        self.keys.insert(public_key.to_vec(), k.clone());
        Ok(k)
    }

    /// The registered key for these bytes, or `None` if it was never admitted.
    pub fn get(&self, public_key: &[u8]) -> Option<&RegisteredKey> {
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return None;
        }
        self.keys.get(public_key)
    }

    pub fn has(&self, public_key: &[u8]) -> bool {
        self.get(public_key).is_some()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn raw_of(keys: &[RegisteredKey]) -> Vec<Vec<u8>> {
    keys.iter().map(|k| k.bytes.to_vec()).collect()
}

/// AggregateVerify over distinct messages, registered keys only. Never panics; `false` on any failure.
pub fn aggregate_verify(keys: &[RegisteredKey], msgs: &[Vec<u8>], agg_sig: &[u8]) -> bool {
    !keys.is_empty() && raw_aggregate_verify(&raw_of(keys), msgs, agg_sig)
}

/// FastAggregateVerify (one message, many signers), registered keys only; a signer may not be counted twice.
pub fn fast_aggregate_verify(keys: &[RegisteredKey], msg: &[u8], agg_sig: &[u8]) -> bool {
    !keys.is_empty() && distinct(keys.iter().map(|k| k.bytes)) && raw_fast_aggregate_verify(&raw_of(keys), msg, agg_sig)
}

// ---- capability chain ------------------------------------------------------------------------------------------------

fn body_of(c: &Map<String, Value>) -> Value {
    let mut m = Map::new();
    for k in ["issuer", "holder", "caveats"] {
        m.insert(k.into(), c.get(k).cloned().unwrap_or(Value::Null));
    }
    m.insert("parent".into(), c.get("parent").cloned().unwrap_or(Value::Null));
    Value::Object(m)
}

fn sig_message(body_digest: &str) -> Result<Vec<u8>, String> {
    let d = unb64u(body_digest).ok_or("bad body digest")?;
    Ok([CAP_BLS_DOMAIN, &d].concat())
}

/// The identity of a capability: the strict hash of everything except `sig`.
pub fn cap_hash(c: &Value) -> Result<String, String> {
    let mut rest = c.as_object().ok_or("capability must be an object")?.clone();
    rest.remove("sig");
    crate::hash_canonical_strict(&Value::Object(rest)).ok_or_else(|| "capability is outside the canonical profile".to_string())
}

fn clone_caveats(cs: &Value) -> Result<Vec<Value>, String> {
    let s = crate::canonicalize_strict(cs)?;
    match serde_json::from_str::<Value>(&s) {
        Ok(Value::Array(a)) => Ok(a),
        _ => Err("caveats must be an array".into()),
    }
}

fn seal(issuer: &str, holder: &str, caveats: Vec<Value>, parent: Option<String>, signer: &[u8]) -> Result<Value, String> {
    let mut body = Map::new();
    body.insert("issuer".into(), issuer.into());
    body.insert("holder".into(), holder.into());
    body.insert("caveats".into(), Value::Array(caveats.clone()));
    body.insert("parent".into(), parent.clone().map_or(Value::Null, Value::String));
    let digest = crate::hash_canonical_strict(&Value::Object(body)).ok_or("capability body is outside the canonical profile")?;
    let sig = sign(signer, &sig_message(&digest)?)?;
    let mut cap = Map::new();
    cap.insert("id".into(), digest.clone().into());
    cap.insert("issuer".into(), issuer.into());
    cap.insert("holder".into(), holder.into());
    cap.insert("caveats".into(), Value::Array(caveats));
    if let Some(p) = parent {
        cap.insert("parent".into(), p.into());
    }
    cap.insert("body_digest".into(), digest.into());
    cap.insert("sig".into(), b64u(&sig).into());
    cap.insert("suite".into(), BLS_SUITE.into());
    Ok(Value::Object(cap))
}

/// The b64u BLS G1 public key of a secret scalar: the identity a chain is rooted at / delegated to.
pub fn bls_public_key(secret_key: &[u8]) -> Result<String, String> {
    Ok(b64u(&public_key_of(secret_key)?))
}

/// Mint a root capability, signed by the principal. `caveats` is a JSON array.
pub fn mint_bls_root(principal_secret: &[u8], principal_public: &str, holder: &str, caveats: &Value) -> Result<Value, String> {
    seal(principal_public, holder, clone_caveats(caveats)?, None, principal_secret)
}

/// A child with the SAME holder; caveats = parent.caveats ++ added; signed by the parent's holder.
pub fn bls_attenuate(parent: &Value, added: &Value, signer_secret: &[u8]) -> Result<Value, String> {
    let h = parent.get("holder").and_then(Value::as_str).ok_or("parent has no holder")?;
    bls_delegate(parent, h, added, signer_secret)
}

/// Like [`bls_attenuate`], but rebinds `holder` to a new key.
pub fn bls_delegate(parent: &Value, to_holder: &str, added: &Value, signer_secret: &[u8]) -> Result<Value, String> {
    let issuer = parent.get("holder").and_then(Value::as_str).ok_or("parent has no holder")?;
    let mut caveats = clone_caveats(parent.get("caveats").unwrap_or(&Value::Null))?;
    caveats.extend(clone_caveats(added)?);
    seal(issuer, to_holder, caveats, Some(cap_hash(parent)?), signer_secret)
}

fn well_typed(x: &Value) -> Option<&Map<String, Value>> {
    let c = x.as_object()?;
    for k in ["id", "issuer", "holder", "body_digest", "sig"] {
        c.get(k)?.as_str()?;
    }
    if c.get("suite").and_then(Value::as_str) != Some(BLS_SUITE) {
        return None;
    }
    if let Some(p) = c.get("parent") {
        p.as_str()?;
    }
    for cv in c.get("caveats")?.as_array()? {
        cv.as_object()?.get("type")?.as_str()?;
    }
    Some(c)
}

fn hop_sigs(items: &[Value]) -> Option<Vec<Vec<u8>>> {
    items.iter().map(|h| unb64u(h.as_object()?.get("sig")?.as_str()?)).collect()
}

/// Collapse every per-hop signature of `chain` into one 96-byte aggregate.
pub fn aggregate_chain_signatures(chain: &[Value]) -> Result<Vec<u8>, String> {
    if chain.is_empty() {
        return Err("aggregateChainSignatures: empty chain".into());
    }
    aggregate(&hop_sigs(chain).ok_or("aggregateChainSignatures: hop sig is not valid base64url")?)
}

/// Verify an entire BLS capability chain against one aggregate signature: structure (depth, well-typedness, links,
/// holder-to-issuer continuity, append-only caveats) then ONE AggregateVerify over every hop. Every hop issuer must be in
/// `registry`. `expected_root` pins the root issuer when given. `Err(reason)` on any failure; never panics.
pub fn verify_aggregated_chain(chain: &[Value], agg_sig: &[u8], registry: &KeyRegistry, expected_root: Option<&str>) -> Result<(), String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"));
    }
    let mut caps = Vec::with_capacity(chain.len());
    for (i, h) in chain.iter().enumerate() {
        caps.push(well_typed(h).ok_or_else(|| format!("hop {i}: malformed capability"))?);
    }
    if caps[0].contains_key("parent") {
        return Err("hop 0: root must not have a parent".into());
    }
    let s = |c: &Map<String, Value>, k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(root) = expected_root {
        if s(caps[0], "issuer") != root {
            return Err("hop 0: root issuer is not the expected principal".into());
        }
    }
    let mut pks = Vec::with_capacity(caps.len());
    let mut msgs = Vec::with_capacity(caps.len());
    for (i, c) in caps.iter().enumerate() {
        let digest = crate::hash_canonical_strict(&body_of(c)).ok_or_else(|| format!("hop {i}: malformed body"))?;
        if digest != s(c, "body_digest") || s(c, "id") != s(c, "body_digest") {
            return Err(format!("hop {i}: body digest mismatch"));
        }
        let ib = unb64u(&s(c, "issuer")).ok_or_else(|| format!("hop {i}: malformed issuer key"))?;
        let pk = registry.get(&ib).ok_or_else(|| format!("hop {i}: issuer key has no verified proof of possession (not in the registry)"))?;
        if i > 0 {
            let parent = caps[i - 1];
            let ph = cap_hash(&chain[i - 1]).map_err(|_| format!("hop {i}: broken parent link"))?;
            if c.get("parent").and_then(Value::as_str) != Some(ph.as_str()) {
                return Err(format!("hop {i}: broken parent link"));
            }
            if s(c, "issuer") != s(parent, "holder") {
                return Err(format!("hop {i}: issuer is not the parent's bound holder"));
            }
            let (cc, pc) = (c["caveats"].as_array().unwrap(), parent["caveats"].as_array().unwrap());
            if cc.len() < pc.len() {
                return Err(format!("hop {i}: drops parent caveat(s)"));
            }
            for (j, p) in pc.iter().enumerate() {
                match (crate::hash_canonical_strict(&cc[j]), crate::hash_canonical_strict(p)) {
                    (Some(a), Some(b)) if a == b => {}
                    _ => return Err(format!("hop {i}: caveat {j} altered or reordered")),
                }
            }
        }
        msgs.push(sig_message(&s(c, "body_digest")).map_err(|_| format!("hop {i}: body digest mismatch"))?);
        pks.push(pk.clone());
    }
    // the per-hop sig fields must sum to the aggregate that is verified
    let hs = hop_sigs(chain).ok_or("malformed hop sig")?;
    let sum = aggregate(&hs).map_err(|_| "malformed hop sig".to_string())?;
    if sum != agg_sig {
        return Err("hop sig fields do not sum to the aggregate signature".into());
    }
    if !aggregate_verify(&pks, &msgs, agg_sig) {
        return Err("aggregate signature does not verify over all hops".into());
    }
    Ok(())
}

// ---- witness cosignatures ----------------------------------------------------------------------------------------------

fn witness_message(h: &Value) -> Result<Vec<u8>, String> {
    let o = h.as_object().ok_or("tree head statement must be an object")?;
    let mut m = Map::new();
    for k in ["size", "root", "prev_root"] {
        m.insert(k.into(), o.get(k).cloned().ok_or_else(|| format!("tree head statement lacks {k}"))?);
    }
    m.insert("guardian_epoch".into(), o.get("guardian_epoch").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| 0.into()));
    let body = crate::canonicalize_strict(&Value::Object(m))?;
    Ok([STH_WITNESS_BLS_DOMAIN, body.as_bytes()].concat())
}

/// A trusted witness cosigns the tree-head statement `{size, root, prev_root, guardian_epoch}` with its BLS key.
pub fn cosign_tree_head(statement: &Value, witness_secret: &[u8]) -> Result<Value, String> {
    let msg = witness_message(statement)?;
    let pk = public_key_of(witness_secret)?;
    let sig = sign(witness_secret, &msg)?;
    let mut m = Map::new();
    m.insert("key".into(), b64u(&pk).into());
    m.insert("sig".into(), b64u(&sig).into());
    m.insert("suite".into(), BLS_SUITE.into());
    Ok(Value::Object(m))
}

/// Verify ONE cosignature against the exact statement. Never panics.
pub fn verify_witness_cosignature(statement: &Value, cosig: &Value) -> bool {
    let Some(c) = cosig.as_object() else { return false };
    if c.get("suite").and_then(Value::as_str) != Some(BLS_SUITE) {
        return false;
    }
    let (Some(k), Some(s)) = (c.get("key").and_then(Value::as_str), c.get("sig").and_then(Value::as_str)) else { return false };
    match (unb64u(k), unb64u(s), witness_message(statement)) {
        (Some(k), Some(s), Ok(m)) => verify(&k, &m, &s),
        _ => false,
    }
}

/// Collapse a quorum of cosignatures into one 96-byte aggregate.
pub fn aggregate_witness_cosignatures(cosigs: &[Value]) -> Result<Vec<u8>, String> {
    if cosigs.is_empty() {
        return Err("aggregateWitnessCosignatures: empty set".into());
    }
    aggregate(&hop_sigs(cosigs).ok_or("aggregateWitnessCosignatures: cosignature sig is not valid base64url")?)
}

/// Verify an aggregate over one statement with a single FastAggregateVerify; a witness may appear once.
pub fn verify_aggregated_witness_cosignatures(statement: &Value, witness_keys: &[RegisteredKey], agg_sig: &[u8]) -> bool {
    match witness_message(statement) {
        Ok(m) => fast_aggregate_verify(witness_keys, &m, agg_sig),
        Err(_) => false,
    }
}
