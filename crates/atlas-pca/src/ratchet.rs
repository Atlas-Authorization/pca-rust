//! The PCA Capability Ratchet: puncturable forward-secure one-time capability keys (a GGM tree of Ed25519 leaf keys under a
//! Merkle-root commitment), the verifier-side spent-leaf and attested-risk bindings, the adapters to the PCActn counter and the
//! risk budget, and the homomorphic risk accumulator (Pedersen commitments on ristretto255 with a 32-bit bit-decomposition range
//! proof and a zero-knowledge spend ceiling).
//!
//! JSON-valued API with the reference's camelCase wire members. A BigInt travels as `{"$bigint": "<decimal>"}`. Group and scalar
//! arithmetic is curve25519-dalek's ristretto255 (RFC 9496, constant time); nothing is hand-rolled. Verifiers never fail open:
//! malformed input is `false`. Errors carry the reference's code (`invalid_depth`, `leaf_out_of_range`, ...) when it has one.
use crate::agent::{rand_bytes, KeyPair};
use crate::b64_encode;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hmac::{Hmac, Mac};
use rsa::BigUint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

pub const RATCHET_MAX_DEPTH: usize = 20;
pub const RATCHET_RISK_SCALE: f64 = 1000.0;
/// The range-proof width; the largest provable ceiling is 2^N - 1.
pub const RATCHET_N_BITS: usize = 32;
const MAX_CEILING: u64 = (1u64 << RATCHET_N_BITS) - 1;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A refusal: the reference's `code` when it raises one, plus its message.
#[derive(Debug, Clone, PartialEq)]
pub struct RatchetError {
    pub code: Option<&'static str>,
    pub message: String,
}
impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl From<String> for RatchetError {
    fn from(message: String) -> Self {
        RatchetError { code: None, message }
    }
}
impl From<&str> for RatchetError {
    fn from(m: &str) -> Self {
        RatchetError { code: None, message: m.to_string() }
    }
}
fn coded(code: &'static str, message: impl Into<String>) -> RatchetError {
    RatchetError { code: Some(code), message: message.into() }
}

// ---- JavaScript value helpers --------------------------------------------------------------------------------------------

/// A JS number argument; anything that is not a JSON number (strings, booleans, null, ...) is NaN, which every numeric check refuses.
fn num_of(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

fn is_int(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0
}

/// A BigInt: (negative, magnitude).
type Big = (bool, BigUint);

fn zero() -> BigUint {
    BigUint::from(0u8)
}

/// An integral finite float as a BigInt (exact decimal expansion).
fn big_of_f64(f: f64) -> Result<Big, RatchetError> {
    if !is_int(f) {
        return Err(format!("The number {f} cannot be converted to a BigInt because it is not an integer").into());
    }
    let mag = BigUint::parse_bytes(format!("{:.0}", f.abs()).as_bytes(), 10).ok_or("BigInt")?;
    Ok((f < 0.0, mag))
}

fn digits_ok(s: &str, radix: u32) -> bool {
    !s.is_empty() && s.chars().all(|c| c.to_digit(radix).is_some())
}

/// `{"$bigint": "<decimal>"}` as a BigInt.
fn bigint_value(v: &Value) -> Option<Big> {
    let m = v.as_object()?;
    if m.len() != 1 {
        return None;
    }
    let s = m.get("$bigint")?.as_str()?;
    let (neg, d) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    if !digits_ok(d, 10) {
        return None;
    }
    Some((neg, BigUint::parse_bytes(d.as_bytes(), 10)?))
}

fn big_json(n: &Big) -> Value {
    let s = n.1.to_str_radix(10);
    let s = if n.0 && n.1 != zero() { format!("-{s}") } else { s };
    json!({ "$bigint": s })
}

/// BigInt(x) for a JSON value: a bigint, a boolean, a numeric string or an integral number; everything else is a TypeError.
fn js_bigint(v: &Value) -> Result<Big, String> {
    if let Some(b) = bigint_value(v) {
        return Ok(b);
    }
    match v {
        Value::Bool(b) => Ok((false, BigUint::from(*b as u8))),
        Value::String(s) => {
            let bad = || format!("Cannot convert {s} to a BigInt");
            let t = s.trim();
            if t.is_empty() {
                return Ok((false, zero()));
            }
            let mut radix = 10;
            let mut body = t;
            if t.len() > 2 && t.starts_with('0') {
                radix = match t.as_bytes()[1] {
                    b'x' | b'X' => 16,
                    b'o' | b'O' => 8,
                    b'b' | b'B' => 2,
                    _ => 10,
                };
                if radix != 10 {
                    body = &t[2..];
                }
            }
            let mut neg = false;
            if radix == 10 {
                if let Some(r) = body.strip_prefix('-') {
                    neg = true;
                    body = r;
                } else if let Some(r) = body.strip_prefix('+') {
                    body = r;
                }
            }
            if !digits_ok(body, radix) {
                return Err(bad());
            }
            Ok((neg, BigUint::parse_bytes(body.as_bytes(), radix).ok_or_else(bad)?))
        }
        Value::Number(_) => big_of_f64(num_of(v)).map_err(|e| e.message),
        _ => Err("Cannot convert value to a BigInt".into()),
    }
}

fn le_prefix(n: &BigUint, len: usize) -> Vec<u8> {
    let mut b = n.to_bytes_le();
    b.resize(len.max(b.len()), 0);
    b.truncate(len);
    b
}

/// BigInt.asUintN(64, n).
fn as_u64(n: &Big) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&le_prefix(&n.1, 8));
    let low = u64::from_le_bytes(a);
    if n.0 {
        low.wrapping_neg()
    } else {
        low
    }
}

fn low32(n: &BigUint) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&le_prefix(n, 4));
    u32::from_le_bytes(a)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn be32(n: usize) -> [u8; 4] {
    (n as u32).to_be_bytes()
}

// ---- GGM puncturable PRF tree -------------------------------------------------------------------------------------------------

const GGM_PRG: &[u8] = b"atlas-pca-ratchet/ggm-prg/v1";
const GGM_LEAF_KEY: &[u8] = b"atlas-pca-ratchet/ggm-leafkey/v1";
const GGM_ROOT: &[u8] = b"atlas-pca-ratchet/ggm-root/v1";
const NULLIFIER_DOMAIN: &[u8] = b"atlas-pca-ratchet/nullifier/v1\x00";
const SIG_DOMAIN: &[u8] = b"atlas-pca-ratchet/leaf-sig/v1\x00";
const ATTEST_DOMAIN: &[u8] = b"atlas-pca-ratchet/risk-attestation/v1\x00";

fn hmac(key: &[u8], msg: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for x in msg {
        m.update(x);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&m.finalize().into_bytes());
    o
}

fn ggm_left(seed: &[u8; 32]) -> [u8; 32] {
    hmac(seed, &[GGM_PRG, &[0]])
}
fn ggm_right(seed: &[u8; 32]) -> [u8; 32] {
    hmac(seed, &[GGM_PRG, &[1]])
}
fn leaf_key(leaf_seed: &[u8; 32]) -> KeyPair {
    KeyPair::from_seed(&hmac(leaf_seed, &[GGM_LEAF_KEY]))
}

/// A ratchet: [`sign_at_leaf`] returns the punctured successor; the old state must be dropped (its seeds are wiped on drop).
#[derive(Clone)]
pub struct RatchetState {
    pub depth: usize,
    pub leaf_count: usize,
    pub root_commitment: String,
    pub leaf_pub_keys: Vec<String>,
    /// covering nodes (level, node index) -> seed; the seed signs every leaf under the node
    covering: BTreeMap<(usize, usize), [u8; 32]>,
}
impl Drop for RatchetState {
    fn drop(&mut self) {
        for s in self.covering.values_mut() {
            s.zeroize();
        }
    }
}
impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RatchetState {{ depth: {}, root: {} }}", self.depth, self.root_commitment)
        // never print seeds
    }
}

/// JS semantics: floor(leaf / 2^k) (a fraction still lands in a subtree).
fn covers(level: usize, node: usize, leaf: f64, depth: usize) -> bool {
    let q = leaf / 2f64.powi((depth - level) as i32);
    q.is_finite() && q.floor() == node as f64
}

fn bit_of(level: usize, leaf: usize, depth: usize) -> usize {
    (leaf >> (depth - level - 1)) & 1
}

impl RatchetState {
    fn find_covering(&self, leaf: f64) -> Option<((usize, usize), [u8; 32])> {
        self.covering.iter().find(|((l, n), _)| covers(*l, *n, leaf, self.depth)).map(|(k, s)| (*k, *s))
    }
}

/// Builds a ratchet from >= 32 bytes of entropy and a tree depth in [1, RATCHET_MAX_DEPTH].
pub fn derive_ratchet_root(seed: &[u8], depth: &Value) -> Result<RatchetState, RatchetError> {
    let d = check_depth(depth)?;
    if seed.len() < 32 {
        return Err(coded("invalid_seed", "seed must be a Uint8Array of at least 32 bytes"));
    }
    let d = d as usize;
    let root = hmac(seed, &[GGM_ROOT]);
    let mut pubs = vec![String::new(); 1 << d];
    fn rec(s: &[u8; 32], level: usize, base: usize, d: usize, pubs: &mut [String]) {
        if level == d {
            pubs[base] = leaf_key(s).public.clone();
            return;
        }
        rec(&ggm_left(s), level + 1, base, d, pubs);
        rec(&ggm_right(s), level + 1, base + (1 << (d - level - 1)), d, pubs);
    }
    rec(&root, 0, 0, d, &mut pubs);
    let leaves: Vec<Value> = pubs.iter().cloned().map(Value::String).collect();
    let root_commitment = crate::merkle_root(&leaves)?;
    let mut covering = BTreeMap::new();
    covering.insert((0, 0), root);
    Ok(RatchetState { depth: d, leaf_count: 1 << d, root_commitment, leaf_pub_keys: pubs, covering })
}

fn nullifier_of(root: &str, n: u64) -> String {
    b64_encode(&sha256(&[NULLIFIER_DOMAIN, &be32(root.len()), root.as_bytes(), &n.to_be_bytes()]))
}

/// b64u(sha256(domain || len32(root) || root || index64)): what a verifier records to detect leaf reuse. leafIndex is read as
/// BigInt(leafIndex) reads it.
pub fn leaf_nullifier(root_commitment: &str, leaf_index: &Value) -> Result<String, String> {
    Ok(nullifier_of(root_commitment, as_u64(&js_bigint(leaf_index)?)))
}

fn sig_message(leaf: u64, msg: &[u8]) -> Vec<u8> {
    let mut m = SIG_DOMAIN.to_vec();
    m.extend_from_slice(&leaf.to_be_bytes());
    m.extend_from_slice(msg);
    m
}

/// RFC 6962 audit path of leaf `index`: `{index, size, path: [{side, hash}]}`.
fn merkle_proof(leaves: &[Value], index: usize) -> Result<Value, String> {
    let hs: Vec<Vec<u8>> = leaves.iter().map(crate::leaf_hash).collect::<Option<_>>().ok_or("leaf is outside the strict JSON profile")?;
    let mut path = Vec::new();
    fn prove(hs: &[Vec<u8>], idx: usize, path: &mut Vec<Value>) {
        if hs.len() == 1 {
            return;
        }
        let k = crate::split(hs.len() as u64) as usize;
        if idx < k {
            prove(&hs[..k], idx, path);
            path.push(json!({ "side": "R", "hash": b64_encode(&crate::build(&hs[k..])) }));
        } else {
            prove(&hs[k..], idx - k, path);
            path.push(json!({ "side": "L", "hash": b64_encode(&crate::build(&hs[..k])) }));
        }
    }
    prove(&hs, index, &mut path);
    Ok(json!({ "index": index, "size": leaves.len(), "path": path }))
}

/// Signs `message` at a leaf, then punctures it: the signature `{edSig, leafPubKey, merklePath, nullifier}` and the successor
/// state. `leaf_out_of_range` / `leaf_punctured` refuse.
pub fn sign_at_leaf(state: &RatchetState, leaf_index: &Value, message: &[u8]) -> Result<(Value, RatchetState), RatchetError> {
    let lf = num_of(leaf_index);
    if !is_int(lf) || lf < 0.0 || lf >= state.leaf_count as f64 {
        return Err(coded("leaf_out_of_range", format!("leaf {lf} is out of range [0, {})", state.leaf_count)));
    }
    let leaf = lf as usize;
    let (node, nseed) = state.find_covering(lf).ok_or_else(|| coded("leaf_punctured", format!("leaf {leaf} is already punctured (spent) and cannot sign")))?;
    let mut seed = nseed;
    for level in node.0..state.depth {
        seed = if bit_of(level, leaf, state.depth) == 0 { ggm_left(&seed) } else { ggm_right(&seed) };
    }
    let key = leaf_key(&seed);
    let ed_sig = key.sign(&sig_message(leaf as u64, message));
    let leaves: Vec<Value> = state.leaf_pub_keys.iter().cloned().map(Value::String).collect();
    let mp = merkle_proof(&leaves, leaf)?;
    let nul = nullifier_of(&state.root_commitment, leaf as u64);
    let mut covering = state.covering.clone();
    covering.remove(&node);
    let (mut s, mut idx) = (nseed, node.1);
    for level in node.0..state.depth {
        let bit = bit_of(level, leaf, state.depth);
        let (left, right) = (ggm_left(&s), ggm_right(&s));
        let (sib, next) = if bit == 0 { (right, left) } else { (left, right) };
        covering.insert((level + 1, idx * 2 + (1 - bit)), sib);
        s = next;
        idx = idx * 2 + bit;
    }
    s.zeroize();
    let next = RatchetState {
        depth: state.depth,
        leaf_count: state.leaf_count,
        root_commitment: state.root_commitment.clone(),
        leaf_pub_keys: state.leaf_pub_keys.clone(),
        covering,
    };
    Ok((json!({ "edSig": b64_encode(&ed_sig), "leafPubKey": key.public.clone(), "merklePath": mp, "nullifier": nul }), next))
}

/// Checks a leaf signature offline against the root commitment; malformed input is false.
pub fn verify_leaf_signature(root_commitment: &str, leaf_index: &Value, message: &[u8], signature: &Value) -> bool {
    let Some(sig) = signature.as_object() else { return false };
    let want = match leaf_nullifier(root_commitment, leaf_index) {
        Ok(w) => w,
        Err(_) => return false,
    };
    match sig.get("nullifier").and_then(Value::as_str) {
        Some(n) if !n.is_empty() && n == want => {}
        _ => return false,
    }
    let (Some(ed_sig), Some(pubk), Some(mp)) =
        (sig.get("edSig").and_then(Value::as_str), sig.get("leafPubKey").and_then(Value::as_str), sig.get("merklePath").and_then(Value::as_object))
    else {
        return false;
    };
    let (Some(Value::Number(mi)), Value::Number(li)) = (mp.get("index"), leaf_index) else { return false };
    if mi.as_f64() != li.as_f64() || mi.as_f64().is_none() {
        return false;
    }
    // the root commits under sha256: a proof naming any other hash suite cannot belong to it
    if let Some(hs) = mp.get("hash_suite") {
        if hs != "sha256" {
            return false;
        }
    }
    let Ok(n) = js_bigint(leaf_index) else { return false };
    if !crate::verify_b64u(pubk, &sig_message(as_u64(&n), message), ed_sig) {
        return false;
    }
    crate::verify_inclusion(root_commitment, Some(mp), &Value::String(pubk.to_string()))
}

/// The leaves that can still sign, ascending.
pub fn available_leaves(state: &RatchetState) -> Vec<usize> {
    let mut out = Vec::new();
    for (l, n) in state.covering.keys() {
        let span = 1usize << (state.depth - l);
        out.extend((0..span).map(|i| n * span + i));
    }
    out.sort_unstable();
    out
}

/// A covering node still holds the leaf.
pub fn is_leaf_available(state: &RatchetState, leaf_index: &Value) -> bool {
    state.find_covering(num_of(leaf_index)).is_some()
}

// ---- adapters: ratchet leaf <-> PCActn counter, accumulator units <-> RiskPolicy budget ---------------------------------------

fn check_depth(depth: &Value) -> Result<f64, RatchetError> {
    let d = num_of(depth);
    if !is_int(d) || d < 1.0 || d > RATCHET_MAX_DEPTH as f64 {
        return Err(coded("invalid_depth", format!("depth must be an integer in [1, {RATCHET_MAX_DEPTH}]")));
    }
    Ok(d)
}

fn safe_nonneg(f: f64) -> bool {
    is_int(f) && f.abs() <= MAX_SAFE && f >= 0.0 && !f.is_sign_negative()
}

/// Maps a PCActn counter to a leaf of a depth-`depth` ratchet.
pub fn counter_to_leaf_index(counter: &Value, depth: &Value) -> Result<Value, RatchetError> {
    let d = check_depth(depth)?;
    let c = num_of(counter);
    if !safe_nonneg(c) {
        return Err(coded("leaf_out_of_range", "counter must be a non-negative safe integer"));
    }
    if c >= 2f64.powf(d) {
        return Err(coded("leaf_out_of_range", format!("counter {c} exceeds the ratchet capacity 2^{d}")));
    }
    Ok(json!(c as u64))
}

/// The inverse map.
pub fn leaf_index_to_counter(leaf_index: &Value) -> Result<Value, RatchetError> {
    let f = num_of(leaf_index);
    if !safe_nonneg(f) {
        return Err(coded("leaf_out_of_range", "leafIndex must be a non-negative safe integer"));
    }
    Ok(json!(f as u64))
}

/// [`counter_to_leaf_index`] over a PCActn's counter member.
pub fn leaf_index_for_action(actn: &Value, depth: &Value) -> Result<Value, RatchetError> {
    if actn.is_null() {
        return Err("Cannot read properties of null (reading 'counter')".into());
    }
    counter_to_leaf_index(actn.get("counter").unwrap_or(&Value::Null), depth)
}

fn js_round(v: f64) -> f64 {
    let f = v.floor();
    if v - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn risk_big(f: f64) -> Result<Value, RatchetError> {
    Ok(big_json(&big_of_f64(f)?))
}

/// Quantizes a risk score to integer accumulator units, rounding UP so the sum never under-counts (float noise tolerated).
pub fn risk_to_units(r: &Value) -> Result<Value, RatchetError> {
    let r = num_of(r);
    if !r.is_finite() || r < 0.0 {
        return Err(coded("invalid_value", "risk must be a finite number >= 0"));
    }
    let v = r * RATCHET_RISK_SCALE;
    let nearest = js_round(v);
    if (v - nearest).abs() <= 1e-9 * v.max(1.0) {
        return risk_big(nearest);
    }
    risk_big(v.ceil())
}

/// A carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * scale).
#[derive(Debug, Clone, Default)]
pub struct RiskQuantizer {
    nano: Option<BigUint>,
    emitted: Option<BigUint>,
}
impl RiskQuantizer {
    pub fn new() -> Self {
        Self::default()
    }
    /// Emits the units for one more risk (`{"$bigint": ...}`).
    pub fn next(&mut self, r: &Value) -> Result<Value, RatchetError> {
        let r = num_of(r);
        if !r.is_finite() || r < 0.0 {
            return Err(coded("invalid_value", "risk must be a finite number >= 0"));
        }
        let add = big_of_f64((r * RATCHET_RISK_SCALE * 1e6 - 1e-3).ceil())?;
        let nano = &self.nano.clone().unwrap_or_else(zero) + &add.1;
        let total = &(&nano + &BigUint::from(999_999u32)) / &BigUint::from(1_000_000u32);
        let emitted = self.emitted.clone().unwrap_or_else(zero);
        let out = &total - &emitted;
        self.nano = Some(nano);
        self.emitted = Some(total);
        Ok(big_json(&(false, out)))
    }
    /// The units emitted so far (`{"$bigint": ...}`).
    pub fn total_units(&self) -> Value {
        big_json(&(false, self.emitted.clone().unwrap_or_else(zero)))
    }
}

/// JS ToNumber of a JSON value (shortcut: hex/octal/binary strings and exotic whitespace are NaN, upgrade if a policy ever needs them).
fn js_to_number(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => *b as u8 as f64,
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            match t {
                "" => 0.0,
                "Infinity" | "+Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ if t.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E')) => t.parse().unwrap_or(f64::NAN),
                _ => f64::NAN,
            }
        }
        Value::Array(a) if a.is_empty() => 0.0,
        _ => f64::NAN,
    }
}

/// The accumulator ceiling in units: floor(SafetyBound(bMax, kappa) * scale). Members are read with JS number semantics (a
/// missing or non-numeric bMax refuses; a kappa that is not > 0 gives 0).
pub fn budget_ceiling_units(policy: &Value) -> Result<Value, RatchetError> {
    if policy.is_null() {
        return Err("Cannot read properties of null".into());
    }
    let num = |k: &str| policy.get(k).map(js_to_number).unwrap_or(f64::NAN);
    let bound = crate::risk::safety_bound(num("bMax"), num("kappa"));
    if !bound.is_finite() || bound < 0.0 {
        return Err(coded("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0"));
    }
    risk_big((bound * RATCHET_RISK_SCALE).floor())
}

// ---- spent-leaf store and verifier-side bindings ------------------------------------------------------------------------------------

/// Records the first message signed at each leaf nullifier (first claim wins). A fleet of verifiers shares one.
pub trait SpentLeafStore {
    /// Records `record` under `nullifier` when it is new (`(true, None)`); otherwise returns the record already there.
    fn claim(&self, nullifier: &str, record: &str) -> Result<(bool, Option<String>), String>;
}

/// An in-process [`SpentLeafStore`].
#[derive(Default)]
pub struct MemorySpentLeafStore {
    seen: Mutex<HashMap<String, String>>,
}
impl SpentLeafStore for MemorySpentLeafStore {
    fn claim(&self, nullifier: &str, record: &str) -> Result<(bool, Option<String>), String> {
        let mut m = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = m.get(nullifier) {
            return Ok((false, Some(p.clone())));
        }
        m.insert(nullifier.to_string(), record.to_string());
        Ok((true, None))
    }
}

/// Verifies a leaf signature and enforces one-time use: a second signature at a leaf is replay (same message) or equivocation
/// (different message). Fail closed: a missing or failing store denies with `store-error`. Returns the verdict object
/// `{ok, reason?, nullifier?, firstMessageDigest?, secondMessageDigest?}`.
pub fn verify_leaf_signature_once(root_commitment: &str, leaf_index: &Value, message: &[u8], signature: &Value, store: Option<&dyn SpentLeafStore>) -> Value {
    if !verify_leaf_signature(root_commitment, leaf_index, message, signature) {
        return json!({ "ok": false, "reason": "invalid" });
    }
    let Ok(nul) = leaf_nullifier(root_commitment, leaf_index) else { return json!({ "ok": false, "reason": "invalid" }) };
    let idx = match num_of(leaf_index) {
        f if f.is_finite() => format!("{}", f as i64), // a verified index is a safe integer
        _ => String::new(),
    };
    let mine = format!("{}@{idx}", b64_encode(&sha256(&[message])));
    let Some(store) = store else { return json!({ "ok": false, "reason": "store-error" }) };
    match store.claim(&nul, &mine) {
        Err(_) => json!({ "ok": false, "reason": "store-error" }),
        Ok((true, _)) => json!({ "ok": true }),
        Ok((false, Some(prev))) if prev == mine => json!({ "ok": false, "reason": "replay", "nullifier": nul }),
        Ok((false, prev)) => {
            json!({ "ok": false, "reason": "equivocation", "nullifier": nul, "firstMessageDigest": prev.unwrap_or_default(), "secondMessageDigest": mine })
        }
    }
}

fn attest_message(digest: &str, commitment: &str) -> Vec<u8> {
    let mut o = ATTEST_DOMAIN.to_vec();
    o.extend_from_slice(&be32(digest.len()));
    o.extend_from_slice(digest.as_bytes());
    o.extend_from_slice(&be32(commitment.len()));
    o.extend_from_slice(commitment.as_bytes());
    o
}

/// (risk authority side) Commits to the risk, proves its range and signs (actionDigest, commitment) with the authority's 32-byte
/// Ed25519 seed. Returns `{commitment, blinding, rangeProof, attestation: {actionDigest, sig}}`.
pub fn issue_risk_commitment(risk: &Value, action_digest: &str, authority_secret_key: &[u8]) -> Result<Value, RatchetError> {
    let (commitment, blinding) = commit(risk, None)?;
    let seed: [u8; 32] = authority_secret_key.try_into().map_err(|_| format!("private key of length 32 expected, got {}", authority_secret_key.len()))?;
    let range_proof = prove_range(risk, &blinding)?;
    let sig = KeyPair::from_seed(&seed).sign(&attest_message(action_digest, &commitment));
    Ok(json!({
        "commitment": commitment,
        "blinding": big_json(&(false, big_of_scalar(&blinding))),
        "rangeProof": range_proof,
        "attestation": { "actionDigest": action_digest, "sig": b64_encode(&sig) },
    }))
}

/// Checks the authority signature over (attestation.actionDigest, commitment). Never fails open.
pub fn verify_risk_attestation(commitment: &Value, attestation: &Value, authority_public_key: &Value) -> bool {
    let (Some(c), Some(pk), Some(a)) = (commitment.as_str(), authority_public_key.as_str(), attestation.as_object()) else { return false };
    match (a.get("actionDigest").and_then(Value::as_str), a.get("sig").and_then(Value::as_str)) {
        (Some(d), Some(s)) => crate::verify_b64u(pk, &attest_message(d, c), s),
        _ => false,
    }
}

/// Every item `{commitment, rangeProof, attestation}` carries a valid authority attestation for exactly the expected digest and
/// its commitment, then the bounded-budget proof must hold. Never fails open.
pub fn verify_attested_budget(items: &Value, expected_action_digests: &Value, authority_public_key: &Value, b_max: &Value, budget_proof: &Value) -> bool {
    let (Some(its), Some(ds)) = (items.as_array(), expected_action_digests.as_array()) else { return false };
    if its.len() != ds.len() {
        return false;
    }
    let (mut cs, mut rps) = (Vec::new(), Vec::new());
    for (it, d) in its.iter().zip(ds) {
        let Some(it) = it.as_object() else { return false };
        let Some(att) = it.get("attestation").filter(|a| a.is_object()) else { return false };
        if att.get("actionDigest") != Some(d) || !d.is_string() {
            return false;
        }
        let c = it.get("commitment").cloned().unwrap_or(Value::Null);
        if !verify_risk_attestation(&c, att, authority_public_key) {
            return false;
        }
        cs.push(c);
        rps.push(it.get("rangeProof").cloned().unwrap_or(Value::Null));
    }
    verify_bounded_budget(&Value::Array(cs), &Value::Array(rps), b_max, budget_proof)
}

// ---- ristretto255 group (curve25519-dalek) and the Pedersen generators ---------------------------------------------------------------

fn gen_h() -> &'static RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    H.get_or_init(|| {
        let mut w = [0u8; 64];
        w.copy_from_slice(&Sha512::digest(b"atlas-pca-ratchet/pedersen-generator-H/v1"));
        RistrettoPoint::from_uniform_bytes(&w)
    })
}

/// The encoding of the second Pedersen generator H.
pub fn generator_h_bytes() -> [u8; 32] {
    gen_h().compress().to_bytes()
}

fn pedersen(v: &Scalar, b: &Scalar) -> RistrettoPoint {
    G * v + gen_h() * b
}

fn enc_point(p: &RistrettoPoint) -> String {
    b64_encode(p.compress().as_bytes())
}

fn dec_point(v: &Value) -> Result<RistrettoPoint, String> {
    let raw = v.as_str().and_then(|s| crate::decode_b64u_strict(s, Some(32))).ok_or("decodePoint: not a canonical 32-byte base64url string")?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    CompressedRistretto(a).decompress().ok_or_else(|| "ristretto255: invalid encoding".to_string())
}

fn enc_scalar(k: &Scalar) -> String {
    b64_encode(k.as_bytes())
}

/// Strict: canonical base64url, exactly 32 bytes, value < L (a reduced scalar would make every proof malleable).
fn dec_scalar(v: &Value) -> Result<Scalar, String> {
    let raw = v.as_str().and_then(|s| crate::decode_b64u_strict(s, Some(32))).ok_or("decodeScalar: not a canonical 32-byte base64url string")?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(a)).ok_or_else(|| "decodeScalar: non-canonical scalar (>= L)".to_string())
}

fn order_l() -> BigUint {
    BigUint::parse_bytes(b"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10).expect("L")
}

/// n mod L (n may be negative or wider than 256 bits).
fn scalar_of_big(n: &Big) -> Scalar {
    let mut a = [0u8; 32];
    a.copy_from_slice(&le_prefix(&(&n.1 % &order_l()), 32));
    let k = Scalar::from_bytes_mod_order(a);
    if n.0 {
        -k
    } else {
        k
    }
}

fn big_of_scalar(k: &Scalar) -> BigUint {
    BigUint::from_bytes_le(k.as_bytes())
}

/// A length-prefixed (4-byte big-endian) transcript, SHA-512, reduced mod L.
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update(be32(p.len()));
        h.update(p);
    }
    let mut w = [0u8; 64];
    w.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&w)
}

fn rand_scalar() -> Result<Scalar, String> {
    loop {
        let k = Scalar::from_bytes_mod_order_wide(&rand_bytes::<64>()?);
        if k != Scalar::ZERO {
            return Ok(k);
        }
    }
}

// ---- Pedersen commitments and the range / budget proofs -------------------------------------------------------------------------------

/// A risk / budget: a non-negative bigint or a non-negative integral JSON number.
fn units(x: &Value) -> Result<BigUint, RatchetError> {
    if let Some(b) = bigint_value(x) {
        if b.0 && b.1 != zero() {
            return Err(coded("invalid_value", "risk/budget must be >= 0"));
        }
        return Ok(b.1);
    }
    let f = num_of(x);
    if f.is_finite() && f.fract() == 0.0 && f >= 0.0 {
        return Ok(big_of_f64(f)?.1);
    }
    Err(coded("invalid_value", "risk/budget must be a non-negative integer"))
}

fn blinding_of(v: &Value) -> Result<Scalar, RatchetError> {
    bigint_value(v).map(|b| scalar_of_big(&b)).ok_or_else(|| "Cannot mix BigInt and other types, use explicit conversions".into())
}

fn commit(risk: &Value, blinding: Option<&Value>) -> Result<(String, Scalar), RatchetError> {
    let v = units(risk)?;
    let b = match blinding {
        Some(b) => blinding_of(b)?,
        None => rand_scalar()?,
    };
    Ok((enc_point(&pedersen(&scalar_of_big(&(false, v)), &b)), b))
}

/// Commits to a non-negative integer risk in units; `blinding` None = fresh random. Returns `{commitment, blinding}`.
pub fn commit_risk(risk: &Value, blinding: Option<&Value>) -> Result<Value, RatchetError> {
    let (c, b) = commit(risk, blinding)?;
    Ok(json!({ "commitment": c, "blinding": big_json(&(false, big_of_scalar(&b))) }))
}

/// The homomorphic sum; an empty input commits to (0, 0), the identity.
pub fn add_commitments(commitments: &Value) -> Result<String, String> {
    let list = commitments.as_array().ok_or("commitments is not iterable")?;
    let mut acc = RistrettoPoint::identity();
    for c in list {
        acc += dec_point(c)?;
    }
    Ok(enc_point(&acc))
}

/// commitment == risk*G + blinding*H; malformed input is false.
pub fn open_commitment(commitment: &Value, risk: &Value, blinding: &Value) -> bool {
    let (Ok(v), Some(b)) = (units(risk), bigint_value(blinding)) else { return false };
    dec_point(commitment).is_ok_and(|c| c == pedersen(&scalar_of_big(&(false, v)), &scalar_of_big(&b)))
}

const CTX_DOMAIN: &[u8] = b"atlas-pca-ratchet/budget/ctx/v1";
const RISK_CTX_DOMAIN: &[u8] = b"atlas-pca-ratchet/risk-range/ctx/v1";
const OR_DOMAIN: &[u8] = b"atlas-pca-ratchet/budget/bit-or/v1";
const AGG_DOMAIN: &[u8] = b"atlas-pca-ratchet/budget/agg/v1";

/// A ceiling above the range is clamped: "sum <= 2^N-1" is strictly stronger, so a verifier is never weakened.
fn ceiling_of(b: &BigUint) -> u64 {
    if *b > BigUint::from(MAX_CEILING) {
        MAX_CEILING
    } else {
        le_prefix(b, 8).iter().rev().fold(0u64, |a, x| (a << 8) | *x as u64)
    }
}

type MakeCtx<'a> = &'a dyn Fn(&[RistrettoPoint]) -> [u8; 32];

fn ctx_hash(domain: &[u8], fixed: &[&[u8]], bits: &[RistrettoPoint]) -> [u8; 32] {
    let enc: Vec<[u8; 32]> = bits.iter().map(|b| b.compress().to_bytes()).collect();
    let mut parts: Vec<&[u8]> = vec![domain, &[RATCHET_N_BITS as u8]];
    parts.extend_from_slice(fixed);
    parts.extend(enc.iter().map(|e| e.as_slice()));
    hash_to_scalar(&parts).to_bytes()
}

fn budget_ctx(ceiling: u64, sum: &RistrettoPoint) -> impl Fn(&[RistrettoPoint]) -> [u8; 32] {
    let c = Scalar::from(ceiling).to_bytes();
    let s = sum.compress().to_bytes();
    move |bits| ctx_hash(CTX_DOMAIN, &[&c, &s], bits)
}

fn risk_ctx(c: &RistrettoPoint) -> impl Fn(&[RistrettoPoint]) -> [u8; 32] {
    let c = c.compress().to_bytes();
    move |bits| ctx_hash(RISK_CTX_DOMAIN, &[&c], bits)
}

fn or_hash(ctx: &[u8; 32], index: usize, a0: &RistrettoPoint, a1: &RistrettoPoint) -> Scalar {
    hash_to_scalar(&[OR_DOMAIN, ctx, &[index as u8], a0.compress().as_bytes(), a1.compress().as_bytes()])
}

fn prove_bit(ctx: &[u8; 32], index: usize, b_pt: &RistrettoPoint, bit: u64, s: &Scalar) -> Result<Value, String> {
    let (p0, p1) = (*b_pt, b_pt - G);
    let (e_fake, z_fake) = (rand_scalar()?, rand_scalar()?);
    let p_fake = if bit == 1 { p0 } else { p1 };
    let a_fake = gen_h() * z_fake - p_fake * e_fake;
    let k = rand_scalar()?;
    let a_real = gen_h() * k;
    let (a0, a1) = if bit == 0 { (a_real, a_fake) } else { (a_fake, a_real) };
    let e = or_hash(ctx, index, &a0, &a1);
    let e_real = e - e_fake;
    let z_real = e_real * s + k;
    let (e0, e1, z0, z1) = if bit == 0 { (e_real, e_fake, z_real, z_fake) } else { (e_fake, e_real, z_fake, z_real) };
    Ok(json!({ "e0": enc_scalar(&e0), "e1": enc_scalar(&e1), "z0": enc_scalar(&z0), "z1": enc_scalar(&z1) }))
}

fn verify_bit(ctx: &[u8; 32], index: usize, b_pt: &RistrettoPoint, proof: &Value) -> bool {
    if !proof.is_object() {
        return false;
    }
    let mut sc = [Scalar::ZERO; 4];
    for (i, k) in ["e0", "e1", "z0", "z1"].iter().enumerate() {
        match dec_scalar(proof.get(*k).unwrap_or(&Value::Null)) {
            Ok(v) => sc[i] = v,
            Err(_) => return false,
        }
    }
    let a0 = gen_h() * sc[2] - b_pt * sc[0];
    let a1 = gen_h() * sc[3] - (b_pt - G) * sc[1];
    sc[0] + sc[1] == or_hash(ctx, index, &a0, &a1)
}

fn verify_schnorr(ctx: &[u8; 32], d: &RistrettoPoint, proof: &Value) -> bool {
    let (Ok(a), Ok(z)) = (dec_point(proof.get("a").unwrap_or(&Value::Null)), dec_scalar(proof.get("z").unwrap_or(&Value::Null))) else { return false };
    let e = hash_to_scalar(&[AGG_DOMAIN, ctx, d.compress().as_bytes(), a.compress().as_bytes()]);
    gen_h() * z == a + d * e
}

/// Proves `v_pt` hides a value whose low N bits are `low` (slack mod 2^N), under blinding `gamma`.
fn range_prove(make_ctx: MakeCtx, v_pt: &RistrettoPoint, low: u32, gamma: &Scalar) -> Result<Value, String> {
    let mut bit_pts = Vec::with_capacity(RATCHET_N_BITS);
    let mut blinds = Vec::with_capacity(RATCHET_N_BITS);
    for i in 0..RATCHET_N_BITS {
        let b = rand_scalar()?;
        bit_pts.push(pedersen(&Scalar::from(((low >> i) & 1) as u64), &b));
        blinds.push(b);
    }
    let ctx = make_ctx(&bit_pts);
    let (mut ors, mut s_star, mut agg) = (Vec::new(), Scalar::ZERO, RistrettoPoint::identity());
    for i in 0..RATCHET_N_BITS {
        ors.push(prove_bit(&ctx, i, &bit_pts[i], ((low >> i) & 1) as u64, &blinds[i])?);
        let p2 = Scalar::from(1u64 << i);
        s_star += p2 * blinds[i];
        agg += bit_pts[i] * p2;
    }
    let d = agg - v_pt;
    let k = rand_scalar()?;
    let a = gen_h() * k;
    let e = hash_to_scalar(&[AGG_DOMAIN, &ctx, d.compress().as_bytes(), a.compress().as_bytes()]);
    let z = e * (s_star - gamma) + k;
    Ok(json!({
        "n": RATCHET_N_BITS,
        "bitCommitments": bit_pts.iter().map(|p| Value::String(enc_point(p))).collect::<Vec<_>>(),
        "or": ors,
        "agg": { "a": enc_point(&a), "z": enc_scalar(&z) },
    }))
}

fn range_verify(make_ctx: MakeCtx, v_pt: &RistrettoPoint, proof: &Value) -> bool {
    if !proof.is_object() || num_of(proof.get("n").unwrap_or(&Value::Null)) != RATCHET_N_BITS as f64 {
        return false;
    }
    let (Some(bc), Some(ors)) = (proof.get("bitCommitments").and_then(Value::as_array), proof.get("or").and_then(Value::as_array)) else { return false };
    let Some(agg_proof) = proof.get("agg").filter(|a| a.is_object()) else { return false };
    if bc.len() != RATCHET_N_BITS || ors.len() != RATCHET_N_BITS {
        return false;
    }
    let mut b = Vec::with_capacity(RATCHET_N_BITS);
    for x in bc {
        match dec_point(x) {
            Ok(p) => b.push(p),
            Err(_) => return false,
        }
    }
    let ctx = make_ctx(&b);
    let mut agg = RistrettoPoint::identity();
    for i in 0..RATCHET_N_BITS {
        if !verify_bit(&ctx, i, &b[i], &ors[i]) {
            return false;
        }
        agg += b[i] * Scalar::from(1u64 << i);
    }
    verify_schnorr(&ctx, &(agg - v_pt), agg_proof)
}

/// Proves sum(risks) <= bMax over the committed values (an over-budget input yields a well-formed proof the verifier rejects).
pub fn prove_budget(risks: &Value, blindings: &Value, b_max: &Value) -> Result<Value, RatchetError> {
    let (Some(rs), Some(bs)) = (risks.as_array(), blindings.as_array()) else { return Err("risks and blindings must be arrays".into()) };
    if rs.len() != bs.len() {
        return Err(coded("length_mismatch", "risks and blindings must have equal length"));
    }
    let ceiling = ceiling_of(&units(b_max)?);
    let (mut sum_risk, mut sum_blind) = (zero(), Scalar::ZERO);
    for (r, b) in rs.iter().zip(bs) {
        sum_risk = &sum_risk + &units(r)?;
        sum_blind += blinding_of(b)?;
    }
    let c_sum = pedersen(&scalar_of_big(&(false, sum_risk.clone())), &sum_blind);
    let v_pt = G * Scalar::from(ceiling) - c_sum;
    let slack_low = (ceiling as u32).wrapping_sub(low32(&sum_risk)); // low N bits of ceiling - sum (two's complement when negative)
    Ok(range_prove(&budget_ctx(ceiling, &c_sum), &v_pt, slack_low, &-sum_blind)?)
}

/// Checks a budget proof for a commitment sum and a ceiling (ceilings above 2^32-1 are clamped). Never fails open.
pub fn verify_budget(commitment_sum: &Value, b_max: &Value, proof: &Value) -> bool {
    let Ok(b) = units(b_max) else { return false };
    let ceiling = ceiling_of(&b);
    let Ok(c) = dec_point(commitment_sum) else { return false };
    range_verify(&budget_ctx(ceiling, &c), &(G * Scalar::from(ceiling) - c), proof)
}

fn prove_range(risk: &Value, blinding: &Scalar) -> Result<Value, RatchetError> {
    let v = units(risk)?;
    let c = pedersen(&scalar_of_big(&(false, v.clone())), blinding);
    Ok(range_prove(&risk_ctx(&c), &c, low32(&v), blinding)?)
}

/// Proves that `commit_risk(risk, blinding)` holds a value in [0, 2^32).
pub fn prove_risk_range(risk: &Value, blinding: &Value) -> Result<Value, RatchetError> {
    units(risk)?; // the reference reads the risk before the blinding
    prove_range(risk, &blinding_of(blinding)?)
}

/// Checks a range proof for a commitment. Never fails open.
pub fn verify_risk_range(commitment: &Value, proof: &Value) -> bool {
    dec_point(commitment).is_ok_and(|c| range_verify(&risk_ctx(&c), &c, proof))
}

/// Every commitment carries a valid range proof and the budget proof verifies for their sum.
pub fn verify_bounded_budget(commitments: &Value, range_proofs: &Value, b_max: &Value, budget_proof: &Value) -> bool {
    let (Some(cs), Some(rs)) = (commitments.as_array(), range_proofs.as_array()) else { return false };
    if cs.len() != rs.len() || !cs.iter().zip(rs).all(|(c, r)| verify_risk_range(c, r)) {
        return false;
    }
    add_commitments(commitments).is_ok_and(|sum| verify_budget(&Value::String(sum), b_max, budget_proof))
}
