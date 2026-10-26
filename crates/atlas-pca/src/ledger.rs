//! Transparency-ledger verification: RFC 9162 consistency, signed tree heads (STH), witness cosignatures, head-to-head
//! consistency, checkpoint chains, legacy witnessed heads and equivocation. Verify-only; Ed25519 only (a head or
//! cosignature under any other signature suite is refused). Inclusion proofs of commit strings are [`crate::verify_inclusion`].
//!
//! Every function is total: malformed input is `false`, never a panic. The sizes of a proof are JSON safe integers
//! (< 2^53) walked as `u64`, so `3` and `3 + 2^32` can never be confused.
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, node_hash, sha, verify_b64u};
use serde_json::{Map, Value};
use std::collections::HashSet;

const STH_DOMAIN: &str = "atlas-pca/sth/v1\0";
const STH_WITNESS_DOMAIN: &str = "atlas-pca/sth-witness/v2\0";
const LEDGER_HEAD_DOMAIN: &str = "atlas-pca/ledger-head/v1\0";
/// Longest consistency path a tree of fewer than 2^53 leaves can need (2 * 53 + 2 accepted, as the reference).
const MAX_CONSISTENCY_PATH: usize = 2 * 53 + 2;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// Root of the empty tree (SHA-256 of the empty string), base64url.
pub fn empty_tree_root() -> String {
    b64_encode(&sha(b""))
}

/// A JSON number that is an integer in [0, 2^53): a JavaScript safe integer >= 0.
fn safe_size(v: Option<&Value>) -> Option<u64> {
    let n = v?.as_number()?;
    if let Some(u) = n.as_u64() {
        return (u as f64 <= MAX_SAFE).then_some(u);
    }
    let f = n.as_f64()?; // negative integers and fractions land here
    (f.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&f)).then_some(f as u64)
}

/// JavaScript `===` on two JSON values (numbers compare by value, 1 === 1.0).
fn js_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// RFC 9162 section 2.1.4.2 consistency verification of `proof` = `{oldSize, newSize, path}` between two roots.
pub fn verify_ledger_consistency(old_root: &Value, new_root: &Value, proof: &Value) -> bool {
    let (old_root, new_root) = match (old_root.as_str(), new_root.as_str()) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    let (first, second) = match (safe_size(proof.get("oldSize")), safe_size(proof.get("newSize"))) {
        (Some(a), Some(b)) if a <= b => (a, b),
        _ => return false,
    };
    let raw = match proof.get("path").and_then(Value::as_array) {
        Some(p) if p.len() <= MAX_CONSISTENCY_PATH => p,
        _ => return false,
    };
    let empty = empty_tree_root();
    if first == 0 {
        if !raw.is_empty() || old_root != empty {
            return false;
        }
        return if second == 0 { new_root == empty } else { true };
    }
    if first == second {
        return raw.is_empty() && old_root == new_root;
    }
    let mut path: Vec<Vec<u8>> = Vec::with_capacity(raw.len() + 1);
    for x in raw {
        match x.as_str().and_then(|s| decode_b64u_strict(s, None)) {
            Some(b) => path.push(b),
            None => return false,
        }
    }
    if first & (first - 1) == 0 {
        match decode_b64u_strict(old_root, None) {
            Some(b) => path.insert(0, b),
            None => return false,
        }
    }
    if path.is_empty() {
        return false;
    }
    let (mut fnn, mut sn) = (first - 1, second - 1);
    while fnn & 1 == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0].clone(), path[0].clone());
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fnn & 1 == 0 && fnn != 0 {
                fnn >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && b64_encode(&fr) == old_root && b64_encode(&sr) == new_root
}

/// The only suites a head may use here: `alg` absent or `"ed25519"`.
fn ed25519_only(alg: Option<&Value>) -> bool {
    match alg {
        None => true,
        Some(a) => a.as_str() == Some("ed25519"),
    }
}

/// domain + strict canonical JSON of the named fields of `src` (a missing field refuses, as the reference's canonicalizer does).
fn signed_message(domain: &str, src: &Value, fields: &[&str], defaults: &[(&str, Value)]) -> Option<Vec<u8>> {
    let mut m = Map::new();
    for f in fields {
        m.insert((*f).into(), src.get(*f)?.clone());
    }
    for (k, v) in defaults {
        m.insert((*k).into(), v.clone());
    }
    let mut out = domain.as_bytes().to_vec();
    out.extend_from_slice(canonicalize_strict(&Value::Object(m)).ok()?.as_bytes());
    Some(out)
}

fn witness_policy_ok(sth: &Value, policy: &Value) -> bool {
    let threshold = match policy.get("threshold").and_then(Value::as_number) {
        Some(n) => match n.as_u64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= MAX_SAFE).map(|f| f as u64)) {
            Some(t) => t as usize,
            None => return false,
        },
        None => return false,
    };
    if threshold == 0 {
        return true;
    }
    let trusted: HashSet<&str> = policy.get("witnessKeys").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if trusted.is_empty() {
        return false;
    }
    let witnesses = match sth.get("witnesses").and_then(Value::as_array) {
        Some(w) => w,
        None => return false,
    };
    let mut counted: HashSet<&str> = HashSet::new();
    for w in witnesses {
        let key = match (w.get("key").and_then(Value::as_str), w.get("sig").and_then(Value::as_str)) {
            (Some(k), Some(_)) => k,
            _ => continue,
        };
        if !trusted.contains(key) || counted.contains(key) || !verify_witness_cosignature(sth, w, key) {
            continue;
        }
        counted.insert(key);
        if counted.len() >= threshold {
            return true;
        }
    }
    counted.len() >= threshold
}

/// One witness cosignature over the tree-head statement, bound to this exact head (`guardian_epoch` defaults to 0).
pub fn verify_witness_cosignature(sth: &Value, cosig: &Value, witness_public: &str) -> bool {
    if cosig.get("key").and_then(Value::as_str) != Some(witness_public) || !ed25519_only(cosig.get("alg")) {
        return false;
    }
    let sig = match cosig.get("sig").and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    let epoch = match sth.get("guardian_epoch") {
        None | Some(Value::Null) => Value::from(0),
        Some(e) => e.clone(),
    };
    match signed_message(STH_WITNESS_DOMAIN, sth, &["instance_id", "principal", "size", "root", "prev_root"], &[("guardian_epoch", epoch)]) {
        Some(msg) => verify_b64u(witness_public, &msg, sig),
        None => false,
    }
}

/// k-of-n over an STH's cosignatures: `policy` is `{witnessKeys: [...], threshold: k}`. Unknown witnesses, duplicate keys
/// and mis-bound or tampered cosignatures do not count; `threshold` 0 is vacuously met; a missing or non-integer threshold refuses.
pub fn verify_witness_cosignatures(sth: &Value, policy: &Value) -> bool {
    witness_policy_ok(sth, policy)
}

/// An STH against the pinned guardian key (and, when `policy` is given, the witness threshold).
pub fn verify_tree_head(sth: &Value, guardian_public: &str, policy: Option<&Value>) -> bool {
    if sth.get("guardian").and_then(Value::as_str) != Some(guardian_public) || !ed25519_only(sth.get("alg")) || safe_size(sth.get("size")).is_none() {
        return false;
    }
    let sig = match sth.get("sig").and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    let msg = match signed_message(STH_DOMAIN, sth, &["instance_id", "principal", "size", "root", "prev_root", "timestamp"], &[]) {
        Some(m) => m,
        None => return false,
    };
    if !verify_b64u(guardian_public, &msg, sig) {
        return false;
    }
    match policy {
        Some(p) if !p.is_null() => verify_witness_cosignatures(sth, p),
        _ => true,
    }
}

/// Both heads genuine, same log, the proof connects `older` to `newer`, and for consecutive heads (`newer.size == older.size + 1`)
/// the signed `prev_root` equals `older.root`.
pub fn verify_head_consistency(older: &Value, newer: &Value, proof: &Value, guardian_public: &str, policy: Option<&Value>) -> bool {
    if !verify_tree_head(older, guardian_public, policy) || !verify_tree_head(newer, guardian_public, policy) {
        return false;
    }
    if !js_eq(older.get("instance_id"), newer.get("instance_id")) || !js_eq(older.get("principal"), newer.get("principal")) {
        return false;
    }
    let (os, ns) = (safe_size(older.get("size")), safe_size(newer.get("size")));
    if safe_size(proof.get("oldSize")) != os || safe_size(proof.get("newSize")) != ns {
        return false;
    }
    if ns == os.map(|o| o + 1) && !js_eq(newer.get("prev_root"), older.get("root")) {
        return false;
    }
    match (older.get("root"), newer.get("root")) {
        (Some(o), Some(n)) => verify_ledger_consistency(o, n, proof),
        _ => false,
    }
}

/// Where a checkpoint chain stops verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointChainVerdict {
    pub ok: bool,
    /// Index of the first checkpoint that does not verify (0 when `ok`).
    pub at: usize,
    /// `empty`, `head`, `proof_missing` or `inconsistent` (empty when `ok`).
    pub reason: &'static str,
}

/// Verify `chain` (an array of `{sth, proof?}`): every head genuine, the first needs no proof, every later one carries a
/// consistency proof from the checkpoint before. An empty chain fails closed.
pub fn verify_checkpoint_chain(chain: &Value, guardian_public: &str, policy: Option<&Value>) -> CheckpointChainVerdict {
    let fail = |at, reason| CheckpointChainVerdict { ok: false, at, reason };
    let cps = match chain.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return fail(0, "empty"),
    };
    for (i, cp) in cps.iter().enumerate() {
        let sth = match cp.get("sth") {
            Some(s) if verify_tree_head(s, guardian_public, policy) => s,
            _ => return fail(i, "head"),
        };
        if i == 0 {
            continue;
        }
        let proof = match cp.get("proof") {
            Some(p) if !p.is_null() => p,
            _ => return fail(i, "proof_missing"),
        };
        if !verify_head_consistency(&cps[i - 1]["sth"], sth, proof, guardian_public, policy) {
            return fail(i, "inconsistent");
        }
    }
    CheckpointChainVerdict { ok: true, at: 0, reason: "" }
}

/// A legacy witnessed head `{principal, size, root, witness, sig}` against the witness key.
pub fn verify_witnessed_head(head: &Value, witness_public: &str) -> bool {
    if head.get("witness").and_then(Value::as_str) != Some(witness_public) || !ed25519_only(head.get("alg")) {
        return false;
    }
    match (head.get("sig").and_then(Value::as_str), signed_message(LEDGER_HEAD_DOMAIN, head, &["principal", "size", "root"], &[])) {
        (Some(sig), Some(msg)) => verify_b64u(witness_public, &msg, sig),
        _ => false,
    }
}

/// Two validly witnessed heads of one principal at one size with different roots prove equivocation.
pub fn detect_equivocation(a: &Value, b: &Value, witness_public: &str) -> bool {
    verify_witnessed_head(a, witness_public)
        && verify_witnessed_head(b, witness_public)
        && js_eq(a.get("principal"), b.get("principal"))
        && js_eq(a.get("size"), b.get("size"))
        && a.get("root") != b.get("root")
}
