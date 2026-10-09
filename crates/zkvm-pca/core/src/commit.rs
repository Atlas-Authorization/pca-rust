//! Native-sha256 commitments — the gap closure.
//!
//! All three commitments are recomputed INSIDE the guest from the structured preimages, using the
//! `sha2` crate (which the guest patches with the RISC Zero sha256 precompile, so this is accelerated,
//! in-circuit sha256 over the *variable-length* canonical-JSON preimage — exactly what the hand-written
//! circom/Winterfell circuits could not do).
//!
//!  - `action_commitment`  = b64u(sha256(canonical(action)))                 == TS `actionCommitment`
//!  - `policy_commitment`  = b64u(sha256(canonical({issuer,holder,caveats,parent})))  == grant.id
//!  - `plan_commitment`    = RFC-6962 Merkle root over the plan-node leaves   == TS `commitPlan().root`
//!
//! Each is byte-for-byte the TS value (`packages/pca/src/hash.ts`, `merkle.ts`, `capability.ts`),
//! cross-checked against the reference in the fixture generator.

use crate::canonical::canonical_bytes;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Raw sha256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// base64url, no padding (`@scure/base` `base64urlnopad`).
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// b64u(sha256(strictCanonical(value))) — the TS `hashCanonical`.
pub fn hash_canonical(v: &Value) -> String {
    b64u(&sha256(&canonical_bytes(v)))
}

/// `actionCommitment(pcactn)` = hashCanonical(action descriptor).
pub fn action_commitment(action: &Value) -> String {
    hash_canonical(action)
}

/// `policyCommitment(grant)` = grant.id = hashCanonical({issuer, holder, caveats, parent: parent ?? null}).
/// Recomputed natively from the grant body (default ed25519 suite body layout, `capability.ts` `bodyOf`).
pub fn policy_commitment(grant: &Value) -> String {
    let body = json!({
        "issuer": grant.get("issuer").cloned().unwrap_or(Value::Null),
        "holder": grant.get("holder").cloned().unwrap_or(Value::Null),
        "caveats": grant.get("caveats").cloned().unwrap_or(Value::Array(Vec::new())),
        "parent": grant.get("parent").cloned().unwrap_or(Value::Null),
    });
    hash_canonical(&body)
}

// ---- RFC-6962 binary Merkle tree (faithful port of merkle.ts) ------------------------------------

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

fn leaf_hash(leaf: &Value) -> [u8; 32] {
    let cb = canonical_bytes(leaf);
    let mut buf = Vec::with_capacity(1 + cb.len());
    buf.push(LEAF);
    buf.extend_from_slice(&cb);
    sha256(&buf)
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(NODE);
    buf.extend_from_slice(l);
    buf.extend_from_slice(r);
    sha256(&buf)
}

/// Largest power of two strictly less than n (merkle.ts `split`).
fn split(n: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn build(hs: &[[u8; 32]]) -> [u8; 32] {
    if hs.len() == 1 {
        return hs[0];
    }
    let k = split(hs.len());
    node_hash(&build(&hs[..k]), &build(&hs[k..]))
}

/// Default values applied when a plan node omits them (merkle.ts). These are the *content addresses*
/// the TS side commits: `EMPTY_PARAMS_DIGEST = hashCanonical({})` and `DEFAULT_REVERSIBILITY_CLASS`.
pub fn empty_params_digest() -> String {
    hash_canonical(&json!({}))
}
pub const DEFAULT_REVERSIBILITY_CLASS: &str = "reversible";

/// `conditionsDigest(pre, post)` = b64u(sha256(canonical({pre: pre??null, post: post??null}))).
fn conditions_digest(node: &Value) -> String {
    let body = json!({
        "pre": node.get("pre").cloned().unwrap_or(Value::Null),
        "post": node.get("post").cloned().unwrap_or(Value::Null),
    });
    b64u(&sha256(&canonical_bytes(&body)))
}

/// The committed leaf for a plan node (merkle.ts `planNodeLeaf` / `planLeaf`).
fn plan_node_leaf(node: &Value) -> Value {
    let params_digest = node
        .get("params_digest")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(empty_params_digest);
    let rev = node
        .get("reversibility_class")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_REVERSIBILITY_CLASS)
        .to_string();
    json!({
        "node_id": node.get("id").cloned().unwrap_or(Value::Null),
        "verb": node.get("verb").cloned().unwrap_or(Value::Null),
        "resource": node.get("resource").cloned().unwrap_or(Value::Null),
        "params_digest": params_digest,
        "reversibility_class": rev,
        "conditions": conditions_digest(node),
    })
}

/// `commitPlan(nodes).root` — RFC-6962 Merkle root over the plan-node leaves. `None` for an empty plan.
pub fn plan_commitment(plan: &[Value]) -> Option<String> {
    if plan.is_empty() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = plan.iter().map(|n| leaf_hash(&plan_node_leaf(n))).collect();
    Some(b64u(&build(&leaves)))
}
