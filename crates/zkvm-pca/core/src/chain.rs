//! In-guest verification of the SIGNED capability chain — the gap closure.
//!
//! This is a faithful Rust port of `packages/pca/src/capability.ts` `verifyChain` (the ed25519 default
//! suite) plus the leaf PCActn signature of `packages/pca/src/pcactn.ts` (`verifyLeafSuite`). It runs
//! INSIDE the zkVM guest, so the succinct proof attests the ENTIRE chain-of-authority:
//!
//!   * every hop is Ed25519-signed by its issuer over the EXACT canonical signed body (`checkSig`);
//!   * the chain roots at the pinned `expected_root_principal` (== `grant.issuer`);
//!   * each hop's `issuer` == the previous hop's `holder` (delegation linkage), hash-linked via `parent`;
//!   * caveats are append-only (parent caveats are an exact prefix) and carried budget allocations are
//!     monotone non-increasing; and
//!   * the leaf PCActn is signed by the leaf capability holder over the canonical PCActn body.
//!
//! FAIL CLOSED: anything malformed, misrooted, broken-linked, or badly-signed returns `ok == false`, which
//! the decision folds into `allow = 0`, making the guest `assert_eq!(allow, 1)` panic — so a forged or
//! broken chain is UNPROVABLE.
//!
//! SCOPE (deliberate, documented boundary — NOT a soundness hole): only the `ed25519` suite is verified
//! in-circuit (absent `alg`, or `alg == "ed25519"` — byte-identical bodies). Any post-quantum / hybrid
//! suite (`ml-dsa-*`, `slh-dsa-*`, `hybrid-*`) FAILS CLOSED here, because verifying ML-DSA / SLH-DSA in
//! the guest is a separate milestone. verifyChain ACCEPTS those suites off-circuit; the guest simply
//! cannot yet PROVE them. ed25519 is the overwhelming default and the only suite the fixtures use.

use crate::canonical::canonical_bytes;
use crate::commit::{b64u, hash_canonical, sha256};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

/// Capability-hop signature domain (`capability.ts` `CAP_DOMAIN`) — note the trailing NUL.
pub const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\0";
/// Leaf PCActn signature domain (`pcactn.ts` `SIG_DOMAIN`) — note the trailing NUL.
pub const SIG_DOMAIN: &[u8] = b"atlas-pca/actn/v2\0";

/// Longest delegation chain accepted (`capability.ts` `MAX_CHAIN_DEPTH`).
pub const MAX_CHAIN_DEPTH: usize = 16;

/// The result of a chain verification (`capability.ts` `ChainResult`).
#[derive(Clone, Debug)]
pub struct ChainVerdict {
    pub ok: bool,
    pub reason: Option<String>,
}

impl ChainVerdict {
    fn ok() -> Self {
        ChainVerdict { ok: true, reason: None }
    }
    fn deny(reason: impl Into<String>) -> Self {
        ChainVerdict { ok: false, reason: Some(reason.into()) }
    }
}

/// The leaf PCActn signature material (`verifyLeafSuite` inputs). `message` is the already-computed
/// `thresholdMessage(pcactn)` = `SIG_DOMAIN ‖ sha256(canonical(pcactn_body))`. `pq_pk`/`pq_sig` are carried
/// for completeness but are unused on the ed25519 path (PQ suites fail closed — see the module scope note).
#[derive(Clone, Debug)]
pub struct LeafSig {
    pub message: Vec<u8>,
    pub alg: Option<String>,
    pub sig: Option<String>,
    pub pq_pk: Option<String>,
    pub pq_sig: Option<String>,
}

/// STRICT base64url (RFC 4648 §5, no padding) — a faithful port of `hash.ts` `decodeB64uStrict`:
/// only `[A-Za-z0-9_-]`, length `mod 4 != 1`, canonical trailing bits (`b64u(decode(s)) == s`), and the
/// decoded length MUST equal `len`. Returns `None` for ANY deviation (never panics).
fn decode_b64u_strict(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    // non-canonical trailing bits: re-encode and require round-trip identity.
    if b64u(&bytes) != s {
        return None;
    }
    if bytes.len() != len {
        return None;
    }
    Some(bytes)
}

/// STRICT RFC-8032 Ed25519 verify over base64url key + signature — the guest analogue of
/// `keys.ts` `verifyB64u` → `verify`. `ed25519-dalek` `verify_strict` rejects small-order `A`/`R` and
/// non-canonical encodings (RFC 8032, cofactorless). FAIL CLOSED: any decode / length / parse / verify
/// failure returns `false`. Never panics.
pub fn ed25519_verify_b64u(public_key_b64u: &str, msg: &[u8], sig_b64u: &str) -> bool {
    let pk = match decode_b64u_strict(public_key_b64u, 32) {
        Some(b) => b,
        None => return false,
    };
    let sg = match decode_b64u_strict(sig_b64u, 64) {
        Some(b) => b,
        None => return false,
    };
    let pk_arr: [u8; 32] = match pk.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sg.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &sig).is_ok()
}

/// True iff the hop's `alg` selects the ed25519 suite we support in-circuit (absent, or the explicit
/// `"ed25519"`). A known-but-PQ suite, or an unknown value, is NOT ed25519 (caller fails closed).
fn is_ed25519_alg(c: &Value) -> bool {
    match c.get("alg") {
        None => true,
        Some(Value::String(s)) => s == "ed25519",
        _ => false,
    }
}

/// The canonical signed body of an ed25519 hop (`capability.ts` `bodyOf` → `signableBody`, ed25519
/// leaves it unchanged): `{issuer, holder, caveats, parent: parent ?? null}`.
fn signable_body_ed25519(c: &Value) -> Value {
    let mut m = serde_json::Map::with_capacity(4);
    m.insert("issuer".to_string(), c.get("issuer").cloned().unwrap_or(Value::Null));
    m.insert("holder".to_string(), c.get("holder").cloned().unwrap_or(Value::Null));
    m.insert("caveats".to_string(), c.get("caveats").cloned().unwrap_or(Value::Array(Vec::new())));
    m.insert("parent".to_string(), c.get("parent").cloned().unwrap_or(Value::Null));
    Value::Object(m)
}

/// `capability.ts` `wellTyped`: the required string fields are strings, the optional suite/parent fields
/// (when present) are strings, and `caveats` is an array of objects each carrying a string `type`.
fn well_typed(c: &Value) -> bool {
    let o = match c.as_object() {
        Some(o) => o,
        None => return false,
    };
    let is_str = |k: &str| o.get(k).map_or(false, |v| v.is_string());
    if !is_str("id") || !is_str("issuer") || !is_str("holder") || !is_str("body_digest") || !is_str("sig") {
        return false;
    }
    for k in ["alg", "pq_pk", "pq_sig", "parent"] {
        if let Some(v) = o.get(k) {
            if !v.is_string() {
                return false;
            }
        }
    }
    match o.get("caveats") {
        Some(Value::Array(a)) => a
            .iter()
            .all(|cv| cv.as_object().map_or(false, |m| m.get("type").map_or(false, |t| t.is_string()))),
        _ => false,
    }
}

/// `capability.ts` `checkSig` (ed25519 suite). Verifies the hop body digest / id binding and the Ed25519
/// signature by `signer` over `CAP_DOMAIN ‖ sha256(canonical(body))`. Returns `Ok(())` or an error label.
fn check_sig(c: &Value, signer: &str, label: &str) -> Result<(), String> {
    // Unknown / unsupported suite => fail closed before any hashing (matches `resolveSigAlg(...) === null`
    // for unknown, and extends fail-closed to PQ suites the guest does not verify in-circuit).
    if !is_ed25519_alg(c) {
        return Err(format!("{label}: unsupported/unknown signature alg for in-circuit verification"));
    }
    let body = signable_body_ed25519(c);
    let cb = canonical_bytes(&body);
    let digest_raw = sha256(&cb);
    let digest_b64 = b64u(&digest_raw);
    let body_digest = c.get("body_digest").and_then(|v| v.as_str()).unwrap_or("");
    let id = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if digest_b64 != body_digest || id != body_digest {
        return Err(format!("{label}: body digest mismatch"));
    }
    // sigMessage(body_digest) == CAP_DOMAIN ‖ unb64u(body_digest); unb64u(body_digest) == digest_raw here.
    let mut msg = Vec::with_capacity(CAP_DOMAIN.len() + 32);
    msg.extend_from_slice(CAP_DOMAIN);
    msg.extend_from_slice(&digest_raw);
    let sig = c.get("sig").and_then(|v| v.as_str()).unwrap_or("");
    if !ed25519_verify_b64u(signer, &msg, sig) {
        return Err(format!("{label}: bad signature (not signed by expected key)"));
    }
    Ok(())
}

/// `capability.ts` `allocationsMonotone`: every `budget_alloc.limit` in the (append-only) leaf caveat list
/// must be a finite number >= 0 and never greater than the previous one. Returns an error string or `None`.
fn allocations_monotone_err(leaf: &Value) -> Option<String> {
    let caveats = match leaf.get("caveats").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Some("malformed caveats".to_string()),
    };
    let mut prev = f64::INFINITY;
    for (i, cv) in caveats.iter().enumerate() {
        let obj = match cv.as_object() {
            Some(o) => o,
            None => continue,
        };
        if obj.get("type").and_then(|t| t.as_str()) != Some("budget_alloc") {
            continue;
        }
        match obj.get("limit").and_then(|v| v.as_f64()) {
            Some(lim) if lim.is_finite() && lim >= 0.0 => {
                if lim > prev {
                    return Some(format!("budget_alloc caveat {i}: allocation widens the parent's carried allocation"));
                }
                prev = lim;
            }
            _ => return Some(format!("budget_alloc caveat {i}: limit must be a finite number >= 0")),
        }
    }
    None
}

/// The leaf PCActn signature (`pcactn.ts` `verifyLeafSuite`, ed25519 path): Ed25519 `sig` by the leaf
/// `holder` over the canonical PCActn message. PQ/unknown suites fail closed (module scope note).
fn verify_leaf_suite(leaf: &LeafSig, holder: &str) -> bool {
    match leaf.alg.as_deref() {
        None | Some("ed25519") => {}
        _ => return false,
    }
    let sig = match &leaf.sig {
        Some(s) => s,
        None => return false,
    };
    ed25519_verify_b64u(holder, &leaf.message, sig)
}

/// Verify the FULL signed capability chain AND the leaf PCActn signature — the faithful port of
/// `capability.ts` `verifyChain(chain, expectedRootIssuer)` followed by the leaf-holder signature check of
/// `verifyPCActnCore` step 3. `expected_root_principal` is the pinned root issuer (== `grant.issuer`).
pub fn verify_chain(chain: &[Value], expected_root_principal: &str, leaf: &LeafSig) -> ChainVerdict {
    if chain.is_empty() {
        return ChainVerdict::deny("empty chain");
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return ChainVerdict::deny(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"));
    }
    for (i, c) in chain.iter().enumerate() {
        if !well_typed(c) {
            return ChainVerdict::deny(format!("hop {i}: malformed capability"));
        }
    }

    // ---- root -------------------------------------------------------------------------------------
    let root = &chain[0];
    if root.get("parent").is_some() {
        return ChainVerdict::deny("hop 0: root must not have a parent");
    }
    let root_issuer = root.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
    if root_issuer != expected_root_principal {
        return ChainVerdict::deny("hop 0: root issuer is not the expected principal");
    }
    if let Err(e) = check_sig(root, root_issuer, "hop 0") {
        return ChainVerdict::deny(e);
    }

    // ---- each delegation hop ----------------------------------------------------------------------
    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let c = &chain[i];
        let label = format!("hop {i}");

        let parent_hash = hash_canonical(parent); // capHash(parent) == hashCanonical(full parent object)
        if c.get("parent").and_then(|v| v.as_str()).unwrap_or("") != parent_hash {
            return ChainVerdict::deny(format!("{label}: broken parent link"));
        }
        // Holder-binding continuity: the hop must be issued by the key the parent is bound to.
        let parent_holder = parent.get("holder").and_then(|v| v.as_str()).unwrap_or("");
        if c.get("issuer").and_then(|v| v.as_str()).unwrap_or("") != parent_holder {
            return ChainVerdict::deny(format!("{label}: issuer is not the parent's bound holder"));
        }
        if let Err(e) = check_sig(c, parent_holder, &label) {
            return ChainVerdict::deny(e);
        }
        // Attenuation-only: parent caveats must be an exact prefix (no drop, reorder or edit).
        let cc = c.get("caveats").and_then(|v| v.as_array());
        let pc = parent.get("caveats").and_then(|v| v.as_array());
        let (cc, pc) = match (cc, pc) {
            (Some(a), Some(b)) => (a, b),
            _ => return ChainVerdict::deny(format!("{label}: malformed caveats")),
        };
        if cc.len() < pc.len() {
            return ChainVerdict::deny(format!("{label}: drops parent caveat(s)"));
        }
        for j in 0..pc.len() {
            if hash_canonical(&cc[j]) != hash_canonical(&pc[j]) {
                return ChainVerdict::deny(format!("{label}: caveat {j} altered or reordered"));
            }
        }
    }

    // ---- carried budget allocations monotone over the leaf's (append-only) caveats ----------------
    if let Some(reason) = allocations_monotone_err(&chain[chain.len() - 1]) {
        return ChainVerdict::deny(reason);
    }

    // ---- leaf PCActn signature under the leaf capability holder -----------------------------------
    let leaf_holder = chain[chain.len() - 1].get("holder").and_then(|v| v.as_str()).unwrap_or("");
    if !verify_leaf_suite(leaf, leaf_holder) {
        return ChainVerdict::deny("leaf signature does not verify under the leaf holder key");
    }

    ChainVerdict::ok()
}
