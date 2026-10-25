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
//! SUITES (PCA 0.4.2): every suite the guest implements ([`crate::pq_suites`]: ed25519, ML-DSA-65/87, SLH-DSA-SHA2-128f/256s
//! and their hybrids, incl. the nested one) is verified in-circuit with the TS PQ-key authority rules (R3-01, F-2): a PQ ROOT
//! verifies only under the verifier's stored grant (`trusted_root`, byte-identical), a PQ HOP only under a `pq_pk` that hashes
//! to its parent's `holder_pq` commitment, and the signed hop body binds `holder_pq` and (for a PQ suite) `alg` + `pq_pk`. FN-DSA,
//! LESS and unknown suites FAIL CLOSED (`unsupported_suite`).

use crate::canonical::canonical_bytes;
use crate::commit::{b64u, hash_canonical, sha256};
use curve25519_dalek::edwards::CompressedEdwardsY;
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
pub fn decode_b64u_strict(s: &str, len: usize) -> Option<Vec<u8>> {
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

/// Decode an Ed25519 point the way the TS reference (`keys.ts` `verify`, noble with `zip215: false` plus the torsion
/// checks) accepts it: the 32 bytes must decompress, RE-ENCODE to exactly the same bytes (R6: `y >= p` aliases such as
/// `y + p` for `y < 19`, and a set sign bit on an `x = 0` point, are refused; dalek's decompression reduces `y` mod p
/// and would accept them), and the point must lie in the prime-order subgroup (torsion-free: no small-order or
/// mixed-order A' = A + T, found by `mixed_order_delegator_key_with_k_0_mod_8`). `None` on any deviation.
pub fn ed25519_point_strict(bytes: &[u8; 32]) -> Option<curve25519_dalek::edwards::EdwardsPoint> {
    let p = CompressedEdwardsY(*bytes).decompress()?;
    if p.compress().to_bytes() != *bytes || !p.is_torsion_free() {
        return None;
    }
    Some(p)
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
    // A and R must be CANONICAL, prime-order-subgroup encodings (see [`ed25519_point_strict`]).
    if ed25519_point_strict(&pk_arr).is_none() {
        return false;
    }
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ed25519_point_strict(<&[u8; 32]>::try_from(&sig_arr[..32]).expect("32 bytes")).is_none() {
        return false;
    }
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &sig).is_ok()
}

/// Every suite name the TS registry knows (`SIG_SUITES`): a name outside it is UNKNOWN (TS `resolveSigAlg` null).
const KNOWN_SUITES: [&str; 14] = [
    "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024",
];

/// `resolveSigAlg(alg)?.alg`: absent = ed25519; a non-string or unregistered name = `None` (unknown).
fn resolve_alg(alg: Option<&Value>) -> Option<&'static str> {
    match alg {
        None => Some("ed25519"),
        Some(Value::String(s)) => KNOWN_SUITES.iter().copied().find(|k| k == s),
        _ => None,
    }
}

/// `holderPqCommitment(pq_pk)` = b64u(sha256("atlas-pca/holder-pq/v1\0" ‖ utf8(pq_pk))).
pub fn holder_pq_commitment(pq_pk: &str) -> String {
    let mut m = b"atlas-pca/holder-pq/v1\0".to_vec();
    m.extend_from_slice(pq_pk.as_bytes());
    b64u(&sha256(&m))
}

/// `pqBindingError(alg, pq_pk, committed)` (F-2, `allowUnboundPq` false): a suite that carries a PQ key needs the signer's
/// holder to have committed (`holder_pq`) to exactly that key. `Some(reason)` = refused.
pub fn pq_binding_error(alg: Option<&str>, pq_pk: Option<&str>, committed: Option<&str>, label: &str) -> Option<String> {
    let needs = alg.is_some_and(|a| a != "ed25519");
    if !needs {
        return None;
    }
    let alg = alg.unwrap_or("ed25519");
    match committed {
        None => Some(format!(
            "{label}: suite '{alg}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
        )),
        Some(c) if pq_pk.map(holder_pq_commitment).as_deref() == Some(c) => None,
        Some(_) => Some(format!("{label}: pq_pk does not match the signer's committed holder_pq (F-2)")),
    }
}

/// The canonical signed body of a hop (`capability.ts` `signableBody` = `bindSuiteFields(bodyOf(c), alg, pq_pk)`):
/// `{issuer, holder, caveats, parent: parent ?? null, holder_pq?}`, plus `alg` and `pq_pk` for a non-ed25519 suite.
fn signable_body(c: &Value, alg: &str) -> Value {
    let mut m = serde_json::Map::with_capacity(7);
    m.insert("issuer".to_string(), c.get("issuer").cloned().unwrap_or(Value::Null));
    m.insert("holder".to_string(), c.get("holder").cloned().unwrap_or(Value::Null));
    m.insert("caveats".to_string(), c.get("caveats").cloned().unwrap_or(Value::Array(Vec::new())));
    m.insert("parent".to_string(), c.get("parent").cloned().unwrap_or(Value::Null));
    if let Some(hp) = c.get("holder_pq") {
        m.insert("holder_pq".to_string(), hp.clone());
    }
    if alg != "ed25519" {
        m.insert("alg".to_string(), Value::String(alg.to_string()));
        m.insert("pq_pk".to_string(), c.get("pq_pk").cloned().unwrap_or(Value::Null));
    }
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
    for k in ["alg", "pq_pk", "pq_sig", "holder_pq", "parent"] {
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

/// `capability.ts` `checkSig`: the hop body digest / id binding, then the suite signature by `signer` (Ed25519 identity) over
/// `CAP_DOMAIN ‖ sha256(canonical(body))`, the PQ half under `pq` (the verifier-authorised key; `None` for a PQ suite =
/// refused). Unknown suite: refused before any hashing; a suite the guest lacks: `unsupported_suite`.
fn check_sig(c: &Value, signer: &str, label: &str, pq: Option<&str>) -> Result<(), String> {
    let alg = match resolve_alg(c.get("alg")) {
        Some(a) => a,
        None => return Err(format!("{label}: unknown signature alg")),
    };
    if !crate::pq_suites::suite_supported(Some(alg)) {
        return Err(format!("{label}: unsupported_suite: {alg}"));
    }
    let body = signable_body(c, alg);
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
    if alg != "ed25519" && pq.is_none() {
        return Err(format!("{label}: no verifier-authorised PQ key for suite '{alg}' (refused)"));
    }
    let s = |k: &str| c.get(k).and_then(|v| v.as_str());
    if crate::pq_suites::verify_with_suite(Some(alg), &msg, Some(signer), s("sig"), pq, s("pq_sig")).is_err() {
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

/// The leaf PCActn signature (`pcactn.ts` step 3): F-2 binding of the leaf's `pq_pk` to the leaf capability's `holder_pq`
/// (`pqBindingError`), then `verifyLeafSuite` under the leaf `holder` with the bound PQ key (`holderPqKey`). Unknown and
/// guest-unsupported suites fail closed.
fn verify_leaf_suite(leaf: &LeafSig, holder: &str, holder_pq: Option<&str>) -> bool {
    let alg = match leaf.alg.as_deref() {
        None => "ed25519",
        Some(a) => match KNOWN_SUITES.iter().copied().find(|k| *k == a) {
            Some(k) => k,
            None => return false,
        },
    };
    if pq_binding_error(Some(alg), leaf.pq_pk.as_deref(), holder_pq, "leaf").is_some() {
        return false;
    }
    let pq = if alg == "ed25519" { None } else { leaf.pq_pk.as_deref() };
    crate::pq_suites::verify_with_suite(Some(alg), &leaf.message, Some(holder), leaf.sig.as_deref(), pq, leaf.pq_sig.as_deref()).is_ok()
}

/// Verify the FULL signed capability chain AND the leaf PCActn signature — the faithful port of
/// `capability.ts` `verifyChain(chain, expectedRootIssuer)` followed by the leaf-holder signature check of
/// `verifyPCActnCore` step 3. `expected_root_principal` is the pinned root issuer (== `grant.issuer`).
pub fn verify_chain(chain: &[Value], expected_root_principal: &str, leaf: &LeafSig) -> ChainVerdict {
    verify_chain_with(chain, expected_root_principal, None, leaf)
}

/// [`verify_chain`] with the verifier's stored grant as `trusted_root` (the PCActn path: the root is the grant, so a PQ root
/// verifies under its own `pq_pk` exactly when it IS the stored grant, `verifyChain(..., {trustedRoot: grant})`).
pub fn verify_chain_with(chain: &[Value], expected_root_principal: &str, trusted_root: Option<&Value>, leaf: &LeafSig) -> ChainVerdict {
    let hops = verify_hops_with(chain, expected_root_principal, trusted_root);
    if !hops.ok {
        return hops;
    }
    // ---- leaf PCActn signature under the leaf capability holder -----------------------------------
    let leaf_cap = &chain[chain.len() - 1];
    let leaf_holder = leaf_cap.get("holder").and_then(|v| v.as_str()).unwrap_or("");
    if !verify_leaf_suite(leaf, leaf_holder, leaf_cap.get("holder_pq").and_then(|v| v.as_str())) {
        return ChainVerdict::deny("leaf signature does not verify under the leaf holder key");
    }
    ChainVerdict::ok()
}

/// The hop-only part of [`verify_chain`] (the faithful port of `capability.ts` `verifyChain`, without the
/// leaf PCActn signature). Exposed so the verdict AND reason can be compared 1:1 with the TypeScript
/// reference in the cross-implementation tests.
pub fn verify_hops(chain: &[Value], expected_root_principal: &str) -> ChainVerdict {
    verify_hops_with(chain, expected_root_principal, None)
}

/// [`verify_hops`] with an optional `trusted_root` (the verifier's stored grant; R3-01).
pub fn verify_hops_with(chain: &[Value], expected_root_principal: &str, trusted_root: Option<&Value>) -> ChainVerdict {
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
    // R3-01: a PQ ROOT's key must come from verifier-side authority: here, the verifier's stored copy of this very grant.
    let root_alg = resolve_alg(root.get("alg"));
    let root_pq = match root_alg {
        Some(a) if a != "ed25519" => {
            let trusted = trusted_root.is_some_and(|t| hash_canonical(t) == hash_canonical(root));
            match root.get("pq_pk").and_then(|v| v.as_str()) {
                Some(pk) if trusted => Some(pk),
                _ => {
                    return ChainVerdict::deny(format!(
                        "hop 0: root suite '{a}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
                    ))
                }
            }
        }
        _ => None,
    };
    if let Err(e) = check_sig(root, root_issuer, "hop 0", root_pq) {
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
        // F-2: a PQ hop's key must be the one the parent's holder committed to (`holder_pq`).
        let hop_alg = resolve_alg(c.get("alg"));
        let hop_pq_pk = c.get("pq_pk").and_then(|v| v.as_str());
        if let Some(e) = pq_binding_error(hop_alg, hop_pq_pk, parent.get("holder_pq").and_then(|v| v.as_str()), &label) {
            return ChainVerdict::deny(e);
        }
        let hop_pq = if hop_alg.is_some_and(|a| a != "ed25519") { hop_pq_pk } else { None };
        if let Err(e) = check_sig(c, parent_holder, &label, hop_pq) {
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

    ChainVerdict::ok()
}
