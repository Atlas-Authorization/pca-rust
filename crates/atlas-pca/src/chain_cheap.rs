//! The cheap, pre-authentication chain check (`verifyChainCheap`): the shape, caveat limit, depth, suite allow-list, body digest and
//! parent links of every hop and the Ed25519 half of every Ed25519 or hybrid hop: at most [`crate::MAX_CHAIN_DEPTH`] Ed25519
//! verifications whatever suites the chain names, and no post-quantum verification at all. A pure post-quantum hop passes on structure alone
//! and is decided only by the full [`crate::verify_chain`].
//!
//! `Ok` is NEVER an authentication: the caller must still run the full verifier (after matching the root to a stored grant) before treating
//! the chain as authentic. The number of hops that still need a post-quantum verification is the `Ok` value.
use crate::{
    alg_name, body_of, body_too_deep, caveat_limit_exceeded, decode_b64u_strict, hash_canonical_strict, hop_well_typed, str_of, suite_allowed, verify_b64u,
    CAP_DOMAIN, CAVEAT_LIMIT_REASON, MAX_CHAIN_DEPTH, REGISTERED_SUITES,
};
use serde_json::Value;

/// The number of hops that still need a post-quantum verification, or the first reason the chain is refused. `allowed` is the suite
/// allow-list (`None` allows every registered suite).
pub fn verify_chain_cheap(chain: &[Value], expected_root_issuer: Option<&str>, allowed: Option<&[String]>) -> Result<usize, String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(format!("chain too long (max {MAX_CHAIN_DEPTH} hops)"));
    }
    if caveat_limit_exceeded(chain) {
        return Err(CAVEAT_LIMIT_REASON.into());
    }
    let mut pq_hops = 0;
    for (i, hop) in chain.iter().enumerate() {
        let label = format!("hop {i}");
        if !hop_well_typed(hop) {
            return Err(format!("{label}: malformed capability"));
        }
        let c = hop.as_object().ok_or_else(|| format!("{label}: malformed capability"))?;
        let alg = alg_name(c.get("alg"));
        if !REGISTERED_SUITES.contains(&alg.as_str()) {
            return Err(format!("{label}: unknown signature alg '{alg}'"));
        }
        if !suite_allowed(c.get("alg"), allowed) {
            return Err(format!("{label}: signature suite '{alg}' is not allowed by this verifier's suite policy"));
        }
        let parent = if i == 0 {
            if c.contains_key("parent") {
                return Err("hop 0: root must not have a parent".into());
            }
            if expected_root_issuer.is_some_and(|e| str_of(c, "issuer") != e) {
                return Err("hop 0: root issuer is not the expected principal".into());
            }
            None
        } else {
            let p = chain[i - 1].as_object().ok_or_else(|| format!("{label}: malformed"))?;
            if hash_canonical_strict(&chain[i - 1]).as_deref() != c.get("parent").and_then(Value::as_str) {
                return Err(format!("{label}: broken parent link"));
            }
            if c.get("issuer") != p.get("holder") {
                return Err(format!("{label}: issuer is not the parent's bound holder"));
            }
            Some(p)
        };
        // the signed body: the hop body plus the suite fields a non-default suite binds in
        if body_too_deep(c) {
            return Err(format!("{label}: malformed body"));
        }
        let mut body = body_of(c);
        let needs_pq = alg != "ed25519";
        if needs_pq {
            if let Value::Object(m) = &mut body {
                m.insert("alg".into(), Value::String(alg.clone()));
                if let Some(pk @ Value::String(_)) = c.get("pq_pk") {
                    m.insert("pq_pk".into(), pk.clone());
                }
            }
        }
        let Some(digest) = hash_canonical_strict(&body) else { return Err(format!("{label}: malformed body")) };
        let bd = str_of(c, "body_digest");
        if digest != bd || str_of(c, "id") != bd {
            return Err(format!("{label}: body digest mismatch"));
        }
        if alg == "ed25519" || alg.starts_with("hybrid-") {
            let signer = parent.map_or_else(|| str_of(c, "issuer"), |p| str_of(p, "holder"));
            let msg = decode_b64u_strict(bd, Some(32)).map(|d| [CAP_DOMAIN, d.as_slice()].concat());
            if !msg.is_some_and(|m| verify_b64u(signer, &m, str_of(c, "sig"))) {
                return Err(format!("{label}: bad signature (not signed by expected key)"));
            }
        }
        if needs_pq {
            pq_hops += 1;
        }
    }
    Ok(pq_hops)
}
