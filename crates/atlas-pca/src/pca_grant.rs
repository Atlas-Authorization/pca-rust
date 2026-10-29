//! The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check.
//! The type is a pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Total: malformed
//! input is a refusal code, never a panic.
use crate::{decode_b64u_strict, hash_canonical_strict, safe_int};
use serde_json::{json, Value};

pub const PCA_GRANT_TYPE: &str = "pca_grant";
pub const PCA_GRANT_DOMAIN: &str = "atlas-pca/pca-grant-chain/v1";
const MAX_DETAILS: usize = 16;
const MAX_CHAIN_LEN: i64 = 16;
const MAX_URL: usize = 2048;
const MAX_LOCATIONS: usize = 8;
const MEMBERS: [&str; 6] = ["type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations"];
const REFUSED: [&str; 4] = ["actions", "datatypes", "identifier", "privileges"];

/// https URL: starts with `https://`, only printable ASCII without `#` or `\`, at most 2048 characters, non-empty authority
/// (up to the first `/` or `?`) without `@`.
pub fn is_https_url(v: &Value) -> bool {
    let Some(u) = v.as_str() else { return false };
    if u.len() > MAX_URL || !u.starts_with("https://") {
        return false;
    }
    if u.bytes().any(|c| !(0x21..=0x7e).contains(&c) || c == b'#' || c == b'\\') {
        return false;
    }
    let rest = &u[8..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    !authority.is_empty() && !authority.contains('@')
}

/// Digest over the first hops' capability ids.
pub fn chain_digest(ids: &[&str]) -> Option<String> {
    hash_canonical_strict(&json!({ "d": PCA_GRANT_DOMAIN, "ids": ids }))
}

/// `Ok(())` for an accepted detail, else the refusal code.
pub fn validate_detail(x: &Value) -> Result<(), &'static str> {
    let Some(m) = x.as_object() else { return Err("bad_entry") };
    if m.get("type").and_then(Value::as_str) != Some(PCA_GRANT_TYPE) {
        return Err("bad_type");
    }
    for k in m.keys() {
        if REFUSED.contains(&k.as_str()) {
            return Err("refused_member");
        }
        if !MEMBERS.contains(&k.as_str()) {
            return Err("unknown_member");
        }
    }
    match m.get("chain_digest").and_then(Value::as_str) {
        Some(d) if decode_b64u_strict(d, Some(32)).is_some() => {}
        _ => return Err("bad_chain_digest"),
    }
    match m.get("chain_len").and_then(safe_int) {
        Some(n) if (1..=MAX_CHAIN_LEN).contains(&n) => {}
        _ => return Err("bad_chain_len"),
    }
    if let Some(r) = m.get("chain_ref") {
        if !is_https_url(r) {
            return Err("bad_chain_ref");
        }
    }
    if let Some(r) = m.get("bundle_revision") {
        if safe_int(r).filter(|n| *n >= 0).is_none() {
            return Err("bad_bundle_revision");
        }
    }
    if let Some(l) = m.get("locations") {
        match l.as_array() {
            Some(a) if !a.is_empty() && a.len() <= MAX_LOCATIONS && a.iter().all(is_https_url) => {}
            _ => return Err("bad_locations"),
        }
    }
    Ok(())
}

/// The `pca_grant` entries of an `authorization_details` array, or the refusal code. Other types are skipped.
pub fn parse_details(arr: &Value) -> Result<Vec<Value>, &'static str> {
    let Some(a) = arr.as_array() else { return Err("not_an_array") };
    if a.len() > MAX_DETAILS {
        return Err("too_many_details");
    }
    let mut out = Vec::new();
    for e in a {
        let Some(t) = e.as_object().and_then(|m| m.get("type")).and_then(Value::as_str) else {
            return Err("bad_entry");
        };
        if t != PCA_GRANT_TYPE {
            continue;
        }
        validate_detail(e)?;
        out.push(e.clone());
    }
    Ok(out)
}

/// Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource).
/// `Ok(index)` of the passing detail, else the deny code.
pub fn check_presentation(
    details: &[Value],
    resource: &str,
    chain_ids: &[&str],
    proof_verified: bool,
) -> Result<usize, &'static str> {
    if details.is_empty() {
        return Err("no_detail");
    }
    if !proof_verified {
        return Err("proof_required");
    }
    let mut reason = "chain_mismatch";
    for (i, d) in details.iter().enumerate() {
        let n = d.get("chain_len").and_then(safe_int).unwrap_or(0) as usize;
        if n == 0 || chain_ids.len() < n {
            continue;
        }
        if chain_digest(&chain_ids[..n]).as_deref() != d.get("chain_digest").and_then(Value::as_str) {
            continue;
        }
        if let Some(loc) = d.get("locations").and_then(Value::as_array) {
            if !loc.iter().any(|u| u.as_str() == Some(resource)) {
                reason = "wrong_location";
                continue;
            }
        }
        return Ok(i);
    }
    Err(reason)
}
