//! Transparency-anchored allowlist verification (wire level), the native counterpart of `verifyAllowlistAnchored` in
//! `@atlasauth/pca`. It checks the log evidence for a manifest that has ALREADY been signature-verified elsewhere: an
//! Ed25519 signed tree head, the RFC 6962 root over the supplied anchor entries, the manifest's inclusion proof, the
//! RFC 9162 consistency proof from a cached head, head freshness and the per-issuer version rules. Same outcome codes as
//! the reference; the reason text is not part of the contract. Heads must use the default Ed25519 suite (a head naming a
//! post-quantum suite is reported as `bad-head` here; the TypeScript verifier handles those).

use super::{b64_encode, canonicalize_strict, decode_b64u_strict, hash_canonical_strict, merkle_root, node_hash, safe_int, sha, verify_b64u, verify_inclusion};
use serde_json::{json, Value};
use std::collections::HashMap;

const ANCHOR_DOMAIN: &str = "pca-attest-allowlist-anchor/v1";
const STH_DOMAIN: &[u8] = b"atlas-pca/sth/v1\0";
const MAX_FEED: usize = 100_000;
const DEFAULT_SKEW_MS: i64 = 60_000;
const DEFAULT_AGE_MS: i64 = 86_400_000;

/// What the operator publishes per manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEntry {
    pub issuer: String,
    pub version: i64,
    pub digest: String,
}

/// Pinned log identity plus the verification clock and optional bounds.
pub struct AnchorOptions<'a> {
    /// b64u Ed25519 public key of the log guardian.
    pub log_key: &'a str,
    pub instance_id: &'a str,
    pub principal: &'a str,
    pub now_ms: i64,
    pub max_head_age_ms: Option<i64>,
    pub clock_skew_ms: Option<i64>,
    /// A previously accepted signed tree head.
    pub cached_head: Option<&'a Value>,
}

/// `Ok(highest anchored version)` or the outcome code (`bad-head`, `stale-head`, `feed-mismatch`, ...).
pub type AnchorResult = Result<i64, &'static str>;

fn commit(e: &AnchorEntry) -> Option<String> {
    hash_canonical_strict(&json!({ "domain": ANCHOR_DOMAIN, "issuer": e.issuer, "version": e.version, "digest": e.digest }))
}

struct Head {
    instance_id: String,
    principal: String,
    root: String,
    prev_root: String,
    size: i64,
    timestamp: i64,
}

fn read_head(v: &Value, log_key: &str) -> Option<Head> {
    let m = v.as_object()?;
    if m.contains_key("alg") {
        return None; // only the default Ed25519 suite is supported natively
    }
    let s = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
    let h = Head {
        instance_id: s("instance_id")?,
        principal: s("principal")?,
        root: s("root")?,
        prev_root: s("prev_root")?,
        size: m.get("size").and_then(safe_int)?,
        timestamp: m.get("timestamp").and_then(safe_int)?,
    };
    let guardian = s("guardian")?;
    let sig = s("sig")?;
    if h.size < 0 || guardian != log_key {
        return None;
    }
    let body = canonicalize_strict(&json!({
        "instance_id": h.instance_id, "principal": h.principal, "size": h.size,
        "root": h.root, "prev_root": h.prev_root, "timestamp": h.timestamp,
    }))
    .ok()?;
    let mut msg = STH_DOMAIN.to_vec();
    msg.extend_from_slice(body.as_bytes());
    if !verify_b64u(log_key, &msg, &sig) {
        return None;
    }
    Some(h)
}

fn empty_root() -> String {
    b64_encode(&sha(b""))
}

/// RFC 9162 section 2.1.4.2 over the base64url roots and path.
fn verify_consistency(old_root: &str, new_root: &str, old_size: i64, new_size: i64, path: &[Value]) -> bool {
    if old_size < 0 || old_size > new_size || path.len() > 2 * 53 + 2 {
        return false;
    }
    if old_size == 0 {
        if !path.is_empty() || old_root != empty_root() {
            return false;
        }
        return if new_size == 0 { new_root == empty_root() } else { true };
    }
    if old_size == new_size {
        return path.is_empty() && old_root == new_root;
    }
    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(path.len() + 1);
    for p in path {
        match p.as_str().and_then(|s| decode_b64u_strict(s, Some(32))) {
            Some(b) => nodes.push(b),
            None => return false,
        }
    }
    if (old_size as u64).is_power_of_two() {
        match decode_b64u_strict(old_root, Some(32)) {
            Some(o) => nodes.insert(0, o),
            None => return false,
        }
    }
    if nodes.is_empty() {
        return false;
    }
    let (mut fnn, mut snn) = ((old_size - 1) as u64, (new_size - 1) as u64);
    while fnn & 1 == 1 {
        fnn >>= 1;
        snn >>= 1;
    }
    let (mut fr, mut sr) = (nodes[0].clone(), nodes[0].clone());
    for c in &nodes[1..] {
        if snn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == snn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fnn & 1 == 0 && fnn != 0 {
                fnn >>= 1;
                snn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnn >>= 1;
        snn >>= 1;
    }
    snn == 0 && b64_encode(&fr) == old_root && b64_encode(&sr) == new_root
}

fn entry_of(v: &Value) -> Option<AnchorEntry> {
    let m = v.as_object()?;
    if m.len() != 3 {
        return None;
    }
    let issuer = m.get("issuer")?.as_str()?;
    let digest = m.get("digest")?.as_str()?;
    let version = m.get("version").and_then(safe_int)?;
    let digest_ok = digest.len() == 43 && digest.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if issuer.is_empty() || issuer.len() > 200 || version < 1 || !digest_ok {
        return None;
    }
    Some(AnchorEntry { issuer: issuer.to_string(), version, digest: digest.to_string() })
}

/// Check `mine` (a signature-verified manifest's issuer, version and digest) against the log evidence
/// `{ head, entries, proof, consistency? }`. Never panics.
pub fn verify_allowlist_anchored(mine: &AnchorEntry, evidence: Option<&Value>, opts: &AnchorOptions) -> AnchorResult {
    let ev = match evidence.and_then(Value::as_object) {
        Some(e) => e,
        None => return Err("missing-proof"),
    };
    let (proof, entries_v) = match (ev.get("proof").and_then(Value::as_object), ev.get("entries").and_then(Value::as_array)) {
        (Some(p), Some(e)) if ev.get("head").map_or(false, |h| !h.is_null()) => (p, e),
        _ => return Err("missing-proof"),
    };
    let head = match read_head(&ev["head"], opts.log_key) {
        Some(h) => h,
        None => return Err("bad-head"),
    };
    if head.instance_id != opts.instance_id || head.principal != opts.principal {
        return Err("bad-head");
    }
    let skew = opts.clock_skew_ms.unwrap_or(DEFAULT_SKEW_MS).max(0);
    let max_age = opts.max_head_age_ms.unwrap_or(DEFAULT_AGE_MS);
    if head.timestamp > opts.now_ms.saturating_add(skew) || opts.now_ms.saturating_sub(head.timestamp) > max_age {
        return Err("stale-head");
    }

    if let Some(cv) = opts.cached_head {
        let cached = match read_head(cv, opts.log_key) {
            Some(c) if c.instance_id == opts.instance_id && c.principal == opts.principal => c,
            _ => return Err("bad-cache"),
        };
        if head.size < cached.size {
            return Err("log-rollback");
        }
        if head.size == cached.size && head.root != cached.root {
            return Err("split-view");
        }
        if head.size > cached.size {
            let ok = ev.get("consistency").and_then(Value::as_object).map_or(false, |c| {
                let (old_s, new_s, path) = (c.get("oldSize").and_then(safe_int), c.get("newSize").and_then(safe_int), c.get("path").and_then(Value::as_array));
                match (old_s, new_s, path) {
                    (Some(o), Some(n), Some(p)) => {
                        o == cached.size && n == head.size && !(head.size == cached.size + 1 && head.prev_root != cached.root) && verify_consistency(&cached.root, &head.root, o, n, p)
                    }
                    _ => false,
                }
            });
            if !ok {
                return Err("inconsistent-with-cache");
            }
        }
    }

    if entries_v.len() > MAX_FEED || entries_v.len() as i64 != head.size {
        return Err("feed-mismatch");
    }
    let mut entries = Vec::with_capacity(entries_v.len());
    let mut commits = Vec::with_capacity(entries_v.len());
    for e in entries_v {
        let ae = entry_of(e).ok_or("feed-mismatch")?;
        commits.push(Value::String(commit(&ae).ok_or("feed-mismatch")?));
        entries.push(ae);
    }
    let root = if commits.is_empty() { empty_root() } else { merkle_root(&commits).map_err(|_| "feed-mismatch")? };
    if root != head.root {
        return Err("feed-mismatch");
    }

    let mut digests: HashMap<i64, &str> = HashMap::new();
    let mut highest = 0i64;
    for e in entries.iter().filter(|e| e.issuer == mine.issuer) {
        if let Some(d) = digests.get(&e.version) {
            if *d != e.digest {
                return Err("log-conflict");
            }
        }
        digests.insert(e.version, &e.digest);
        highest = highest.max(e.version);
    }
    let my_commit = commit(mine).ok_or("bad-proof")?;
    if proof.get("size").and_then(safe_int) != Some(head.size) {
        return Err("bad-proof");
    }
    if !verify_inclusion(&head.root, Some(proof), &Value::String(my_commit)) {
        return Err("bad-proof");
    }
    if mine.version < highest {
        return Err("anchored-rollback");
    }
    if digests.get(&mine.version).copied() != Some(mine.digest.as_str()) {
        return Err("not-anchored");
    }
    Ok(highest)
}
