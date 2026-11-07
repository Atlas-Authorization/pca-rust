//! Transparency-anchored allowlist verification (wire level), the native counterpart of `verifyAllowlistAnchored` in
//! `@atlasauth/pca`. It checks the log evidence for a manifest that has ALREADY been signature-verified elsewhere: an
//! Ed25519 signed tree head, the RFC 6962 root over the supplied anchor entries, the manifest's inclusion proof, the
//! RFC 9162 consistency proof from a cached head, head freshness and the per-issuer version rules. Same outcome codes as
//! the reference; the reason text is not part of the contract. Heads must use the default Ed25519 suite (a head naming a
//! post-quantum suite is reported as `bad-head` here; the TypeScript verifier handles those).

use super::{b64_encode, canonicalize_strict, hash_canonical_strict, merkle_root, safe_int, sha, verify_b64u, verify_inclusion};
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

/// The reference's `entries.length > MAX_FEED || entries.length !== head.size` (refused as `feed-mismatch`); the cap bounds the
/// hashing work before the root comparison.
fn feed_size_ok(n: usize, size: i64) -> bool {
    n <= MAX_FEED && n as i64 == size
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
    // the reference counts the issuer in UTF-16 code units (`r['issuer'].length <= 200`)
    if issuer.is_empty() || issuer.encode_utf16().count() > 200 || version < 1 || !digest_ok {
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
            // the reference's verifyHeadConsistency: sizes bound to the heads, the prev_root link, then the shared ledger verifier
            let ok = ev.get("consistency").filter(|c| c.is_object()).map_or(false, |c| {
                c.get("oldSize").and_then(safe_int) == Some(cached.size)
                    && c.get("newSize").and_then(safe_int) == Some(head.size)
                    && !(head.size == cached.size + 1 && head.prev_root != cached.root)
                    && crate::ledger::verify_ledger_consistency(&json!(cached.root), &json!(head.root), c)
            });
            if !ok {
                return Err("inconsistent-with-cache");
            }
        }
    }

    if !feed_size_ok(entries_v.len(), head.size) {
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

#[cfg(test)]
mod tests {
    use super::{entry_of, feed_size_ok, MAX_FEED};
    use serde_json::json;

    /// attest-proved.ts validEntry: issuer 1..200 UTF-16 units, version a safe integer >= 1, digest /^[A-Za-z0-9_-]{43}$/;
    /// each condition fails alone.
    #[test]
    fn anchor_entries_are_checked_like_the_reference() {
        let d43 = "A".repeat(42) + "_";
        let ok = |issuer: &str, version: i64, digest: &str| entry_of(&json!({"issuer": issuer, "version": version, "digest": digest})).is_some();
        assert!(ok("iss", 1, &d43));
        assert!(!ok("", 1, &d43));
        assert!(ok(&"i".repeat(200), 1, &d43) && !ok(&"i".repeat(201), 1, &d43));
        // 200 UTF-16 units of a 2-byte character is 400 bytes: still within the reference's limit
        assert!(ok(&"\u{e9}".repeat(200), 1, &d43) && !ok(&"\u{e9}".repeat(201), 1, &d43));
        assert!(!ok("iss", 0, &d43));
        for bad in ["A".repeat(42), "A".repeat(44), "A".repeat(42) + "=", "A".repeat(42) + "+"] {
            assert!(!ok("iss", 1, &bad), "{bad}");
        }
        assert!(entry_of(&json!({"issuer": "iss", "version": 1, "digest": d43, "x": 1})).is_none());
    }

    /// attest-proved.ts:386 `entries.length > MAX_FEED || entries.length !== head.size` (MAX_FEED = 100_000, line 328).
    #[test]
    fn the_feed_is_bounded_and_must_match_the_signed_size() {
        assert_eq!(MAX_FEED, 100_000);
        assert!(feed_size_ok(MAX_FEED, MAX_FEED as i64));
        assert!(!feed_size_ok(MAX_FEED + 1, MAX_FEED as i64 + 1));
        assert!(!feed_size_ok(5, 6) && !feed_size_ok(6, 5));
        assert!(feed_size_ok(0, 0));
    }
}
