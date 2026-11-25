//! Chain compaction (`chain-compact.ts`): a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus the
//! leaf hop. A verifier that verified the full chain once remembers it under that root ([`ChainMemo`]); later presentations carry only
//! `{depth, hops_root, leaf}`.
//!
//!  - The root commits to the order and the number of hops: another chain, an inserted, dropped or reordered hop has another root.
//!  - Nothing is trusted from the presentation. A compact chain resolves only against the verifier's OWN memo, which only
//!    [`ChainMemo::remember_verified`] fills, and that runs [`crate::verify_chain`] itself, so an unverified chain cannot be remembered.
//!  - What a compact chain gives the caveat layer is a [`ChainView`]: hop count, per-hop hash and caveat-list length, and the leaf.
//!
//! Scope: the verifier-side fold. The PCActn wire still carries `cap_chain`. `evaluate_k1_in`, `bound_caveats_in` and `verify_narrow_in`
//! take a full chain or a [`ChainView`] (`ChainInput`): the view feeds identity and accounting (`n`, `hash`, `count`, `leaf`) and is built
//! from a full chain with [`chain_view`] or from a verified memo.
use crate::intent_strict::closed_members_error;
use crate::{hash_canonical_strict, merkle_root, safe_int, verify_chain, MAX_CHAIN_DEPTH};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub const CHAIN_HOP_DOMAIN: &str = "atlas-pca/chain-hop/v1";
/// A memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time).
pub const CHAIN_MEMO_MAX_TTL_MS: i64 = 3_600_000;
pub const CHAIN_MEMO_DEFAULT_MAX_ENTRIES: usize = 10_000;

/// The hops, hashes and caveat counts of a chain, without the middle hops when it came from a memo.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainView {
    pub n: usize,
    pub leaf: Value,
    hashes: Vec<String>,
    counts: Vec<usize>,
}

impl ChainView {
    /// The strict content hash of hop `i`.
    pub fn hash(&self, i: usize) -> Option<&str> {
        self.hashes.get(i).map(String::as_str)
    }
    /// The length of hop `i`'s (cumulative) caveat list.
    pub fn count(&self, i: usize) -> Option<usize> {
        self.counts.get(i).copied()
    }
}

fn caveat_count(hop: &Value) -> usize {
    hop.get("caveats").and_then(Value::as_array).map_or(0, Vec::len)
}

/// The view of the hops the policy layer sees: the chain (root first), else the grant alone. `None` when a hop is outside the strict
/// JSON profile (a malformed chain).
pub fn chain_view(grant: &Value, chain: &Value) -> Option<ChainView> {
    let hops: Vec<&Value> = match chain.as_array() {
        Some(a) if !a.is_empty() => a.iter().collect(),
        _ => vec![grant],
    };
    let hashes = hops.iter().map(|h| hash_canonical_strict(h)).collect::<Option<Vec<_>>>()?;
    Some(ChainView { n: hops.len(), leaf: (*hops.last()?).clone(), hashes, counts: hops.iter().map(|h| caveat_count(h)).collect() })
}

/// The view of a full chain, for symmetry with [`ChainMemo::resolve`].
pub fn view_of_chain(grant: &Value, chain: &Value) -> Option<ChainView> {
    chain_view(grant, chain)
}

/// The Merkle leaf of one hop: its content hash under a domain tag.
pub fn hop_leaf(hop: &Value) -> Option<Value> {
    Some(json!({"d": CHAIN_HOP_DOMAIN, "hop": hash_canonical_strict(hop)?}))
}

/// The handle of a chain: Merkle root over the ordered hop leaves.
pub fn hops_root(chain: &[Value]) -> Result<String, String> {
    let leaves = chain.iter().map(hop_leaf).collect::<Option<Vec<_>>>().ok_or("a hop is outside the strict JSON profile")?;
    merkle_root(&leaves)
}

/// Fold a chain into `{v, kind, depth, hops_root, leaf}`. `Err` on an empty or over-deep chain. Does not verify it (the memo does).
pub fn compact_chain(chain: &[Value]) -> Result<Value, String> {
    if chain.is_empty() || chain.len() > MAX_CHAIN_DEPTH {
        return Err("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops".into());
    }
    Ok(json!({"v": 1, "kind": "pca-chain-compact", "depth": chain.len(), "hops_root": hops_root(chain)?, "leaf": chain[chain.len() - 1]}))
}

/// Why `c` is not a compact chain, or `None` when it is well formed.
pub fn compact_chain_shape_error(c: &Value) -> Option<String> {
    let Some(o) = c.as_object() else { return Some("not an object".into()) };
    if let Some(e) = closed_members_error(o, &["v", "kind", "depth", "hops_root", "leaf"], &[], "compact chain") {
        return Some(e);
    }
    if safe_int(&o["v"]) != Some(1) || o["kind"].as_str() != Some("pca-chain-compact") {
        return Some("not a pca-chain-compact v1".into());
    }
    if !safe_int(&o["depth"]).is_some_and(|d| (1..=MAX_CHAIN_DEPTH as i64).contains(&d)) {
        return Some(format!("depth must be 1..{MAX_CHAIN_DEPTH}"));
    }
    if o["hops_root"].as_str().is_none_or(|s| s.chars().count() != 43) {
        return Some("hops_root must be a 43 character digest".into());
    }
    if !o["leaf"].is_object() {
        return Some("leaf must be a capability".into());
    }
    None
}

struct MemoEntry {
    depth: usize,
    hashes: Vec<String>,
    counts: Vec<usize>,
    expires_at: i64,
}

/// The verifier-side memo: remembers a chain only after its own [`verify_chain`] pass, and never evicts a live entry (a full memo
/// refuses, so one tenant cannot push another out).
pub struct ChainMemo {
    entries: Mutex<HashMap<String, MemoEntry>>,
    max_entries: usize,
    ttl_ms: i64,
}

impl Default for ChainMemo {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl ChainMemo {
    /// `max_entries` default [`CHAIN_MEMO_DEFAULT_MAX_ENTRIES`]; `ttl_ms` default and ceiling [`CHAIN_MEMO_MAX_TTL_MS`].
    pub fn new(max_entries: Option<usize>, ttl_ms: Option<i64>) -> Self {
        ChainMemo {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.unwrap_or(CHAIN_MEMO_DEFAULT_MAX_ENTRIES),
            ttl_ms: ttl_ms.unwrap_or(CHAIN_MEMO_MAX_TTL_MS).min(CHAIN_MEMO_MAX_TTL_MS),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |m| m.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verify `chain` (rooted at `expected_root_issuer`) with the full verifier and remember it. `Err` when the chain does not verify or
    /// the memo is full of live entries. Returns the compact form a holder presents.
    pub fn remember_verified(&self, chain: &[Value], expected_root_issuer: &str, now: i64) -> Result<Value, String> {
        verify_chain(chain, Some(expected_root_issuer)).map_err(|r| format!("rememberVerified: the chain does not verify: {r}"))?;
        let compact = compact_chain(chain)?;
        let root = compact["hops_root"].as_str().unwrap_or("").to_string();
        let hashes = chain.iter().map(hash_canonical_strict).collect::<Option<Vec<_>>>().ok_or("a hop is outside the strict JSON profile")?;
        let mut m = self.entries.lock().map_err(|_| "the memo lock is poisoned".to_string())?;
        m.retain(|_, e| e.expires_at >= now);
        if !m.contains_key(&root) && m.len() >= self.max_entries {
            return Err("rememberVerified: the memo is full of live entries".into());
        }
        m.insert(root, MemoEntry { depth: chain.len(), hashes, counts: chain.iter().map(caveat_count).collect(), expires_at: now.saturating_add(self.ttl_ms) });
        Ok(compact)
    }

    /// Drop entries whose time is up.
    pub fn prune(&self, now: i64) {
        if let Ok(mut m) = self.entries.lock() {
            m.retain(|_, e| e.expires_at >= now);
        }
    }

    /// Forget a chain (e.g. when it is revoked).
    pub fn forget(&self, hops_root_value: &str) -> bool {
        self.entries.lock().is_ok_and(|mut m| m.remove(hops_root_value).is_some())
    }

    /// Resolve a presented compact chain against the memo: its view, or the reason it is refused. Total.
    pub fn resolve(&self, compact: &Value, now: i64) -> Result<ChainView, String> {
        if let Some(e) = compact_chain_shape_error(compact) {
            return Err(format!("malformed compact chain: {e}"));
        }
        let c: &Map<String, Value> = compact.as_object().ok_or("malformed compact chain")?;
        let root = c["hops_root"].as_str().unwrap_or("");
        let mut m = self.entries.lock().map_err(|_| "compact chain error (fail closed): the memo lock is poisoned".to_string())?;
        let Some(e) = m.get(root) else { return Err("the chain is not in this verifier memo (present the full chain)".into()) };
        if e.expires_at < now {
            m.remove(root);
            return Err("the memoized chain has expired (present the full chain)".into());
        }
        if safe_int(&c["depth"]) != Some(e.depth as i64) {
            return Err("the depth differs from the memoized chain".into());
        }
        let leaf = &c["leaf"];
        if hash_canonical_strict(leaf).as_deref() != e.hashes.last().map(String::as_str) {
            return Err("the leaf is not the memoized last hop".into());
        }
        if leaf.get("caveats").and_then(Value::as_array).map(Vec::len) != e.counts.last().copied() {
            return Err("the leaf caveats differ from the memoized chain".into());
        }
        Ok(ChainView { n: e.depth, leaf: leaf.clone(), hashes: e.hashes.clone(), counts: e.counts.clone() })
    }
}
