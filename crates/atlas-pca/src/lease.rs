//! Leases (verification side): a time-boxed grant that must be renewed, has a hard `max_ttl` cap, and dies when revoked. Records and
//! revocations are Ed25519-signed under a domain string over strict-canonical JSON. [`LeaseRegistry`] keeps the newest record per
//! `lease_id` plus the revocations in a REQUIRED atomic key-value store (sharded like lease.ts); [`check_lease`] gates a presented record. Total: no function panics.
//! Replays packages/pca/conformance/lease-vectors.json.
use crate::fresh_at::verify_body;
use crate::safe_int;
use crate::authorize::StoreError;
use crate::kv::AtomicKv;
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const LEASE_DOMAIN: &str = "atlas-pca/lease/v1\0";
pub const LEASE_REVOKE_DOMAIN: &str = "atlas-pca/lease-revoke/v1\0";
const BODY_KEYS: [&str; 14] = ["v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"];
const REV_KEYS: [&str; 5] = ["v", "target", "value", "revoked_at", "authority"];

pub(crate) fn s(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|x| !x.is_empty() && x.encode_utf16().count() <= max)
}
pub(crate) fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}
pub(crate) fn int(v: &Value, k: &str) -> i64 {
    nat(v.get(k)).unwrap_or(0)
}
pub(crate) fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// `^[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}$`
fn path_ok(p: &str) -> bool {
    let segs: Vec<&str> = p.split('/').collect();
    segs.len() <= 8 && segs.iter().all(|g| (1..=64).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')))
}

pub(crate) fn pick(v: &Value, keys: &[&str]) -> Value {
    let mut m = Map::new();
    for k in keys {
        if let Some(x) = v.get(*k) {
            m.insert((*k).to_string(), x.clone());
        }
    }
    Value::Object(m)
}

pub fn lease_cap(l: &Value) -> i64 {
    int(l, "issued_at") + int(l, "max_ttl")
}

fn well_formed(l: &Value) -> bool {
    if !l.is_object() || l.get("v").and_then(safe_int) != Some(1) {
        return false;
    }
    if !(s(l.get("lease_id"), 128) && s(l.get("grant_ref"), 256) && s(l.get("holder"), 128) && s(l.get("requester"), 128) && s(l.get("authority"), 128) && s(l.get("justification_digest"), 128)) {
        return false;
    }
    if !l.get("path").and_then(Value::as_str).is_some_and(path_ok) {
        return false;
    }
    if !["seq", "issued_at", "renewed_at", "expires_at", "max_ttl"].iter().all(|k| nat(l.get(*k)).is_some()) {
        return false;
    }
    let (seq, issued, renewed, expires) = (int(l, "seq"), int(l, "issued_at"), int(l, "renewed_at"), int(l, "expires_at"));
    if seq < 1 || int(l, "max_ttl") < 1 || renewed < issued || expires <= renewed || (seq == 1 && renewed != issued) {
        return false;
    }
    l.get("approvers").and_then(Value::as_array).is_some_and(|a| a.len() <= 16 && a.iter().all(|x| s(Some(x), 128)))
}

/// Well formed and signed by its `authority` over exactly its content. Does NOT check the cap.
pub fn verify_lease(l: &Value) -> bool {
    well_formed(l) && verify_body(LEASE_DOMAIN, &pick(l, &BODY_KEYS), text(l, "authority"), l.get("sig").and_then(Value::as_str))
}

fn rev_well_formed(r: &Value) -> bool {
    if !r.is_object() || r.get("v").and_then(safe_int) != Some(1) || !s(r.get("value"), 256) || !s(r.get("authority"), 128) || nat(r.get("revoked_at")).is_none() {
        return false;
    }
    match text(r, "target") {
        "lease" | "grant" => true,
        "prefix" => path_ok(text(r, "value")),
        _ => false,
    }
}

pub fn verify_lease_revocation(r: &Value) -> bool {
    rev_well_formed(r) && verify_body(LEASE_REVOKE_DOMAIN, &pick(r, &REV_KEYS), text(r, "authority"), r.get("sig").and_then(Value::as_str))
}

/// `prefix` covers `path` iff equal or `path` continues it at a segment boundary.
pub fn path_under(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

fn covers(r: &Value, l: &Value) -> bool {
    if int(l, "issued_at") > int(r, "revoked_at") {
        return false;
    }
    match text(r, "target") {
        "lease" => text(l, "lease_id") == text(r, "value"),
        "grant" => text(l, "grant_ref") == text(r, "value"),
        _ => path_under(text(l, "path"), text(r, "value")),
    }
}

/// `min_approvals` `None` = 1; `eligible` `None` = any approver; `fresh_justification` default true (use [`LeasePolicy::new`]).
#[derive(Debug, Clone)]
pub struct LeasePolicy {
    pub authorities: Vec<String>,
    pub min_approvals: Option<i64>,
    pub eligible: Option<Vec<String>>,
    pub fresh_justification: bool,
    /// Longest `max_ttl` (ms) the registry accepts (`ttl_ceiling`); `None` = no ceiling. [`LeaseRegistry::new`] panics unless it is an integer from 1 to 2^53-1.
    pub max_ttl_ceiling: Option<i64>,
}
impl LeasePolicy {
    pub fn new(authorities: Vec<String>) -> Self {
        Self { authorities, min_approvals: None, eligible: None, fresh_justification: true, max_ttl_ceiling: None }
    }
}

/// Separation of duties over one (well formed) record. `chain` is every key in the holder's delegation chain. A reason or `None`.
pub fn sod_error(l: &Value, p: &LeasePolicy, chain: &[String]) -> Option<String> {
    let k = p.min_approvals.unwrap_or(1);
    if !(1..=(1 << 53) - 1).contains(&k) {
        return Some("minApprovals must be a positive integer".into());
    }
    let approvers = l.get("approvers").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let mut seen: Vec<&str> = Vec::new();
    for x in approvers {
        let a = x.as_str().unwrap_or("");
        if seen.contains(&a) {
            return Some("an approver is listed twice".into());
        }
        seen.push(a);
        if a == text(l, "requester") {
            return Some("the requester may not approve their own request".into());
        }
        if a == text(l, "holder") {
            return Some("the holder may not approve its own lease".into());
        }
        if chain.iter().any(|c| c == a) {
            return Some("an approver appears in the holder's delegation chain".into());
        }
        if p.eligible.as_ref().is_some_and(|e| !e.iter().any(|c| c == a)) {
            return Some("an approver is not eligible".into());
        }
    }
    if (approvers.len() as i64) < k { Some(format!("{} approver(s), need {k}", approvers.len())) } else { None }
}

/// Default and maximum shard counts (lease.ts DEFAULT_LEASE_SHARDS / MAX_LEASE_SHARDS).
pub const DEFAULT_LEASE_SHARDS: usize = 16;
pub const MAX_LEASE_SHARDS: usize = 4096;
const META_KEY: &str = "lease/meta";

fn shard_key(n: usize, i: usize) -> String {
    format!("lease/{n}/{i}")
}

/// The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes.
pub fn shard_of(id: &str, shards: usize) -> usize {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(id.as_bytes());
    (u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize) % shards
}

fn empty_shard() -> Value {
    serde_json::json!({"leases": {}, "revocations": []})
}

/// A shard document, or an empty one when the stored value has not the shape (lease.ts `load`).
fn load(x: Option<&Value>) -> Value {
    match x {
        Some(v) if v.get("leases").is_some_and(Value::is_object) && v.get("revocations").is_some_and(Value::is_array) => v.clone(),
        _ => empty_shard(),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// The registry keeps each lease in the shard its id hashes to (one small document per shard in the REQUIRED key-value store), so an
/// issue, a renewal and a check read and write one document. A path-prefix or grant revocation is written to EVERY shard; a revocation
/// of one lease id only to that lease's shard. Within a shard each operation is one atomic `update`. A store that cannot decide is
/// `store_unreachable` (lease.ts: the constructor requires a durable store, a process-local default would forget revocations on restart;
/// [`MemoryAtomicKv`](crate::kv::MemoryAtomicKv) is for tests and single-process use).
pub struct LeaseRegistry {
    policy: LeasePolicy,
    kv: Arc<dyn AtomicKv>,
    shards: usize,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    meta_ok: AtomicBool,
}

impl LeaseRegistry {
    /// Panics on a malformed `max_ttl_ceiling`: a misconfiguration at startup, as the reference constructor throws.
    pub fn new(policy: LeasePolicy, kv: Arc<dyn AtomicKv>) -> Self {
        assert!(policy.max_ttl_ceiling.is_none_or(|c| (1..=9_007_199_254_740_991).contains(&c)), "LeaseRegistry: max_ttl_ceiling must be a positive integer");
        Self { policy, kv, shards: DEFAULT_LEASE_SHARDS, clock: Box::new(now_ms), meta_ok: AtomicBool::new(false) }
    }

    /// Number of shards (default 16), fixed for the life of the store: a store opened with another count is refused. Panics unless 1..=4096.
    pub fn with_shards(mut self, shards: usize) -> Self {
        assert!((1..=MAX_LEASE_SHARDS).contains(&shards), "LeaseRegistry: shards must be an integer from 1 to 4096");
        self.shards = shards;
        self
    }

    /// The clock used to prune revocations (default: the system clock in ms).
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn shard_count(&self) -> usize {
        self.shards
    }

    /// Pin the shard count in the store on first use; a different count would make existing leases invisible, so it is refused.
    fn ready(&self) -> Result<bool, StoreError> {
        if self.meta_ok.load(Ordering::Acquire) {
            return Ok(true);
        }
        let shards = self.shards as i64;
        let m = self.kv.update(META_KEY, &mut |prev| if prev.is_none() { Some(serde_json::json!({"v": 1, "shards": shards})) } else { None })?;
        let ok = m.as_ref().and_then(|m| m.get("shards")).and_then(Value::as_i64) == Some(shards);
        if ok {
            self.meta_ok.store(true, Ordering::Release);
        }
        Ok(ok)
    }

    /// Drop revocations past `revoked_at + ceiling` (every lease they could cover is then beyond its own cap); no ceiling = no pruning.
    fn prune(&self, st: &mut Value) {
        let Some(c) = self.policy.max_ttl_ceiling else { return };
        let now = (self.clock)();
        if let Some(r) = st.get_mut("revocations").and_then(Value::as_array_mut) {
            r.retain(|x| int(x, "revoked_at") + c >= now);
        }
    }

    /// `Ok((replaced, seq))` when taken (an idempotent re-accept is `replaced == false`), else the refusal code. `chain`: the keys
    /// in the holder's delegation chain, for the separation-of-duties rule.
    pub fn accept(&self, rec: &Value, chain: &[String]) -> Result<(bool, i64), &'static str> {
        if !verify_lease(rec) {
            return Err("bad_record");
        }
        if !self.policy.authorities.iter().any(|a| a == text(rec, "authority")) {
            return Err("unknown_authority");
        }
        if sod_error(rec, &self.policy, chain).is_some() {
            return Err("sod");
        }
        if int(rec, "expires_at") > lease_cap(rec) {
            return Err("over_max_ttl");
        }
        if self.policy.max_ttl_ceiling.is_some_and(|c| int(rec, "max_ttl") > c) {
            return Err("ttl_ceiling");
        }
        if !self.ready().unwrap_or(false) {
            return Err("store_unreachable");
        }
        let id = text(rec, "lease_id");
        let mut out: Result<(bool, i64), &'static str> = Err("store_unreachable");
        let seq = int(rec, "seq");
        let key = shard_key(self.shards, shard_of(id, self.shards));
        let done = self.kv.update(&key, &mut |prev| {
            let mut st = load(prev);
            let cur = st["leases"].get(id).and_then(|l| l.get("current")).cloned();
            if st["revocations"].as_array().is_some_and(|r| r.iter().any(|x| covers(x, rec))) {
                out = Err("revoked");
                return None;
            }
            if let Some(cur) = &cur {
                let cseq = int(cur, "seq");
                if seq < cseq {
                    out = Err("stale_seq");
                    return None;
                }
                if seq == cseq {
                    out = if cur["sig"] == rec["sig"] { Ok((false, seq)) } else { Err("lease_fork") };
                    return None;
                }
                if seq != cseq + 1 {
                    out = Err("bad_seq");
                    return None;
                }
                let same = ["authority", "path", "grant_ref", "holder", "requester"].iter().all(|k| rec[*k] == cur[*k]);
                if !same || int(rec, "max_ttl") != int(cur, "max_ttl") || int(rec, "issued_at") != int(cur, "issued_at") {
                    out = Err("renewal_mismatch");
                    return None;
                }
                if int(rec, "renewed_at") >= int(cur, "expires_at") {
                    out = Err("expired_lease");
                    return None;
                }
                if int(rec, "renewed_at") < int(cur, "renewed_at") || int(rec, "expires_at") <= int(cur, "expires_at") {
                    out = Err("not_extending");
                    return None;
                }
                if self.policy.fresh_justification && rec["justification_digest"] == cur["justification_digest"] {
                    out = Err("stale_justification");
                    return None;
                }
            } else if seq != 1 {
                out = Err("bad_seq");
                return None;
            }
            let entry = serde_json::json!({"seq": seq, "renewed_at": int(rec, "renewed_at"), "expires_at": int(rec, "expires_at"), "justification_digest": rec["justification_digest"]});
            let mut history = st["leases"].get(id).and_then(|l| l.get("history")).and_then(Value::as_array).cloned().unwrap_or_default();
            history.push(entry);
            st["leases"][id] = serde_json::json!({"current": rec, "history": history});
            self.prune(&mut st);
            out = Ok((true, seq));
            Some(st)
        });
        if done.is_err() {
            return Err("store_unreachable");
        }
        out
    }

    /// `Ok(n)` with `n` leases covered (idempotent), else the refusal code. A prefix or grant revocation is written to every shard.
    pub fn revoke(&self, rec: &Value) -> Result<usize, &'static str> {
        if !verify_lease_revocation(rec) {
            return Err("bad_record");
        }
        if !self.policy.authorities.iter().any(|a| a == text(rec, "authority")) {
            return Err("unknown_authority");
        }
        if !self.ready().unwrap_or(false) {
            return Err("store_unreachable");
        }
        let targets: Vec<usize> = if text(rec, "target") == "lease" { vec![shard_of(text(rec, "value"), self.shards)] } else { (0..self.shards).collect() };
        let mut n = 0usize;
        for i in targets {
            let r = self.kv.update(&shard_key(self.shards, i), &mut |prev| {
                let mut st = load(prev);
                let have = st["revocations"].as_array().is_some_and(|r| r.iter().any(|x| x["sig"] == rec["sig"]));
                if let (false, Some(r)) = (have, st["revocations"].as_array_mut()) {
                    r.push(rec.clone());
                }
                n += st["leases"].as_object().map_or(0, |m| m.values().filter(|s| s.get("current").is_some_and(|c| covers(rec, c))).count());
                self.prune(&mut st);
                Some(st)
            });
            if r.is_err() {
                return Err("store_unreachable");
            }
        }
        Ok(n)
    }

    fn shard(&self, id: &str) -> Result<Value, StoreError> {
        if !self.ready()? {
            return Err(StoreError("shard count mismatch".into()));
        }
        Ok(load(self.kv.get(&shard_key(self.shards, shard_of(id, self.shards)))?.as_ref()))
    }

    /// The newest record of a lease.
    pub fn get(&self, id: &str) -> Result<Option<Value>, StoreError> {
        Ok(self.shard(id)?["leases"].get(id).and_then(|l| l.get("current")).cloned())
    }

    /// The renewal ledger of a lease, oldest first.
    pub fn history(&self, id: &str) -> Result<Vec<Value>, StoreError> {
        Ok(self.shard(id)?["leases"].get(id).and_then(|l| l.get("history")).and_then(Value::as_array).cloned().unwrap_or_default())
    }

    /// The newest record of a lease and whether a stored revocation covers it.
    pub fn lookup(&self, id: &str) -> Result<Option<(Value, bool)>, StoreError> {
        let st = self.shard(id)?;
        let Some(cur) = st["leases"].get(id).and_then(|l| l.get("current")).cloned() else { return Ok(None) };
        let revoked = st["revocations"].as_array().is_some_and(|r| r.iter().any(|x| covers(x, &cur)));
        Ok(Some((cur, revoked)))
    }

    /// Revocations held by one shard (for operators and the conformance kit). Panics on a shard index out of range.
    pub fn shard_revocations(&self, i: usize) -> Result<Vec<Value>, StoreError> {
        assert!(i < self.shards, "no such shard");
        Ok(load(self.kv.get(&shard_key(self.shards, i))?.as_ref())["revocations"].as_array().cloned().unwrap_or_default())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LeaseDecision {
    /// `allow` or `deny`.
    pub decision: &'static str,
    pub code: Option<&'static str>,
    pub lease_id: Option<String>,
    pub expires_at: Option<i64>,
}

/// Is `presented` a live lease? It must verify, be the newest record, be inside its window and cap, and not be revoked. A store that
/// cannot answer is `store_unreachable`.
pub fn check_lease(presented: &Value, reg: &LeaseRegistry, now: &Value) -> LeaseDecision {
    let deny = |code: &'static str, id: Option<String>| LeaseDecision { decision: "deny", code: Some(code), lease_id: id, expires_at: None };
    let Some(now) = nat(Some(now)) else { return deny("bad_input", None) };
    if !verify_lease(presented) {
        return deny("bad_record", None);
    }
    let id = text(presented, "lease_id").to_string();
    let found = match reg.lookup(&id) {
        Ok(f) => f,
        Err(_) => return deny("store_unreachable", Some(id)),
    };
    let Some((cur, revoked)) = found else { return deny("unknown_lease", Some(id)) };
    if cur["sig"] != presented["sig"] {
        return deny("superseded", Some(id));
    }
    if revoked {
        return deny("revoked", Some(id));
    }
    if now < int(&cur, "renewed_at") {
        return deny("not_yet_valid", Some(id));
    }
    if now >= lease_cap(&cur) {
        return deny("past_max_ttl", Some(id));
    }
    if now >= int(&cur, "expires_at") {
        return deny("expired", Some(id));
    }
    LeaseDecision { decision: "allow", code: None, lease_id: Some(id), expires_at: Some(int(&cur, "expires_at")) }
}

#[cfg(test)]
#[path = "k05_grants_lease_test.rs"]
mod k05_test;

#[cfg(test)]
#[path = "k05f_state_test.rs"]
mod k05f_state_test;
