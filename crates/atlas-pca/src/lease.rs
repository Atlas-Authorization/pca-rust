//! Leases (verification side): a time-boxed grant that must be renewed, has a hard `max_ttl` cap, and dies when revoked. Records and
//! revocations are Ed25519-signed under a domain string over strict-canonical JSON. [`LeaseRegistry`] keeps the newest record per
//! `lease_id` (in memory) plus the revocations; [`check_lease`] gates a presented record. Total: no function panics.
//! Replays packages/pca/conformance/lease-vectors.json.
use crate::fresh_at::verify_body;
use crate::safe_int;
use serde_json::{Map, Value};
use std::collections::HashMap;

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
}
impl LeasePolicy {
    pub fn new(authorities: Vec<String>) -> Self {
        Self { authorities, min_approvals: None, eligible: None, fresh_justification: true }
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

pub struct LeaseRegistry {
    policy: LeasePolicy,
    leases: HashMap<String, Value>,
    revocations: Vec<Value>,
}

impl LeaseRegistry {
    pub fn new(policy: LeasePolicy) -> Self {
        Self { policy, leases: HashMap::new(), revocations: Vec::new() }
    }

    /// `Ok((replaced, seq))` when taken (an idempotent re-accept is `replaced == false`), else the refusal code. `chain`: the keys
    /// in the holder's delegation chain, for the separation-of-duties rule.
    pub fn accept(&mut self, rec: &Value, chain: &[String]) -> Result<(bool, i64), &'static str> {
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
        if self.revocations.iter().any(|r| covers(r, rec)) {
            return Err("revoked");
        }
        let seq = int(rec, "seq");
        if let Some(cur) = self.leases.get(text(rec, "lease_id")) {
            let cseq = int(cur, "seq");
            if seq < cseq {
                return Err("stale_seq");
            }
            if seq == cseq {
                return if cur["sig"] == rec["sig"] { Ok((false, seq)) } else { Err("lease_fork") };
            }
            if seq != cseq + 1 {
                return Err("bad_seq");
            }
            let same = ["authority", "path", "grant_ref", "holder", "requester"].iter().all(|k| rec[*k] == cur[*k]);
            if !same || int(rec, "max_ttl") != int(cur, "max_ttl") || int(rec, "issued_at") != int(cur, "issued_at") {
                return Err("renewal_mismatch");
            }
            if int(rec, "renewed_at") >= int(cur, "expires_at") {
                return Err("expired_lease");
            }
            if int(rec, "renewed_at") < int(cur, "renewed_at") || int(rec, "expires_at") <= int(cur, "expires_at") {
                return Err("not_extending");
            }
            if self.policy.fresh_justification && rec["justification_digest"] == cur["justification_digest"] {
                return Err("stale_justification");
            }
        } else if seq != 1 {
            return Err("bad_seq");
        }
        self.leases.insert(text(rec, "lease_id").to_string(), rec.clone());
        Ok((true, seq))
    }

    /// `Ok(n)` with `n` leases covered (idempotent), else the refusal code.
    pub fn revoke(&mut self, rec: &Value) -> Result<usize, &'static str> {
        if !verify_lease_revocation(rec) {
            return Err("bad_record");
        }
        if !self.policy.authorities.iter().any(|a| a == text(rec, "authority")) {
            return Err("unknown_authority");
        }
        if !self.revocations.iter().any(|r| r["sig"] == rec["sig"]) {
            self.revocations.push(rec.clone());
        }
        Ok(self.leases.values().filter(|l| covers(rec, l)).count())
    }

    pub fn get(&self, id: &str) -> Option<&Value> {
        self.leases.get(id)
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

/// Is `presented` a live lease? It must verify, be the newest record, be inside its window and cap, and not be revoked.
pub fn check_lease(presented: &Value, reg: &LeaseRegistry, now: &Value) -> LeaseDecision {
    let deny = |code: &'static str, id: Option<String>| LeaseDecision { decision: "deny", code: Some(code), lease_id: id, expires_at: None };
    let Some(now) = nat(Some(now)) else { return deny("bad_input", None) };
    if !verify_lease(presented) {
        return deny("bad_record", None);
    }
    let id = text(presented, "lease_id").to_string();
    let Some(cur) = reg.get(&id) else { return deny("unknown_lease", Some(id)) };
    if cur["sig"] != presented["sig"] {
        return deny("superseded", Some(id));
    }
    if reg.revocations.iter().any(|r| covers(r, cur)) {
        return deny("revoked", Some(id));
    }
    if now < int(cur, "renewed_at") {
        return deny("not_yet_valid", Some(id));
    }
    if now >= lease_cap(cur) {
        return deny("past_max_ttl", Some(id));
    }
    if now >= int(cur, "expires_at") {
        return deny("expired", Some(id));
    }
    LeaseDecision { decision: "allow", code: None, lease_id: Some(id), expires_at: Some(int(cur, "expires_at")) }
}
