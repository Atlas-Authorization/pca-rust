//! Break-glass grants (verification side): a time-boxed, small-budget, loud emergency grant with a mandatory signed review after the
//! fact. Records and reviews are Ed25519-signed under a domain string over strict-canonical JSON. [`BreakGlassRegistry`] keeps each
//! holder's grants, numbered uses, reviews and freeze status in a REQUIRED atomic key-value store (one document per shard, as breakglass.ts). Total: no function panics.
//! Port of packages/pca-grants/src/breakglass.ts; replays break-glass-vectors.json.
use crate::fresh_at::verify_body;
use crate::lease::{int, nat, pick, s, text};
use crate::authorize::StoreError;
use crate::kv::AtomicKv;
use crate::lease::{shard_of, DEFAULT_LEASE_SHARDS, MAX_LEASE_SHARDS};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const BREAK_GLASS_DOMAIN: &str = "atlas-pca/break-glass/v1\0";
pub const BREAK_GLASS_REVIEW_DOMAIN: &str = "atlas-pca/break-glass-review/v1\0";
pub const MAX_BREAK_GLASS_WINDOW_MS: i64 = 86_400_000;
pub const MAX_BREAK_GLASS_USES: i64 = 16;
pub const MAX_REVIEW_WITHIN_MS: i64 = 30 * 86_400_000;
const BODY_KEYS: [&str; 11] = ["v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"];
const REV_KEYS: [&str; 6] = ["v", "id", "outcome", "notes_digest", "at", "reviewer"];

fn well_formed(b: &Value) -> bool {
    if !b.is_object() || b.get("v").and_then(crate::safe_int) != Some(1) {
        return false;
    }
    if !(s(b.get("id"), 128) && s(b.get("holder"), 128) && s(b.get("grant_ref"), 256) && s(b.get("reason_digest"), 128) && s(b.get("notify_to"), 256) && s(b.get("authority"), 128)) {
        return false;
    }
    if !["max_uses", "issued_at", "expires_at", "review_within"].iter().all(|k| nat(b.get(*k)).is_some()) {
        return false;
    }
    let (uses, issued, expires, within) = (int(b, "max_uses"), int(b, "issued_at"), int(b, "expires_at"), int(b, "review_within"));
    (1..=MAX_BREAK_GLASS_USES).contains(&uses) && expires > issued && expires - issued <= MAX_BREAK_GLASS_WINDOW_MS && (1..=MAX_REVIEW_WITHIN_MS).contains(&within)
}

/// Well formed and signed by its `authority` over exactly its content.
pub fn verify_break_glass(b: &Value) -> bool {
    well_formed(b) && verify_body(BREAK_GLASS_DOMAIN, &pick(b, &BODY_KEYS), text(b, "authority"), b.get("sig").and_then(Value::as_str))
}

fn rv_well_formed(r: &Value) -> bool {
    r.is_object()
        && r.get("v").and_then(crate::safe_int) == Some(1)
        && s(r.get("id"), 128)
        && matches!(r.get("outcome").and_then(Value::as_str), Some("justified" | "unjustified"))
        && s(r.get("notes_digest"), 128)
        && nat(r.get("at")).is_some()
        && s(r.get("reviewer"), 128)
}

pub fn verify_break_glass_review(r: &Value) -> bool {
    rv_well_formed(r) && verify_body(BREAK_GLASS_REVIEW_DOMAIN, &pick(r, &REV_KEYS), text(r, "reviewer"), r.get("sig").and_then(Value::as_str))
}

/// `authorities` may issue records, `reviewers` may sign reviews.
#[derive(Debug, Clone)]
pub struct BreakGlassPolicy {
    pub authorities: Vec<String>,
    pub reviewers: Vec<String>,
}

/// `allow` carries `id`, `use_n`, `remaining`, `review_due`; `deny` carries `code` (and `id` when known).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgUseDecision {
    pub decision: &'static str,
    pub code: Option<&'static str>,
    pub id: Option<String>,
    pub use_n: Option<i64>,
    pub remaining: Option<i64>,
    pub review_due: Option<i64>,
}

/// A grant of the holder was judged unjustified, or has uses, no review and a review clock that has run out
/// (breakglass.ts `frozenIn`, over one shard's document).
fn frozen_in(st: &Value, holder: &str, now: i64) -> bool {
    st["grants"].as_object().is_some_and(|g| {
        g.values().any(|e| {
            text(&e["rec"], "holder") == holder
                && match e.get("review") {
                    Some(r) => text(r, "outcome") == "unjustified",
                    None => e["uses"].as_array().and_then(|u| u.first()).is_some_and(|u| now >= int(u, "at") + int(&e["rec"], "review_within")),
                }
        })
    })
}

fn bg_key(n: usize, i: usize) -> String {
    format!("breakglass/{n}/{i}")
}

/// A shard document, or an empty one when the stored value has not the shape (breakglass.ts `loadShard`).
fn load_shard(x: Option<&Value>) -> Value {
    match x {
        Some(v) if v.get("grants").is_some_and(Value::is_object) => v.clone(),
        _ => json!({"grants": {}}),
    }
}

/// Grants, numbered uses, reviews and freeze status per holder, one document per shard (the holder's hash) in the REQUIRED atomic
/// key-value store; a store that cannot decide is `store_unreachable` (accept / review / use) and a frozen holder (`frozen`).
/// [`MemoryAtomicKv`](crate::kv::MemoryAtomicKv) is for tests and single-process use.
pub struct BreakGlassRegistry {
    policy: BreakGlassPolicy,
    kv: Arc<dyn AtomicKv>,
    shards: usize,
    meta_ok: AtomicBool,
}

impl BreakGlassRegistry {
    pub fn new(policy: BreakGlassPolicy, kv: Arc<dyn AtomicKv>) -> Self {
        Self { policy, kv, shards: DEFAULT_LEASE_SHARDS, meta_ok: AtomicBool::new(false) }
    }

    /// Number of shards (default 16), fixed for the life of the store. Panics unless 1..=4096.
    pub fn with_shards(mut self, shards: usize) -> Self {
        assert!((1..=MAX_LEASE_SHARDS).contains(&shards), "BreakGlassRegistry: shards must be an integer from 1 to 4096");
        self.shards = shards;
        self
    }

    fn ready(&self) -> Result<bool, StoreError> {
        if self.meta_ok.load(Ordering::Acquire) {
            return Ok(true);
        }
        let shards = self.shards as i64;
        let m = self.kv.update("breakglass/meta", &mut |prev| if prev.is_none() { Some(json!({"v": 1, "shards": shards})) } else { None })?;
        let ok = m.as_ref().and_then(|m| m.get("shards")).and_then(Value::as_i64) == Some(shards);
        if ok {
            self.meta_ok.store(true, Ordering::Release);
        }
        Ok(ok)
    }

    fn key(&self, holder: &str) -> String {
        bg_key(self.shards, shard_of(holder, self.shards))
    }

    /// `Ok(replaced)` (an idempotent re-accept is `false`) or the refusal code. A frozen holder gets no new record.
    pub fn accept(&self, rec: &Value, now: &Value) -> Result<bool, &'static str> {
        let Some(now) = nat(Some(now)) else { return Err("bad_record") };
        if !verify_break_glass(rec) {
            return Err("bad_record");
        }
        if !self.policy.authorities.iter().any(|a| a == text(rec, "authority")) {
            return Err("unknown_authority");
        }
        if !self.ready().unwrap_or(false) {
            return Err("store_unreachable");
        }
        let (id, holder) = (text(rec, "id"), text(rec, "holder"));
        let mut out: Result<bool, &'static str> = Err("store_unreachable");
        let done = self.kv.update(&self.key(holder), &mut |prev| {
            let mut st = load_shard(prev);
            if let Some(cur) = st["grants"].get(id) {
                out = if cur["rec"]["sig"] == rec["sig"] { Ok(false) } else { Err("id_conflict") };
                return None;
            }
            if frozen_in(&st, holder, now) {
                out = Err("holder_frozen");
                return None;
            }
            st["grants"][id] = json!({"rec": rec, "uses": []});
            out = Ok(true);
            Some(st)
        });
        if done.is_err() {
            return Err("store_unreachable");
        }
        out
    }

    /// Record one use; `notified` must be `true`. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification.
    pub fn use_grant(&self, id: &str, holder: &str, action_digest: &str, now: &Value, notified: &Value) -> BgUseDecision {
        let bad = || BgUseDecision { decision: "deny", code: Some("bad_input"), id: None, use_n: None, remaining: None, review_due: None };
        let (Some(now), Some(notified)) = (nat(Some(now)), notified.as_bool()) else { return bad() };
        if ![id, holder, action_digest].iter().all(|x| !x.is_empty() && x.encode_utf16().count() <= 128) {
            return bad();
        }
        let deny = |code: &'static str| BgUseDecision { decision: "deny", code: Some(code), id: Some(id.to_string()), use_n: None, remaining: None, review_due: None };
        if !self.ready().unwrap_or(false) {
            return deny("store_unreachable");
        }
        let mut out = deny("store_unreachable");
        let done = self.kv.update(&self.key(holder), &mut |prev| {
            let mut st = load_shard(prev);
            let Some(e) = st["grants"].get(id).cloned() else {
                out = deny("unknown_break_glass");
                return None;
            };
            let rec = &e["rec"];
            if text(rec, "holder") != holder {
                out = deny("wrong_holder");
                return None;
            }
            if frozen_in(&st, holder, now) {
                out = deny("holder_frozen");
                return None;
            }
            if e.get("review").is_some_and(|r| text(r, "outcome") == "unjustified") {
                out = deny("revoked");
                return None;
            }
            if now < int(rec, "issued_at") {
                out = deny("not_yet_valid");
                return None;
            }
            if now >= int(rec, "expires_at") {
                out = deny("expired");
                return None;
            }
            let used_before = e["uses"].as_array().map_or(0, |u| u.len()) as i64;
            if used_before >= int(rec, "max_uses") {
                out = deny("budget_exhausted");
                return None;
            }
            if !notified {
                out = deny("not_notified");
                return None;
            }
            let first_at = e["uses"].as_array().and_then(|u| u.first()).map_or(now, |u| int(u, "at"));
            let used = used_before + 1;
            if let Some(u) = st["grants"][id]["uses"].as_array_mut() {
                u.push(json!({"n": used, "action_digest": action_digest, "at": now}));
            }
            out = BgUseDecision {
                decision: "allow",
                code: None,
                id: Some(id.to_string()),
                use_n: Some(used),
                remaining: Some(int(rec, "max_uses") - used),
                review_due: Some(first_at + int(rec, "review_within")),
            };
            Some(st)
        });
        if done.is_err() {
            return deny("store_unreachable");
        }
        out
    }

    /// Record the signed review. The first review of a grant is final; a late review lifts an overdue freeze.
    pub fn review(&self, rec: &Value, holder: &str, now: &Value) -> Result<bool, &'static str> {
        let Some(now) = nat(Some(now)) else { return Err("bad_record") };
        if !verify_break_glass_review(rec) || holder.is_empty() || holder.encode_utf16().count() > 128 {
            return Err("bad_record");
        }
        if !self.policy.reviewers.iter().any(|a| a == text(rec, "reviewer")) {
            return Err("unknown_reviewer");
        }
        if !self.ready().unwrap_or(false) {
            return Err("store_unreachable");
        }
        let id = text(rec, "id");
        let mut out: Result<bool, &'static str> = Err("store_unreachable");
        let done = self.kv.update(&self.key(holder), &mut |prev| {
            let mut st = load_shard(prev);
            let Some(e) = st["grants"].get(id).cloned() else {
                out = Err("unknown_break_glass");
                return None;
            };
            if text(&e["rec"], "holder") != holder {
                out = Err("unknown_break_glass");
                return None;
            }
            let reviewer = text(rec, "reviewer");
            if reviewer == text(&e["rec"], "holder") || reviewer == text(&e["rec"], "authority") {
                out = Err("sod");
                return None;
            }
            if let Some(cur) = e.get("review") {
                out = if cur["sig"] == rec["sig"] { Ok(false) } else { Err("already_reviewed") };
                return None;
            }
            let Some(first) = e["uses"].as_array().and_then(|u| u.first()) else {
                out = Err("nothing_to_review");
                return None;
            };
            let at = int(rec, "at");
            if at < int(first, "at") || at > now {
                out = Err("bad_time");
                return None;
            }
            st["grants"][id]["review"] = rec.clone();
            out = Ok(true);
            Some(st)
        });
        if done.is_err() {
            return Err("store_unreachable");
        }
        out
    }

    /// Fails closed (`true`) on bad input or a store that cannot answer.
    pub fn frozen(&self, holder: &str, now: &Value) -> bool {
        let Some(n) = nat(Some(now)).filter(|_| !holder.is_empty() && holder.encode_utf16().count() <= 128) else { return true };
        if !self.ready().unwrap_or(false) {
            return true;
        }
        match self.kv.get(&self.key(holder)) {
            Ok(v) => frozen_in(&load_shard(v.as_ref()), holder, n),
            Err(_) => true,
        }
    }

    /// The numbered use log of a grant, oldest first.
    pub fn uses(&self, holder: &str, id: &str) -> Result<Vec<Value>, StoreError> {
        if !self.ready()? {
            return Ok(Vec::new());
        }
        let st = load_shard(self.kv.get(&self.key(holder))?.as_ref());
        Ok(st["grants"].get(id).and_then(|e| e["uses"].as_array()).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
#[path = "k05_grants_bg_test.rs"]
mod k05_test;
