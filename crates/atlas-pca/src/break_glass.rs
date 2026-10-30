//! Break-glass grants (verification side): a time-boxed, small-budget, loud emergency grant with a mandatory signed review after the
//! fact. Records and reviews are Ed25519-signed under a domain string over strict-canonical JSON. [`BreakGlassRegistry`] keeps each
//! holder's grants, numbered uses, reviews and freeze status in memory (one document per holder). Total: no function panics.
//! Port of packages/pca-grants/src/breakglass.ts; replays break-glass-vectors.json.
use crate::fresh_at::verify_body;
use crate::lease::{int, nat, pick, s, text};
use serde_json::Value;
use std::collections::HashMap;

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

struct Entry {
    rec: Value,
    /// (time, action digest) of each use, oldest first.
    uses: Vec<(i64, String)>,
    review: Option<Value>,
}

/// A grant of the holder was judged unjustified, or has uses, no review and a review clock that has run out.
fn frozen_in(grants: Option<&HashMap<String, Entry>>, now: i64) -> bool {
    grants.is_some_and(|g| {
        g.values().any(|e| match &e.review {
            Some(r) => text(r, "outcome") == "unjustified",
            None => e.uses.first().is_some_and(|u| now >= u.0 + int(&e.rec, "review_within")),
        })
    })
}

pub struct BreakGlassRegistry {
    policy: BreakGlassPolicy,
    holders: HashMap<String, HashMap<String, Entry>>,
}

impl BreakGlassRegistry {
    pub fn new(policy: BreakGlassPolicy) -> Self {
        Self { policy, holders: HashMap::new() }
    }

    /// `Ok(replaced)` (an idempotent re-accept is `false`) or the refusal code. A frozen holder gets no new record.
    pub fn accept(&mut self, rec: &Value, now: &Value) -> Result<bool, &'static str> {
        let Some(now) = nat(Some(now)) else { return Err("bad_record") };
        if !verify_break_glass(rec) {
            return Err("bad_record");
        }
        if !self.policy.authorities.iter().any(|a| a == text(rec, "authority")) {
            return Err("unknown_authority");
        }
        let grants = self.holders.entry(text(rec, "holder").to_string()).or_default();
        if let Some(cur) = grants.get(text(rec, "id")) {
            return if cur.rec["sig"] == rec["sig"] { Ok(false) } else { Err("id_conflict") };
        }
        if frozen_in(Some(&*grants), now) {
            return Err("holder_frozen");
        }
        grants.insert(text(rec, "id").to_string(), Entry { rec: rec.clone(), uses: vec![], review: None });
        Ok(true)
    }

    /// Record one use; `notified` must be `true`. Checks in order: input, existence, freeze, revocation, window, budget, notification.
    pub fn use_grant(&mut self, id: &str, holder: &str, action_digest: &str, now: &Value, notified: &Value) -> BgUseDecision {
        let bad = || BgUseDecision { decision: "deny", code: Some("bad_input"), id: None, use_n: None, remaining: None, review_due: None };
        let (Some(now), Some(notified)) = (nat(Some(now)), notified.as_bool()) else { return bad() };
        if ![id, holder, action_digest].iter().all(|x| !x.is_empty() && x.encode_utf16().count() <= 128) {
            return bad();
        }
        let deny = |code: &'static str| BgUseDecision { decision: "deny", code: Some(code), id: Some(id.to_string()), use_n: None, remaining: None, review_due: None };
        let frozen = frozen_in(self.holders.get(holder), now);
        let Some(e) = self.holders.get_mut(holder).and_then(|g| g.get_mut(id)) else { return deny("unknown_break_glass") };
        if frozen {
            return deny("holder_frozen");
        }
        if e.review.as_ref().is_some_and(|r| text(r, "outcome") == "unjustified") {
            return deny("revoked");
        }
        if now < int(&e.rec, "issued_at") {
            return deny("not_yet_valid");
        }
        if now >= int(&e.rec, "expires_at") {
            return deny("expired");
        }
        if e.uses.len() as i64 >= int(&e.rec, "max_uses") {
            return deny("budget_exhausted");
        }
        if !notified {
            return deny("not_notified");
        }
        e.uses.push((now, action_digest.to_string()));
        let used = e.uses.len() as i64;
        BgUseDecision {
            decision: "allow",
            code: None,
            id: Some(id.to_string()),
            use_n: Some(used),
            remaining: Some(int(&e.rec, "max_uses") - used),
            review_due: Some(e.uses[0].0 + int(&e.rec, "review_within")),
        }
    }

    /// Record the signed review. The first review of a grant is final; a late review lifts an overdue freeze.
    pub fn review(&mut self, rec: &Value, holder: &str, now: &Value) -> Result<bool, &'static str> {
        let Some(now) = nat(Some(now)) else { return Err("bad_record") };
        if !verify_break_glass_review(rec) || holder.is_empty() || holder.encode_utf16().count() > 128 {
            return Err("bad_record");
        }
        if !self.policy.reviewers.iter().any(|a| a == text(rec, "reviewer")) {
            return Err("unknown_reviewer");
        }
        let Some(e) = self.holders.get_mut(holder).and_then(|g| g.get_mut(text(rec, "id"))) else { return Err("unknown_break_glass") };
        let reviewer = text(rec, "reviewer");
        if reviewer == text(&e.rec, "holder") || reviewer == text(&e.rec, "authority") {
            return Err("sod");
        }
        if let Some(cur) = &e.review {
            return if cur["sig"] == rec["sig"] { Ok(false) } else { Err("already_reviewed") };
        }
        let Some(first) = e.uses.first() else { return Err("nothing_to_review") };
        let at = int(rec, "at");
        if at < first.0 || at > now {
            return Err("bad_time");
        }
        e.review = Some(rec.clone());
        Ok(true)
    }

    /// Fails closed (`true`) on bad input.
    pub fn frozen(&self, holder: &str, now: &Value) -> bool {
        match nat(Some(now)) {
            Some(n) if !holder.is_empty() && holder.encode_utf16().count() <= 128 => frozen_in(self.holders.get(holder), n),
            _ => true,
        }
    }
}
