//! The grant management resource and its HTTP bindings (port of @atlasauth/pca-grants): list / inspect / amend / revoke and incremental
//! authorization for principals, nothing widening in place. [`GrantService`] runs over a [`GrantStore`] you pass ([`MemoryGrantStore`] is for
//! tests and single-process use); [`grant_http`] and [`lease_http`] turn the service and the lease registry into framework-neutral
//! handlers over a plain request `{method, path, query?, body?}` returning `{status, body}`.
//!
//! The pure verification side (amendment, revoke and need-approval decisions) is [`crate::k3`]; this module adds the stateful service.
//! Hooks (`verify_step_up`, `on_revoke`, `on_change`, `validate_need`, providers) are plain closures set with the `with_*` builders.
//! Not ported: the `GrantClient` (an HTTP client over an injected transport) and the lease-store conformance kit.
use crate::actions::js_str_to_number;
use crate::fresh_at::verify_body;
use crate::grants::{u16key, without};
use crate::k3::{authority_digest, compare_authority, merge_authority, verify_need_approval, verify_revoke_signature, Authority, GRANT_AMEND_DOMAIN};
use crate::lease::{check_lease, s, LeaseDecision, LeaseRegistry};
use crate::oauth::truthy;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub const NEED_REQUEST_DOMAIN: &str = "atlas-pca/need-request/v1\0";
pub const GRANT_STEPUP_DOMAIN: &str = "atlas-pca/grant-stepup/v1\0";
pub const GRANTS_PATH: &str = "/pca/grants";
pub const NEEDS_PATH: &str = "/pca/needs";
pub const LEASES_PATH: &str = "/pca/leases";

/// The message a need request signs.
pub fn need_request_message(grant_id: &str, rev: &Value, needs: &Value) -> Value {
    json!({"grant": grant_id, "rev": rev, "needs": needs})
}

/// The message a step-up response signs.
pub fn step_up_message(grant_id: &str, challenge_id: &str, nonce: &str) -> Value {
    json!({"grant": grant_id, "challenge": challenge_id, "nonce": nonce})
}

/// What an amendment signs: `{grant, rev, action, authority: digest}`. `None` when the authority has no digest (malformed).
pub fn amend_message(g: &Value, action: &str, authority: &Value) -> Option<Value> {
    Some(
        json!({"grant": g.get("id").cloned().unwrap_or(Value::Null), "rev": g.get("rev").cloned().unwrap_or(Value::Null), "action": action, "authority": authority_digest(authority)?}),
    )
}

/// What a revocation signs: `{grant, scope}`.
pub fn grant_revoke_message(grant_id: &str, scope: &str) -> Value {
    json!({"grant": grant_id, "scope": scope})
}

/// What a need approval signs: `{need, grant, rev, approved}`.
pub fn need_approve_message(need_id: &str, grant_id: &str, rev: &Value, approved: &Value) -> Value {
    json!({"need": need_id, "grant": grant_id, "rev": rev, "approved": approved})
}

/// A refusal with a stable `code`: not_found, conflict, bad_request, not_narrower, signature_required, bad_signature, step_up_required,
/// not_active, need_not_lowered_only, need_not_adjustable, forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantError {
    pub code: String,
    pub message: String,
}

impl GrantError {
    pub fn new(code: &str, message: &str) -> Self {
        Self { code: code.to_string(), message: message.to_string() }
    }
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn fail_message(code: &str) -> &'static str {
    match code {
        "not_found" => "no such grant",
        "conflict" => "conflict",
        "bad_request" => "malformed request",
        "not_narrower" => "a narrow amendment must be strictly narrower",
        "signature_required" => "the amendment is signed (by the principal when it widens)",
        "bad_signature" => "the signature does not verify for this grant revision",
        "step_up_required" => "widening needs a satisfied step-up",
        "not_active" => "grant is not active",
        "need_not_lowered_only" => "an approval may only lower amounts of the requested needs",
        "need_not_adjustable" => "the need is not adjustable",
        "forbidden" => "not authorised",
        _ => "error",
    }
}

fn status_of(code: &str) -> i64 {
    match code {
        "not_found" => 404,
        "conflict" | "not_active" => 409,
        "bad_request" => 400,
        "not_narrower" | "need_not_lowered_only" | "need_not_adjustable" => 422,
        "signature_required" | "bad_signature" => 401,
        "step_up_required" | "forbidden" => 403,
        _ => 500,
    }
}

fn refusal(code: &str) -> GrantError {
    GrantError::new(code, fail_message(code))
}

fn adigest(a: &Value) -> Value {
    authority_digest(a).map(Value::String).unwrap_or(Value::Null)
}

fn set(v: &mut Value, k: &str, x: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(k.to_string(), x);
    }
}

fn push_history(g: &mut Value, entry: Value) {
    if let Some(h) = g.get_mut("history").and_then(Value::as_array_mut) {
        h.push(entry);
    }
}

// ---- store ------------------------------------------------------------------------------------------------------------------

/// Where grants and need requests live. A store hands out copies: mutating a returned record changes nothing until `put`.
pub trait GrantStore: Send + Sync {
    fn get(&self, id: &str) -> Option<Value>;
    fn put(&self, g: &Value);
    /// Every grant, in the order each id was first stored.
    fn list(&self) -> Vec<Value>;
    fn get_need(&self, id: &str) -> Option<Value>;
    fn put_need(&self, n: &Value);
    /// The need requests of one grant, in the order each id was first stored.
    fn list_needs(&self, grant_id: &str) -> Vec<Value>;
}

/// In-process grant store (forgets everything on restart).
#[derive(Default)]
pub struct MemoryGrantStore {
    inner: Mutex<(Map<String, Value>, Map<String, Value>)>,
}

impl MemoryGrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (Map<String, Value>, Map<String, Value>)> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl GrantStore for MemoryGrantStore {
    fn get(&self, id: &str) -> Option<Value> {
        self.lock().0.get(id).cloned()
    }
    fn put(&self, g: &Value) {
        let id = g.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        self.lock().0.insert(id, g.clone());
    }
    fn list(&self) -> Vec<Value> {
        self.lock().0.values().cloned().collect()
    }
    fn get_need(&self, id: &str) -> Option<Value> {
        self.lock().1.get(id).cloned()
    }
    fn put_need(&self, n: &Value) {
        let id = n.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        self.lock().1.insert(id, n.clone());
    }
    fn list_needs(&self, grant_id: &str) -> Vec<Value> {
        self.lock().1.values().filter(|n| n.get("grant_id").and_then(Value::as_str) == Some(grant_id)).cloned().collect()
    }
}

// ---- service ----------------------------------------------------------------------------------------------------------------

/// Extra facts shown on `inspect` (each `(grant) -> value`; plain functions).
#[derive(Default, Clone)]
pub struct Providers {
    pub usage: Option<fn(&Value) -> Value>,
    pub remaining_budget: Option<fn(&Value) -> Value>,
    pub policy_card: Option<fn(&Value) -> Value>,
    pub residual: Option<fn(&Value) -> Value>,
}

pub struct GrantService {
    store: Arc<dyn GrantStore>,
    now: Box<dyn Fn() -> i64>,
    new_id: Box<dyn Fn(&str) -> String>,
    providers: Option<Providers>,
    verify_step_up: Option<Box<dyn Fn(&str, &Value) -> bool>>,
    on_revoke: Option<Box<dyn Fn(&[String], &str, &Value)>>,
    on_change: Option<Box<dyn Fn(&str, &Value)>>,
    validate_need: Option<Box<dyn Fn(&Value) -> Option<String>>>,
}

type Verdict = Result<(bool, Value), &'static str>;

impl GrantService {
    /// `now()` is epoch ms; `new_id(kind)` returns a fresh id for kind `grant` or `need`.
    pub fn new(store: Arc<dyn GrantStore>, now: impl Fn() -> i64 + 'static, new_id: impl Fn(&str) -> String + 'static) -> Self {
        Self {
            store,
            now: Box::new(now),
            new_id: Box::new(new_id),
            providers: None,
            verify_step_up: None,
            on_revoke: None,
            on_change: None,
            validate_need: None,
        }
    }

    pub fn with_providers(mut self, p: Providers) -> Self {
        self.providers = Some(p);
        self
    }

    /// `verify_step_up(ref, grant)`; absent, a widening is refused.
    pub fn with_verify_step_up(mut self, f: impl Fn(&str, &Value) -> bool + 'static) -> Self {
        self.verify_step_up = Some(Box::new(f));
        self
    }

    /// `on_revoke(revoked ids, scope, root grant)`.
    pub fn with_on_revoke(mut self, f: impl Fn(&[String], &str, &Value) + 'static) -> Self {
        self.on_revoke = Some(Box::new(f));
        self
    }

    /// `on_change(kind, grant)` with kind `amend`, `supersede`, `revoke` or `need`.
    pub fn with_on_change(mut self, f: impl Fn(&str, &Value) + 'static) -> Self {
        self.on_change = Some(Box::new(f));
        self
    }

    /// `validate_need(need)` returns an error text to refuse a need, `None` to take it.
    pub fn with_validate_need(mut self, f: impl Fn(&Value) -> Option<String> + 'static) -> Self {
        self.validate_need = Some(Box::new(f));
        self
    }

    pub fn store(&self) -> &Arc<dyn GrantStore> {
        &self.store
    }

    fn step_up(&self, r: Option<&Value>, g: &Value) -> bool {
        match (r.and_then(Value::as_str).filter(|x| !x.is_empty()), &self.verify_step_up) {
            (Some(x), Some(f)) => f(x, g),
            _ => false,
        }
    }

    /// Create a grant record (the host calls this when a grant is registered).
    pub fn register(&self, g: &Value) -> Result<Value, GrantError> {
        let authority =
            g.get("authority").filter(|a| Authority::from_json(a).is_some()).ok_or_else(|| GrantError::new("bad_request", "malformed authority"))?;
        let id = g.get("id").and_then(Value::as_str).ok_or_else(|| GrantError::new("bad_request", "malformed grant id"))?;
        if self.store.get(id).is_some() {
            return Err(GrantError::new("conflict", "grant id exists"));
        }
        let now = (self.now)();
        let mut rec = g.as_object().cloned().unwrap_or_default();
        let status = match g.get("status") {
            Some(x) if !x.is_null() => x.clone(),
            _ => json!("active"),
        };
        rec.insert("status".to_string(), status);
        rec.insert("rev".to_string(), json!(1));
        rec.insert("created_at".to_string(), json!(now));
        rec.insert("history".to_string(), json!([{"rev": 1, "authority_digest": adigest(authority), "at": now, "action": "create"}]));
        let rec = Value::Object(rec);
        self.store.put(&rec);
        Ok(rec)
    }

    /// `{grants: [view], next_cursor?}`; `f` is `{principal?, agent?, status?, limit?, cursor?}`.
    pub fn list(&self, f: &Value) -> Result<Value, GrantError> {
        let matches = |g: &Value, k: &str| -> bool {
            match f.get(k) {
                None | Some(Value::Null) => true,
                Some(x) => g.get(k) == Some(x),
            }
        };
        let limit = f.get("limit").and_then(Value::as_f64).unwrap_or(50.0).max(1.0).min(200.0);
        let mut all: Vec<Value> = self.store.list().into_iter().filter(|g| matches(g, "principal") && matches(g, "agent") && matches(g, "status")).collect();
        let id_key = |g: &Value| u16key(g.get("id").and_then(Value::as_str).unwrap_or(""));
        all.sort_by_key(|g| id_key(g));
        if let Some(c) = f.get("cursor").and_then(Value::as_str) {
            let ck = u16key(c);
            all.retain(|g| ck < id_key(g));
        }
        let page: Vec<&Value> = all.iter().take(limit as usize).collect();
        let mut out = Map::new();
        out.insert("grants".to_string(), Value::Array(page.iter().map(|g| self.view(g, false)).collect()));
        if (all.len() as f64) > limit {
            if let Some(last) = page.last() {
                out.insert("next_cursor".to_string(), last.get("id").cloned().unwrap_or(Value::Null));
            }
        }
        Ok(Value::Object(out))
    }

    pub fn inspect(&self, id: &str) -> Result<Value, GrantError> {
        Ok(self.view(&self.must(id)?, true))
    }

    fn view(&self, g: &Value, rich: bool) -> Value {
        let mut m = Map::new();
        if let Some(o) = g.as_object() {
            for (k, v) in o {
                if k != "history" {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
        m.insert("authority_digest".to_string(), adigest(&g["authority"]));
        let id = g.get("id").and_then(Value::as_str).unwrap_or("");
        let pending: Vec<Value> =
            self.store.list_needs(id).iter().filter(|n| n.get("status").and_then(Value::as_str) == Some("pending")).map(|n| n["id"].clone()).collect();
        m.insert("pending_needs".to_string(), Value::Array(pending));
        if let (true, Some(p)) = (rich, &self.providers) {
            for (key, hook) in [("usage", p.usage), ("remaining_budget", p.remaining_budget), ("policy_card", p.policy_card), ("residual", p.residual)] {
                if let Some(h) = hook {
                    m.insert(key.to_string(), h(g));
                }
            }
        }
        Value::Object(m)
    }

    fn must(&self, id: &str) -> Result<Value, GrantError> {
        self.store.get(id).ok_or_else(|| GrantError::new("not_found", "no such grant"))
    }

    fn changed(&self, kind: &str, g: &Value) {
        if let Some(f) = &self.on_change {
            f(kind, g);
        }
    }

    /// The reference `verifyAmendment` with its normative check order; `Ok((widens, next authority))` or the refusal code.
    fn verify_amend(cur: &Value, req: &Value, step_up_ok: bool) -> Verdict {
        let action = match req.get("action").and_then(Value::as_str) {
            Some(a @ ("narrow" | "merge" | "replace")) => a,
            _ => return Err("bad_request"),
        };
        let auth_v = req.get("authority").ok_or("bad_request")?;
        let req_auth = Authority::from_json(auth_v).ok_or("bad_request")?;
        if cur.get("status").and_then(Value::as_str) != Some("active") {
            return Err("not_active");
        }
        let cur_v = cur.get("authority").ok_or("bad_request")?;
        let cur_auth = Authority::from_json(cur_v).ok_or("bad_request")?;
        let next = if action == "merge" { merge_authority(&cur_auth, &req_auth).to_json() } else { auth_v.clone() };
        let order = compare_authority(cur_v, &next);
        let widens = order == "wider" || order == "incomparable";
        if action == "narrow" && (widens || order == "equal") {
            return Err("not_narrower");
        }
        let sig = req.get("sig").and_then(Value::as_str);
        let signed_by = req.get("signed_by").and_then(Value::as_str).filter(|x| *x == "holder" || *x == "principal");
        let (Some(sig), Some(signed_by)) = (sig, signed_by) else { return Err("signature_required") };
        if widens && signed_by != "principal" {
            return Err("signature_required");
        }
        let who = cur.get(if signed_by == "principal" { "principal" } else { "agent" }).and_then(Value::as_str).ok_or("bad_request")?;
        let msg = amend_message(cur, action, auth_v).ok_or("bad_request")?;
        if !verify_body(GRANT_AMEND_DOMAIN, &msg, who, Some(sig)) {
            return Err("bad_signature");
        }
        if widens && !step_up_ok {
            return Err("step_up_required");
        }
        Ok((widens, next))
    }

    /// Amend a grant. A narrowing changes it in place (`rev + 1`); a widening is a NEW grant that supersedes the old one.
    /// Returns `{grant, created}`.
    pub fn amend(&self, id: &str, req: &Value) -> Result<Value, GrantError> {
        let mut cur = self.must(id)?;
        let mut v = Self::verify_amend(&cur, req, false);
        // evaluate the (possibly consuming) step-up only when everything else already passed
        if v == Err("step_up_required") && self.step_up(req.get("step_up_ref"), &cur) {
            v = Self::verify_amend(&cur, req, true);
        }
        let (widens, next) = v.map_err(refusal)?;
        let now = (self.now)();
        let action = req.get("action").and_then(Value::as_str).unwrap_or("");
        if !widens {
            let rev = cur.get("rev").and_then(Value::as_i64).unwrap_or(0) + 1;
            set(&mut cur, "authority", next.clone());
            set(&mut cur, "rev", json!(rev));
            push_history(&mut cur, json!({"rev": rev, "authority_digest": adigest(&next), "at": now, "action": action}));
            self.store.put(&cur);
            self.changed("amend", &cur);
            return Ok(json!({"grant": self.view(&cur, true), "created": false}));
        }
        let nid = (self.new_id)("grant");
        let fresh = Self::supersede(&mut cur, &nid, next, now, &format!("supersedes:{id}"));
        self.store.put(&fresh);
        self.store.put(&cur);
        self.changed("supersede", &fresh);
        Ok(json!({"grant": self.view(&fresh, true), "created": true}))
    }

    /// The successor of `old`: same record under `nid` with `authority`, `rev` 1, active, `supersedes` set; `old` becomes `superseded`.
    fn supersede(old: &mut Value, nid: &str, authority: Value, now: i64, action: &str) -> Value {
        let mut fresh = old.clone();
        let old_id = old.get("id").cloned().unwrap_or(Value::Null);
        set(&mut fresh, "id", json!(nid));
        set(&mut fresh, "authority", authority.clone());
        set(&mut fresh, "rev", json!(1));
        set(&mut fresh, "status", json!("active"));
        set(&mut fresh, "supersedes", old_id);
        set(&mut fresh, "created_at", json!(now));
        set(&mut fresh, "history", json!([{"rev": 1, "authority_digest": adigest(&authority), "at": now, "action": action}]));
        if let Some(o) = fresh.as_object_mut() {
            o.remove("superseded_by");
        }
        set(old, "status", json!("superseded"));
        set(old, "superseded_by", json!(nid));
        fresh
    }

    /// Authorised by the principal's signature over `{grant id, scope}` (`auth = {"sig": ...}`) or by a host-authenticated admin
    /// (`auth = {"admin": true}`). `agent` revokes every grant of the grant's agent and principal; `subtree` the grant and every
    /// descendant. Returns `{revoked: [ids]}`.
    pub fn revoke(&self, id: &str, scope: &Value, auth: &Value) -> Result<Value, GrantError> {
        let sc = match scope.as_str() {
            Some(x @ ("grant" | "agent" | "subtree")) => x,
            _ => return Err(GrantError::new("bad_request", "unknown scope")),
        };
        let root = self.must(id)?;
        if let Some(sig) = auth.get("sig") {
            let rv = verify_revoke_signature(&root, scope, Some(sig));
            if rv.get("ok") != Some(&Value::Bool(true)) {
                return Err(refusal(rv.get("code").and_then(Value::as_str).unwrap_or("bad_signature")));
            }
        } else if auth.get("admin") != Some(&Value::Bool(true)) {
            return Err(GrantError::new("forbidden", "not authorised"));
        }
        let all = self.store.list();
        let hit: Vec<Value> = match sc {
            "grant" => vec![root.clone()],
            "agent" => all.iter().filter(|g| g.get("agent") == root.get("agent") && g.get("principal") == root.get("principal")).cloned().collect(),
            _ => {
                let mut ids: HashSet<String> = HashSet::new();
                ids.insert(id.to_string());
                loop {
                    let mut grew = false;
                    for g in &all {
                        let gid = g.get("id").and_then(Value::as_str).unwrap_or("");
                        let parent = g.get("parent").and_then(Value::as_str);
                        if parent.is_some_and(|p| ids.contains(p)) && !ids.contains(gid) {
                            ids.insert(gid.to_string());
                            grew = true;
                        }
                    }
                    if !grew {
                        break;
                    }
                }
                all.iter().filter(|g| g.get("id").and_then(Value::as_str).is_some_and(|x| ids.contains(x))).cloned().collect()
            }
        };
        let mut revoked: Vec<String> = Vec::new();
        for mut g in hit {
            if g.get("status").and_then(Value::as_str) == Some("revoked") {
                continue;
            }
            set(&mut g, "status", json!("revoked"));
            let entry = json!({"rev": g["rev"], "authority_digest": adigest(&g["authority"]), "at": (self.now)(), "action": format!("revoke:{sc}")});
            push_history(&mut g, entry);
            self.store.put(&g);
            revoked.push(g.get("id").and_then(Value::as_str).unwrap_or("").to_string());
        }
        if let Some(f) = &self.on_revoke {
            f(&revoked, sc, &root);
        }
        self.changed("revoke", &root);
        Ok(json!({"revoked": revoked}))
    }

    /// Agent side: ask for more. Typed needs only (validated); no authority changes until the principal approves.
    pub fn request_needs(&self, grant_id: &str, needs: &Value) -> Result<Value, GrantError> {
        let g = self.must(grant_id)?;
        let status = g.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "active" {
            return Err(GrantError::new("not_active", &format!("grant is {status}")));
        }
        let list = match needs.as_array() {
            Some(l) if (1..=32).contains(&l.len()) => l,
            _ => return Err(GrantError::new("bad_request", "1..32 needs")),
        };
        for n in list {
            let limits_ok = match n.get("limits") {
                None => true,
                Some(l) => l.as_object().is_some_and(|o| o.values().all(|v| v.as_f64().is_some_and(|f| f.is_finite() && f >= 0.0))),
            };
            if !n.is_object() || !s(n.get("verb"), 128) || !s(n.get("resource"), 512) || !limits_ok {
                return Err(GrantError::new("bad_request", "malformed need"));
            }
            if let Some(e) = self.validate_need.as_ref().and_then(|f| f(n)).filter(|e| !e.is_empty()) {
                return Err(GrantError::new("bad_request", &e));
            }
        }
        let nr = json!({"id": (self.new_id)("need"), "grant_id": grant_id, "needs": needs, "status": "pending", "created_at": (self.now)()});
        self.store.put_need(&nr);
        self.changed("need", &g);
        Ok(nr)
    }

    /// Principal side: approve the delta (amounts may only be LOWERED, and only when the need is `adjustable`); the result is a widening
    /// merge, a NEW grant that supersedes the old one. Returns `{grant, created: true}`.
    pub fn approve_needs(&self, need_id: &str, approved: &Value, sig: &Value, step_up_ref: Option<&str>) -> Result<Value, GrantError> {
        let mut nr = self.store.get_need(need_id).ok_or_else(|| GrantError::new("not_found", "no such need request"))?;
        let status = nr.get("status").and_then(Value::as_str).unwrap_or("").to_string();
        if status != "pending" {
            return Err(GrantError::new("conflict", &format!("need request is {status}")));
        }
        let mut g = self.must(nr.get("grant_id").and_then(Value::as_str).unwrap_or(""))?;
        let ref_v = step_up_ref.map(|x| Value::String(x.to_string()));
        let mut v = verify_need_approval(&nr, &g, approved, Some(sig), false);
        if v.get("code").and_then(Value::as_str) == Some("step_up_required") && self.step_up(ref_v.as_ref(), &g) {
            v = verify_need_approval(&nr, &g, approved, Some(sig), true);
        }
        if v.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(v.get("code").and_then(Value::as_str).unwrap_or("bad_request")));
        }
        let authority = merged_for_needs(&g, approved).ok_or_else(|| refusal("bad_request"))?;
        let nid = (self.new_id)("grant");
        let now = (self.now)();
        let fresh = Self::supersede(&mut g, &nid, authority, now, &format!("needs:{need_id}"));
        set(&mut nr, "status", json!("approved"));
        set(&mut nr, "result_grant_id", json!(nid));
        self.store.put(&fresh);
        self.store.put(&g);
        self.store.put_need(&nr);
        self.changed("supersede", &fresh);
        Ok(json!({"grant": self.view(&fresh, true), "created": true}))
    }

    /// The grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants).
    pub fn need_grant_id(&self, need_id: &str) -> Result<String, GrantError> {
        let nr = self.store.get_need(need_id).ok_or_else(|| GrantError::new("not_found", "no such need request"))?;
        Ok(nr.get("grant_id").and_then(Value::as_str).unwrap_or("").to_string())
    }

    pub fn deny_needs(&self, need_id: &str) -> Result<(), GrantError> {
        let mut nr = self.store.get_need(need_id).ok_or_else(|| GrantError::new("not_found", "no such need request"))?;
        let status = nr.get("status").and_then(Value::as_str).unwrap_or("").to_string();
        if status != "pending" {
            return Err(GrantError::new("conflict", &format!("need request is {status}")));
        }
        set(&mut nr, "status", json!("denied"));
        self.store.put_need(&nr);
        Ok(())
    }
}

/// The merged authority an approved need set produces (the same delta [`verify_need_approval`] digests): the approved verbs and resources,
/// the approved amounts as ceilings, merged into the grant's authority.
fn merged_for_needs(g: &Value, approved: &Value) -> Option<Value> {
    let cur = Authority::from_json(g.get("authority")?)?;
    let mut delta = Authority::default();
    for a in approved.as_array()? {
        let verb = a.get("verb")?.as_str()?;
        let resource = a.get("resource")?.as_str()?;
        if let Some(l) = a.get("limits").and_then(Value::as_object) {
            for (k, v) in l {
                let f = v.as_f64()?;
                let e = delta.limits.entry(k.clone()).or_insert(0.0);
                *e = (*e).max(f);
            }
        }
        delta.verbs.push(verb.to_string());
        delta.resources.push(resource.to_string());
    }
    Some(merge_authority(&cur, &delta).to_json())
}

// ---- HTTP binding -----------------------------------------------------------------------------------------------------------

/// Discovery fragment for `/.well-known/pca-configuration`.
pub fn grant_management_metadata(base: &str) -> Value {
    json!({"grant_management": {"grants_endpoint": format!("{base}{GRANTS_PATH}"), "needs_endpoint": format!("{base}{NEEDS_PATH}"), "amend_actions": ["narrow", "merge", "replace"], "revoke_scopes": ["grant", "agent", "subtree"], "widening": "new_grant_id_with_supersedes"}})
}

pub fn lease_management_metadata(base: &str) -> Value {
    json!({"leases": {"leases_endpoint": format!("{base}{LEASES_PATH}"), "revoke_targets": ["lease", "prefix", "grant"]}})
}

fn resp(status: i64, body: Value) -> Value {
    json!({"status": status, "body": body})
}

fn err_resp(e: &GrantError) -> Value {
    let status = status_of(&e.code);
    if status == 500 {
        return resp(500, json!({"error": "server_error"}));
    }
    resp(status, json!({"error": e.code, "message": e.message}))
}

fn segments(req: &Value) -> Vec<String> {
    req.get("path").and_then(Value::as_str).unwrap_or("").split('/').filter(|x| !x.is_empty()).map(String::from).collect()
}

fn query<'a>(req: &'a Value, k: &str) -> Option<&'a str> {
    req.get("query").and_then(|q| q.get(k)).and_then(Value::as_str)
}

fn authenticated(who: &Option<Value>) -> Option<&Value> {
    who.as_ref().filter(|w| !w.is_null() && (truthy(w.get("admin")) || truthy(w.get("principal"))))
}

/// One request against the grant management resource. `authenticate(request) -> {principal?, admin?} | None` is who is calling, as the
/// host authenticated them; `principal` limits every read and write to that principal's grants. Never errs: a failure is a status.
pub fn grant_http(svc: &GrantService, authenticate: &dyn Fn(&Value) -> Option<Value>, req: &Value) -> Value {
    let who = authenticate(req);
    let Some(who) = authenticated(&who) else { return resp(401, json!({"error": "unauthenticated"})) };
    match grant_route(svc, who, req) {
        Ok(r) => r,
        Err(e) => err_resp(&e),
    }
}

fn grant_route(svc: &GrantService, who: &Value, req: &Value) -> Result<Value, GrantError> {
    let seg = segments(req);
    let admin = truthy(who.get("admin"));
    let empty = json!({});
    let b = match req.get("body") {
        Some(x) if x.is_object() => x,
        _ => &empty,
    };
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let own = |gid: &str| -> Result<(), GrantError> {
        let g = svc.inspect(gid)?;
        if !admin && g.get("principal") != who.get("principal") {
            return Err(GrantError::new("not_found", "no such grant"));
        }
        Ok(())
    };
    if seg.first().map(String::as_str) != Some("pca") {
        return Ok(resp(404, json!({"error": "not_found"})));
    }
    let kind = seg.get(1).map(String::as_str);
    if kind == Some("grants") {
        if seg.len() == 2 && method == "GET" {
            let status = query(req, "status");
            if status.is_some_and(|x| !matches!(x, "active" | "revoked" | "superseded")) {
                return Err(GrantError::new("bad_request", "bad status"));
            }
            let principal = if admin { query(req, "principal").map(|x| Value::String(x.to_string())) } else { who.get("principal").cloned() };
            let mut f = Map::new();
            if let Some(p) = principal.filter(|p| truthy(Some(p))) {
                f.insert("principal".to_string(), p);
            }
            if let Some(a) = query(req, "agent").filter(|x| !x.is_empty()) {
                f.insert("agent".to_string(), json!(a));
            }
            if let Some(x) = status.filter(|x| !x.is_empty()) {
                f.insert("status".to_string(), json!(x));
            }
            if let Some(l) = query(req, "limit").map(js_str_to_number).filter(|l| l.is_finite()) {
                f.insert("limit".to_string(), json!(l));
            }
            if let Some(c) = query(req, "cursor").filter(|x| !x.is_empty()) {
                f.insert("cursor".to_string(), json!(c));
            }
            return Ok(resp(200, svc.list(&Value::Object(f))?));
        }
        let Some(gid) = seg.get(2).filter(|x| !x.is_empty()) else { return Ok(resp(404, json!({"error": "not_found"}))) };
        own(gid)?;
        if seg.len() == 3 && method == "GET" {
            return Ok(resp(200, svc.inspect(gid)?));
        }
        if seg.len() == 3 && method == "DELETE" {
            let scope = json!(query(req, "scope").unwrap_or("grant"));
            let sig = b.get("sig").and_then(Value::as_str).unwrap_or("");
            // a principal-scoped caller must still sign; only an admin may revoke without a principal signature
            let auth = if admin && sig.is_empty() { json!({"admin": true}) } else { json!({"sig": sig}) };
            return Ok(resp(200, svc.revoke(gid, &scope, &auth)?));
        }
        if seg.len() == 4 && seg[3] == "amend" && method == "POST" {
            let r = svc.amend(gid, req.get("body").unwrap_or(&Value::Null))?;
            return Ok(resp(if r["created"] == true { 201 } else { 200 }, r["grant"].clone()));
        }
        if seg.len() == 4 && seg[3] == "needs" && method == "POST" {
            return Ok(resp(201, svc.request_needs(gid, b.get("needs").unwrap_or(&Value::Null))?));
        }
    }
    if kind == Some("needs") && seg.len() > 3 && method == "POST" {
        if seg[3] == "approve" {
            own(&svc.need_grant_id(&seg[2])?)?;
            let (Some(sig), Some(approved)) = (b.get("sig").filter(|x| x.is_string()), b.get("approved").filter(|x| x.is_array())) else {
                return Err(GrantError::new("bad_request", "sig and approved are required"));
            };
            let r = svc.approve_needs(&seg[2], approved, sig, b.get("step_up_ref").and_then(Value::as_str))?;
            return Ok(resp(201, r["grant"].clone()));
        }
        if seg[3] == "deny" {
            own(&svc.need_grant_id(&seg[2])?)?;
            svc.deny_needs(&seg[2])?;
            return Ok(resp(200, json!({"status": "denied"})));
        }
    }
    Ok(resp(404, json!({"error": "not_found"})))
}

// ---- lease HTTP binding -----------------------------------------------------------------------------------------------------

fn lease_status(code: &str) -> i64 {
    match code {
        "bad_record" => 400,
        "bad_seq" | "stale_seq" | "lease_fork" | "expired_lease" | "revoked" => 409,
        "renewal_mismatch" | "over_max_ttl" | "ttl_ceiling" | "not_extending" | "stale_justification" => 422,
        "sod" | "unknown_authority" => 403,
        "store_unreachable" => 503,
        _ => 400,
    }
}

/// The `{decision, code?, lease_id?, expires_at?}` body of a lease check.
pub fn lease_decision_json(d: &LeaseDecision) -> Value {
    let mut m = Map::new();
    m.insert("decision".to_string(), json!(d.decision));
    if let Some(c) = d.code {
        m.insert("code".to_string(), json!(c));
    }
    if let Some(l) = &d.lease_id {
        m.insert("lease_id".to_string(), json!(l));
    }
    if let Some(e) = d.expires_at {
        m.insert("expires_at".to_string(), json!(e));
    }
    Value::Object(m)
}

/// Hosted lease routes. The server only stores records the lease authority already signed; it never mints one. `POST /pca/leases`
/// `{lease, chain?}` issues or renews (admin); `GET /pca/leases/:id`; `POST /pca/leases/:id/check` `{lease}`; `POST /pca/leases/revoke`
/// `{revocation}` (admin). `authenticate(request) -> {admin?, principal?} | None`; `now()` is epoch ms.
pub fn lease_http(reg: &LeaseRegistry, authenticate: &dyn Fn(&Value) -> Option<Value>, now: &dyn Fn() -> i64, req: &Value) -> Value {
    let who = authenticate(req);
    let Some(who) = authenticated(&who) else { return resp(401, json!({"error": "unauthenticated"})) };
    let server_error = || resp(500, json!({"error": "server_error"}));
    let seg = segments(req);
    let empty = json!({});
    let b = match req.get("body") {
        Some(x) if x.is_object() => x,
        _ => &empty,
    };
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    if seg.len() < 2 || seg[0] != "pca" || seg[1] != "leases" {
        return resp(404, json!({"error": "not_found"}));
    }
    let admin = who.get("admin") == Some(&Value::Bool(true));
    let visible = |holder: Option<&Value>| admin || who.get("principal") == holder;
    let null = Value::Null;
    if seg.len() == 2 && method == "POST" {
        if !truthy(who.get("admin")) {
            return resp(403, json!({"error": "forbidden"}));
        }
        let chain: Vec<String> = match b.get("chain").and_then(Value::as_array) {
            Some(c) if c.iter().all(Value::is_string) => c.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => Vec::new(),
        };
        return match reg.accept(b.get("lease").unwrap_or(&null), &chain) {
            Ok((replaced, seq)) => resp(if replaced { 201 } else { 200 }, json!({"ok": true, "replaced": replaced, "seq": seq})),
            Err(code) => {
                let lease = b.get("lease").unwrap_or(&null);
                let mut body = json!({"error": code});
                if let Some(m) = reg.accept_reason(code, lease, &chain) {
                    body["message"] = json!(m);
                }
                resp(lease_status(code), body)
            }
        };
    }
    if seg.len() == 3 && seg[2] == "revoke" && method == "POST" {
        if !truthy(who.get("admin")) {
            return resp(403, json!({"error": "forbidden"}));
        }
        return match reg.revoke(b.get("revocation").unwrap_or(&null)) {
            Ok(n) => resp(200, json!({"ok": true, "revoked": n})),
            Err(code) => resp(
                if code == "store_unreachable" {
                    503
                } else if code == "unknown_authority" {
                    403
                } else {
                    400
                },
                json!({"error": code}),
            ),
        };
    }
    let Some(lid) = seg.get(2).filter(|x| !x.is_empty()) else { return resp(404, json!({"error": "not_found"})) };
    if seg.len() == 3 && method == "GET" {
        return match reg.get(lid) {
            Err(_) => server_error(),
            Ok(Some(cur)) if visible(cur.get("holder")) => match reg.history(lid) {
                Ok(h) => resp(200, json!({"lease": cur, "history": h})),
                Err(_) => server_error(),
            },
            Ok(_) => resp(404, json!({"error": "not_found"})),
        };
    }
    if seg.len() == 4 && seg[3] == "check" && method == "POST" {
        return match reg.get(lid) {
            Err(_) => server_error(),
            Ok(Some(cur)) if visible(cur.get("holder")) => {
                let d = check_lease(b.get("lease").unwrap_or(&null), reg, &json!(now()));
                resp(if d.decision == "allow" { 200 } else { 403 }, lease_decision_json(&d))
            }
            Ok(_) => resp(404, json!({"error": "not_found"})),
        };
    }
    resp(404, json!({"error": "not_found"}))
}

/// `o` without `reason` and `message` (the diagnostic text of a refusal).
pub fn strip_diagnostics(o: &Value) -> Value {
    without(o, &["reason", "message"])
}
