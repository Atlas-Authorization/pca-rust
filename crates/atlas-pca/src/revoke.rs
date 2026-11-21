//! Revocation registry for PCA capability chains: point revocations (a cap id, a holder key, an issuer key), subtree
//! revocations (a cap-id path prefix), scheduled revocations (`notBefore`), the instant kill-switch, the fail-closed chain
//! check, `verify_with_revocation` (core result AND not revoked), and the Shared-Signals / CAEP ingest bridge.
//!
//! Entries are JSON objects in the reference's shape `{kind, value, prefix?, reason, revokedAt, notBefore?}`; inputs follow
//! JavaScript value semantics (`x ?? default`, `String(x)` keys) so the registry is byte-identical to the reference.
use crate::oauth::js_str;
use serde_json::{json, Map, Value};
use std::sync::Mutex;

pub const CAEP_SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
pub const CAEP_GRANT_REVOKED: &str = "https://atlasauth.net/caep/grant-revoked";
pub const CAEP_KILL_SWITCH: &str = "https://atlasauth.net/caep/kill-switch";

/// `CAEP_EVENT_TYPES` of the reference.
pub fn caep_event_types() -> Value {
    json!({ "sessionRevoked": CAEP_SESSION_REVOKED, "grantRevoked": CAEP_GRANT_REVOKED, "killSwitch": CAEP_KILL_SWITCH })
}

/// A member of an object (`v.k`); `None` for a missing member and for any non-object (a string's / array's own members are
/// never names the reference reads).
pub(crate) fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

/// `v.k ?? ...`: absent or null.
fn nn<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    member(v, k).filter(|x| !x.is_null())
}

/// `String(x)` with `undefined` for a missing value.
fn js_key(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".into(), js_str)
}

fn finite(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

/// `Math.round` (half rounds toward +infinity).
fn js_round(v: f64) -> f64 {
    let f = v.floor();
    if v - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

/// Is the entry in force at `now` (ms)? An entry without `notBefore` always is; a non-finite clock or schedule fails closed (in force).
pub fn is_active_at(entry: &Value, now: &Value) -> bool {
    let Some(nb) = member(entry, "notBefore") else { return true };
    match (finite(Some(now)), finite(Some(nb))) {
        (Some(n), Some(b)) => n >= b,
        _ => true,
    }
}

/// A pluggable revocation store, keyed by `(kind, value)`; `add` replaces an existing entry in place. Any `Err` from the
/// store makes the chain check fail closed.
pub trait RevocationStore {
    fn add(&self, entry: Value) -> Result<(), String>;
    fn remove(&self, kind: &str, value: &str) -> Result<bool, String>;
    fn get(&self, kind: &str, value: &str) -> Result<Option<Value>, String>;
    fn all(&self) -> Result<Vec<Value>, String>;
    fn clear(&self) -> Result<(), String>;
}

fn store_key(kind: &str, value: &str) -> String {
    format!("{kind}\u{0}{value}")
}

/// Insertion-ordered in-memory store (a replaced entry keeps its position, as a JavaScript `Map` does).
#[derive(Default)]
pub struct InMemoryRevocationStore {
    entries: Mutex<Vec<(String, Value)>>,
}

impl InMemoryRevocationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn add(&self, entry: Value) -> Result<(), String> {
        let key = store_key(&js_key(member(&entry, "kind")), &js_key(member(&entry, "value")));
        let mut e = self.entries.lock().map_err(|_| "store poisoned".to_string())?;
        match e.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = entry,
            None => e.push((key, entry)),
        }
        Ok(())
    }
    fn remove(&self, kind: &str, value: &str) -> Result<bool, String> {
        let key = store_key(kind, value);
        let mut e = self.entries.lock().map_err(|_| "store poisoned".to_string())?;
        let before = e.len();
        e.retain(|(k, _)| *k != key);
        Ok(e.len() != before)
    }
    fn get(&self, kind: &str, value: &str) -> Result<Option<Value>, String> {
        let key = store_key(kind, value);
        Ok(self.entries.lock().map_err(|_| "store poisoned".to_string())?.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()))
    }
    fn all(&self) -> Result<Vec<Value>, String> {
        Ok(self.entries.lock().map_err(|_| "store poisoned".to_string())?.iter().map(|(_, v)| v.clone()).collect())
    }
    fn clear(&self) -> Result<(), String> {
        self.entries.lock().map_err(|_| "store poisoned".to_string())?.clear();
        Ok(())
    }
}

fn valid_file_entry(e: &Value) -> bool {
    let Some(o) = e.as_object() else { return false };
    let text = |k: &str| o.get(k).and_then(Value::as_str);
    let Some(kind) = text("kind").filter(|k| ["cap", "holder", "issuer", "prefix"].contains(k)) else { return false };
    if text("value").map_or(true, str::is_empty) || text("reason").is_none() || finite(o.get("revokedAt")).is_none() {
        return false;
    }
    // an absent notBefore is fine; a present one (null included) must be a finite number
    if o.get("notBefore").is_some() && finite(o.get("notBefore")).is_none() {
        return false;
    }
    if kind == "prefix" {
        let Some(p) = o.get("prefix").and_then(Value::as_array).filter(|p| !p.is_empty()) else { return false };
        let parts: Vec<&str> = p.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).collect();
        return parts.len() == p.len() && Some(parts.join(",").as_str()) == text("value");
    }
    true
}

/// A durable [`RevocationStore`] backed by one JSON file. Every change is written to a temporary file, flushed to disk, then renamed
/// over the real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two processes must not
/// share one file.
///
/// Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes [`FileRevocationStore::open`]
/// fail; silently starting empty would un-revoke everything. A failed flush puts memory back, so memory never claims more than disk.
pub struct FileRevocationStore {
    path: std::path::PathBuf,
    entries: Mutex<Vec<(String, Value)>>,
}

impl FileRevocationStore {
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let mut entries: Vec<(String, Value)> = Vec::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|_| "FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty".to_string())?;
            let parsed: Value = serde_json::from_str(&text).map_err(|_| "FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty".to_string())?;
            let list = parsed.get("entries").and_then(Value::as_array).filter(|l| l.iter().all(valid_file_entry));
            let Some(list) = list else { return Err("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty".into()) };
            for e in list {
                let key = store_key(&js_key(member(e, "kind")), &js_key(member(e, "value")));
                match entries.iter_mut().find(|(k, _)| *k == key) {
                    Some(slot) => slot.1 = e.clone(),
                    None => entries.push((key, e.clone())),
                }
            }
        }
        Ok(FileRevocationStore { path, entries: Mutex::new(entries) })
    }

    fn flush(&self, entries: &[(String, Value)]) -> Result<(), String> {
        use std::io::Write;
        let tmp = std::path::PathBuf::from(format!("{}.tmp", self.path.display()));
        let body = crate::js_stringify(&json!({"v": 1, "entries": entries.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()}));
        let mut f = crate::private_file::open_private(std::fs::OpenOptions::new().write(true).create(true).truncate(true), &tmp).map_err(|e| e.to_string())?;
        f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        crate::durable_rename::replace_file(&tmp, &self.path).map_err(|e| e.to_string())?;
        crate::durable_rename::sync_parent(&self.path).map_err(|e| e.to_string())
    }

    /// Apply `change` and flush; on a failed flush the previous entries are put back.
    fn write<T>(&self, change: impl FnOnce(&mut Vec<(String, Value)>) -> T) -> Result<T, String> {
        let mut e = self.entries.lock().map_err(|_| "store poisoned".to_string())?;
        let before = e.clone();
        let out = change(&mut e);
        if let Err(err) = self.flush(&e) {
            *e = before;
            return Err(err);
        }
        Ok(out)
    }
}

impl RevocationStore for FileRevocationStore {
    fn add(&self, entry: Value) -> Result<(), String> {
        let key = store_key(&js_key(member(&entry, "kind")), &js_key(member(&entry, "value")));
        self.write(|e| match e.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = entry,
            None => e.push((key, entry)),
        })
    }
    fn remove(&self, kind: &str, value: &str) -> Result<bool, String> {
        let key = store_key(kind, value);
        self.write(|e| {
            let before = e.len();
            e.retain(|(k, _)| *k != key);
            e.len() != before
        })
    }
    fn get(&self, kind: &str, value: &str) -> Result<Option<Value>, String> {
        let key = store_key(kind, value);
        Ok(self.entries.lock().map_err(|_| "store poisoned".to_string())?.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()))
    }
    fn all(&self) -> Result<Vec<Value>, String> {
        Ok(self.entries.lock().map_err(|_| "store poisoned".to_string())?.iter().map(|(_, v)| v.clone()).collect())
    }
    fn clear(&self) -> Result<(), String> {
        self.write(|e| e.clear())
    }
}

/// The registry over a [`RevocationStore`].
pub struct RevocationRegistry<S: RevocationStore = InMemoryRevocationStore> {
    pub store: S,
}

impl Default for RevocationRegistry {
    fn default() -> Self {
        Self { store: InMemoryRevocationStore::new() }
    }
}

impl<S: RevocationStore> RevocationRegistry<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Record a revocation (`{kind: cap|holder|issuer, value}` or `{kind: prefix, prefix: [cap ids]}`, plus `reason?`,
    /// `revokedAt?` (default now, ms), `notBefore?`). Returns the stored entry.
    pub fn revoke(&self, input: &Value) -> Result<Value, String> {
        if input.is_null() {
            return Err("revoke: input is required".into());
        }
        let revoked_at = nn(input, "revokedAt").cloned().unwrap_or_else(|| num(now_ms()));
        let reason = nn(input, "reason").cloned().unwrap_or_else(|| json!(""));
        if finite(Some(&revoked_at)).is_none() {
            return Err("revoke: revokedAt must be a finite number".into());
        }
        let not_before = member(input, "notBefore");
        if not_before.is_some() && finite(not_before).is_none() {
            return Err("revoke: notBefore must be a finite number".into());
        }
        if !reason.is_string() {
            return Err("revoke: reason must be a string".into());
        }
        let kind = member(input, "kind");
        let mut e = Map::new();
        if kind.and_then(Value::as_str) == Some("prefix") {
            let p = match member(input, "prefix") {
                Some(Value::Array(p)) if !p.is_empty() => p,
                _ => return Err("revoke: a prefix revocation requires a non-empty cap-id path".into()),
            };
            if p.iter().any(|id| id.as_str().is_none_or(|s| s.is_empty() || s.contains(','))) {
                return Err("revoke: every prefix element must be a non-empty string without ','".into());
            }
            e.insert("kind".into(), json!("prefix"));
            e.insert("value".into(), json!(js_str(&Value::Array(p.clone()))));
            e.insert("prefix".into(), Value::Array(p.clone()));
        } else {
            let value = match member(input, "value") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return Err(format!("revoke: a {} revocation requires a non-empty value", js_key(kind))),
            };
            if let Some(k) = kind {
                e.insert("kind".into(), k.clone());
            }
            e.insert("value".into(), json!(value));
        }
        e.insert("reason".into(), reason);
        e.insert("revokedAt".into(), revoked_at);
        if let Some(nb) = not_before {
            e.insert("notBefore".into(), nb.clone());
        }
        let entry = Value::Object(e);
        self.store.add(entry.clone())?;
        Ok(entry)
    }

    /// Revoke a cap id (a string target) or a cap-id path prefix (an array target) and everything below it.
    pub fn revoke_subtree(&self, target: &Value, opts: Option<&Value>) -> Result<Value, String> {
        let mut input = Map::new();
        if target.is_array() {
            input.insert("kind".into(), json!("prefix"));
            input.insert("prefix".into(), target.clone());
        } else {
            input.insert("kind".into(), json!("cap"));
            input.insert("value".into(), target.clone());
        }
        if let Some(Value::Object(o)) = opts {
            input.extend(o.clone());
        }
        self.revoke(&Value::Object(input))
    }

    /// Remove a revocation by key; `false` when there was none.
    pub fn unrevoke(&self, key: &Value) -> Result<bool, String> {
        if key.is_null() {
            return Err("unrevoke: key is required".into());
        }
        let kind = member(key, "kind");
        if kind.and_then(Value::as_str) == Some("prefix") {
            return match member(key, "prefix") {
                Some(p @ Value::Array(a)) if !a.is_empty() => self.store.remove("prefix", &js_str(p)),
                _ => Ok(false),
            };
        }
        self.store.remove(&js_key(kind), &js_key(member(key, "value")))
    }

    pub fn list(&self) -> Result<Vec<Value>, String> {
        self.store.all()
    }

    pub fn lookup(&self, kind: &str, value: &str) -> Result<Option<Value>, String> {
        self.store.get(kind, value)
    }

    pub fn prefixes(&self) -> Result<Vec<Value>, String> {
        Ok(self.store.all()?.into_iter().filter(|e| member(e, "kind").and_then(Value::as_str) == Some("prefix")).collect())
    }

    pub fn clear(&self) -> Result<(), String> {
        self.store.clear()
    }

    fn kill(&self, kind: &str, value: &Value, opts: Option<&Value>, default_reason: &str) -> Result<Value, String> {
        let opts = opts.unwrap_or(&Value::Null);
        let mut input = Map::new();
        input.insert("kind".into(), json!(kind));
        input.insert("value".into(), value.clone());
        input.insert("reason".into(), nn(opts, "reason").cloned().unwrap_or_else(|| json!(default_reason)));
        if let Some(at) = member(opts, "revokedAt") {
            input.insert("revokedAt".into(), at.clone());
        }
        self.revoke(&Value::Object(input))
    }

    /// Kill-switch: revoke every capability held by `holder`, instantly (no `notBefore`).
    pub fn kill_agent(&self, holder: &Value, opts: Option<&Value>) -> Result<Value, String> {
        self.kill("holder", holder, opts, "kill-switch: agent killed")
    }

    /// Kill-switch: revoke the subtree rooted at a capability id, instantly.
    pub fn kill_subtree(&self, root_cap_id: &Value, opts: Option<&Value>) -> Result<Value, String> {
        self.kill("cap", root_cap_id, opts, "kill-switch: subtree killed")
    }
}

fn match_reason(e: &Value) -> String {
    let base = format!("{} {} is revoked", js_key(member(e, "kind")), js_key(member(e, "value")));
    match member(e, "reason").and_then(Value::as_str) {
        Some(r) if !r.is_empty() => format!("{base}: {r}"),
        _ => base,
    }
}

fn hit(e: Value) -> Value {
    let reason = match_reason(&e);
    json!({ "revoked": true, "matched": e, "reason": reason })
}

fn scan<S: RevocationStore>(chain: &[Value], reg: &RevocationRegistry<S>, now: &Value) -> Result<Value, String> {
    let mut ids: Vec<Value> = Vec::new();
    for hop in chain {
        for kind in ["cap", "issuer", "holder"] {
            let k = if kind == "cap" { "id" } else { kind };
            let key = member(hop, k).and_then(Value::as_str).unwrap_or("");
            if let Some(e) = reg.lookup(kind, key)? {
                if is_active_at(&e, now) {
                    return Ok(hit(e));
                }
            }
        }
        ids.push(hop["id"].clone());
    }
    for e in reg.prefixes()? {
        if let Some(Value::Array(p)) = member(&e, "prefix") {
            if !p.is_empty() && ids.len() >= p.len() && p.iter().zip(&ids).all(|(a, b)| a == b) && is_active_at(&e, now) {
                return Ok(hit(e));
            }
        }
    }
    Ok(json!({ "revoked": false }))
}

/// Is any hop of the action's chain revoked (cap id, issuer, holder per hop root to leaf, then subtree prefixes)? Fails
/// closed (`revoked: true`) on a non-finite clock, a missing / empty chain, a hop without id / issuer / holder, or a store error.
pub fn check_revocation<S: RevocationStore>(p: &Value, reg: &RevocationRegistry<S>, opts: Option<&Value>) -> Value {
    let closed = |why: &str| json!({ "revoked": true, "reason": format!("revocation check failed closed: {why}") });
    let now = opts.and_then(|o| nn(o, "now")).cloned().unwrap_or_else(|| num(now_ms()));
    if finite(Some(&now)).is_none() {
        return closed("clock is not a finite number");
    }
    let chain = match member(p, "cap_chain") {
        Some(Value::Array(c)) if !c.is_empty() => c,
        _ => return closed("the action carries no capability chain"),
    };
    for hop in chain {
        for k in ["id", "issuer", "holder"] {
            if member(hop, k).and_then(Value::as_str).is_none_or(str::is_empty) {
                return closed(&format!("a chain hop has no {k}"));
            }
        }
    }
    scan(chain, reg, &now).unwrap_or_else(|_| closed("the revocation store failed (Error)"))
}

/// The core verify result (`{allow, reason?}`) AND the revocation check: `{allow, coreAllow, revocation, reason?}`.
pub fn verify_with_revocation<S: RevocationStore>(p: &Value, core: &Value, reg: &RevocationRegistry<S>, opts: Option<&Value>) -> Value {
    let core_allow = member(core, "allow") == Some(&Value::Bool(true));
    let revocation = check_revocation(p, reg, opts);
    let revoked = revocation["revoked"] == Value::Bool(true);
    let allow = core_allow && !revoked;
    let mut out = json!({ "allow": allow, "coreAllow": core_allow, "revocation": revocation });
    if !allow {
        out["reason"] = if !core_allow {
            nn(core, "reason").cloned().unwrap_or_else(|| json!("core verification failed"))
        } else {
            nn(&out["revocation"], "reason").cloned().unwrap_or_else(|| json!("revoked"))
        };
    }
    out
}

fn revoked_at_from(ts: Option<&Value>) -> Value {
    num(finite(ts).map_or_else(now_ms, |t| js_round(t * 1000.0)))
}

fn non_empty_str(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| x.as_str().is_some_and(|s| !s.is_empty()))
}

/// Ingest a CAEP / Shared-Signals event (`{type, payload}`) into the registry: grant-revoked -> cap, kill-switch -> holder
/// (+ cap), anything else is read as session-revoked -> holder (`subject.holder ?? agent ?? id`). Returns the entries added.
pub fn ingest_caep_event<S: RevocationStore>(event: &Value, reg: &RevocationRegistry<S>) -> Result<Vec<Value>, String> {
    if event.is_null() {
        return Err("ingestCaepEvent: event is required".into());
    }
    let ty = member(event, "type").and_then(Value::as_str);
    let ev = match member(event, "payload") {
        None | Some(Value::Null) => return Err("ingestCaepEvent: the event has no payload".into()),
        Some(v) => v,
    };
    let mut added = Vec::new();
    let reason = |k: &str, d: &str| nn(ev, k).cloned().unwrap_or_else(|| json!(d));
    if ty == Some(CAEP_GRANT_REVOKED) {
        if let Some(g) = non_empty_str(member(ev, "grant_ref")) {
            let at = revoked_at_from(member(ev, "event_timestamp"));
            added.push(reg.revoke(&json!({ "kind": "cap", "value": g, "reason": reason("reason", "CAEP grant-revoked"), "revokedAt": at }))?);
        }
    } else if ty == Some(CAEP_KILL_SWITCH) {
        let at = revoked_at_from(member(ev, "event_timestamp"));
        if let Some(a) = non_empty_str(member(ev, "agent")) {
            added.push(reg.kill_agent(a, Some(&json!({ "reason": reason("reason", "CAEP kill-switch"), "revokedAt": at })))?);
        }
        if let Some(g) = non_empty_str(member(ev, "grant_ref")) {
            added.push(reg.revoke(&json!({ "kind": "cap", "value": g, "reason": reason("reason", "CAEP kill-switch"), "revokedAt": at }))?);
        }
    } else {
        let subject = member(ev, "subject");
        if subject == Some(&Value::Null) {
            return Err("ingestCaepEvent: subject is null".into());
        }
        let field = |k: &str| subject.and_then(|s| non_empty_str(member(s, k)));
        if let Some(h) = field("holder").or_else(|| field("agent")).or_else(|| field("id")) {
            let why = nn(ev, "reason_admin").or_else(|| nn(ev, "reason_user")).cloned().unwrap_or_else(|| json!("CAEP session-revoked"));
            added.push(reg.kill_agent(h, Some(&json!({ "reason": why, "revokedAt": revoked_at_from(member(ev, "event_timestamp")) })))?);
        }
    }
    Ok(added)
}

#[cfg(test)]
mod owner_only_tests {
    use super::*;

    #[test]
    fn the_revocation_file_is_owner_only() {
        let d = std::env::temp_dir().join(format!("revoke-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        crate::private_file::create_dir_all_private(&d).unwrap();
        let p = d.join("r.json");
        let s = FileRevocationStore::open(&p).unwrap();
        s.add(json!({"kind": "key", "value": "k1"})).unwrap();
        crate::private_file::assert_owner_only(&p);
        let _ = std::fs::remove_dir_all(&d);
    }
}
