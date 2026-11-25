//! Durable aggregate budgets (`packages/pca/src/budget-ledger.ts`): the `BudgetLedger` contract, the reference [`KvBudgetLedger`], signed
//! and anchored releases, and scoped admission.
//!
//! CLAIMED: NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE, given a ledger that is linearizable per key and durable. An accumulator with
//! `scope: principal | org | fleet` counts the events of EVERY session and delegated agent of that scope in ONE state keyed by the scope
//! id, so N sessions share one cap and a split across sessions or agents buys nothing. A reservation counts as soon as it is made; the
//! ledger refuses one whose post-value would pass the accumulator's `domain_max`, inside the same atomic step that records it.
//!
//! TWO PHASES, THREE STEPS: `reserve` (counted at once), `start` (recorded BEFORE the effect runs), then `commit` (the effect happened)
//! or `release` (it did not; a signed event, [`sign_release`], that can be anchored in a transparency log, [`anchor_release`]). `expire`
//! frees only a reservation that was never started: expiry needs no trusted clock. A release that never arrives only OVER-restricts.
//! [`admit_aggregate_action`] refuses (`not_durable`) a ledger whose `durable` is not true, and denies `scope_unbound` when the caller
//! names no id for a scope the root uses. Events are `{id, verb, resource, params, t, status}`.
use crate::agent::KeyPair;
use crate::hash::canonical_bytes_strict;
use crate::kv::AtomicKv;
use crate::ledger_store::LedgerStore;
use crate::store_errors::{kv_err, safe_int, CodedError, R};
use crate::{b64_encode, decode_b64u_strict, hash_canonical, verify_b64u};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub const BUDGET_PREFIX: &str = "pca-budget-ledger/v1/";
pub const RELEASE_DOMAIN: &str = "atlas-pca/budget-release/v1\0";
const RELEASE_REASONS: [&str; 4] = ["effect_failed", "effect_not_run", "denied_downstream", "rollback"];

fn id_ok(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        let n = s.encode_utf16().count();
        n > 0 && n <= 256 && !s.chars().any(|c| (c as u32) < 0x20)
    })
}

fn is_int(v: Option<&Value>) -> bool {
    v.is_some_and(|x| safe_int(x).is_some())
}

/// The ledger key of a scope (`principal` | `org` | `fleet`) and its id. Injective: the id is percent-encoded.
pub fn scope_key(scope: &str, id: &Value) -> R<String> {
    if !id_ok(id) {
        return Err(CodedError::new("invalid", "a scope id is a non-empty string of at most 256 characters without control characters"));
    }
    let mut enc = String::new();
    for b in id.as_str().unwrap_or("").bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(format!("{scope}/{enc}"))
}

fn empty_doc() -> Value {
    json!({"v": 1, "ver": 0, "events": []})
}

fn decode_doc(raw: Option<&Value>) -> R<Value> {
    let Some(raw) = raw.filter(|r| !r.is_null()) else { return Ok(empty_doc()) };
    let ok = raw.get("v").and_then(Value::as_f64) == Some(1.0)
        && is_int(raw.get("ver"))
        && raw["events"].as_array().is_some_and(|l| l.iter().all(|e| e.is_object() && e["id"].is_string()));
    if !ok {
        return Err(CodedError::new("store_corrupt", "budget document has the wrong shape"));
    }
    Ok(raw.clone())
}

fn same_event(a: &Value, b: &Value) -> bool {
    let k = |e: &Value| {
        hash_canonical(&json!({"id": e.get("id"), "verb": e.get("verb"), "resource": e.get("resource"), "params": e.get("params"), "t": e.get("t")}))
    };
    k(a) == k(b)
}

fn generic(why: impl AsRef<str>) -> CodedError {
    CodedError::new("Error", why)
}

fn ver_of(doc: &Value) -> Value {
    doc["ver"].clone()
}

fn bump(doc: &mut Value) {
    doc["ver"] = json!(doc["ver"].as_i64().unwrap_or(0) + 1);
}

/// Reserve `req["event"]` in `doc` (`{ver, events}`) unless it would pass an accumulator's cap. The pure transition every store is this
/// plus a per-key lock.
pub fn reserve_in_doc(doc: &mut Value, req: &Value) -> R<Value> {
    let e = req.get("event").filter(|e| e.is_object());
    let bad = || CodedError::range("reserve: a malformed event");
    let e = e.ok_or_else(bad)?;
    if !id_ok(&e["id"]) || !e["verb"].is_string() || !e["resource"].is_string() || !is_int(e.get("t")) || !(e["params"].is_object() || e["params"].is_array()) {
        return Err(bad());
    }
    let accs = req.get("accumulators").and_then(Value::as_array).ok_or_else(|| CodedError::range("reserve: accumulators must be an array"))?;
    let expected = req.get("expectedVersion").filter(|v| !v.is_null());
    if let Some(x) = expected {
        if safe_int(x).is_none_or(|n| n < 0) {
            return Err(CodedError::range("reserve: expectedVersion must be a non-negative safe integer"));
        }
    }
    let expires = req.get("expiresAt").filter(|v| !v.is_null());
    if expires.is_some_and(|x| safe_int(x).is_none()) {
        return Err(CodedError::range("reserve: expiresAt must be a safe integer"));
    }
    let events = doc["events"].as_array().cloned().unwrap_or_default();
    if let Some(prior) = events.iter().find(|x| x["id"] == e["id"]) {
        return Ok(if same_event(prior, e) {
            json!({"outcome": "replayed", "version": ver_of(doc), "status": prior.get("status")})
        } else {
            json!({"outcome": "id_conflict", "version": ver_of(doc)})
        });
    }
    if let Some(x) = expected {
        if safe_int(x) != safe_int(&doc["ver"]) {
            return Ok(json!({"outcome": "conflict", "version": ver_of(doc)}));
        }
    }
    let schema = req.get("schema").filter(|s| !s.is_null());
    let (verb, t) = (e["verb"].as_str().unwrap_or(""), e.get("t"));
    let empty = Map::new();
    let params = e["params"].as_object().unwrap_or(&empty);
    let mut post = Map::new();
    for a in accs {
        let a = a.as_object().ok_or_else(|| generic("accumulator is not an object"))?;
        let Some(cap) = a.get("domain_max").filter(|c| !c.is_null()) else {
            return Err(CodedError::range(format!(
                "reserve: accumulator {} has no domain_max (the cap)",
                a.get("id").map_or("None".to_string(), crate::intent_v2::js_value_string)
            )));
        };
        if !crate::intent_acc::acc_selects(a, verb, schema).map_err(generic)? {
            continue;
        }
        let p = crate::intent_history::acc_post(a, &events, verb, params, t, schema)
            .map_err(|m| CodedError::new("store_corrupt", if m.is_empty() { "unreadable history" } else { &m }))?;
        if !cap.as_f64().is_some_and(|c| (p as f64).is_finite() && (p as f64) <= c) {
            return Ok(json!({"outcome": "over_cap", "version": ver_of(doc), "acc": a.get("id"), "post": p, "cap": cap}));
        }
        post.insert(a.get("id").map_or(String::new(), crate::intent_v2::js_value_string), json!(p));
    }
    let mut entry = json!({"id": e["id"], "verb": e["verb"], "resource": e["resource"], "params": e["params"], "t": e["t"], "status": "reserved"});
    if let Some(x) = expires {
        entry["exp"] = x.clone();
    }
    doc["events"].as_array_mut().expect("decoded doc").push(entry);
    bump(doc);
    Ok(json!({"outcome": "reserved", "version": ver_of(doc), "post": post}))
}

fn find_mut<'a>(doc: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    doc["events"].as_array_mut()?.iter_mut().find(|x| x["id"].as_str() == Some(id))
}

fn start_in_doc(doc: &mut Value, id: &str) -> Value {
    let ver = ver_of(doc);
    let Some(e) = find_mut(doc, id) else { return json!({"outcome": "unknown", "version": ver}) };
    if e["status"] == "released" {
        return json!({"outcome": "refused", "version": ver, "status": e["status"]});
    }
    if e.get("started").is_some_and(|s| s == &json!(true)) || e["status"] == "committed" {
        return json!({"outcome": "replayed", "version": ver});
    }
    e["started"] = json!(true);
    bump(doc);
    json!({"outcome": "settled", "version": ver_of(doc)})
}

fn commit_in_doc(doc: &mut Value, id: &str) -> Value {
    let ver = ver_of(doc);
    let Some(e) = find_mut(doc, id) else { return json!({"outcome": "unknown", "version": ver}) };
    if e["status"] == "committed" {
        return json!({"outcome": "replayed", "version": ver});
    }
    if e["status"] != "reserved" {
        return json!({"outcome": "refused", "version": ver, "status": e["status"]});
    }
    e["status"] = json!("committed");
    bump(doc);
    json!({"outcome": "settled", "version": ver_of(doc)})
}

fn release_in_doc(doc: &mut Value, key: &str, id: &str, evidence: Option<&Value>) -> R<Value> {
    let ver = ver_of(doc);
    let Some(e) = find_mut(doc, id) else { return Ok(json!({"outcome": "unknown", "version": ver})) };
    if e["status"] == "released" {
        return Ok(json!({"outcome": "replayed", "version": ver}));
    }
    if e["status"] != "reserved" {
        return Ok(json!({"outcome": "refused", "version": ver, "status": e["status"]}));
    }
    if let Some(ev) = evidence {
        if ev.get("key").and_then(Value::as_str) != Some(key) || ev.get("id").and_then(Value::as_str) != Some(id) {
            return Err(CodedError::range("release: the evidence is for another reservation"));
        }
    }
    e["status"] = json!("released");
    if let Some(ev) = evidence.filter(|x| x.as_object().is_some_and(|o| !o.is_empty())) {
        e["rel"] = ev.clone();
    }
    bump(doc);
    Ok(json!({"outcome": "settled", "version": ver_of(doc)}))
}

fn expire_in_doc(doc: &mut Value, now: &Value) -> R<Value> {
    let Some(n) = safe_int(now) else { return Err(CodedError::range("expire: now must be a safe integer")) };
    let mut released = Vec::new();
    for e in doc["events"].as_array_mut().into_iter().flatten() {
        let exp = e.get("exp").and_then(Value::as_f64);
        if e["status"] == "reserved" && !e.get("started").is_some_and(|s| s == &json!(true)) && exp.is_some_and(|x| x <= n as f64) {
            e["status"] = json!("released");
            e["rel"] = json!({"reason": "expired", "at": n});
            released.push(e["id"].clone());
        }
    }
    if !released.is_empty() {
        bump(doc);
    }
    Ok(json!({"released": released, "version": ver_of(doc)}))
}

/// The reference budget ledger: one document per key in an atomic key-value store, so every operation is one atomic read-modify-write.
/// `durable` is declared by the caller (a kv cannot tell): true only for a persistent one.
pub struct KvBudgetLedger {
    kv: Arc<dyn AtomicKv>,
    pub durable: bool,
}

impl KvBudgetLedger {
    pub fn new(kv: Arc<dyn AtomicKv>, durable: bool) -> Self {
        KvBudgetLedger { kv, durable }
    }

    fn k(&self, key: &str) -> R<String> {
        if !id_ok(&json!(key)) {
            return Err(CodedError::range("a ledger key is a non-empty string without control characters"));
        }
        Ok(format!("{BUDGET_PREFIX}{key}"))
    }

    fn txn(&self, key: &str, f: &dyn Fn(&mut Value) -> R<Value>, writes: &dyn Fn(&Value) -> bool) -> R<Value> {
        let k = self.k(key)?;
        let mut out: Option<R<Value>> = None;
        self.kv
            .update(&k, &mut |prev| match decode_doc(prev).and_then(|mut d| f(&mut d).map(|r| (d, r))) {
                Ok((d, r)) => {
                    let w = writes(&r);
                    out = Some(Ok(r));
                    w.then_some(d)
                }
                Err(e) => {
                    out = Some(Err(e));
                    None
                }
            })
            .map_err(kv_err)?;
        out.unwrap_or_else(|| Err(CodedError::new("store_unavailable", "the store did not run the update")))
    }

    pub fn snapshot(&self, key: &str) -> R<Value> {
        let k = self.k(key)?;
        let d = decode_doc(self.kv.get(&k).map_err(kv_err)?.as_ref())?;
        Ok(json!({"version": d["ver"], "events": d["events"]}))
    }

    pub fn reserve(&self, key: &str, req: &Value) -> R<Value> {
        self.txn(key, &|d| reserve_in_doc(d, req), &|r| r["outcome"] == "reserved")
    }

    pub fn start(&self, key: &str, id: &str) -> R<Value> {
        self.txn(key, &|d| Ok(start_in_doc(d, id)), &|r| r["outcome"] == "settled")
    }

    pub fn commit(&self, key: &str, id: &str) -> R<Value> {
        self.txn(key, &|d| Ok(commit_in_doc(d, id)), &|r| r["outcome"] == "settled")
    }

    pub fn release(&self, key: &str, id: &str, evidence: Option<&Value>) -> R<Value> {
        let ev = evidence.filter(|e| !e.is_null());
        self.txn(key, &|d| release_in_doc(d, key, id, ev), &|r| r["outcome"] == "settled")
    }

    pub fn expire(&self, key: &str, now: &Value) -> R<Value> {
        self.txn(key, &|d| expire_in_doc(d, now), &|r| r["released"].as_array().is_some_and(|l| !l.is_empty()))
    }
}

// ---- signed, anchored releases -----------------------------------------------------------------------------------------

fn release_message(r: &Value) -> Result<Vec<u8>, String> {
    let mut body = Map::new();
    for k in ["v", "key", "id", "reason", "at", "signer"] {
        body.insert(k.into(), r.get(k).cloned().unwrap_or(Value::Null));
    }
    let mut m = RELEASE_DOMAIN.as_bytes().to_vec();
    m.extend(canonical_bytes_strict(&Value::Object(body))?);
    Ok(m)
}

/// A signed statement by the releaser that a reservation's effect did NOT happen (`reason`: effect_failed, effect_not_run,
/// denied_downstream or rollback).
pub fn sign_release(key: &Value, id: &Value, reason: &Value, at: &Value, secret: &KeyPair) -> R<Value> {
    let bad = || CodedError::range("signRelease: a malformed release");
    if !reason.as_str().is_some_and(|r| RELEASE_REASONS.contains(&r)) || safe_int(at).is_none() || !id_ok(key) || !id_ok(id) {
        return Err(bad());
    }
    let base = json!({"v": 1, "key": key, "id": id, "reason": reason, "at": at, "signer": secret.public});
    let sig = b64_encode(&secret.sign(&release_message(&base).map_err(|e| CodedError::new("Error", e))?));
    let mut out = base;
    out["sig"] = json!(sig);
    Ok(out)
}

/// True iff `r` is well formed and signed by `expected_signer` over exactly its content. Never fails.
pub fn verify_release(r: &Value, expected_signer: &Value) -> bool {
    let (Some(signer), Some(sig)) = (expected_signer.as_str(), r.get("sig").and_then(Value::as_str)) else { return false };
    if r.get("v").and_then(Value::as_f64) != Some(1.0)
        || r.get("signer").and_then(Value::as_str) != Some(signer)
        || !r.get("reason").and_then(Value::as_str).is_some_and(|x| RELEASE_REASONS.contains(&x))
        || !is_int(r.get("at"))
        || !r.get("key").is_some_and(id_ok)
        || !r.get("id").is_some_and(id_ok)
        || decode_b64u_strict(sig, Some(64)).is_none()
    {
        return false;
    }
    release_message(r).is_ok_and(|m| verify_b64u(signer, &m, sig))
}

pub fn release_digest(r: &Value) -> String {
    hash_canonical(&json!({"d": "atlas-pca/budget-release-ref/v1", "r": r}))
}

/// The log leaf of a release.
pub fn release_commit(r: &Value) -> String {
    hash_canonical(&json!({"d": "atlas-pca/budget-release-leaf/v1", "digest": release_digest(r)}))
}

/// Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index.
pub fn anchor_release(log: &dyn LedgerStore, r: &Value) -> R<i64> {
    let commit = release_commit(r);
    for _ in 0..64 {
        let size = log.size()?;
        let o = log.append(&json!(size), &json!([commit]))?;
        if matches!(o["outcome"].as_str(), Some("appended" | "replayed")) {
            return Ok(size);
        }
    }
    Err(CodedError::new("conflict_exhausted", "could not anchor the release: the log kept moving"))
}

// ---- scoped admission --------------------------------------------------------------------------------------------------

/// The ledger key of an accumulator for this admission, or `None` when it is session-scoped. Errs `scope_unbound`.
pub fn aggregate_key_of(a: &Value, ids: &Value) -> R<Option<String>> {
    let Some(scope) = a.get("scope").and_then(Value::as_str).filter(|s| *s != "session") else { return Ok(None) };
    let aid = a.get("id").map_or("None".to_string(), crate::intent_v2::js_value_string);
    match ids.get(scope).filter(|i| !i.is_null()) {
        None => Err(CodedError::new("scope_unbound", format!("accumulator {aid} is {scope}-scoped but no {scope} id was given"))),
        Some(i) => scope_key(scope, i).map(Some),
    }
}

fn context_state(accs: &[Value], history: &[Value], cand: &Value, schema: Option<&Value>) -> R<Map<String, Value>> {
    let mut state = Map::new();
    let empty = Map::new();
    let params = cand["params"].as_object().unwrap_or(&empty);
    for a in accs {
        if a["holder"]["kind"] != "site_local" {
            continue;
        }
        let m = a.as_object().ok_or_else(|| generic("accumulator is not an object"))?;
        if m.get("key").is_some_and(|k| !k.is_null()) && crate::intent_history::acc_key_of(m, params).is_none() {
            continue; // the verifier fails the claim (missing key)
        }
        let id = m.get("id").map_or(String::new(), crate::intent_v2::js_value_string);
        state.insert(id, crate::intent_history::acc_pre_state(m, history, params, cand.get("t"), schema).map_err(generic)?);
    }
    Ok(state)
}

/// Admit one action against every non-session accumulator of the root, atomically per key: read each key's snapshot and compute the
/// pre-states, `verify(state)` (the host's verifier; returns an object with `allow`), then on allow `reserve` in every key with the
/// snapshot's version. A moved key repeats from the start; a key over its cap denies and releases what the earlier keys reserved. Errs
/// `not_durable` for a ledger that is not durable. Returns `{admitted: true, verdict, reservations, state}` or `{admitted: false,
/// reason, verdict?}`.
pub fn admit_aggregate_action(
    ledger: &KvBudgetLedger,
    ids: &Value,
    accumulators: &[Value],
    schema: Option<&Value>,
    event: &Value,
    verify: &dyn Fn(&Value) -> Value,
    expires_at: Option<i64>,
    max_attempts: Option<usize>,
) -> R<Value> {
    let scoped: Vec<&Value> = accumulators.iter().filter(|a| a.get("scope").is_some_and(|s| !s.is_null() && s.as_str() != Some("session"))).collect();
    if !scoped.is_empty() && !ledger.durable {
        return Err(CodedError::new("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)"));
    }
    let mut by_key: Vec<(String, Vec<Value>)> = Vec::new();
    for a in scoped {
        match aggregate_key_of(a, ids) {
            Ok(Some(k)) => match by_key.iter_mut().find(|(x, _)| *x == k) {
                Some((_, l)) => l.push(a.clone()),
                None => by_key.push((k, vec![a.clone()])),
            },
            Ok(None) => {}
            Err(e) if e.code == "scope_unbound" => return Ok(json!({"admitted": false, "reason": format!("scope_unbound: {e}")})),
            Err(e) => return Err(e),
        }
    }
    by_key.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    for _ in 0..max_attempts.unwrap_or(256) {
        let mut snaps: Vec<Value> = Vec::new();
        let mut state = Map::new();
        for (k, accs) in &by_key {
            let s = ledger.snapshot(k)?;
            let events = s["events"].as_array().cloned().unwrap_or_default();
            state.extend(context_state(accs, &events, event, schema)?);
            snaps.push(s);
        }
        let state_v = Value::Object(state);
        let verdict = verify(&state_v);
        if !verdict["allow"].as_bool().unwrap_or(false) {
            return Ok(json!({"admitted": false, "reason": "verifier denied", "verdict": verdict}));
        }
        let mut done: Vec<Value> = Vec::new();
        let mut moved = false;
        for (i, (k, accs)) in by_key.iter().enumerate() {
            let mut req = json!({"event": event, "accumulators": accs, "expectedVersion": snaps[i]["version"]});
            if let Some(s) = schema {
                req["schema"] = s.clone();
            }
            if let Some(x) = expires_at {
                req["expiresAt"] = json!(x);
            }
            let r = ledger.reserve(k, &req)?;
            if r["outcome"] == "reserved" || (r["outcome"] == "replayed" && r["status"] == "reserved") {
                done.push(json!({"key": k, "id": event["id"]}));
                continue;
            }
            for d in &done {
                ledger.release(d["key"].as_str().unwrap_or(""), d["id"].as_str().unwrap_or(""), None)?;
            }
            if r["outcome"] == "conflict" {
                moved = true;
                break;
            }
            let js = crate::intent_v2::js_value_string;
            let why = match r["outcome"].as_str() {
                Some("over_cap") => format!("over_cap: {} would reach {} (cap {})", js(&r["acc"]), js(&r["post"]), js(&r["cap"])),
                Some("replayed") => format!("already {}", js(&r["status"])),
                other => other.unwrap_or("").to_string(),
            };
            return Ok(json!({"admitted": false, "reason": format!("aggregate: {why}"), "verdict": verdict}));
        }
        if !moved {
            return Ok(json!({"admitted": true, "verdict": verdict, "reservations": done, "state": state_v}));
        }
    }
    Err(CodedError::new("conflict_exhausted", "the aggregate kept moving under this admission"))
}

/// BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (released or expired in the
/// meantime): the effect must NOT run then.
pub fn start_aggregate(ledger: &KvBudgetLedger, reservations: &[Value]) -> R<bool> {
    for r in reservations {
        let o = ledger.start(r["key"].as_str().unwrap_or(""), r["id"].as_str().unwrap_or(""))?;
        if !matches!(o["outcome"].as_str(), Some("settled" | "replayed")) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// After the effect: `committed` (it happened) or `released` (it did not; a signed `evidence` is stored and can be anchored).
pub fn settle_aggregate(ledger: &KvBudgetLedger, reservations: &[Value], status: &str, evidence: Option<&dyn Fn(&Value) -> Option<Value>>) -> R<Vec<Value>> {
    let mut out = Vec::new();
    for r in reservations {
        let (k, id) = (r["key"].as_str().unwrap_or(""), r["id"].as_str().unwrap_or(""));
        out.push(if status == "committed" { ledger.commit(k, id)? } else { ledger.release(k, id, evidence.and_then(|f| f(r)).as_ref())? });
    }
    Ok(out)
}

impl crate::undo_coordinator::UndoBudgetLedger for KvBudgetLedger {
    fn commit(&self, key: &str, id: &str) -> Result<String, String> {
        KvBudgetLedger::commit(self, key, id).map(|o| o["outcome"].as_str().unwrap_or("").to_string()).map_err(|e| e.to_string())
    }

    fn release(&self, key: &str, id: &str, evidence: Option<Value>) -> Result<String, String> {
        KvBudgetLedger::release(self, key, id, evidence.as_ref()).map(|o| o["outcome"].as_str().unwrap_or("").to_string()).map_err(|e| e.to_string())
    }
}
