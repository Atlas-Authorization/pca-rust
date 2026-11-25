//! The session-store half of the intent history: the verifier context of a candidate action ([`acc_context_for`]: pre-states of
//! the site-local accumulators and the monitor states) and atomic admission against a session's accumulators through an
//! [`IntentSessionStore`] ([`admit_intent_action`], then [`settle_intent_event`] after the effect).
//!
//! Linearizability holds iff `with_session` serialises every admission of a session: the pre-state read, the verification and
//! the `reserved` append happen under one lock (a row lock in a database, the mutex of [`MemoryIntentSessionStore`]). Events are
//! JSON values `{id, verb, resource, params, t, status}` with `status` one of `reserved`, `committed`, `released`, `reverted`.

use crate::intent_history::{acc_key_of, acc_pre_state, monitor_state};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

/// The verifier context for a candidate action `cand` (`{params, t}`): `{state: {<accumulator id>: pre-state}, monitors:
/// {<monitor id>: state}}`. An accumulator held elsewhere, or keyed on a parameter the candidate lacks, has no pre-state (the
/// verifier then fails the claim).
pub fn acc_context_for(root: &Value, history: &[Value], cand: &Value, schema: Option<&Value>) -> Result<Value, String> {
    let empty = Map::new();
    let none: Vec<Value> = Vec::new();
    let params = cand.get("params").and_then(Value::as_object).unwrap_or(&empty);
    let list = |k: &str| root.get(k).and_then(Value::as_array).unwrap_or(&none);
    let id = |m: &Map<String, Value>| m.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
    let mut state = Map::new();
    for a in list("accumulators") {
        let am = a.as_object().ok_or("an accumulator declaration is not an object")?;
        if am.get("holder").and_then(|h| h.get("kind")).and_then(Value::as_str) != Some("site_local") {
            continue;
        }
        if am.get("key").is_some_and(|k| !k.is_null()) && acc_key_of(am, params).is_none() {
            continue;
        }
        state.insert(id(am), acc_pre_state(am, history, params, cand.get("t"), schema)?);
    }
    let mut monitors = Map::new();
    for m in list("monitors") {
        let mm = m.as_object().ok_or("a monitor declaration is not an object")?;
        monitors.insert(id(mm), monitor_state(mm, history)?.map_or(Value::Null, Value::String));
    }
    Ok(json!({"state": state, "monitors": monitors}))
}

/// A transaction on ONE session's history, holding its exclusive lock.
pub trait SessionTx {
    /// The session's events in admission order, with their current statuses.
    fn events(&self) -> Result<Vec<Value>, String>;
    fn append(&mut self, event: Value) -> Result<(), String>;
    /// Set the status of event `id`; `false` when the session has no such event.
    fn set_status(&mut self, id: &str, status: &str) -> Result<bool, String>;
}

/// The accumulator state holder. Hosts implement it over their database (a row lock and rows).
pub trait IntentSessionStore {
    /// Run `f` under the exclusive lock of `session`.
    fn with_session(&self, session: &str, f: &mut dyn FnMut(&mut dyn SessionTx) -> Result<Value, String>) -> Result<Value, String>;
    /// `true` when the history survives a restart of the process. A store that does not say so is treated as volatile: after a
    /// restart its accumulators read zero, so a cap would admit again, and [`admit_intent_action`] refuses it by default.
    fn durable(&self) -> bool {
        false
    }
}

/// An in-process store: a test double for single-process sites. Its history does NOT survive a restart, so it is not durable
/// unless the caller says so for a test ([`MemoryIntentSessionStore::claiming_durable`]).
#[derive(Default)]
pub struct MemoryIntentSessionStore {
    events: Mutex<HashMap<String, Vec<Value>>>,
    durable: bool,
}

impl MemoryIntentSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that reports itself durable (tests only: the history is still in memory).
    pub fn claiming_durable() -> Self {
        MemoryIntentSessionStore { events: Mutex::default(), durable: true }
    }

    /// The events recorded for `session` (empty when unknown).
    pub fn events_of(&self, session: &str) -> Vec<Value> {
        self.events.lock().map(|m| m.get(session).cloned().unwrap_or_default()).unwrap_or_default()
    }
}

struct MemoryTx<'a>(&'a mut Vec<Value>);

impl SessionTx for MemoryTx<'_> {
    fn events(&self) -> Result<Vec<Value>, String> {
        Ok(self.0.clone())
    }

    fn append(&mut self, event: Value) -> Result<(), String> {
        self.0.push(event);
        Ok(())
    }

    fn set_status(&mut self, id: &str, status: &str) -> Result<bool, String> {
        match self.0.iter_mut().find(|e| e.get("id").and_then(Value::as_str) == Some(id)) {
            Some(e) => {
                e["status"] = json!(status);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl IntentSessionStore for MemoryIntentSessionStore {
    fn with_session(&self, session: &str, f: &mut dyn FnMut(&mut dyn SessionTx) -> Result<Value, String>) -> Result<Value, String> {
        let mut all = self.events.lock().map_err(|_| "the session store is poisoned".to_string())?;
        f(&mut MemoryTx(all.entry(session.to_string()).or_default()))
    }

    fn durable(&self) -> bool {
        self.durable
    }
}

/// Admit one action atomically against the session's accumulators: under the session lock, compute the pre-states and monitor
/// states from the history, run `verify` with them, and when its verdict has `allow: true` append `event` (`{id, verb, resource,
/// params, t}`) as `reserved`. Returns the verdict. After the effect the host calls [`settle_intent_event`].
///
/// `require_durable` defaults to `true`: a store that is not durable is refused (a restart would reset every cap). Pass
/// `Some(false)` only for tests and single-process sites that accept losing every cap on restart. A `verify` error, like any store
/// error, appends nothing.
pub fn admit_intent_action(
    store: &dyn IntentSessionStore,
    session: &str,
    root: &Value,
    schema: Option<&Value>,
    event: &Value,
    verify: &mut dyn FnMut(&Value) -> Result<Value, String>,
    require_durable: Option<bool>,
) -> Result<Value, String> {
    if require_durable != Some(false) && !store.durable() {
        return Err("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore".into());
    }
    let ev = event.as_object().ok_or("admitIntentAction: the event is not an object")?;
    store.with_session(session, &mut |tx: &mut dyn SessionTx| {
        let history = tx.events()?;
        let acc = acc_context_for(root, &history, event, schema)?;
        let verdict = verify(&acc)?;
        if verdict.get("allow") == Some(&Value::Bool(true)) {
            let mut reserved = ev.clone();
            reserved.insert("status".into(), json!("reserved"));
            tx.append(Value::Object(reserved))?;
        }
        Ok(verdict)
    })
}

/// Settle an admitted event after its effect: `committed`, `released` or `reverted`. `Ok(false)` when the session has no such
/// event.
pub fn settle_intent_event(store: &dyn IntentSessionStore, session: &str, id: &str, status: &str) -> Result<bool, String> {
    if !["committed", "released", "reverted"].contains(&status) {
        return Err(format!("settleIntentEvent: unknown status '{status}'"));
    }
    store.with_session(session, &mut |tx: &mut dyn SessionTx| tx.set_status(id, status).map(Value::Bool)).map(|v| v == Value::Bool(true))
}
