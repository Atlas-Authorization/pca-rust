//! `durable_pca_state_store`: the replay / budget / pin [`StateStore`] over any [`AtomicKv`] (the reference `durablePcaStateStore`).
//!
//! One JSON document per counter stream under `<prefix><key>` holds `{lastCounter, budget?, lastEpoch?, lastBeaconSeq?}`; every claim is ONE
//! `AtomicKv::update`, so it is correct across every process that shares the backend (a crash-safe `DurableState` on one host, SQLite, ...).

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::kv::AtomicKv;
use crate::{BudgetClaim, ClaimResult, StateStore, StoreError, StoreScope};

/// [`StateStore`] over an atomic key/value store. `prefix` (default `pca-state:`) namespaces the keys; `scope` defaults to `Shared`.
pub struct DurablePcaStateStore {
    kv: Arc<dyn AtomicKv>,
    prefix: String,
    scope: StoreScope,
}

/// The reference `durablePcaStateStore(kv)`.
pub fn durable_pca_state_store(kv: Arc<dyn AtomicKv>) -> DurablePcaStateStore {
    DurablePcaStateStore { kv, prefix: "pca-state:".to_string(), scope: StoreScope::Shared }
}

impl DurablePcaStateStore {
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn with_scope(mut self, scope: StoreScope) -> Self {
        self.scope = scope;
        self
    }

    fn key(&self, k: &str) -> String {
        format!("{}{k}", self.prefix)
    }

    fn doc(&self, k: &str) -> Result<Option<Map<String, Value>>, StoreError> {
        Ok(self.kv.get(&self.key(k))?.and_then(|v| v.as_object().cloned()))
    }
}

/// Two budgets are the same when B, tau and asOf are equal; an absent budget equals only an absent one.
fn same_budget(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => ["B", "tau", "asOf"].iter().all(|k| a.get(*k).and_then(Value::as_f64) == b.get(*k).and_then(Value::as_f64)),
        (None, None) => true,
        _ => false,
    }
}

fn last_counter(cur: Option<&Map<String, Value>>) -> Option<u64> {
    cur.and_then(|m| m.get("lastCounter")).and_then(Value::as_u64)
}

impl StateStore for DurablePcaStateStore {
    fn scope(&self) -> StoreScope {
        self.scope
    }

    fn supports_pins(&self) -> bool {
        true
    }

    fn pin(&self, key: &str) -> Result<Option<i64>, StoreError> {
        Ok(self.doc(key)?.and_then(|m| m.get("lastEpoch").and_then(Value::as_i64)))
    }

    /// Atomically raise the monotone pin; it never lowers, whatever races.
    fn raise_pin(&self, key: &str, value: i64) -> Result<(), StoreError> {
        self.kv.update(&self.key(key), &mut |prev| {
            let cur = prev.and_then(|v| v.as_object().cloned());
            if cur.as_ref().and_then(|m| m.get("lastEpoch")).and_then(Value::as_i64).is_some_and(|p| p >= value) {
                return None;
            }
            let mut m = cur.unwrap_or_default();
            m.insert("lastEpoch".into(), json!(value));
            Some(Value::Object(m))
        })?;
        Ok(())
    }

    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        Ok(self.doc(key)?.and_then(|m| m.get("budget").cloned()))
    }

    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let mut result = ClaimResult::replay(None);
        self.kv.update(&self.key(key), &mut |prev| {
            let cur = prev.and_then(|v| v.as_object().cloned());
            if let Some(seen) = last_counter(cur.as_ref()) {
                if counter <= seen {
                    result = ClaimResult::replay(Some(seen));
                    return None;
                }
            }
            let mut m = cur.unwrap_or_default();
            m.insert("lastCounter".into(), json!(counter));
            result = ClaimResult::claimed();
            Some(Value::Object(m))
        })?;
        Ok(result)
    }

    /// One compare-and-set: replay when the stored counter is >= `counter`; conflict when the stored budget differs from `before`;
    /// else store the counter and `after` (or keep the stored budget).
    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        let mut result = BudgetClaim::Conflict;
        self.kv.update(&self.key(key), &mut |prev| {
            let cur = prev.and_then(|v| v.as_object().cloned());
            if let Some(seen) = last_counter(cur.as_ref()) {
                if counter <= seen {
                    result = BudgetClaim::Replay(Some(seen));
                    return None;
                }
            }
            if !same_budget(cur.as_ref().and_then(|m| m.get("budget")), before) {
                result = BudgetClaim::Conflict;
                return None;
            }
            let mut m = cur.unwrap_or_default();
            if let Some(a) = after {
                m.insert("budget".into(), a.clone());
            }
            m.insert("lastCounter".into(), json!(counter));
            result = BudgetClaim::Claimed;
            Some(Value::Object(m))
        })?;
        Ok(result)
    }

    fn last(&self, key: &str) -> Option<Option<u64>> {
        self.doc(key).ok().map(|m| last_counter(m.as_ref()))
    }

    fn consume_once(&self, key: &str, retain_until_ms: i64, now_ms: i64) -> Result<bool, StoreError> {
        crate::authorize::consume_once_args(key, retain_until_ms, now_ms)?;
        let mut first = false;
        self.kv.update(&self.key(&format!("once:{key}")), &mut |prev| {
            let until = prev.and_then(|v| v.get("until").and_then(Value::as_i64));
            first = until.map_or(true, |u| u < now_ms);
            first.then(|| json!({"until": retain_until_ms}))
        })?;
        Ok(first)
    }
}
