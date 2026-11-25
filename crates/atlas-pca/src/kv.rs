//! A tiny atomic key/value seam shared by the operation-record store and the plan registry. One `update` is atomic across
//! every thread (and, for a durable backend such as `SqliteAtomicKv`, every process) sharing the store.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::authorize::StoreError;

/// Atomic key/value storage of JSON documents. A call that cannot decide MUST return an error; callers then fail closed.
pub trait AtomicKv: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError>;

    /// Atomically compute the next value from the current one: `f(current)` returns `Some(next)` to store it or `None` to
    /// leave the key unchanged. Returns the value stored under `key` afterwards.
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError>;

    /// Every value whose key starts with `prefix`, or `None` when the backend cannot enumerate.
    fn list(&self, _prefix: &str) -> Result<Option<Vec<Value>>, StoreError> {
        Ok(None)
    }
}

/// In-process {@link AtomicKv} (one mutex): correct for ONE process; its documents die with it.
#[derive(Debug, Default)]
pub struct MemoryAtomicKv {
    m: Mutex<BTreeMap<String, Value>>,
}

impl MemoryAtomicKv {
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned() -> StoreError {
    StoreError("the memory store lock is poisoned".into())
}

impl AtomicKv for MemoryAtomicKv {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        Ok(self.m.lock().map_err(|_| poisoned())?.get(key).cloned())
    }

    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        let mut m = self.m.lock().map_err(|_| poisoned())?;
        let next = f(m.get(key));
        if let Some(n) = next {
            m.insert(key.to_string(), n);
        }
        Ok(m.get(key).cloned())
    }

    fn list(&self, prefix: &str) -> Result<Option<Vec<Value>>, StoreError> {
        let m = self.m.lock().map_err(|_| poisoned())?;
        Ok(Some(m.iter().filter(|(k, _)| k.starts_with(prefix)).map(|(_, v)| v.clone()).collect()))
    }
}
