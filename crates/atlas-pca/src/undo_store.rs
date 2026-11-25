//! The persistence contract of the undo ledger and its two reference stores (the reference `UndoStore`, `KvUndoStore`,
//! `MemoryUndoStore`, `withReceipt`, `UndoError`). Records are the JSON documents of [`crate::undo`].

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::agent::KeyPair;
use crate::kv::AtomicKv;
use crate::undo::{sign_undo_receipt, undo_id_ok, undo_receipt_digest, UNDO_STATES};

/// The failure classes of the undo ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoErrorCode {
    NotDurable,
    StoreMissing,
    StoreCorrupt,
    Invalid,
    ConflictExhausted,
    SignerMissing,
    Config,
}

impl UndoErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotDurable => "not_durable",
            Self::StoreMissing => "store_missing",
            Self::StoreCorrupt => "store_corrupt",
            Self::Invalid => "invalid",
            Self::ConflictExhausted => "conflict_exhausted",
            Self::SignerMissing => "signer_missing",
            Self::Config => "config",
        }
    }
}

/// An undo-ledger error; `message` is the full text `"<code>: <detail>"` as the reference formats it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoError {
    pub code: UndoErrorCode,
    pub message: String,
}

impl UndoError {
    pub fn new(code: UndoErrorCode, detail: impl AsRef<str>) -> Self {
        UndoError { code, message: format!("{}: {}", code.as_str(), detail.as_ref()) }
    }
}

impl fmt::Display for UndoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UndoError {}

/// Append the signed receipt of an applied transition (linked to the previous one by digest).
pub fn with_receipt(rec: &Value, event: &str, note: &str, at: i64, key: &KeyPair) -> Result<Value, String> {
    let empty = Vec::new();
    let receipts = rec.get("receipts").and_then(Value::as_array).unwrap_or(&empty);
    let prev = match receipts.last() {
        Some(last) => undo_receipt_digest(last).ok_or("with_receipt: the previous receipt is outside the strict JSON profile")?,
        None => String::new(),
    };
    let body = json!({"record": rec.get("id").cloned().unwrap_or(Value::Null), "event": event, "state": rec.get("state").cloned().unwrap_or(Value::Null), "at": at,
        "compensation_digest": rec.get("compensation_digest").cloned().unwrap_or(Value::Null), "prev": prev, "note": note});
    let receipt = sign_undo_receipt(&body, key)?;
    let mut next = rec.clone();
    if let Some(a) = next.get_mut("receipts").and_then(Value::as_array_mut) {
        a.push(receipt);
    } else {
        next["receipts"] = json!([receipt]);
    }
    Ok(next)
}

/// A store query: records in `state` (and, when set, whose window ended at or before `window_ended_by`, of one grant, of one bond).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UndoQuery {
    pub state: String,
    /// Only records whose window ended at or before this time (the finalize sweep).
    pub window_ended_by: Option<i64>,
    pub grant_ref: Option<String>,
    pub bond_ref: Option<String>,
    pub limit: Option<usize>,
}

/// What [`UndoStore::create`] returns.
#[derive(Debug, Clone, PartialEq)]
pub enum UndoCreate {
    Created,
    /// A record with this id exists: it is returned unchanged.
    Exists(Value),
}

/// The persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and a version column:
/// `UPDATE ... WHERE id = $1 AND ver = $2`) or use [`KvUndoStore`].
pub trait UndoStore: Send + Sync {
    /// True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so.
    fn durable(&self) -> bool;
    fn get(&self, id: &str) -> Result<Option<Value>, UndoError>;
    /// Atomically insert if no record with this id exists; otherwise return the stored one unchanged.
    fn create(&self, rec: &Value) -> Result<UndoCreate, UndoError>;
    /// Atomically replace the record iff its stored `ver` is `expected_ver`.
    fn replace(&self, id: &str, expected_ver: i64, next: &Value) -> Result<bool, UndoError>;
    fn list(&self, q: &UndoQuery) -> Result<Vec<Value>, UndoError>;
}

fn ver_of(r: &Value) -> Option<i64> {
    crate::safe_int(r.get("ver")?)
}

fn matches(r: &Value, q: &UndoQuery) -> bool {
    r.get("state").and_then(Value::as_str) == Some(q.state.as_str())
        && q.window_ended_by.map_or(true, |t| r.get("window_end").and_then(Value::as_f64).is_some_and(|w| w <= t as f64))
        && q.grant_ref.as_deref().map_or(true, |g| r.get("grant_ref").and_then(Value::as_str) == Some(g))
        && q.bond_ref.as_deref().map_or(true, |b| r.get("bond_ref").and_then(Value::as_str) == Some(b))
}

fn decode_record(raw: Option<&Value>) -> Result<Option<Value>, UndoError> {
    let Some(raw) = raw else { return Ok(None) };
    let ok = raw.is_object()
        && raw.get("v").and_then(Value::as_f64) == Some(1.0)
        && undo_id_ok(raw.get("id"))
        && raw.get("state").and_then(Value::as_str).is_some_and(|s| UNDO_STATES.contains(&s))
        && ver_of(raw).is_some()
        && raw.get("receipts").is_some_and(Value::is_array);
    if ok {
        Ok(Some(raw.clone()))
    } else {
        Err(UndoError::new(UndoErrorCode::StoreCorrupt, "an undo record has the wrong shape"))
    }
}

fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn id_of(r: &Value) -> &str {
    r.get("id").and_then(Value::as_str).unwrap_or("")
}

fn finish_list(mut out: Vec<Value>, q: &UndoQuery) -> Vec<Value> {
    out.sort_by(|a, b| utf16_order(id_of(a), id_of(b)));
    if let Some(l) = q.limit {
        out.truncate(l);
    }
    out
}

const PREFIX: &str = "pca-undo/v1/";

/// The reference [`UndoStore`] over any [`AtomicKv`] that can enumerate (one document per record, every write one atomic
/// read-modify-write). `durable` is declared by the caller because a key/value store cannot tell: true only over a persistent one
/// (`DurableState`), false over an in-memory one.
// shortcut: `list` scans every record (fine for one host's backlog); a database store indexes (state, window_end).
pub struct KvUndoStore {
    kv: Arc<dyn AtomicKv>,
    durable: bool,
}

impl KvUndoStore {
    pub fn new(kv: Arc<dyn AtomicKv>, durable: bool) -> Self {
        KvUndoStore { kv, durable }
    }

    fn key(id: &str) -> Result<String, UndoError> {
        if !undo_id_ok(Some(&Value::String(id.to_string()))) {
            return Err(UndoError::new(UndoErrorCode::Invalid, "an undo record id is a non-empty string without control characters"));
        }
        Ok(format!("{PREFIX}{id}"))
    }
}

fn kv_err(e: crate::StoreError) -> UndoError {
    UndoError::new(UndoErrorCode::StoreCorrupt, e.0)
}

impl UndoStore for KvUndoStore {
    fn durable(&self) -> bool {
        self.durable
    }

    fn get(&self, id: &str) -> Result<Option<Value>, UndoError> {
        decode_record(self.kv.get(&Self::key(id)?).map_err(kv_err)?.as_ref())
    }

    fn create(&self, rec: &Value) -> Result<UndoCreate, UndoError> {
        let key = Self::key(rec.get("id").and_then(Value::as_str).unwrap_or(""))?;
        let mut existing: Result<Option<Value>, UndoError> = Ok(None);
        self.kv
            .update(&key, &mut |prev| {
                existing = decode_record(prev);
                match &existing {
                    Ok(None) => Some(rec.clone()),
                    _ => None,
                }
            })
            .map_err(kv_err)?;
        Ok(match existing? {
            Some(r) => UndoCreate::Exists(r),
            None => UndoCreate::Created,
        })
    }

    fn replace(&self, id: &str, expected_ver: i64, next: &Value) -> Result<bool, UndoError> {
        if next.get("id").and_then(Value::as_str) != Some(id) {
            return Err(UndoError::new(UndoErrorCode::Invalid, "replace: the record id cannot change"));
        }
        let key = Self::key(id)?;
        let mut done: Result<bool, UndoError> = Ok(false);
        self.kv
            .update(&key, &mut |prev| {
                done = decode_record(prev).map(|cur| cur.as_ref().and_then(ver_of) == Some(expected_ver));
                matches!(done, Ok(true)).then(|| next.clone())
            })
            .map_err(kv_err)?;
        done
    }

    fn list(&self, q: &UndoQuery) -> Result<Vec<Value>, UndoError> {
        let docs = self
            .kv
            .list(PREFIX)
            .map_err(kv_err)?
            .ok_or_else(|| UndoError::new(UndoErrorCode::StoreMissing, "the key/value store cannot enumerate its records"))?;
        let mut out = Vec::new();
        for d in &docs {
            if let Some(r) = decode_record(Some(d))? {
                if matches(&r, q) {
                    out.push(r);
                }
            }
        }
        Ok(finish_list(out, q))
    }
}

/// A process-memory [`UndoStore`]: `durable` is false, so the coordinator refuses it unless the caller says, for a test, that it accepts
/// losing every open window on restart. Never use it in production.
#[derive(Default)]
pub struct MemoryUndoStore {
    m: Mutex<HashMap<String, Value>>,
}

impl MemoryUndoStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Value>> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl UndoStore for MemoryUndoStore {
    fn durable(&self) -> bool {
        false
    }

    fn get(&self, id: &str) -> Result<Option<Value>, UndoError> {
        Ok(self.lock().get(id).cloned())
    }

    fn create(&self, rec: &Value) -> Result<UndoCreate, UndoError> {
        if !undo_id_ok(rec.get("id")) {
            return Err(UndoError::new(UndoErrorCode::Invalid, "an undo record id is a non-empty string without control characters"));
        }
        let id = id_of(rec).to_string();
        let mut m = self.lock();
        if let Some(cur) = m.get(&id) {
            return Ok(UndoCreate::Exists(cur.clone()));
        }
        m.insert(id, rec.clone());
        Ok(UndoCreate::Created)
    }

    fn replace(&self, id: &str, expected_ver: i64, next: &Value) -> Result<bool, UndoError> {
        if next.get("id").and_then(Value::as_str) != Some(id) {
            return Err(UndoError::new(UndoErrorCode::Invalid, "replace: the record id cannot change"));
        }
        let mut m = self.lock();
        if m.get(id).and_then(ver_of) != Some(expected_ver) {
            return Ok(false);
        }
        m.insert(id.to_string(), next.clone());
        Ok(true)
    }

    fn list(&self, q: &UndoQuery) -> Result<Vec<Value>, UndoError> {
        Ok(finish_list(self.lock().values().filter(|r| matches(r, q)).cloned().collect(), q))
    }
}
