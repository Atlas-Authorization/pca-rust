//! Durable approval stores for the CIBA broker (packages/pca-ciba/src/kv-store.ts and the file store of approval.ts): a versioned
//! [`ApprovalStore`] over a tiny durable key-value interface that needs ONE primitive, a compare-and-swap on a string
//! ([`DurableKv::put_if_equals`]), a directory-backed KV safe for several processes on one host, an in-memory KV, and a one-file
//! store for a single process.
use crate::ciba::{ApprovalStore, Versioned};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Raised by the KV reference implementations; the broker treats any error from the store as "no approval".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStoreError {
    /// `corrupt_record`, `lock_timeout` or `bad_key`.
    pub code: &'static str,
    pub message: String,
}

impl ApprovalStoreError {
    fn new(code: &'static str, message: &str) -> Self {
        ApprovalStoreError { code, message: message.into() }
    }
}

impl fmt::Display for ApprovalStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApprovalStoreError {}

/// A durable string key-value store with compare-and-swap. `put_if_equals(key, expected, next)` writes `next` only if the stored
/// value is exactly `expected` (`None`: the key must be absent) and reports whether it wrote. It MUST be atomic across every process
/// sharing the store and durable before it returns. Any failure must be an `Err`: never `Ok(true)` for a write that may be lost.
pub trait DurableKv {
    fn get(&self, key: &str) -> Result<Option<String>, ApprovalStoreError>;
    fn put_if_equals(&self, key: &str, expected: Option<&str>, next: &str) -> Result<bool, ApprovalStoreError>;
}

fn decode(raw: &str) -> Result<Versioned, ApprovalStoreError> {
    let corrupt = |m: &str| ApprovalStoreError::new("corrupt_record", m);
    let v: Value = serde_json::from_str(raw).map_err(|_| corrupt("ciba: stored approval record is not valid JSON"))?;
    let version = v.get("version").and_then(Value::as_u64).filter(|n| *n >= 1);
    match (version, v.get("value")) {
        (Some(version), Some(value)) => Ok(Versioned { version, value: value.clone() }),
        _ => Err(corrupt("ciba: stored approval record has no valid version")),
    }
}

/// An [`ApprovalStore`] over a [`DurableKv`]. Each key holds `{version, value}` as JSON; `cas` re-reads the raw string, checks the
/// version and swaps only if the raw string is still the one it read, so two processes racing on one expected version cannot both win.
pub struct KvApprovalStore<K: DurableKv>(pub K);

/// `createKvApprovalStore`.
pub fn create_kv_approval_store<K: DurableKv>(kv: K) -> KvApprovalStore<K> {
    KvApprovalStore(kv)
}

impl<K: DurableKv> ApprovalStore for KvApprovalStore<K> {
    fn get(&self, key: &str) -> Result<Option<Versioned>, String> {
        match self.0.get(key).map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(raw) => decode(&raw).map(Some).map_err(|e| e.to_string()),
        }
    }

    fn cas(&self, key: &str, expected: u64, value: Value) -> Result<bool, String> {
        let raw = self.0.get(key).map_err(|e| e.to_string())?;
        let current = match &raw {
            None => 0,
            Some(r) => decode(r).map_err(|e| e.to_string())?.version,
        };
        if current != expected {
            return Ok(false);
        }
        let next = json!({"version": expected + 1, "value": value}).to_string();
        self.0.put_if_equals(key, raw.as_deref(), &next).map_err(|e| e.to_string())
    }
}

/// An in-process [`DurableKv`] (tests).
#[derive(Default)]
pub struct MemoryKv(Mutex<HashMap<String, String>>);

/// `createMemoryKv`.
pub fn create_memory_kv() -> MemoryKv {
    MemoryKv::default()
}

impl DurableKv for MemoryKv {
    fn get(&self, key: &str) -> Result<Option<String>, ApprovalStoreError> {
        Ok(self.0.lock().map_err(|_| ApprovalStoreError::new("lock_timeout", "ciba: store poisoned"))?.get(key).cloned())
    }

    fn put_if_equals(&self, key: &str, expected: Option<&str>, next: &str) -> Result<bool, ApprovalStoreError> {
        let mut m = self.0.lock().map_err(|_| ApprovalStoreError::new("lock_timeout", "ciba: store poisoned"))?;
        if m.get(key).map(String::as_str) != expected {
            return Ok(false);
        }
        m.insert(key.into(), next.into());
        Ok(true)
    }
}

/// `createMemoryApprovalStore`: the in-memory KV store, with the version check of the durable one.
pub fn create_memory_approval_store() -> KvApprovalStore<MemoryKv> {
    KvApprovalStore(MemoryKv::default())
}

/// A [`DurableKv`] on a directory, safe for several processes on ONE host (and one filesystem with atomic exclusive-create and
/// rename). One file per key (the key is hashed into the file name, so no key can escape the directory); each swap takes a per-key
/// lock file (exclusive create), compares, writes a temp file, syncs it and renames it over the key. A process that dies holding the
/// lock leaves it behind: every later swap on that key then fails with `lock_timeout` (fail closed) until an operator removes the
/// `.lock` file. For several hosts use a database-backed KV.
pub struct DirectoryKv {
    dir: PathBuf,
    lock_timeout: Duration,
}

/// `createDirectoryKv`. `lock_timeout_ms` defaults to 5000.
pub fn create_directory_kv(dir: &Path, lock_timeout_ms: Option<f64>) -> Result<DirectoryKv, ApprovalStoreError> {
    let t = lock_timeout_ms.unwrap_or(5000.0);
    if !t.is_finite() || t <= 0.0 {
        return Err(ApprovalStoreError::new("bad_key", "createDirectoryKv: lockTimeoutMs must be a positive number"));
    }
    crate::private_file::create_dir_all_private(dir).map_err(|e| ApprovalStoreError::new("lock_timeout", &format!("ciba: cannot create the store directory: {e}")))?;
    Ok(DirectoryKv { dir: dir.into(), lock_timeout: Duration::from_millis(t as u64) })
}

impl DirectoryKv {
    fn file_of(&self, key: &str) -> Result<PathBuf, ApprovalStoreError> {
        if key.is_empty() {
            return Err(ApprovalStoreError::new("bad_key", "ciba: store key must be a non-empty string"));
        }
        Ok(self.dir.join(Sha256::digest(key.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }
}

fn read_opt(f: &Path) -> Result<Option<String>, ApprovalStoreError> {
    match std::fs::read_to_string(f) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ApprovalStoreError::new("corrupt_record", &format!("ciba: cannot read the stored record: {e}"))),
    }
}

impl DurableKv for DirectoryKv {
    fn get(&self, key: &str) -> Result<Option<String>, ApprovalStoreError> {
        read_opt(&self.file_of(key)?)
    }

    fn put_if_equals(&self, key: &str, expected: Option<&str>, next: &str) -> Result<bool, ApprovalStoreError> {
        let f = self.file_of(key)?;
        let lock = PathBuf::from(format!("{}.lock", f.display()));
        let deadline = Instant::now() + self.lock_timeout;
        let guard = loop {
            match crate::private_file::open_private(crate::private_file::Create::New, &lock) {
                Ok(h) => break h,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        return Err(ApprovalStoreError::new("lock_timeout", "ciba: could not take the store lock in time"));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(ApprovalStoreError::new("lock_timeout", &format!("ciba: cannot take the store lock: {e}"))),
            }
        };
        let swap = || -> Result<bool, ApprovalStoreError> {
            if read_opt(&f)?.as_deref() != expected {
                return Ok(false);
            }
            let tmp = PathBuf::from(format!("{}.{}.tmp", f.display(), std::process::id()));
            let io = |e: std::io::Error| ApprovalStoreError::new("corrupt_record", &format!("ciba: cannot write the record: {e}"));
            let mut t = crate::private_file::open_private(crate::private_file::Create::Truncate, &tmp).map_err(io)?;
            t.write_all(next.as_bytes()).map_err(io)?;
            t.sync_all().map_err(io)?; // durable before the rename publishes it
            drop(t);
            crate::durable_rename::replace_file(&tmp, &f).map_err(io)?;
            crate::durable_rename::sync_parent(&f).map_err(io)?;
            Ok(true)
        };
        let out = swap();
        drop(guard);
        let _ = std::fs::remove_file(&lock);
        out
    }
}

/// A one-file [`ApprovalStore`] rewritten atomically (temp file + rename) on each write. Correct for ONE process at a time; use a
/// database store when several processes share the approvals. A corrupt file is an error (fail closed).
pub struct FileApprovalStore {
    path: PathBuf,
}

/// `createFileApprovalStore`.
pub fn create_file_approval_store(path: &Path) -> FileApprovalStore {
    FileApprovalStore { path: path.into() }
}

impl FileApprovalStore {
    fn load(&self) -> Result<serde_json::Map<String, Value>, String> {
        match std::fs::read_to_string(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::Map::new()),
            Err(e) => Err(format!("ciba: cannot read the approval store file: {e}")),
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(Value::Object(m)) => Ok(m),
                _ => Err("ciba: approval store file is corrupt".into()),
            },
        }
    }
}

impl ApprovalStore for FileApprovalStore {
    fn get(&self, key: &str) -> Result<Option<Versioned>, String> {
        match self.load()?.get(key) {
            None => Ok(None),
            Some(v) => match (v.get("version").and_then(Value::as_u64), v.get("value")) {
                (Some(version), Some(value)) => Ok(Some(Versioned { version, value: value.clone() })),
                _ => Err("ciba: approval store file is corrupt".into()),
            },
        }
    }

    fn cas(&self, key: &str, expected: u64, value: Value) -> Result<bool, String> {
        let mut all = self.load()?;
        let current = all.get(key).and_then(|v| v.get("version")).and_then(Value::as_u64).unwrap_or(0);
        if current != expected {
            return Ok(false);
        }
        all.insert(key.into(), json!({"version": expected + 1, "value": value}));
        let tmp = PathBuf::from(format!("{}.{}.tmp", self.path.display(), std::process::id()));
        let io = |e: std::io::Error| format!("ciba: cannot write the approval store file: {e}");
        {
            let mut t = crate::private_file::open_private(crate::private_file::Create::Truncate, &tmp).map_err(io)?;
            t.write_all(Value::Object(all).to_string().as_bytes()).map_err(io)?;
            t.sync_all().map_err(io)?; // durable before the rename publishes it
        }
        crate::durable_rename::replace_file(&tmp, &self.path).map_err(io)?;
        crate::durable_rename::sync_parent(&self.path).map_err(io)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise<S: ApprovalStore>(s: &S) {
        assert!(s.get("a").unwrap().is_none());
        assert!(!s.cas("a", 1, json!(1)).unwrap(), "key must be absent for version 0 only");
        assert!(s.cas("a", 0, json!({"x": 1})).unwrap());
        assert!(!s.cas("a", 0, json!(2)).unwrap(), "a second writer at the same expected version loses");
        assert!(s.cas("a", 1, json!(3)).unwrap());
        let v = s.get("a").unwrap().unwrap();
        assert_eq!((v.version, v.value), (2, json!(3)));
    }

    #[test]
    fn memory_directory_and_file_stores_agree() {
        exercise(&create_memory_approval_store());
        let d = std::env::temp_dir().join(format!("ciba-stores-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        exercise(&create_kv_approval_store(create_directory_kv(&d.join("kv"), None).unwrap()));
        exercise(&create_file_approval_store(&d.join("one.json")));
        // a corrupt record fails closed, and an empty key is refused
        let kv = create_directory_kv(&d.join("kv2"), Some(50.0)).unwrap();
        assert_eq!(kv.get("").unwrap_err().code, "bad_key");
        assert!(kv.put_if_equals("k", None, "not json").unwrap());
        assert!(KvApprovalStore(kv).get("k").is_err());
        std::fs::write(d.join("bad.json"), "[1]").unwrap();
        assert!(create_file_approval_store(&d.join("bad.json")).get("a").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn approval_store_files_and_directories_are_owner_only() {
        let d = std::env::temp_dir().join(format!("ciba-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let kv = create_directory_kv(&d.join("kv"), None).unwrap();
        assert!(kv.put_if_equals("k", None, "{\"a\":1}").unwrap());
        crate::private_file::assert_owner_only(&d.join("kv"));
        crate::private_file::assert_owner_only(&kv.file_of("k").unwrap());
        let one = d.join("one.json");
        let fs = create_file_approval_store(&one);
        assert!(fs.cas("k", 0, json!({"a": 1})).unwrap());
        crate::private_file::assert_owner_only(&one);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_held_lock_times_out_closed() {
        let d = std::env::temp_dir().join(format!("ciba-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let kv = create_directory_kv(&d, Some(30.0)).unwrap();
        let f = kv.file_of("k").unwrap();
        std::fs::write(format!("{}.lock", f.display()), "").unwrap();
        assert_eq!(kv.put_if_equals("k", None, "v").unwrap_err().code, "lock_timeout");
        let _ = std::fs::remove_dir_all(&d);
    }
}
