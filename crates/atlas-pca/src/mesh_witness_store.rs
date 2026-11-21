//! Durable memory for a mesh log witness (packages/pca/src/mesh.ts `MeshWitnessStore` / `MemoryMeshWitnessStore` and
//! durable-mesh-witness.ts `FileMeshWitnessStore`). The witness state is `{seen: [{head, rev_ids}]}` as JSON. A witness that forgets
//! across a restart can be walked back to cosign a fork, so `save` MUST be durable and atomic and `load` never returns a partial state.
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Where a witness keeps what it has cosigned. `load` is `Ok(None)` for a store never written and `Err` on corrupt data.
pub trait MeshWitnessStore {
    fn load(&self) -> Result<Option<Value>, String>;
    fn save(&self, state: &Value) -> Result<(), String>;
}

/// In-process store: a test double, and the default when no store is given. It does not survive a restart.
#[derive(Default)]
pub struct MemoryMeshWitnessStore(Mutex<Option<String>>);

impl MeshWitnessStore for MemoryMeshWitnessStore {
    fn load(&self) -> Result<Option<Value>, String> {
        match &*self.0.lock().map_err(|_| "the witness store is poisoned".to_string())? {
            None => Ok(None),
            Some(s) => serde_json::from_str(s).map(Some).map_err(|e| e.to_string()),
        }
    }

    fn save(&self, state: &Value) -> Result<(), String> {
        *self.0.lock().map_err(|_| "the witness store is poisoned".to_string())? = Some(state.to_string());
        Ok(())
    }
}

/// A file-backed store. Every save writes a temporary file, syncs it, renames it over the real file and syncs the directory, so a crash
/// leaves the old state or the new one, never a torn file. The file carries a digest of its state: one that does not parse, has the wrong
/// shape or fails the digest makes `load` fail (a witness never starts empty over a damaged file). A missing file is a first run.
/// Single process: two witnesses must not share one file.
pub struct FileMeshWitnessStore {
    path: PathBuf,
}

impl FileMeshWitnessStore {
    pub fn new(path: &Path) -> Self {
        FileMeshWitnessStore { path: path.into() }
    }
}

impl MeshWitnessStore for FileMeshWitnessStore {
    fn load(&self) -> Result<Option<Value>, String> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("FileMeshWitnessStore: cannot read the state file: {e}")),
        };
        let doc: Value =
            serde_json::from_str(&text).map_err(|_| "FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty".to_string())?;
        let shaped = doc.get("v") == Some(&json!(1)) && doc.get("digest").is_some_and(Value::is_string) && doc.get("state").is_some_and(Value::is_object);
        if !shaped {
            return Err("FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty".into());
        }
        if doc["digest"].as_str() != Some(crate::hash_canonical(&doc["state"]).as_str()) {
            return Err("FileMeshWitnessStore: the state file fails its digest; refusing to start empty".into());
        }
        Ok(Some(doc["state"].clone()))
    }

    fn save(&self, state: &Value) -> Result<(), String> {
        let io = |e: std::io::Error| format!("FileMeshWitnessStore: cannot save: {e}");
        let body = json!({"v": 1, "state": state, "digest": crate::hash_canonical(state)}).to_string();
        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        let mut f = crate::private_file::open_private(std::fs::OpenOptions::new().write(true).create(true).truncate(true), &tmp).map_err(io)?;
        f.write_all(body.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
        drop(f);
        crate::durable_rename::replace_file(&tmp, &self.path).map_err(io)?;
        // a directory cannot be opened for a flush on Windows; the write-through rename (durable_rename) is the durable step there
        #[cfg(unix)]
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip_and_damage_is_refused() {
        let d = std::env::temp_dir().join(format!("mesh-witness-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let s = FileMeshWitnessStore::new(&d.join("w.json"));
        assert_eq!(s.load().unwrap(), None);
        let st = json!({"seen": [{"head": {"domain": "a"}, "rev_ids": ["r1"]}]});
        s.save(&st).unwrap();
        assert_eq!(s.load().unwrap(), Some(st.clone()));
        std::fs::write(d.join("w.json"), "{not json").unwrap();
        assert!(s.load().is_err());
        std::fs::write(d.join("w.json"), json!({"v": 1, "state": {"seen": []}, "digest": "x"}).to_string()).unwrap();
        assert!(s.load().unwrap_err().contains("digest"));
        std::fs::write(d.join("w.json"), "[]").unwrap();
        assert!(s.load().unwrap_err().contains("shape"));
        crate::private_file::assert_owner_only(&d.join("w.json"));
        let m = MemoryMeshWitnessStore::default();
        assert_eq!(m.load().unwrap(), None);
        m.save(&st).unwrap();
        assert_eq!(m.load().unwrap(), Some(st));
        let _ = std::fs::remove_dir_all(&d);
    }
}
