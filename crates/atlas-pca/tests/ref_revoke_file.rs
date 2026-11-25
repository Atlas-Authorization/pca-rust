//! `FileRevocationStore`: the same contract as the in-memory store, durable across reopening, and fail closed on a bad file.
use atlas_pca::revoke::{FileRevocationStore, InMemoryRevocationStore, RevocationStore};
use atlas_pca::serde_json::{json, Value};

fn entry(kind: &str, value: &str) -> Value {
    json!({"kind": kind, "value": value, "reason": "r", "revokedAt": 10})
}

fn tmp(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("atlas-pca-revoke-{tag}-{}.json", std::process::id()))
}

#[test]
fn behaves_like_the_in_memory_store_and_survives_reopening() {
    let path = tmp("a");
    let _ = std::fs::remove_file(&path);
    let file = FileRevocationStore::open(&path).unwrap();
    let mem = InMemoryRevocationStore::new();
    let ops: Vec<Value> = vec![entry("cap", "c1"), entry("holder", "h1"), json!({"kind": "cap", "value": "c1", "reason": "again", "revokedAt": 11})];
    for e in &ops {
        file.add(e.clone()).unwrap();
        mem.add(e.clone()).unwrap();
    }
    assert_eq!(file.all().unwrap(), mem.all().unwrap());
    assert_eq!(file.get("cap", "c1").unwrap(), mem.get("cap", "c1").unwrap());
    assert_eq!(file.remove("holder", "nope").unwrap(), mem.remove("holder", "nope").unwrap());
    assert_eq!(file.remove("holder", "h1").unwrap(), mem.remove("holder", "h1").unwrap());
    let reopened = FileRevocationStore::open(&path).unwrap();
    assert_eq!(reopened.all().unwrap(), mem.all().unwrap());
    reopened.clear().unwrap();
    assert!(FileRevocationStore::open(&path).unwrap().all().unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_bad_file_refuses_to_start_empty() {
    for (tag, body) in [
        ("junk", "not json".to_string()),
        ("noentries", "{\"v\":1}".to_string()),
        ("badkind", json!({"entries": [entry("nope", "x")]}).to_string()),
        ("emptyvalue", json!({"entries": [entry("cap", "")]}).to_string()),
        ("nullnb", json!({"entries": [{"kind": "cap", "value": "x", "reason": "r", "revokedAt": 1, "notBefore": null}]}).to_string()),
        ("prefixmismatch", json!({"entries": [{"kind": "prefix", "value": "a,b", "prefix": ["a", "c"], "reason": "r", "revokedAt": 1}]}).to_string()),
    ] {
        let path = tmp(tag);
        std::fs::write(&path, body).unwrap();
        assert!(FileRevocationStore::open(&path).is_err(), "{tag} was accepted");
        let _ = std::fs::remove_file(&path);
    }
    let ok = tmp("prefixok");
    std::fs::write(&ok, json!({"entries": [{"kind": "prefix", "value": "a,b", "prefix": ["a", "b"], "reason": "r", "revokedAt": 1, "notBefore": 5}]}).to_string()).unwrap();
    assert_eq!(FileRevocationStore::open(&ok).unwrap().all().unwrap().len(), 1);
    let _ = std::fs::remove_file(&ok);
}
