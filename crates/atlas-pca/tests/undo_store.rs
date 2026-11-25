//! The undo ledger stores: the persistence contract over the memory store and the kv store (create-once, versioned replace, query),
//! corrupt documents failing closed, and the receipt chain `with_receipt` builds.

use std::sync::Arc;

use atlas_pca::agent::KeyPair;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::undo::{undo_receipt_chain_error, verify_undo_receipt};
use atlas_pca::undo_store::*;
use atlas_pca::{AtomicKv, MemoryAtomicKv};

fn rec(id: &str, state: &str, ver: i64, window_end: i64, grant: &str) -> Value {
    json!({"v": 1, "id": id, "aud": "rs", "grant_ref": grant, "holder": "h", "principal": "p", "compensation_digest": "cd", "opened_at": 1, "window_end": window_end,
        "converted": false, "state": state, "ver": ver, "pcactn": "x", "attempt": 0, "receipts": []})
}

fn contract(s: &dyn UndoStore) {
    assert_eq!(s.get("a").unwrap(), None);
    assert_eq!(s.create(&rec("a", "open", 0, 100, "g1")).unwrap(), UndoCreate::Created);
    let other = rec("a", "vetoed", 5, 999, "g2");
    assert_eq!(s.create(&other).unwrap(), UndoCreate::Exists(rec("a", "open", 0, 100, "g1")), "create never overwrites");
    assert_eq!(s.get("a").unwrap(), Some(rec("a", "open", 0, 100, "g1")));
    // replace is a compare-and-swap on ver
    assert!(!s.replace("a", 1, &rec("a", "vetoed", 2, 100, "g1")).unwrap(), "stale expected version");
    assert!(s.replace("a", 0, &rec("a", "vetoed", 1, 100, "g1")).unwrap());
    assert!(!s.replace("a", 0, &rec("a", "finalized", 1, 100, "g1")).unwrap(), "the first replace bumped the version");
    assert!(!s.replace("zz", 0, &rec("zz", "open", 1, 1, "g")).unwrap(), "no record, no replace");
    assert_eq!(s.replace("a", 1, &rec("b", "open", 2, 1, "g")).unwrap_err().code, UndoErrorCode::Invalid, "the id cannot change");
    // queries
    for (id, st, we, g) in [("b", "open", 50, "g1"), ("c", "open", 200, "g2"), ("d", "open", 60, "g1")] {
        s.create(&rec(id, st, 0, we, g)).unwrap();
    }
    let ids = |q: UndoQuery| s.list(&q).unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(ids(UndoQuery { state: "open".into(), ..Default::default() }), vec!["b", "c", "d"], "sorted by id");
    assert_eq!(ids(UndoQuery { state: "vetoed".into(), ..Default::default() }), vec!["a"]);
    assert_eq!(ids(UndoQuery { state: "open".into(), window_ended_by: Some(60), ..Default::default() }), vec!["b", "d"]);
    assert_eq!(ids(UndoQuery { state: "open".into(), grant_ref: Some("g2".into()), ..Default::default() }), vec!["c"]);
    assert_eq!(ids(UndoQuery { state: "open".into(), limit: Some(2), ..Default::default() }), vec!["b", "c"]);
    assert_eq!(ids(UndoQuery { state: "finalized".into(), ..Default::default() }), Vec::<String>::new());
    // ids: non-empty, no control characters
    assert_eq!(s.create(&rec("", "open", 0, 1, "g")).unwrap_err().code, UndoErrorCode::Invalid);
    assert_eq!(s.create(&rec("a\nb", "open", 0, 1, "g")).unwrap_err().code, UndoErrorCode::Invalid);
}

#[test]
fn the_memory_store_is_never_durable_and_meets_the_contract() {
    let s = MemoryUndoStore::new();
    assert!(!s.durable());
    contract(&s);
}

#[test]
fn the_kv_store_declares_durability_and_meets_the_contract() {
    let s = KvUndoStore::new(Arc::new(MemoryAtomicKv::new()), true);
    assert!(s.durable());
    contract(&s);
    assert!(!KvUndoStore::new(Arc::new(MemoryAtomicKv::new()), false).durable());
}

#[test]
fn a_stored_document_of_the_wrong_shape_fails_closed() {
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    let s = KvUndoStore::new(kv.clone(), true);
    for bad in [
        json!({"v": 2, "id": "a", "state": "open", "ver": 0, "receipts": []}),
        json!({"v": 1, "id": "a", "state": "weird", "ver": 0, "receipts": []}),
        json!({"v": 1, "id": "a", "state": "open", "ver": 0}),
        json!({"v": 1, "id": "a", "state": "open", "ver": 1.5, "receipts": []}),
        json!("not an object"),
    ] {
        kv.update("pca-undo/v1/a", &mut |_| Some(bad.clone())).unwrap();
        assert_eq!(s.get("a").unwrap_err().code, UndoErrorCode::StoreCorrupt);
        assert_eq!(s.create(&rec("a", "open", 0, 1, "g")).unwrap_err().code, UndoErrorCode::StoreCorrupt, "never overwrites what it cannot read");
        assert_eq!(s.replace("a", 0, &rec("a", "open", 1, 1, "g")).unwrap_err().code, UndoErrorCode::StoreCorrupt);
        assert_eq!(s.list(&UndoQuery { state: "open".into(), ..Default::default() }).unwrap_err().code, UndoErrorCode::StoreCorrupt);
    }
}

#[test]
fn errors_carry_the_reference_wording() {
    let e = UndoError::new(UndoErrorCode::NotDurable, "x");
    assert_eq!(e.message, "not_durable: x");
    assert_eq!(UndoErrorCode::ConflictExhausted.as_str(), "conflict_exhausted");
}

#[test]
fn with_receipt_chains_signed_receipts() {
    let key = KeyPair::from_seed(&[7u8; 32]);
    let r0 = rec("op1", "open", 0, 100, "g");
    let r1 = with_receipt(&r0, "opened", "", 10, &key).unwrap();
    assert_eq!(r0["receipts"].as_array().unwrap().len(), 0, "the input is untouched");
    let mut v = r1.clone();
    v["state"] = json!("vetoed");
    let r2 = with_receipt(&v, "vetoed", "token", 20, &key).unwrap();
    let receipts = r2["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|r| verify_undo_receipt(r, &key.public)));
    assert_eq!(receipts[0]["prev"], json!(""));
    assert_ne!(receipts[1]["prev"], json!(""));
    assert_eq!(receipts[1]["note"], json!("token"));
    assert_eq!(undo_receipt_chain_error(&r2, &key.public), None);
    assert!(undo_receipt_chain_error(&r2, &KeyPair::from_seed(&[8u8; 32]).public).is_some());
}
