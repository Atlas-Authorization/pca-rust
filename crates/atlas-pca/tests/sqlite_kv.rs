//! Feature `sqlite`: the durable key/value seam under the operation store and the plan registry survives a restart and
//! stays atomic across connections.
#![cfg(feature = "sqlite")]

use std::sync::{Arc, Barrier};

use atlas_pca::*;
use serde_json::json;

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("pca-kv-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn record(id: &str) -> OperationRecord {
    OperationRecord {
        id: id.into(),
        state: OperationState::Pending,
        verb: "v".into(),
        resource: "/r".into(),
        params_digest: params_digest(None),
        reversibility: Reversibility::Reversible,
        started_at: 10,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    }
}

#[test]
fn operation_records_are_durable_and_listable() {
    let d = dir("ops");
    let path = d.join("kv.db");
    let store = KvOperationStore::new(Arc::new(SqliteAtomicKv::open(&path).unwrap()));
    assert_eq!(store.create(record("a")).unwrap(), CreateOutcome::Created);
    assert_eq!(store.create(record("b")).unwrap(), CreateOutcome::Created);
    let mut running = record("a");
    running.state = OperationState::Executing;
    running.executing_at = Some(11);
    assert!(store.transition("a", OperationState::Pending, running).unwrap());
    drop(store);
    // a restart: a new connection on the same file sees both records, and recovery settles them without re-running anything
    let again = KvOperationStore::new(Arc::new(SqliteAtomicKv::open(&path).unwrap()));
    assert_eq!(again.get("a").unwrap().unwrap().state, OperationState::Executing);
    assert_eq!(again.list_open().unwrap().unwrap().len(), 2);
    let settled = recover_operations(&again, &RecoverOptions { older_than_ms: Some(1000), now: Some(10_000) }).unwrap();
    let mut states: Vec<_> = settled.iter().map(|r| (r.id.clone(), r.state)).collect();
    states.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(states, vec![("a".to_string(), OperationState::Uncertain), ("b".to_string(), OperationState::Aborted)]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn concurrent_creates_on_separate_connections_make_exactly_one_record() {
    let d = dir("race");
    let path = d.join("kv.db");
    let n = 8;
    let gate = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (path, gate) = (path.clone(), gate.clone());
            std::thread::spawn(move || {
                let store = KvOperationStore::new(Arc::new(SqliteAtomicKv::open(&path).unwrap()));
                gate.wait();
                store.create(record("same")).unwrap()
            })
        })
        .collect();
    let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outs.iter().filter(|o| **o == CreateOutcome::Created).count(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn plans_survive_a_restart() {
    let d = dir("plans");
    let path = d.join("kv.db");
    let nodes = [json!({"id": "n1", "verb": "orders.read", "resource": "/orders/1"})];
    let reg = PlanRegistry::new().with_kv(Arc::new(SqliteAtomicKv::open(&path).unwrap()));
    let root = match reg.draft("g1", &nodes) {
        PlanTransition::Ok(r) => r.root,
        other => panic!("{other:?}"),
    };
    assert!(reg.validate("g1", &root).is_ok() && reg.commit("g1", &root).is_ok());
    drop(reg);
    let again = PlanRegistry::new().with_kv(Arc::new(SqliteAtomicKv::open(&path).unwrap()));
    assert!(again.authorize("g1", &root, Some(&PlanApproval { by: "p".into(), expires_at: None })).is_ok());
    assert!(again.status("g1", &root, None).executable);
    assert!(matches!(again.draft("g1", &nodes), PlanTransition::Refused { .. }));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_sqlite_stores_pass_the_conformance_helper() {
    use atlas_pca::store_conformance::*;
    let d = dir("conf");
    let opts = Options { rounds: 3, copies: 8, durable: true };
    let state_path = d.join("state.db");
    let r = run_state_store_conformance(&|| Arc::new(SqliteStateStore::open(&state_path).unwrap()) as Arc<dyn StateStore>, &opts);
    r.assert_passed();
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
    let kv_path = d.join("kv.db");
    let r = run_operation_store_conformance(
        &|| Arc::new(KvOperationStore::new(Arc::new(SqliteAtomicKv::open(&kv_path).unwrap()))) as Arc<dyn OperationStore>,
        &opts,
    );
    r.assert_passed();
    assert!(r.tests.iter().all(|t| t.status == Status::Pass), "{r:?}");
    let _ = std::fs::remove_dir_all(&d);
}
