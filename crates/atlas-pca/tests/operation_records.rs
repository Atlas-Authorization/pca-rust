//! Operation records (T3): replays operation-vectors.json scenario by scenario against the real executor and in-memory store,
//! then proves the at-most-once guarantee under real threads and the durable-store contract over the key/value seam.
mod common;

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use atlas_pca::*;
use common::load;
use serde_json::{json, Value};

fn empty_digest() -> String {
    params_digest(None)
}

fn execute(store: Option<&dyn OperationStore>, s: &Value, calls: &Cell<usize>) -> (Value, bool) {
    let id = s["id"].as_str().unwrap().to_string();
    let at = s["at"].as_i64().unwrap();
    let not_allowed = s["not_allowed"] == json!(true);
    let mut pcactn = json!({"action": {}});
    if let Some(e) = s["exp"].as_i64() {
        pcactn["exp"] = json!(e);
    }
    if let Some(c) = s["signed_class"].as_str() {
        pcactn["action"]["reversibility_class"] = json!(c);
    }
    let az = ExecutableAuthorization {
        allow: !not_allowed,
        pcactn: Some(if not_allowed { json!({}) } else { pcactn }),
        operation: (!not_allowed).then(|| AuthorizedOperation {
            verb: s["verb"].as_str().unwrap_or("payments.refund").to_string(),
            resource: s["resource"].as_str().unwrap_or("/orders/1").to_string(),
            params_digest: s["params_digest"].as_str().map(str::to_string).unwrap_or_else(empty_digest),
            id: id.clone(),
        }),
    };
    let recheck_spec = s["recheck"].clone();
    let recheck = move |_: &ExecutionHandle| -> Result<(), String> {
        if recheck_spec == json!("ok") {
            Ok(())
        } else if let Some(r) = recheck_spec["refuse"].as_str() {
            Err(r.to_string())
        } else {
            panic!("{}", recheck_spec["throw"].as_str().unwrap())
        }
    };
    let clock = move || at;
    let opts = ExecuteOptions {
        store,
        operation: None,
        recheck: (!s["recheck"].is_null()).then_some(&recheck as &RecheckFn<'_>),
        recheck_for: if s["recheck_for"] == json!("always") { RecheckFor::Always } else { RecheckFor::Irreversible },
        reversibility_class: s["server_class"].as_str(),
        pending_timeout_ms: s["timeout_ms"].as_i64(),
        now: Some(&clock),
    };
    let fnspec = s["fn"].clone();
    let az_inner = az.clone();
    let out = execute_authorized(
        &az,
        |h| {
            calls.set(calls.get() + 1);
            match fnspec["kind"].as_str().unwrap() {
                "throw" => Err(fnspec["message"].as_str().unwrap().to_string()),
                "reenter" => {
                    let inner = execute_authorized(&az_inner, |_| Err("inner must not run".to_string()), &opts);
                    Ok(inner.to_json()["status"].clone())
                }
                _ => Ok(if fnspec.get("result").is_none() { json!(h.idempotency_key) } else { fnspec["result"].clone() }),
            }
        },
        &opts,
    );
    (out.to_json(), not_allowed)
}

#[test]
fn operation_vectors() {
    let d = load("operation-vectors.json");
    assert_eq!(d["constants"]["pending_timeout_ms"].as_i64(), Some(OPERATION_PENDING_TIMEOUT_MS));
    let scenarios = d["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 19);
    let mut steps_run = 0;
    for sc in scenarios {
        let name = sc["name"].as_str().unwrap();
        let store = MemoryOperationStore::new();
        let steps = sc["steps"].as_array().unwrap();
        let expect = sc["expect"].as_array().unwrap();
        assert_eq!(steps.len(), expect.len(), "{name}");
        for (i, (s, want)) in steps.iter().zip(expect).enumerate() {
            steps_run += 1;
            let at = s["at"].as_i64();
            let got = match s["op"].as_str().unwrap() {
                "seed" => {
                    let rec = OperationRecord::from_json(&s["record"]).unwrap_or_else(|| panic!("{name}: seed record"));
                    assert_eq!(store.create(rec).unwrap(), CreateOutcome::Created);
                    Value::Null
                }
                "get" => store.get(s["id"].as_str().unwrap()).unwrap().map_or(Value::Null, |r| r.to_json()),
                "recover" => {
                    let o = RecoverOptions { older_than_ms: s["older_than_ms"].as_i64(), now: at };
                    let mut v: Vec<Value> = recover_operations(&store, &o).unwrap().iter().map(|r| json!({"id": r.id, "state": r.state.as_str()})).collect();
                    v.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
                    Value::Array(v)
                }
                "recover_one" => {
                    let o = RecoverOptions { older_than_ms: s["older_than_ms"].as_i64(), now: at };
                    recover_operation(&store, s["id"].as_str().unwrap(), &o).unwrap().map_or(Value::Null, |r| r.to_json())
                }
                "resolve" => {
                    let o = &s["outcome"];
                    let outcome = if o["state"] == json!("committed") {
                        ResolvedOutcome::Committed(o.get("result").cloned())
                    } else {
                        ResolvedOutcome::Failed(o["error"].as_str().unwrap().to_string())
                    };
                    json!(resolve_operation(&store, s["id"].as_str().unwrap(), &outcome, at).unwrap())
                }
                "execute" => {
                    let calls = Cell::new(0);
                    let no_store = s["no_store"] == json!(true);
                    let (outcome, skip_record) = execute((!no_store).then_some(&store as &dyn OperationStore), s, &calls);
                    let record = if no_store || skip_record { Value::Null } else { store.get(s["id"].as_str().unwrap()).unwrap().map_or(Value::Null, |r| r.to_json()) };
                    json!({"outcome": outcome, "fn_calls": calls.get(), "record": record})
                }
                other => panic!("{name}: unknown op {other}"),
            };
            assert_eq!(&got, want, "{name} step {i}");
        }
    }
    assert_eq!(steps_run, 49);
}

fn az(id: &str) -> ExecutableAuthorization {
    ExecutableAuthorization {
        allow: true,
        pcactn: Some(json!({"action": {"reversibility_class": "reversible"}})),
        operation: Some(AuthorizedOperation { verb: "v".into(), resource: "/r".into(), params_digest: empty_digest(), id: id.into() }),
    }
}

fn burst(store: Arc<dyn OperationStore>, n: usize) -> (usize, Vec<ExecuteOutcome>) {
    let runs = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (store, runs, gate) = (store.clone(), runs.clone(), gate.clone());
            std::thread::spawn(move || {
                gate.wait();
                let opts = ExecuteOptions { store: Some(store.as_ref()), ..Default::default() };
                execute_authorized(
                    &az("burst"),
                    |_| {
                        runs.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        Ok(json!("done"))
                    },
                    &opts,
                )
            })
        })
        .collect();
    let outs = handles.into_iter().map(|h| h.join().unwrap()).collect();
    (runs.load(Ordering::SeqCst), outs)
}

#[test]
fn n_parallel_executions_of_one_id_run_the_function_exactly_once() {
    let stores: Vec<Arc<dyn OperationStore>> =
        vec![Arc::new(MemoryOperationStore::new()), Arc::new(KvOperationStore::new(Arc::new(MemoryAtomicKv::new())))];
    for store in stores {
        let (runs, outs) = burst(store.clone(), 16);
        assert_eq!(runs, 1);
        let fresh: Vec<_> = outs.iter().filter(|o| matches!(o, ExecuteOutcome::Committed { replayed: false, .. })).collect();
        assert_eq!(fresh.len(), 1, "{outs:?}");
        for o in &outs {
            assert!(
                matches!(o, ExecuteOutcome::Committed { .. } | ExecuteOutcome::Pending { .. }),
                "a loser must be answered from the record or pending: {o:?}"
            );
        }
        let rec = store.get("burst").unwrap().unwrap();
        assert_eq!((rec.state, rec.result), (OperationState::Committed, Some(json!("done"))));
    }
}

#[test]
fn the_kv_store_is_linearizable_on_create_and_transition() {
    let store = KvOperationStore::new(Arc::new(MemoryAtomicKv::new())).with_prefix("t:");
    let rec = |state| OperationRecord {
        id: "a".into(),
        state,
        verb: "v".into(),
        resource: "/r".into(),
        params_digest: empty_digest(),
        reversibility: Reversibility::Costly,
        started_at: 1,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    };
    assert_eq!(store.create(rec(OperationState::Pending)).unwrap(), CreateOutcome::Created);
    assert!(matches!(store.create(rec(OperationState::Failed)).unwrap(), CreateOutcome::Exists(r) if r.state == OperationState::Pending));
    assert!(!store.transition("a", OperationState::Executing, rec(OperationState::Committed)).unwrap());
    assert!(store.transition("a", OperationState::Pending, rec(OperationState::Executing)).unwrap());
    assert!(!store.transition("a", OperationState::Pending, rec(OperationState::Executing)).unwrap());
    assert_eq!(store.list_open().unwrap().unwrap().len(), 1);
    assert!(store.get("missing").unwrap().is_none());
}

#[test]
fn a_store_that_cannot_decide_refuses_and_runs_nothing() {
    struct Down;
    impl OperationStore for Down {
        fn create(&self, _: OperationRecord) -> Result<CreateOutcome, StoreError> {
            Err(StoreError("down".into()))
        }
        fn get(&self, _: &str) -> Result<Option<OperationRecord>, StoreError> {
            Err(StoreError("down".into()))
        }
        fn transition(&self, _: &str, _: OperationState, _: OperationRecord) -> Result<bool, StoreError> {
            Err(StoreError("down".into()))
        }
    }
    let ran = Cell::new(false);
    let out = execute_authorized(&az("x"), |_| { ran.set(true); Ok(json!(1)) }, &ExecuteOptions { store: Some(&Down), ..Default::default() });
    assert!(!ran.get());
    assert!(matches!(out, ExecuteOutcome::Refused { ref reason } if reason.contains("operation store: down (fail closed)")), "{out:?}");
    assert!(recover_operations(&Down, &RecoverOptions::default()).is_err());
}

#[test]
fn a_panicking_function_is_recorded_failed_and_not_rerun() {
    let store = MemoryOperationStore::new();
    let opts = ExecuteOptions { store: Some(&store), ..Default::default() };
    let first = execute_authorized(&az("p"), |_| -> Result<Value, String> { panic!("kaboom") }, &opts);
    assert!(matches!(first, ExecuteOutcome::Failed { ref error, replayed: false, .. } if error == "kaboom"), "{first:?}");
    let again = execute_authorized(&az("p"), |_| Ok(json!(1)), &opts);
    assert!(matches!(again, ExecuteOutcome::Failed { replayed: true, .. }), "{again:?}");
}
