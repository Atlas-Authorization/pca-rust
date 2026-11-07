//! The `Executor` (authorize + execute at most once) and the binding `execute_authorized` enforces: the clock, the
//! irreversible re-check (extra hook, registered plan), a replay answered only from a record of THIS operation, and the
//! operation / allow gates of the direct API.
mod common;

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use atlas_pca::*;
use serde_json::{json, Value};

struct Fx {
    grant: Value,
    pcactn: Value,
    op: Operation,
    now: i64,
    audience: String,
}

fn fx() -> Fx {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let s = &d["cases"][0]["steps"][0];
    Fx {
        grant: d["cases"][0]["grant"].clone(),
        pcactn: s["pcactn"].clone(),
        op: Operation::from_json(&s["operation"]).unwrap(),
        now: d["now"].as_i64().unwrap(),
        audience: d["audience"].as_str().unwrap().to_string(),
    }
}

fn az_opts(state: Arc<MemoryStateStore>, revoked: Arc<AtomicBool>, plans: Arc<PlanRegistry>) -> AuthorizeOptions {
    AuthorizeOptions::new(state, move |_: &Value, _: &Value| Ok(revoked.load(Ordering::SeqCst)))
        .with_plans(plans)
        .with_provenance_mediators(common::harness_pins())
        .with_provenance_bundle(common::principal_direct)
}

fn executor(f: &Fx, az: AuthorizeOptions, store: Arc<dyn OperationStore>) -> Executor {
    let (grant, now) = (f.grant.clone(), f.now);
    Executor::new(az, f.audience.clone(), move |_: &str| Ok(Some(grant.clone())), store).with_clock(move || now)
}

fn fresh(f: &Fx, store: Arc<dyn OperationStore>) -> Executor {
    executor(f, az_opts(Arc::new(MemoryStateStore::new()), Arc::new(AtomicBool::new(false)), Arc::new(PlanRegistry::new())), store)
}

#[test]
fn an_executor_runs_once_on_its_clock_and_answers_the_replay_from_the_record() {
    let f = fx();
    let ex = fresh(&f, Arc::new(MemoryOperationStore::new()));
    let calls = Cell::new(0);
    let first = ex.execute(&f.pcactn, &f.op, |_| {
        calls.set(calls.get() + 1);
        Ok(json!("done"))
    });
    assert!(matches!(first, ExecutorOutcome::Executed(ExecuteOutcome::Committed { replayed: false, recorded: true, .. })), "{first:?}");
    let again = ex.execute(&f.pcactn, &f.op, |_| {
        calls.set(calls.get() + 1);
        Ok(json!("again"))
    });
    match again {
        ExecutorOutcome::Executed(ExecuteOutcome::Committed { replayed: true, result, .. }) => assert_eq!(result, json!("done")),
        other => panic!("the replay must be answered from the record: {other:?}"),
    }
    assert_eq!(calls.get(), 1);
}

#[test]
fn an_executable_authorization_needs_both_the_result_and_the_verdict_to_allow() {
    let f = fx();
    let revoked = executor(&f, az_opts(Arc::new(MemoryStateStore::new()), Arc::new(AtomicBool::new(true)), Arc::new(PlanRegistry::new())), Arc::new(MemoryOperationStore::new()));
    let ExecutorOutcome::Denied(mut r) = revoked.execute(&f.pcactn, &f.op, |_| Ok(json!(1))) else { panic!("a revoked grant is denied") };
    let verdict = |allow: bool| Some(Verdict { allow, checks: Default::default(), reason: String::new(), reasons: Vec::new(), legacy_model_polarity: false });
    r.allow = false;
    r.verdict = verdict(true);
    assert!(!ExecutableAuthorization::from(&*r).allow);
    r.allow = true;
    r.verdict = verdict(false);
    assert!(!ExecutableAuthorization::from(&*r).allow);
    r.allow = true;
    r.verdict = verdict(true);
    assert!(ExecutableAuthorization::from(&*r).allow);
}

#[test]
fn an_executor_recheck_refusal_aborts_without_running() {
    let f = fx();
    let ex = fresh(&f, Arc::new(MemoryOperationStore::new())).with_recheck(|_| Err("step-up withdrawn".into()));
    let ran = Cell::new(false);
    let out = ex.execute(&f.pcactn, &f.op, |_| {
        ran.set(true);
        Ok(json!(1))
    });
    assert!(!ran.get());
    assert!(matches!(out, ExecutorOutcome::Executed(ExecuteOutcome::Aborted { ref reason, .. }) if reason == "recheck: step-up withdrawn"), "{out:?}");
}

#[test]
fn a_registered_executable_plan_lets_the_executor_run() {
    let f = fx();
    let p = &f.pcactn;
    let (root, grant_ref) = (p["plan"]["root"].as_str().unwrap(), p["grant_ref"].as_str().unwrap());
    let n = json!({"id": p["plan"]["node_id"], "verb": f.op.verb, "resource": f.op.resource, "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]});
    let reg = Arc::new(PlanRegistry::new());
    assert!(reg.draft(grant_ref, std::slice::from_ref(&n)).is_ok());
    assert!(reg.validate(grant_ref, root).is_ok() && reg.commit(grant_ref, root).is_ok());
    assert!(reg.authorize(grant_ref, root, Some(&PlanApproval { by: "p".into(), expires_at: None })).is_ok());
    assert!(reg.get(grant_ref, root).is_some());
    let ex = executor(&f, az_opts(Arc::new(MemoryStateStore::new()), Arc::new(AtomicBool::new(false)), reg), Arc::new(MemoryOperationStore::new()));
    let out = ex.execute(&f.pcactn, &f.op, |_| Ok(json!("ran")));
    assert!(matches!(out, ExecutorOutcome::Executed(ExecuteOutcome::Committed { replayed: false, .. })), "{out:?}");
}

#[test]
fn a_replay_is_answered_only_from_a_record_of_this_operation() {
    let f = fx();
    let state = Arc::new(MemoryStateStore::new());
    let revoked = Arc::new(AtomicBool::new(false));
    let plans = Arc::new(PlanRegistry::new());
    // consume the PCActn's counter once
    let first = executor(&f, az_opts(state.clone(), revoked.clone(), plans.clone()), Arc::new(MemoryOperationStore::new())).execute(&f.pcactn, &f.op, |_| Ok(json!(1)));
    assert!(matches!(first, ExecutorOutcome::Executed(_)), "{first:?}");
    let id = hash_canonical_strict(&f.pcactn).unwrap();
    let digest = hash_canonical_strict(&f.op.params).unwrap();
    let seeded = |verb: &str, resource: &str, params_digest: &str| -> Arc<dyn OperationStore> {
        let s = MemoryOperationStore::new();
        let rec = OperationRecord {
            id: id.clone(),
            state: OperationState::Committed,
            verb: verb.into(),
            resource: resource.into(),
            params_digest: params_digest.into(),
            reversibility: Reversibility::Irreversible,
            started_at: 1,
            executing_at: Some(1),
            finished_at: Some(2),
            result: Some(json!("seeded")),
            error: None,
        };
        assert_eq!(s.create(rec).unwrap(), CreateOutcome::Created);
        Arc::new(s)
    };
    let replay = |store: Arc<dyn OperationStore>| executor(&f, az_opts(state.clone(), revoked.clone(), plans.clone()), store).execute(&f.pcactn, &f.op, |_| panic!("a replay never runs"));
    for (what, store) in [
        ("verb", seeded("other.verb", &f.op.resource, &digest)),
        ("resource", seeded(&f.op.verb, "other/resource", &digest)),
        ("params", seeded(&f.op.verb, &f.op.resource, &hash_canonical_strict(&json!({"amount": 1})).unwrap())),
    ] {
        let out = replay(store);
        assert!(matches!(out, ExecutorOutcome::Denied(ref r) if r.failed_checks() == ["replay"]), "{what}: {out:?}");
    }
    match replay(seeded(&f.op.verb, &f.op.resource, &digest)) {
        ExecutorOutcome::Executed(ExecuteOutcome::Committed { replayed: true, result, .. }) => assert_eq!(result, json!("seeded")),
        other => panic!("a matching record answers the replay: {other:?}"),
    }
    // a 403 that is not ONLY a replay stands even with a matching record
    revoked.store(true, Ordering::SeqCst);
    match replay(seeded(&f.op.verb, &f.op.resource, &digest)) {
        ExecutorOutcome::Denied(r) => assert!(r.status == 403 && r.failed_checks() != ["replay"], "{r:?}"),
        other => panic!("a revoked grant is denied: {other:?}"),
    }
}

// ---- execute_authorized directly ----------------------------------------------------------------------------------------

fn bound(id: &str, allow: bool) -> ExecutableAuthorization {
    ExecutableAuthorization {
        allow,
        pcactn: Some(json!({"action": {"reversibility_class": "reversible"}})),
        operation: Some(AuthorizedOperation { verb: "v".into(), resource: "/r".into(), params_digest: hash_canonical_strict(&json!({"amount": 5})).unwrap(), id: id.into() }),
    }
}

fn run(az: &ExecutableAuthorization, want: Option<&Operation>) -> (bool, ExecuteOutcome) {
    let store = MemoryOperationStore::new();
    let ran = Cell::new(false);
    let out = execute_authorized(
        az,
        |_| {
            ran.set(true);
            Ok(json!(1))
        },
        &ExecuteOptions { store: Some(&store), operation: want, now: Some(&|| 1_000), ..Default::default() },
    );
    (ran.get(), out)
}

#[test]
fn execute_authorized_runs_only_the_operation_it_was_allowed_for() {
    let (ran, out) = run(&bound("ok", true), Some(&Operation::new("v", "/r", json!({"amount": 5}))));
    assert!(ran && matches!(out, ExecuteOutcome::Committed { .. }), "{out:?}");
    for (what, op) in [
        ("verb", Operation::new("w", "/r", json!({"amount": 5}))),
        ("resource", Operation::new("v", "/s", json!({"amount": 5}))),
        ("params", Operation::new("v", "/r", json!({"amount": 6}))),
    ] {
        let (ran, out) = run(&bound("ok", true), Some(&op));
        assert!(!ran, "{what}");
        assert!(matches!(out, ExecuteOutcome::Refused { ref reason } if reason.contains("is not for this operation")), "{what}: {out:?}");
    }
    for az in [bound("ok", false), bound("", true)] {
        let (ran, out) = run(&az, None);
        assert!(!ran && matches!(out, ExecuteOutcome::Refused { ref reason } if reason.contains("did not allow an operation")), "{out:?}");
    }
}

#[test]
fn without_a_clock_records_carry_the_system_time() {
    let store = MemoryOperationStore::new();
    let out = execute_authorized(&bound("sys", true), |_| Ok(json!(1)), &ExecuteOptions { store: Some(&store), ..Default::default() });
    assert!(matches!(out, ExecuteOutcome::Committed { .. }), "{out:?}");
    let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let rec = store.get("sys").unwrap().unwrap();
    assert!((rec.started_at - wall).abs() < 86_400_000, "{rec:?}");
}

#[test]
fn a_commit_after_recovery_settled_the_execution_is_still_recorded() {
    // recovery marks the running execution uncertain while the function runs; its result then settles the record
    let store = MemoryOperationStore::new();
    let out = execute_authorized(
        &bound("late", true),
        |_| {
            let settled = recover_operation(&store, "late", &RecoverOptions { older_than_ms: Some(0), now: Some(5_000) }).unwrap();
            assert_eq!(settled.map(|r| r.state), Some(OperationState::Uncertain));
            Ok(json!("late"))
        },
        &ExecuteOptions { store: Some(&store), now: Some(&|| 1_000), ..Default::default() },
    );
    assert!(matches!(out, ExecuteOutcome::Committed { recorded: true, .. }), "{out:?}");
    assert_eq!(store.get("late").unwrap().unwrap().state, OperationState::Committed);
}

/// BRIEF "a fault after every core check passed must deny" (TS pcactn.ts turns a throw there into `malformed`): with a PCActn
/// that otherwise allows, a revocation hook that panics, or a replay store that panics on the last step (the counter claim),
/// is a deny with that check failed, never an allow.
#[test]
fn a_fault_after_every_core_check_passed_denies() {
    struct PanicOnClaim(MemoryStateStore);
    impl StateStore for PanicOnClaim {
        fn claim(&self, _: &str, _: u64) -> Result<ClaimResult, StoreError> {
            panic!("injected fault in the last step")
        }
        fn last(&self, key: &str) -> Option<Option<u64>> {
            self.0.last(key)
        }
    }
    let f = fx();
    let ok = fresh(&f, Arc::new(MemoryOperationStore::new())).execute(&f.pcactn, &f.op, |_| Ok(json!(1)));
    assert!(matches!(ok, ExecutorOutcome::Executed(_)), "the control allows: {ok:?}");

    let faulty = |az: AuthorizeOptions| {
        let ran = Cell::new(false);
        let out = executor(&f, az, Arc::new(MemoryOperationStore::new())).execute(&f.pcactn, &f.op, |_| {
            ran.set(true);
            Ok(json!(1))
        });
        assert!(!ran.get(), "a faulted authorization never runs the operation");
        match out {
            ExecutorOutcome::Denied(r) => *r,
            other => panic!("a fault must deny: {other:?}"),
        }
    };
    let plans = || Arc::new(PlanRegistry::new());
    let revocation = faulty(
        AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| -> Result<bool, String> { panic!("injected fault in the revocation hook") })
            .with_plans(plans())
            .with_provenance_mediators(common::harness_pins())
            .with_provenance_bundle(common::principal_direct),
    );
    assert!(!revocation.allow);
    assert_eq!(revocation.checks.get("revocation"), Some(&CheckStatus::Fail), "{revocation:?}");
    assert!(revocation.reasons.contains(&"revocation: the revocation check failed (fail closed)".to_string()), "{revocation:?}");

    let claim = faulty(
        AuthorizeOptions::new(Arc::new(PanicOnClaim(MemoryStateStore::new())), |_: &Value, _: &Value| Ok(false))
            .with_plans(plans())
            .with_provenance_mediators(common::harness_pins())
            .with_provenance_bundle(common::principal_direct),
    );
    assert!(!claim.allow);
    assert_eq!(claim.checks.get("replay"), Some(&CheckStatus::Fail), "{claim:?}");
}
