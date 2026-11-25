//! The undo-window coordinator end to end over a real grant and a signed PCActn: eligibility, the durable open, the one-click veto,
//! the at-most-once compensation, finalization, recovery, revocation and the relay.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use atlas_pca::agent::{default_risk_policy, mint_grant, Agent, KeyPair, Suite};
use atlas_pca::operations::MemoryOperationStore;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::undo::{sign_undo_token, UNDO_MIN_WINDOW_MS};
use atlas_pca::undo_coordinator::*;
use atlas_pca::undo_store::{MemoryUndoStore, UndoErrorCode, UndoStore};
use atlas_pca::Operation;

struct Engine {
    confirmed: bool,
}

impl UndoEngine for Engine {
    fn plan(&self, op: &Operation, _id: &str) -> Option<UndoPlan> {
        self.confirmed.then(|| UndoPlan {
            def_digest: "def1".into(),
            compensation_verb: "orders.cancel".into(),
            compensation_params: json!({"reason": "undo"}),
            compensation_def_digest: "def2".into(),
            target_param: (op.verb == "orders.create").then(|| "order_id".to_string()),
            render: None,
            render_digest: None,
        })
    }
}

#[derive(Default)]
struct Bell {
    deliver: bool,
    seen: Mutex<Vec<&'static str>>,
}

impl UndoNotifier for Bell {
    fn notify(&self, n: &UndoNotice) -> UndoNotifyResult {
        self.seen.lock().unwrap().push(n.kind);
        UndoNotifyResult { delivered: self.deliver, reason: (!self.deliver).then(|| "no channel".to_string()) }
    }
}

struct Rig {
    undo: UndoCoordinator,
    store: Arc<MemoryUndoStore>,
    clock: Arc<AtomicI64>,
    alerts: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<UndoCompensationCall>>>,
    bell: Arc<Bell>,
    agent: Agent,
    grant: Value,
    signer: Vec<u8>,
}

fn rig(confirmed: bool, deliver: bool, compensate_ok: bool, tweak: impl FnOnce(&mut UndoCoordinatorOptions)) -> Rig {
    let principal = KeyPair::from_seed(&[1u8; 32]);
    let agent_key = KeyPair::from_seed(&[2u8; 32]);
    let env = json!({"predicates": [{"verb": ["orders.create", "orders.update", "orders.cancel"], "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &agent_key.public, &env, "manage orders", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(agent_key, grant.clone(), "rs", 0);
    let store = Arc::new(MemoryUndoStore::new());
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let alerts = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bell = Arc::new(Bell { deliver, ..Default::default() });
    let (a, c, ck, g) = (alerts.clone(), calls.clone(), clock.clone(), grant.clone());
    let signer = vec![9u8; 32];
    let mut o = UndoCoordinatorOptions {
        store: Some(store.clone()),
        engine: Some(Arc::new(Engine { confirmed })),
        signer_secret: Some(signer.clone()),
        audience: "rs".into(),
        resolve_grant: Some(Arc::new(move |_r: &str, _p: &Value| Some(g.clone()))),
        compensate: Some(Arc::new(move |call: &UndoCompensationCall| {
            c.lock().unwrap().push(call.clone());
            if compensate_ok {
                Ok(json!({"cancelled": true}))
            } else {
                Err("downstream is down".to_string())
            }
        })),
        operations: Some(Arc::new(MemoryOperationStore::new())),
        notifier: Some(bell.clone()),
        alert: Some(Arc::new(move |x: &UndoAlert| a.lock().unwrap().push(format!("{}:{}", x.code, x.reason)))),
        now: Some(Arc::new(move || ck.load(Ordering::SeqCst))),
        insecure_volatile_store: true,
        ..Default::default()
    };
    tweak(&mut o);
    Rig { undo: create_undo_coordinator(o).unwrap(), store, clock, alerts, calls, bell, agent, grant, signer }
}

fn action(r: &Rig, verb: &str, params: Value) -> (Value, Operation) {
    let a = r.agent.act(verb, "orders/1", Some(&params), Map::new(), &Suite::default()).unwrap();
    (a.pcactn, Operation::new(verb, "orders/1", params))
}

fn open_window(r: &Rig, verb: &str) -> (UndoWindowInfo, Value) {
    let (pc, op) = action(r, verb, json!({"qty": 1}));
    let draft = r.undo.admit(&pc, Some(&r.grant), &op, false).unwrap_or_else(|e| panic!("refused: {e}"));
    (r.undo.open(&draft, None).unwrap(), pc)
}

#[test]
fn the_required_components_and_a_durable_store_are_checked_first() {
    let o = UndoCoordinatorOptions::default();
    assert_eq!(
        missing_undo_components(&o),
        vec!["store", "engine", "signerSecret", "audience", "resolveGrant", "compensate", "operations", "notifier", "alert"]
    );
    assert_eq!(create_undo_coordinator(o).err().unwrap().code, UndoErrorCode::Config);
    let r = rig(true, true, true, |_| {});
    // a volatile store is refused unless the test says it accepts losing every window
    let o2 = UndoCoordinatorOptions { insecure_volatile_store: false, ..complete(&r) };
    assert_eq!(create_undo_coordinator(o2).err().unwrap().code, UndoErrorCode::NotDurable);
}

fn complete(r: &Rig) -> UndoCoordinatorOptions {
    let g = r.grant.clone();
    UndoCoordinatorOptions {
        store: Some(r.store.clone()),
        engine: Some(Arc::new(Engine { confirmed: true })),
        signer_secret: Some(r.signer.clone()),
        audience: "rs".into(),
        resolve_grant: Some(Arc::new(move |_: &str, _: &Value| Some(g.clone()))),
        compensate: Some(Arc::new(|_: &UndoCompensationCall| Ok(json!(null)))),
        operations: Some(Arc::new(MemoryOperationStore::new())),
        notifier: Some(r.bell.clone()),
        alert: Some(Arc::new(|_: &UndoAlert| {})),
        ..Default::default()
    }
}

#[test]
fn only_a_confirmed_reversible_action_authorized_under_the_grant_gets_a_window() {
    let r = rig(true, true, true, |_| {});
    let (pc, op) = action(&r, "orders.update", json!({"qty": 1}));
    let d = r.undo.admit(&pc, Some(&r.grant), &op, false).unwrap();
    assert_eq!((d.compensation["verb"].as_str(), d.compensation["undo_of"].as_str()), (Some("orders.cancel"), Some(d.id.as_str())));
    assert!(d.window_end - d.opened_at >= UNDO_MIN_WINDOW_MS);
    // the definition does not confirm it: irreversible
    let none = rig(false, true, true, |_| {});
    let (pc2, op2) = action(&none, "orders.update", json!({}));
    assert_eq!(none.undo.admit(&pc2, Some(&none.grant), &op2, false).err().unwrap(), "not confirmed reversible, or no confirmed compensating action");
    // an agent that signs another class is taken at its word
    let mut irreversible = pc.clone();
    irreversible["action"]["reversibility_class"] = json!("irreversible");
    assert_eq!(r.undo.admit(&irreversible, Some(&r.grant), &op, false).err().unwrap(), "the signed class is irreversible");
    // the compensating verb must itself be permitted by the grant
    let narrow = rig(true, true, true, |o| {
        let env_grant = {
            let p = KeyPair::from_seed(&[1u8; 32]);
            let a = KeyPair::from_seed(&[2u8; 32]);
            mint_grant(
                &p,
                &a.public,
                &json!({"predicates": [{"verb": "orders.update", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()}),
                "g",
                None,
                None,
                &Suite::default(),
            )
            .unwrap()
            .grant
        };
        o.resolve_grant = Some(Arc::new(move |_: &str, _: &Value| Some(env_grant.clone())));
    });
    let a = narrow.agent.act("orders.update", "orders/1", Some(&json!({})), Map::new(), &Suite::default()).unwrap();
    let why = narrow.undo.admit(&a.pcactn, None, &Operation::new("orders.update", "orders/1", json!({})), false).err().unwrap();
    assert!(why.starts_with("the compensating action is not authorized under the grant"), "{why}");
}

#[test]
fn policy_can_turn_windows_off_or_limit_them_to_escalations() {
    let off =
        rig(true, true, true, |o| o.policy = Some(Arc::new(|_: &Operation, _: &Value| Some(UndoPolicy { mode: Some("off".into()), ..Default::default() }))));
    let (pc, op) = action(&off, "orders.update", json!({}));
    assert_eq!(off.undo.admit(&pc, Some(&off.grant), &op, true).err().unwrap(), "policy: undo windows are off");
    let esc = rig(true, true, true, |o| {
        o.policy = Some(Arc::new(|_: &Operation, _: &Value| Some(UndoPolicy { mode: Some("escalations".into()), ..Default::default() })))
    });
    let (pc, op) = action(&esc, "orders.update", json!({}));
    assert_eq!(esc.undo.admit(&pc, Some(&esc.grant), &op, false).err().unwrap(), "policy: windows only replace approvals");
    assert!(esc.undo.admit(&pc, Some(&esc.grant), &op, true).is_ok());
}

#[test]
fn opening_writes_the_record_and_tells_the_principal_a_failed_notice_aborts_it() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    assert_eq!(info.obligation["kind"], json!("undo_window"));
    let rec = r.undo.get(&info.id).unwrap().unwrap();
    assert_eq!((rec["state"].as_str(), rec["receipts"].as_array().unwrap().len()), (Some("open"), 1));
    assert_eq!(r.bell.seen.lock().unwrap().as_slice(), &["opened"]);
    // a retry of the same admission returns the same window
    let (pc, op) = action(&r, "orders.update", json!({"qty": 1}));
    let again = r.undo.admit(&pc, Some(&r.grant), &op, false).unwrap();
    r.undo.open(&again, None).unwrap();
    assert_eq!(r.undo.open(&again, None).unwrap().id, again.id);
    // nobody was told: the window is aborted and an alert raised
    let deaf = rig(true, false, true, |_| {});
    let (pc, op) = action(&deaf, "orders.update", json!({}));
    let d = deaf.undo.admit(&pc, Some(&deaf.grant), &op, false).unwrap();
    let e = deaf.undo.open(&d, None).unwrap_err();
    assert!(e.message.starts_with("invalid: notify_failed:"), "{}", e.message);
    assert_eq!(deaf.undo.get(&d.id).unwrap().unwrap()["state"], json!("finalized"));
    assert!(deaf.alerts.lock().unwrap().iter().any(|a| a.starts_with("notify_failed:")));
}

#[test]
fn a_valid_token_inside_the_window_vetoes_once_and_compensates_at_most_once() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    r.undo.record_effect(&info.id, Some(&json!({"id": "o-1"}))).unwrap();
    let v = r.undo.veto(&info.id, &VetoBy::Token { token: json!(info.token), at: None });
    let VetoResult::Ok { record, replayed } = v else { panic!("{v:?}") };
    assert_eq!((record["state"].as_str(), replayed), (Some("compensated"), false));
    assert_eq!(r.calls.lock().unwrap().len(), 1);
    assert_eq!(r.calls.lock().unwrap()[0].operation.verb, "orders.cancel");
    // the same token again is a replay: nothing runs twice
    let v2 = r.undo.veto(&info.id, &VetoBy::Token { token: json!(info.token), at: None });
    assert!(matches!(v2, VetoResult::Ok { replayed: true, .. }), "{v2:?}");
    assert_eq!(r.calls.lock().unwrap().len(), 1, "at most once");
    assert_eq!(r.bell.seen.lock().unwrap().as_slice(), &["opened", "vetoed", "compensated"]);
}

#[test]
fn forged_expired_and_foreign_tokens_are_refused() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    let VetoResult::Refused { code, .. } = r.undo.veto(&info.id, &VetoBy::Token { token: json!("garbage"), at: None }) else { panic!() };
    assert_eq!(code, "malformed");
    let rec = r.undo.get(&info.id).unwrap().unwrap();
    let other_signer = sign_undo_token(&rec, &KeyPair::from_seed(&[3u8; 32])).unwrap();
    let VetoResult::Refused { code, .. } = r.undo.veto(&info.id, &VetoBy::Token { token: other_signer, at: None }) else { panic!() };
    assert_eq!(code, "signer");
    let VetoResult::Refused { code, .. } = r.undo.veto("no-such", &VetoBy::Operator("op".into())) else { panic!() };
    assert_eq!(code, "unknown");
    // after the window the token is expired
    r.clock.fetch_add(UNDO_MIN_WINDOW_MS * 100, Ordering::SeqCst);
    let VetoResult::Refused { code, .. } = r.undo.veto(&info.id, &VetoBy::Token { token: json!(info.token), at: None }) else { panic!() };
    assert_eq!(code, "expired");
    assert_eq!(r.calls.lock().unwrap().len(), 0);
    let VetoResult::Refused { code, .. } = r.undo.veto(&info.id, &VetoBy::Operator("".into())) else { panic!() };
    assert_eq!(code, "malformed");
}

#[test]
fn a_failed_compensation_keeps_the_record_alerts_and_can_be_retried() {
    let r = rig(true, true, false, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    r.undo.record_effect(&info.id, None).unwrap();
    let VetoResult::Ok { record, .. } = r.undo.veto(&info.id, &VetoBy::Operator("ops".into())) else { panic!() };
    assert_eq!(record["state"], json!("compensation_failed"));
    assert!(r.alerts.lock().unwrap().iter().any(|a| a.starts_with("compensation_failed:the compensating action failed: downstream is down")));
    // the retry runs under the next attempt number (a new operation record)
    let again = r.undo.retry(&info.id).unwrap();
    assert_eq!(again["state"], json!("compensation_failed"));
    assert_eq!(again["attempt"], json!(1));
    // one guard: locking the same mutex twice in one statement deadlocks
    let calls = r.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].idempotency_key, calls[1].idempotency_key);
}

#[test]
fn a_veto_before_the_effect_report_waits_for_it() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.create");
    let VetoResult::Ok { record, .. } = r.undo.veto(&info.id, &VetoBy::Operator("ops".into())) else { panic!() };
    assert_eq!(record["state"], json!("vetoed"), "no effect reported yet: wait");
    assert_eq!(r.calls.lock().unwrap().len(), 0);
    // the effect result names the compensation target; reporting it resumes the compensation
    let done = r.undo.record_effect(&info.id, Some(&json!({"id": "order-77"}))).unwrap();
    assert_eq!(done["state"], json!("compensated"));
    assert_eq!(r.calls.lock().unwrap()[0].operation.params["order_id"], json!("order-77"));
    assert_eq!(r.calls.lock().unwrap()[0].original_result, Some(json!({"id": "order-77"})));
}

#[test]
fn an_unknown_target_fails_the_compensation_and_never_guesses() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.create");
    r.undo.record_effect(&info.id, Some(&json!({"nothing": 1}))).unwrap();
    let VetoResult::Ok { record, .. } = r.undo.veto(&info.id, &VetoBy::Operator("ops".into())) else { panic!() };
    assert_eq!(record["state"], json!("compensation_failed"));
    assert!(record["outcome"]["reason"].as_str().unwrap().contains("the target 'order_id' of the compensation is unknown"));
    assert_eq!(r.calls.lock().unwrap().len(), 0);
}

#[test]
fn finalize_closes_only_due_windows_and_reports_an_effect_never_reported() {
    let r = rig(true, true, true, |_| {});
    let (a, _) = open_window(&r, "orders.update");
    let (b, _) = open_window(&r, "orders.update2");
    r.undo.record_effect(&a.id, None).unwrap();
    assert!(r.undo.finalize_due().unwrap().is_empty(), "the window is still open");
    r.clock.fetch_add(UNDO_MIN_WINDOW_MS * 100, Ordering::SeqCst);
    let mut done = r.undo.finalize_due().unwrap();
    done.sort();
    let mut want = vec![a.id.clone(), b.id.clone()];
    want.sort();
    assert_eq!(done, want);
    assert_eq!(r.undo.get(&a.id).unwrap().unwrap()["state"], json!("finalized"));
    assert!(r.alerts.lock().unwrap().iter().any(|x| x.starts_with("effect_unknown:")), "the second effect was never reported");
    assert!(r.undo.finalize_due().unwrap().is_empty(), "closing is once");
}

#[test]
fn abort_closes_a_window_whose_effect_never_ran_and_reports_map_outcomes() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    let rec = report_undo_effect(&r.undo, &info.id, "failed", None).unwrap();
    assert_eq!(
        (rec["state"].as_str(), rec["outcome"]["status"].as_str(), rec["outcome"]["reason"].as_str()),
        (Some("finalized"), Some("aborted"), Some("effect_failed"))
    );
    let (b, _) = open_window(&r, "orders.update3");
    assert_eq!(report_undo_effect(&r.undo, &b.id, "uncertain", None).unwrap()["state"], json!("open"), "an unknown outcome leaves the window running");
    assert_eq!(report_undo_effect(&r.undo, &b.id, "committed", Some(&json!({"id": "x"}))).unwrap()["effect"]["result"], json!({"id": "x"}));
    assert!(report_undo_effect(&r.undo, "nope", "uncertain", None).is_err());
}

#[test]
fn a_relay_vetoes_are_applied_and_an_unreadable_relay_finalizes_nothing() {
    struct Relay(Mutex<Result<Vec<UndoRelayedVeto>, ()>>);
    impl UndoVetoRelay for Relay {
        fn pending(&self) -> Result<Vec<UndoRelayedVeto>, atlas_pca::undo_store::UndoError> {
            self.0.lock().unwrap().clone().map_err(|_| atlas_pca::undo_store::UndoError::new(UndoErrorCode::Invalid, "relay down"))
        }
    }
    let relay = Arc::new(Relay(Mutex::new(Err(()))));
    let r = rig(true, true, true, |o| o.relay = Some(relay.clone()));
    let (info, _) = open_window(&r, "orders.update");
    r.undo.record_effect(&info.id, None).unwrap();
    r.clock.fetch_add(UNDO_MIN_WINDOW_MS * 100, Ordering::SeqCst);
    assert!(r.undo.finalize_due().unwrap().is_empty());
    assert!(r.alerts.lock().unwrap().iter().any(|a| a.starts_with("veto_relay_failed:")), "a relay that cannot be read finalizes nothing");
    assert_eq!(r.undo.get(&info.id).unwrap().unwrap()["state"], json!("open"));
    // the relay answers with a veto made inside the window: applied as of its time, then compensated
    let rec = r.undo.get(&info.id).unwrap().unwrap();
    let at = rec["opened_at"].as_i64().unwrap() + 10;
    *relay.0.lock().unwrap() = Ok(vec![UndoRelayedVeto { id: info.id.clone(), token: json!(info.token), at }]);
    let out = r.undo.sync_relay().unwrap();
    assert!(matches!(&out[0], VetoResult::Ok { record, .. } if record["state"] == json!("compensated")), "{out:?}");
    // a relayed time in the future is refused
    let VetoResult::Refused { code, .. } = r.undo.veto(&info.id, &VetoBy::Token { token: json!(info.token), at: Some(i64::MAX / 2) }) else { panic!() };
    assert_eq!(code, "malformed");
}

#[test]
fn revocation_keeps_the_window_and_alerts_or_vetoes_by_policy() {
    let keep = rig(true, true, true, |_| {});
    let (info, pc) = open_window(&keep, "orders.update");
    let gref = pc["grant_ref"].as_str().unwrap().to_string();
    assert!(keep.undo.on_revocation(&gref).unwrap().is_empty());
    assert!(keep.alerts.lock().unwrap().iter().any(|a| a.starts_with("revoked_open_window:")));
    assert_eq!(keep.undo.get(&info.id).unwrap().unwrap()["state"], json!("open"));
    assert_eq!(keep.bell.seen.lock().unwrap().last(), Some(&"revoked"));
    let veto = rig(true, true, true, |o| {
        o.policy = Some(Arc::new(|_: &Operation, _: &Value| Some(UndoPolicy { on_revocation: Some("veto".into()), ..Default::default() })))
    });
    let (info, pc) = open_window(&veto, "orders.update");
    veto.undo.record_effect(&info.id, None).unwrap();
    let gref = pc["grant_ref"].as_str().unwrap().to_string();
    assert_eq!(veto.undo.on_revocation(&gref).unwrap(), vec![info.id.clone()]);
    assert_eq!(veto.undo.get(&info.id).unwrap().unwrap()["state"], json!("compensated"));
}

#[test]
fn recovery_finishes_vetoed_records_after_a_restart() {
    let r = rig(true, true, true, |_| {});
    let (info, _) = open_window(&r, "orders.update");
    let VetoResult::Ok { record, .. } = r.undo.veto(&info.id, &VetoBy::Operator("ops".into())) else { panic!() };
    assert_eq!(record["state"], json!("vetoed"), "no effect report yet");
    r.clock.fetch_add(10 * 60_000, Ordering::SeqCst); // past the effect timeout: compensate anyway
    let done = r.undo.recover().unwrap();
    assert!(done.contains(&info.id), "{done:?}");
    assert_eq!(r.undo.get(&info.id).unwrap().unwrap()["state"], json!("compensated"));
}

struct Ledger(Mutex<Vec<String>>);
impl UndoBudgetLedger for Ledger {
    fn commit(&self, key: &str, id: &str) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("commit {key}/{id}"));
        Ok("settled".into())
    }
    fn release(&self, key: &str, id: &str, _e: Option<Value>) -> Result<String, String> {
        self.0.lock().unwrap().push(format!("release {key}/{id}"));
        Ok("denied".into())
    }
}

#[test]
fn held_budget_is_committed_on_finalize_and_released_on_compensation() {
    let ledger = Arc::new(Ledger(Mutex::new(Vec::new())));
    let r = rig(true, true, true, |o| o.budget = Some(ledger.clone()));
    let (a, _) = open_window(&r, "orders.update");
    r.undo.hold_budget(&a.id, &[("agg".to_string(), "r1".to_string())]).unwrap();
    r.undo.record_effect(&a.id, None).unwrap();
    r.undo.veto(&a.id, &VetoBy::Operator("ops".into()));
    assert_eq!(ledger.0.lock().unwrap().as_slice(), &["release agg/r1"]);
    assert!(r.alerts.lock().unwrap().iter().any(|x| x.starts_with("budget_settle_failed:")), "an unsettled outcome is never silent");
    let (b, _) = open_window(&r, "orders.update2");
    r.undo.hold_budget(&b.id, &[("agg".to_string(), "r2".to_string())]).unwrap();
    r.undo.record_effect(&b.id, None).unwrap();
    r.clock.fetch_add(UNDO_MIN_WINDOW_MS * 100, Ordering::SeqCst);
    r.undo.finalize_due().unwrap();
    assert!(ledger.0.lock().unwrap().contains(&"commit agg/r2".to_string()));
    assert!(r.undo.hold_budget(&a.id, &[]).is_err(), "a closed record holds no budget");
}

struct EvLedger(Mutex<Vec<Option<Value>>>);
impl UndoBudgetLedger for EvLedger {
    fn commit(&self, _k: &str, _i: &str) -> Result<String, String> {
        Ok("settled".into())
    }
    fn release(&self, _k: &str, _i: &str, e: Option<Value>) -> Result<String, String> {
        self.0.lock().unwrap().push(e);
        Ok("settled".into())
    }
}

fn release_evidence_seen(evidence: Option<Arc<UndoBudgetEvidence>>) -> Vec<Option<Value>> {
    let ledger = Arc::new(EvLedger(Mutex::new(Vec::new())));
    let r = rig(true, true, true, |o| {
        o.budget = Some(ledger.clone());
        o.budget_evidence = evidence;
    });
    let (a, _) = open_window(&r, "orders.update");
    r.undo.hold_budget(&a.id, &[("agg".to_string(), "r1".to_string())]).unwrap();
    r.undo.record_effect(&a.id, None).unwrap();
    r.undo.veto(&a.id, &VetoBy::Operator("ops".into()));
    let seen = ledger.0.lock().unwrap().clone();
    seen
}

#[test]
fn a_budget_release_carries_no_evidence_unless_the_caller_supplies_it() {
    assert_eq!(release_evidence_seen(None), vec![None]);
}

#[test]
fn the_callers_release_evidence_is_passed_through_with_the_rollback_reason() {
    let ev: Arc<UndoBudgetEvidence> = Arc::new(|r, how| Some(json!({"key": r["key"], "how": how})));
    assert_eq!(release_evidence_seen(Some(ev)), vec![Some(json!({"key": "agg", "how": "rollback"}))]);
}

#[test]
fn a_bond_slash_vetoes_the_record_by_fraud_proof() {
    struct Bonds;
    impl UndoBondSlasher for Bonds {
        fn slash_bond(&self, p: &Value) -> Result<Value, String> {
            Ok(json!({"claim": p["claimId"], "slashed": true}))
        }
    }
    let r = rig(true, true, true, |_| {});
    let (pc, op) = action(&r, "orders.update", json!({}));
    let d = r.undo.admit(&pc, Some(&r.grant), &op, false).unwrap();
    r.undo.open(&d, Some(("claim-1", d.window_end + 5))).unwrap();
    r.undo.record_effect(&d.id, None).unwrap();
    let (settlement, v) = r.undo.rollback_on_slash(&Bonds, &json!({"claimId": "claim-1"})).unwrap();
    assert_eq!(settlement["slashed"], json!(true));
    assert!(
        matches!(v, VetoResult::Ok { ref record, .. } if record["veto"]["via"] == json!("fraud_proof") && record["state"] == json!("compensated")),
        "{v:?}"
    );
    let (_, none) = r.undo.rollback_on_slash(&Bonds, &json!({"claimId": "unknown"})).unwrap();
    assert!(matches!(none, VetoResult::Refused { ref code, .. } if code == "unknown"));
}

#[test]
fn small_helpers_admission_error_signer_public_and_the_hosted_relay() {
    assert_eq!(undo_admission_error(&json!({"id": "a", "window_end": 10, "compensation": {"verb": "x"}})), None);
    assert!(undo_admission_error(&json!("no")).unwrap().contains("must be an object"));
    assert!(undo_admission_error(&json!({"id": "", "window_end": 1, "compensation": {"verb": "x"}})).unwrap().contains("non-empty string of at most 128"));
    assert!(undo_admission_error(&json!({"id": "a", "window_end": -1, "compensation": {"verb": "x"}})).unwrap().contains("non-negative safe integer"));
    assert!(undo_admission_error(&json!({"id": "a", "window_end": 1, "compensation": {"verb": ""}})).unwrap().contains("compensation.verb"));
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&[9u8; 32]);
    assert_eq!(undo_signer_public(&seed), KeyPair::from_seed(&seed).public);
    let seen = Arc::new(Mutex::new(Vec::<(String, Vec<(String, String)>)>::new()));
    let s2 = seen.clone();
    let relay = hosted_undo_veto_relay(
        "https://ledger.example/",
        "sk_test",
        Arc::new(move |url: &str, method: &str, h: &[(String, String)]| {
            assert_eq!(method, "GET");
            s2.lock().unwrap().push((url.to_string(), h.to_vec()));
            Ok((true, 200, json!({"data": [{"record_id": "r1", "veto": {"token": "tok", "at": 5}}]})))
        }),
        Some(1000),
    );
    let got = relay.pending().unwrap();
    assert_eq!(got, vec![UndoRelayedVeto { id: "r1".into(), token: json!("tok"), at: 5 }]);
    assert_eq!(seen.lock().unwrap()[0].0, "https://ledger.example/v1/pca/undo/vetoes?limit=200", "the limit is capped at 200");
    assert!(seen.lock().unwrap()[0].1.iter().any(|(k, v)| k == "authorization" && v == "Bearer sk_test"));
    let bad = hosted_undo_veto_relay("https://x", "k", Arc::new(|_: &str, _: &str, _: &[(String, String)]| Ok((false, 503, json!({})))), None);
    assert!(bad.pending().unwrap_err().message.contains("answered 503"));
    let malformed = hosted_undo_veto_relay(
        "https://x",
        "k",
        Arc::new(|_: &str, _: &str, _: &[(String, String)]| Ok((true, 200, json!({"data": [{"record_id": 1}]})))),
        None,
    );
    assert!(malformed.pending().unwrap_err().message.contains("malformed entry"));
}

// old: a negative effect timeout was accepted, so a vetoed record whose effect was never reported was compensated at once
#[test]
fn a_negative_effect_timeout_is_a_config_error() {
    let r = rig(true, true, true, |_| {});
    let bad = UndoCoordinatorOptions { effect_timeout_ms: Some(-1), insecure_volatile_store: true, ..complete(&r) };
    assert_eq!(create_undo_coordinator(bad).err().unwrap().code, UndoErrorCode::Config);
    let ok = UndoCoordinatorOptions { effect_timeout_ms: Some(0), insecure_volatile_store: true, ..complete(&r) };
    assert!(create_undo_coordinator(ok).is_ok());
}
