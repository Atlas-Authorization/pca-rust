//! Provenance by default through `authorize` (check `provenance_flow`): on without any configuration, the bundle read from the
//! explicit input, the bundle hook, the `PCA-Provenance` header or the `pca_provenance` body member, the principal's signed
//! `insecure_off` envelope opt-out, and the undo-window admission hook (cases a to f of the cross-feature rule).

mod common;

use std::cell::Cell;
use std::sync::Mutex;

use atlas_pca::agent::{build_pcactn, mint_grant, KeyPair, PcactnInput, Suite};
use atlas_pca::arg_provenance::{encode_provenance_header, principal_direct_provenance, ProvenanceRecorder};
use atlas_pca::undo::{UndoAdmission, UndoCompensationRef};
use atlas_pca::{authorize, params_digest, AuthorizeInput, AuthorizeResult, CheckStatus, MemoryStateStore, Operation, UndoAdmitFn, Verdict, CORE_HOOK};
use serde_json::{json, Map, Value};

// CORE_HOOK is process-global: every test here that authorizes runs one at a time
static SERIAL: Mutex<()> = Mutex::new(());

fn with_hook<T>(h: Option<fn(&mut Verdict)>, f: impl FnOnce() -> T) -> T {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *CORE_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = h;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    *CORE_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = None;
    r.unwrap_or_else(|e| std::panic::resume_unwind(e))
}

struct Fx {
    d: Value,
    grant: Value,
    pcactn: Value,
    op: Operation,
}

/// The first single-step allow case of the shared authorize fixtures (payments.send of $50).
fn fx() -> Fx {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = atlas_pca::strict_parse(&text).unwrap();
    let c = d["cases"].as_array().unwrap().iter().find(|c| c["steps"].as_array().unwrap().len() == 1 && c["steps"][0]["expect"]["allow"] == true).unwrap().clone();
    Fx { grant: c["grant"].clone(), pcactn: c["steps"][0]["pcactn"].clone(), op: Operation::from_json(&c["steps"][0]["operation"]).unwrap(), d }
}

/// What a test varies in the authorize input.
#[derive(Default)]
struct Opt<'a> {
    pins: Option<Vec<Value>>,
    provenance: Option<&'a Value>,
    hook: bool,
    header: Option<&'a str>,
    body: Option<&'a [u8]>,
    answer: Option<&'a Value>,
    undo: Option<&'a UndoAdmitFn<'a>>,
}

fn run(f: &Fx, o: Opt<'_>) -> AuthorizeResult {
    let g = f.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let pins = o.pins.unwrap_or_else(common::harness_pins);
    let input = AuthorizeInput {
        operation: Some(&f.op),
        audience: f.d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: f.d["now"].as_i64(),
        plan: Some("single-step"),
        provenance_mediators: &pins,
        provenance: o.provenance,
        provenance_bundle: o.hook.then_some(&common::principal_direct as &atlas_pca::ProvBundleFn<'_>),
        provenance_header: o.header,
        provenance_body: o.body,
        escalation_answer: o.answer,
        undo: o.undo,
        ..Default::default()
    };
    authorize(Some(&f.pcactn), &input)
}

fn flow(r: &AuthorizeResult) -> Option<CheckStatus> {
    r.check("provenance_flow")
}

fn flow_reason(r: &AuthorizeResult) -> String {
    r.reasons.iter().find(|x| x.starts_with("provenance_flow: ")).cloned().unwrap_or_default()
}

#[test]
fn provenance_flow_is_on_by_default() {
    let f = fx();
    // no bundle, no pins, nothing configured: the agent's choice and every value are untrusted, so the principal must confirm
    let r = with_hook(None, || run(&f, Opt { pins: Some(vec![]), ..Default::default() }));
    assert_eq!((r.allow, r.decision, flow(&r)), (false, "escalate", Some(CheckStatus::Fail)), "{:?}", r.reasons);
    assert_eq!(
        flow_reason(&r),
        "provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, currency derive from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)"
    );
    assert!(r.escalation.as_ref().is_some_and(|e| e["kind"] == "pca-escalation-request"));
    // the gate does not overwrite Intent v2 rule 17's own check
    assert_ne!(r.check("provenance"), Some(CheckStatus::Fail));
}

#[test]
fn provenance_flow_passes_a_principal_direct_bundle_from_every_source() {
    let f = fx();
    let bundle = common::principal_direct(&f.op).unwrap().unwrap();
    let header = encode_provenance_header(&bundle).unwrap();
    let body = serde_json::to_vec(&json!({"amount": 50, "pca_provenance": bundle})).unwrap();
    with_hook(None, || {
        for (name, o) in [
            ("input", Opt { provenance: Some(&bundle), ..Default::default() }),
            ("hook", Opt { hook: true, ..Default::default() }),
            ("header", Opt { header: Some(&header), ..Default::default() }),
            ("body", Opt { body: Some(&body), ..Default::default() }),
        ] {
            let r = run(&f, o);
            assert_eq!((r.allow, flow(&r)), (true, Some(CheckStatus::Pass)), "{name}: {:?}", r.reasons);
            assert!(r.undo.is_none() && r.obligations.is_empty());
        }
    });
}

#[test]
fn provenance_flow_source_order_and_fail_closed_reads() {
    let f = fx();
    let good = common::principal_direct(&f.op).unwrap().unwrap();
    let other = common::principal_direct(&Operation::new("payments.send", "payments/acme", json!({"amount": 99, "currency": "usd"}))).unwrap().unwrap();
    let good_header = encode_provenance_header(&good).unwrap();
    with_hook(None, || {
        // the explicit input wins over the header
        let r = run(&f, Opt { provenance: Some(&other), header: Some(&good_header), ..Default::default() });
        assert!(flow_reason(&r).starts_with("provenance_flow: unbound_action: "), "{:?}", r.reasons);
        assert_eq!((r.allow, r.decision), (false, "deny"), "a forged binding is a deny, never an escalation");
        // an undecodable header fails closed (deny), even with a good body
        let body = serde_json::to_vec(&json!({"pca_provenance": good})).unwrap();
        let r = run(&f, Opt { header: Some("%%%"), body: Some(&body), ..Default::default() });
        assert_eq!(flow_reason(&r), "provenance_flow: the provenance bundle is unreadable (fail closed)");
        assert_eq!((r.allow, r.decision), (false, "deny"));
        // a body that is not JSON carries no bundle: escalate
        let r = run(&f, Opt { body: Some(b"{not json"), ..Default::default() });
        assert_eq!((r.allow, r.decision), (false, "escalate"));
    });
}

#[test]
fn provenance_flow_ignores_an_unpinned_mediator() {
    let f = fx();
    let mut stranger = ProvenanceRecorder::new("someone", "k1", Some([5u8; 32])).unwrap();
    let b = principal_direct_provenance(&mut stranger, &f.op).unwrap();
    let r = with_hook(None, || run(&f, Opt { provenance: Some(&b), ..Default::default() }));
    assert_eq!((r.allow, r.decision), (false, "escalate"), "{:?}", r.reasons);
    // pinned, the same bundle passes
    let r = with_hook(None, || run(&f, Opt { provenance: Some(&b), pins: Some(vec![stranger.pin()]), ..Default::default() }));
    assert!(r.allow, "{:?}", r.reasons);
}

#[test]
fn provenance_flow_observed_and_actions_hooks() {
    let f = fx();
    let g = f.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let pins = common::harness_pins();
    let bundle = common::principal_direct(&f.op).unwrap().unwrap();
    let seen = |_: &Value, _: &Operation, session: Option<&str>| {
        assert!(session.is_some(), "the hook gets the bundle's session");
        vec![json!({"origin": "web", "source": "https://evil.example"})]
    };
    let boom = |_: &Value, _: &Operation, _: Option<&str>| -> Vec<Value> { panic!("observation source down") };
    let read_only = |_: &Operation| Some(json!({"effects": ["read"]}));
    let decide = |observed: Option<&atlas_pca::ProvObservedFn<'_>>, actions: Option<&atlas_pca::ProvActionsFn<'_>>| {
        let store = MemoryStateStore::new();
        let input = AuthorizeInput {
            operation: Some(&f.op),
            audience: f.d["audience"].as_str().unwrap(),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&not_revoked),
            now: f.d["now"].as_i64(),
            plan: Some("single-step"),
            provenance_mediators: &pins,
            provenance: Some(&bundle),
            provenance_observed: observed,
            provenance_actions: actions,
            ..Default::default()
        };
        authorize(Some(&f.pcactn), &input)
    };
    with_hook(None, || {
        // content the server saw reach the agent raises the context: values the principal typed stay trusted ("50", "usd" are in
        // the principal-direct text), the choice does not
        let r = decide(Some(&seen as &atlas_pca::ProvObservedFn<'_>), None);
        assert_eq!(r.decision, "escalate", "{:?}", r.reasons);
        assert!(flow_reason(&r).contains("the choice of payments.send derives from untrusted content [web:https://evil.example]"), "{:?}", r.reasons);
        // the same observation on a read-only action is not a sink
        assert!(decide(Some(&seen as &atlas_pca::ProvObservedFn<'_>), Some(&read_only as &atlas_pca::ProvActionsFn<'_>)).allow);
        // an observation source that fails is a deny (fail closed)
        let r = decide(Some(&boom as &atlas_pca::ProvObservedFn<'_>), None);
        assert_eq!((r.allow, r.decision), (false, "deny"));
        assert_eq!(flow_reason(&r), "provenance_flow: the observation source failed (fail closed)");
    });
}

// ---- the signed envelope opt-out ------------------------------------------------------------------------------------------

const AUD: &str = "assistant-rs";
const NOW: i64 = 1_793_188_800_000;

/// A freshly minted grant (with `extra` envelope members) and a PCActn for `op` under it.
fn minted(extra: Value, op: &Operation) -> Result<(Value, Value), String> {
    let principal = KeyPair::from_seed(&[11u8; 32]);
    let holder = KeyPair::from_seed(&[12u8; 32]);
    let mut env = json!({"predicates": [{"verb": "payments.send", "resource": "payments/*"}], "caveats": [], "agent_binding": {},
        "risk_policy": {"bMax": 1000, "kappa": 1, "lambda": 0, "rho": 0, "theta1": 0.5, "theta2": 0.8,
            "weights": {"alpha": 0, "beta": 0, "delta": 0, "epsilon": 0, "gamma": 0, "zeta": 0}}});
    for (k, v) in extra.as_object().unwrap() {
        env[k] = v.clone();
    }
    let grant = mint_grant(&principal, &holder.public, &env, "run my errands", Some("c2FsdA"), None, &Suite::default())?.grant;
    let node = json!({"id": "n1", "verb": op.verb, "resource": op.resource, "params_digest": params_digest(Some(&op.params)), "reversibility_class": "irreversible"});
    let pcactn = build_pcactn(&PcactnInput {
        grant: &grant,
        chain: &[grant.clone()],
        plan: &[node],
        node_id: "n1",
        params: Some(&op.params),
        counter: 1,
        signer: &holder,
        aud: AUD,
        iat: NOW,
        exp: None,
        extra: Map::new(),
        suite: Suite::default(),
    })?;
    Ok((grant, pcactn))
}

fn run_minted(grant: &Value, pcactn: &Value, op: &Operation) -> AuthorizeResult {
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(op),
        audience: AUD,
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: Some(NOW),
        plan: Some("single-step"),
        ..Default::default()
    };
    authorize(Some(pcactn), &input)
}

#[test]
fn provenance_flow_insecure_off_is_the_only_opt_out() {
    let op = Operation::new("payments.send", "payments/acme", json!({"amount": 50, "currency": "usd"}));
    with_hook(None, || {
        // this is the one test that turns the gate off: the principal-signed envelope member, nothing else
        let (g, p) = minted(json!({"provenance": {"mode": "insecure_off"}}), &op).unwrap();
        let r = run_minted(&g, &p, &op);
        assert_eq!((r.allow, flow(&r)), (true, Some(CheckStatus::NotEnforced)), "{:?}", r.reasons);
        for extra in [json!({"provenance": {"mode": "enforce"}}), json!({})] {
            let (g, p) = minted(extra.clone(), &op).unwrap();
            let r = run_minted(&g, &p, &op);
            assert_eq!((r.decision, flow(&r)), ("escalate", Some(CheckStatus::Fail)), "{extra}: {:?}", r.reasons);
        }
        // mediators the principal designates in the envelope are pinned for that grant
        let mut rec = ProvenanceRecorder::new("principal-harness", "k1", Some([13u8; 32])).unwrap();
        let (g, p) = minted(json!({"provenance": {"mediators": [rec.pin()]}}), &op).unwrap();
        let bundle = principal_direct_provenance(&mut rec, &op).unwrap();
        let gg = g.clone();
        let resolve = move |_: &str| Ok::<_, String>(Some(gg.clone()));
        let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
        let store = MemoryStateStore::new();
        let input = AuthorizeInput {
            operation: Some(&op),
            audience: AUD,
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&not_revoked),
            now: Some(NOW),
            plan: Some("single-step"),
            provenance: Some(&bundle),
            ..Default::default()
        };
        let r = authorize(Some(&p), &input);
        assert_eq!((r.allow, flow(&r)), (true, Some(CheckStatus::Pass)), "{:?}", r.reasons);
    });
    // a malformed member cannot be minted
    assert!(minted(json!({"provenance": {"mode": "off"}}), &op).unwrap_err().contains("provenance"));
}

// ---- the undo admission hook (a)-(f) ----------------------------------------------------------------------------------------

fn inject_facts_escalate(core: &mut Verdict) {
    core.checks.insert("facts".into(), false);
    core.allow = false;
    core.reason = "facts: intent_required: which order?".into();
    core.reasons = vec!["facts: intent_required: which order?".into()];
}

fn inject_rule17(core: &mut Verdict) {
    core.checks.insert("provenance".into(), false);
    core.allow = false;
    core.reason = "provenance: intent_required: a question is required".into();
    core.reasons = vec!["provenance: intent_required: a question is required".into()];
}

fn inject_hard(core: &mut Verdict) {
    inject_facts_escalate(core);
    core.checks.insert("leaf_signature".into(), false);
    core.reasons.push("leaf_signature: the leaf signature does not verify".into());
}

const WINDOW_END: i64 = 1_800_000_900_000;

fn admission() -> UndoAdmission {
    UndoAdmission { id: "op_1".into(), window_end: WINDOW_END, compensation: UndoCompensationRef { verb: "payments.refund".into(), resource: "payments/acme".into() } }
}

#[test]
fn undo_a_escalation_with_an_admitting_hook_runs_under_a_window() {
    let f = fx();
    let calls = Cell::new(0);
    let seen: Cell<Option<(String, String)>> = Cell::new(None);
    let admit = |p: &Value, g: &Value, op: &Operation| {
        calls.set(calls.get() + 1);
        assert_eq!(p["grant_ref"], g["id"], "the hook gets the PCActn and its grant");
        seen.set(Some((op.verb.clone(), op.resource.clone())));
        Ok::<_, String>(Some(admission()))
    };
    let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { hook: true, undo: Some(&admit), ..Default::default() }));
    assert_eq!(calls.get(), 1);
    assert_eq!(seen.take(), Some(("payments.send".to_string(), "payments/acme".to_string())), "the hook gets the bound operation");
    assert_eq!((r.allow, r.decision, r.status), (true, "allow", 200), "{:?}", r.reasons);
    assert!(r.escalation.is_none(), "the escalation request is dropped");
    assert_eq!(r.undo, Some(admission()));
    assert_eq!(r.obligations, vec![json!({"kind": "undo_window", "params": {"id": "op_1", "window_end": WINDOW_END}, "due": WINDOW_END})]);
    assert_eq!((r.check("undo_window"), r.check("facts")), (Some(CheckStatus::Pass), Some(CheckStatus::Pass)));
    assert!(r.checks.values().all(|c| *c != CheckStatus::Fail));
    assert!(r.reasons.contains(&format!("undo_window: runs now under a veto window until {WINDOW_END} (compensation payments.refund)")), "{:?}", r.reasons);
    // the allow spent the replay counter: the same PCActn again is a replay, not a second window
    let again = with_hook(Some(inject_facts_escalate), || {
        let g = f.grant.clone();
        let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
        let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
        let store = MemoryStateStore::new();
        let pins = common::harness_pins();
        let input = AuthorizeInput {
            operation: Some(&f.op),
            audience: f.d["audience"].as_str().unwrap(),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&not_revoked),
            now: f.d["now"].as_i64(),
            plan: Some("single-step"),
            provenance_mediators: &pins,
            provenance_bundle: Some(&common::principal_direct),
            undo: Some(&admit),
            ..Default::default()
        };
        let first = authorize(Some(&f.pcactn), &input);
        (first.allow, authorize(Some(&f.pcactn), &input))
    });
    assert!(again.0);
    assert_eq!((again.1.allow, again.1.check("replay")), (false, Some(CheckStatus::Fail)));
}

#[test]
fn undo_b_provenance_flow_escalation_never_reaches_the_hook() {
    let f = fx();
    let calls = Cell::new(0);
    let admit = |_: &Value, _: &Value, _: &Operation| {
        calls.set(calls.get() + 1);
        Ok::<_, String>(Some(admission()))
    };
    // no bundle: provenance_flow escalates on its own, and together with another escalate-class failure
    for hook in [None, Some(inject_facts_escalate as fn(&mut Verdict))] {
        let r = with_hook(hook, || run(&f, Opt { undo: Some(&admit), ..Default::default() }));
        assert_eq!((r.allow, r.decision, flow(&r)), (false, "escalate", Some(CheckStatus::Fail)), "{:?}", r.reasons);
        assert!(r.undo.is_none() && r.obligations.is_empty());
    }
    assert_eq!(calls.get(), 0);
}

#[test]
fn undo_c_rule_17_provenance_failure_never_reaches_the_hook() {
    let f = fx();
    let calls = Cell::new(0);
    let admit = |_: &Value, _: &Value, _: &Operation| {
        calls.set(calls.get() + 1);
        Ok::<_, String>(Some(admission()))
    };
    let r = with_hook(Some(inject_rule17), || run(&f, Opt { hook: true, undo: Some(&admit), ..Default::default() }));
    assert_eq!((r.allow, r.decision, r.check("provenance")), (false, "escalate", Some(CheckStatus::Fail)), "{:?}", r.reasons);
    assert_eq!(flow(&r), Some(CheckStatus::Pass));
    assert_eq!(calls.get(), 0);
}

#[test]
fn undo_d_a_presented_answer_never_reaches_the_hook() {
    let f = fx();
    let calls = Cell::new(0);
    let admit = |_: &Value, _: &Value, _: &Operation| {
        calls.set(calls.get() + 1);
        Ok::<_, String>(Some(admission()))
    };
    // an answer that does not admit (no principal is pinned) leaves the escalation standing; the hook is not a fallback for it
    let answer = json!({"v": 1, "kind": "pca-escalation-answer", "decision": "allow"});
    let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { hook: true, answer: Some(&answer), undo: Some(&admit), ..Default::default() }));
    assert_eq!((r.allow, r.decision), (false, "escalate"), "{:?}", r.reasons);
    assert_eq!(calls.get(), 0);
    // a JSON null is no answer: the hook runs
    let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { hook: true, answer: Some(&Value::Null), undo: Some(&admit), ..Default::default() }));
    assert!(r.allow);
    assert_eq!(calls.get(), 1);
}

#[test]
fn undo_e_a_failing_hook_leaves_the_escalation_standing() {
    let f = fx();
    let err = |_: &Value, _: &Value, _: &Operation| Err::<Option<UndoAdmission>, String>("the ledger is down".into());
    let none = |_: &Value, _: &Value, _: &Operation| Ok::<Option<UndoAdmission>, String>(None);
    let panics = |_: &Value, _: &Value, _: &Operation| -> Result<Option<UndoAdmission>, String> { panic!("hook bug") };
    let malformed = |_: &Value, _: &Value, _: &Operation| {
        let mut a = admission();
        a.id = "x".repeat(129);
        Ok::<_, String>(Some(a))
    };
    let negative = |_: &Value, _: &Value, _: &Operation| {
        let mut a = admission();
        a.window_end = -1;
        Ok::<_, String>(Some(a))
    };
    let hooks: [(&str, &UndoAdmitFn<'_>); 5] = [("err", &err), ("none", &none), ("panic", &panics), ("129-char id", &malformed), ("negative end", &negative)];
    for (name, h) in hooks {
        let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { hook: true, undo: Some(h), ..Default::default() }));
        assert_eq!((r.allow, r.decision), (false, "escalate"), "{name}: {:?}", r.reasons);
        assert!(r.escalation.is_some() && r.undo.is_none() && r.obligations.is_empty(), "{name}");
        assert_eq!(r.check("undo_window"), None, "{name}");
    }
}

#[test]
fn undo_f_a_deny_never_reaches_the_hook() {
    let f = fx();
    let calls = Cell::new(0);
    let admit = |_: &Value, _: &Value, _: &Operation| {
        calls.set(calls.get() + 1);
        Ok::<_, String>(Some(admission()))
    };
    let r = with_hook(Some(inject_hard), || run(&f, Opt { hook: true, undo: Some(&admit), ..Default::default() }));
    assert_eq!((r.allow, r.decision), (false, "deny"), "{:?}", r.reasons);
    // a forged provenance bundle is a deny too
    let forged = common::principal_direct(&Operation::new("payments.send", "payments/acme", json!({"amount": 1}))).unwrap().unwrap();
    let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { provenance: Some(&forged), undo: Some(&admit), ..Default::default() }));
    assert_eq!((r.allow, r.decision), (false, "deny"), "{:?}", r.reasons);
    assert_eq!(calls.get(), 0);
}

#[test]
fn undo_without_a_hook_is_off() {
    let f = fx();
    let r = with_hook(Some(inject_facts_escalate), || run(&f, Opt { hook: true, ..Default::default() }));
    assert_eq!((r.allow, r.decision, r.check("undo_window")), (false, "escalate", None));
}

/// The same hook through the request guard (`AuthorizeOptions::with_undo`) and the `PCA-Provenance` header the guard reads.
#[cfg(feature = "axum")]
mod guard {
    use super::*;
    use atlas_pca::middleware::{authorize_request, authorize_request_provenance, GuardConfig};
    use atlas_pca::AuthorizeOptions;
    use base64::Engine;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn cfg(f: &Fx, calls: Arc<AtomicUsize>) -> GuardConfig {
        let (g, op, now) = (f.grant.clone(), f.op.clone(), f.d["now"].as_i64().unwrap());
        GuardConfig::new(f.d["audience"].as_str().unwrap().to_string(), move |_: &str| Some(g.clone()))
            .with_clock(move || now)
            .with_authorize(
                AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false))
                    .with_provenance_mediators(common::harness_pins())
                    .with_undo(move |_: &Value, _: &Value, _: &Operation| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Some(admission()))
                    }),
            )
            .with_operation(move |_, _| Some(op.clone()))
    }

    fn header(p: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(atlas_pca::canonicalize_strict(p).unwrap().as_bytes())
    }

    #[test]
    fn undo_guard_admits_and_provenance_header_is_read() {
        let f = fx();
        let calls = Arc::new(AtomicUsize::new(0));
        let prov = encode_provenance_header(&common::principal_direct(&f.op).unwrap().unwrap()).unwrap();
        let r = with_hook(Some(inject_facts_escalate), || {
            authorize_request_provenance(Some(&header(&f.pcactn)), None, Some(f.op.clone()), &cfg(&f, calls.clone()), None, None, None, Some(&prov))
        });
        let a = r.authorization.as_ref().unwrap();
        assert!(r.allow, "{:?}", a.reasons);
        assert_eq!((a.undo.clone(), a.obligations.len()), (Some(admission()), 1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // without the header the gate escalates and the hook is never reached
        let r = with_hook(Some(inject_facts_escalate), || authorize_request(Some(&header(&f.pcactn)), None, Some(f.op.clone()), &cfg(&f, calls.clone())));
        assert_eq!((r.allow, r.authorization.as_ref().unwrap().decision), (false, "escalate"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
