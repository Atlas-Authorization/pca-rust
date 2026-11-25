//! `authorize_execution`: the full-policy check for one local execution, over the shared authorize fixtures (the same signed
//! PCActns the plain pipeline is replayed against), plus the binding / configuration / kind mapping of the wrapper.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use atlas_pca::authorize_execution::*;
use atlas_pca::{CheckStatus, MemoryStateStore, Operation};
use serde_json::{json, Value};

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

fn options(d: &Value, grant: &Value, revoked: Arc<AtomicBool>, state: Arc<MemoryStateStore>) -> AuthorizeExecutionOptions {
    AuthorizeExecutionOptions {
        audience: d["audience"].as_str().unwrap().to_string(),
        grant: Some(grant.clone()),
        state: Some(state),
        is_revoked: Some(Arc::new(move |_g: &Value, _p: &Value| Ok(revoked.load(Ordering::SeqCst)))),
        // the fixtures are priced by the calm-risk test seam, as the plain pipeline replay does
        risk: Some(Arc::new(|g: &Value, _p: &Value, pc: &Value| atlas_pca::insecure_calm_risk(&Operation::new("v", "r", json!({})), g, pc).ok())),
        now: d["now"].as_i64().map(|n| Arc::new(move || n) as Arc<dyn Fn() -> i64 + Send + Sync>),
        provenance_mediators: common::harness_pins(),
        ..Default::default()
    }
}

fn step_op(step: &Value) -> ExecutionOperation {
    let op = Operation::from_json(&step["operation"]).unwrap();
    ExecutionOperation {
        verb: op.verb.clone(),
        resource: Some(op.resource.clone()),
        params: op.params.clone(),
        provenance: common::principal_direct(&op).unwrap(),
    }
}

#[test]
fn the_shared_fixtures_decide_as_the_plain_pipeline_does() {
    let d = fixtures();
    for c in d["cases"].as_array().unwrap() {
        let state = Arc::new(MemoryStateStore::new());
        let revoked = Arc::new(AtomicBool::new(false));
        let opts = options(&d, &c["grant"], revoked.clone(), state);
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            revoked.store(s["revoked"].as_bool().unwrap_or(false), Ordering::SeqCst);
            let got = authorize_execution(&s["pcactn"], &step_op(s), &opts);
            let want_allow = s["expect"]["allow"].as_bool().unwrap();
            assert_eq!(got.is_allow(), want_allow, "{} step {i}", c["name"]);
            if let ExecutionDecision::Deny { status, checks, kind, .. } = &got {
                assert_eq!(*status as i64, s["expect"]["status"].as_i64().unwrap(), "{} step {i}", c["name"]);
                let failed: Vec<&str> = checks.iter().flat_map(|m| m.iter()).filter(|(_, s)| **s == CheckStatus::Fail).map(|(k, _)| k.as_str()).collect();
                // the wrapper takes the plan node from the signed PCActn (planOf), so a different executed operation is caught by
                // `operation` / `params_digest`, not by `plan_root_authorized` as in the plain pipeline's operation-built plan
                let want: Vec<&str> = s["expect"]["failed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).filter(|k| *k != "plan_root_authorized").collect();
                // a proof presented for another operation is refused by the wrapper's own binding gate before the pipeline runs: there are no
                // per-check results to compare (the plain pipeline reports the same refusal as a failed `operation` check)
                if *kind == ExecutionDenialKind::Binding {
                    assert!(want.contains(&"operation"), "{} step {i}: a binding refusal stands for the operation check", c["name"]);
                } else {
                    assert_eq!(failed, want, "{} step {i}", c["name"]);
                }
                if checks.as_ref().is_some_and(|m| m.get("revocation") == Some(&CheckStatus::Fail)) && *status == 403 {
                    assert_eq!(*kind, ExecutionDenialKind::Revoked, "{} step {i}", c["name"]);
                }
            }
        }
    }
}

#[test]
fn a_missing_component_denies_every_call_naming_what_is_missing() {
    let o = AuthorizeExecutionOptions::default();
    assert_eq!(missing_execution_components(&o), vec!["audience", "grant or resolveGrant", "state", "isRevoked"]);
    let d = fixtures();
    let s = &d["cases"][0]["steps"][0];
    match authorize_execution(&s["pcactn"], &step_op(s), &o) {
        ExecutionDecision::Deny { kind, status, reason, .. } => {
            assert_eq!((kind, status), (ExecutionDenialKind::Config, 403));
            assert_eq!(reason, "full policy mode is missing audience, grant or resolveGrant, state, isRevoked (fail closed)");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_proof_for_another_operation_is_refused_before_any_state_is_spent() {
    let d = fixtures();
    let c = &d["cases"][0];
    let s = &c["steps"][0];
    let state = Arc::new(MemoryStateStore::new());
    let opts = options(&d, &c["grant"], Arc::new(AtomicBool::new(false)), state.clone());
    let mut wrong = step_op(s);
    wrong.verb = "payments.refund".into();
    match authorize_execution(&s["pcactn"], &wrong, &opts) {
        ExecutionDecision::Deny { kind, status, reason, .. } => {
            assert_eq!((kind, status), (ExecutionDenialKind::Binding, 403));
            assert!(reason.starts_with("the proof is for payments.send on payments/acme, but this call is payments.refund"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    let mut other_resource = step_op(s);
    other_resource.resource = Some("payments/other".into());
    assert!(matches!(authorize_execution(&s["pcactn"], &other_resource, &opts), ExecutionDecision::Deny { kind: ExecutionDenialKind::Binding, .. }));
    // nothing was spent: the same proof is still admissible for its own operation
    assert!(authorize_execution(&s["pcactn"], &step_op(s), &opts).is_allow());
    // and a second presentation is a replay
    match authorize_execution(&s["pcactn"], &step_op(s), &opts) {
        ExecutionDecision::Deny { kind, status, .. } => assert_eq!((kind, status), (ExecutionDenialKind::Replay, 403)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unknown_grant_ref_is_an_authentication_failure_and_a_resolver_error_fails_closed() {
    let d = fixtures();
    let c = &d["cases"][0];
    let s = &c["steps"][0];
    let mut opts = options(&d, &c["grant"], Arc::new(AtomicBool::new(false)), Arc::new(MemoryStateStore::new()));
    opts.grant = None;
    opts.resolve_grant = Some(Arc::new(|_r: &str, _p: &Value| Ok(None)));
    match authorize_execution(&s["pcactn"], &step_op(s), &opts) {
        ExecutionDecision::Deny { kind, status, reason, .. } => {
            assert_eq!((kind, status, reason.as_str()), (ExecutionDenialKind::Authn, 401, "unknown grant_ref"))
        }
        other => panic!("{other:?}"),
    }
    opts.resolve_grant = Some(Arc::new(|_r: &str, _p: &Value| Err("db down".to_string())));
    match authorize_execution(&s["pcactn"], &step_op(s), &opts) {
        ExecutionDecision::Deny { kind, status, reason, .. } => {
            assert_eq!((kind, status, reason.as_str()), (ExecutionDenialKind::Policy, 403, "authorization error (fail closed): db down"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn amount_risk_prices_the_blast_radius_from_the_verified_amount_and_the_grants_kappa() {
    let d = fixtures();
    let grant = &d["cases"][0]["grant"];
    let kappa = atlas_pca::read_envelope(grant).unwrap()["risk_policy"]["kappa"].as_f64().unwrap();
    let r = amount_risk(grant, &json!({"amount": kappa / 4.0}), None).unwrap();
    assert_eq!(r["blastRadius"].as_f64().unwrap(), 0.25);
    assert_eq!(amount_risk(grant, &json!({"amount": kappa * 10.0}), None).unwrap()["blastRadius"].as_f64().unwrap(), 1.0, "clamped to 1");
    assert_eq!(amount_risk(grant, &json!({"amount": -5}), None).unwrap()["blastRadius"].as_f64().unwrap(), 0.0, "clamped to 0");
    assert_eq!(amount_risk(grant, &json!({"total": kappa}), Some("total")).unwrap()["blastRadius"].as_f64().unwrap(), 1.0);
    assert!(amount_risk(grant, &json!({"amount": "12"}), None).is_none(), "a non-number amount prices nothing");
    assert!(amount_risk(grant, &json!({}), None).is_none());
    assert!(amount_risk(&json!({"caveats": []}), &json!({"amount": 1}), None).is_none(), "no envelope, no kappa");
}
