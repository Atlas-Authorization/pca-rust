//! RT-06 regression: the journal must commit the context the gate evaluated (now, subject, env, rate
//! history, delegation depth, tool binding, risk inputs, budget, floor, root principal, leaf PCActn),
//! and a verifier must be able to pin it. PoC: redteam/stark/src/zkvm_unbound_context.rs.
use pca_zkvm_core::{context::{check_context, ContextMismatch, ExpectedContext}, decide_from_str, Decision};
use serde_json::{json, Value};

fn sample() -> Value {
    serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap()
}
fn run(v: &Value) -> Decision {
    decide_from_str(&v.to_string())
}
fn expected(v: &Value) -> ExpectedContext {
    ExpectedContext::from_input_json(&v.to_string(), 0.0).expect("input parses")
}

#[test]
fn backdated_now_yields_a_different_journal() {
    let base = sample();
    let honest = run(&base);
    let mut backdated = base.clone();
    backdated["now"] = json!(1_000_000_000_000u64);
    let b = run(&backdated);
    assert_ne!(honest, b, "RT-06: now is not in the journal");
}

#[test]
fn every_context_input_moves_the_journal() {
    let base = sample();
    let want = run(&base);
    let edits: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("subject", Box::new(|v| v["subject"] = json!({"role": "admin"}))),
        ("env", Box::new(|v| v["env"] = json!({"current_device": "dev-EVIL"}))),
        ("recent_action_times", Box::new(|v| v["recent_action_times"] = json!([]))),
        // R3-12: depth is derived from the chain, so the journal-moving edit is the chain, not a scalar
        ("derived delegation depth", Box::new(|v| { let c = v["chain"].as_array().unwrap()[..1].to_vec(); v["chain"] = json!(c); })),
        ("node_id", Box::new(|v| v["pcactn"]["plan"]["node_id"] = json!("n2"))),
        ("grant_ref", Box::new(|v| v["chain"][0]["id"] = json!("other"))),
        ("tool_binding", Box::new(|v| v["tool_binding"] = json!("x"))),
        ("budget", Box::new(|v| v["budget_scaled"] = json!(999_999))),
        ("r_floor", Box::new(|v| v["r_floor_scaled"] = json!(1))),
        ("risk_inputs", Box::new(|v| v["risk_inputs_scaled"][0] = json!(0))),
    ];
    for (name, f) in edits {
        let mut v = base.clone();
        f(&mut v);
        assert_ne!(run(&v).context, want.context, "{name} is not committed in the journal context");
    }
}

#[test]
fn verifier_rejects_a_receipt_whose_now_is_not_the_verifier_clock() {
    let base = sample();
    let journal = run(&base);
    let mut exp = expected(&base);
    check_context(&journal, &exp).expect("matching context accepted");
    // verifier clock is 1 day later than the proven `now`, tolerance 1 minute
    exp.now = 1_760_000_000_000.0 + 86_400_000.0;
    exp.now_tolerance_ms = 60_000.0;
    assert!(matches!(check_context(&journal, &exp), Err(ContextMismatch::Now { .. })));
    exp.now_tolerance_ms = 2.0 * 86_400_000.0;
    // R4-04: within the clock tolerance, but the PCActn (exp = proven now + 20 min) is long expired on the verifier's clock
    assert_eq!(check_context(&journal, &exp), Err(ContextMismatch::PcactnExpired));
    exp.now = 1_760_000_000_000.0 + 600_000.0;
    check_context(&journal, &exp).expect("within tolerance and inside the PCActn window");
}

#[test]
fn verifier_rejects_each_mismatched_pinned_value() {
    let base = sample();
    let journal = run(&base);
    let mut e = expected(&base);
    e.subject = Some(json!({"role": "admin"}));
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::Subject)));
    let mut e = expected(&base);
    e.env = Some(json!({"current_device": "dev-EVIL"}));
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::Env)));
    let mut e = expected(&base);
    e.recent_action_times = Some(vec![]);
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::RateHistory)));
    let mut e = expected(&base);
    e.delegation_depth = 0;
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::DelegationDepth)));
    let mut e = expected(&base);
    e.grant_ref = "other".into();
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::GrantRef)));
    let mut e = expected(&base);
    e.node_id = "n2".into();
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::NodeId)));
    let mut e = expected(&base);
    e.risk_inputs_scaled = [0; 6];
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::RiskInputs)));
    let mut e = expected(&base);
    e.budget_scaled += 1;
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::Budget)));
    let mut e = expected(&base);
    e.policy_commit = "other".into();
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::PolicyCommit)));
    let mut e = expected(&base);
    e.action_commit = "other".into();
    assert!(matches!(check_context(&journal, &e), Err(ContextMismatch::ActionCommit)));
}

#[test]
fn denied_or_chain_unverified_journals_never_pass() {
    let mut base = sample();
    let exp = expected(&base);
    base["action"]["verb"] = json!("delete");
    let j = run(&base);
    assert!(matches!(check_context(&j, &exp), Err(ContextMismatch::NotAllowed)));
}

#[test]
fn an_empty_failed_parse_journal_has_an_empty_context_and_is_not_allowed() {
    let j = decide_from_str("not json");
    assert_eq!(j.allow, 0);
    assert!(check_context(&j, &expected(&sample())).is_err());
}
