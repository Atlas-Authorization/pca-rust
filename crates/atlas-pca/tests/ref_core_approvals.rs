//! Differential replay of the agent-facing half of approvals (review, goal lineage, batch review, time-boxing) against the TypeScript
//! reference (test-data/ref-core-approvals-java.json.gz). Keys are sha256("atlas-pca-conformance/approvals/" + label) seeds.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::approvals::*;
use atlas_pca::facade::{create_agent, AgentHandle, AgentOptions};
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn key(label: &str) -> KeyPair {
    let h = Sha256::digest(format!("atlas-pca-conformance/approvals/{label}").as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&h);
    KeyPair::from_seed(&seed)
}

fn build(spec: &Value) -> AgentHandle {
    let principal = key(spec["principal"].as_str().unwrap());
    let mut o = AgentOptions::new(&principal, spec["goal"].as_str().unwrap(), &spec["permissions"]);
    o.holder = Some(key(spec["holder"].as_str().unwrap()));
    o.goal_salt = spec["goalSalt"].as_str();
    o.limits = spec.get("limits").filter(|v| v.is_object());
    o.risk_policy = spec.get("riskPolicy").filter(|v| v.is_object());
    o.budget_model = spec.get("budgetModel").and_then(Value::as_str);
    o.aud = spec.get("aud").and_then(Value::as_str);
    o.now = spec["now"].as_i64();
    create_agent(o).expect("agent")
}

fn render_for(mode: &str, verb: &str, resource: &str) -> Result<Value, String> {
    match mode {
        "throw" => Err("boom".into()),
        "badshape" => Ok(json!({"v": 2})),
        _ => Ok(json!({"v": 1, "kind": "pca-approval-render", "verb": verb, "def_digest": "A".repeat(43), "unreviewed": true,
            "fields": [{"id": "resource", "class": "param", "value": resource}]})),
    }
}

fn veq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x == y || x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| veq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| veq(v, w))),
        _ => a == b,
    }
}

fn with_opts<T>(o: &Value, f: impl FnOnce(&ReviewOptions) -> T) -> T {
    let mode = o.get("renderer").and_then(Value::as_str).map(str::to_string);
    let renderer = mode.as_deref().map(|m| move |verb: &str, resource: &str, _: Option<&Value>| render_for(m, verb, resource));
    let standing: Vec<Value> = o.get("standing").and_then(Value::as_array).cloned().unwrap_or_default();
    let ro = ReviewOptions {
        now: o.get("now").and_then(Value::as_i64),
        goal: o.get("goal").and_then(Value::as_str),
        standing: &standing,
        renderer: renderer.as_ref().map(|r| r as Renderer<'_>),
        insecure_unbound_approval: o.get("insecure") == Some(&json!(true)),
    };
    f(&ro)
}

fn opt_params(v: &Value) -> Option<&Value> {
    Some(v).filter(|p| !p.is_null())
}

#[test]
fn approvals_match_the_reference() {
    let cases = common::ref_cases("core-approvals-java");
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    for c in &cases {
        let (name, a) = (c["name"].as_str().unwrap(), c["args"].as_array().unwrap());
        let f = c["fn"].as_str().unwrap();
        let got = match f {
            "reviewAction" => with_opts(&a[4], |ro| {
                review_action_checked(&build(&a[0]), a[1].as_str().unwrap(), a[2].as_str().unwrap(), opt_params(&a[3]), ro).unwrap_or_else(|e| json!({"$throws": e}))
            }),
            "batchReview" => with_opts(&a[2], |ro| json!(batch_review(&build(&a[0]), a[1].as_array().unwrap(), ro))),
            "buildGoalLineage" => {
                build_goal_lineage(&build(&a[0]), a[1].as_str().unwrap(), a[2].as_str().unwrap(), opt_params(&a[3]), a[4].get("goal").and_then(Value::as_str))
            }
            "describeGoalLineage" => describe_goal_lineage_values(&a[0]).map_or_else(|e| json!({"$throws": e}), |l| json!(l)),
            "timeBox" => time_box(&a[0], &key(a[1].as_str().unwrap()), a[2].as_f64().unwrap(), a[3].as_f64()).unwrap_or_else(|e| json!({"$throws": e})),
            other => panic!("unreplayed fn {other}"),
        };
        assert!(veq(&c["out"], &got), "{name}: want {} got {got}", c["out"]);
        *seen.entry(f.to_string()).or_default() += 1;
    }
    for f in ["reviewAction", "buildGoalLineage", "describeGoalLineage", "batchReview", "timeBox"] {
        assert!(seen.get(f).copied().unwrap_or(0) > 0, "{f} not replayed");
    }
}

#[test]
fn standing_class_approvals_and_decisions() {
    let a = approve_class(&["stripe.refund", "gmail.send"], 3_600_000, "ops@example.com", Some(1_000), Some("acct:*"));
    assert!(class_approval_covers(&a, "stripe.refund", "acct:42", 1_000));
    assert!(class_approval_covers(&a, "gmail.send", "acct:", 3_599_999));
    assert!(!class_approval_covers(&a, "stripe.refund", "acct:42", 3_601_000), "expired at granted + ttl");
    assert!(!class_approval_covers(&a, "stripe.refund", "acct:42", 999), "not yet granted");
    assert!(!class_approval_covers(&a, "stripe.payout", "acct:42", 1_000), "verb not covered");
    assert!(!class_approval_covers(&a, "stripe.refund", "other", 1_000), "resource prefix");
    assert!(covered_by_any(&[a.clone()], "gmail.send", "acct:1", 2_000));
    assert!(!covered_by_any(&[], "gmail.send", "acct:1", 2_000));
    let any = approve_class(&["x.y"], 10, "me", Some(0), None);
    assert!(class_approval_covers(&any, "x.y", "anything", 5));
    // the id does not depend on the order the verbs were listed in
    assert_eq!(approve_class(&["b", "a"], 1, "m", Some(0), None)["id"], approve_class(&["a", "b"], 1, "m", Some(0), None)["id"]);
    let d = record_decision(&json!({"id": "req-1"}), "approve", "ops", Some(7));
    assert_eq!(d, json!({"requestId": "req-1", "decision": "approve", "by": "ops", "at": 7}));
    let reviews = vec![json!({"kind": "auto"}), json!({"kind": "step_up", "request": {"id": "r"}}), json!({"kind": "deny", "reason": "x"})];
    assert_eq!(pending_requests(&reviews), vec![json!({"id": "r"})]);
}

#[test]
fn a_cosign_recharges_the_budget() {
    use atlas_pca::risk::{RiskPolicy, TrustBudget};
    let p = RiskPolicy::from_value(&atlas_pca::agent::default_risk_policy()).unwrap();
    let low = TrustBudget { b: 0.0, tau: 0.0, as_of: Some(0.0) };
    let part = apply_cosign(&low, &p, 5.0, false);
    assert!(part.b > 0.0 && part.b <= p.b_max && part.tau == 5.0);
    let full = apply_cosign(&low, &p, 9.0, true);
    assert_eq!((full.b, full.tau), (p.b_max, 9.0));
}
