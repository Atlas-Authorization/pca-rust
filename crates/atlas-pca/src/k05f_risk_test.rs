//! F2: the risk functional, threshold map, trust budget and the release decision, pinned against packages/pca/src/risk.test.ts and
//! the policy VM (policy-vm.ts steps 3-5, the Dafny kernels). Every boundary is inclusive or exclusive exactly as the reference has it.
use super::*;
use serde_json::json;

const P: RiskPolicy = DEFAULT_RISK_POLICY;
const CALM: RiskInputs = RiskInputs { semantic_distance: 0.0, reversibility: 1.0, blast_radius: 0.0, taint: 0.0, confidence: 1.0, age: 0.0 };

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

fn bud(b: f64, tau: f64) -> TrustBudget {
    TrustBudget { b, tau, as_of: None }
}

#[test]
fn risk_score_is_zero_for_calm_and_clamped_for_worst() {
    let w = P.weights;
    assert_eq!(risk_score(&CALM, &w), 0.0);
    assert!(close(risk_score(&WORST, &w), 1.0));
    let big = RiskWeights { alpha: 5.0, beta: 5.0, gamma: 5.0, delta: 5.0, epsilon: 5.0, zeta: 5.0 };
    assert_eq!(risk_score(&WORST, &big), 1.0);
    // out of range clamps, NaN fails closed (taint -> 1, confidence -> 0), negative weights are ignored
    let taint = |t: f64| risk_score(&RiskInputs { taint: t, ..CALM }, &w);
    assert_eq!(taint(7.0), taint(1.0));
    assert_eq!(taint(f64::NAN), taint(1.0));
    assert_eq!(taint(-3.0), taint(0.0));
    assert_eq!(risk_score(&RiskInputs { confidence: f64::NAN, ..CALM }, &w), risk_score(&RiskInputs { confidence: 0.0, ..CALM }, &w));
    assert_eq!(risk_score(&RiskInputs { taint: 1.0, ..CALM }, &RiskWeights { delta: -3.0, ..w }), 0.0);
    assert_eq!(risk_score(&RiskInputs { taint: 1.0, ..CALM }, &RiskWeights { delta: f64::NAN, ..w }), 0.0);
    // each input counts with its own weight
    let one = |i: RiskInputs| risk_score(&i, &RiskWeights { alpha: 0.5, beta: 0.25, gamma: 0.125, delta: 0.0625, epsilon: 0.03125, zeta: 0.015625 });
    assert_eq!(one(RiskInputs { semantic_distance: 1.0, ..CALM }), 0.5);
    assert_eq!(one(RiskInputs { reversibility: 0.0, ..CALM }), 0.25);
    assert_eq!(one(RiskInputs { blast_radius: 1.0, ..CALM }), 0.125);
    assert_eq!(one(RiskInputs { taint: 1.0, ..CALM }), 0.0625);
    assert_eq!(one(RiskInputs { confidence: 0.0, ..CALM }), 0.03125);
    assert_eq!(one(RiskInputs { age: 1.0, ..CALM }), 0.015625);
}

#[test]
fn risk_score_is_monotone_in_every_input() {
    let w = P.weights;
    let incr: [fn(f64) -> RiskInputs; 4] = [|v| RiskInputs { semantic_distance: v, ..CALM }, |v| RiskInputs { blast_radius: v, ..CALM }, |v| RiskInputs { taint: v, ..CALM }, |v| RiskInputs { age: v, ..CALM }];
    for f in incr {
        let mut prev = -1.0;
        for v in [0.0, 0.2, 0.5, 0.9, 1.0] {
            let r = risk_score(&f(v), &w);
            assert!(r >= prev);
            prev = r;
        }
        assert!(risk_score(&f(1.0), &w) > 0.0);
    }
    let decr: [fn(f64) -> RiskInputs; 2] = [|v| RiskInputs { reversibility: v, ..CALM }, |v| RiskInputs { confidence: v, ..CALM }];
    for f in decr {
        let mut prev = 2.0;
        for v in [0.0, 0.2, 0.5, 0.9, 1.0] {
            let r = risk_score(&f(v), &w);
            assert!(r <= prev);
            prev = r;
        }
    }
}

#[test]
fn the_threshold_bands_are_inclusive_on_the_lower_tier() {
    let rt = |r: f64, irr: bool| required_threshold(r, 0.25, 0.6, irr);
    assert_eq!(rt(0.0, false), RequiredThreshold { t: 1, proof: 0, optimistic_allowed: true });
    assert_eq!(rt(0.25, false).t, 1);
    assert_eq!(rt(0.2501, false), RequiredThreshold { t: 2, proof: 1, optimistic_allowed: false });
    assert_eq!(rt(0.6, false).t, 2);
    assert_eq!(rt(0.6001, false), RequiredThreshold { t: 3, proof: 2, optimistic_allowed: false });
    assert_eq!(rt(f64::NAN, false).t, 3);
    assert_eq!(rt(f64::INFINITY, false).t, 3);
    assert_eq!(rt(f64::NEG_INFINITY, false).t, 3, "a non-finite r is the worst case, whatever its sign");
    assert!(!rt(0.1, true).optimistic_allowed, "irreversible is never optimistic");
    assert_eq!((rt(0.25, false).proof_name(), rt(0.5, false).proof_name(), rt(0.9, false).proof_name()), ("claim", "standard", "strong"));
    let mut prev = 0;
    for i in 0..=100 {
        let t = rt(i as f64 / 100.0, false).t;
        assert!(t >= prev);
        prev = t;
    }
}

#[test]
fn escalation_never_lowers_and_keeps_the_threshold_coherent() {
    let t1 = required_threshold(0.0, 0.25, 0.6, false);
    assert_eq!(escalate_threshold(t1, 1), t1);
    assert_eq!(escalate_threshold(t1, 2), RequiredThreshold { t: 2, proof: 1, optimistic_allowed: false });
    assert_eq!(escalate_threshold(t1, 3), RequiredThreshold { t: 3, proof: 2, optimistic_allowed: false });
    let t3 = required_threshold(0.9, 0.25, 0.6, false);
    assert_eq!(escalate_threshold(t3, 1), t3, "never lowers");
    assert_eq!(escalate_threshold(t3, 2), t3);
    // a stronger proof than the floor is kept
    let odd = RequiredThreshold { t: 1, proof: 2, optimistic_allowed: true };
    assert_eq!(escalate_threshold(odd, 2), RequiredThreshold { t: 2, proof: 2, optimistic_allowed: false });
}

#[test]
fn cost_debit_and_leak() {
    assert!(close(cost(0.2, 2.0), 0.4));
    assert_eq!(cost(f64::NAN, 2.0), 2.0, "a non-finite r costs r = 1");
    assert_eq!(cost(0.5, -1.0), 0.0);
    assert_eq!(cost(7.0, 2.0), 2.0);
    let b0 = bud(1.0, 0.0);
    assert!(close(debit(&b0, 0.3).b, 0.7));
    assert_eq!(debit(&b0, 5.0).b, 0.0);
    assert_eq!(debit(&b0, f64::NAN).b, 1.0);
    let l = leak(&b0, 1_000_000.0, 0.0005);
    assert!(close(l.b, 0.5));
    assert!(close(leak(&l, 1_000_000.0, 0.0005).b, 0.5), "idempotent at the same now");
    assert!(close(leak(&l, 2_000_000.0, 0.0005).b, 0.0));
    assert_eq!(leak(&b0, -5.0, 1.0).b, 1.0, "time going backwards: no change");
    assert_eq!(l.tau, 0.0, "a leak is not a human touch");
    assert_eq!(l.as_of, Some(1_000_000.0));
    assert!(leak(&bud(f64::NAN, 0.0), 10.0, 1.0).b.is_nan(), "Math.max(0, NaN) is NaN, so a NaN budget never covers a cost");
}

#[test]
fn recharge_caps_at_b_max_and_resets_tau() {
    let low = bud(0.2, 0.0);
    assert_eq!(recharge(&low, 0.5, 1.0, 99.0), TrustBudget { b: 0.7, tau: 99.0, as_of: Some(99.0) });
    assert_eq!(recharge(&low, 5.0, 1.0, 99.0).b, 1.0);
    assert_eq!(recharge_full(1.0, 7.0), TrustBudget { b: 1.0, tau: 7.0, as_of: Some(7.0) });
}

#[test]
fn age_since_touch_is_normalized_and_fails_closed() {
    assert!(close(age_since_touch(&bud(1.0, 0.0), 1_800_000.0, DEFAULT_AGE_HORIZON_MS), 0.5));
    assert_eq!(age_since_touch(&bud(1.0, 0.0), 9e9, DEFAULT_AGE_HORIZON_MS), 1.0);
    assert_eq!(age_since_touch(&bud(1.0, 0.0), f64::NAN, DEFAULT_AGE_HORIZON_MS), 1.0);
    assert_eq!(age_since_touch(&bud(1.0, f64::NAN), 5.0, DEFAULT_AGE_HORIZON_MS), 1.0);
    assert_eq!(age_since_touch(&bud(1.0, 0.0), 5.0, 0.0), 1.0, "a zero horizon is the worst case");
    assert_eq!(age_since_touch(&bud(1.0, 10.0), 5.0, 100.0), 0.0, "a touch in the future is age 0");
}

#[test]
fn admission_follows_the_band_and_the_budget() {
    let a = |r: f64, b: f64| admit(r, &bud(b, 0.0), &P);
    assert_eq!(a(0.1, 1.0), Admission { admit: true, need_step_up: false, t: 1, metered: true });
    assert!(a(0.25, 0.25).admit, "B >= cost at the edge");
    assert_eq!(a(0.4, 1.0), Admission { admit: false, need_step_up: true, t: 2, metered: true });
    assert_eq!(a(0.4, 0.3), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(a(0.9, 1.0), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(a(0.1, 0.05), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(admit_of(1, false), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(admit_of(2, false), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(admit_of(3, true), Admission { admit: false, need_step_up: true, t: 3, metered: false });
    assert_eq!(admit_of(2, true), Admission { admit: false, need_step_up: true, t: 2, metered: true });
}

#[test]
fn the_safety_bound_holds_for_an_adversarial_sequence() {
    for pol in [P, RiskPolicy { kappa: 2.0, b_max: 1.5, ..P }, RiskPolicy { kappa: 0.5, b_max: 0.7, lambda: 0.0, ..P }] {
        let mut seed: u64 = 12345;
        let mut rnd = || {
            seed = (seed * 1664525 + 1013904223) % 4294967296;
            seed as f64 / 4294967296.0
        };
        let mut b = bud(pol.b_max, 0.0);
        let (mut sum, mut now, mut touches) = (0.0, 0.0, 0);
        for _ in 0..5000 {
            now += (rnd() * 5000.0).floor();
            b = leak(&b, now, pol.lambda);
            let r = rnd() * 0.7;
            let a = admit(r, &b, &pol);
            if a.metered {
                sum += r;
                b = debit(&b, cost(r, pol.kappa));
                assert!(sum <= safety_bound(pol.b_max, pol.kappa) + 1e-9);
            } else if rnd() < 0.05 {
                b = recharge(&b, pol.rho, pol.b_max, now);
                touches += 1;
                sum = 0.0;
            }
        }
        assert!(touches > 0);
    }
    assert_eq!(safety_bound(1.0, 4.0), 0.25);
    assert_eq!(safety_bound(1.0, 0.0), 0.0);
    assert_eq!(safety_bound(-1.0, 2.0), 0.0);
}

#[test]
fn a_sub_budget_cannot_exceed_its_parent_and_debits_consolidate() {
    let parent = bud(0.6, 5.0);
    assert_eq!(sub_budget(&parent, 0.7), Err("allocation exceeds parent remaining budget".to_string()));
    assert_eq!(sub_budget(&parent, -1.0), Err("allocation must be finite and >= 0".to_string()));
    assert_eq!(sub_budget(&parent, f64::NAN), Err("allocation must be finite and >= 0".to_string()));
    let s1 = sub_budget(&parent, 0.6).unwrap();
    assert_eq!(s1, TrustBudget { b: 0.6, tau: 5.0, as_of: Some(5.0) });
    let (p2, _) = debit_consolidated(&parent, &s1, 0.4).unwrap();
    assert!(close(p2.b, 0.2));
    assert_eq!(debit_consolidated(&p2, &s1, 0.4), Err("parent budget insufficient".to_string()));
    assert_eq!(debit_consolidated(&parent, &bud(0.1, 0.0), 0.2), Err("sub-agent budget insufficient".to_string()));
}

#[test]
fn a_path_debit_touches_every_node_or_none() {
    let path = [bud(5.0, 0.0), bud(3.0, 0.0), bud(2.0, 0.0)];
    let a = debit_consolidated_path(&path, 1.5).unwrap();
    assert_eq!(a.iter().map(|n| n.b).collect::<Vec<_>>(), vec![3.5, 1.5, 0.5]);
    assert_eq!(debit_consolidated_path(&a, 1.5), Err("budget node at depth 2 insufficient (need 1.5, have 0.5)".to_string()));
    assert_eq!(debit_consolidated_path(&[bud(0.2, 0.0), bud(9.0, 0.0)], 1.0), Err("budget node at depth 0 insufficient (need 1, have 0.2)".to_string()));
    assert_eq!(debit_consolidated_path(&path, 0.0).unwrap().iter().map(|n| n.b).collect::<Vec<_>>(), vec![5.0, 3.0, 2.0]);
    assert!(debit_consolidated_path(&[bud(f64::NAN, 0.0)], 0.0).is_err(), "a NaN node never covers, even a zero cost");
}

fn policy_json() -> Value {
    json!({"weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05}, "theta1": 0.25, "theta2": 0.6, "kappa": 1, "lambda": 0.0005, "rho": 0.5, "bMax": 1})
}

#[test]
fn the_risk_policy_is_validated_with_the_reference_texts() {
    assert_eq!(validate_risk_policy(&policy_json()), None);
    assert_eq!(RiskPolicy::from_value(&policy_json()), Ok(P));
    let with = |k: &str, v: Value| {
        let mut p = policy_json();
        p[k] = v;
        validate_risk_policy(&p)
    };
    assert_eq!(validate_risk_policy(&Value::Null).as_deref(), Some("risk_policy must be an object"));
    assert_eq!(validate_risk_policy(&json!("x")).as_deref(), Some("risk_policy must be an object"));
    assert_eq!(validate_risk_policy(&json!({})).as_deref(), Some("risk_policy.weights missing"));
    assert_eq!(validate_risk_policy(&json!({"weights": 3})).as_deref(), Some("risk_policy.weights missing"));
    let mut p = policy_json();
    p["weights"]["alpha"] = json!(-1);
    assert_eq!(validate_risk_policy(&p).as_deref(), Some("risk_policy.weights.alpha must be finite and >= 0"));
    p["weights"]["alpha"] = json!("1");
    assert_eq!(validate_risk_policy(&p).as_deref(), Some("risk_policy.weights.alpha must be finite and >= 0"));
    for k in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"] {
        assert_eq!(with(k, json!("x")).as_deref(), Some(format!("risk_policy.{k} must be finite").as_str()), "{k}");
        assert_eq!(with(k, json!(null)).as_deref(), Some(format!("risk_policy.{k} must be finite").as_str()), "{k}");
    }
    let mut q = policy_json();
    q["theta1"] = json!(0.9);
    q["theta2"] = json!(0.1);
    assert_eq!(validate_risk_policy(&q).as_deref(), Some("risk_policy requires 0 <= theta1 <= theta2"));
    assert_eq!(with("theta1", json!(-0.1)).as_deref(), Some("risk_policy requires 0 <= theta1 <= theta2"));
    assert_eq!(with("theta2", json!(0.25)), None, "theta1 == theta2 is allowed");
    assert_eq!(with("kappa", json!(0)).as_deref(), Some("risk_policy.kappa must be > 0"));
    for k in ["lambda", "rho", "bMax"] {
        assert_eq!(with(k, json!(-1)).as_deref(), Some("risk_policy lambda/rho/bMax must be >= 0"), "{k}");
        assert_eq!(with(k, json!(0)), None, "{k} = 0 is allowed");
    }
    assert!(RiskPolicy::from_value(&json!({})).is_err());
}

fn node(id: &str, extra: Value) -> Value {
    let mut n = json!({"id": id, "verb": "v", "resource": format!("/{id}")});
    for (k, v) in extra.as_object().unwrap() {
        n[k] = v.clone();
    }
    n
}

#[test]
fn the_plan_geodesic_falls_back_to_the_index_distance_without_edges() {
    let plan: Vec<Value> = ["a", "b", "c", "d"].iter().map(|i| node(i, json!({}))).collect();
    assert_eq!(plan_geodesic(&plan, "a", "a"), 0.0);
    assert_eq!(plan_geodesic(&plan, "a", "d"), 1.0);
    assert!(close(plan_geodesic(&plan, "b", "d"), 2.0 / 3.0));
    assert_eq!(plan_geodesic(&plan, "d", "b"), plan_geodesic(&plan, "b", "d"));
    assert_eq!(plan_geodesic(&plan, "a", "nope"), 1.0);
    assert_eq!(plan_geodesic(&plan, "nope", "a"), 1.0);
    assert_eq!(plan_geodesic(&[node("a", json!({}))], "a", "a"), 0.0);
    assert_eq!(plan_geodesic(&[], "a", "b"), 1.0);
}

#[test]
fn the_plan_geodesic_is_a_bfs_over_the_undirected_references() {
    let plan = vec![
        node("a", json!({"post": {"before": ["b"]}})),
        node("b", json!({})),
        node("c", json!({"pre": {"after": "b"}})),
        node("d", json!({"pre": "c"})),
        node("x", json!({})),
    ];
    assert!(close(plan_geodesic(&plan, "a", "d"), 0.75));
    assert!(close(plan_geodesic(&plan, "d", "a"), 0.75));
    assert!(close(plan_geodesic(&plan, "c", "d"), 0.25));
    assert_eq!(plan_geodesic(&plan, "a", "x"), 1.0, "unreachable");
    // every reference key counts: pre under depends_on / requires / nodes, post under enables / then / next
    for (k, pre) in [("depends_on", true), ("requires", true), ("nodes", true), ("enables", false), ("then", false), ("next", false)] {
        let ref_node = if pre { node("b", json!({"pre": {k: ["a"]}})) } else { node("a", json!({"post": {k: "b"}})) };
        let (a, b) = if pre { (node("a", json!({})), ref_node) } else { (ref_node, node("b", json!({}))) };
        let p = vec![a, node("m", json!({})), b];
        assert!(close(plan_geodesic(&p, "a", "b"), 0.5), "{k}");
    }
}

#[test]
fn to_fixed_3_rounds_half_up_like_javascript() {
    for (x, want) in [(0.0625, "0.063"), (0.1875, "0.188"), (0.3125, "0.313"), (0.9375, "0.938"), (0.5, "0.500"), (0.25, "0.250"), (1.0, "1.000"), (0.0, "0.000"), (0.0004, "0.000"), (0.0005, "0.001"), (0.9996, "1.000"), (0.95, "0.950"), (0.6001, "0.600")] {
        assert_eq!(js_to_fixed3(x), want, "{x}");
    }
}

fn step<'a>(risk: &'a Map<String, Value>, budget: TrustBudget) -> RiskStep<'a> {
    RiskStep { policy: &P, risk, plan: None, node_id: None, goal_node_id: None, budget, now: 0.0, age_horizon_ms: None, r_floor: None, reversibility_class: Some("reversible"), pr_ok: true, cv_ok: true, dcv_ok: true, chain_ok: true }
}

fn calm() -> Map<String, Value> {
    json!({"semanticDistance": 0, "reversibility": 1, "blastRadius": 0, "taint": 0, "confidence": 1, "age": 0}).as_object().unwrap().clone()
}

#[test]
fn a_calm_action_with_budget_is_admitted_without_a_human() {
    let risk = calm();
    let d = decide_risk(&step(&risk, bud(1.0, 0.0)));
    assert_eq!((d.release_guardian_share, d.admit, d.need_step_up, d.r), (true, true, false, 0.0));
    assert_eq!(d.required_threshold, RequiredThreshold { t: 1, proof: 0, optimistic_allowed: true });
    assert!(d.reasons.is_empty());
    assert_eq!(d.budget.b, 1.0);
}

#[test]
fn an_admitted_action_is_debited_its_cost() {
    let mut risk = calm();
    risk.insert("blastRadius".into(), json!(1));
    let d = decide_risk(&step(&risk, bud(1.0, 0.0)));
    assert_eq!((d.r, d.admit, d.required_threshold.t), (0.2, true, 1));
    assert_eq!(d.budget.b, 0.8);
    // a denied action (a failing check) is never debited, and always needs a step-up
    for (pr, cv, dcv, chain) in [(false, true, true, true), (true, false, true, true), (true, true, false, true), (true, true, true, false)] {
        let mut s = step(&risk, bud(1.0, 0.0));
        (s.pr_ok, s.cv_ok, s.dcv_ok, s.chain_ok) = (pr, cv, dcv, chain);
        let d = decide_risk(&s);
        assert_eq!((d.release_guardian_share, d.admit, d.need_step_up, d.budget.b), (false, false, true, 1.0), "{pr}{cv}{dcv}{chain}");
    }
}

#[test]
fn a_depleted_budget_forces_a_human_step_up_even_for_low_risk() {
    let mut risk = calm();
    risk.insert("blastRadius".into(), json!(1));
    let d = decide_risk(&step(&risk, bud(0.1, 0.0)));
    assert_eq!((d.release_guardian_share, d.admit, d.need_step_up, d.required_threshold.t), (true, false, true, 3));
    assert_eq!(d.reasons, vec!["trust budget depleted: human recharge required".to_string()]);
    assert_eq!(d.budget.b, 0.1, "an unmetered step-up is not debited");
}

#[test]
fn a_high_risk_names_the_step_up_in_the_reasons() {
    let mut risk = calm();
    risk.insert("taint".into(), json!(1));
    risk.insert("semanticDistance".into(), json!(1));
    risk.insert("blastRadius".into(), json!(1));
    let d = decide_risk(&step(&risk, bud(1.0, 0.0)));
    assert_eq!((d.admit, d.need_step_up, d.required_threshold.t), (false, true, 3));
    assert_eq!(d.reasons, vec![format!("risk {} exceeds auto threshold: step-up to t=3", js_to_fixed3(d.r))]);
    assert_eq!(d.reasons[0], "risk 0.650 exceeds auto threshold: step-up to t=3");
    // t=2: the guardian auto-cosigns, the action is metered
    let mut mid = calm();
    mid.insert("taint".into(), json!(1));
    mid.insert("semanticDistance".into(), json!(1));
    let d2 = decide_risk(&step(&mid, bud(1.0, 0.0)));
    assert_eq!((d2.required_threshold.t, d2.admit, d2.need_step_up), (2, false, true));
    assert_eq!(d2.reasons[0], "risk 0.450 exceeds auto threshold: step-up to t=2");
    assert_eq!(d2.budget.b, 1.0 - d2.r, "a t=2 release is metered");
}

#[test]
fn missing_inputs_are_assumed_worst_and_named() {
    let risk = Map::new();
    let d = decide_risk(&step(&risk, bud(1.0, 0.0)));
    assert_eq!(d.reasons[0], "risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence");
    assert!(d.r > 0.9);
    // a non-finite or non-number value counts as missing too
    let mut some = calm();
    some.insert("taint".into(), json!("0"));
    some.insert("confidence".into(), json!(null));
    let d = decide_risk(&step(&some, bud(1.0, 0.0)));
    assert_eq!(d.reasons[0], "risk input(s) missing, assumed worst case: taint, confidence");
}

#[test]
fn the_semantic_distance_comes_from_the_plan_when_the_server_gave_none() {
    let plan: Vec<Value> = ["a", "b", "c", "d"].iter().map(|i| node(i, json!({}))).collect();
    let mut risk = calm();
    risk.remove("semanticDistance");
    let mut s = step(&risk, bud(1.0, 0.0));
    s.plan = Some(&plan);
    s.node_id = Some("a");
    let d = decide_risk(&s);
    assert!(!d.reasons.iter().any(|r| r.contains("semanticDistance")), "{:?}", d.reasons);
    assert!(close(d.r, 0.25), "plan distance a -> last = 1, weight 0.25: {}", d.r);
    s.goal_node_id = Some("b");
    assert!(close(decide_risk(&s).r, 0.25 / 3.0));
    s.node_id = None;
    assert!(close(decide_risk(&s).r, 0.25), "no node id: the worst case");
    // a supplied distance wins over the plan
    risk.insert("semanticDistance".into(), json!(0));
    let mut s2 = step(&risk, bud(1.0, 0.0));
    s2.plan = Some(&plan);
    s2.node_id = Some("a");
    assert_eq!(decide_risk(&s2).r, 0.0);
    // an empty plan has no goal: the worst case
    risk.remove("semanticDistance");
    let mut s3 = step(&risk, bud(1.0, 0.0));
    let empty: Vec<Value> = Vec::new();
    s3.plan = Some(&empty);
    s3.node_id = Some("a");
    assert!(close(decide_risk(&s3).r, 0.25));
}

#[test]
fn the_age_is_derived_from_the_last_human_touch_unless_supplied() {
    let mut risk = calm();
    risk.remove("age");
    let mut s = step(&risk, bud(1.0, 0.0));
    s.now = 1_800_000.0;
    let d = decide_risk(&s);
    assert!(close(d.r, 0.05 * 0.5), "{}", d.r);
    s.age_horizon_ms = Some(3_600_000.0 / 2.0);
    assert!(close(decide_risk(&s).r, 0.05), "a shorter horizon ages faster");
    // the budget leaks to the decision time before it is judged
    let leaked = decide_risk(&RiskStep { now: 1_000_000.0, ..step(&calm(), bud(1.0, 0.0)) });
    assert!(close(leaked.budget.b, 0.5));
    assert_eq!(leaked.budget.as_of, Some(1_000_000.0));
}

#[test]
fn the_signed_caution_is_a_floor_on_r() {
    let risk = calm();
    let with = |f: Option<f64>| {
        let mut s = step(&risk, bud(1.0, 0.0));
        s.r_floor = f;
        decide_risk(&s)
    };
    assert_eq!(with(None).r, 0.0);
    assert_eq!(with(Some(0.3)).r, 0.3);
    assert_eq!(with(Some(0.3)).required_threshold.t, 2);
    assert_eq!(with(Some(0.9)).required_threshold.t, 3);
    assert_eq!(with(Some(7.0)).r, 1.0, "clamped to 1");
    assert_eq!(with(Some(-2.0)).r, 0.0, "clamped to 0");
    assert_eq!(with(Some(f64::NAN)).r, 0.0, "a non-finite caution is ignored");
    assert_eq!(with(Some(f64::INFINITY)).r, 0.0);
    // a floor below the server's own r changes nothing
    let mut hot = calm();
    hot.insert("blastRadius".into(), json!(1));
    let mut s = step(&hot, bud(1.0, 0.0));
    s.r_floor = Some(0.1);
    assert_eq!(decide_risk(&s).r, 0.2);
}

#[test]
fn only_a_recognized_reversible_class_may_be_optimistic() {
    let risk = calm();
    let opt = |c: Option<&str>| {
        let mut s = step(&risk, bud(1.0, 0.0));
        s.reversibility_class = c;
        decide_risk(&s).required_threshold.optimistic_allowed
    };
    for c in ["reversible", "rate_limited", "costly"] {
        assert!(opt(Some(c)), "{c}");
        assert!(fast_path_eligible(Some(c)));
    }
    for c in [Some("irreversible"), Some("compensable"), Some("Reversible"), Some(""), None] {
        assert!(!opt(c), "{c:?}");
        assert!(!fast_path_eligible(c));
    }
}

#[test]
fn the_core_decision_matches_the_dafny_kernel() {
    let rt = required_threshold(0.1, 0.25, 0.6, false);
    let adm = admit_of(1, true);
    let ok = decide_core(true, true, true, true, rt, adm);
    assert_eq!(ok, CoreDecision { release: true, admit: true, need_step_up: false, threshold: rt, debit: true });
    for (a, b, c, d) in [(false, true, true, true), (true, false, true, true), (true, true, false, true), (true, true, true, false)] {
        let x = decide_core(a, b, c, d, rt, adm);
        assert_eq!((x.release, x.admit, x.need_step_up, x.debit), (false, false, true, false));
    }
    // the escalation uses the admission's t: a depleted budget raises t=1 to t=3
    let depleted = decide_core(true, true, true, true, rt, admit_of(1, false));
    assert_eq!((depleted.threshold.t, depleted.threshold.proof, depleted.threshold.optimistic_allowed, depleted.debit), (3, 2, false, false));
}

#[test]
fn the_math_helpers_follow_nan_and_signed_zero_like_javascript() {
    assert!(js_max(f64::NAN, 1.0).is_nan() && js_max(1.0, f64::NAN).is_nan());
    assert!(js_min(f64::NAN, 1.0).is_nan() && js_min(1.0, f64::NAN).is_nan());
    assert!(js_max(-0.0, 0.0).is_sign_positive(), "Math.max(-0, 0) is +0");
    assert!(js_min(0.0, -0.0).is_sign_negative(), "Math.min(0, -0) is -0");
    assert!(clamp01(-0.0).is_sign_negative(), "x < 0 is false for -0, so x itself is returned");
    assert!(wt(-0.0).is_sign_positive() && nz(-0.0).is_sign_positive());
    assert_eq!(wt(f64::INFINITY), 0.0);
    assert_eq!(nz(f64::INFINITY), 0.0);
    assert_eq!(wt(f64::NAN), 0.0);
}

#[test]
fn a_non_finite_clock_never_leaks_the_budget() {
    let b = bud(5.0, 0.0);
    for now in [f64::INFINITY, f64::NAN] {
        let l = leak(&b, now, 1.0);
        assert_eq!(l.b, 5.0, "{now}");
        assert_eq!(l.as_of, Some(0.0), "{now}");
    }
    assert_eq!(leak(&bud(5.0, f64::NAN), 1000.0, 1.0).b, 5.0, "a NaN last-touch time drains nothing");
    assert_eq!(leak(&b, 2000.0, 1.0).b, 3.0);
}

#[test]
fn the_age_refuses_a_zero_horizon_and_the_budget_guards_are_inclusive() {
    assert_eq!(age_since_touch(&bud(1.0, 100.0), 100.0, 0.0), 1.0);
    assert_eq!(sub_budget(&bud(5.0, 0.0), 0.0).map(|s| s.b), Ok(0.0));
    assert!(sub_budget(&bud(5.0, 0.0), -0.5).is_err());
    assert!(debit_consolidated(&bud(3.0, 0.0), &bud(2.0, 0.0), 2.0).is_ok(), "a sub budget equal to the cost covers it");
    assert!(debit_consolidated(&bud(2.0, 0.0), &bud(3.0, 0.0), 2.0).is_ok(), "a parent budget equal to the cost covers it");
    assert_eq!(debit_consolidated(&bud(3.0, 0.0), &bud(1.0, 0.0), 2.0).unwrap_err(), "sub-agent budget insufficient");
    assert_eq!(debit_consolidated(&bud(1.0, 0.0), &bud(3.0, 0.0), 2.0).unwrap_err(), "parent budget insufficient");
}

#[test]
fn a_zero_theta1_is_a_valid_policy() {
    let mut p = policy_json();
    p["theta1"] = json!(0);
    assert_eq!(validate_risk_policy(&p), None);
}

#[test]
fn to_fixed_3_prints_non_finite_and_negative_values_with_the_float_formatter() {
    assert_eq!(js_to_fixed3(f64::NAN), "NaN");
    assert_eq!(js_to_fixed3(f64::INFINITY), "inf");
    assert_eq!(js_to_fixed3(-1.0), "-1.000");
    assert_eq!(js_to_fixed3(-0.0), "0.000", "(-0).toFixed(3) is 0.000");
}

#[test]
fn the_plan_geodesic_bfs_terminates() {
    let d = crate::k042_support::within("plan_geodesic", || {
        let plan = vec![node("a", json!({"post": {"before": ["b"]}})), node("b", json!({})), node("c", json!({"pre": "b"}))];
        plan_geodesic(&plan, "a", "c")
    });
    assert_eq!(d, 1.0);
}
