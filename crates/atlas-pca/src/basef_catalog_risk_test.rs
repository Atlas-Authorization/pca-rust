//! `catalog_risk` against packages/pca/src/catalog-risk.ts: reversibility score and blast radius from the catalogue, the money-moving
//! blast radius amount / kappa, and the worst case for anything it cannot vouch for.
use super::*;

fn grant(kappa: f64) -> Value {
    json!({"caveats": [{"type": "envelope", "goal_commit": "g", "predicates": [], "caveats": [], "agent_binding": {},
        "risk_policy": {"weights": {"alpha": 0, "beta": 0, "gamma": 0, "delta": 0, "epsilon": 0, "zeta": 0}, "theta1": 0.3, "theta2": 0.7, "kappa": kappa, "lambda": 1, "rho": 1, "bMax": 1}}]})
}

#[test]
fn the_catalogue_has_the_21_reviewed_actions() {
    assert_eq!(BUILTIN_CATALOG.len(), 21);
    let verbs: std::collections::HashSet<_> = BUILTIN_CATALOG.iter().map(|r| r.0).collect();
    assert_eq!(verbs.len(), 21, "verbs are unique");
    assert_eq!(BUILTIN_CATALOG.iter().filter(|r| r.3.is_some()).count(), 3, "stripe charge, refund and payout move money");
}

#[test]
fn a_cataloged_verb_is_priced_from_the_catalogue() {
    let r = catalog_risk("github.read", &json!({}), &grant(1.0), None);
    assert_eq!(r.get("reversibility"), Some(&json!(1.0)));
    assert_eq!(r.get("blastRadius"), Some(&json!(0.05)));
    assert_eq!(r.get("confidence"), Some(&json!(1)));
    assert!(!r.contains_key("taint"), "taint is not vouched for unless the server observed it");
    let w = catalog_risk("files.write", &json!({}), &grant(1.0), None);
    assert_eq!((w["reversibility"].as_f64(), w["blastRadius"].as_f64()), (Some(0.4), Some(0.5)));
    let d = catalog_risk("gmail.delete", &json!({}), &grant(1.0), None);
    assert_eq!((d["reversibility"].as_f64(), d["blastRadius"].as_f64()), (Some(0.0), Some(0.8)));
}

#[test]
fn an_unknown_verb_is_priced_at_the_worst_case() {
    assert!(catalog_risk("nope.unknown", &json!({}), &grant(1.0), None).is_empty());
    assert!(catalog_risk("", &json!({}), &grant(1.0), None).is_empty());
    assert!(catalog_risk("GITHUB.READ", &json!({}), &grant(1.0), None).is_empty(), "verbs match exactly");
}

#[test]
fn a_money_moving_verb_is_priced_by_its_amount_over_kappa() {
    let blast = |params: Value, kappa: f64| catalog_risk("stripe.refund", &params, &grant(kappa), None)["blastRadius"].as_f64().unwrap();
    assert_eq!(blast(json!({"amount": 0}), 100.0), 0.0);
    assert_eq!(blast(json!({"amount": 25}), 100.0), 0.25);
    assert_eq!(blast(json!({"amount": 100}), 100.0), 1.0);
    assert_eq!(blast(json!({"amount": 500}), 100.0), 1.0, "clamped to 1");
    assert_eq!(blast(json!({"amount": 10.0}), 4.0), 1.0, "10 / 4 clamps");
    assert_eq!(blast(json!({"amount": 2}), 4.0), 0.5);
    // a missing, negative, non-number or non-finite amount is the worst case; so is a kappa that is not positive
    for bad in [json!({}), json!({"amount": -1}), json!({"amount": "5"}), json!({"amount": null}), json!({"amount": true}), json!({"other": 5}), json!([5])] {
        assert_eq!(blast(bad.clone(), 100.0), 1.0, "{bad}");
    }
    let no_grant = catalog_risk("stripe.refund", &json!({"amount": 1}), &json!({}), None);
    assert_eq!(no_grant["blastRadius"].as_f64(), Some(1.0), "no readable envelope: no kappa");
    // reversibility is the catalogue's whatever the amount
    assert_eq!(catalog_risk("stripe.refund", &json!({"amount": 1}), &grant(100.0), None)["reversibility"].as_f64(), Some(0.0));
}

#[test]
fn a_server_observed_taint_is_clamped_and_a_non_finite_one_is_dropped() {
    let taint = |t: Option<f64>| catalog_risk("github.read", &json!({}), &grant(1.0), t).get("taint").and_then(Value::as_f64);
    assert_eq!(taint(None), None);
    assert_eq!(taint(Some(0.25)), Some(0.25));
    assert_eq!(taint(Some(7.0)), Some(1.0));
    assert_eq!(taint(Some(-1.0)), Some(0.0));
    assert_eq!(taint(Some(f64::NAN)), None);
    assert_eq!(taint(Some(f64::INFINITY)), None);
}

#[test]
fn the_reversibility_scale() {
    for (c, want) in [("reversible", Some(1.0)), ("rate_limited", Some(0.4)), ("costly", Some(0.4)), ("irreversible", Some(0.0)), ("bogus", None), ("", None)] {
        assert_eq!(reversibility_score(c), want, "{c}");
    }
}

#[test]
fn a_zero_kappa_prices_a_money_verb_at_the_worst_case_even_for_a_zero_amount() {
    // kappa = 0 is not a positive kappa: 0 / 0 must not leak a NaN blast radius
    let r = catalog_risk("stripe.charge", &json!({"amount": 0}), &grant(0.0), None);
    assert_eq!(r["blastRadius"].as_f64(), Some(1.0));
    let r = catalog_risk("stripe.charge", &json!({"amount": 0}), &grant(10.0), None);
    assert_eq!(r["blastRadius"].as_f64(), Some(0.0));
}

#[test]
fn a_kappa_of_exactly_zero_is_not_positive_so_the_blast_radius_is_the_worst_case() {
    // 0 / 0 would be NaN (serialised as null) and 5 / 0 infinite: a kappa that is not strictly positive prices the verb at 1
    for amount in [0, 5] {
        let r = catalog_risk("stripe.refund", &json!({"amount": amount}), &grant(0.0), None);
        assert_eq!(r.get("blastRadius"), Some(&json!(1.0)), "amount {amount}");
    }
}

#[test]
fn a_zero_kappa_is_no_policy_even_for_a_zero_amount() {
    // kappa 0 is not a positive policy: worst case 1, never 0 / 0 (which is not a number and would not serialize as one)
    let r = catalog_risk("stripe.refund", &json!({"amount": 0}), &grant(0.0), None);
    assert_eq!(r.get("blastRadius"), Some(&json!(1.0)));
    let r = catalog_risk("stripe.refund", &json!({"amount": 0}), &grant(-0.0), None);
    assert_eq!(r.get("blastRadius"), Some(&json!(1.0)));
}
