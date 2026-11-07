//! Kill tests for the producer helpers (full run 41891707650, shards 90-91). Limits and reason texts are the reference's:
//! packages/pca/src/risk.ts validateRiskPolicy, packages/pca/src/workflow.ts wfOutput, packages/pca/src/caveat-lang.ts members.
use super::*;
use serde_json::json;

fn rp(k: &str, v: Value) -> Value {
    let mut p = default_risk_policy();
    p[k] = v;
    p
}
fn err(p: &Value) -> Option<String> {
    risk_policy_error(p)
}

#[test]
fn risk_policy_shape_refusals_are_the_references() {
    for bad in [json!(5), json!("x"), json!(true), Value::Null] {
        assert_eq!(err(&bad).as_deref(), Some("risk_policy must be an object"), "{bad}");
        assert_eq!(err(&rp("weights", bad.clone())).as_deref(), Some("risk_policy.weights missing"), "{bad}");
    }
    // an array is typeof 'object' there: the policy has no weights, the weights have no alpha
    assert_eq!(err(&json!([])).as_deref(), Some("risk_policy.weights missing"));
    assert_eq!(err(&rp("weights", json!([]))).as_deref(), Some("risk_policy.weights.alpha must be finite and >= 0"));
    assert_eq!(err(&default_risk_policy()), None);
}

#[test]
fn risk_policy_bounds_are_inclusive_at_zero_and_at_theta_equality() {
    assert_eq!(err(&rp("theta1", json!(0))), None);
    let mut eq = default_risk_policy();
    eq["theta1"] = json!(0.6);
    eq["theta2"] = json!(0.6);
    assert_eq!(err(&eq), None);
    assert_eq!(err(&rp("theta1", json!(-0.1))).as_deref(), Some("risk_policy requires 0 <= theta1 <= theta2"));
    assert_eq!(err(&rp("theta2", json!(0.2))).as_deref(), Some("risk_policy requires 0 <= theta1 <= theta2"));
    for k in ["lambda", "rho", "bMax"] {
        assert_eq!(err(&rp(k, json!(0))), None, "{k} = 0");
        assert_eq!(err(&rp(k, json!(-1))).as_deref(), Some("risk_policy lambda/rho/bMax must be >= 0"), "{k} = -1");
    }
}

#[test]
fn pq_key_pair_debug_names_only_the_family() {
    let k = PqKeyPair::generate("ML-DSA-65").unwrap();
    assert_eq!(format!("{k:?}"), "PqKeyPair { family: ML-DSA-65 }");
}

#[test]
fn attenuate_appends_under_the_same_holder() {
    let (p, k) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let s = Suite::default();
    let env = json!({"predicates": [{"verb": "v", "resource": "r"}], "caveats": [], "risk_policy": default_risk_policy()});
    let g = mint_grant(&p, &k.public, &env, "g", None, None, &s).unwrap().grant;
    let add = json!({"type": "budget_alloc", "limit": 5});
    let a = attenuate(&g, &json!([add]), &k, &s).unwrap();
    assert_eq!(a["holder"], g["holder"]);
    assert_eq!(a["issuer"], json!(k.public));
    assert_eq!(a["parent"], json!(hash_canonical_strict(&g).unwrap()));
    let (cg, ca) = (g["caveats"].as_array().unwrap(), a["caveats"].as_array().unwrap());
    assert_eq!(ca.len(), cg.len() + 1);
    assert_eq!(ca[..cg.len()], cg[..]);
    assert_eq!(ca[cg.len()], add);
}

/// Every leaf's proof (right subtrees included: that is where the index is rebased) verifies against the root.
#[test]
fn plan_proofs_verify_for_every_leaf_of_every_size() {
    for size in 1..=9usize {
        let nodes: Vec<Value> = (0..size).map(|i| json!({"id": format!("n{i}"), "verb": "v", "resource": format!("r/{i}")})).collect();
        let c = plan_commit(&nodes).unwrap();
        let root = c["root"].as_str().unwrap();
        for n in &nodes {
            let id = n["id"].as_str().unwrap();
            assert!(crate::verify_inclusion(root, c["proofs"][id].as_object(), &node_leaf(n).unwrap()), "size {size}, leaf {id}");
        }
    }
}

#[test]
fn caveat_builders_write_the_reference_members() {
    assert_eq!(
        needs_discharge_caveat("c1", "kyc", "org", "action", 1000, json!([{"claim": "x"}])),
        json!({"type": "needs_discharge", "id": "c1", "issuer": "kyc", "issuer_class": "org", "bind": "action", "ttl_ms": 1000, "require": [{"claim": "x"}]})
    );
    assert_eq!(max_uses_caveat("m1", 3, 5000), json!({"type": "max_uses", "id": "m1", "n": 3, "until": 5000}));
}

#[test]
fn wf_output_sorts_labels_and_carries_num_only_for_an_integer_asked_for() {
    let d = |v: &Value| crate::workflow::value_digest(v).unwrap();
    let seven = json!(7);
    assert_eq!(wf_output(&seven, &["b", "a"], Some("usd"), true).unwrap(), json!({"digest": d(&seven), "num": 7, "unit": "usd", "labels": ["a", "b"]}));
    assert_eq!(wf_output(&seven, &[], None, false).unwrap(), json!({"digest": d(&seven), "num": null, "unit": null, "labels": []}));
    let text = json!("x");
    assert_eq!(wf_output(&text, &[], None, true).unwrap(), json!({"digest": d(&text), "num": null, "unit": null, "labels": []}));
}

#[test]
fn the_default_clock_is_the_wall_clock_in_milliseconds() {
    // 2020-09-13 in ms: any real clock is past it; 0, 1 and -1 are not
    assert!(now_ms() > 1_600_000_000_000);
}

#[test]
fn a_key_pair_debugs_as_its_public_key_only() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    assert_eq!(format!("{k:?}"), format!("KeyPair {{ public: {} }}", k.public));
}
