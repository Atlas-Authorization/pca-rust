//! Intent Layer M2: the signed `envelope.intent` slot (wire rules) and the `intent` check (binding to the root
//! grant's first `envelope` caveat `goal_commit`, policy floor / ceiling, fail-closed misconfiguration).
use atlas_pca::*;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\x00";
const AUD: &str = "rs-intent";
const IAT: i64 = 1_800_000_000_000;
const NOW: i64 = IAT + 1_000;
const SALT: &str = "c2FsdC1pbnRlbnQtdGVzdA";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    SigningKey::from_bytes(&seed)
}
fn pubk(k: &SigningKey) -> String {
    b64(k.verifying_key().as_bytes())
}
fn digest(s: &str) -> String {
    b64(&Sha256::digest(s.as_bytes()))
}
fn root_grant(caveats: Value) -> Value {
    let (issuer, holder) = (key("principal"), key("agent"));
    let body = json!({"issuer": pubk(&issuer), "holder": pubk(&holder), "caveats": caveats.clone(), "parent": null});
    let d = b64(&Sha256::digest(canonicalize(&body).as_bytes()));
    let mut msg = CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&d).unwrap());
    json!({"id": d, "issuer": pubk(&issuer), "holder": pubk(&holder), "caveats": caveats, "body_digest": d,
           "sig": b64(&issuer.sign(&msg).to_bytes())})
}
fn ref_() -> String {
    digest("intent/ref")
}
fn map_() -> String {
    digest("intent/map")
}
fn bound_commit(salt: &str) -> String {
    intent_goal_commit(&ref_(), &map_(), salt).unwrap()
}
fn envelope(goal_commit: Value) -> Value {
    json!({"type": "envelope", "goal_commit": goal_commit})
}
fn the_intent() -> Value {
    json!({"ref": ref_(), "map_digest": map_(), "goal_salt": SALT, "fidelity_ppm": 950_000, "residual_risk_ppm": 4_310_000})
}

/// A signed single-node PCActn over `grant` (optionally carrying `intent`).
fn pcactn(grant: &Value, intent: Option<Value>) -> Value {
    let action = json!({"verb": "read", "resource": "db/users", "params_digest": digest("p"), "reversibility_class": "reversible"});
    let cond = digest("cond");
    let leaf = json!({"node_id": "only", "verb": "read", "resource": "db/users", "params_digest": digest("p"),
                      "reversibility_class": "reversible", "conditions": cond});
    let mut lb = vec![0u8];
    lb.extend_from_slice(canonicalize(&leaf).as_bytes());
    let root = b64(&Sha256::digest(&lb));
    let mut p = json!({
        "ver": 2, "action": action, "grant_ref": grant["id"], "cap_chain": [grant],
        "plan": {"root": root, "node_id": "only", "conditions_digest": cond, "inclusion_proof": {"index": 0, "size": 1, "path": []}},
        "attestation": {"epoch": 1, "quote_digest": "q", "model_id": "m", "measurement": "x", "operator": "o"},
        "provenance": {"causal_hash": "h", "taint_level": 0, "trusted_refs": []},
        "freshness": {"beacon_ref": "b", "accumulator_witness": "w", "epoch": 1},
        "counter": 1, "risk_claim": {"r": 0.5, "inputs": {}},
        "aud": AUD, "iat": IAT, "exp": IAT + 600_000,
    });
    let m: &mut Map<String, Value> = p.as_object_mut().unwrap();
    if let Some(i) = intent {
        m.insert("intent".into(), i);
    }
    let msg = threshold_message(m).unwrap();
    m.insert("sig".into(), json!(b64(&key("agent").sign(&msg).to_bytes())));
    p
}

fn verify(p: &Value, grant: &Value, pol: Option<&IntentPolicy>) -> Verdict {
    verify_pcactn_core_with(p, grant, NOW, AUD, &VerifyOptions { allowed: None, intent: pol, intent_v2: None })
}

fn pol(require: bool, min: Option<f64>, max: Option<f64>) -> IntentPolicy {
    IntentPolicy { require, min_fidelity_ppm: min, max_residual_risk_ppm: max }
}

#[test]
fn absent_slot_and_inactive_policy_is_the_pre_m2_verdict() {
    let g = root_grant(json!([envelope(json!(bound_commit(SALT)))]));
    let p = pcactn(&g, None);
    let base = verify_pcactn_core(&p, &g, NOW, AUD);
    assert!(base.allow, "{}", base.reason);
    for policy in [None, Some(IntentPolicy::default())] {
        let v = verify(&p, &g, policy.as_ref());
        assert!(v.allow && !v.checks.contains_key("intent"));
        assert_eq!(v.checks, base.checks);
    }
}

#[test]
fn bound_intent_passes_with_inclusive_thresholds() {
    let g = root_grant(json!([{"type": "max_spend", "usd": 100}, envelope(json!(bound_commit(SALT)))]));
    let p = pcactn(&g, Some(the_intent()));
    for policy in [None, Some(pol(true, Some(950_000.0), Some(4_310_000.0)))] {
        let v = verify(&p, &g, policy.as_ref());
        assert!(v.allow, "{}", v.reason);
        assert_eq!(v.checks.get("intent"), Some(&true));
        assert_eq!(v.checks.len(), 10);
    }
}

#[test]
fn intent_check_failures() {
    let good = root_grant(json!([envelope(json!(bound_commit(SALT)))]));
    let not_string = root_grant(json!([envelope(json!(7))]));
    let no_env = root_grant(json!([]));
    let first_wins = root_grant(json!([envelope(json!("decoy")), envelope(json!(bound_commit(SALT)))]));
    let mut wrong_salt = the_intent();
    wrong_salt["goal_salt"] = json!("wrong");
    let cases: Vec<(&str, &Value, Option<Value>, Option<IntentPolicy>, &str)> = vec![
        ("absent-required", &good, None, Some(pol(true, None, None)), "requires an intent"),
        ("threshold-implies-require", &good, None, Some(pol(false, Some(1.0), None)), "requires an intent"),
        ("misconfig-negative", &good, Some(the_intent()), Some(pol(false, Some(-1.0), None)), "misconfigured"),
        ("misconfig-fraction", &good, Some(the_intent()), Some(pol(false, None, Some(0.5))), "misconfigured"),
        ("salt-mismatch", &good, Some(wrong_salt), None, "do not open"),
        ("goal-commit-not-string", &not_string, Some(the_intent()), None, "no envelope goal commitment"),
        ("no-envelope", &no_env, Some(the_intent()), None, "no envelope goal commitment"),
        ("first-envelope-wins", &first_wins, Some(the_intent()), None, "do not open"),
        ("fidelity-below-min", &good, Some(the_intent()), Some(pol(false, Some(950_001.0), None)), "below the policy minimum"),
        ("residual-above-max", &good, Some(the_intent()), Some(pol(false, None, Some(4_309_999.0))), "exceeds the policy maximum"),
    ];
    for (name, g, intent, policy, why) in cases {
        let v = verify(&pcactn(g, intent), g, policy.as_ref());
        assert!(!v.allow, "{name}");
        assert_eq!(v.checks.get("intent"), Some(&false), "{name}");
        assert_eq!(v.checks.get("leaf_signature"), Some(&true), "{name}");
        assert!(v.reason.starts_with("intent: ") && v.reason.contains(why), "{name}: {}", v.reason);
    }
}

#[test]
fn wire_refusals_are_terminal() {
    let g = root_grant(json!([envelope(json!(bound_commit(SALT)))]));
    let with = |k: &str, x: Value| {
        let mut i = the_intent();
        i[k] = x;
        i
    };
    let mut missing = the_intent();
    missing.as_object_mut().unwrap().remove("residual_risk_ppm");
    let bad = [
        json!("x"),
        Value::Null,
        json!([the_intent()]),
        with("note", json!("x")),
        missing,
        with("ref", json!(b64(&[0u8; 31]))),
        with("ref", json!(format!("{}=", ref_()))),
        with("map_digest", json!(1)),
        with("goal_salt", json!("")),
        with("goal_salt", json!(format!("{}a", "\u{e9}".repeat(64)))),
        with("fidelity_ppm", json!(1_000_001)),
        with("fidelity_ppm", json!(-1)),
        with("fidelity_ppm", json!(1.5)),
        with("fidelity_ppm", json!("950000")),
        with("residual_risk_ppm", json!(-1)),
        with("residual_risk_ppm", json!(true)),
    ];
    for i in bad {
        let v = verify(&pcactn(&g, Some(i.clone())), &g, None);
        assert!(!v.allow && v.checks.len() == 1 && v.checks.get("wire") == Some(&false), "{i}: {:?}", v.checks);
    }
    // 128 UTF-8 bytes is the inclusive edge
    let salt = "\u{e9}".repeat(64);
    let g2 = root_grant(json!([envelope(json!(bound_commit(&salt)))]));
    let v = verify(&pcactn(&g2, Some(with("goal_salt", json!(salt)))), &g2, None);
    assert!(v.allow && v.checks.get("intent") == Some(&true), "{}", v.reason);
}

#[test]
fn policy_from_json_is_lenient() {
    let p = IntentPolicy::from_json(&json!({"require": false, "min_fidelity_ppm": -1, "max_residual_risk_ppm": 0.5})).unwrap();
    assert!(p.is_active() && !p.require);
    assert_eq!((p.min_fidelity_ppm, p.max_residual_risk_ppm), (Some(-1.0), Some(0.5)));
    assert!(!IntentPolicy::from_json(&json!({"require": false})).unwrap().is_active());
    assert!(IntentPolicy::from_json(&json!(null)).is_none());
}

// ---- mutation-kill: every intent boundary pinned on both sides --------------------------------------------------

const PRIOR: [&str; 9] = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"];

fn bound() -> Value {
    root_grant(json!([envelope(json!(bound_commit(SALT)))]))
}
fn patched(k: &str, x: Value) -> Value {
    let mut i = the_intent();
    i[k] = x;
    i
}
fn must_wire(name: &str, v: &Verdict) {
    assert!(!v.allow && v.checks.len() == 1 && v.checks.get("wire") == Some(&false) && v.reason.starts_with("wire: "), "{name}: {v:?}");
}
fn must_pass(name: &str, v: &Verdict) {
    assert!(v.allow && v.checks.get("intent") == Some(&true) && v.checks.len() == 10 && v.reason.is_empty(), "{name}: {v:?}");
}
fn must_fail(name: &str, why: &str, v: &Verdict) {
    assert!(!v.allow && v.checks.get("intent") == Some(&false) && v.checks.len() == 10, "{name}: {v:?}");
    assert!(v.reason.starts_with("intent: ") && v.reason.contains(why), "{name}: {}", v.reason);
    for c in PRIOR {
        assert_eq!(v.checks.get(c), Some(&true), "{name}: {c}");
    }
}

#[test]
fn kill_wire_accepted_boundaries() {
    let salt128 = "\u{e9}".repeat(64);
    let cases = [
        ("fidelity-0", patched("fidelity_ppm", json!(0)), SALT.to_string()),
        ("fidelity-1000000", patched("fidelity_ppm", json!(1_000_000)), SALT.to_string()),
        ("residual-0", patched("residual_risk_ppm", json!(0)), SALT.to_string()),
        ("residual-max-safe", patched("residual_risk_ppm", json!(9_007_199_254_740_991i64)), SALT.to_string()),
        ("salt-1-byte", patched("goal_salt", json!("s")), "s".to_string()),
        ("salt-128-bytes", patched("goal_salt", json!(salt128.clone())), salt128.clone()),
    ];
    for (name, i, salt) in cases {
        let g = root_grant(json!([envelope(json!(bound_commit(&salt)))]));
        must_pass(name, &verify(&pcactn(&g, Some(i)), &g, None));
    }
}

#[test]
fn kill_wire_refusals() {
    let g = bound();
    let mut cases: Vec<(String, Value)> = vec![
        ("null".into(), Value::Null),
        ("array".into(), json!([the_intent()])),
        ("string".into(), json!("x")),
        ("number".into(), json!(1)),
        ("extra-member".into(), patched("extra", json!("x"))),
        ("ref-31".into(), patched("ref", json!(b64(&[0u8; 31])))),
        ("ref-33".into(), patched("ref", json!(b64(&[0u8; 33])))),
        ("ref-padded".into(), patched("ref", json!(format!("{}=", ref_())))),
        ("ref-number".into(), patched("ref", json!(1))),
        ("map-31".into(), patched("map_digest", json!(b64(&[0u8; 31])))),
        ("map-std-alphabet".into(), patched("map_digest", json!(format!("+{}", &map_()[1..])))),
        ("map-null".into(), patched("map_digest", Value::Null)),
        ("salt-empty".into(), patched("goal_salt", json!(""))),
        ("salt-129".into(), patched("goal_salt", json!(format!("{}a", "\u{e9}".repeat(64))))),
        ("salt-number".into(), patched("goal_salt", json!(5))),
        ("salt-null".into(), patched("goal_salt", Value::Null)),
        ("fidelity-minus-1".into(), patched("fidelity_ppm", json!(-1))),
        ("fidelity-1000001".into(), patched("fidelity_ppm", json!(1_000_001))),
        ("fidelity-fraction".into(), patched("fidelity_ppm", json!(1.5))),
        ("fidelity-string".into(), patched("fidelity_ppm", json!("950000"))),
        ("fidelity-bool".into(), patched("fidelity_ppm", json!(true))),
        ("residual-minus-1".into(), patched("residual_risk_ppm", json!(-1))),
        ("residual-fraction".into(), patched("residual_risk_ppm", json!(0.25))),
        ("residual-bool".into(), patched("residual_risk_ppm", json!(true))),
        ("residual-string".into(), patched("residual_risk_ppm", json!("0"))),
    ];
    for k in ["ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"] {
        let mut i = the_intent();
        i.as_object_mut().unwrap().remove(k);
        cases.push((format!("missing-{k}"), i));
    }
    for (name, i) in cases {
        let v = verify(&pcactn(&g, Some(i)), &g, None);
        must_wire(&name, &v);
    }
    // the wire reason names the member
    for k in ["ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"] {
        let mut i = the_intent();
        i.as_object_mut().unwrap().remove(k);
        let v = verify(&pcactn(&g, Some(i)), &g, None);
        assert_eq!(v.reason, format!("wire: missing field 'intent.{k}'"));
        let v = verify(&pcactn(&g, Some(patched(k, json!([])))), &g, None);
        assert!(v.reason.contains(&format!("'intent.{k}'")), "{k}: {}", v.reason);
    }
    let v = verify(&pcactn(&g, Some(patched("zz", json!(1)))), &g, None);
    assert_eq!(v.reason, "wire: unknown field 'intent.zz'");
}

#[test]
fn kill_policy_activation() {
    let g = bound();
    let p = pcactn(&g, None);
    for policy in [None, Some(IntentPolicy::default()), Some(pol(false, None, None))] {
        let v = verify(&p, &g, policy.as_ref());
        assert!(v.allow && v.checks.len() == 9 && !v.checks.contains_key("intent"), "{v:?}");
    }
    for (name, policy) in [
        ("require-true", pol(true, None, None)),
        ("min-alone", pol(false, Some(0.0), None)),
        ("max-alone", pol(false, None, Some(0.0))),
    ] {
        assert!(policy.is_active(), "{name}");
        must_fail(name, "requires an intent binding", &verify(&p, &g, Some(&policy)));
    }
    assert!(!IntentPolicy::default().is_active());
}

#[test]
fn kill_policy_misconfigured() {
    let g = bound();
    let p = pcactn(&g, Some(the_intent()));
    let bad = [-1.0, 0.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0, 9_007_199_254_740_992.0];
    for x in bad {
        for policy in [
            pol(false, Some(x), None),
            pol(false, None, Some(x)),
            pol(false, Some(0.0), Some(x)),
            pol(false, Some(x), Some(0.0)),
        ] {
            must_fail(&format!("{x}"), "misconfigured", &verify(&p, &g, Some(&policy)));
        }
    }
    // valid thresholds get past the sanity step (they may still fail the floor / ceiling on their merits)
    for x in [0.0, 1.0, 9_007_199_254_740_991.0] {
        for policy in [pol(false, Some(x), None), pol(false, None, Some(x))] {
            let v = verify(&p, &g, Some(&policy));
            assert!(v.checks.contains_key("intent") && !v.reason.contains("misconfigured"), "{x}: {}", v.reason);
        }
    }
    must_pass("max max-safe", &verify(&p, &g, Some(&pol(false, Some(0.0), Some(9_007_199_254_740_991.0)))));
    // checked before the absent-slot rule
    must_fail("before-absent", "misconfigured", &verify(&pcactn(&g, None), &g, Some(&pol(true, Some(-1.0), None))));
}

#[test]
fn kill_thresholds_inclusive() {
    let g = bound();
    let p = pcactn(&g, Some(the_intent())); // fidelity 950000, residual 4310000
    must_pass("min ==", &verify(&p, &g, Some(&pol(false, Some(950_000.0), None))));
    must_pass("min -1", &verify(&p, &g, Some(&pol(false, Some(949_999.0), None))));
    must_fail("min +1", "below the policy minimum", &verify(&p, &g, Some(&pol(false, Some(950_001.0), None))));
    must_pass("max ==", &verify(&p, &g, Some(&pol(false, None, Some(4_310_000.0)))));
    must_pass("max +1", &verify(&p, &g, Some(&pol(false, None, Some(4_310_001.0)))));
    must_fail("max -1", "exceeds the policy maximum", &verify(&p, &g, Some(&pol(false, None, Some(4_309_999.0)))));
    must_fail("floor first", "below the policy minimum", &verify(&p, &g, Some(&pol(false, Some(950_001.0), Some(0.0)))));
    let q = pcactn(&g, Some(patched("goal_salt", json!("wrong"))));
    must_fail("binding first", "do not open", &verify(&q, &g, Some(&pol(false, Some(950_001.0), None))));
}

#[test]
fn kill_root_grant_binding() {
    let bc = json!(bound_commit(SALT));
    let g = bound();
    let p = pcactn(&g, Some(the_intent()));
    // a grant that is not the chain root fails `chain`, but the intent check still reads it (isolates the scan rules)
    let cases = [
        ("non-object-caveats-skipped", json!({"caveats": [5, "x", null, [1], envelope(bc.clone())]}), true),
        ("non-envelope-skipped", json!({"caveats": [{"type": "max_spend"}, envelope(bc.clone())]}), true),
        ("untyped-skipped", json!({"caveats": [{"goal_commit": "x"}, envelope(bc.clone())]}), true),
        ("first-envelope-wins", json!({"caveats": [envelope(json!("decoy")), envelope(bc.clone())]}), false),
        ("first-envelope-bad-type-wins", json!({"caveats": [envelope(json!(7)), envelope(bc.clone())]}), false),
        ("goal-commit-number", json!({"caveats": [envelope(json!(7))]}), false),
        ("goal-commit-missing", json!({"caveats": [{"type": "envelope"}]}), false),
        ("no-envelope", json!({"caveats": [{"type": "max_spend"}]}), false),
        ("empty-caveats", json!({"caveats": []}), false),
        ("caveats-not-array", json!({"caveats": envelope(bc.clone())}), false),
        ("no-caveats-key", json!({}), false),
        ("grant-not-object", json!([envelope(bc.clone())]), false),
    ];
    for (name, grant, pass) in cases {
        let v = verify(&p, &grant, None);
        assert!(!v.allow && v.checks.get("chain") == Some(&false), "{name}: {v:?}");
        assert_eq!(v.checks.get("intent"), Some(&pass), "{name}: {}", v.reason);
    }
    let v = verify(&p, &json!({}), None);
    assert!(v.reason.starts_with("chain: "));
    for (k, x) in [("ref", json!(digest("other"))), ("map_digest", json!(digest("other"))), ("goal_salt", json!(format!("{SALT}x")))] {
        must_fail(k, "do not open", &verify(&pcactn(&g, Some(patched(k, x))), &g, None));
    }
    // a ref-only goal ("pca-intent:v1:" + ref) does not open
    let ref_only = hash_canonical_strict(&json!({"d": "atlas-pca/goal/v1\u{0}", "goal": format!("pca-intent:v1:{}", ref_()), "salt": SALT})).unwrap();
    let h = root_grant(json!([envelope(json!(ref_only))]));
    must_fail("ref-only-goal", "do not open", &verify(&pcactn(&h, Some(the_intent())), &h, None));
    // the exact preimage
    let want = hash_canonical_strict(&json!({"d": "atlas-pca/goal/v1\u{0}", "goal": format!("pca-intent:v1:{}:{}", ref_(), map_()), "salt": SALT}));
    assert_eq!(intent_goal_commit(&ref_(), &map_(), SALT), want);
    // distinct reasons
    must_fail("no-commitment", "no envelope goal commitment", &verify(&pcactn(&root_grant(json!([])), Some(the_intent())), &root_grant(json!([])), None));
}

#[test]
fn kill_verdict_shape_and_order() {
    let g = bound();
    // counter_format is evaluated before intent: both fail, counter_format is the reason
    let mut p = pcactn(&g, Some(patched("goal_salt", json!("wrong"))));
    p["counter"] = json!(-1);
    let m = p.as_object_mut().unwrap();
    m.remove("sig");
    let msg = threshold_message(m).unwrap();
    m.insert("sig".into(), json!(b64(&key("agent").sign(&msg).to_bytes())));
    let v = verify(&p, &g, None);
    assert!(!v.allow && v.checks.len() == 10 && v.checks.get("counter_format") == Some(&false) && v.checks.get("intent") == Some(&false), "{v:?}");
    assert!(v.reason.starts_with("counter_format: "), "{}", v.reason);
    // a wire failure never reports intent, even under an active policy
    must_wire("wire beats policy", &verify(&pcactn(&g, Some(patched("fidelity_ppm", json!(-1)))), &g, Some(&pol(true, None, None))));
    // the JSON entry point threads the policy too
    let text = serde_json::to_string(&pcactn(&g, None)).unwrap();
    let v = verify_pcactn_json_with(&text, &g, NOW, AUD, &VerifyOptions { allowed: None, intent: Some(&pol(true, None, None)), intent_v2: None });
    must_fail("json entry", "requires an intent binding", &v);
    let v = verify_pcactn_json_policy(&text, &g, NOW, AUD, None);
    assert!(v.allow && !v.checks.contains_key("intent"));
}

#[test]
fn kill_tamper_after_signing() {
    let g = bound();
    let mut p = pcactn(&g, Some(the_intent()));
    must_pass("signed", &verify(&p, &g, None));
    p["intent"]["fidelity_ppm"] = json!(999_999); // NOT re-signed
    let v = verify(&p, &g, None);
    assert!(!v.allow && v.checks.get("leaf_signature") == Some(&false) && v.checks.get("intent") == Some(&true), "{v:?}");
    assert!(v.reason.starts_with("leaf_signature: "), "{}", v.reason);
}

#[test]
fn kill_policy_from_json() {
    for v in [json!(null), json!([]), json!("x"), json!(1)] {
        assert!(IntentPolicy::from_json(&v).is_none(), "{v}");
    }
    assert_eq!(IntentPolicy::from_json(&json!({})), Some(IntentPolicy::default()));
    assert!(IntentPolicy::from_json(&json!({"require": true})).unwrap().require);
    assert!(!IntentPolicy::from_json(&json!({"require": "true"})).unwrap().require);
    let p = IntentPolicy::from_json(&json!({"min_fidelity_ppm": 7, "max_residual_risk_ppm": -2.5})).unwrap();
    assert_eq!((p.min_fidelity_ppm, p.max_residual_risk_ppm), (Some(7.0), Some(-2.5)));
    for x in [json!("5"), json!(true), json!(null), json!({})] {
        let p = IntentPolicy::from_json(&json!({"min_fidelity_ppm": x.clone(), "max_residual_risk_ppm": x})).unwrap();
        assert!(p.is_active() && p.min_fidelity_ppm.unwrap().is_nan() && p.max_residual_risk_ppm.unwrap().is_nan());
    }
}

/// A threshold is valid iff its NUMERIC VALUE is a non-negative safe integer, whatever its lexical form.
#[test]
fn kill_policy_lexical_forms() {
    let g = bound();
    let p = pcactn(&g, Some(the_intent())); // fidelity 950000, residual 4310000
    let pol_of = |text: &str| IntentPolicy::from_json_text(text).unwrap();
    for text in [
        r#"{"min_fidelity_ppm":950000.0}"#,
        r#"{"max_residual_risk_ppm":4.31e6}"#,
        r#"{"max_residual_risk_ppm":4.31E+6}"#,
        r#"{"min_fidelity_ppm":0.0}"#,
        r#"{"max_residual_risk_ppm":9007199254740991}"#,
    ] {
        must_pass(text, &verify(&p, &g, Some(&pol_of(text))));
    }
    let e6 = pol_of(r#"{"min_fidelity_ppm":1e6}"#);
    assert_eq!(e6.min_fidelity_ppm, Some(1_000_000.0));
    must_fail("1e6 floor", "below the policy minimum", &verify(&p, &g, Some(&e6)));
    for text in [
        r#"{"min_fidelity_ppm":-0.0}"#,
        r#"{"min_fidelity_ppm":-0}"#,
        r#"{"min_fidelity_ppm":950000.5}"#,
        r#"{"max_residual_risk_ppm":-1}"#,
        r#"{"max_residual_risk_ppm":9007199254740992}"#,
        r#"{"max_residual_risk_ppm":1e16}"#,
        r#"{"min_fidelity_ppm":null}"#,
        r#"{"min_fidelity_ppm":true}"#,
        r#"{"min_fidelity_ppm":"950000"}"#,
    ] {
        must_fail(text, "misconfigured", &verify(&p, &g, Some(&pol_of(text))));
    }
    for text in ["[]", "\"x\"", "{", "nul"] {
        assert!(IntentPolicy::from_json_text(text).is_err(), "{text}");
    }
}
