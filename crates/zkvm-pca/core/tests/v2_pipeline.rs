//! Intent Layer v2 pipeline in the guest (`intent_v2::decide_intent_v2`) against the TypeScript reference `decideIntentV2`
//! (fixtures/ts_v2_pipeline.json, gen_ts_v2_pipeline.ts) over the realistic rule-13 scenarios: the ordered (check, ok) list and
//! the verifier-computed env must be identical. Scenarios with a post-quantum suite (`pq`) must match exactly too (the guest
//! implements the suites, pq_suites.rs).
use pca_zkvm_core::intent_v2::{decide_intent_v2, v2_env};
use serde_json::{json, Value};

fn fx() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ts_v2_pipeline.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn decide_intent_v2_matches_the_reference() {
    let d = fx();
    let cases = d["cases"].as_array().unwrap();
    assert!(cases.len() >= 80);
    let mut bad = Vec::new();
    for c in cases {
        let ctx = c.get("ctx");
        let now = c["now"].as_f64().unwrap_or(f64::NAN);
        let got = decide_intent_v2(&c["pcactn"], &c["grant"], ctx, now);
        let got_checks: Vec<Value> = got.checks.iter().map(|x| json!({"name": x.name, "ok": x.ok})).collect();
        let want_checks = c["checks"].as_array().unwrap();
        let pq = c["pq"].as_bool().unwrap_or(false);
        let names_eq = got_checks.iter().map(|x| &x["name"]).eq(want_checks.iter().map(|x| &x["name"]));
        let _ = pq; // PCA 0.4.2: PQ suites are implemented in the guest: every case must match exactly
        // a registered suite the guest does not implement (LESS): the check that verifies it must fail in the guest where the
        // reference (with its optional LESS backend) may pass; every other check must match exactly
        let less = c["name"].as_str().unwrap_or("").contains("less");
        let ok_eq = names_eq
            && got.checks.iter().zip(want_checks).all(|(g, w)| {
                json!({"name": g.name, "ok": g.ok}) == *w
                    || (less && !g.ok && w["name"] == g.name && g.reason.as_deref().is_some_and(|r| r.contains("unsupported_suite")))
            });
        // TS leaves `env` as `{}` when W-B ran without computing members; the guest returns no members. Both give the
        // identical effective predicate env (v2_env merges nothing), so `{}` and absent compare equal here.
        let norm = |v: &Value| if v.is_null() || v == &json!({}) { Value::Null } else { v.clone() };
        let env_got = if got.env.is_empty() { Value::Null } else { Value::Object(got.env.clone()) };
        let env_eq = norm(&env_got) == norm(&c["env"]);
        if !(ok_eq && env_eq) {
            bad.push(format!("{}: guest {:?} env {} | TS {} env {}", c["name"], got_checks, env_got, c["checks"], c["env"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} pipeline cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn v2_env_replaces_only_the_verifier_members() {
    let host = json!({"acc": "host", "canon": 1, "x": 2, "world": {}});
    let p_no = json!({});
    let d = pca_zkvm_core::intent_v2::V2Decision::default();
    assert_eq!(v2_env(Some(&host), &p_no, &d), Some(host.clone()), "no intent_session: host env unchanged");
    let p = json!({"intent_session": {}});
    let mut d = d;
    d.env.insert("acc".into(), json!({"a": {"post": 3}}));
    assert_eq!(v2_env(Some(&host), &p, &d), Some(json!({"x": 2, "acc": {"a": {"post": 3}}})));
    assert_eq!(v2_env(None, &p, &pca_zkvm_core::intent_v2::V2Decision::default()), Some(json!({})));
}
