//! Kill tests from the 0.5 full mutation run: behaviour the shared corpora never pin (PQ-suite narrow blocks, the verifier's
//! bind-`action` digest against the producer's, how a presented K1 input merges into the configured one).
use atlas_pca::agent::{discharge_action_digest as producer_action_digest, sign_narrow, KeyPair, PqKeyPair, Suite};
use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{discharge_action_digest, hash_canonical_strict, verify_narrow, DischargePin, K1Input, NarrowBinding, NarrowVerdict, PresentedK1};

fn grant_for(principal: &KeyPair, agent: &KeyPair, holder_pq: Option<&str>) -> Value {
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    mint_grant(principal, &agent.public, &env, "refund an order", None, holder_pq, &Suite::default()).unwrap().grant
}

#[test]
fn narrow_block_under_a_pq_suite_needs_the_committed_pq_key() {
    let (alg, fam) = ("hybrid-ed25519-ml-dsa-65", "ML-DSA-65");
    let (pq, other) = (PqKeyPair::generate(fam).unwrap(), PqKeyPair::generate(fam).unwrap());
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let grant = grant_for(&principal, &key, Some(&pq.public));
    let leaf = hash_canonical_strict(&grant).unwrap();
    let (iat, na) = (1_800_000_000_000i64, 1_800_000_060_000i64);
    let bind = NarrowBinding { now: iat + 1, action_digest: None };
    let caveats = json!([{"type": "expires", "at": na}]);
    let sign = |k: &PqKeyPair| sign_narrow(&key, &leaf, &caveats, iat, na, None, None, &Suite { alg: Some(alg), pq: Some(k) }).unwrap();
    match verify_narrow(&sign(&pq), &grant, &Value::Null, &bind) {
        NarrowVerdict::Ok { caveats: got } => assert_eq!(Value::Array(got), caveats),
        v => panic!("the committed PQ key was refused: {v:?}"),
    }
    match verify_narrow(&sign(&other), &grant, &Value::Null, &bind) {
        NarrowVerdict::Fail { reason } => assert_eq!(reason, "narrow signature invalid"),
        v => panic!("a PQ key the leaf never committed to verified: {v:?}"),
    }
    // the same PQ suite on a leaf that commits to no PQ key: nothing to pin, so refused
    let plain = grant_for(&principal, &key, None);
    let leaf = hash_canonical_strict(&plain).unwrap();
    let n = sign_narrow(&key, &leaf, &caveats, iat, na, None, None, &Suite { alg: Some(alg), pq: Some(&pq) }).unwrap();
    assert!(matches!(verify_narrow(&n, &plain, &Value::Null, &bind), NarrowVerdict::Fail { .. }));
}

#[test]
fn verifier_action_digest_is_the_producers() {
    let (principal, key) = (KeyPair::from_seed(&[3u8; 32]), KeyPair::from_seed(&[4u8; 32]));
    let grant = grant_for(&principal, &key, None);
    for p in [json!({"grant_ref": grant["id"], "verb": "refund", "resource": "orders/1", "counter": 1}), json!({"a": [1, "two"]}), grant] {
        let want = producer_action_digest(&p).unwrap();
        assert_eq!(want.len(), 43, "base64url of 32 bytes");
        assert_eq!(discharge_action_digest(&p).as_deref(), Some(want.as_str()));
    }
    assert_ne!(discharge_action_digest(&json!({"a": 1})), discharge_action_digest(&json!({"a": 2})));
}

#[test]
fn presented_k1_fills_only_what_the_configured_input_leaves_empty() {
    let pin = DischargePin { label: "idp".into(), class: "human".into(), pk: "pk".into(), pq_pk: None, spiffe_id: None };
    let own = K1Input { pins: vec![pin], action_digest: Some("ad".into()), spiffe_id: Some("spiffe://x/y".into()), history: Some(vec![json!({"t": 1})]), revoked_discharges: Some(vec!["r".into()]), ..Default::default() };
    let presented = PresentedK1 { discharges: Some(vec![json!({"d": 1})]), narrow: Some(json!({"n": 1})) };
    let m = presented.merged_into(&own);
    assert_eq!((m.pins.len(), m.pins[0].label.as_str()), (1, "idp"));
    assert_eq!((m.action_digest.as_deref(), m.spiffe_id.as_deref()), (Some("ad"), Some("spiffe://x/y")));
    assert_eq!((m.history, m.revoked_discharges), (Some(vec![json!({"t": 1})]), Some(vec!["r".to_string()])));
    assert_eq!((m.discharges, m.narrow), (vec![json!({"d": 1})], Some(json!({"n": 1}))));
    // own wins where it sets a value
    let set = K1Input { discharges: vec![json!("own")], narrow: Some(json!("own")), ..Default::default() };
    let m = presented.merged_into(&set);
    assert_eq!((m.discharges, m.narrow), (vec![json!("own")], Some(json!("own"))));
    // nothing presented: the configured input unchanged
    let m = PresentedK1::default().merged_into(&own);
    assert_eq!((m.discharges.len(), m.narrow, m.action_digest.as_deref()), (0, None, Some("ad")));
}

#[test]
fn model_paths_stop_at_condition_depth_64() {
    let nest = |depth: usize| {
        let mut c = json!({"field": "env.class.label", "op": "eq", "value": 1});
        for _ in 0..depth {
            c = json!({"all_of": [c]});
        }
        json!([{"where": [c]}])
    };
    assert_eq!(atlas_pca::model_paths_read(&[nest(64)], &[]), vec!["env.class.label".to_string()]);
    assert!(atlas_pca::model_paths_read(&[nest(65)], &[]).is_empty(), "past depth 64 nothing is read");
    // a bare `env` (or a non-env path) is not model-derived
    let flat = |f: &str| json!([{"where": [{"field": f, "op": "eq", "value": 1}]}]);
    assert!(atlas_pca::model_paths_read(&[flat("env")], &[]).is_empty());
    assert!(atlas_pca::model_paths_read(&[flat("x")], &[]).is_empty());
    assert_eq!(atlas_pca::model_paths_read(&[flat("env.judge.x")], &[]), vec!["env.judge.x".to_string()]);
}

#[test]
fn lone_surrogate_markers_need_four_hex_digits_and_the_close_marker() {
    let (open, close) = ('\u{FDD0}', '\u{FDD1}');
    assert_eq!(atlas_pca::restore_lone_surrogates(&format!("a{open}d800{close}b")), "a\\ud800b");
    for kept in [format!("{open}zzzz{close}"), format!("{open}d800x"), format!("{open}d8{close}")] {
        assert_eq!(atlas_pca::restore_lone_surrogates(&kept), kept, "{kept:?} is not a marker");
    }
}

#[test]
fn escalation_clock_bound_is_inclusive() {
    use atlas_pca::{verify_escalation_answer, EscalationBinding, EscalationVerdict};
    let b = EscalationBinding { policy_digest: "p".into(), action_digest: "a".into(), history_head: "h".into(), render_digest: None };
    let clock = "the verifier clock is not a safe integer (fail closed)";
    let max = 9_007_199_254_740_991i64;
    for now in [max, -max] {
        match verify_escalation_answer(&json!(null), &[], &b, now) {
            EscalationVerdict::Refused(r) => assert!(r.starts_with("malformed escalation answer"), "{r}"),
            v => panic!("{v:?}"),
        }
    }
    for now in [max + 1, -max - 1] {
        assert!(matches!(verify_escalation_answer(&json!(null), &[], &b, now), EscalationVerdict::Refused(r) if r == clock));
    }
}

fn units(u: Value) -> Result<(), String> {
    atlas_pca::decide_units(&json!({"units": u, "verb": "pay", "schema_units": {"usd": {"kind": "money"}},
        "verb_params": {"action.params.amt": {"unit": "usd"}}}))
}

#[test]
fn unit_tags_read_keys_in_object_keys_order_and_bound_their_members() {
    let k = json!({"kind": "money"});
    assert_eq!(units(json!({"action.params.a_b": k, "action.params.a-b": k, "action.params.a1": k})), Ok(()));
    assert_eq!(units(json!({"": k})), Err("units key '' must be an action.params.<name> path".into()));
    let unknown = |extra: &str, want: &str| {
        let mut t = json!({"kind": "money", "z": 1});
        t[extra] = json!(1);
        assert_eq!(units(json!({"action.params.x": t})), Err(format!("unknown member 'units['action.params.x'].{want}'")), "{extra}");
    };
    // canonical array indices come first; a leading zero or 2^32-1 is not one
    unknown("01", "z");
    unknown("4294967294", "4294967294");
    unknown("4294967295", "z");
    let exp = |e: Value| units(json!({"action.params.x": {"kind": "money", "exponent": e}}));
    assert_eq!(exp(json!(2)), Ok(()));
    assert_eq!(exp(json!(1.5)), Err("units['action.params.x'].exponent must be an integer in [0, 18]".into()));
    assert_eq!(exp(json!(-0.0)), Err("units['action.params.x'].exponent must be an integer in [0, 18]".into()), "envelope-rules.ts isSafeInt refuses -0");
    let many = |n: usize| units(Value::Object((0..n).map(|i| (format!("action.params.p{i}"), k.clone())).collect()));
    assert_eq!(many(64), Ok(()));
    assert_eq!(many(65), Err("units has more than 64 entries".into()));
    // a schema tag and a policy tag that both omit currency and exponent are the same unit
    assert_eq!(units(json!({"action.params.amt": k})), Ok(()));
}
