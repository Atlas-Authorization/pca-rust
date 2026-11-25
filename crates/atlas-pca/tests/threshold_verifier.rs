//! The t-of-n threshold verifier and the `threshold` hook it builds for `authorize`: registered roles and keys only, distinct keys
//! counted, a server-derived `t`, and no default taken from the agent's own claim.

use atlas_pca::agent::{KeyPair, Suite};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::signers_more::sign_threshold_share;
use atlas_pca::threshold::{assemble_threshold, create_threshold_verifier, verify_threshold};
use atlas_pca::HookResult;

fn keys() -> (KeyPair, KeyPair, KeyPair) {
    (KeyPair::from_seed(&[1; 32]), KeyPair::from_seed(&[2; 32]), KeyPair::from_seed(&[3; 32]))
}

fn set(a: &KeyPair, g: &KeyPair, p: &KeyPair) -> Vec<Value> {
    vec![json!({"role": "agent", "publicKey": a.public}), json!({"role": "guardian", "publicKey": g.public}), json!({"role": "principal", "publicKey": p.public})]
}

#[test]
fn shares_count_by_registered_role_and_distinct_key() {
    let (a, g, p) = keys();
    let ss = set(&a, &g, &p);
    let msg = b"threshold message".to_vec();
    let share = |role: &str, k: &KeyPair, t: i64| sign_threshold_share(role, k, &msg, &ss, t, &Suite::default()).unwrap();
    let ssv = Value::Array(ss.clone());

    let two = assemble_threshold(&[share("guardian", &g, 2), share("principal", &p, 2)]);
    let v = verify_threshold(&two, &msg, &ssv, &json!(2), None);
    assert_eq!((v["ok"].as_bool(), v["count"].as_u64()), (Some(true), Some(2)), "{v}");

    // the same key twice is one key; a share bound to another t does not verify under this t
    let dup = assemble_threshold(&[share("guardian", &g, 2), share("guardian", &g, 2)]);
    assert_eq!(verify_threshold(&dup, &msg, &ssv, &json!(2), None)["ok"], json!(false));
    let other_t = assemble_threshold(&[share("guardian", &g, 3), share("principal", &p, 3)]);
    assert_eq!(verify_threshold(&other_t, &msg, &ssv, &json!(2), None)["ok"], json!(false));

    // a key outside the signer set, another message, a malformed set and an invalid t all fail closed
    let stranger = KeyPair::from_seed(&[9; 32]);
    let outside = assemble_threshold(&[share("guardian", &stranger, 2), share("principal", &p, 2)]);
    assert_eq!(verify_threshold(&outside, &msg, &ssv, &json!(2), None)["reason"], json!("share for role guardian uses a key not registered for that role"));
    assert_eq!(verify_threshold(&two, b"another message", &ssv, &json!(2), None)["ok"], json!(false));
    assert_eq!(verify_threshold(&two, &msg, &json!([{"role": "owner", "publicKey": g.public}]), &json!(1), None)["reason"], json!("malformed signer set"));
    for t in [json!(0), json!(4), json!(1.5), json!("2"), Value::Null] {
        assert_eq!(verify_threshold(&two, &msg, &ssv, &t, None)["ok"], json!(false), "t={t}");
    }
}

#[test]
fn the_hook_needs_a_server_side_threshold_and_reports_the_t_it_enforced() {
    let (a, g, p) = keys();
    let ss = set(&a, &g, &p);
    assert!(create_threshold_verifier(ss.clone(), None, None).is_err(), "no default from the agent's own claim");

    let mut pc = json!({"id": "act-1", "action": {"verb": "refund", "resource": "orders/1"}, "cap_chain": []});
    let msg = atlas_pca::threshold_message(pc.as_object().unwrap()).unwrap();
    let share = |role: &str, k: &KeyPair| sign_threshold_share(role, k, &msg, &ss, 2, &Suite::default()).unwrap();
    pc["threshold"] = assemble_threshold(&[share("guardian", &g), share("principal", &p)]);
    let grant = json!({});

    let fixed = create_threshold_verifier(ss.clone(), Some(2), None).unwrap();
    assert_eq!(fixed(&pc, &grant, 0), HookResult::Enforced { ok: true, reason: None, t: Some(2) });

    // the server asks for 3: the two shares (bound to t=2) do not meet it
    let derived = create_threshold_verifier(ss.clone(), None, Some(Box::new(|_ctx: &Value| 3))).unwrap();
    assert!(matches!(derived(&pc, &grant, 0), HookResult::Enforced { ok: false, t: Some(3), .. }));

    // a share removed after signing leaves one key
    pc["threshold"] = assemble_threshold(&[share("guardian", &g)]);
    assert!(matches!(fixed(&pc, &grant, 0), HookResult::Enforced { ok: false, t: Some(2), .. }));
}
