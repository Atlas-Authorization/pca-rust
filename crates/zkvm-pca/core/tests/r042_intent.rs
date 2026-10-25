//! PCA 0.4.2 Intent Layer M2 in the guest: the signed `intent` slot of a PCActn (intent-binding.ts).
//!
//! * `fixtures/ts_intent_cases.json` (TS reference verdicts, `gen_ts_intent_cases.ts`): `validateIntentWire` (35 slots),
//!   `intentGoalCommit` (3) and `decideIntentBinding` (360 slot x root grant x policy combinations) are reproduced by the
//!   guest's in-guest binding (`bind_intent`) followed by the verifier's policy (`check_intent_policy`).
//! * decide(): a validly signed PCActn carrying a bound intent is allowed and commits the claims; a malformed or unbound
//!   slot denies; the verifier's `check_context` applies the relying party's policy to the journal.
use pca_zkvm_core::context::{check_context, ContextMismatch, ExpectedContext};
use pca_zkvm_core::intent::{
    bind_intent, check_intent_policy, intent_goal_commit, validate_intent_wire, IntentClaim, IntentPolicy, IntentPolicyFailure,
};
use pca_zkvm_core::{decide, DecideInput};
use serde_json::{json, Value};

#[path = "support/chain_mint.rs"]
mod mint;

fn fx(rel: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(rel);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn policy(v: Option<&Value>) -> IntentPolicy {
    let v = match v {
        Some(Value::Object(o)) => o,
        _ => return IntentPolicy::default(),
    };
    IntentPolicy {
        require: v.get("require").and_then(|x| x.as_bool()) == Some(true),
        min_fidelity_ppm: v.get("min_fidelity_ppm").and_then(|x| x.as_u64()),
        max_residual_risk_ppm: v.get("max_residual_risk_ppm").and_then(|x| x.as_u64()),
    }
}

#[test]
fn wire_rules_match_the_reference() {
    let d = fx("ts_intent_cases.json");
    let cases = d["wire"].as_array().unwrap();
    assert!(cases.len() >= 35);
    let bad: Vec<String> = cases
        .iter()
        .filter(|c| validate_intent_wire(&c["slot"]).is_ok() != c["ok"].as_bool().unwrap())
        .map(|c| format!("{} (TS ok={})", c["slot"], c["ok"]))
        .collect();
    assert!(bad.is_empty(), "wire verdicts differ from TS:\n{}", bad.join("\n"));
}

#[test]
fn goal_commitment_matches_the_reference() {
    let d = fx("ts_intent_cases.json");
    for c in d["commit"].as_array().unwrap() {
        let got = intent_goal_commit(c["ref"].as_str().unwrap(), c["map_digest"].as_str().unwrap(), c["goal_salt"].as_str().unwrap());
        assert_eq!(got, c["commit"].as_str().unwrap(), "{c}");
    }
}

#[test]
fn binding_and_policy_match_decide_intent_binding() {
    let d = fx("ts_intent_cases.json");
    let cases = d["binding"].as_array().unwrap();
    assert!(cases.len() >= 360);
    let mut bad = Vec::new();
    for c in cases {
        let grant = &d["grants"][c["grant"].as_str().unwrap()];
        let slot = d["slots"].get(c["slot"].as_str().unwrap());
        let pol = policy(d["policies"].get(c["policy"].as_str().unwrap()));
        let pcactn = match slot {
            Some(s) => json!({ "intent": s }),
            None => json!({}),
        };
        let got = match bind_intent(&pcactn, grant) {
            Err(_) => "fail",
            Ok(claim) => match check_intent_policy(claim.as_ref(), &pol) {
                Err(_) => "fail",
                Ok(()) if claim.is_none() && !pol.active() => "absent",
                Ok(()) => "pass",
            },
        };
        if got != c["status"].as_str().unwrap() {
            bad.push(format!("{}/{}/{}: guest {got}, TS {}", c["grant"], c["slot"], c["policy"], c["status"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} binding verdicts differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

// ---- decide() on a validly signed, minted chain ----------------------------------------------------------------------

fn base() -> Value {
    fx("decide_input.sample.json")
}

fn slot(salt: &str, fidelity: u64) -> Value {
    let d = fx("ts_intent_cases.json");
    let v = &d["slots"]["valid"];
    json!({ "ref": v["ref"], "map_digest": v["map_digest"], "goal_salt": salt, "fidelity_ppm": fidelity, "residual_risk_ppm": 2500 })
}

/// The minted fixture with its root envelope's `goal_commit` opened by `bind` (ref, map_digest, salt) and the PCActn
/// carrying `intent` (re-signed by the leaf holder).
fn with_intent(bind: &Value, intent: Option<Value>) -> Value {
    let commit = intent_goal_commit(bind["ref"].as_str().unwrap(), bind["map_digest"].as_str().unwrap(), bind["goal_salt"].as_str().unwrap());
    let mut v = mint::envelope_edited(&base(), &|e| e["goal_commit"] = json!(commit.clone()));
    if let Some(i) = intent {
        v["pcactn"]["intent"] = i;
    }
    mint::resign(&mut v, &mint::key(3));
    v
}

fn run(v: &Value) -> (pca_zkvm_core::Decision, ExpectedContext) {
    let d = decide(&serde_json::from_value::<DecideInput>(v.clone()).unwrap());
    let e = ExpectedContext::from_input_json(&v.to_string(), 0.0).unwrap();
    (d, e)
}

#[test]
fn decide_proves_a_bound_intent_and_commits_its_claims() {
    let good = slot("salt-01", 900_000);
    let (d, e) = run(&with_intent(&good, Some(good.clone())));
    assert_eq!(d.allow, 1, "bound intent must be allowed");
    let want = IntentClaim {
        intent_ref: good["ref"].as_str().unwrap().into(),
        map_digest: good["map_digest"].as_str().unwrap().into(),
        fidelity_ppm: 900_000,
        residual_risk_ppm: 2500,
    };
    assert_eq!(d.context.intent.as_ref(), Some(&want));
    assert_eq!(check_context(&d, &e), Ok(()));
    // the relying party's policy is applied to the journal
    let mut e2 = e.clone();
    e2.intent_policy = IntentPolicy { require: false, min_fidelity_ppm: Some(900_000), max_residual_risk_ppm: Some(2500) };
    assert_eq!(check_context(&d, &e2), Ok(()));
    e2.intent_policy.min_fidelity_ppm = Some(900_001);
    assert_eq!(check_context(&d, &e2), Err(ContextMismatch::Intent(IntentPolicyFailure::Fidelity { claimed: 900_000, minimum: 900_001 })));
    e2.intent_policy = IntentPolicy { max_residual_risk_ppm: Some(2499), ..Default::default() };
    assert_eq!(check_context(&d, &e2), Err(ContextMismatch::Intent(IntentPolicyFailure::ResidualRisk { claimed: 2500, maximum: 2499 })));
    e2.intent_policy = IntentPolicy { min_fidelity_ppm: Some(1 << 53), ..Default::default() };
    assert_eq!(check_context(&d, &e2), Err(ContextMismatch::Intent(IntentPolicyFailure::Misconfigured)));
}

#[test]
fn decide_denies_an_unbound_or_malformed_intent() {
    let good = slot("salt-01", 900_000);
    // the slot does not open the root grant's goal commitment
    assert_eq!(run(&with_intent(&good, Some(slot("salt-02", 900_000)))).0.allow, 0, "wrong salt");
    let mut wrong_ref = good.clone();
    wrong_ref["map_digest"] = good["ref"].clone();
    assert_eq!(run(&with_intent(&good, Some(wrong_ref))).0.allow, 0, "wrong map_digest");
    // the minted fixture's own goal commitment (not an intent goal): a slot cannot open it
    let mut v = base();
    v["pcactn"]["intent"] = good.clone();
    mint::resign(&mut v, &mint::key(3));
    assert_eq!(run(&v).0.allow, 0, "grant not minted for this intent");
    // malformed slots
    for bad in [json!({"ref": good["ref"]}), json!("x"), json!(null), json!({ "fidelity_ppm": 1_000_001 }), {
        let mut b = good.clone();
        b["fidelity_ppm"] = json!(1_000_001);
        b
    }, {
        let mut b = good.clone();
        b["extra"] = json!(1);
        b
    }] {
        assert_eq!(run(&with_intent(&good, Some(bad.clone()))).0.allow, 0, "malformed slot {bad}");
    }
}

#[test]
fn no_intent_keeps_the_decision_and_an_active_policy_refuses_it() {
    let good = slot("salt-01", 900_000);
    let (d, e) = run(&with_intent(&good, None));
    assert_eq!(d.allow, 1);
    assert_eq!(d.context.intent, None);
    assert_eq!(check_context(&d, &e), Ok(()));
    let mut e2 = e.clone();
    e2.intent_policy.require = true;
    assert_eq!(check_context(&d, &e2), Err(ContextMismatch::Intent(IntentPolicyFailure::Missing)));
    e2.intent_policy = IntentPolicy { min_fidelity_ppm: Some(0), ..Default::default() };
    assert_eq!(check_context(&d, &e2), Err(ContextMismatch::Intent(IntentPolicyFailure::Missing)));
}

#[test]
fn signature_covers_the_intent_slot() {
    // editing the claimed fidelity after signing breaks the leaf signature (the slot is signed like tool_binding)
    let good = slot("salt-01", 900_000);
    let mut v = with_intent(&good, Some(good.clone()));
    v["pcactn"]["intent"]["fidelity_ppm"] = json!(1_000_000);
    assert_eq!(run(&v).0.allow, 0);
}
