//! Fraud-proof filing, the interactive dispute game and the open-time snapshot freeze. The fixtures (grant, snapshots, claims,
//! PCActns and the proofs the TypeScript reference filed for them) are the ones the scripted ledger cases of
//! test-data/ref-core-bond-settlement-java.json.gz carry, so `file_fraud_proof` is compared with the reference's own proofs.
mod common;
use atlas_pca::optimistic_adjudication::*;
use atlas_pca::policy_vm::decide;
use atlas_pca::serde_json::{json, Map, Value};

fn fixtures() -> Map<String, Value> {
    let mut all = Map::new();
    for c in common::ref_cases("core-bond-settlement-java").iter().filter(|c| c["fn"] == "ledger") {
        for (k, v) in c["args"][0].as_object().into_iter().flatten() {
            all.insert(k.clone(), v.clone());
        }
    }
    all
}

fn vm(input: &Value) -> Result<Value, String> {
    Ok(decide(input))
}

fn blast(input: &str, _snap: &Value) -> Result<Value, String> {
    Ok(if input == "blastRadius" { json!({"input": "blastRadius", "value": 0.95, "valid": true}) } else { Value::Null })
}

fn game(fx: &Map<String, Value>, steps: Value, defender: Value, challenger: Value) -> Value {
    json!({"pcactn_digest": fx["claim_ok"]["pcactn_digest"], "bond_ref": fx["claim_ok"]["bond_ref"], "steps": steps, "defender": defender, "challenger": challenger})
}

#[test]
fn file_fraud_proof_matches_the_proofs_the_reference_filed() {
    let fx = fixtures();
    let mut checked = 0;
    // (claim and PCActn, snapshot) -> the proof the reference filed (null: the claim is compliant, nothing to file)
    for (c, s) in [("low", "ok"), ("deny", "deny"), ("irr", "irr"), ("high", "high"), ("mid-low", "mid"), ("ok-hi", "ok")] {
        let (Some(claim), Some(pc), Some(snap), Some(want)) = (fx.get(&format!("claim_{c}")), fx.get(&format!("pc_{c}")), fx.get(&format!("snap_{s}")), fx.get(&format!("proof_{c}"))) else { continue };
        let got = file_fraud_proof(claim, pc, &fx["grant"], snap, None, Some(&vm)).expect("filed").unwrap_or(Value::Null);
        assert_eq!(atlas_pca::canonicalize(want), atlas_pca::canonicalize(&got), "fileFraudProof {c}");
        if !want.is_null() {
            let v = verify_fraud_proof(claim, &got, &fx["grant"], snap, Some(&vm));
            assert_eq!(v["fraudulent"], json!(true), "the filed proof verifies ({c}): {v}");
        }
        checked += 1;
    }
    assert!(checked >= 4, "the corpus fixtures cover fileFraudProof ({checked})");
}

#[test]
fn file_fraud_proof_files_nothing_that_is_not_fraud_and_fails_closed_without_a_policy_vm() {
    let fx = fixtures();
    let grant = &fx["grant"];
    assert_eq!(file_fraud_proof(&fx["claim_low"], &fx["pc_low"], grant, &Value::Null, None, Some(&vm)), Ok(None), "no snapshot");
    assert_eq!(file_fraud_proof(&fx["claim_low"], &fx["pc_deny"], grant, &fx["snap_ok"], None, Some(&vm)), Ok(None), "a claim for another action");
    assert!(file_fraud_proof(&fx["claim_low"], &fx["pc_low"], grant, &fx["snap_ok"], None, None).is_err(), "no Policy VM");
}

#[test]
fn a_one_step_game_is_the_one_shot_dispute_and_bisection_localizes_the_contested_step() {
    let fx = fixtures();
    let (claim, grant, snap) = (&fx["claim_ok"], &fx["grant"], &fx["snap_ok"]);
    let one = adjudicate_dispute_game(claim, &game(&fx, json!(["blastRadius"]), json!([{"value": 0.1}]), json!([{"value": 0.95}])), grant, snap, Some(&blast), None, Some(&vm));
    let direct = adjudicate_dispute(claim, &fx["disp_ok_blastRadius"], grant, snap, Some(&blast), None, Some(&vm));
    assert_eq!((one["converged"].as_bool(), one["contestedStep"].as_i64(), one["rounds"].as_i64()), (Some(true), Some(0), Some(0)), "{one}");
    assert_eq!(one["verdict"]["outcome"], json!("agent-fraud"));
    assert_eq!(atlas_pca::canonicalize(&one["verdict"]), atlas_pca::canonicalize(&direct));

    // both parties agree on the first step (the snapshot's own semantic distance) and differ on the second
    let two = adjudicate_dispute_game(
        claim,
        &game(&fx, json!(["semanticDistance", "blastRadius"]), json!([{"value": 0.2}, {"value": 0.1}]), json!([{"value": 0.2}, {"value": 0.95}])),
        grant,
        snap,
        Some(&blast),
        None,
        Some(&vm),
    );
    assert_eq!((two["converged"].as_bool(), two["contestedStep"].as_i64(), two["rounds"].as_i64()), (Some(true), Some(1), Some(1)), "{two}");
    assert_eq!(two["contestedInput"], json!("blastRadius"));
    assert_eq!(two["transcript"], json!([{"lo": 0, "hi": 2, "mid": 1, "agreedAtMid": true}]));
    assert_eq!(two["verdict"]["outcome"], json!("agent-fraud"));
}

#[test]
fn the_dispute_game_fails_closed() {
    let fx = fixtures();
    let (claim, grant, snap) = (&fx["claim_ok"], &fx["grant"], &fx["snap_ok"]);
    let good = game(&fx, json!(["blastRadius"]), json!([{"value": 0.1}]), json!([{"value": 0.95}]));
    let mut other_bond = good.clone();
    other_bond["bond_ref"] = json!("elsewhere");
    let cases = [
        ("malformed", adjudicate_dispute_game(claim, &json!("x"), grant, snap, Some(&blast), None, Some(&vm))),
        ("no oracle", adjudicate_dispute_game(claim, &good, grant, snap, None, None, Some(&vm))),
        ("no snapshot", adjudicate_dispute_game(claim, &good, grant, &Value::Null, Some(&blast), None, Some(&vm))),
        ("no Policy VM", adjudicate_dispute_game(claim, &good, grant, snap, Some(&blast), None, None)),
        ("identical traces", adjudicate_dispute_game(claim, &game(&fx, json!(["blastRadius"]), json!([{"value": 0.1}]), json!([{"value": 0.1}])), grant, snap, Some(&blast), None, Some(&vm))),
        ("short trace", adjudicate_dispute_game(claim, &game(&fx, json!(["blastRadius", "semanticDistance"]), json!([{"value": 0.1}]), json!([{"value": 0.95}])), grant, snap, Some(&blast), None, Some(&vm))),
        ("unknown step", adjudicate_dispute_game(claim, &game(&fx, json!(["budget"]), json!([{"value": 0.1}]), json!([{"value": 0.95}])), grant, snap, Some(&blast), None, Some(&vm))),
        ("other bond", adjudicate_dispute_game(claim, &other_bond, grant, snap, Some(&blast), None, Some(&vm))),
    ];
    for (what, r) in cases {
        assert_eq!((r["converged"].as_bool(), r["verdict"]["outcome"].as_str(), r["verdict"]["fraudulent"].as_bool()), (Some(false), Some("indeterminate"), Some(false)), "{what}: {r}");
        assert_eq!(r["verdict"]["slashCounterBond"], json!(false), "{what}: neither bond is slashed");
    }
}

#[test]
fn a_frozen_snapshot_is_an_equal_independent_copy() {
    let fx = fixtures();
    let frozen = freeze_open_snapshot(&fx["snap_ok"]).expect("frozen");
    assert_eq!(frozen, fx["snap_ok"]);
    let mut changed = fx["snap_ok"].clone();
    changed["risk"]["blastRadius"] = json!(1);
    assert_ne!(frozen, changed);
}
