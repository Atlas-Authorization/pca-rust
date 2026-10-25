//! RT-05 regression: the per-step cost must be bound to the committed action, so a history relabelled
//! with a forged (lower) cost cannot reproduce the honest history's chain digest.
//! Regression test for an internal red-team finding (fold cost not bound to the step).

use pca_folding_ivc::*;

fn hist(cost: u64) -> Vec<ActionStep> {
    [0xA11CE_u64, 0xB0B, 0xC0DE].iter().map(|&d| ActionStep { action_digest: d, cost }).collect()
}

#[test]
fn native_chain_digest_commits_to_cost() {
    let honest = hist(600_000);
    let forged = hist(0);
    assert_ne!(native_final_state(&honest).0, native_final_state(&forged).0,
        "chain digest must depend on cost");
}

#[test]
fn forged_zero_cost_history_cannot_reproduce_the_honest_chain_digest() {
    let honest = hist(600_000); // 1.8M > B_MAX: unprovable
    assert!(prove_history(&honest).is_err());
    let forged = hist(0);
    let ph = prove_history(&forged).expect("zero-cost history folds on its own terms");
    let (want_chain, _) = native_final_state(&honest);
    assert_ne!(ph.final_state[0], want_chain,
        "RT-05: forged-cost proof must not present the honest history's chain digest");
}

#[test]
fn a_single_cost_edit_changes_the_proved_chain_digest() {
    let a = vec![ActionStep { action_digest: 7, cost: 10 }, ActionStep { action_digest: 8, cost: 20 }];
    let mut b = a.clone();
    b[1].cost = 19;
    let pa = prove_history(&a).unwrap();
    let pb = prove_history(&b).unwrap();
    assert_ne!(pa.final_state[0], pb.final_state[0]);
}
