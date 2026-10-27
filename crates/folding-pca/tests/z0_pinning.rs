//! R3-15: the verifier pins the initial state z0 = [0, 0]; it is not taken from the caller or a public-IO file.
//! PoC: redteam/round3/zk/src/folding_z0.rs. The step circuit only constrains `budget_spent' in
//! [0, B_MAX]; a prover that starts from the field-negative z0 = [0, -X] folds a history whose real total
//! exceeds B_MAX by X, and Nova accepts it *under that z0*. Before the fix `verify_compressed(.., z0)` took
//! z0 from the caller, so a verifier that read z0 from the prover's public IO (fixtures/public_io.json carries
//! it) accepted an over-budget history whose chain digest still matched the honest ledger.
use ff::Field;
use pca_folding_ivc::*;

const COSTS: [u64; 3] = [4_000_000_000, 600_000, 300_000]; // the first step alone is 4000x B_MAX

fn actions() -> Vec<ActionStep> {
    COSTS.iter().enumerate().map(|(i, &c)| ActionStep { action_digest: 100 + i as u64, cost: c }).collect()
}

/// A prover that starts from the field-negative z0 (the PoC's attack) and folds the over-budget history.
fn attack(lie: Scalar) -> (PP, Recursive, Vec<Scalar>) {
    let acts = actions();
    let circuits = circuits_for(&acts);
    let pp = public_params(&circuits[0]).unwrap();
    let z0 = vec![Scalar::ZERO, lie];
    let mut rs = Recursive::new(&pp, &circuits[0], &z0).unwrap();
    for c in &circuits {
        rs.prove_step(&pp, c).unwrap();
    }
    (pp, rs, z0)
}

#[test]
fn honest_over_budget_history_is_unprovable() {
    assert!(prove_history(&actions()).is_err());
}

#[test]
fn a_proof_folded_from_a_field_negative_start_is_rejected_by_the_pinned_verifier() {
    let lie = -Scalar::from(4_000_000_000u64);
    let (pp, rs, z0) = attack(lie);
    // the attack really is a valid Nova proof under the attacker's own z0 (this is what the old API accepted) ...
    assert!(rs.verify(&pp, 3, &z0).is_ok(), "control: Nova itself accepts the proof under the attacker's z0");
    // ... and the chain digest of the attacker's history is the honest ledger digest, so a digest-only check passes
    let out = rs.verify(&pp, 3, &z0).unwrap();
    assert_eq!(out[0], native_final_state(&actions()).0);
    // but every verifier entry point now pins z0 = [0, 0]
    assert!(verify_recursive(&pp, &rs, 3).is_err(), "pinned recursive verify must reject");
    let (pk, vk) = compress_keys(&pp).unwrap();
    let comp = compress(&pp, &pk, &rs).unwrap();
    assert!(verify_compressed(&comp, &vk, 3).is_err(), "pinned compressed verify must reject");
    // a caller that reads the prover's claimed z0 gets a refusal, not a verification under it
    assert!(verify_compressed_claimed(&comp, &vk, 3, &z0).is_err());
    assert!(verify_recursive_claimed(&pp, &rs, 3, &z0).is_err());
    // claiming the honest z0 does not help: the proof was folded from another start
    assert!(verify_compressed_claimed(&comp, &vk, 3, &initial_state()).is_err());
}

#[test]
fn honest_proofs_still_verify_with_the_pinned_start() {
    let p = prove_history(&[ActionStep { action_digest: 1, cost: 400_000 }, ActionStep { action_digest: 2, cost: 500_000 }]).unwrap();
    let (pk, vk) = compress_keys(&p.pp).unwrap();
    let c = compress(&p.pp, &pk, &p.recursive).unwrap();
    assert_eq!(verify_compressed(&c, &vk, 2).unwrap(), p.final_state);
    assert_eq!(verify_compressed_claimed(&c, &vk, 2, &p.z0).unwrap(), p.final_state);
    assert_eq!(verify_recursive(&p.pp, &p.recursive, 2).unwrap(), p.final_state);
}

#[test]
fn only_exactly_zero_zero_passes_the_pin_mutations() {
    assert!(check_claimed_z0(&initial_state()).is_ok());
    let one = Scalar::ONE;
    for bad in [
        vec![one, Scalar::ZERO],
        vec![Scalar::ZERO, one],
        vec![Scalar::ZERO, -one],
        vec![Scalar::ZERO, -Scalar::from(4_000_000_000u64)],
        vec![Scalar::ZERO],
        vec![Scalar::ZERO, Scalar::ZERO, Scalar::ZERO],
        vec![],
    ] {
        assert!(check_claimed_z0(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_initial_state_commitment_is_stable_and_distinguishes_starts() {
    let c = initial_state_commitment();
    assert_eq!(c, hash2_native(Scalar::ZERO, Scalar::ZERO));
    assert_ne!(c, hash2_native(Scalar::ZERO, -Scalar::from(4_000_000_000u64)));
    assert_ne!(c, Scalar::ZERO);
}

#[test]
fn the_committed_public_io_records_the_pinned_start_and_its_commitment() {
    let io: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/public_io.json")).unwrap(),
    )
    .unwrap();
    let zero = felt_to_hex(&Scalar::ZERO);
    assert_eq!(io["z0"], serde_json::json!([zero, zero]));
    assert_eq!(io["z0_commitment"], felt_to_hex(&initial_state_commitment()), "public_io.json z0_commitment");
}
