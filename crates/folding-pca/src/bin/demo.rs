//! Fold a sample action history into ONE proof, verify it, compress it, verify the compressed
//! proof, then show that an over-budget history correctly FAILS to prove. Writes fixtures to
//! `fixtures/`.
//!
//!   cargo run --release --bin demo

use std::fs;
use std::path::Path;
use std::time::Instant;

use pca_folding_ivc::{
    compress, compress_keys, felt_to_hex, native_final_state, prove_history, verify_compressed,
    within_budget, ActionStep, B_MAX, BUDGET_BITS, COST_BITS, MIMC_ROUNDS,
};

/// A compliant 8-action history: Σcost = 8 · 100_000 = 800_000 ≤ B_MAX (1_000_000).
fn good_history() -> Vec<ActionStep> {
    (0..8u64)
        .map(|i| ActionStep {
            action_digest: 0xC0FF_EE00 + i, // a distinct per-action digest
            cost: 100_000,
        })
        .collect()
}

/// An over-budget 8-action history: Σcost = 8 · 200_000 = 1_600_000 > B_MAX. The cumulative
/// bound is breached at action #6 (running total 1_200_000), making the fold unprovable.
fn over_budget_history() -> Vec<ActionStep> {
    (0..8u64)
        .map(|i| ActionStep {
            action_digest: 0xBAD0_0000 + i,
            cost: 200_000,
        })
        .collect()
}

fn main() {
    println!("== pca-folding-ivc : Nova folding proof of a whole PCA action history ==");
    println!("curve cycle        : Pallas / Vesta (cycle of curves)");
    println!("PCS / final SNARK  : IPA (transparent) + Spartan CompressedSNARK");
    println!(
        "chain hash         : MiMC x^5, {MIMC_ROUNDS} rounds (didactic)   B_MAX = {B_MAX}"
    );
    println!("range gadgets      : cost {COST_BITS}-bit, budget/headroom {BUDGET_BITS}-bit");
    println!();

    // ---------------------------------------------------------------- compliant history
    let actions = good_history();
    assert!(within_budget(&actions), "sample history should be within budget");
    println!("folding {} actions (compliant) ...", actions.len());

    let t0 = Instant::now();
    let proved = prove_history(&actions).expect("compliant history must prove");
    let fold_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "  folded + verified RecursiveSNARK in {fold_ms:.1} ms ({} steps)",
        proved.num_steps
    );

    // Cross-check the IVC output against the native replay.
    let (exp_chain, exp_budget) = native_final_state(&actions);
    assert_eq!(proved.final_state.len(), 2);
    assert_eq!(proved.final_state[0], exp_chain, "chain_digest mismatch vs native");
    assert_eq!(proved.final_state[1], exp_budget, "budget_spent mismatch vs native");
    println!("  final chain_digest : {}", felt_to_hex(&proved.final_state[0]));
    println!(
        "  final budget_spent : {} (native-checked)",
        felt_to_hex(&proved.final_state[1])
    );

    // ----------------------------------------------------------------------- compress
    println!("compressing to a single succinct proof ...");
    let t1 = Instant::now();
    let (pk, vk) = compress_keys(&proved.pp).expect("compress setup");
    let setup_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let compressed = compress(&proved.pp, &pk, &proved.recursive).expect("compress prove");
    let compress_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    let out = verify_compressed(&compressed, &vk, proved.num_steps, &proved.z0)
        .expect("compressed proof must verify");
    let verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(out, proved.final_state, "compressed output must equal recursive output");

    let proof_bytes = bincode::serialize(&compressed).expect("serialize compressed proof");
    let vk_bytes = bincode::serialize(&vk).expect("serialize verifier key");
    println!("  compress setup     : {setup_ms:.1} ms");
    println!("  compress prove     : {compress_ms:.1} ms");
    println!("  compress verify    : {verify_ms:.1} ms");
    println!("  compressed proof   : {} bytes", proof_bytes.len());
    println!("  verifier key       : {} bytes", vk_bytes.len());
    println!();

    // ---------------------------------------------------- over-budget history must FAIL
    let bad = over_budget_history();
    assert!(!within_budget(&bad), "over-budget history should exceed B_MAX natively");
    println!("attempting to fold {} actions (OVER budget) ...", bad.len());
    match prove_history(&bad) {
        Ok(_) => panic!("SOUNDNESS BUG: over-budget history produced a verifying proof"),
        Err(e) => println!("  correctly REJECTED (Sigma cost > B_MAX is unprovable): {e:?}"),
    }
    println!();

    // -------------------------------------------------------------------- write fixtures
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&dir).expect("create fixtures dir");

    fs::write(dir.join("compressed_proof.bin"), &proof_bytes).unwrap();
    fs::write(dir.join("verifier_key.bin"), &vk_bytes).unwrap();

    let public_io = serde_json::json!({
        "description": "Public IO for the committed CompressedSNARK over a compliant PCA action history.",
        "curve_cycle": "Pallas/Vesta",
        "num_steps": proved.num_steps,
        "b_max": B_MAX,
        "z0": [felt_to_hex(&proved.z0[0]), felt_to_hex(&proved.z0[1])],
        "final_state": {
            "chain_digest": felt_to_hex(&proved.final_state[0]),
            "budget_spent": felt_to_hex(&proved.final_state[1]),
        },
        "actions": actions.iter().map(|a| serde_json::json!({
            "action_digest": a.action_digest,
            "cost": a.cost,
        })).collect::<Vec<_>>(),
    });
    fs::write(
        dir.join("public_io.json"),
        serde_json::to_string_pretty(&public_io).unwrap(),
    )
    .unwrap();

    let params = serde_json::json!({
        "scheme": "Nova folding scheme (IVC) + Spartan CompressedSNARK",
        "crate": "nova-snark 0.76.0",
        "curve_cycle": "Pallas/Vesta",
        "pcs": "IPA (ipa_pc::EvaluationEngine) — transparent, no trusted setup",
        "step_state": "[chain_digest, budget_spent] (arity 2)",
        "chain_hash": format!("MiMC x^5, {MIMC_ROUNDS} rounds (didactic placeholder for Poseidon)"),
        "b_max": B_MAX,
        "cost_bits": COST_BITS,
        "budget_bits": BUDGET_BITS,
        "num_steps": proved.num_steps,
        "compressed_proof_bytes": proof_bytes.len(),
        "verifier_key_bytes": vk_bytes.len(),
        "fold_ms": fold_ms,
        "compress_prove_ms": compress_ms,
        "compress_verify_ms": verify_ms,
        "note": "Folding makes per-step prover work and recursive-proof size independent of history length N; compression yields one succinct proof of the entire history."
    });
    fs::write(
        dir.join("params.json"),
        serde_json::to_string_pretty(&params).unwrap(),
    )
    .unwrap();

    println!("fixtures written to {}", dir.display());
    println!("  compressed_proof.bin  ({} bytes)", proof_bytes.len());
    println!("  verifier_key.bin      ({} bytes)", vk_bytes.len());
    println!("  public_io.json");
    println!("  params.json");
    println!();
    println!("ONE proof now attests: the exact ordered action history (hash chain) AND Sigma cost <= B_MAX.");
}
