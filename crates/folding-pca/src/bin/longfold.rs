//! Long-history fold: N steps folded into one RecursiveSNARK, compressed and verified.
//!
//!   cargo run --release --bin longfold -- <N> [out.json]
//!
//! Actions are deterministic: action_digest_i = 0xA11C_E000_0000 + i, cost_i = B_MAX / N (integer),
//! so the cumulative total is at most B_MAX.
use std::time::Instant;

use pca_folding_ivc::{
    compress, compress_keys, felt_to_hex, native_final_state, prove_history, verify_compressed,
    within_budget, ActionStep, B_MAX,
};

fn main() {
    let mut a = std::env::args().skip(1);
    let n: u64 = a.next().expect("N").parse().expect("N integer");
    let out = a.next();
    let cost = B_MAX / n;
    let actions: Vec<ActionStep> = (0..n)
        .map(|i| ActionStep { action_digest: 0xA11C_E000_0000 + i, cost })
        .collect();
    assert!(within_budget(&actions));

    let t0 = Instant::now();
    let proved = prove_history(&actions).expect("history must prove");
    let fold_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (c, b) = native_final_state(&actions);
    assert_eq!(proved.final_state[0], c, "chain digest vs native replay");
    assert_eq!(proved.final_state[1], b, "budget vs native replay");

    let t1 = Instant::now();
    let (pk, vk) = compress_keys(&proved.pp).expect("setup");
    let setup_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let t2 = Instant::now();
    let comp = compress(&proved.pp, &pk, &proved.recursive).expect("compress");
    let compress_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let t3 = Instant::now();
    let fin = verify_compressed(&comp, &vk, proved.num_steps).expect("verify");
    let verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(fin, proved.final_state);

    // negative: wrong step count must be rejected
    assert!(verify_compressed(&comp, &vk, proved.num_steps + 1).is_err());
    let bytes = bincode::serialize(&comp).expect("ser");
    let doc = serde_json::json!({
        "num_steps": n, "cost_per_step": cost, "cumulative_cost": cost * n, "b_max": B_MAX,
        "final_chain_digest": felt_to_hex(&proved.final_state[0]),
        "final_budget_spent": felt_to_hex(&proved.final_state[1]),
        "fold_and_verify_recursive_ms": fold_ms, "compress_setup_ms": setup_ms,
        "compress_prove_ms": compress_ms, "compress_verify_ms": verify_ms,
        "compressed_proof_bytes": bytes.len(), "crate": "nova-snark 0.76.0",
        "host": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    if let Some(p) = out { std::fs::write(p, serde_json::to_string_pretty(&doc).unwrap()).unwrap(); }
}
