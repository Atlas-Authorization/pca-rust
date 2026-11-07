//! Property and differential tests: seeded random histories, no extra dependency.
//!
//! * native replay (`native_final_state`, the verifier's reference) vs the real Nova fold of the same history
//!   (differential: two independent evaluations of the same chain, one native Poseidon, one in-circuit);
//! * the chain digest has no collisions across many random histories and moves under every single edit
//!   (swap, drop, append, change of digest, change of cost);
//! * the budget component is the exact sum of the costs.
//!
//! Run in release mode: `cargo test --release`.

use pca_folding_ivc::*;

/// splitmix64: a fixed, documented generator, so a failure reproduces from the seed alone.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn random_history(rng: &mut Rng, max_len: u64) -> Vec<ActionStep> {
    let len = 1 + rng.next() % max_len;
    let per = B_MAX / len;
    (0..len)
        .map(|_| ActionStep { action_digest: rng.next(), cost: rng.next() % (per + 1) })
        .collect()
}

#[test]
fn nova_fold_matches_native_replay_on_random_histories() {
    let mut rng = Rng(0x5EED_F01D);
    let sample = random_history(&mut rng, 4);
    let pp = public_params(&circuits_for(&sample)[0]).expect("public params");
    for case in 0..6 {
        let h = if case == 0 { sample.clone() } else { random_history(&mut rng, 4) };
        assert!(within_budget(&h), "generator stays within budget");
        let circuits = circuits_for(&h);
        let z0 = initial_state();
        let mut rec = Recursive::new(&pp, &circuits[0], &z0).expect("new");
        for c in &circuits {
            rec.prove_step(&pp, c).expect("fold");
        }
        let out = verify_recursive(&pp, &rec, circuits.len()).expect("verify");
        let (chain, spent) = native_final_state(&h);
        assert_eq!(out, vec![chain, spent], "case {case}: fold differs from native replay");
    }
}

#[test]
fn chain_digest_has_no_collisions_and_moves_under_every_edit() {
    let mut rng = Rng(0xC0111DE);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..300 {
        let h = random_history(&mut rng, 6);
        let (d, spent) = native_final_state(&h);
        assert!(seen.insert(format!("{d:?}")), "digest collision across random histories");
        assert_eq!(spent, Scalar::from(h.iter().map(|a| a.cost).sum::<u64>()), "budget is the exact sum of costs");

        // every single edit changes the digest
        let mut e = h.clone();
        e[0].action_digest ^= 1;
        assert_ne!(native_final_state(&e).0, d, "digest edit");
        let mut e = h.clone();
        e[0].cost ^= 1;
        assert_ne!(native_final_state(&e).0, d, "cost edit");
        let mut e = h.clone();
        e.push(ActionStep { action_digest: rng.next(), cost: 0 });
        assert_ne!(native_final_state(&e).0, d, "append");
        if h.len() > 1 {
            assert_ne!(native_final_state(&h[..h.len() - 1]).0, d, "drop last");
            let mut e = h.clone();
            e.swap(0, 1);
            if (e[0].action_digest, e[0].cost) != (e[1].action_digest, e[1].cost) {
                assert_ne!(native_final_state(&e).0, d, "swap");
            }
        }
    }
}
