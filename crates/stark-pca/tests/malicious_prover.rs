//! Malicious-prover and structure-aware forgery tests for the release-gate STARK.
//!
//! The attacker here is stronger than the byte-flipping tests in `mutation.rs`: it crafts witnesses
//! that violate each policy rule and tries to obtain a verifying proof by manipulating the trace, the
//! public inputs, or by splicing/rewriting the structured parts of valid proofs (trace commitment,
//! constraint commitment, OOD frame, FRI layers, queries). The only acceptable outcome is that the
//! real verifier (`verify_release`) rejects every forgery.
//!
//! Run: `cargo test --release --test malicious_prover -- --nocapture`.

mod common;
use common::*;
use stark_pca::{compute_witness_commitment, proof_from_bytes, prove_release, verify_release, verify_release_bytes, PolicyParams, Witness};
use winter_utils::Serializable;
use winterfell::math::{fields::f128::BaseElement as F, FieldElement, StarkField};
use winterfell::Proof;

fn policy_for(w: &Witness, base: &PolicyParams) -> PolicyParams {
    let mut p = base.clone();
    let wc = compute_witness_commitment(w);
    p.witness_commitment = core::array::from_fn(|m| wc[m].as_int().to_string());
    p
}

fn real_accepts(w: &Witness, policy: &PolicyParams) -> bool {
    let (w2, p2) = (w.clone(), policy.clone());
    match std::panic::catch_unwind(move || prove_release(&w2, &p2)) {
        Ok(Ok(proof)) => verify_release(proof, policy).is_ok(),
        _ => false,
    }
}

// ---------------------------------------------------------------- witnesses that break a rule

#[test]
fn every_policy_rule_violation_is_unprovable() {
    let base = PolicyParams::default_policy();
    let ok = Witness::compliant();
    assert!(real_accepts(&ok, &policy_for(&ok, &base)), "control: the compliant witness verifies");

    let mut deny: Vec<(&str, Witness)> = Vec::new();
    // risk over theta1: every single risk-increasing input pushed up until r > 0.25
    for (i, name) in [(0usize, "semantic distance"), (2, "blast radius"), (3, "taint")] {
        let mut w = ok.clone();
        w.inputs[i] = 1_000_000;
        deny.push((name, w));
    }
    let mut w = ok.clone();
    w.inputs = [600_000, 0, 600_000, 600_000, 0, 600_000];
    deny.push(("all risk dimensions high", w));
    // budget exactly one unit below the cost kappa*r (r_raw/S rounded up, minus one)
    let r_raw = stark_pca::risk_raw(&ok.inputs, &base.weights);
    let need = r_raw.div_ceil(1_000_000) as u64;
    let mut w = ok.clone();
    w.budget_scaled = need - 1;
    deny.push(("budget one unit under cost", w));
    let mut w = ok.clone();
    w.budget_scaled = 0;
    deny.push(("zero budget", w));
    let mut w = ok.clone();
    w.predicate_match = false;
    deny.push(("predicate miss", w));
    let mut w = ok.clone();
    w.caveats_ok = false;
    deny.push(("caveat unsatisfied / expired", w));
    let mut w = ok.clone();
    w.predicate_match = false;
    w.caveats_ok = false;
    deny.push(("predicate miss and expired", w));
    // quantization-domain violations: the field would let them wrap
    let mut w = ok.clone();
    w.inputs[0] = 1_000_001;
    deny.push(("input just above S", w));
    let mut w = ok.clone();
    w.inputs[3] = u64::MAX;
    deny.push(("input u64::MAX", w));
    let mut w = ok.clone();
    w.budget_scaled = 1_000_001;
    deny.push(("budget just above bMax", w));
    let mut w = ok.clone();
    w.budget_scaled = u64::MAX;
    deny.push(("budget u64::MAX", w));

    std::panic::set_hook(Box::new(|_| {}));
    for (name, w) in &deny {
        assert!(!real_accepts(w, &policy_for(w, &base)), "deny witness '{name}' obtained a verifying proof");
    }
    let _ = std::panic::take_hook();
    eprintln!("{} deny witnesses, none provable", deny.len());
}

// ---------------------------------------------------------------- trace manipulation under the real AIR

#[test]
fn trace_manipulations_of_a_deny_witness_never_verify() {
    // Start from a deny witness and try every cheap trick to turn the trace into an "allow":
    // overwrite the gate bits, the allow column, the r_raw column, the range-check bits/accumulators,
    // the hash-chain output. Under the REAL (un-ablated) AIR none of these may produce a verifying proof.
    let policy0 = PolicyParams::default_policy();
    let deny_rows = [
        ("high risk", Row0::from_u64([900_000, 100_000, 900_000, 900_000, 100_000, 900_000], 1_000_000, true, true)),
        ("low budget", Row0::from_u64(Witness::compliant().inputs, 1, true, true)),
        ("predicate miss", Row0::from_u64(Witness::compliant().inputs, 1_000_000, false, true)),
        ("expired", Row0::from_u64(Witness::compliant().inputs, 1_000_000, true, false)),
    ];
    let mut attempts = 0usize;
    for (name, row) in deny_rows {
        let tweaks: Vec<(&str, Box<dyn Fn(&mut Cols)>)> = vec![
            ("allow=1", Box::new(|c: &mut Cols| c[C_ALLOW] = vec![F::ONE; 64])),
            ("pm=co=1", Box::new(|c: &mut Cols| { c[C_PM] = vec![F::ONE; 64]; c[C_CO] = vec![F::ONE; 64]; c[C_ALLOW] = vec![F::ONE; 64]; })),
            ("rraw=0", Box::new(|c: &mut Cols| c[C_RRAW] = vec![F::ZERO; 64])),
            ("budget=bmax (witness cols only)", Box::new(|c: &mut Cols| c[C_BS] = vec![F::new(1_000_000); 64])),
            ("zero all residual accumulators", Box::new(|c: &mut Cols| for k in 0..16 { c[rc_acc(k)] = vec![F::ZERO; 64]; })),
            ("zero all range bits and accumulators", Box::new(|c: &mut Cols| for k in 0..16 { c[rc_acc(k)] = vec![F::ZERO; 64]; c[rc_bit(k)] = vec![F::ZERO; 64]; })),
            ("forge last-row residuals to 0", Box::new(|c: &mut Cols| for k in 0..16 { c[rc_acc(k)][63] = F::ZERO; })),
            ("allow=1 and last-row residuals 0", Box::new(|c: &mut Cols| { c[C_ALLOW] = vec![F::ONE; 64]; for k in 0..16 { c[rc_acc(k)][63] = F::ZERO; } })),
            ("pow column all ones", Box::new(|c: &mut Cols| c[C_POW] = vec![F::ONE; 64])),
            ("hash chain restarted from zero state", Box::new(|c: &mut Cols| for j in 0..10 { c[h_lane(j)] = vec![F::ZERO; 64]; })),
        ];
        for (tn, tweak) in &tweaks {
            let mut cols = build_cols(&row, &wide_policy());
            tweak(&mut cols);
            let mut p = policy0.clone();
            p.theta1_scaled = 250_000;
            commit_to_trace(&cols, &mut p);
            attempts += 1;
            assert!(!forged_proof_accepted_by_real_verifier(&cols, &p), "{name} + {tn}: forged proof accepted");
            // also try with the commitment of the HONEST hash of the witness (binding attack)
            let mut p2 = p.clone();
            let honest = hash_trace(&row.preimage());
            for m in 0..4 {
                p2.witness_commitment[m] = honest[63][m].as_int().to_string();
            }
            attempts += 1;
            assert!(!forged_proof_accepted_by_real_verifier(&cols, &p2), "{name} + {tn} (honest commitment): forged proof accepted");
        }
    }
    eprintln!("{attempts} trace-manipulation forgeries, all rejected");
}

// ---------------------------------------------------------------- public-input (policy) downgrade

#[test]
fn proof_under_a_weaker_policy_does_not_verify_under_the_real_policy() {
    // The attacker proves a witness that is DENIED by the real policy but ALLOWED by a doctored one
    // (higher theta1, kappa = 0, tiny weights, ...) and presents it to a verifier using the real policy.
    let real = PolicyParams::default_policy();
    let mut w = Witness::compliant();
    w.inputs = [500_000, 500_000, 500_000, 500_000, 500_000, 500_000]; // r = 0.5 > theta1 = 0.25
    let weaker: Vec<(&str, Box<dyn Fn(&mut PolicyParams)>)> = vec![
        ("theta1 = 0.9", Box::new(|p| p.theta1_scaled = 900_000)),
        ("kappa = 0", Box::new(|p| p.kappa = 0)),
        ("weights halved", Box::new(|p| p.weights = p.weights.map(|x| x / 2))),
        ("weights zero", Box::new(|p| p.weights = [0; 6])),
        ("bmax raised", Box::new(|p| p.bmax_scaled = 5_000_000)),
        ("s scaled", Box::new(|p| p.s = 2_000_000)),
    ];
    assert!(!real_accepts(&w, &policy_for(&w, &real)), "control: denied under the real policy");
    for (name, f) in weaker {
        let mut doctored = real.clone();
        f(&mut doctored);
        let doctored = policy_for(&w, &doctored);
        std::panic::set_hook(Box::new(|_| {}));
        let proof = std::panic::catch_unwind(|| prove_release(&w, &doctored)).ok().and_then(|r| r.ok());
        let _ = std::panic::take_hook();
        if let Some(proof) = proof {
            // (a proof under the doctored policy may legitimately exist; it must not verify under the real one)
            let mut as_real = real.clone();
            as_real.witness_commitment = doctored.witness_commitment.clone();
            assert!(verify_release(proof, &as_real).is_err(), "{name}: downgraded proof verified under the real policy");
        }
    }
}

#[test]
fn proof_for_one_action_does_not_verify_for_another_commitment() {
    let base = PolicyParams::default_policy();
    let w = Witness::compliant();
    let policy = policy_for(&w, &base);
    let proof = prove_release(&w, &policy).unwrap();
    assert!(verify_release(proof.clone(), &policy).is_ok());
    // wrong witness commitment (different action), wrong action commitment, wrong policy commitment
    let mut other = w.clone();
    other.inputs[5] += 1;
    let wrong_wc = policy_for(&other, &base);
    assert!(verify_release(proof.clone(), &wrong_wc).is_err());
    for which in 0..2 {
        let mut p = policy.clone();
        let f = if which == 0 { &mut p.policy_commitment } else { &mut p.action_commitment };
        let flipped: String = f.chars().enumerate().map(|(i, c)| if i == 0 { if c == '0' { '1' } else { '0' } } else { c }).collect();
        *f = flipped;
        assert!(verify_release(proof.clone(), &p).is_err(), "commitment {which}");
    }
}

// ---------------------------------------------------------------- structure-aware proof forgery

/// Byte ranges of each top-level section of the serialized proof.
fn sections(bytes: &[u8]) -> Vec<(&'static str, usize, usize)> {
    let p = Proof::from_bytes(bytes).expect("decode");
    let lens = [
        p.context.to_bytes().len(),
        1,
        p.commitments.to_bytes().len(),
        0,
        p.constraint_queries.to_bytes().len(),
        p.ood_frame.to_bytes().len(),
        p.fri_proof.to_bytes().len(),
        8,
    ];
    let tq = bytes.len() - lens.iter().sum::<usize>();
    let names = ["context", "num_unique_queries", "commitments", "trace_queries", "constraint_queries", "ood_frame", "fri_proof", "pow_nonce"];
    let mut at = 0;
    let mut out = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let len = if i == 3 { tq } else { lens[i] };
        out.push((*n, at, at + len));
        at += len;
    }
    assert_eq!(at, bytes.len());
    out
}

fn two_proofs() -> ((Vec<u8>, PolicyParams), (Vec<u8>, PolicyParams)) {
    let base = PolicyParams::default_policy();
    let wa = Witness::compliant();
    let mut wb = Witness::compliant();
    wb.inputs[0] += 7_000;
    wb.inputs[2] += 3_000;
    let (pa, pb) = (policy_for(&wa, &base), policy_for(&wb, &base));
    let a = prove_release(&wa, &pa).unwrap().to_bytes();
    let b = prove_release(&wb, &pb).unwrap().to_bytes();
    assert!(verify_release_bytes(&a, &pa).is_ok() && verify_release_bytes(&b, &pb).is_ok());
    ((a, pa), (b, pb))
}

#[test]
fn splicing_sections_between_two_valid_proofs_is_rejected() {
    let ((a, pa), (b, pb)) = two_proofs();
    let (sa, sb) = (sections(&a), sections(&b));
    let (mut tried, mut decoded) = (0, 0);
    // every non-empty subset of the 7 spliceable sections taken from B, the rest from A
    let spliceable = [1usize, 2, 3, 4, 5, 6, 7];
    for mask in 1u32..(1 << spliceable.len()) {
        let mut bytes = Vec::new();
        for (idx, sec) in sa.iter().enumerate() {
            let from_b = idx > 0 && mask & (1 << (idx - 1)) != 0;
            let (src, s) = if from_b { (&b, &sb[idx]) } else { (&a, sec) };
            bytes.extend_from_slice(&src[s.1..s.2]);
        }
        if bytes == a || bytes == b {
            continue;
        }
        tried += 1;
        if proof_from_bytes(&bytes).is_ok() {
            decoded += 1;
        }
        assert!(verify_release_bytes(&bytes, &pa).is_err(), "splice {mask:07b} verified for A's statement");
        assert!(verify_release_bytes(&bytes, &pb).is_err(), "splice {mask:07b} verified for B's statement");
    }
    eprintln!("section splices: {tried} tried, {decoded} decoded structurally, 0 verified");
    assert!(tried >= 100 && decoded >= 50, "the splice matrix must exercise the verifier, not only the decoder");
}

#[test]
fn element_aligned_rewrites_inside_every_section_are_rejected() {
    // Replace whole 16-byte field-element slots (not random bits) inside the structured sections by
    // adversarially chosen elements: 0, 1, p-1, the previous slot (duplicate), and the slot's negation.
    let ((a, pa), _) = two_proofs();
    let p_minus_1 = F::ZERO - F::ONE;
    let mut tried = 0usize;
    let mut rejected_by_verifier = 0usize;
    for (name, lo, hi) in sections(&a) {
        if matches!(name, "context" | "num_unique_queries" | "pow_nonce") {
            continue;
        }
        let slots = (hi - lo) / 16;
        let step = (slots / 120).max(1);
        for slot in (0..slots).step_by(step) {
            let off = lo + slot * 16;
            let cur = u128::from_le_bytes(a[off..off + 16].try_into().unwrap());
            let prev = if slot > 0 { u128::from_le_bytes(a[off - 16..off].try_into().unwrap()) } else { 1 };
            let neg = (F::ZERO - F::new(cur % F::MODULUS)).as_int();
            for repl in [0u128, 1, p_minus_1.as_int(), prev, neg] {
                if repl == cur {
                    continue;
                }
                let mut m = a.clone();
                m[off..off + 16].copy_from_slice(&repl.to_le_bytes());
                tried += 1;
                let r = verify_release_bytes(&m, &pa);
                assert!(r.is_err(), "section {name} slot {slot}: rewrite to {repl:#x} verified");
                if proof_from_bytes(&m).is_ok() {
                    rejected_by_verifier += 1;
                }
            }
        }
    }
    eprintln!("element rewrites: {tried} tried, {rejected_by_verifier} decoded and then rejected by the verifier");
    assert!(tried > 1500, "{tried}");
    assert!(rejected_by_verifier > 500);
}
