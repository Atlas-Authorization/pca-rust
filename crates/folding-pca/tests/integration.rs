//! Integration tests for pca-folding-ivc. Run in release mode (Nova setup is slow in debug):
//!
//!   cargo test --release
//!
//! The committed `fixtures/*` are read-only here; they are regenerated only by the `demo` binary.

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use ff::PrimeField;
use nova_snark::errors::NovaError;
use pca_folding_ivc::{
    circuits_for, compress, compress_keys, felt_to_hex, hash2_native, initial_state,
    native_final_state, prove_history, public_params, verify_compressed, verify_recursive,
    within_budget, ActionStep, CompVerifierKey, Compressed, Scalar, B_MAX, PP,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}

fn committed_actions() -> Vec<ActionStep> {
    (0..8u64)
        .map(|i| ActionStep { action_digest: 0xC0FF_EE00 + i, cost: 100_000 })
        .collect()
}

fn hex_to_scalar(s: &str) -> Scalar {
    let h = s.strip_prefix("0x").expect("0x prefix");
    let mut be: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    be.reverse();
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&be);
    Option::<Scalar>::from(Scalar::from_repr(repr)).expect("canonical field element")
}

/// Public params + verifier key derived once from the step-circuit shape (the vk is a pure
/// function of the circuit; the committed `verifier_key.bin` is not shipped in the repo).
fn keys() -> &'static (PP, CompVerifierKey, pca_folding_ivc::CompProverKey) {
    static K: OnceLock<(PP, CompVerifierKey, pca_folding_ivc::CompProverKey)> = OnceLock::new();
    K.get_or_init(|| {
        let c = circuits_for(&committed_actions());
        let pp = public_params(&c[0]).expect("public params");
        let (pk, vk) = compress_keys(&pp).expect("compress setup");
        (pp, vk, pk)
    })
}

fn committed_proof_bytes() -> Vec<u8> {
    fs::read(fixture("compressed_proof.bin")).expect("committed proof")
}

fn z0() -> Vec<Scalar> {
    initial_state()
}

// ---------------------------------------------------------------- committed fixtures

#[test]
fn committed_public_io_matches_native_replay() {
    let io: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture("public_io.json")).unwrap()).unwrap();
    let (chain, budget) = native_final_state(&committed_actions());
    assert_eq!(io["final_state"]["chain_digest"], felt_to_hex(&chain));
    assert_eq!(io["final_state"]["budget_spent"], felt_to_hex(&budget));
    assert_eq!(io["num_steps"], 8);
    assert_eq!(io["b_max"], B_MAX);
    assert_eq!(hex_to_scalar(io["final_state"]["budget_spent"].as_str().unwrap()), Scalar::from(800_000u64));
}

#[test]
fn committed_proof_verifies_to_committed_public_io() {
    let io: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture("public_io.json")).unwrap()).unwrap();
    let proof: Compressed = bincode::deserialize(&committed_proof_bytes()).expect("decode proof");
    let (_, vk, _) = keys();
    let out = verify_compressed(&proof, vk, 8, &z0()).expect("committed proof must verify");
    assert_eq!(out.len(), 2);
    assert_eq!(felt_to_hex(&out[0]), io["final_state"]["chain_digest"].as_str().unwrap());
    assert_eq!(felt_to_hex(&out[1]), io["final_state"]["budget_spent"].as_str().unwrap());
}

#[test]
fn committed_proof_rejects_wrong_step_count() {
    let proof: Compressed = bincode::deserialize(&committed_proof_bytes()).unwrap();
    let (_, vk, _) = keys();
    for n in [0usize, 1, 7, 9, 16] {
        assert!(verify_compressed(&proof, vk, n, &z0()).is_err(), "num_steps={n} must be rejected");
    }
}

#[test]
fn committed_proof_rejects_wrong_initial_state() {
    let proof: Compressed = bincode::deserialize(&committed_proof_bytes()).unwrap();
    let (_, vk, _) = keys();
    let bad_z0 = vec![Scalar::from(1u64), Scalar::from(0u64)];
    assert!(verify_compressed(&proof, vk, 8, &bad_z0).is_err());
    let bad_z0 = vec![Scalar::from(0u64), Scalar::from(1u64)];
    assert!(verify_compressed(&proof, vk, 8, &bad_z0).is_err());
    // wrong arity
    assert!(verify_compressed(&proof, vk, 8, &[Scalar::from(0u64)]).is_err());
}

/// Flip one byte at many offsets spread over the whole committed proof. Every mutation must be
/// rejected: either the bytes no longer decode, or verification fails. None may verify.
#[test]
fn committed_proof_rejects_byte_flips_everywhere() {
    let good = committed_proof_bytes();
    let (_, vk, _) = keys();
    let n = good.len();
    let mut decode_fail = 0usize;
    let mut verify_fail = 0usize;
    let mut offsets: Vec<usize> = (0..n).step_by(97).collect();
    offsets.extend([0, 1, 7, 8, n - 1, n - 2, n / 2]);
    for off in offsets {
        let mut b = good.clone();
        b[off] ^= 0x01;
        match bincode::deserialize::<Compressed>(&b) {
            Err(_) => decode_fail += 1,
            Ok(p) => {
                assert!(
                    verify_compressed(&p, vk, 8, &z0()).is_err(),
                    "byte flip at offset {off} still verified"
                );
                verify_fail += 1;
            }
        }
    }
    assert!(decode_fail + verify_fail > 100);
    eprintln!("byte-flip mutations: {decode_fail} rejected at decode, {verify_fail} rejected at verify");
}

#[test]
fn committed_proof_rejects_truncation_and_trailing_garbage() {
    let good = committed_proof_bytes();
    let (_, vk, _) = keys();
    for cut in [1usize, 32, good.len() / 2] {
        let b = &good[..good.len() - cut];
        assert!(bincode::deserialize::<Compressed>(b).is_err(), "truncated by {cut} must not decode");
    }
    // bincode 1.x tolerates trailing bytes by default; the decoded proof must still be the same
    // proof, i.e. trailing bytes cannot change the verified statement.
    let mut ext = good.clone();
    ext.extend_from_slice(&[0xAA; 16]);
    if let Ok(p) = bincode::deserialize::<Compressed>(&ext) {
        let out = verify_compressed(&p, vk, 8, &z0()).expect("same proof");
        assert_eq!(out.len(), 2);
    }
}

// ---------------------------------------------------------------- fresh prove / verify

fn small_history() -> Vec<ActionStep> {
    vec![
        ActionStep { action_digest: 11, cost: 300_000 },
        ActionStep { action_digest: 22, cost: 400_000 },
        ActionStep { action_digest: 33, cost: 300_000 }, // exactly B_MAX
    ]
}

#[test]
fn fresh_fold_compress_verify_matches_native_replay() {
    let h = small_history();
    assert!(within_budget(&h));
    let p = prove_history(&h).expect("compliant history proves");
    let (chain, budget) = native_final_state(&h);
    assert_eq!(p.final_state, vec![chain, budget]);
    assert_eq!(budget, Scalar::from(B_MAX));
    let (pk, vk) = compress_keys(&p.pp).unwrap();
    let c = compress(&p.pp, &pk, &p.recursive).unwrap();
    assert_eq!(verify_compressed(&c, &vk, 3, &p.z0).unwrap(), p.final_state);
    // recursive verification path too
    assert_eq!(verify_recursive(&p.pp, &p.recursive, 3, &p.z0).unwrap(), p.final_state);
}

#[test]
fn chain_digest_is_order_and_content_sensitive() {
    let a = small_history();
    let mut swapped = a.clone();
    swapped.swap(0, 1);
    let mut changed = a.clone();
    changed.pop();
    let (ca, ba) = native_final_state(&a);
    let (cs, bs) = native_final_state(&swapped);
    let (cc, bc) = native_final_state(&changed);
    assert_ne!(ca, cs, "reordering must change the chain digest");
    assert_eq!(ba, bs, "reordering preserves the total");
    assert_ne!(ca, cc, "dropping an action must change the chain digest");
    assert_ne!(ba, bc);
    assert_ne!(hash2_native(Scalar::from(1u64), Scalar::from(2u64)), hash2_native(Scalar::from(2u64), Scalar::from(1u64)));
}

#[test]
fn proof_for_one_history_does_not_verify_other_public_state() {
    // A proof of history A, checked against history B's step count / start state, is rejected.
    let p = prove_history(&small_history()).unwrap();
    assert!(verify_recursive(&p.pp, &p.recursive, 2, &p.z0).is_err());
    assert!(verify_recursive(&p.pp, &p.recursive, 4, &p.z0).is_err());
    let bad = vec![Scalar::from(5u64), Scalar::from(0u64)];
    assert!(verify_recursive(&p.pp, &p.recursive, 3, &bad).is_err());
    // A compressed proof of 3 steps is not a proof of the committed 8-step statement.
    let (pk, vk) = compress_keys(&p.pp).unwrap();
    let c = compress(&p.pp, &pk, &p.recursive).unwrap();
    assert!(verify_compressed(&c, &vk, 8, &p.z0).is_err());
}

#[test]
fn over_budget_history_is_unprovable() {
    let over: Vec<ActionStep> = (0..4u64)
        .map(|i| ActionStep { action_digest: i, cost: 300_000 }) // 1_200_000 > B_MAX
        .collect();
    assert!(!within_budget(&over));
    assert!(prove_history(&over).is_err(), "Σcost > B_MAX must not produce a verifying proof");

    // one unit over, exactly at the boundary
    let edge = vec![
        ActionStep { action_digest: 1, cost: B_MAX },
        ActionStep { action_digest: 2, cost: 1 },
    ];
    assert!(prove_history(&edge).is_err());
    let at = vec![ActionStep { action_digest: 1, cost: B_MAX }];
    assert!(prove_history(&at).is_ok());
}

#[test]
fn out_of_range_cost_cannot_wrap_the_budget() {
    // cost >= 2^32 violates the cost range gadget even if the field sum would look small.
    let h = vec![ActionStep { action_digest: 1, cost: 1u64 << 32 }];
    assert!(prove_history(&h).is_err());
}

#[test]
fn proof_bytes_from_a_different_circuit_instance_param_set_are_rejected() {
    // Verifier key from freshly-built params must reject a proof whose bytes were produced for
    // different public parameters: here, the committed proof checked after we swap in the
    // bytes of a different (3-step) proof truncated/padded to the same length.
    let (_, vk, _) = keys();
    let p = prove_history(&small_history()).unwrap();
    let (pk2, _vk2) = compress_keys(&p.pp).unwrap();
    let c3 = compress(&p.pp, &pk2, &p.recursive).unwrap();
    let c3_bytes = bincode::serialize(&c3).unwrap();
    let committed = committed_proof_bytes();
    assert_ne!(c3_bytes, committed);
    // splice: first half of one proof + second half of the other
    let mid = c3_bytes.len().min(committed.len()) / 2;
    let mut spliced = c3_bytes[..mid].to_vec();
    spliced.extend_from_slice(&committed[mid..]);
    match bincode::deserialize::<Compressed>(&spliced) {
        Err(_) => {}
        Ok(p) => assert!(verify_compressed(&p, vk, 8, &z0()).is_err()),
    }
}

fn reason(e: NovaError) -> String {
    match e {
        NovaError::ProofVerifyError { reason } | NovaError::UnSat { reason } => reason,
        other => format!("{other:?}"),
    }
}

#[test]
fn rejection_reasons_are_the_expected_ones() {
    let proof: Compressed = bincode::deserialize(&committed_proof_bytes()).unwrap();
    let (_, vk, _) = keys();
    let r = reason(verify_compressed(&proof, vk, 0, &z0()).unwrap_err());
    assert_eq!(r, "Number of steps cannot be zero");
    // wrong step count / wrong z0 break the public-IO hash binding
    let r = reason(verify_compressed(&proof, vk, 7, &z0()).unwrap_err());
    assert_eq!(r, "Invalid output hash in R1CS instances");
    let bad = [Scalar::from(1u64), Scalar::from(0u64)];
    let r = reason(verify_compressed(&proof, vk, 8, &bad).unwrap_err());
    assert_eq!(r, "Invalid output hash in R1CS instances");
    let r = reason(verify_compressed(&proof, vk, 8, &[Scalar::from(0u64)]).unwrap_err());
    assert_eq!(r, "Invalid input or output arity");

    let over: Vec<ActionStep> = (0..4u64)
        .map(|i| ActionStep { action_digest: i, cost: 300_000 })
        .collect();
    let r = reason(prove_history(&over).err().expect("over budget"));
    assert_eq!(r, "Relaxed R1CS is unsatisfiable");
    let r = reason(
        prove_history(&[ActionStep { action_digest: 1, cost: 1u64 << 32 }])
            .err()
            .expect("range"),
    );
    assert_eq!(r, "Relaxed R1CS is unsatisfiable");
}
