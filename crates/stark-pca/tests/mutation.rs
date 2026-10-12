//! Mutation, public-input tampering and cross-implementation tests for the release-gate STARK.
//!
//! Run in release mode: `cargo test --release`.

use stark_pca::{
    compute_witness_commitment, prove_release, verify_release, PolicyParams, Witness, COMMIT_LIMBS,
};
use winter_utils::Serializable;
use winterfell::{Proof, VerifierError};

trait ElemsForTest {
    fn to_elements_for_test(&self) -> Vec<u128>;
}
impl ElemsForTest for stark_pca::PublicInputs {
    fn to_elements_for_test(&self) -> Vec<u128> {
        use winterfell::math::{StarkField, ToElements};
        self.to_elements().iter().map(|e| e.as_int()).collect()
    }
}

fn fixture_bytes() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin"))
        .expect("committed sample proof")
}

/// Byte ranges of each top-level proof section inside the serialized proof.
fn sections(bytes: &[u8]) -> Vec<(&'static str, usize, usize)> {
    let p = Proof::from_bytes(bytes).expect("decode");
    assert_eq!(p.to_bytes(), bytes, "canonical re-serialization");
    let ctx = p.context.to_bytes().len();
    let com = p.commitments.to_bytes().len();
    let cq = p.constraint_queries.to_bytes().len();
    let ood = p.ood_frame.to_bytes().len();
    let fri = p.fri_proof.to_bytes().len();
    let total = bytes.len();
    let tq = total - ctx - 1 - com - cq - ood - fri - 8;
    let mut out = Vec::new();
    let mut at = 0;
    for (name, len) in [
        ("context", ctx),
        ("num_unique_queries", 1),
        ("commitments", com),
        ("trace_queries", tq),
        ("constraint_queries", cq),
        ("ood_frame", ood),
        ("fri_proof", fri),
        ("pow_nonce", 8),
    ] {
        out.push((name, at, at + len));
        at += len;
    }
    assert_eq!(at, total);
    out
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
enum Outcome {
    DecodeRejected,
    Verifier(String),
}

fn variant(e: &VerifierError) -> String {
    let s = format!("{e:?}");
    s.split(['(', ' ']).next().unwrap_or("").to_string()
}

fn run(bytes: &[u8], policy: &PolicyParams) -> Result<(), Outcome> {
    match stark_pca::proof_from_bytes(bytes) {
        Err(_) => Err(Outcome::DecodeRejected),
        Ok(p) => verify_release(p, policy).map_err(|e| Outcome::Verifier(variant(&e))),
    }
}

#[test]
fn baseline_committed_proof_verifies() {
    assert_eq!(run(&fixture_bytes(), &PolicyParams::default_policy()), Ok(()));
}

#[test]
fn every_section_rejects_byte_flips() {
    let good = fixture_bytes();
    let policy = PolicyParams::default_policy();
    let mut seen = std::collections::BTreeMap::<&str, std::collections::BTreeSet<Outcome>>::new();
    for (name, a, b) in sections(&good) {
        let len = b - a;
        // first, last, middle and a spread of interior offsets
        let mut offs: Vec<usize> = vec![a, b - 1, a + len / 2, a + len / 3, a + len / 5];
        offs.extend((a..b).step_by((len / 40).max(1)));
        offs.sort();
        offs.dedup();
        for off in offs {
            for mask in [0x01u8, 0x80] {
                let mut m = good.clone();
                m[off] ^= mask;
                let r = run(&m, &policy);
                assert!(r.is_err(), "flip of section {name} at {off} (mask {mask:#x}) still verified");
                seen.entry(name).or_default().insert(r.unwrap_err());
            }
        }
    }
    for (k, v) in &seen {
        eprintln!("{k}: {v:?}");
    }
}

#[test]
fn truncation_and_extension_are_rejected() {
    let good = fixture_bytes();
    let policy = PolicyParams::default_policy();
    for cut in [1usize, 8, 100, good.len() / 2] {
        let r = run(&good[..good.len() - cut], &policy);
        assert_eq!(r, Err(Outcome::DecodeRejected), "truncated by {cut}");
    }
    assert!(stark_pca::proof_from_bytes(&[]).is_err());
    let mut ext = good.clone();
    ext.extend_from_slice(&[0u8; 8]);
    assert!(run(&ext, &policy).is_err(), "trailing bytes must be rejected");
}

#[test]
fn public_input_tampering_is_rejected_field_by_field() {
    let good = fixture_bytes();
    let base = PolicyParams::default_policy();
    let mut cases: Vec<(String, PolicyParams)> = Vec::new();
    for i in 0..6 {
        let mut p = base.clone();
        p.weights[i] += 1;
        cases.push((format!("weights[{i}]"), p));
    }
    let mut p = base.clone(); p.s += 1; cases.push(("s".into(), p));
    let mut p = base.clone(); p.theta1_scaled += 1; cases.push(("theta1_scaled".into(), p));
    let mut p = base.clone(); p.theta1_scaled -= 1; cases.push(("theta1_scaled-1".into(), p));
    let mut p = base.clone(); p.kappa += 1; cases.push(("kappa".into(), p));
    let mut p = base.clone(); p.bmax_scaled += 1; cases.push(("bmax_scaled".into(), p));
    // EVERY 64-bit limb of both 256-bit opaque commitments: flip the last hex digit of each
    // 16-digit group (the lowest bit of that limb), including the very last digit overall.
    for limb in 0..4 {
        for (name, which) in [("policy_commitment", 0), ("action_commitment", 1)] {
            let mut p = base.clone();
            let field = if which == 0 { &mut p.policy_commitment } else { &mut p.action_commitment };
            let idx = 16 * limb + 15;
            let c = field.as_bytes()[idx] as char;
            let flipped = char::from_digit(c.to_digit(16).unwrap() ^ 1, 16).unwrap();
            field.replace_range(idx..idx + 1, &flipped.to_string());
            cases.push((format!("{name} limb {limb}"), p));
        }
    }
    for m in 0..COMMIT_LIMBS {
        let mut p = base.clone();
        let v: u128 = p.witness_commitment[m].parse().unwrap();
        p.witness_commitment[m] = (v ^ 1).to_string();
        cases.push((format!("witness_commitment[{m}]"), p));
    }
    // witness commitment of a different (also compliant-looking) witness
    let mut other = Witness::compliant();
    other.inputs[0] += 1;
    let wc = compute_witness_commitment(&other);
    let mut p = base.clone();
    p.witness_commitment = core::array::from_fn(|m| winterfell::math::StarkField::as_int(&wc[m]).to_string());
    cases.push(("witness_commitment (other witness)".into(), p));

    for (name, p) in cases {
        let r = run(&good, &p);
        match r {
            Err(Outcome::Verifier(ref v)) => {
                assert!(
                    v == "InconsistentOodConstraintEvaluations"
                        || v == "TraceQueryDoesNotMatchCommitment"
                        || v == "ConstraintQueryDoesNotMatchCommitment"
                        || v == "FriVerificationFailed"
                        || v == "QuerySeedProofOfWorkVerificationFailed"
                        || v == "RandomCoinError",
                    "{name}: unexpected rejection reason {v}"
                );
                eprintln!("{name}: {v}");
            }
            other => panic!("{name}: expected a verifier rejection, got {other:?}"),
        }
    }
}

#[test]
fn hostile_length_prefix_does_not_abort_the_process() {
    // A length prefix inside the trace-query section rewritten to a huge value used to make the
    // stock decoder request a multi-exabyte allocation (process abort). The bounded decoder
    // must return an error instead.
    let good = fixture_bytes();
    let (_, start, end) = sections(&good).into_iter().find(|s| s.0 == "trace_queries").unwrap();
    for off in start..start + 16 {
        let mut m = good.clone();
        m[off] = 0xff;
        assert!(run(&m, &PolicyParams::default_policy()).is_err(), "offset {off}");
    }
    assert!(end > start);
}

/// Regression for the former 128-bit-prefix limit: two commitments that differ ONLY in the last
/// hex digit are distinct statements, and a proof for one does not verify for the other.
#[test]
fn commitments_differing_only_in_last_hex_digit_are_distinct_statements() {
    let good = fixture_bytes();
    let base = PolicyParams::default_policy();
    assert_eq!(run(&good, &base), Ok(()));
    for which in 0..2 {
        let mut p = base.clone();
        let f = if which == 0 { &mut p.policy_commitment } else { &mut p.action_commitment };
        let last = f.pop().unwrap();
        f.push(if last == '0' { '1' } else { '0' });
        assert_ne!(
            p.to_public().to_elements_for_test(),
            base.to_public().to_elements_for_test(),
            "statement must differ"
        );
        assert!(matches!(run(&good, &p), Err(Outcome::Verifier(_))), "proof for the original must not verify (which={which})");
        // and a fresh proof for the variant verifies for it but not for the original
        let proof = prove_release(&Witness::compliant(), &p).unwrap();
        assert!(verify_release(proof.clone(), &p).is_ok());
        assert!(verify_release(proof, &base).is_err());
    }
}

#[test]
fn malformed_commitments_are_refused_not_truncated() {
    let good = fixture_bytes();
    let base = PolicyParams::default_policy();
    for bad in [
        base.action_commitment[..32].to_string(),            // legacy 128-bit prefix
        format!("{}ffff", base.action_commitment),            // too long
        format!("0x{}", &base.action_commitment[2..]),        // not hex
        String::new(),
    ] {
        let mut p = base.clone();
        p.action_commitment = bad.clone();
        assert!(p.validate().is_err(), "{bad}");
        assert!(run(&good, &p).is_err(), "{bad}");
        assert!(prove_release(&Witness::compliant(), &p).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------- TS reference cross-check

#[derive(serde::Deserialize)]
struct TsLimbs {
    hex: String,
    limbs_u64_be: [String; 4],
    #[allow(dead_code)]
    limbs_u32_be: Vec<String>,
}
#[derive(serde::Deserialize)]
struct TsRef {
    scale: u64,
    commitment_limb_vectors: Vec<TsLimbs>,
    policy: TsPolicy,
    cases: Vec<TsCase>,
}
#[derive(serde::Deserialize)]
struct TsPolicy {
    weights_scaled: [u64; 6],
    theta1_scaled: u64,
    kappa: u64,
    bmax_scaled: u64,
}
#[derive(serde::Deserialize)]
struct TsCase {
    name: String,
    inputs_scaled: [u64; 6],
    budget_scaled: u64,
    predicate_match: bool,
    caveats_ok: bool,
    ts_risk: f64,
    ts_required_tier: u8,
    ts_allow: bool,
}

fn load_ts() -> TsRef {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/ts_reference.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("ts_reference.json")).expect("parse")
}

#[test]
fn public_inputs_match_the_ts_reference_policy() {
    let ts = load_ts();
    let rust = PolicyParams::default_policy();
    assert_eq!(rust.s, ts.scale);
    assert_eq!(rust.weights, ts.policy.weights_scaled);
    assert_eq!(rust.theta1_scaled, ts.policy.theta1_scaled);
    assert_eq!(rust.kappa, ts.policy.kappa);
    assert_eq!(rust.bmax_scaled, ts.policy.bmax_scaled);
}

#[test]
fn risk_functional_and_gate_agree_with_ts_reference() {
    let ts = load_ts();
    let s2 = (ts.scale as u128 * ts.scale as u128) as f64;
    for c in &ts.cases {
        let r_raw = stark_pca::risk_raw(&c.inputs_scaled, &ts.policy.weights_scaled);
        let r = r_raw as f64 / s2;
        assert!((r - c.ts_risk).abs() < 1e-9, "{}: rust r={r} ts r={}", c.name, c.ts_risk);
        let tier1 = r_raw <= ts.policy.theta1_scaled as u128 * ts.scale as u128;
        assert_eq!(tier1, c.ts_required_tier == 1, "{}: tier-1 disagreement", c.name);

        // End to end: does the STARK produce a verifying allow proof exactly when TS admits?
        let w = Witness {
            inputs: c.inputs_scaled,
            budget_scaled: c.budget_scaled,
            predicate_match: c.predicate_match,
            caveats_ok: c.caveats_ok,
        };
        let mut policy = PolicyParams::default_policy();
        policy.witness_commitment = core::array::from_fn(|m| {
            winterfell::math::StarkField::as_int(&compute_witness_commitment(&w)[m]).to_string()
        });
        let (w2, p2) = (w.clone(), policy.clone());
        let proved = std::panic::catch_unwind(move || prove_release(&w2, &p2));
        let allowed = match proved {
            Ok(Ok(proof)) => verify_release(proof, &policy).is_ok(),
            _ => false,
        };
        assert_eq!(allowed, c.ts_allow, "{}: STARK allow={allowed}, TS allow={}", c.name, c.ts_allow);
    }
}

#[test]
fn commitment_limb_split_matches_ts_bigint_reference() {
    for v in load_ts().commitment_limb_vectors {
        let got = stark_pca::hex256_limbs(&v.hex).unwrap().map(|l| l.to_string());
        assert_eq!(got, v.limbs_u64_be, "{}", v.hex);
    }
}
