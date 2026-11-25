//! The property-based invariant checks against the real core: every registered invariant holds on a fixed-seed sample, a run is
//! reproducible from its seed, the generators emit legal, verifying chains and well-formed risk policies, and a failure's case seed
//! replays. The generator stream is the crate's own SplitMix64 (not the reference library's), so a seed explores different cases than the
//! reference does.
use atlas_pca::invariants::{DEFAULT_SEED, INVARIANT_NAMES};
use atlas_pca::invariants_check::*;

#[test]
fn every_invariant_holds_on_a_fixed_seed_sample() {
    let results = check_invariants(60, DEFAULT_SEED, false).expect("run");
    assert_eq!(results.iter().map(|r| r.name).collect::<Vec<_>>(), INVARIANT_NAMES.to_vec());
    let failed: Vec<String> = results.iter().filter(|r| !r.ok).map(|r| format!("{}: {:?}", r.name, r.error)).collect();
    assert!(failed.is_empty(), "invariants failed: {failed:?}");
}

#[test]
fn a_run_is_reproducible_from_its_seed() {
    let a = check_invariants(10, 7, false).expect("run");
    let b = check_invariants(10, 7, false).expect("run");
    assert_eq!(a, b);
    assert!(check_invariants(10_000_001, 7, false).is_err());
    // bail stops at the first failure; with none it runs everything
    assert_eq!(check_invariants(3, 7, true).expect("run").len(), INVARIANT_REGISTRY.len());
}

#[test]
fn the_splitmix_stream_is_fixed() {
    let mut r = InvRng::new(0);
    // the published SplitMix64 outputs for seed 0
    assert_eq!(r.next_u64(), 0xe220a8397b1dcdaf);
    assert_eq!(r.next_u64(), 0x6e789e6aa1b965f4);
    let mut r = InvRng::new(42);
    for _ in 0..200 {
        let i = r.int(-3, 3);
        assert!((-3..=3).contains(&i));
        let d = r.dbl(0.25, 0.75);
        assert!((0.25..=0.75).contains(&d));
        assert!((0.0..1.0).contains(&r.float()));
    }
    assert_eq!(r.int(5, 5), 5);
}

#[test]
fn generators_emit_legal_chains_and_wellformed_policies() {
    let mut r = InvRng::new(99);
    for _ in 0..8 {
        let chain = arb_chain(&mut r).expect("chain");
        let caps: Vec<_> = chain["caps"].as_array().unwrap().clone();
        assert!(!caps.is_empty() && caps.len() <= 7);
        assert!(atlas_pca::verify_chain(&caps, chain["rootIssuer"].as_str()).is_ok());
        let p = arb_risk_policy(&mut r);
        assert!(p.kappa > 0.0 && p.theta1 >= 0.0 && p.theta2 >= p.theta1);
    }
}

#[test]
fn replay_reruns_one_case_and_refuses_unknown_names() {
    assert_eq!(replay_invariant("fail-closed:undecidable-groups", 1), Ok(true));
    assert!(replay_invariant("no-such-invariant", 1).is_err());
}
