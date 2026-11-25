//! The public constants agree with the behaviour they describe, and the default-deny fold never allows more than it was given.
use atlas_pca::CheckStatus::{Fail, NotEnforced, Pass, Unsupported};
use atlas_pca::consts::*;
use std::collections::BTreeMap;

#[test]
fn constants_agree_with_the_crate() {
    assert_eq!(PCACTN_DEFAULT_TTL_MS, atlas_pca::agent::DEFAULT_TTL_MS);
    assert_eq!(REPLAY_MIN_RETENTION_MS, 3_720_000);
    assert_eq!(MAX_POLICY_CLASSES, 5);
    assert_eq!(MAX_JSON_BYTES, 1_048_576);
    assert_eq!(PCA_GRANT_MAX_CHAIN_LEN, 16);
    assert_eq!(EXECUTION_REQUIRED_CHECKS[..7], STATEFUL_REQUIRED_CHECKS);
    assert!(atlas_pca::DEFAULT_REQUIRED_CHECKS.iter().all(|c| EXECUTION_REQUIRED_CHECKS.contains(c) || *c == "operation"));
    assert_eq!(CATALOG_REVERSIBILITY_SCORE.iter().find(|(c, _)| *c == "rate_limited").map(|c| c.1), Some(0.4));
    for (class, score) in CATALOG_REVERSIBILITY_SCORE {
        assert_eq!(atlas_pca::catalog_risk::reversibility_score(class), Some(score), "{class}");
    }
}

fn checks(rows: &[(&str, atlas_pca::CheckStatus)]) -> BTreeMap<String, atlas_pca::CheckStatus> {
    rows.iter().map(|(n, s)| (n.to_string(), *s)).collect()
}

#[test]
fn enforce_required_is_default_deny() {
    let (mut c, mut r) = (checks(&[("revocation", Pass), ("audience", Pass)]), vec![]);
    assert!(enforce_required(true, &mut c, &mut r, &["revocation", "audience"]));
    assert!(r.is_empty());

    let (mut c, mut r) = (checks(&[("revocation", Pass), ("replay", NotEnforced), ("validity", Unsupported), ("audience", Fail)]), vec![]);
    assert!(!enforce_required(true, &mut c, &mut r, &["revocation", "replay", "validity", "audience", "grant_ref_bound"]));
    assert_eq!((c["replay"], c["validity"], c["audience"], c["grant_ref_bound"]), (Fail, Unsupported, Fail, Fail), "unsupported stays unsupported");
    assert_eq!(r.len(), 3, "a check that already failed adds no reason");
    assert_eq!(r[0], "replay: required check is not-enforced (default-deny: not enforced by this resource server)");
    assert_eq!(r[1], "validity: required check is unsupported (default-deny: not enforced by this resource server)");
    assert_eq!(r[2], "grant_ref_bound: required check is absent (default-deny: not enforced by this resource server)");

    // it never lifts a deny
    let (mut c, mut r) = (checks(&[("revocation", Pass)]), vec![]);
    assert!(!enforce_required(false, &mut c, &mut r, &["revocation"]));

    // the old `counter` name follows the check that exists
    let (mut c, mut r) = (checks(&[("replay", Pass)]), vec![]);
    assert!(enforce_required(true, &mut c, &mut r, &["counter"]));
    let (mut c, mut r) = (checks(&[]), vec![]);
    assert!(!enforce_required(true, &mut c, &mut r, &["counter"]));
    assert!(r[0].starts_with("counter_format: "));
}

#[test]
fn assemble_threshold_copies_the_shares() {
    let shares = vec![atlas_pca::serde_json::json!({"role": "agent"}), atlas_pca::serde_json::json!({"role": "guardian"})];
    let t = assemble_threshold(&shares);
    assert_eq!(t, atlas_pca::serde_json::json!({"shares": [{"role": "agent"}, {"role": "guardian"}]}));
    assert_eq!(assemble_threshold(&[]), atlas_pca::serde_json::json!({"shares": []}));
}
