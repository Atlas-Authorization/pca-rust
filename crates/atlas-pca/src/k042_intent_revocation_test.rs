//! Rule 13 step 7 (intent_revocation.rs): the identifiers, the full-set list rule, the clock and the epoch bookkeeping,
//! on both sides of every condition. (The shared TS corpus is run by k042_intent_session_test.rs.)
use super::*;
use serde_json::json;

const AUTH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn revocation_ids() {
    assert_eq!(session_revocation_id("S"), "pca-intent:session:S");
    assert_eq!(map_revocation_id("M"), "pca-intent:map:M");
    assert_eq!(delta_revocation_id("D"), "pca-intent:delta:D");
    assert_eq!(profile_revocation_id("travel", "2"), "pca-intent:profile:travel@2");
    assert_eq!(session_revocation_scope("S"), "pca-intent-session:S");
    assert_ne!(revset_root(&[]), revset_root(&["a".to_string()]));
    assert_eq!(revset_root(&[]), revset_root(&Vec::new()));
    assert_ne!(revset_root(&["a".to_string()]), revset_root(&["b".to_string()]));
    assert_ne!(revset_root(&["a".to_string(), "b".to_string()]), revset_root(&["b".to_string(), "a".to_string()]));
}

fn epoch(list: &[&str]) -> Map<String, Value> {
    let l: Vec<String> = list.iter().map(|x| x.to_string()).collect();
    let mut m = Map::new();
    m.insert("set_size".into(), json!(l.len()));
    m.insert("epoch".into(), json!(l.len()));
    m.insert("root".into(), json!(revset_root(&l).unwrap()));
    m
}

#[test]
fn the_revoked_list_is_the_full_signed_set() {
    let ok = json!(["a", "b", "c"]);
    assert_eq!(revoked_list(&epoch(&["a", "b", "c"]), Some(&ok)), Ok(vec!["a".to_string(), "b".to_string(), "c".to_string()]));
    assert_eq!(revoked_list(&epoch(&[]), Some(&json!([]))), Ok(vec![]));
    // strictly ascending by UTF-8 bytes: a duplicate and an inversion are refused
    let e = "revoked must be sorted by UTF-8 bytes and distinct";
    assert_eq!(revoked_list(&epoch(&["a", "a"]), Some(&json!(["a", "a"]))), Err(e.into()));
    assert_eq!(revoked_list(&epoch(&["a", "b", "b"]), Some(&json!(["a", "b", "b"]))), Err(e.into()));
    assert_eq!(revoked_list(&epoch(&["b", "a"]), Some(&json!(["b", "a"]))), Err(e.into()));
    assert_eq!(revoked_list(&epoch(&["a", "b"]), Some(&json!(["a", "b"]))), Ok(vec!["a".to_string(), "b".to_string()]));
    // UTF-8 order, not UTF-16: U+FFFF sorts before U+1F600
    assert!(revoked_list(&epoch(&["\u{ffff}", "\u{1f600}"]), Some(&json!(["\u{ffff}", "\u{1f600}"]))).is_ok());
    assert!(revoked_list(&epoch(&["\u{1f600}", "\u{ffff}"]), Some(&json!(["\u{1f600}", "\u{ffff}"]))).is_err());
    // not an array of strings
    assert_eq!(revoked_list(&epoch(&[]), None), Err("revoked must be an array of ids".into()));
    assert_eq!(revoked_list(&epoch(&[]), Some(&json!({}))), Err("revoked must be an array of ids".into()));
    assert_eq!(revoked_list(&epoch(&["a"]), Some(&json!([1]))), Err("revoked must be an array of ids".into()));
    // numbered by its set size
    let mut bad = epoch(&["a"]);
    bad.insert("set_size".into(), json!(2));
    assert!(revoked_list(&bad, Some(&json!(["a"]))).unwrap_err().starts_with("the epoch must be numbered"));
    let mut bad = epoch(&["a"]);
    bad.insert("epoch".into(), json!(2));
    assert!(revoked_list(&bad, Some(&json!(["a"]))).unwrap_err().starts_with("the epoch must be numbered"));
    // and the root commits to it
    let mut bad = epoch(&["a"]);
    bad.insert("root".into(), json!(AUTH));
    assert_eq!(revoked_list(&bad, Some(&json!(["a"]))), Err("the revoked list is not the signed set (root mismatch)".into()));
    assert!(revoked_list(&epoch(&["a"]), Some(&json!(["b"]))).is_err());
}

#[test]
fn the_clock_and_the_max_age_are_judged_before_the_evidence() {
    let ids: Vec<String> = vec![];
    let mis = Err("revocation max age misconfigured (fail closed)".to_string());
    let clk = Err("the verifier clock is not a safe integer (fail closed)".to_string());
    let none = Err("no session revocation epoch supplied".to_string());
    let c = |now: f64, max: f64| check_session_revocation(None, "s", AUTH, &ids, now, max, None, None, None);
    assert_eq!(c(0.0, f64::NAN), mis);
    assert_eq!(c(0.0, f64::INFINITY), mis);
    assert_eq!(c(0.0, -0.0), mis);
    assert_eq!(c(0.0, -1.0), mis);
    assert_eq!(c(0.0, 0.5), mis);
    assert_eq!(c(0.0, 9007199254740992.0), mis);
    assert_eq!(c(f64::NAN, 0.0), clk);
    assert_eq!(c(f64::NEG_INFINITY, 0.0), clk);
    assert_eq!(c(f64::INFINITY, 0.0), clk);
    assert_eq!(c(-0.0, 0.0), clk);
    assert_eq!(c(0.5, 0.0), clk);
    assert_eq!(c(-1.5, 0.0), clk);
    assert_eq!(c(9007199254740992.0, 0.0), clk);
    assert_eq!(c(-9007199254740992.0, 0.0), clk);
    // the bounds themselves are clocks / ages
    assert_eq!(c(0.0, 0.0), none);
    assert_eq!(c(-1.0, 0.0), none);
    assert_eq!(c(1.0, 0.0), none);
    assert_eq!(c(9007199254740991.0, 9007199254740991.0), none);
    assert_eq!(c(-9007199254740991.0, 0.0), none);
    // evidence: an object of exactly {epoch, revoked}
    assert_eq!(check_session_revocation(Some(&json!(5)), "s", AUTH, &ids, 0.0, 0.0, None, None, None), none);
    assert!(check_session_revocation(Some(&json!({"epoch": 1, "revoked": [], "x": 1})), "s", AUTH, &ids, 0.0, 0.0, None, None, None).unwrap_err().contains("unknown member 'x'"));
}
