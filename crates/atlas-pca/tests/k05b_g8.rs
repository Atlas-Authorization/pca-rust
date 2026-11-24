//! 0.5 mutation kills (group g8): defence-in-depth guards reached through hidden test seams. Each test names the survivor it kills.
use atlas_pca::arg_provenance::ProvenanceRecorder;
use atlas_pca::k05b_g8_seam::{check_revocation_epoch, first_overlap, set_nested};
use atlas_pca::{k05b_anchored_tail, AnchorEntry};
use base64::Engine;
use serde_json::{json, Map, Value};

/// arg_provenance.rs `delete ? statement in ProvenanceRecorder::new` (the session-id RNG): a failing RNG must fail `new`.
#[test]
fn recorder_new_fails_when_the_rng_fails() {
    let r = ProvenanceRecorder::k05b_new_with_fill("mediator", "kid", Some([7u8; 32]), |_| Err("rng down".to_string()));
    assert_eq!(r.err(), Some("rng down".to_string()));
    // control: a working RNG yields exactly that session id
    let ok = ProvenanceRecorder::k05b_new_with_fill("mediator", "kid", Some([7u8; 32]), |b| {
        b.fill(9);
        Ok(())
    })
    .ok()
    .expect("a working RNG builds the recorder");
    assert_eq!(ok.session(), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]));
}

/// allowlist_anchor.rs `delete return Err("not-anchored")`: the entry's digest must be the one anchored for its version.
#[test]
fn anchored_tail_requires_the_anchored_digest() {
    let mine = AnchorEntry { issuer: "iss".into(), version: 2, digest: "dig".into() };
    assert_eq!(k05b_anchored_tail(&mine, &[(2, "dig")], 2), Ok(2));
    assert_eq!(k05b_anchored_tail(&mine, &[(2, "other")], 2), Err("not-anchored"));
    assert_eq!(k05b_anchored_tail(&mine, &[(1, "dig")], 2), Err("not-anchored"));
    assert_eq!(k05b_anchored_tail(&mine, &[], 0), Err("not-anchored"));
    // rollback is checked first
    assert_eq!(k05b_anchored_tail(&mine, &[(2, "dig")], 3), Err("anchored-rollback"));
}

/// intent_revocation.rs:96 `delete return Err("revocation epoch not signed by the pinned guardian")`: with another guardian
/// the refusal is this one, not the later signature failure.
#[test]
fn revocation_epoch_refuses_a_foreign_guardian_first() {
    let mut o = Map::new();
    o.insert("guardian".into(), json!("G1"));
    let e = check_revocation_epoch(&o, "G2", 1000.0, "scope").unwrap_err();
    assert_eq!(e, "revocation epoch not signed by the pinned guardian");
    // control: the same guardian passes that guard (and fails further on, the epoch carries no valid signature)
    let e = check_revocation_epoch(&o, "G1", 1000.0, "scope").unwrap_err();
    assert_ne!(e, "revocation epoch not signed by the pinned guardian");
}

/// intent_wb.rs:800 `replace if condition with false in set_nested`: placing a value on an occupied node is a collision.
#[test]
fn set_nested_refuses_an_occupied_node() {
    let mut root = Map::new();
    root.insert("a".into(), json!(1));
    assert!(!set_nested(&mut root, "a", Value::Null));
    assert_eq!(Value::Object(root.clone()), json!({"a": 1}));
    // an occupied interior node
    let mut root = Map::new();
    root.insert("a".into(), json!({"b": {"c": 1}}));
    assert!(!set_nested(&mut root, "a.b", Value::Null));
    assert_eq!(Value::Object(root.clone()), json!({"a": {"b": {"c": 1}}}));
    // an occupied nested leaf
    assert!(!set_nested(&mut root, "a.b.c", Value::Null));
    assert_eq!(Value::Object(root.clone()), json!({"a": {"b": {"c": 1}}}));
    // a fresh path is placed
    assert!(set_nested(&mut root, "a.d", json!("v")));
    assert_eq!(Value::Object(root), json!({"a": {"b": {"c": 1}, "d": "v"}}));
}

/// intent_wb.rs:867 `replace if condition with false in prov_inner` (the overlap scan): a path under another is an overlap.
#[test]
fn first_overlap_finds_a_path_under_another() {
    let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(first_overlap(&p(&["action.params.a", "action.params.a.b"])), Some(("action.params.a".to_string(), "action.params.a.b".to_string())));
    assert_eq!(first_overlap(&p(&["action.params.a.b", "action.params.a"])), Some(("action.params.a".to_string(), "action.params.a.b".to_string())));
    // no dot, no overlap; a path is not under itself
    assert_eq!(first_overlap(&p(&["action.params.a", "action.params.ab", "action.params.a"])), None);
    assert_eq!(first_overlap(&p(&[])), None);
}
