//! Chain compaction: the memo remembers only chains its own verifier accepted, and resolves only what it remembered.
use atlas_pca::agent::{delegate, mint_root, KeyPair, Suite};
use atlas_pca::chain_compact::*;
use atlas_pca::serde_json::{json, Value};

fn kp(n: u8) -> KeyPair {
    KeyPair::from_seed(&[n; 32])
}

/// A verified chain of `depth` hops rooted at key 1 (hop i is held by key i + 2).
fn chain(depth: usize) -> Vec<Value> {
    let s = Suite::default();
    let mut hops = vec![mint_root(&kp(1), &kp(2).public, &json!([{"type": "expires", "at": 4_000_000_000_000i64}]), None, &s).unwrap()];
    for i in 1..depth {
        let next = delegate(&hops[i - 1], &kp(i as u8 + 1), Some(&kp(i as u8 + 2).public), &json!([]), None, &s).unwrap();
        hops.push(next);
    }
    hops
}

#[test]
fn a_remembered_chain_resolves_and_nothing_else_does() {
    let (c, root) = (chain(3), kp(1).public);
    let memo = ChainMemo::default();
    let compact = memo.remember_verified(&c, &root, 1_000).unwrap();
    assert_eq!(compact["depth"], json!(3));
    assert_eq!(compact["hops_root"], json!(hops_root(&c).unwrap()));
    assert_eq!(compact_chain_shape_error(&compact), None);
    let view = memo.resolve(&compact, 2_000).unwrap();
    assert_eq!(view.n, 3);
    assert_eq!(view.leaf, c[2]);
    assert_eq!(view.hash(0), chain_view(&c[0], &json!(c)).unwrap().hash(0));
    assert_eq!(view.count(2), Some(1));
    assert_eq!(view.hash(3), None);
    assert_eq!(chain_view(&c[0], &json!(c)).unwrap(), view);

    // not remembered: another memo, another depth, another leaf, another caveat list
    assert!(ChainMemo::default().resolve(&compact, 2_000).unwrap_err().contains("not in this verifier memo"));
    let mut deeper = compact.clone();
    deeper["depth"] = json!(2);
    assert!(memo.resolve(&deeper, 2_000).unwrap_err().contains("depth differs"));
    let mut other_leaf = compact.clone();
    other_leaf["leaf"] = c[1].clone();
    assert!(memo.resolve(&other_leaf, 2_000).unwrap_err().contains("leaf is not the memoized last hop"));
    let mut padded = compact.clone();
    padded["leaf"]["caveats"] = json!([]);
    assert!(memo.resolve(&padded, 2_000).is_err());
}

#[test]
fn the_root_commits_to_order_and_length() {
    let c = chain(3);
    let r = hops_root(&c).unwrap();
    assert_ne!(r, hops_root(&c[..2]).unwrap());
    assert_ne!(r, hops_root(&[c[1].clone(), c[0].clone(), c[2].clone()]).unwrap());
    assert!(hops_root(&[]).is_err());
}

#[test]
fn an_unverified_chain_cannot_be_remembered() {
    let c = chain(2);
    let memo = ChainMemo::default();
    assert!(memo.remember_verified(&c, &kp(9).public, 0).unwrap_err().contains("does not verify"), "wrong root issuer");
    let mut forged = c.clone();
    forged[1]["holder"] = json!(kp(7).public);
    assert!(memo.remember_verified(&forged, &kp(1).public, 0).is_err());
    assert!(memo.is_empty());
    assert!(compact_chain(&[]).is_err());
    assert!(compact_chain(&vec![c[0].clone(); 17]).is_err());
}

#[test]
fn entries_expire_and_a_full_memo_never_evicts_a_live_entry() {
    let (a, b) = (chain(1), chain(2));
    let memo = ChainMemo::new(Some(1), Some(100));
    let ca = memo.remember_verified(&a, &kp(1).public, 0).unwrap();
    assert!(memo.remember_verified(&b, &kp(1).public, 50).unwrap_err().contains("full of live entries"));
    assert!(memo.resolve(&ca, 100).is_ok());
    assert!(memo.resolve(&ca, 101).unwrap_err().contains("expired"));
    assert!(memo.is_empty(), "the expired entry is dropped on resolve");
    // after expiry the slot is free again
    let ca = memo.remember_verified(&a, &kp(1).public, 0).unwrap();
    memo.remember_verified(&b, &kp(1).public, 500).unwrap();
    assert_eq!(memo.len(), 1);
    assert!(memo.resolve(&ca, 501).is_err());
    assert!(memo.forget(&hops_root(&b).unwrap()));
    assert!(!memo.forget("nope"));
}

#[test]
fn shape_errors_name_the_member() {
    assert_eq!(compact_chain_shape_error(&json!(1)).as_deref(), Some("not an object"));
    let good = compact_chain(&chain(1)).unwrap();
    let mut extra = good.clone();
    extra["x"] = json!(1);
    assert_eq!(compact_chain_shape_error(&extra).as_deref(), Some("unknown member 'compact chain.x'"));
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("leaf");
    assert_eq!(compact_chain_shape_error(&missing).as_deref(), Some("missing member 'compact chain.leaf'"));
    let mut bad_depth = good.clone();
    bad_depth["depth"] = json!(17);
    assert_eq!(compact_chain_shape_error(&bad_depth).as_deref(), Some("depth must be 1..16"));
    let mut bad_root = good.clone();
    bad_root["hops_root"] = json!("short");
    assert!(compact_chain_shape_error(&bad_root).unwrap().contains("43 character"));
    let mut bad_kind = good;
    bad_kind["kind"] = json!("x");
    assert_eq!(compact_chain_shape_error(&bad_kind).as_deref(), Some("not a pca-chain-compact v1"));
}
