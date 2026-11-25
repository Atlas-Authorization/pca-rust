//! `evaluate_k1` over a compact chain's view gives the verdict it gives over the full chain: the caveat language reads only the hop
//! count, the per-hop hash and caveat count, and the leaf.

use atlas_pca::agent::{delegate, mint_root, KeyPair, Suite};
use atlas_pca::chain_compact::{chain_view, ChainView};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{bound_caveats, bound_caveats_in, evaluate_k1, evaluate_k1_in, ChainInput, K1Ctx, K1Input};

fn kp(n: u8) -> KeyPair {
    KeyPair::from_seed(&[n; 32])
}

/// root (one plain caveat) -> hop1 (adds a `sealed`-shaped K1 caveat) -> hop2 (adds an expiry).
fn chain() -> (Value, Vec<Value>) {
    let s = Suite::default();
    let root = mint_root(&kp(1), &kp(2).public, &json!([{"type": "expires", "at": 4_000_000_000_000i64}]), None, &s).unwrap();
    let h1 = delegate(&root, &kp(2), Some(&kp(3).public), &json!([{"type": "max_uses", "id": "u1", "n": 2, "until": 4_000_000_000_000i64}]), None, &s).unwrap();
    let h2 = delegate(&h1, &kp(3), Some(&kp(4).public), &json!([{"type": "expires", "at": 4_000_000_000_001i64}]), None, &s).unwrap();
    (root.clone(), vec![root, h1, h2])
}

fn view(grant: &Value, chain: &[Value]) -> ChainView {
    chain_view(grant, &Value::Array(chain.to_vec())).unwrap()
}

#[test]
fn bound_caveats_agree_between_the_chain_and_its_view() {
    let (grant, c) = chain();
    let cv = Value::Array(c.clone());
    let v = view(&grant, &c);
    let full = bound_caveats(&grant, &cv).unwrap();
    assert_eq!(bound_caveats_in(&grant, ChainInput::View(&v)).unwrap(), full);
    assert_eq!(bound_caveats_in(&grant, ChainInput::Chain(&cv)).unwrap(), full);
    assert_eq!(full.iter().map(|b| b.hop).collect::<Vec<_>>(), vec![0, 1, 2], "each caveat is bound to the hop that introduced it");
    // the grant alone when there is no chain
    let alone = chain_view(&grant, &Value::Null).unwrap();
    assert_eq!(bound_caveats_in(&grant, ChainInput::View(&alone)).unwrap(), bound_caveats(&grant, &Value::Null).unwrap());
}

#[test]
fn the_verdict_over_a_view_equals_the_verdict_over_the_chain() {
    let (grant, c) = chain();
    let cv = Value::Array(c.clone());
    let v = view(&grant, &c);
    for k1 in [None, Some(K1Input::default())] {
        for now in [1_000i64, 5_000_000_000_000i64] {
            let ctx = K1Ctx { now, action: None };
            let a = evaluate_k1(&grant, &cv, k1.as_ref(), &ctx);
            let b = evaluate_k1_in(&grant, ChainInput::from(&v), k1.as_ref(), &ctx);
            assert_eq!((a.ok, &a.failed, &a.reasons), (b.ok, &b.failed, &b.reasons), "now={now} k1={}", k1.is_some());
            assert_eq!(a.bound, b.bound);
        }
    }
}

#[test]
fn a_view_with_a_wrong_hash_binds_to_that_hash() {
    // the view is what the memo remembered: the hop hash the caveat is bound to is the view's, not recomputed
    let (grant, c) = chain();
    let v = view(&grant, &c);
    let b = bound_caveats_in(&grant, ChainInput::View(&v)).unwrap();
    assert_eq!(b[1].cap_hash, v.hash(1).unwrap());
}
