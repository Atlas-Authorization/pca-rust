//! The cheap chain check: structure, links, digests and the Ed25519 halves, never a PQ verification.
use atlas_pca::agent::{delegate, mint_root, KeyPair, PqKeyPair, Suite};
use atlas_pca::chain_cheap::verify_chain_cheap;
use atlas_pca::serde_json::{json, Value};

fn kp(n: u8) -> KeyPair {
    KeyPair::from_seed(&[n; 32])
}

fn chain() -> Vec<Value> {
    let s = Suite::default();
    let root = mint_root(&kp(1), &kp(2).public, &json!([{"type": "expires", "at": 4_000_000_000_000i64}]), None, &s).unwrap();
    let child = delegate(&root, &kp(2), Some(&kp(3).public), &json!([]), None, &s).unwrap();
    vec![root, child]
}

#[test]
fn a_well_formed_chain_passes_without_post_quantum_work() {
    let c = chain();
    assert_eq!(verify_chain_cheap(&c, Some(&kp(1).public), None), Ok(0));
    assert_eq!(verify_chain_cheap(&c, None, None), Ok(0));
}

#[test]
fn every_structural_defect_is_named() {
    let c = chain();
    assert_eq!(verify_chain_cheap(&[], None, None).unwrap_err(), "empty chain");
    assert_eq!(verify_chain_cheap(&vec![c[0].clone(); 17], None, None).unwrap_err(), "chain too long (max 16 hops)");
    assert_eq!(verify_chain_cheap(&c, Some(&kp(9).public), None).unwrap_err(), "hop 0: root issuer is not the expected principal");
    assert_eq!(verify_chain_cheap(&[c[1].clone()], None, None).unwrap_err(), "hop 0: root must not have a parent");
    assert_eq!(verify_chain_cheap(&[c[0].clone(), c[0].clone()], None, None).unwrap_err(), "hop 1: broken parent link");
    let mut other_holder = c.clone();
    other_holder[0]["holder"] = json!(kp(8).public);
    assert!(verify_chain_cheap(&other_holder, None, None).unwrap_err().contains("body digest mismatch"));
    let mut bad_sig = c.clone();
    bad_sig[1]["sig"] = c[0]["sig"].clone();
    assert_eq!(verify_chain_cheap(&bad_sig, None, None).unwrap_err(), "hop 1: bad signature (not signed by expected key)");
    let mut ill = c.clone();
    ill[0]["caveats"] = json!([1]);
    assert_eq!(verify_chain_cheap(&ill, None, None).unwrap_err(), "hop 0: malformed capability");
    let mut alg = c.clone();
    alg[0]["alg"] = json!("rot13");
    assert_eq!(verify_chain_cheap(&alg, None, None).unwrap_err(), "hop 0: unknown signature alg 'rot13'");
    let allowed = vec!["ml-dsa-65".to_string()];
    assert!(verify_chain_cheap(&c, None, Some(&allowed)).unwrap_err().contains("is not allowed by this verifier's suite policy"));
}

#[test]
fn a_pure_pq_hop_passes_on_structure_and_is_counted() {
    let pq = PqKeyPair::from_seed("ML-DSA-65", &[5u8; 32]).unwrap();
    let suite = Suite { alg: Some("ml-dsa-65"), pq: Some(&pq) };
    let root = mint_root(&kp(1), &kp(2).public, &json!([]), None, &suite).unwrap();
    assert_eq!(verify_chain_cheap(&[root.clone()], None, None), Ok(1));
    // the full verifier is stricter: no PQ authority was supplied for the root
    assert!(atlas_pca::verify_chain(&[root], None).is_err());
}
