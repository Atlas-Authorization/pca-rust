use atlas_pca::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/");

fn load(name: &str) -> Value {
    let b = std::fs::read_to_string(format!("{DIR}{name}")).expect("read file");
    serde_json::from_str(&b).expect("parse json")
}

fn b64d(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

#[test]
fn vectors() {
    let doc = load("vectors.json");
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(!vs.is_empty());
    let mut bad = Vec::new();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let got = verify_pcactn_core(&v["pcactn"], &v["grant"]);
        let exp = &v["expect"];
        if got.allow != exp["allow"].as_bool().unwrap() {
            bad.push(format!("{name}: allow = {}, want {} ({})", got.allow, exp["allow"], got.reason));
        }
        for (k, w) in exp["checks"].as_object().unwrap() {
            if got.checks[k] != w.as_bool().unwrap() {
                bad.push(format!("{name}: check {k} = {}, want {w}", got.checks[k]));
            }
        }
    }
    assert!(bad.is_empty(), "{} of {} vectors failed:\n{}", bad.len(), vs.len(), bad.join("\n"));
    eprintln!("{} vectors passed", vs.len());
}

#[test]
fn primitives() {
    let doc = load("vectors.json");
    let prim = &doc["primitives"];
    for c in prim["canonical"].as_array().unwrap() {
        assert_eq!(canonicalize(&c["value"]), c["expect"].as_str().unwrap());
        assert_eq!(hash_canonical(&c["value"]), c["hash"].as_str().unwrap());
    }
    for m in prim["merkle"].as_array().unwrap() {
        let leaves = m["leaves"].as_array().unwrap();
        let root = merkle_root(leaves).unwrap();
        assert_eq!(root, m["root"].as_str().unwrap());
        for (i, p) in m["proofs"].as_array().unwrap().iter().enumerate() {
            assert!(verify_inclusion(&root, p.as_object(), &leaves[i]), "proof {i}");
        }
    }
    assert_eq!(params_digest(None), prim["params_digest_empty"].as_str().unwrap());
}

#[test]
fn keys_consistent() {
    let keys = load("keys.json");
    for (label, k) in keys.as_object().unwrap() {
        let seed: [u8; 32] = b64d(k["seed"].as_str().unwrap()).try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().to_bytes().to_vec(), b64d(k["public"].as_str().unwrap()), "{label}");
    }
}
