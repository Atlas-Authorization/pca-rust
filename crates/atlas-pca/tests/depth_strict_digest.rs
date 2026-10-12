//! Protocol digests use the STRICT canonical form, like the reference (hash.ts `canonicalBytes` ==
//! `canonicalizeStrict`): nesting depth <= MAX_JSON_DEPTH (32, same counting) and safe integers only. A hop whose body
//! is out of profile is refused even when it is correctly signed over a lenient digest: the reference cannot hash it
//! and refuses the chain, so a lenient native would accept a chain the reference rejects.
use atlas_pca::{canonicalize, strict_parse, verify_chain, verify_inclusion, MAX_JSON_DEPTH};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\x00";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    SigningKey::from_bytes(&seed)
}
fn pubk(k: &SigningKey) -> String {
    b64(k.verifying_key().as_bytes())
}
/// What an attacker holding a delegation key can compute for an out-of-profile body.
fn lenient_digest(v: &Value) -> String {
    b64(&Sha256::digest(canonicalize(v).as_bytes()))
}
fn hop(issuer: &SigningKey, holder: &SigningKey, caveats: Value, parent: Option<String>) -> Value {
    let body = json!({"issuer": pubk(issuer), "holder": pubk(holder), "caveats": caveats.clone(), "parent": parent.clone()});
    let d = lenient_digest(&body);
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&d).unwrap();
    let mut msg = CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&raw);
    let mut m = Map::new();
    m.insert("id".into(), json!(d));
    m.insert("issuer".into(), json!(pubk(issuer)));
    m.insert("holder".into(), json!(pubk(holder)));
    m.insert("caveats".into(), caveats);
    m.insert("body_digest".into(), json!(d));
    m.insert("sig".into(), json!(b64(&issuer.sign(&msg).to_bytes())));
    if let Some(p) = parent {
        m.insert("parent".into(), json!(p));
    }
    Value::Object(m)
}
fn nest(k: usize) -> Value {
    let mut v = json!(1);
    for _ in 0..k {
        v = Value::Array(vec![v]);
    }
    v
}
fn root() -> Value {
    hop(&key("principal"), &key("agent"), json!([{"type": "max_spend", "usd": 100}]), None)
}
fn chain_with(extra: Value) -> Vec<Value> {
    let r = root();
    let mut cav = r["caveats"].as_array().unwrap().clone();
    cav.push(extra);
    let h1 = hop(&key("agent"), &key("sub"), Value::Array(cav), Some(lenient_digest(&r)));
    vec![r, h1]
}
fn principal() -> String {
    pubk(&key("principal"))
}

#[test]
fn baseline_chain_verifies() {
    assert_eq!(verify_chain(&chain_with(json!({"type": "resource_prefix", "prefix": "db/"})), Some(&principal())), Ok(()));
}

#[test]
fn hop_depth_limit_minus_one_and_limit_accepted() {
    // body=1, caveats=2, caveat=3, nest(k) adds k -> deepest container 3+k
    for k in [MAX_JSON_DEPTH - 4, MAX_JSON_DEPTH - 3] {
        assert_eq!(verify_chain(&chain_with(json!({"type": "x", "v": nest(k)})), Some(&principal())), Ok(()), "k={k}");
    }
}

#[test]
fn hop_depth_limit_plus_one_refused() {
    assert!(verify_chain(&chain_with(json!({"type": "x", "v": nest(MAX_JSON_DEPTH - 2)})), Some(&principal())).is_err());
}

#[test]
fn hop_out_of_profile_numbers_refused() {
    for v in [json!(1e300), json!(9007199254740993u64), json!(0.1234567890123456), json!(1e-7)] {
        assert!(verify_chain(&chain_with(json!({"type": "x", "v": v.clone()})), Some(&principal())).is_err(), "{v}");
    }
}

#[test]
fn parent_out_of_profile_root_refused() {
    let r = hop(&key("principal"), &key("agent"), json!([{"type": "max_spend", "usd": 100, "deep": nest(MAX_JSON_DEPTH)}]), None);
    let h1 = hop(&key("agent"), &key("sub"), r["caveats"].clone(), Some(lenient_digest(&r)));
    assert!(verify_chain(&[r.clone()], Some(&principal())).is_err());
    assert!(verify_chain(&[r, h1], Some(&principal())).is_err());
}

#[test]
fn inclusion_leaf_is_strict() {
    let proof = json!({"index": 0, "size": 1, "path": []});
    let root_of = |leaf: &Value| {
        let mut m = vec![0u8];
        m.extend_from_slice(canonicalize(leaf).as_bytes());
        b64(&Sha256::digest(&m))
    };
    for leaf in [json!({"x": 1e300}), json!({"x": nest(MAX_JSON_DEPTH)})] {
        assert!(!verify_inclusion(&root_of(&leaf), proof.as_object(), &leaf), "{leaf}");
    }
    let ok = json!({"x": nest(MAX_JSON_DEPTH - 1)}); // object=1 + 31 arrays = depth 32
    assert!(verify_inclusion(&root_of(&ok), proof.as_object(), &ok));
}

#[test]
fn strict_parse_depth_boundaries() {
    for (n, ok) in [(MAX_JSON_DEPTH - 1, true), (MAX_JSON_DEPTH, true), (MAX_JSON_DEPTH + 1, false), (100_000, false)] {
        let t = "[".repeat(n) + &"]".repeat(n);
        assert_eq!(strict_parse(&t).is_ok(), ok, "n={n}");
    }
}

/// A caller-built hop value far deeper than serde_json's own parse limit must be a clean refusal: the verifier may not
/// recurse over it (a deep clone / serialisation overflows the stack, which aborts the process, not a panic). Run on a
/// thread with an ordinary 8 MiB stack; the values are leaked so the test's own recursive Drop is not what is measured.
fn deep_caveat() -> Value {
    let mut m = Map::new();
    m.insert("type".into(), Value::String("x".into()));
    m.insert("v".into(), nest(1_000_000));
    Value::Object(m)
}

#[test]
fn caller_built_huge_depth_is_a_clean_refusal() {
    let r = std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            let mut ch = chain_with(json!({"type": "x"}));
            ch[1]["caveats"].as_array_mut().unwrap().push(deep_caveat()); // NOT json!: it would serialise (recurse) the value
            let hop_refused = verify_chain(&ch, Some(&principal())).is_err();
            let mut r = root();
            r["caveats"].as_array_mut().unwrap().push(deep_caveat());
            let one = vec![r];
            let root_refused = verify_chain(&one, Some(&principal())).is_err();
            std::mem::forget(ch);
            std::mem::forget(one);
            hop_refused && root_refused
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(r);
}
