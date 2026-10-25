//! Mutation-kill suite for `verify_threshold_share` (R5 signer-set-pinned shares) and the wire rules for `threshold`/`aud`/`nonce`.
mod common;
use atlas_pca::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

fn ed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct Pq {
    pk: String,
    sk: ml_dsa_65::PrivateKey,
}

fn pq() -> Pq {
    let (pk, sk) = ml_dsa_65::KG::try_keygen().unwrap();
    Pq { pk: B64.encode(pk.into_bytes()), sk }
}

fn signer_set_hash(set: &Value) -> Vec<u8> {
    let mut es: Vec<(String, String, Option<String>)> = set
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["role"].as_str().unwrap().into(), e["publicKey"].as_str().unwrap().into(), e.get("pq_pk").and_then(Value::as_str).map(String::from)))
        .collect();
    es.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let arr: Vec<Value> = es
        .iter()
        .map(|(r, p, q)| {
            let mut m = Map::new();
            if let Some(q) = q {
                m.insert("pq_pk".into(), json!(q));
            }
            m.insert("publicKey".into(), json!(p));
            m.insert("role".into(), json!(r));
            Value::Object(m)
        })
        .collect();
    let mut m = b"atlas-pca/signerset/v1\x00".to_vec();
    m.extend_from_slice(canonicalize_strict(&Value::Array(arr)).unwrap().as_bytes());
    sha(&m)
}

fn share_msg(role: &str, tm: &[u8], set: &Value, t: u8, tag: Option<&str>) -> Vec<u8> {
    let mut m = b"atlas-pca/share/".to_vec();
    m.extend_from_slice(role.as_bytes());
    m.push(0);
    m.extend_from_slice(&sha(tm));
    m.extend_from_slice(&signer_set_hash(set));
    m.push(t);
    if let Some(a) = tag {
        m.extend_from_slice(b"\x00atlas-pca/share-suite/v1\x00");
        m.extend_from_slice(a.as_bytes());
    }
    m
}

fn pq_sign(p: &Pq, msg: &[u8]) -> String {
    let s: [u8; 3309] = p.sk.try_sign(msg, &[]).unwrap();
    B64.encode(s)
}

fn ed_entry(role: &str, t: i64, signed_t: u8) -> Value {
    let k = ed(7);
    let pk = B64.encode(k.verifying_key().to_bytes());
    let set = json!([{ "role": role, "publicKey": pk }, { "role": "guardian", "publicKey": B64.encode(ed(9).verifying_key().to_bytes()) }]);
    let tm = b"threshold message";
    let sig = B64.encode(k.sign(&share_msg(role, tm, &set, signed_t, None)).to_bytes());
    json!({ "role": role, "t": t, "signer_set": set, "threshold_message": B64.encode(tm), "share": { "role": role, "publicKey": pk, "sig": sig } })
}

#[test]
fn ed25519_share_and_t_bounds() {
    assert!(verify_threshold_share(&ed_entry("agent", 2, 2)));
    assert!(verify_threshold_share(&ed_entry("agent", 1, 1)));
    assert!(verify_threshold_share(&ed_entry("agent", 3, 3)));
    // R6-04: t is exactly 1, 2 or 3 like the reference (0..=255 used to be accepted)
    assert!(!verify_threshold_share(&ed_entry("agent", 0, 0)));
    assert!(!verify_threshold_share(&ed_entry("agent", 4, 4)));
    assert!(!verify_threshold_share(&ed_entry("agent", 255, 255)));
    assert!(!verify_threshold_share(&ed_entry("agent", 3, 2)));
    // t outside 0..=255 must be refused, not truncated to a u8 that the signature happens to cover
    assert!(!verify_threshold_share(&ed_entry("agent", 256, 0)));
    assert!(!verify_threshold_share(&ed_entry("agent", 512, 0)));
    assert!(!verify_threshold_share(&ed_entry("agent", -1, 255)));
    assert!(!verify_threshold_share(&ed_entry("agent", 300, 44)));
}

#[test]
fn share_role_and_registration_rules() {
    let mut e = ed_entry("agent", 2, 2);
    e["share"]["role"] = json!("agent");
    assert!(verify_threshold_share(&e));
    e["share"]["role"] = json!("guardian");
    assert!(!verify_threshold_share(&e));
    // R6-03: share.role is required (reference wellFormed)
    e["share"].as_object_mut().unwrap().remove("role");
    assert!(!verify_threshold_share(&e));
    // the share key must be the ONE key the signer set registers for the role
    let mut e = ed_entry("agent", 2, 2);
    e["share"]["publicKey"] = json!(B64.encode(ed(8).verifying_key().to_bytes()));
    assert!(!verify_threshold_share(&e));
    let mut e = ed_entry("agent", 2, 2);
    e["signer_set"].as_array_mut().unwrap().push(json!({"role": "agent", "publicKey": B64.encode(ed(8).verifying_key().to_bytes())}));
    assert!(!verify_threshold_share(&e), "two keys for one role");
    let mut e = ed_entry("agent", 2, 2);
    let shared = e["share"]["publicKey"].clone();
    e["signer_set"].as_array_mut().unwrap().push(json!({"role": "principal", "publicKey": shared}));
    assert!(!verify_threshold_share(&e), "one key under two roles");
    let mut e = ed_entry("agent", 2, 2);
    e["signer_set"] = json!([{"role": "nobody", "publicKey": e["share"]["publicKey"].clone()}]);
    assert!(!verify_threshold_share(&e), "role not registered");
    for bad in [json!(null), json!([]), json!("x"), json!({})] {
        assert!(!verify_threshold_share(&bad));
    }
    let mut e = ed_entry("agent", 2, 2);
    e["signer_set"] = json!([5]);
    assert!(!verify_threshold_share(&e));
    let mut e = ed_entry("agent", 2, 2);
    e["signer_set"].as_array_mut().unwrap().push(json!(5));
    assert!(!verify_threshold_share(&e));
    let mut e = ed_entry("agent", 2, 2);
    e["share"]["alg"] = json!("nope");
    assert!(!verify_threshold_share(&e));
    let mut e = ed_entry("agent", 2, 2);
    e["share"]["alg"] = json!("ed25519");
    assert!(verify_threshold_share(&e));
}

fn pq_entry(alg: &str, registered: Option<&Pq>, signer: &Pq, tag_alg: Option<&str>, hybrid: bool) -> Value {
    let k = ed(7);
    let pk = B64.encode(k.verifying_key().to_bytes());
    let mut me = json!({ "role": "agent", "publicKey": pk });
    if let Some(r) = registered {
        me["pq_pk"] = json!(r.pk);
    }
    let set = json!([me]);
    let tm = b"tm";
    let msg = share_msg("agent", tm, &set, 1, tag_alg);
    let mut share = json!({ "role": "agent", "publicKey": pk, "alg": alg });
    if hybrid {
        share["sig"] = json!(B64.encode(k.sign(&msg).to_bytes()));
        share["pq_sig"] = json!(pq_sign(signer, &msg));
    } else {
        share["sig"] = json!(pq_sign(signer, &msg));
    }
    json!({ "role": "agent", "t": 1, "signer_set": set, "threshold_message": B64.encode(tm), "share": share })
}

#[test]
fn pq_shares_verify_under_the_registered_key_only() {
    let a = pq();
    let b = pq();
    for (alg, hybrid) in [("ml-dsa-65", false), ("hybrid-ed25519-ml-dsa-65", true)] {
        let tag = Some(alg);
        assert!(verify_threshold_share(&pq_entry(alg, Some(&a), &a, tag, hybrid)), "{alg} positive");
        // signed by a key other than the registered one
        assert!(!verify_threshold_share(&pq_entry(alg, Some(&a), &b, tag, hybrid)), "{alg} wrong signer");
        // not bound to the suite tag
        assert!(!verify_threshold_share(&pq_entry(alg, Some(&a), &a, None, hybrid)), "{alg} untagged");
        assert!(!verify_threshold_share(&pq_entry(alg, Some(&a), &a, Some("ml-dsa-87"), hybrid)), "{alg} wrong tag");
        // no PQ key registered for the role
        assert!(!verify_threshold_share(&pq_entry(alg, None, &a, tag, hybrid)), "{alg} unregistered");
        // the share's own pq_pk must equal the registered one when present, and never replaces it
        let mut e = pq_entry(alg, Some(&a), &a, tag, hybrid);
        e["share"]["pq_pk"] = json!(a.pk);
        assert!(verify_threshold_share(&e), "{alg} matching own pq_pk");
        e["share"]["pq_pk"] = json!(b.pk);
        assert!(!verify_threshold_share(&e), "{alg} differing own pq_pk");
        e["share"]["pq_pk"] = json!(5);
        assert!(!verify_threshold_share(&e), "{alg} non-string own pq_pk");
        // empty registered key
        let mut e = pq_entry(alg, Some(&a), &a, tag, hybrid);
        e["signer_set"][0]["pq_pk"] = json!("");
        assert!(!verify_threshold_share(&e), "{alg} empty registered key");
    }
    // an ed25519 share never takes the PQ path / tag
    assert!(verify_threshold_share(&ed_entry("agent", 2, 2)));
}

fn valid_pcactn() -> Value {
    load("vectors.json")["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "valid-in-plan-action").unwrap()["pcactn"].clone()
}

#[test]
fn wire_rules_for_aud_nonce_and_unsigned_members() {
    let base = valid_pcactn();
    assert!(validate_wire(&base).is_ok());
    let with = |k: &str, v: Value| {
        let mut p = base.clone();
        p[k] = v;
        p
    };
    assert!(validate_wire(&with("aud", json!(""))).is_err());
    assert!(validate_wire(&with("aud", json!("a".repeat(256)))).is_ok());
    assert!(validate_wire(&with("aud", json!("a".repeat(257)))).is_err());
    assert!(validate_wire(&with("aud", json!(5))).is_err());
    assert!(validate_wire(&with("nonce", json!(""))).is_err());
    assert!(validate_wire(&with("nonce", json!("n".repeat(128)))).is_ok());
    assert!(validate_wire(&with("nonce", json!("n".repeat(129)))).is_err());
    // unsigned members are excluded from the strict-canonical body check: their own rules decide
    let e = validate_wire(&with("sig", json!(-0.0))).unwrap_err();
    assert!(!e.contains("negative zero"), "{e}");
    let e = validate_wire(&with("pq_sig", json!(-0.0))).unwrap_err();
    assert!(!e.contains("negative zero"), "{e}");
    let e = validate_wire(&with("threshold", json!({"shares": [], "x": -0.0}))).map(|_| String::new()).unwrap_or_else(|e| e);
    assert!(!e.contains("negative zero"), "{e}");
    // while a signed member is checked
    assert!(validate_wire(&with("rationale_commitment", json!(-0.0))).unwrap_err().contains("negative zero"));
    // threshold share members
    let pk = B64.encode([1u8; 32]);
    let sg = B64.encode([2u8; 64]);
    let th = |s: Value| with("threshold", json!({"shares": [s]}));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg}))).is_ok());
    assert!(validate_wire(&th(json!({"role": 5, "publicKey": pk, "sig": sg}))).unwrap_err().contains("threshold.shares[0] is malformed"));
    assert!(validate_wire(&th(json!(5))).unwrap_err().contains("malformed"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": "AA", "sig": sg}))).unwrap_err().contains("publicKey is not canonical"));
    // 0.4.1: the share signature is validated per suite; the reason names the suite
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": "AA"}))).unwrap_err().contains("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": B64.encode([2u8; 65])}))).unwrap_err().contains("'sig' is not canonical"));
    let ml = B64.encode(vec![3u8; 3309]);
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": ml, "alg": "ml-dsa-65"}))).is_ok());
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": ml, "alg": "ml-dsa-65", "pq_pk": "not-judged-by-wire"}))).is_ok());
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": "hybrid-ed25519-ml-dsa-65", "pq_sig": ml}))).is_ok());
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": "hybrid-ed25519-ml-dsa-65"}))).unwrap_err().contains("'pq_sig' is not canonical"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "pq_sig": ml}))).unwrap_err().contains("'pq_sig' must be absent"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": ml, "alg": "ml-dsa-65", "pq_sig": ml}))).unwrap_err().contains("'pq_sig' must be absent"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": "ml-dsa-65"}))).unwrap_err().contains("(3309 bytes) for alg 'ml-dsa-65'"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": null}))).unwrap_err().contains("'alg' must be a string"));
    // ml-dsa-87 is implemented (0.4.2): judged by its own lengths; an unregistered alg is unknown
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": "ml-dsa-87"}))).unwrap_err().contains("(4627 bytes) for alg 'ml-dsa-87'"));
    assert!(validate_wire(&th(json!({"role": "r", "publicKey": pk, "sig": sg, "alg": "ml-dsa-44"}))).unwrap_err().contains("unknown signature alg"));
}

#[test]
fn duplicate_identical_registration_is_accepted() {
    let k = ed(7);
    let pk = B64.encode(k.verifying_key().to_bytes());
    let set = json!([{ "role": "agent", "publicKey": pk }, { "role": "agent", "publicKey": pk }]);
    let tm = b"tm";
    let sig = B64.encode(k.sign(&share_msg("agent", tm, &set, 1, None)).to_bytes());
    let e = json!({ "role": "agent", "t": 1, "signer_set": set, "threshold_message": B64.encode(tm), "share": { "role": "agent", "publicKey": pk, "sig": sig } });
    assert!(verify_threshold_share(&e));
}
