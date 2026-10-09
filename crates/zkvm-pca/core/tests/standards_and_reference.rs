//! Conformance tests for the zkVM-guest decision logic that need no zkVM:
//!
//!  * RFC 8032 section 7.1 Ed25519 vectors against the guest's strict verifier (official vectors,
//!    committed in `fixtures/rfc_vectors.json` with provenance) plus fail-closed negative cases;
//!  * RFC 6234 SHA-256 vectors against the commitment hash;
//!  * the committed sample input: commitments equal the TypeScript reference output, and the pure
//!    decision equals the committed journal; deny variants are denied.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pca_zkvm_core::chain::ed25519_verify_b64u;
use pca_zkvm_core::commit::{self, sha256};
use pca_zkvm_core::decide_from_str;
use serde_json::{json, Value};

fn fx(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

struct Ed {
    name: String,
    pk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn rfc8032() -> Vec<Ed> {
    let doc: Value = serde_json::from_str(&fx("rfc_vectors.json")).unwrap();
    doc["ed25519"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Ed {
            name: v["name"].as_str().unwrap().to_string(),
            pk: unhex(v["public_key"].as_str().unwrap()),
            msg: unhex(v["message"].as_str().unwrap()),
            sig: unhex(v["signature"].as_str().unwrap()),
        })
        .collect()
}

#[test]
fn rfc8032_ed25519_vectors_verify() {
    let v = rfc8032();
    assert_eq!(v.len(), 5);
    for e in &v {
        assert!(ed25519_verify_b64u(&b64u(&e.pk), &e.msg, &b64u(&e.sig)), "RFC 8032 TEST {}", e.name);
    }
}

#[test]
fn rfc8032_vectors_reject_every_single_bit_mutation_class() {
    for e in rfc8032() {
        let (pk, sig) = (b64u(&e.pk), b64u(&e.sig));
        // message mutations
        if !e.msg.is_empty() {
            for i in [0, e.msg.len() / 2, e.msg.len() - 1] {
                let mut m = e.msg.clone();
                m[i] ^= 1;
                assert!(!ed25519_verify_b64u(&pk, &m, &sig), "TEST {}: msg byte {i}", e.name);
            }
        }
        let mut longer = e.msg.clone();
        longer.push(0);
        assert!(!ed25519_verify_b64u(&pk, &longer, &sig), "TEST {}: extended msg", e.name);
        // signature mutations in R and in S
        for i in [0usize, 15, 31, 32, 47, 62] {
            let mut s = e.sig.clone();
            s[i] ^= 0x01;
            assert!(!ed25519_verify_b64u(&pk, &e.msg, &b64u(&s)), "TEST {}: sig byte {i}", e.name);
        }
        // public-key mutation
        let mut k = e.pk.clone();
        k[0] ^= 1;
        assert!(!ed25519_verify_b64u(&b64u(&k), &e.msg, &sig), "TEST {}: key", e.name);
        // wrong lengths / empty / non-base64
        assert!(!ed25519_verify_b64u(&b64u(&e.pk[..31]), &e.msg, &sig));
        assert!(!ed25519_verify_b64u(&pk, &e.msg, &b64u(&e.sig[..63])));
        assert!(!ed25519_verify_b64u("", &e.msg, ""));
        assert!(!ed25519_verify_b64u("!!!", &e.msg, "!!!"));
    }
}

/// Signatures made valid under another vector's key do not verify under this key.
#[test]
fn rfc8032_cross_vector_key_confusion_is_rejected() {
    let v = rfc8032();
    for (i, a) in v.iter().enumerate() {
        for (j, b) in v.iter().enumerate() {
            if i != j {
                assert!(!ed25519_verify_b64u(&b64u(&b.pk), &a.msg, &b64u(&a.sig)), "{} sig under {} key", a.name, b.name);
            }
        }
    }
}

/// Group order L of the Ed25519 base point (RFC 8032 section 5.1), little-endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Self-constructed (NOT an official vector): S' = S + L is a different encoding of the same
/// scalar. RFC 8032 section 5.1.7 requires S < L, so the strict verifier must reject it.
#[test]
fn non_canonical_s_plus_l_is_rejected() {
    let e = &rfc8032()[1];
    let mut s = e.sig[32..].to_vec();
    let mut carry = 0u16;
    for i in 0..32 {
        let t = s[i] as u16 + L_LE[i] as u16 + carry;
        s[i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0, "S + L must still fit in 32 bytes for this vector");
    let mut sig = e.sig[..32].to_vec();
    sig.extend_from_slice(&s);
    assert!(!ed25519_verify_b64u(&b64u(&e.pk), &e.msg, &b64u(&sig)), "S+L malleated signature accepted");
}

/// Self-constructed (NOT an official vector): the all-identity "signature" (A = identity,
/// R = identity, S = 0) verifies for EVERY message under cofactor-less non-strict checks. The guest
/// uses `verify_strict`, which rejects small-order keys and R.
#[test]
fn small_order_key_and_r_are_rejected() {
    let mut identity = [0u8; 32];
    identity[0] = 1; // y = 1, the neutral element encoding
    let mut sig = [0u8; 64];
    sig[0] = 1; // R = identity, S = 0
    for msg in [&b""[..], b"anything", b"release the funds"] {
        assert!(!ed25519_verify_b64u(&b64u(&identity), msg, &b64u(&sig)));
    }
}

// ------------------------------------------------------------------------ SHA-256 (RFC 6234)

#[test]
fn rfc6234_sha256_vectors() {
    let doc: Value = serde_json::from_str(&fx("rfc_vectors.json")).unwrap();
    let cases = doc["sha256"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let unit = unhex(c["message_hex"].as_str().unwrap());
        let reps = c["repeat"].as_u64().unwrap() as usize;
        let msg: Vec<u8> = unit.iter().copied().cycle().take(unit.len() * reps).collect();
        let got: String = sha256(&msg).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, c["digest"].as_str().unwrap(), "{}", c["name"]);
    }
}

// ------------------------------------------------------------- reference (TypeScript) agreement

fn sample() -> Value {
    serde_json::from_str(&fx("decide_input.sample.json")).unwrap()
}

#[test]
fn commitments_equal_the_typescript_reference_output() {
    let input = sample();
    let want: Value = serde_json::from_str(&fx("expected_commitments.json")).unwrap();
    let plan: Vec<Value> = input["plan"].as_array().unwrap().clone();
    assert_eq!(commit::action_commitment(&input["action"]), want["action_commit"].as_str().unwrap());
    assert_eq!(commit::policy_commitment(&input["grant"]), want["policy_commit"].as_str().unwrap());
    assert_eq!(commit::plan_commitment(&plan).unwrap(), want["plan_commit"].as_str().unwrap());
}

#[test]
fn pure_decision_equals_the_committed_journal() {
    let d = decide_from_str(&sample().to_string());
    let journal: Value = serde_json::from_str(&fx("public_journal.json")).unwrap();
    assert_eq!(serde_json::to_value(&d).unwrap(), journal);
    assert_eq!((d.allow, d.tier, d.chain_verified), (1, 1, 1));
}

fn deny(v: &Value) -> pca_zkvm_core::Decision {
    decide_from_str(&v.to_string())
}

#[test]
fn deny_variants_are_denied_and_each_has_its_own_cause() {
    let base = sample();
    // risk-maximal with no budget
    let mut v = base.clone();
    v["risk_inputs_scaled"] = json!([900000, 100000, 900000, 900000, 100000, 900000]);
    v["budget_scaled"] = json!(0);
    assert_eq!(deny(&v).allow, 0);
    // predicate miss
    let mut v = base.clone();
    v["action"]["verb"] = json!("delete");
    assert_eq!(deny(&v).allow, 0);
    // tampered leaf-hop signature: chain not verified
    let mut v = base.clone();
    let sig = v["chain"][1]["sig"].as_str().unwrap().to_string();
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    v["chain"][1]["sig"] = json!(chars.into_iter().collect::<String>());
    let d = deny(&v);
    assert_eq!((d.allow, d.chain_verified), (0, 0));
    // misrooted chain
    let mut v = base.clone();
    v["expected_root_principal"] = json!("not-the-pinned-root-principal-key");
    let d = deny(&v);
    assert_eq!((d.allow, d.chain_verified), (0, 0));
    // empty chain
    let mut v = base.clone();
    v["chain"] = json!([]);
    assert_eq!(deny(&v).allow, 0);
    // budget exactly insufficient: zero budget with non-zero risk
    let mut v = base.clone();
    v["budget_scaled"] = json!(0);
    assert_eq!(deny(&v).allow, 0);
    // malformed / hostile JSON fails closed
    for bad in ["", "{}", "null", "[]", "{\"chain\": 5}"] {
        assert_eq!(decide_from_str(bad).allow, 0, "{bad}");
    }
}

/// Cross-implementation: the TypeScript reference `verifyChain` (Node/OpenSSL Ed25519) and the
/// in-guest Rust verifier (ed25519-dalek, strict) must reach the same verdict on the same chain,
/// including every tampered variant.
#[test]
fn chain_verdicts_agree_with_the_typescript_reference() {
    let reference: Value = serde_json::from_str(&fx("ts_chain_reference.json")).unwrap();
    let base = sample();
    let flip = |s: &str| format!("{}{}", if s.starts_with('A') { 'B' } else { 'A' }, &s[1..]);
    let mut n = 0;
    for c in reference["cases"].as_array().unwrap() {
        let mut v = base.clone();
        match c["name"].as_str().unwrap() {
            "untouched" => {}
            "leaf_hop_signature_tampered" => {
                let s = v["chain"][1]["sig"].as_str().unwrap().to_string();
                v["chain"][1]["sig"] = json!(flip(&s));
            }
            "root_hop_signature_tampered" => {
                let s = v["chain"][0]["sig"].as_str().unwrap().to_string();
                v["chain"][0]["sig"] = json!(flip(&s));
            }
            "wrong_pinned_root" => v["expected_root_principal"] = json!("not-the-pinned-root-principal-key"),
            other => panic!("unknown case {other}"),
        }
        let d = deny(&v);
        assert_eq!(d.chain_verified == 1, c["ts_ok"].as_bool().unwrap(), "{}", c["name"]);
        n += 1;
    }
    assert_eq!(n, 4);
}
