//! Each clause of the `fresh_at` validity chains alone, on an otherwise valid token with a VALID signature, so nothing later can
//! refuse it for the same input. Limits are UTF-16 units as packages/pca/src/fresh-at.ts isStr (`x.length`).
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

const SK: [u8; 32] = [7; 32];
const OTHER: [u8; 32] = [8; 32];

fn pk(seed: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// U+1F600: 1 char, 2 UTF-16 units, 4 UTF-8 bytes.
fn astral(n: usize) -> String {
    "\u{1F600}".repeat(n)
}

/// A token with `edit` applied, then signed by SK over exactly the nine body fields.
fn signed(edit: &[(&str, Value)]) -> Value {
    let mut b = json!({
        "v": 1, "scope": "inst_1", "revocation_epoch": 1, "ledger_tree_size": 2, "budget_version": 3,
        "policy_revision": 4, "policy_digest": "d1", "issued_at": 5, "signer": pk(&SK),
    });
    for (k, x) in edit {
        b[*k] = x.clone();
    }
    let sig = SigningKey::from_bytes(&SK).sign(&domain_bytes(FRESH_AT_DOMAIN, &b).unwrap()).to_bytes();
    b["sig"] = json!(URL_SAFE_NO_PAD.encode(sig));
    b
}

/// scope up to 256 units, policy_digest up to 128, whatever the UTF-8 or char count.
fn in_range() -> Vec<(&'static str, String)> {
    vec![
        ("scope", "a".repeat(256)),
        ("scope", astral(128)),
        ("scope", "a".to_string()),
        ("policy_digest", "a".repeat(128)),
        ("policy_digest", astral(64)),
        ("policy_digest", "a".to_string()),
    ]
}

/// Empty, one unit over (ASCII and astral), and one char past the limit in units while under it in chars.
fn out_of_range() -> Vec<(&'static str, String)> {
    vec![
        ("scope", String::new()),
        ("scope", "a".repeat(257)),
        ("scope", format!("{}a", astral(128))),
        ("scope", astral(129)),
        ("policy_digest", String::new()),
        ("policy_digest", "a".repeat(129)),
        ("policy_digest", format!("{}a", astral(64))),
        ("policy_digest", astral(65)),
    ]
}

#[test]
fn utf16_len_counts_utf16_units() {
    assert_eq!(utf16_len(""), 0);
    assert_eq!(utf16_len("a"), 1);
    assert_eq!(utf16_len("\u{e9}"), 1); // 2 UTF-8 bytes
    assert_eq!(utf16_len("\u{1F600}"), 2); // 1 char, 4 UTF-8 bytes
    assert_eq!(utf16_len(&format!("{}a", astral(2))), 5);
}

#[test]
fn is_str_is_a_non_empty_string_within_max_units() {
    assert!(is_str(Some(&json!("a")), 1));
    assert!(is_str(Some(&json!(astral(2))), 4));
    assert!(!is_str(Some(&json!(astral(2))), 3)); // 2 chars, 4 units
    assert!(!is_str(Some(&json!("ab")), 1));
    assert!(!is_str(Some(&json!("")), 1));
    assert!(!is_str(Some(&json!(1)), 1));
    assert!(!is_str(None, 1));
}

#[test]
fn verify_fresh_at_refuses_each_clause_alone_under_a_valid_signature() {
    let me = pk(&SK);
    assert!(verify_fresh_at(&signed(&[]), &me), "control");
    for (k, s) in in_range() {
        assert!(verify_fresh_at(&signed(&[(k, json!(s))]), &me), "{k} {s}");
    }
    for (k, s) in out_of_range() {
        assert!(!verify_fresh_at(&signed(&[(k, json!(s))]), &me), "{k} {s}");
    }
    assert!(!verify_fresh_at(&signed(&[("v", json!(2))]), &me));
    assert!(!verify_fresh_at(&signed(&[("scope", json!(1))]), &me));
    assert!(!verify_fresh_at(&signed(&[("policy_digest", json!(1))]), &me));
    // SK really signed a body naming another signer: only the signer clause can refuse it
    assert!(!verify_fresh_at(&signed(&[("signer", json!(pk(&OTHER)))]), &me));
    assert!(!verify_fresh_at(&signed(&[]), &pk(&OTHER)));
    for k in ["issued_at", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"] {
        assert!(!verify_fresh_at(&signed(&[(k, json!("1"))]), &me), "{k} string");
        assert!(!verify_fresh_at(&signed(&[(k, json!(-1))]), &me), "{k} negative");
    }
}

#[test]
fn wire_refuses_scope_or_digest_alone() {
    const REASON: &str = "'fresh_at' scope and policy_digest must be non-empty strings";
    assert_eq!(validate_fresh_at_wire(&signed(&[])), None);
    for (k, s) in in_range() {
        assert_eq!(validate_fresh_at_wire(&signed(&[(k, json!(s))])), None, "{k} {s}");
    }
    for (k, s) in out_of_range() {
        assert_eq!(validate_fresh_at_wire(&signed(&[(k, json!(s))])).as_deref(), Some(REASON), "{k} {s}");
    }
}
