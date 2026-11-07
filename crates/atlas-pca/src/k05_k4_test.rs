//! k05 kill tests for the K4 helpers. Pinned to the references: packages/pca-payments/src/network-token.ts (luhn, binding),
//! packages/pca-erc7715/src/index.ts (context and manager shapes), packages/pca-wallet/src/escalation-pricing.ts (cost <= max).
use super::*;
use crate::agent::KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[test]
fn luhn_doubles_each_digit_to_its_digit_sum() {
    // every digit in the doubled position, with the one check digit that completes it
    for (d, sum) in [0u32, 2, 4, 6, 8, 1, 3, 5, 7, 9].into_iter().enumerate() {
        let check = (10 - sum) % 10;
        assert!(luhn(&format!("{d}{check}")), "digit {d}");
        assert!(!luhn(&format!("{d}{}", (check + 1) % 10)), "digit {d}, wrong check");
    }
    assert!(looks_like_pan("4242424242424242"));
    assert!(!looks_like_pan("4242424242424243"));
}

/// Reaches only the context and manager checks: `sent` is empty, so a manager that passes then fails on the request (`response_malformed`).
fn granted(context: &str, manager: &str, allowed: &str) -> Option<&'static str> {
    let got = json!({"permission": {}, "context": context, "delegationManager": manager});
    let no_owner = |_: &str| None::<String>;
    verify_granted_permission(&json!({}), &json!({}), &got, &[allowed.to_string()], &no_owner)
}

#[test]
fn context_must_be_0x_and_at_least_one_hex_digit() {
    let addr = format!("0x{}", "a".repeat(40));
    assert_eq!(granted("0xABCdef09", &addr, &addr), Some("response_malformed"));
    for bad in ["0xzz", "0xabz", "0x", "abc"] {
        assert_eq!(granted(bad, &addr, &addr), Some("context_malformed"), "{bad}");
    }
}

#[test]
fn manager_must_be_a_full_address_even_when_allowed() {
    let addr = format!("0x{}", "a".repeat(40));
    assert_eq!(granted("0xabc", &addr, &addr.to_uppercase()), Some("response_malformed"), "allow list compare is case-insensitive");
    // each of these is on the allow list: only the shape refuses it
    for bad in ["0xabcd".to_string(), format!("ab{}", "a".repeat(40)), format!("0x{}", "z".repeat(40)), format!("0x{}", "a".repeat(41))] {
        assert_eq!(granted("0xabc", &bad, &bad), Some("delegation_manager_not_allowed"), "{bad}");
    }
}

#[test]
fn binding_with_an_undecodable_holder_or_proof_is_malformed_not_a_bad_proof() {
    let k = KeyPair::from_seed(&[4u8; 32]);
    let grant = json!({"n": 1});
    let digest = hash_canonical_strict(&grant).unwrap();
    let nonce = "nonce-0123456789ab";
    let binding = |holder: &str, proof: &str| json!({"kind": NETWORK_TOKEN_BINDING_KIND, "provider": "generic", "token_ref": "tok_abcdef12", "grant_digest": digest, "issuer_nonce": nonce, "holder": holder, "binding_proof": proof});
    let body = json!({"kind": NETWORK_TOKEN_BINDING_KIND, "v": 1, "provider": "generic", "token_ref": "tok_abcdef12", "grant_digest": digest, "issuer_nonce": nonce, "holder": k.public});
    let proof = URL_SAFE_NO_PAD.encode(k.sign(hash_canonical_strict(&body).unwrap().as_bytes()));
    assert_eq!(verify_network_token_binding(&binding(&k.public, &proof), &grant, &k.public, nonce, None), None);
    // the reference's decodeKey throws on either one: caught as binding_malformed
    assert_eq!(verify_network_token_binding(&binding(&k.public, "***"), &grant, &k.public, nonce, None), Some("binding_malformed"));
    assert_eq!(verify_network_token_binding(&binding("***", &proof), &grant, "***", nonce, None), Some("binding_malformed"));
    // both decode, the proof is simply not the holder's
    assert_eq!(verify_network_token_binding(&binding(&k.public, "AAAA"), &grant, &k.public, nonce, None), Some("binding_proof_invalid"));
}

fn config(k: &KeyPair, cost: i64, max: i64) -> Value {
    let mut c = json!({"v": 1, "principal": k.public, "currency": "USD", "interruptionCost": cost, "maxInterruptionCost": max, "hardCeilingLoss": 1000, "tightenStepPpm": 0, "epoch": 1});
    let h = hash_canonical_strict(&json!({"kind": "pca.escalation_pricing", "body": c})).unwrap();
    c["sig"] = json!(URL_SAFE_NO_PAD.encode(k.sign(h.as_bytes())));
    c
}

#[test]
fn pricing_cost_may_equal_max_under_a_valid_signature() {
    let k = KeyPair::from_seed(&[6u8; 32]);
    assert_eq!(pricing_config_error(&config(&k, 100, 100)), None);
    assert_eq!(pricing_config_error(&config(&k, 101, 100)), Some("config_cost_above_max"));
}
