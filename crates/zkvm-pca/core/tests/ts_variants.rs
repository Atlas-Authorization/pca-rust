//! Cross-implementation: ~49 tampered / re-signed / structurally odd capability chains and 13 leaf PCActn
//! variants whose verdicts were produced by the TypeScript reference (`@atlasauth/pca`, @noble/curves
//! Ed25519) must get the SAME verdict (and, for hops, the same reason text) from the in-guest Rust
//! verifier (ed25519-dalek). Regenerate the fixture with `core/tests/gen_ts_chain_variants.mjs`.

use pca_zkvm_core::chain::verify_hops;
use pca_zkvm_core::decide_from_str;
use serde_json::Value;

fn fx(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Cases whose reason TEXT legitimately differs: the guest fails closed on every non-ed25519 suite by design.
const REASON_MAY_DIFFER: &[&str] = &["unknown_alg", "pq_alg_declared_without_pq_material"];

#[test]
fn hop_verdicts_and_reasons_equal_the_typescript_reference() {
    let v: Value = serde_json::from_str(&fx("ts_chain_variants.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 52, "expected the full variant set, got {}", cases.len());
    let mut accepted = 0;
    let mut mismatches = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let chain = c["chain"].as_array().unwrap();
        let root = c["expected_root"].as_str().unwrap();
        let ts_ok = c["ts_ok"].as_bool().unwrap();
        let got = verify_hops(chain, root);
        if got.ok != ts_ok {
            mismatches.push(format!("{name}: ts_ok={ts_ok} guest_ok={} guest_reason={:?}", got.ok, got.reason));
            continue;
        }
        if ts_ok {
            accepted += 1;
        } else if !REASON_MAY_DIFFER.contains(&name) {
            let ts_reason = c["ts_reason"].as_str().unwrap();
            let r = got.reason.clone().unwrap_or_default();
            // the TS reason for allocation widening carries the numbers; compare the stable prefix
            if r != ts_reason && !(r.contains("widens the parent") && ts_reason.contains("widens the parent")) {
                mismatches.push(format!("{name}: reason differs: ts={ts_reason:?} guest={r:?}"));
            }
        }
    }
    assert!(accepted >= 5, "expected several accepted valid variants, got {accepted}");
    assert!(mismatches.is_empty(), "cross-implementation divergences:\n{}", mismatches.join("\n"));
}

#[test]
fn leaf_pcactn_verdicts_equal_the_typescript_reference() {
    let v: Value = serde_json::from_str(&fx("ts_chain_variants.json")).unwrap();
    let base: Value = serde_json::from_str(&fx("decide_input.sample.json")).unwrap();
    let mut mismatches = Vec::new();
    let leaf_cases = v["leaf_cases"].as_array().unwrap();
    // a silently emptied or truncated fixture must fail, not pass vacuously
    assert!(leaf_cases.len() >= 13, "expected the full leaf variant set, got {}", leaf_cases.len());
    let mut leaf_accept = 0usize;
    let mut leaf_deny = 0usize;
    for c in leaf_cases {
        let name = c["name"].as_str().unwrap();
        let mut input = base.clone();
        input["pcactn"] = c["pcactn"].clone();
        let d = decide_from_str(&input.to_string());
        // the chain itself is the untouched, valid one, so chain_verified == leaf-signature verdict
        let got = d.chain_verified == 1;
        if got { leaf_accept += 1 } else { leaf_deny += 1 }
        if got != c["ts_ok"].as_bool().unwrap() {
            mismatches.push(format!("leaf {name}: ts_ok={} guest={got}", c["ts_ok"]));
        }
    }
    assert!(leaf_accept >= 2 && leaf_deny >= 6, "leaf corpus must contain both verdicts: accept={leaf_accept} deny={leaf_deny}");
    assert!(mismatches.is_empty(), "cross-implementation divergences:\n{}", mismatches.join("\n"));
}

// ---------------------------------------------------------------------------------------------------
// Torsion: show that the torsion-freeness check added to the guest is THE cause of denial.

use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};

fn b64u_dec(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// What the guest verified BEFORE the torsion fix: dalek `verify_strict` only.
fn strict_only(hop: &Value) -> bool {
    let pk: [u8; 32] = b64u_dec(hop["issuer"].as_str().unwrap()).try_into().unwrap();
    let sig: [u8; 64] = b64u_dec(hop["sig"].as_str().unwrap()).try_into().unwrap();
    let digest = b64u_dec(hop["body_digest"].as_str().unwrap());
    let mut msg = pca_zkvm_core::chain::CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&digest);
    match VerifyingKey::from_bytes(&pk) {
        Ok(vk) => vk.verify_strict(&msg, &Signature::from_bytes(&sig)).is_ok(),
        Err(_) => false,
    }
}

fn torsion_free(bytes32: &[u8]) -> (bool, bool) {
    // (decompresses, torsion free)
    match CompressedEdwardsY(bytes32.try_into().unwrap()).decompress() {
        Some(p) => (true, p.is_torsion_free()),
        None => (false, false),
    }
}

#[test]
fn torsion_check_is_the_sole_cause_of_denial_for_mixed_order_points() {
    let v: Value = serde_json::from_str(&fx("ts_chain_variants.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    let get = |n: &str| cases.iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("missing fixture case {n}"));

    // (a) mixed-order delegator key A' (k = 0 mod 8) and (b) mixed-order A' together with mixed-order R:
    // the cofactorless equation holds, dalek's strict check ACCEPTS the signature, the TS reference and the
    // fixed guest reject: the only difference is the torsion-freeness requirement.
    for name in ["mixed_order_delegator_key_with_k_0_mod_8", "mixed_order_key_and_mixed_order_R_cofactorless_valid"] {
        let c = get(name);
        let chain = c["chain"].as_array().unwrap();
        let hop = &chain[1];
        assert!(strict_only(hop), "{name}: the pre-fix check (verify_strict alone) must accept this signature");
        let (ok_a, tf_a) = torsion_free(&b64u_dec(hop["issuer"].as_str().unwrap()));
        assert!(ok_a && !tf_a, "{name}: issuer key must be a mixed-order point");
        assert!(!c["ts_ok"].as_bool().unwrap());
        let got = verify_hops(chain, c["expected_root"].as_str().unwrap());
        assert!(!got.ok, "{name}: the fixed guest must reject");
        assert_eq!(got.reason.as_deref(), c["ts_reason"].as_str(), "{name}: same reason as the TS reference");
        // direct: the guest's verifier is false although the pre-fix check is true
        assert!(!pca_zkvm_core::chain::ed25519_verify_b64u(hop["issuer"].as_str().unwrap(), &{
            let mut m = pca_zkvm_core::chain::CAP_DOMAIN.to_vec();
            m.extend_from_slice(&b64u_dec(hop["body_digest"].as_str().unwrap()));
            m
        }, hop["sig"].as_str().unwrap()));
    }
    // R of the second case is mixed-order too (both points contribute torsion)
    let hop = &get("mixed_order_key_and_mixed_order_R_cofactorless_valid")["chain"][1];
    let sig = b64u_dec(hop["sig"].as_str().unwrap());
    let (ok_r, tf_r) = torsion_free(&sig[..32]);
    assert!(ok_r && !tf_r, "R of the cofactorless-valid case must be mixed-order");

    // (c) cases where R carries torsion but the equation cannot hold: both reject, for the signature reason.
    for name in ["prime_order_key_with_torsion_R", "small_order_R_with_prime_order_key"] {
        let c = get(name);
        let chain = c["chain"].as_array().unwrap();
        assert!(!strict_only(&chain[1]), "{name}: invalid even for the strict-only check (equation or small-order R)");
        assert!(!verify_hops(chain, c["expected_root"].as_str().unwrap()).ok);
        assert!(!c["ts_ok"].as_bool().unwrap());
    }
}

#[test]
fn torsion_cases_are_present_and_the_corpus_has_a_minimum_size() {
    let v: Value = serde_json::from_str(&fx("ts_chain_variants.json")).unwrap();
    let names: Vec<&str> = v["cases"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    for n in [
        "mixed_order_delegator_key_with_k_0_mod_8",
        "prime_order_key_with_torsion_R",
        "mixed_order_key_and_mixed_order_R_cofactorless_valid",
        "small_order_R_with_prime_order_key",
    ] {
        assert!(names.contains(&n), "missing torsion case {n}");
    }
    assert!(names.len() >= 52, "chain variant corpus shrank: {}", names.len());
}
