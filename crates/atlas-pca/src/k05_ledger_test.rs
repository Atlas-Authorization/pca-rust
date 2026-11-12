//! k05 differential oracle for the transparency ledger: tests/data/k05-ledger.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/ledger-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file) through the
//! pin-less forms. A key argument that is not a string is passed as "" (no key matches it); a policy that is not an object is
//! absent, as in the Java port.
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

fn key(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn policy(v: &Value) -> Option<&Value> {
    v.is_object().then_some(v)
}

#[test]
fn k05_ledger_matches_the_reference() {
    // 3128 cases, ~64 skipped for lone surrogates
    k05_run("ledger", 2750, |_, f, a| match f {
        "verifyLedgerConsistency" => K05::Val(json!(verify_ledger_consistency(&a[0], &a[1], &a[2]))),
        "verifyLedgerInclusion" => K05::Val(json!(crate::verify_inclusion(key(&a[0]), a[1].as_object(), &a[2]))),
        "verifyWitnessedHead" => K05::Val(json!(verify_witnessed_head(&a[0], key(&a[1])))),
        "detectEquivocation" => K05::Val(json!(detect_equivocation(&a[0], &a[1], key(&a[2])))),
        "verifyWitnessCosignature" => K05::Val(json!(verify_witness_cosignature(&a[0], &a[1], key(&a[2])))),
        "verifyWitnessCosignatures" => K05::Val(json!(verify_witness_cosignatures(&a[0], policy(&a[1]).unwrap_or(&Value::Null)))),
        "verifyTreeHead" => K05::Val(json!(verify_tree_head(&a[0], key(&a[1]), policy(&a[2])))),
        "verifyHeadConsistency" => K05::Val(json!(verify_head_consistency(&a[0], &a[1], &a[2], key(&a[3]), policy(&a[4])))),
        "verifyCheckpointChain" => {
            let v = verify_checkpoint_chain(&a[0], key(&a[1]), policy(&a[2]));
            K05::Val(if v.ok { json!({"ok": true}) } else { json!({"ok": false, "at": v.at}) })
        }
        _ => K05::Skip("fn not in this module"),
    });
}

// ---- clauses and caps, under valid signatures (ledger.ts) ----

use crate::agent::KeyPair;

fn sign_fields(k: &KeyPair, domain: &str, body: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(k.sign(&domain_message(domain, body.as_object().unwrap().clone()).unwrap()))
}

fn guardian() -> KeyPair {
    KeyPair::from_seed(&[1u8; 32])
}

fn root() -> String {
    KeyPair::from_seed(&[9u8; 32]).public
}

/// A guardian-signed tree head for `size`, whose root is always [`root`].
fn head(size: i64, prev_root: &str) -> Value {
    let g = guardian();
    let mut h = json!({"instance_id": "i", "principal": "p", "size": size, "root": root(), "prev_root": prev_root, "timestamp": 1});
    let sig = sign_fields(&g, STH_DOMAIN, &h);
    h["guardian"] = json!(g.public);
    h["sig"] = json!(sig);
    h
}

#[test]
fn the_path_cap_is_108_as_the_reference() {
    assert_eq!(MAX_CONSISTENCY_PATH, 108);
    assert!(path_within_cap(&vec![Value::Null; 108]));
    assert!(!path_within_cap(&vec![Value::Null; 109]));
}

#[test]
fn a_size_may_be_spelled_as_a_float_up_to_the_safe_limit() {
    // Number.isSafeInteger: 5.0 is 5
    assert_eq!(safe_size(Some(&json!(5.0))), Some(5));
    assert_eq!(safe_size(Some(&json!(9_007_199_254_740_991.0))), Some(9_007_199_254_740_991));
    for bad in [json!(9_007_199_254_740_992.0), json!(9_007_199_254_740_992u64), json!(1.5), json!(-0.0), json!(-1), json!("1")] {
        assert_eq!(safe_size(Some(&bad)), None, "{bad}");
    }
}

#[test]
fn js_eq_compares_numbers_by_value() {
    assert!(js_eq(Some(&json!(1)), Some(&json!(1.0))));
    assert!(!js_eq(Some(&json!(1)), Some(&json!(2.0))));
}

#[test]
fn a_float_threshold_counts_when_it_is_an_integer() {
    // ledger.ts: Number.isInteger(threshold) && threshold >= 0
    let sth = json!({});
    for (t, want) in [(json!(0.0), true), (json!(0), true), (json!(1.5), false), (json!(-1.0), false)] {
        assert_eq!(verify_witness_cosignatures(&sth, &json!({ "threshold": t })), want, "{t}");
    }
}

#[test]
fn a_cosignature_names_the_witness_it_is_checked_against() {
    let w = KeyPair::from_seed(&[2u8; 32]);
    let sth = head(1, "e");
    let body = json!({"instance_id": "i", "principal": "p", "size": 1, "root": root(), "prev_root": "e", "guardian_epoch": 0});
    let sig = sign_fields(&w, STH_WITNESS_DOMAIN, &body);
    assert!(verify_witness_cosignature(&sth, &json!({"key": w.public, "sig": sig}), &w.public));
    // the signature is the witness's own: only the named key is wrong
    assert!(!verify_witness_cosignature(&sth, &json!({"key": "other", "sig": sig}), &w.public));
    assert!(!verify_witness_cosignature(&sth, &json!({"key": w.public, "sig": 5}), &w.public));
}

#[test]
fn a_proof_must_name_both_head_sizes() {
    let (older, newer, g) = (head(1, "e"), head(2, &root()), guardian());
    let r = json!(root());
    for (old, new) in [(2, 2), (1, 1)] {
        let proof = json!({"oldSize": old, "newSize": new, "path": []});
        // the proof holds between the roots: only its sizes are wrong
        assert!(verify_ledger_consistency(&r, &r, &proof));
        assert!(!verify_head_consistency(&older, &newer, &proof, &g.public, None), "{old} {new}");
    }
}

#[test]
fn a_null_proof_is_a_missing_proof() {
    let g = guardian();
    for later in [json!({"sth": head(2, &root()), "proof": null}), json!({"sth": head(2, &root())})] {
        let v = verify_checkpoint_chain(&json!([{"sth": head(1, "e")}, later]), &g.public, None);
        assert_eq!((v.ok, v.at, v.reason), (false, 1, "proof_missing"));
    }
}
