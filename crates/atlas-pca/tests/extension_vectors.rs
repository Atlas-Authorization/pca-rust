//! The extension layer of the conformance corpus (packages/pca/conformance/LAYERS.md): optimistic-vectors.json and
//! ledger-vectors.json. Every vector must reproduce its `expect` exactly; nothing is skipped.
mod common;

use atlas_pca::ledger::*;
use atlas_pca::optimistic::*;
use common::load;
use serde_json::{json, Value};

fn rows<'a>(doc: &'a Value, table: &str) -> &'a Vec<Value> {
    let r = doc[table].as_array().unwrap_or_else(|| panic!("{table}"));
    assert_eq!(r.len() as u64, doc["counts"][table].as_u64().unwrap(), "{table}: count");
    assert!(!r.is_empty());
    r
}

fn each(doc: &Value, table: &str, f: impl Fn(&Value) -> Value) {
    for v in rows(doc, table) {
        assert_eq!(f(v), v["expect"], "{table}/{}", v["name"].as_str().unwrap());
    }
}

fn policy(doc: &Value) -> WindowPolicy {
    let w = &doc["window_policy"];
    WindowPolicy { min_window_ms: w["minWindowMs"].as_f64().unwrap(), max_window_ms: w["maxWindowMs"].as_f64().unwrap(), max_skew_ms: w["maxSkewMs"].as_f64().unwrap() }
}

fn check(c: &str) -> Value {
    json!({ "ok": c == "ok", "check": c })
}

#[test]
fn optimistic_vectors() {
    let doc = load("optimistic-vectors.json");
    let p = policy(&doc);
    each(&doc, "optimistic_claim", |v| check(claim_check(&v["claim"], v["pcactn_digest"].as_str().unwrap(), v["signer_public"].as_str().unwrap(), v["server_now"].as_f64().unwrap(), &p)));
    each(&doc, "optimistic_window", |v| {
        let (i, w, n) = (v["issued_at"].as_f64().unwrap(), v["challenge_window_ms"].as_f64().unwrap(), v["now"].as_f64().unwrap());
        json!({ "end": challenge_window_end(i, w) as i64, "within": within_challenge_window(i, w, n), "phase": claim_status(i, w, n) })
    });
    each(&doc, "optimistic_fraud_proof", |v| check(fraud_proof_wire_check(&v["claim"], &v["proof"])));
    each(&doc, "optimistic_settlement", |v| check(settlement_wire_check(&v["record"], v["guardian_public"].as_str().unwrap())));
}

#[test]
fn ledger_vectors() {
    let doc = load("ledger-vectors.json");
    assert_eq!(doc["empty_tree_root"].as_str().unwrap(), empty_tree_root());
    let ok = |b: bool| json!({ "ok": b });
    // inclusion of a commit string leaf through the existing Merkle verifier
    each(&doc, "ledger_inclusion", |v| ok(atlas_pca::verify_inclusion(v["root"].as_str().unwrap_or(""), v["proof"].as_object(), &v["leaf"]) && v["root"].is_string()));
    each(&doc, "ledger_consistency", |v| ok(verify_ledger_consistency(&v["old_root"], &v["new_root"], &v["proof"])));
    each(&doc, "ledger_tree_head", |v| ok(verify_tree_head(&v["sth"], v["guardian_public"].as_str().unwrap(), None)));
    each(&doc, "ledger_cosign", |v| ok(verify_tree_head(&v["sth"], v["guardian_public"].as_str().unwrap(), Some(&v["policy"]))));
    each(&doc, "ledger_head_consistency", |v| ok(verify_head_consistency(&v["older"], &v["newer"], &v["proof"], v["guardian_public"].as_str().unwrap(), None)));
    each(&doc, "ledger_checkpoint_chain", |v| {
        let r = verify_checkpoint_chain(&v["chain"], v["guardian_public"].as_str().unwrap(), Some(&v["policy"]));
        if r.ok { json!({ "ok": true }) } else { json!({ "ok": false, "at": r.at }) }
    });
    each(&doc, "ledger_witnessed_head", |v| ok(verify_witnessed_head(&v["head"], v["witness_public"].as_str().unwrap())));
    each(&doc, "ledger_equivocation", |v| json!({ "equivocation": detect_equivocation(&v["a"], &v["b"], v["witness_public"].as_str().unwrap()) }));
}

/// Each rule fails without its check: hand-broken variants of valid inputs from the corpus.
#[test]
fn rules_are_each_load_bearing() {
    let doc = load("ledger-vectors.json");
    let g = doc["keys"]["guardian"].as_str().unwrap();
    let sth = &doc["ledger_tree_head"][0]["sth"];
    assert!(verify_tree_head(sth, g, None));
    let mut bad = sth.clone();
    bad["alg"] = json!("ml-dsa-65");
    assert!(!verify_tree_head(&bad, g, None), "a non-Ed25519 head is refused");
    // sizes 3 and 3 + 2^32 must never alias
    let c = load("ledger-vectors.json");
    let v = c["ledger_consistency"].as_array().unwrap().iter().find(|v| v["name"] == "ok-3-to-7").unwrap();
    assert!(verify_ledger_consistency(&v["old_root"], &v["new_root"], &v["proof"]));
    let mut wrapped = v["proof"].clone();
    wrapped["oldSize"] = json!(3u64 + (1 << 32));
    wrapped["newSize"] = json!(7u64 + (1 << 32));
    assert!(!verify_ledger_consistency(&v["old_root"], &v["new_root"], &wrapped));
    // the empty chain fails closed
    assert_eq!(verify_checkpoint_chain(&json!([]), g, None), CheckpointChainVerdict { ok: false, at: 0, reason: "empty" });
}
