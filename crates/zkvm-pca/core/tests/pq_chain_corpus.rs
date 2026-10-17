//! The capability chain + leaf PCActn signature in the guest against the shared conformance corpus (packages/pca/conformance/
//! vectors.json, TS reference = oracle): every wire-valid PCActn vector (ed25519 core, `pq-leaf-*` under all suites,
//! `pq-nonleaf-*` hop suites, `pqbind-*` holder_pq / suite binding). The guest runs `verifyChain(chain, grant.issuer,
//! {trustedRoot: grant})` (its PCActn path) and the leaf step; `expect.checks.chain` / `leaf_signature` must match, except that
//! FN-DSA / LESS suites (and vectors without an `allowed_suites`-free context, which the guest has no input for) are refused.
use pca_zkvm_core::chain::{verify_chain_with, verify_hops_with};
use pca_zkvm_core::leaf_sig_from_pcactn;
use serde_json::Value;

const UNSUPPORTED: [&str; 2] = ["less-cat1", "hybrid-ed25519-less-cat1"];

fn vectors() -> Vec<Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conformance/vectors.json");
    let text = std::fs::read_to_string(p).unwrap();
    let mut lines = text.lines().skip_while(|l| l.trim() != "\"vectors\": [").skip(1);
    lines
        .by_ref()
        .take_while(|l| !l.trim().starts_with(']'))
        .filter_map(|l| serde_json::from_str(l.trim().trim_end_matches(',')).ok()) // lone-surrogate vectors do not parse: wire failures anyway
        .collect()
}

fn uses_unsupported(v: &Value) -> bool {
    let s = v.to_string();
    UNSUPPORTED.iter().any(|a| s.contains(&format!("\"alg\":\"{a}\"")))
}

#[test]
fn chain_and_leaf_match_the_corpus() {
    let vs = vectors();
    assert!(vs.len() >= 300, "{} vectors", vs.len());
    let (mut ran, mut pq, mut refused) = (0, 0, 0);
    let mut bad = Vec::new();
    for v in &vs {
        let name = v["name"].as_str().unwrap_or("?");
        let checks = &v["expect"]["checks"];
        if checks["wire"] != Value::Bool(true) || v.get("pcactn").is_none() {
            continue;
        }
        if v["context"].get("allowed_suites").is_some() {
            continue; // a verifier suite policy: the guest has no such input
        }
        let p = &v["pcactn"];
        let chain = match p["cap_chain"].as_array() {
            Some(c) => c.clone(),
            None => continue,
        };
        let grant = &v["grant"];
        let root = grant["issuer"].as_str().unwrap_or("");
        let leaf = match leaf_sig_from_pcactn(p) {
            Some(l) => l,
            None => continue,
        };
        let hops = verify_hops_with(&chain, root, Some(grant));
        let full = verify_chain_with(&chain, root, Some(grant), &leaf);
        ran += 1;
        if name.starts_with("pq") {
            pq += 1;
        }
        if uses_unsupported(v) {
            refused += 1;
            if full.ok {
                bad.push(format!("{name}: an unsupported suite must be refused"));
            }
            continue;
        }
        let want_chain = checks["chain"] == Value::Bool(true);
        let want_leaf = checks["leaf_signature"] == Value::Bool(true);
        if hops.ok != want_chain {
            bad.push(format!("{name}: chain guest {} ({:?}) TS {want_chain}", hops.ok, hops.reason));
        } else if want_chain && full.ok != want_leaf {
            bad.push(format!("{name}: leaf guest {} ({:?}) TS {want_leaf}", full.ok, full.reason));
        }
    }
    assert!(bad.is_empty(), "{} of {ran} vectors differ:\n{}", bad.len(), bad.join("\n"));
    assert!(ran >= 150 && pq >= 60, "ran {ran} pq {pq} refused {refused}");
    eprintln!("chain corpus: {ran} vectors ({pq} pq*, {refused} unsupported-suite refusals)");
}
