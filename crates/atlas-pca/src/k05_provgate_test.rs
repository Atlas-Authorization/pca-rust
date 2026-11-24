//! k05 differential oracle for build provenance as a K1 discharge: tests/data/k05-provgate.json.gz, written by the TypeScript
//! reference (tools/pca-audit/k05-oracles/provgate-oracle.mts; every native replays the same file). Byte arguments are base64url
//! strings; a negative or fractional RFC 9162 index / size (not a u64 here) is a proof that cannot verify.
use super::*;
use crate::k042_support::{k05_b64, k05_run, K05};

fn ub(v: &Value) -> Vec<u8> {
    crate::decode_b64u_strict(v.as_str().unwrap_or(""), None).expect("oracle bytes")
}

fn ostr(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(String::from)
}

#[test]
fn k05_provgate_matches_the_reference() {
    k05_run("provgate", 4400, |_, f, a| match f {
        "provenanceFactsError" => K05::Val(json!(provenance_facts_error(&a[0]))),
        "provenancePolicyError" => K05::Val(json!(provenance_policy_error(&a[0]))),
        "provenanceGate" => K05::Val(match provenance_gate(&a[0]) {
            Ok(ok) => json!({"ok": true, "level": ok.level, "claims": ok.claims}),
            Err(code) => json!({"ok": false, "code": code}),
        }),
        "verifyRfc9162Inclusion" => {
            let proof: Vec<Vec<u8>> = a[3].as_array().expect("proof").iter().map(ub).collect();
            K05::Val(json!(match (a[1].as_u64(), a[2].as_u64()) {
                (Some(i), Some(n)) => verify_rfc9162_inclusion(&ub(&a[0]), i, n, &proof, &ub(&a[4])),
                _ => false,
            }))
        }
        "rfc9162LeafHash" => K05::Val(k05_b64(&rfc9162_leaf_hash(&ub(&a[0])))),
        "provenanceCaveat" => {
            let o = &a[0];
            let opts = ProvenanceCaveatOptions {
                id: ostr(o, "id"),
                issuer: ostr(o, "issuer").unwrap_or_default(),
                min_level: o.get("min_level").and_then(Value::as_i64).unwrap_or(0),
                source_repo: ostr(o, "source_repo"),
                builder_ids: o.get("builder_ids").and_then(Value::as_array).map(|xs| xs.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
                oidc_issuer: ostr(o, "oidc_issuer"),
                require_runtime: o.get("require_runtime").and_then(Value::as_bool),
                bind: ostr(o, "bind"),
                ttl_ms: o.get("ttl_ms").and_then(Value::as_i64),
            };
            K05::Val(provenance_caveat(&opts))
        }
        _ => K05::Skip("fn not in this module"),
    });
}
