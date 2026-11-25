//! Differential replay of test-data/ref-connectors-providers.json.gz (written by the TypeScript reference): the 15 seeded provider
//! manifests (manifest, digest, validity), their structural invariants, the built-in list (order and catalog digest) and lookups of ids
//! outside the catalog (case, whitespace and prototype names are never found). Every function of the corpus has a handler and the totals
//! are asserted.
mod common;
use std::collections::BTreeMap;

use atlas_pca::connectors::{catalog_digest, get_provider, manifest_digest, validate_manifest};
use atlas_pca::connectors_providers::builtin_manifests;
use atlas_pca::serde_json::{json, Value};

fn manifest(id: &str) -> Value {
    builtin_manifests().into_iter().find(|m| m["id"] == json!(id)).unwrap_or_else(|| panic!("no built-in provider {id}"))
}

fn strings(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect()
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "provider" => {
            let m = manifest(a[0].as_str().unwrap());
            json!({"manifest": m, "digest": manifest_digest(&m), "valid": validate_manifest(&m)["ok"] == json!(true)})
        }
        "invariants" => {
            let id = a[0].as_str().unwrap();
            let m = manifest(id);
            let (available, defaults) = (strings(&m["scopesAvailable"]), strings(&m["defaultScopes"]));
            let mut unique = available.clone();
            unique.sort_unstable();
            unique.dedup();
            let https = ["authorizeUrl", "tokenUrl"].iter().all(|k| m[*k].as_str().unwrap().starts_with("https://"));
            json!({
                "defaultScopesSubset": defaults.iter().all(|s| available.contains(s)),
                "scopesUnique": unique.len() == available.len(),
                "idMatchesKey": m["id"] == json!(id),
                "httpsEndpoints": https,
            })
        }
        "builtinManifests" => {
            let all = builtin_manifests();
            json!({
                "ids": all.iter().map(|m| m["id"].clone()).collect::<Vec<_>>(),
                "digests": all.iter().map(manifest_digest).collect::<Vec<_>>(),
                "catalogDigest": catalog_digest(None),
            })
        }
        "unknownProvider" => json!({"found": get_provider(a[0].as_str().unwrap()).is_some()}),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn connectors_providers_replay() {
    let cases = common::ref_cases("connectors-providers");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [("provider", 15), ("invariants", 15), ("builtinManifests", 1), ("unknownProvider", 9)]
        .iter()
        .map(|(k, n)| (k.to_string(), *n))
        .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 40);
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
