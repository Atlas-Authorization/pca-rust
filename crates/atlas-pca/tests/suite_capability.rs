//! Suite capability (packages/pca/conformance/SUITES.md): the manifest, the unsupported_suite refusal, and the FN-DSA
//! known-answer vectors of the TS reference (packages/pca/conformance/fndsa-vectors.json) through the suite dispatch, and
//! (feature `less`) the LESS known answers (packages/pca/conformance/less-vectors.json).
mod common;

use atlas_pca::{supported_suites, verify_artifact_suite, REGISTERED_SUITES};
use common::load;
use serde_json::Value;

#[test]
fn manifest() {
    assert_eq!(REGISTERED_SUITES.len(), 14);
    let s = supported_suites();
    let less = cfg!(feature = "less");
    assert_eq!(s.len(), if less { 14 } else { 12 }, "{s:?}");
    assert_eq!(s.contains(&"less-cat1"), less);
    assert_eq!(s.contains(&"hybrid-ed25519-less-cat1"), less);
    for a in ["fn-dsa-512", "fn-dsa-1024", "slh-dsa-sha2-256s", "hybrid-nested-ed25519-ml-dsa-65"] {
        assert!(s.contains(&a), "{a}");
    }
}

#[cfg(not(feature = "less"))]
#[test]
fn unsupported_suite_reason() {
    use atlas_pca::UNSUPPORTED_SUITE_REASON;
    use serde_json::json;
    let doc = load("vectors.json");
    let v = doc["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "pq-leaf-ml-dsa-87-valid").unwrap();
    for alg in ["less-cat1", "hybrid-ed25519-less-cat1"] {
        let mut p = v["pcactn"].clone();
        p["alg"] = json!(alg);
        let got = atlas_pca::verify_pcactn_core_policy(&p, &v["grant"], v["context"]["now"].as_i64().unwrap(), v["context"]["aud"].as_str().unwrap(), None);
        assert!(!got.allow && got.reason.contains(&format!("{UNSUPPORTED_SUITE_REASON}: {alg}")), "{alg}: {}", got.reason);
    }
    let mut p = v["pcactn"].clone();
    p["alg"] = json!("ml-dsa-999");
    let got = atlas_pca::verify_pcactn_core_policy(&p, &v["grant"], 0, "x", None);
    assert!(!got.allow && !got.reason.contains(UNSUPPORTED_SUITE_REASON), "{}", got.reason);
}

#[test]
fn fndsa_known_answers() {
    let doc = load("fndsa-vectors.json");
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(vs.len() >= 10);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let mut art = serde_json::Map::new();
        for k in ["alg", "sig", "pq_pk", "pq_sig"] {
            if let Some(x) = v.get(k) {
                art.insert(k.into(), x.clone());
            }
        }
        let msg = v["message"].as_str().and_then(|m| atlas_pca::decode_b64u_strict(m, None));
        let want = v["expect"]["allow"].as_bool().unwrap();
        let got = msg.is_some_and(|m| verify_artifact_suite(&Value::Object(art), "", &m));
        assert_eq!(got, want, "{name}");
    }
}

#[cfg(feature = "less")]
#[test]
fn less_known_answers() {
    let doc = load("less-vectors.json");
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(vs.len() >= 20);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let key = &doc["keys"][v["key"].as_str().unwrap()];
        let mut art = serde_json::Map::new();
        for k in ["alg", "sig", "pq_sig"] {
            if let Some(x) = v.get(k) {
                art.insert(k.into(), x.clone());
            }
        }
        art.insert("pq_pk".into(), v.get("pq_pk_override").unwrap_or(&key["pq_pk"]).clone());
        let msg = atlas_pca::decode_b64u_strict(v["message"].as_str().unwrap(), None).expect("message");
        let got = verify_artifact_suite(&Value::Object(art), key["ed_pub"].as_str().unwrap(), &msg);
        assert_eq!(got, v["expect"]["allow"].as_bool().unwrap(), "{name}");
    }
}

/// less-c/ must be byte-identical to the canonical sdks/pca-less-c (in the repository; skipped when it is absent).
#[cfg(feature = "less")]
#[test]
fn less_copy_matches_canonical() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let canon = root.join("../pca-less-c");
    if !canon.join("atlas_less.c").is_file() {
        return;
    }
    let mut n = 0;
    let mut stack = vec![root.join("less-c")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p.strip_prefix(root.join("less-c")).unwrap();
            assert_eq!(std::fs::read(&p).unwrap(), std::fs::read(canon.join(rel)).unwrap(), "less-c/{} drifted (sdks/pca-less-c/sync-copies.sh)", rel.display());
            n += 1;
        }
    }
    assert!(n >= 31, "{n} files");
}
