mod common;
use atlas_pca::*;
use common::*;
use serde_json::Value;

/// Replays packages/pca/conformance/allowlist-anchor-vectors.json (wire-level allowlist anchor evidence).
#[test]
fn allowlist_anchor_vectors() {
    let doc = load("allowlist-anchor-vectors.json");
    let trust = &doc["trust"];
    let vs = doc["allowlist_anchor"].as_array().expect("vectors");
    assert!(vs.len() >= 74, "only {} vectors", vs.len());
    let mut bad = Vec::new();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let m = &v["manifest"];
        let mine = AnchorEntry { issuer: m["issuer"].as_str().unwrap().into(), version: m["version"].as_i64().unwrap(), digest: m["digest"].as_str().unwrap().into() };
        let cached = v.get("cachedHead").filter(|c| !c.is_null());
        let evidence = v.get("evidence").filter(|e| !e.is_null());
        let got = verify_allowlist_anchored(
            &mine,
            evidence,
            &AnchorOptions {
                log_key: trust["logKey"].as_str().unwrap(),
                instance_id: trust["instanceId"].as_str().unwrap(),
                principal: trust["principal"].as_str().unwrap(),
                now_ms: v["now"].as_i64().unwrap(),
                max_head_age_ms: v.get("maxHeadAgeMs").and_then(Value::as_i64),
                clock_skew_ms: v.get("clockSkewMs").and_then(Value::as_i64),
                cached_head: cached,
            },
        );
        let want = &v["expect"];
        let ok = if want["ok"].as_bool().unwrap() {
            got == Ok(want["highestAnchoredVersion"].as_i64().unwrap())
        } else {
            got == Err(want["code"].as_str().unwrap())
        };
        if !ok {
            bad.push(format!("{name}: got {got:?}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} vectors disagree:\n{}", bad.len(), vs.len(), bad.join("\n"));
}
