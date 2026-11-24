//! Runtime-class claims: packages/pca/conformance/runtime-claim-vectors.json. A missing file fails, it never skips.
use atlas_pca::agent::{sign_artifact, KeyPair, Suite};
use atlas_pca::runtime_claim::{verified_runtime_class, RUNTIME_CLAIM_DOMAIN};
use atlas_pca::serde_json::{json, Value};

fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

#[test]
fn runtime_claim_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/runtime-claim-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read runtime-claim-vectors.json")).expect("parse");
    let t = &doc["trust"];
    let (pinned, pd, ev) = (strs(&t["pinnedAttestors"]), t["passportDigest"].as_str().unwrap(), strs(&t["verifiedEvidenceDigests"]));
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 8);
    let mut bad = Vec::new();
    for c in cases {
        let got = verified_runtime_class(&c["claim"], &pinned, pd, &ev, c["now"].as_i64().unwrap());
        if got != c["expect"].as_str().unwrap() {
            bad.push(format!("{}: {got}", c["name"]));
        }
    }
    let first = &cases[0];
    let now = first["now"].as_i64().unwrap();
    if verified_runtime_class(&first["claim"], &[], pd, &ev, now) != "none" {
        bad.push("unpinned attestor accepted".into());
    }
    if verified_runtime_class(&first["claim"], &pinned, pd, &[], now) != "none" {
        bad.push("unverified evidence accepted".into());
    }
    if verified_runtime_class(&Value::Null, &pinned, pd, &ev, now) != "none" {
        bad.push("null claim".into());
    }
    assert!(bad.is_empty(), "{bad:?}");
}

const CLASS: &str = "os_confined";

fn signed_claim(k: &KeyPair, edit: impl FnOnce(&mut Value)) -> Value {
    let mut body = json!({"v": 1, "class": CLASS, "passport_digest": "pd", "evidence_digest": "ev", "iat": 100, "exp": 200, "attestor": k.public});
    edit(&mut body);
    sign_artifact(RUNTIME_CLAIM_DOMAIN, &body, k, &Suite::default()).unwrap()
}

/// Every claim is correctly signed by the pinned attestor, so only the clause under test can refuse it.
#[test]
fn runtime_claim_refuses_each_clause_alone() {
    let k = KeyPair::from_seed(&[5u8; 32]);
    let pinned = [k.public.clone()];
    let class = |c: &Value, pd: &str, ev: &str, now: i64| verified_runtime_class(c, &pinned, pd, &[ev.to_string()], now);
    let base = signed_claim(&k, |_| {});
    assert_eq!(class(&base, "pd", "ev", 150), CLASS);

    // now = 0 is a valid clock, the same as the reference
    let from_zero = signed_claim(&k, |b| b["iat"] = json!(0));
    assert_eq!(class(&from_zero, "pd", "ev", 0), CLASS);

    assert_eq!(class(&signed_claim(&k, |b| b["extra"] = json!(1)), "pd", "ev", 150), "none");
    assert_eq!(class(&signed_claim(&k, |b| b["v"] = json!(2)), "pd", "ev", 150), "none");

    // Stricter than packages/pca-sandbox/src/runtime-claim.ts (no length or emptiness check there), as Go and Python are.
    let (max, over) = ("e".repeat(128), "e".repeat(129));
    assert_eq!(class(&signed_claim(&k, |b| b["evidence_digest"] = json!(max)), "pd", &max, 150), CLASS);
    assert_eq!(class(&signed_claim(&k, |b| b["evidence_digest"] = json!(over)), "pd", &over, 150), "none");
    assert_eq!(class(&signed_claim(&k, |b| b["passport_digest"] = json!(over)), &over, "ev", 150), "none");
    assert_eq!(class(&signed_claim(&k, |b| b["evidence_digest"] = json!("")), "pd", "", 150), "none");
    assert_eq!(class(&signed_claim(&k, |b| b["passport_digest"] = json!("")), "", "ev", 150), "none");
}
