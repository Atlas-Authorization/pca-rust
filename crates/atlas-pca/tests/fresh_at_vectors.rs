//! The `fresh_at` PCActn member: packages/pca/conformance/fresh-at-vectors.json (case shape of vectors.json plus
//! `context.fresh_at`, the verifier's policy). A missing file fails, it never skips.
use atlas_pca::fresh_at::FreshAtPolicy;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::{
    decision_of, verify_pcactn_core_with, verify_pcactn_core_with_fresh_at, VerifyOptions,
};

fn load() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/fresh-at-vectors.json"
    );
    let doc: Value = atlas_pca::serde_json::from_str(
        &std::fs::read_to_string(path).expect("read fresh-at-vectors.json"),
    )
    .expect("parse fresh-at-vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(1));
    let vs = doc["vectors"].as_array().expect("vectors").clone();
    assert!(vs.len() >= 28, "the corpus shrank: {} vectors", vs.len());
    vs
}

#[test]
fn fresh_at_member_vectors() {
    let mut bad = Vec::new();
    for v in load() {
        let name = v["name"].as_str().unwrap_or("?");
        let ctx = &v["context"];
        let policy = match ctx.get("fresh_at") {
            Some(p) => Some(
                FreshAtPolicy::from_json(p)
                    .unwrap_or_else(|| panic!("{name}: malformed context.fresh_at")),
            ),
            None => None,
        };
        let got = verify_pcactn_core_with_fresh_at(
            &v["pcactn"],
            &v["grant"],
            ctx["now"].as_i64().unwrap(),
            ctx["aud"].as_str().unwrap(),
            &VerifyOptions::default(),
            policy.as_ref(),
        );
        let want = &v["expect"];

        if got.allow != want["allow"].as_bool().unwrap() {
            bad.push(format!("{name}: allow {} ({})", got.allow, got.reason));
        }
        // the corpus keeps `fresh_at` out of `checks` and reports it on its own
        let status = match got.checks.get("fresh_at") {
            Some(true) => "pass",
            Some(false) => "fail",
            None => "absent",
        };
        if status != want["fresh_at"].as_str().unwrap() {
            bad.push(format!(
                "{name}: fresh_at {status}, want {}",
                want["fresh_at"]
            ));
        }
        let rest: Vec<(&String, &bool)> = got
            .checks
            .iter()
            .filter(|(k, _)| k.as_str() != "fresh_at")
            .collect();
        let wc = want["checks"].as_object().unwrap();
        if rest.len() != wc.len()
            || rest
                .iter()
                .any(|(k, b)| wc.get(k.as_str()).and_then(Value::as_bool) != Some(**b))
        {
            bad.push(format!(
                "{name}: checks {rest:?}, want {wc:?} ({})",
                got.reason
            ));
        }
        // the ternary decision, from the verdict's own status map and reason list
        let statuses: Map<String, Value> = got
            .checks
            .iter()
            .map(|(k, b)| (k.clone(), json!(if *b { "pass" } else { "fail" })))
            .collect();
        let decision =
            decision_of(&json!({"allow": got.allow, "checks": statuses, "reasons": got.reasons}));
        if decision != want["decision"].as_str().unwrap() {
            bad.push(format!(
                "{name}: decision {decision}, want {} ({:?})",
                want["decision"], got.reasons
            ));
        }
        if let Some(r) = want.get("reason").and_then(Value::as_str) {
            // `fresh_at:` and `wire:` reasons are pinned exactly; another check's wording is that check's own vectors' business
            let exact = r.starts_with("fresh_at: ") || r.starts_with("wire: ");
            let same = if exact {
                got.reason == r
            } else {
                got.reason.split(": ").next() == r.split(": ").next()
            };
            if !same {
                bad.push(format!("{name}: reason {:?}, want {r:?}", got.reason));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} fresh_at vectors failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// A verifier built without a policy (every entry point except `..._with_fresh_at`) refuses a PCActn that carries the member.
#[test]
fn member_without_a_policy_fails_closed() {
    let mut seen = 0;
    for v in load() {
        if v["pcactn"].get("fresh_at").is_none() {
            continue;
        }
        let ctx = &v["context"];
        let got = verify_pcactn_core_with(
            &v["pcactn"],
            &v["grant"],
            ctx["now"].as_i64().unwrap(),
            ctx["aud"].as_str().unwrap(),
            &VerifyOptions::default(),
        );
        assert!(!got.allow, "{}", v["name"]);
        if got.checks.get("wire") != Some(&false) {
            assert_eq!(got.checks.get("fresh_at"), Some(&false), "{}", v["name"]);
            seen += 1;
        }
    }
    assert!(seen > 0);
}
