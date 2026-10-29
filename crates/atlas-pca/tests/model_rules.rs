//! Rules 20 (units) and 21 (tighten-only) END TO END through `authorize`: the shared vectors
//! `packages/pca/conformance/model-rules-vectors.json` (signed grants, decided by the TypeScript reference). A grant's
//! `tighten[]` rules, unit tags and polarity are signed policy: ignoring them would let a model move a decision up, so every
//! case must decide the same as the reference, reason text included.

mod common;

use atlas_pca::{
    authorize, AuthorizeInput, AuthorizeResult, IntentV2Context, MemoryStateStore, Operation,
};
use serde_json::{json, Value};

fn vectors() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/model-rules-vectors.json"
    );
    atlas_pca::strict_parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn is_model_reason(r: &str) -> bool {
    ["units: ", "tighten: ", "schema: ", "intent_session: "]
        .iter()
        .any(|p| r.starts_with(p))
}

fn run(d: &Value, c: &Value) -> AuthorizeResult {
    let op = Operation::from_json(&c["operation"]).unwrap();
    let g = c["grant"].clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let is_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let v2 = c.get("intent_v2").cloned();
    let intent = move |_: &Value| {
        Ok::<Option<IntentV2Context>, String>(v2.as_ref().and_then(IntentV2Context::from_json))
    };
    let env = c["context"]["env"].clone();
    let context = move |_: &Value| Ok::<Option<Value>, String>(Some(json!({ "env": env.clone() })));
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&is_revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        intent_v2: if c.get("intent_v2").is_some() {
            Some(&intent)
        } else {
            None
        },
        context: if c.get("context").is_some() {
            Some(&context)
        } else {
            None
        },
        provenance_mediators: &common::harness_pins(),
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    authorize(Some(&c["pcactn"]), &input)
}

#[test]
fn model_rules_vectors() {
    let d = vectors();
    let mut decisions = std::collections::BTreeSet::new();
    for c in d["cases"].as_array().unwrap() {
        let e = &c["expect"];
        let name = c["name"].as_str().unwrap();
        decisions.insert(e["decision"].as_str().unwrap().to_string());
        let r = run(&d, c);
        assert_eq!(
            (r.allow, r.decision, r.status as i64),
            (
                e["allow"].as_bool().unwrap(),
                e["decision"].as_str().unwrap(),
                e["status"].as_i64().unwrap()
            ),
            "{name}: {:?}",
            r.reasons
        );
        let want: Vec<&str> = e["failed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(r.failed_checks(), want, "{name}: {:?}", r.reasons);
        let got: Vec<&str> = r
            .reasons
            .iter()
            .map(String::as_str)
            .filter(|x| is_model_reason(x))
            .collect();
        let want: Vec<&str> = e["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(got, want, "{name}");
        for k in ["units", "tighten"] {
            assert_eq!(
                r.checks.get(k).map(|s| s.as_str()),
                e[k].as_str(),
                "{name}: check {k}"
            );
        }
        let want_deg: Vec<(String, String)> = e["degraded"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let got_deg: Vec<(String, String)> = r
            .degraded
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(got_deg, want_deg, "{name}");
    }
    assert_eq!(
        decisions.len(),
        3,
        "the vectors must exercise allow, escalate and deny"
    );
}
