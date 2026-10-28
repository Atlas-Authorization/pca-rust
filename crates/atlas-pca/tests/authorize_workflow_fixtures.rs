//! K5 workflow admission inside `authorize` (C-308): packages/pca/conformance/authorize-workflow-fixtures.json, signed by the
//! TypeScript reference with its outcomes recorded. Each case threads its steps through ONE replay store, with the file's `plan`
//! as the server's authorized plan. A missing file fails, it never skips.
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{authorize, AuthorizeInput, MemoryStateStore, Operation, WorkflowCall, WorkflowGate};

fn load() -> Value {
    let path = format!("{}/../../conformance/authorize-workflow-fixtures.json", env!("CARGO_MANIFEST_DIR"));
    atlas_pca::strict_parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))).expect("parse")
}

#[test]
fn authorize_workflow_fixtures_replay() {
    let f = load();
    assert_eq!(f["format"], "pca-authorize-workflow-fixtures/1");
    let cases = f["cases"].as_array().unwrap();
    assert!(cases.len() >= 14, "{} cases", cases.len());
    let grant = f["grant"].clone();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    let resolve = move |r: &str| Ok::<_, String>(if r == grant_id { Some(grant.clone()) } else { None });
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let plan = f["plan"].clone();
    let context = move |_: &Value| Ok::<_, String>(Some(json!({ "plan": plan, "plan_authorized": true })));
    let mut bad: Vec<String> = Vec::new();
    for c in cases {
        let store = MemoryStateStore::new();
        let gate = WorkflowGate { principal: f["principal"].as_str().unwrap().into(), rs_signer: f["rs_signer"].as_str().unwrap().into(), required: c["required"].as_bool().unwrap() };
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            let op = Operation::from_json(&s["operation"]).unwrap();
            let call = s.get("workflow").map(|w| WorkflowCall {
                commitment: w["commitment"].clone(),
                receipts: w["receipts"].clone(),
                step: w["step"].clone(),
                units: w.get("units").cloned().unwrap_or_else(|| json!({})),
                goal_digest: w.get("goal_digest").cloned().unwrap_or(Value::Null),
            });
            let input = AuthorizeInput {
                operation: Some(&op),
                audience: f["audience"].as_str().unwrap(),
                resolve_grant: Some(&resolve),
                state_store: Some(&store),
                is_revoked: Some(&revoked),
                now: f["now"].as_i64(),
                plan: None,
                context: Some(&context),
                workflow: Some(&gate),
                workflow_call: call.as_ref(),
                ..Default::default()
            };
            let r = authorize(Some(&s["pcactn"]), &input);
            let e = &s["expect"];
            let want_failed: Vec<&str> = e["failed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            let got = (r.allow, r.decision, i64::from(r.status), r.failed_checks());
            let want = (e["allow"].as_bool().unwrap(), e["decision"].as_str().unwrap(), e["status"].as_i64().unwrap(), want_failed);
            if got != want {
                bad.push(format!("{} step {i}: got {got:?} ({:?}), want {want:?}", c["name"], r.reason));
            }
            if let Some(why) = e["reason"].as_str() {
                if !r.reason.as_deref().unwrap_or("").contains(why) {
                    bad.push(format!("{} step {i}: reason {:?} lacks {why:?}", c["name"], r.reason));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
