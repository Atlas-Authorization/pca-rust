//! R4-03: a malformed or unbound `tool_schema` caveat must be UNSATISFIED in the guest, exactly as in the TS
//! reference (agent-native.ts `evaluateToolSchema`). Before the fix every `?` on an `Option` in
//! `evaluate_tool_schema` returned `None`, which the caller reads as "satisfied".
//! Golden: fixtures/ts_tool_schema_cases.json from tests/gen_ts_tool_schema_cases.ts (the 6 round-4 PoC cases + 32 more).
use pca_zkvm_core::caveats::{evaluate_caveat, evaluate_caveats, CaveatCtx};
use pca_zkvm_core::commit::hash_canonical;
use serde_json::{json, Value};

fn ctx<'a>(root: &'a Value, tool: Option<&str>, args: Option<Value>, sigd: Option<String>) -> CaveatCtx<'a> {
    CaveatCtx {
        now: 1.0e12,
        blast_radius: None,
        reversibility_class: None,
        delegation_depth: None,
        recent_action_times: None,
        action_root: root,
        tool: tool.map(|s| s.to_string()),
        tool_args: args,
        tool_signature_digest: sigd,
    }
}

#[test]
fn guest_agrees_with_ts_on_every_golden_tool_schema_case() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("../../fixtures/ts_tool_schema_cases.json")).unwrap();
    assert!(cases.len() >= 38);
    let mut bad = Vec::new();
    let mut sat = 0;
    for c in &cases {
        let root = json!({ "action": { "verb": c["tool"].clone(), "resource": "x", "params": c["args"].clone() } });
        let cx = ctx(&root, c["tool"].as_str(), Some(c["args"].clone()), c["tool_signature_digest"].as_str().map(String::from));
        let got = evaluate_caveat(&c["caveat"], &cx);
        let want = c["satisfied"].as_bool().unwrap();
        if want { sat += 1 }
        if got != want {
            bad.push(format!("{}: TS {} guest {}", c["id"], want, got));
        }
    }
    assert!(sat >= 3, "the corpus must contain satisfied controls");
    assert!(bad.is_empty(), "divergences: {bad:?}");
}

fn good() -> Value {
    let schema = json!({ "props": { "amount": { "type": "integer", "max": 10 } }, "required": ["amount"] });
    let sig = "sigdigest".to_string();
    let binding = json!({ "tool": "pay", "signature_digest": sig, "schema": schema });
    json!({ "type": "tool_schema", "tool": "pay", "signature_digest": sig, "schema": schema,
            "schema_digest": hash_canonical(&schema), "binding_digest": hash_canonical(&binding) })
}

#[test]
fn control_well_formed_caveat_is_satisfied_and_each_field_is_load_bearing() {
    let root = json!({});
    let cx = ctx(&root, Some("pay"), Some(json!({ "amount": 5 })), None);
    assert!(evaluate_caveat(&good(), &cx), "positive control");
    for key in ["tool", "schema", "schema_digest", "binding_digest", "signature_digest"] {
        let mut c = good();
        c.as_object_mut().unwrap().remove(key);
        assert!(!evaluate_caveat(&c, &cx), "missing {key} must be unsatisfied");
        let mut c = good();
        c[key] = json!(42);
        assert!(!evaluate_caveat(&c, &cx), "{key} of the wrong type must be unsatisfied");
        let mut c = good();
        c[key] = Value::Null;
        assert!(!evaluate_caveat(&c, &cx), "null {key} must be unsatisfied");
    }
}

#[test]
fn no_tool_call_in_context_is_unsatisfied() {
    // the PoC class "unbound": the call context carries no tool / no args
    let root = json!({});
    assert!(!evaluate_caveat(&good(), &ctx(&root, None, Some(json!({ "amount": 5 })), None)));
    assert!(!evaluate_caveat(&good(), &ctx(&root, Some("pay"), None, None)));
    assert!(!evaluate_caveat(&good(), &ctx(&root, Some("pay"), Some(json!("x")), None)));
}

#[test]
fn schema_that_is_not_an_object_is_unsatisfied() {
    let root = json!({});
    let cx = ctx(&root, Some("pay"), Some(json!({})), None);
    for bad in [json!(null), json!("x"), json!(3), json!([]), json!(true)] {
        let mut c = good();
        c["schema"] = bad.clone();
        c["schema_digest"] = json!(hash_canonical(&bad));
        let b = json!({ "tool": "pay", "signature_digest": "sigdigest", "schema": bad });
        c["binding_digest"] = json!(hash_canonical(&b));
        assert!(!evaluate_caveat(&c, &cx), "schema {bad} (digests consistent) must be unsatisfied");
    }
}

#[test]
fn a_malformed_delegated_tool_schema_fails_the_caveat_list() {
    let root = json!({});
    let cx = ctx(&root, Some("pay"), Some(json!({ "amount": 5 })), None);
    let malformed = json!({ "type": "tool_schema", "tool": "pay" });
    let out = evaluate_caveats(&[good(), malformed], &cx);
    assert!(!out.ok);
    assert_eq!(out.failed, vec!["tool_schema".to_string()]);
}
