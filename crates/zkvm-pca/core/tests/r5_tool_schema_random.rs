//! R5-ZK-01/02: the guest's `tool_schema` evaluation must agree with the TS reference (agent-native.ts `evaluateToolSchema`)
//! on RANDOM schemas with well-formed and malformed scalar bounds, astral strings and mixed-type arguments.
//! Golden: fixtures/ts_tool_schema_random.json from tests/gen_ts_tool_schema_random.ts (1200 schemas x 4 argument sets).
//! `PCA_SCHEMA_CASES=<file>` replaces the golden (the 100k run: 25000 schemas x 4 on a cloud box).
use pca_zkvm_core::caveats::{evaluate_caveat, CaveatCtx};
use serde_json::{json, Value};

fn guest(cv: &Value, args: &Value) -> bool {
    let root = json!({ "action": { "verb": "tool", "resource": "x", "params": args.clone() } });
    let ctx = CaveatCtx {
        now: 1.0e12, blast_radius: None, reversibility_class: None, delegation_depth: None, recent_action_times: None,
        action_root: &root, tool: Some("tool".to_string()), tool_args: Some(args.clone()), tool_signature_digest: None,
    };
    evaluate_caveat(cv, &ctx)
}

fn load() -> (Value, bool) {
    match std::env::var("PCA_SCHEMA_CASES") {
        Ok(p) => (serde_json::from_str(&std::fs::read_to_string(p).expect("PCA_SCHEMA_CASES readable")).unwrap(), true),
        Err(_) => (serde_json::from_str(include_str!("../../fixtures/ts_tool_schema_random.json")).unwrap(), false),
    }
}

#[test]
fn guest_agrees_with_the_ts_reference_on_random_malformed_and_wellformed_schemas() {
    let (g, custom) = load();
    let caveats = g["caveats"].as_array().unwrap();
    let cases = g["cases"].as_array().unwrap();
    assert!(custom || cases.len() >= 4800);
    let (mut sat, mut bad) = (0usize, Vec::new());
    for c in cases {
        let cv = &caveats[c[0].as_u64().unwrap() as usize];
        let want = c[2].as_bool().unwrap();
        if want { sat += 1 }
        let got = guest(cv, &c[1]);
        if got != want {
            bad.push(format!("TS {want} guest {got}: schema {} args {}", cv["schema"], c[1]));
        }
    }
    eprintln!("r5 tool_schema random: cases={} TS-satisfied={} divergences={}", cases.len(), sat, bad.len());
    assert!(sat > 100 && sat < cases.len() - 100, "corpus must exercise both verdicts ({sat}/{})", cases.len());
    assert!(bad.is_empty(), "{} divergences, first 10:\n{}", bad.len(), bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}
