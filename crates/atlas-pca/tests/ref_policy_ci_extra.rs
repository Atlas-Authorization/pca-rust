//! Differential replay of test-data/ref-policy-ci-java-extra.json.gz (written by the TypeScript reference): `lintPolicy` with a parameter schema
//! (rule schema-mismatch), and the authoring `test` and `coverage` commands run to their results (`{ok, exitCode, lines}`). Every case keeps the
//! reference result, an internal-error finding included. A reference throw requires a refusal; per-function totals are asserted.
mod common;
use std::collections::BTreeMap;

use atlas_pca::policy_ci::{coverage_command, lint_policy, test_command};
use atlas_pca::serde_json::Value;

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let opts = a.get(2).cloned().unwrap_or(Value::Null);
    match f {
        "lintPolicy" => Ok(lint_policy(&a[0], a.get(1).unwrap_or(&Value::Null))),
        "testCommand" => test_command(&a[0], &a[1], &opts),
        "coverageCommand" => coverage_command(&a[0], &a[1], &opts),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn policy_ci_extra_replay() {
    let cases = common::ref_cases("policy-ci-java-extra");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = Vec::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        *per_fn.entry(f.to_string()).or_default() += 1;
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    let want: BTreeMap<String, usize> =
        [("lintPolicy", 81), ("testCommand", 45), ("coverageCommand", 36)].iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 162);
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
