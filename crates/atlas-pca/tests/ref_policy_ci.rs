//! Differential replay of the policy-safety CI gate (normalization, lint rules over the analyzer, summary, pinned lint-rule digest,
//! authoring gates, command line) against the TypeScript reference (test-data/ref-policy-ci.json.gz). A reference throw only requires a
//! refusal. `run` cases write their files into a fresh directory and resolve the argument names there. A case whose reference result
//! carried an `internal-error` finding was dropped by the generator. Skipped (counted, must stay under 10%): cases with a lone surrogate.
mod common;
use atlas_pca::policy_ci::*;
use atlas_pca::serde_json::{json, Value};

fn opts(a: &[Value], i: usize) -> Value {
    a.get(i).cloned().unwrap_or(Value::Null)
}

fn run_case(a: &Value) -> Value {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("pcaci-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    for (k, v) in a["files"].as_object().unwrap() {
        std::fs::write(dir.join(k), v.as_str().unwrap()).unwrap();
    }
    let argv: Vec<String> = a["argv"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    let mut lines: Vec<String> = vec![];
    let code = run_in(&argv, Some(&dir), &mut |l: &str| lines.push(l.to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    json!({ "code": code, "lines": lines })
}

fn run(f: &str, a: &Value) -> Result<Value, String> {
    if f == "run" {
        return Ok(run_case(a));
    }
    let a = a.as_array().unwrap();
    match f {
        "normalizePolicyInput" => Ok(normalize_policy_input(&a[0])),
        "normalizeChain" => normalize_chain(&a[0]),
        "isCapability" => Ok(json!(is_capability(&a[0]))),
        "isEnvelope" => Ok(json!(is_envelope(&a[0]))),
        "lintPolicy" => Ok(lint_policy(&a[0], &opts(a, 1))),
        "lintChain" => lint_chain(&a[0], &opts(a, 1)),
        "lint" => lint(&a[0], &opts(a, 1)),
        "lintPolicies" => lint_policies(&a[0], &opts(a, 1)),
        "summarize" => summarize(&a[0], &opts(a, 1)),
        "checkLintRulesPin" => Ok(check_lint_rules_pin(a[0].as_str().ok_or("pin text must be a string")?, a.get(1).and_then(Value::as_str))),
        "toAnalyzerPolicy" => Ok(to_analyzer_policy(&a[0])),
        "diffCommand" => diff_command(&a[0], &a[1], &opts(a, 2)),
        "testCommand" => test_command(&a[0], &a[1], &opts(a, 2)),
        "coverageCommand" => coverage_command(&a[0], &a[1], &opts(a, 2)),
        "parseArgs" => {
            let argv: Vec<String> = a[0].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
            Ok(parse_args(&argv))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn policy_ci_vectors() {
    let cases = common::ref_cases("policy-ci");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, &c["args"])).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
