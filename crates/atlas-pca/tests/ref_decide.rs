//! Differential replay of the Policy VM against the TypeScript reference: `decide` over test-data/ref-decide-java.json.gz (226 cases)
//! and `derive_decide_input` alone and followed by `decide` over test-data/ref-decide-derive.json.gz (240 cases). Every case of both
//! corpora is replayed; an unknown function fails the test.
mod common;
use atlas_pca::policy_vm::{decide, derive_decide_input, DECIDE_INPUT_GRANT_REQUIRED};
use atlas_pca::serde_json::{json, Value};

fn run(f: &str, a: &[Value]) -> Value {
    let null = Value::Null;
    let arg = |i: usize| a.get(i).unwrap_or(&null);
    let thrown = |e: String| {
        if e == DECIDE_INPUT_GRANT_REQUIRED {
            json!({"$throws": e, "code": "grant_required"})
        } else {
            json!({"$throws": e})
        }
    };
    match f {
        "decide" => decide(arg(0)),
        "deriveDecideInput" => derive_decide_input(arg(0), arg(1)).unwrap_or_else(thrown),
        // the reference answers `{input, decision}`: the derived input and the decision taken on it
        "deriveThenDecide" => derive_decide_input(arg(0), arg(1)).map(|i| json!({"decision": decide(&i), "input": i})).unwrap_or_else(thrown),
        other => panic!("unhandled corpus function {other}"),
    }
}

fn replay(corpus: &str, total: usize) {
    let cases = common::ref_cases(corpus);
    assert_eq!(cases.len(), total, "{corpus}: case total");
    let mut bad = Vec::new();
    for c in &cases {
        let args = c["args"].as_array().cloned().unwrap_or_default();
        let got = run(c["fn"].as_str().unwrap_or(""), &args);
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{corpus}: {} of {total} cases differ:\n{}", bad.len(), bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn decide_matches_the_reference() {
    replay("decide-java", 226);
}

#[test]
fn derive_decide_input_matches_the_reference() {
    replay("decide-derive", 240);
}
