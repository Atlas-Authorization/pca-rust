//! Differential replay of the dataflow trace-rule language, its compiler and the lethal-trifecta lint against the TypeScript
//! reference (test-data/ref-dataflow-rs.json.gz). A refusal compares its code and message exactly.
mod common;
use atlas_pca::dataflow::*;
use atlas_pca::serde_json::{json, Value};

fn err(e: TraceRuleError) -> Value {
    json!({ "$throws": e.message, "code": e.code })
}

fn run(f: &str, a: &[Value]) -> Value {
    let s = |i: usize| a[i].as_str().unwrap();
    let r = match f {
        "parseTraceRule" => parse_trace_rule(s(0), s(1), a.get(2).and_then(Value::as_str)),
        "parseInvariantRule" => parse_invariant_rule(s(0), s(1), a.get(2).unwrap_or(&Value::Null)),
        "compileTraceRules" => compile_trace_rules(a[0].as_array().unwrap(), &a[1]),
        "compileTexts" => a[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| parse_trace_rule(p[0].as_str().unwrap(), p[1].as_str().unwrap(), None))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|rules| compile_trace_rules(&rules, &a[1])),
        "lethalTrifecta" => Ok(lethal_trifecta(&a[0], a[1].as_array().unwrap(), a.get(2))),
        "categoryId" => Ok(json!(category_id(&a[0]))),
        f => panic!("unknown fn {f}"),
    };
    r.unwrap_or_else(err)
}

#[test]
fn dataflow_vectors() {
    let cases = common::ref_cases("dataflow-rs");
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {got}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
