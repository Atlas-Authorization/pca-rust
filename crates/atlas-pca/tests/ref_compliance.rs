//! Differential replay of the compliance package (toAuditEvent, controlMappings / constants, toComplianceReport, renderJson /
//! renderMarkdown, frameworkReport, frameworkReportToMarkdown) against the TypeScript reference (test-data/ref-compliance.json.gz).
//! A reference throw only requires a refusal; outputs are compared through the canonical form.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate in their arguments (a Rust string cannot hold one).
mod common;
use atlas_pca::compliance::*;
use atlas_pca::serde_json::Value;

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i);
    match f {
        "toAuditEvent" => to_audit_event(arg(0)),
        "constants" => Ok(constants()),
        "controlMappings" => control_mappings(arg(0)),
        "toComplianceReport" => to_compliance_report(arg(0), arg(1)),
        "renderJson" => render_json(arg(0)).map(Value::String),
        "renderMarkdown" => render_markdown(arg(0)).map(Value::String),
        "frameworkReport" => framework_report(arg(0), arg(1), arg(2)),
        "frameworkReportToMarkdown" => framework_report_to_markdown(arg(0)).map(Value::String),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn compliance_vectors() {
    let cases = common::ref_cases("compliance");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap().clone();
        let got = std::panic::catch_unwind(|| run(f, &args)).unwrap_or_else(|_| Err("panic".into()));
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
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
