//! Differential replay of the MCP adapter's pure surface against the TypeScript reference (test-data/ref-mcp.json.gz): the
//! WWW-Authenticate parser, step-up planner and RFC 9207 iss table, the tool-result proof meta and header, the v1
//! action-schema draft with decisions, and the closed-world tool-call check.
//! A reference refusal must be a refusal; the package's own texts (`applySchemaDecisions: ...`) compare exactly.
mod common;
use atlas_pca::mcp::*;
use atlas_pca::serde_json::{json, Value};

static NULL: Value = Value::Null;

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if !w.starts_with("applySchemaDecisions:") || w == g => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

#[test]
fn mcp_vectors() {
    let cases = common::ref_cases("mcp");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        if c.to_string().contains(common::LONE) {
            skipped += 1;
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let g = |i: usize| a.get(i).unwrap_or(&NULL);
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "constants" => Ok(constants()),
            "parseChallenges" => Ok(parse_challenges(g(0))),
            "pcaNeedProblem" => Ok(json!(pca_need_problem(g(0)))),
            "planStepUp" => plan_step_up(g(0), g(1), g(2)),
            "checkAuthorizationResponseIss" => check_authorization_response_iss(g(0)),
            "guardToolResult" => guard_tool_result(g(0), g(1)),
            "pcaHeaders" => match g(0).as_str() {
                Some(e) => Ok(pca_headers(e)),
                None => {
                    skipped += 1;
                    continue;
                }
            },
            "draftActionSchemaFromMcp" => draft_action_schema_from_mcp(g(0), g(1)),
            "applySchemaDecisions" => apply_schema_decisions(g(0), g(1)),
            "verbOfTool" => verb_of_tool(g(0), g(1)),
            "conformToolCall" => conform_tool_call(g(0), g(1), g(2)),
            other => panic!("unknown fn {other}"),
        };
        if let Err(e) = same(&c["out"], got) {
            bad.push(format!("{}: {e}", c["name"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "too many skipped: {skipped}");
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
