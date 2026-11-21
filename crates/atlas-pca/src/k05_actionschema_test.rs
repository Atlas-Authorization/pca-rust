//! k05 differential oracle for rule-14 action schemas: tests/data/k05-actionschema.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/actionschema-oracle.mts; the Java suite replays the same file): generated variants of a fully
//! populated v1 / v2 schema (every member deleted, retyped, at its byte limit), every collection limit, the parameter paths,
//! every declaration rule per type, the confirmation and floors shapes, paramValueViolation over every type and v2 format, and
//! formatCheck. Exact strings; only the strict canonicalizer's own message is language-specific (the "malformed schema:
//! canonicalize: " prefix is compared).
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

const MALFORMED: &str = "malformed schema: canonicalize: ";
static NUL: Value = Value::Null;

fn text(want: &Value, got: Option<String>) -> K05 {
    match (want.as_str(), &got) {
        (Some(w), Some(g)) if w.starts_with(MALFORMED) && g.starts_with(MALFORMED) => K05::Match(true),
        _ => K05::Val(json!(got)),
    }
}

#[test]
fn k05_actionschema_matches_the_reference() {
    k05_run("actionschema", 15000, |c, f, a| {
        let arg = |i: usize| a.get(i).unwrap_or(&NUL);
        let want = &c["out"];
        match f {
            "shape" => text(want, action_schema_shape_error(arg(0))),
            "shapeUnsigned" => text(want, action_schema_shape_error_unsigned(arg(0))),
            "confirmation" => K05::Val(json!(confirmation_shape_error(arg(0)))),
            "floors" => K05::Val(json!(schema_floors_error(Some(arg(0))))),
            "pvv" => match arg(0).as_object() {
                Some(d) => K05::Val(param_value_violation(d, arg(1)).map_or(Value::Null, |(code, reason)| json!({"code": code, "reason": reason}))),
                None => K05::Throw(None),
            },
            "format" => match (arg(0).as_str(), arg(1).as_str()) {
                (Some(fm), Some(x)) => K05::Val(format_check(fm, x).map_or(json!("unknown"), Value::Bool)),
                _ => K05::Skip("non-string format / value (typed port)"),
            },
            _ => K05::Skip("fn not mapped"),
        }
    });
}
