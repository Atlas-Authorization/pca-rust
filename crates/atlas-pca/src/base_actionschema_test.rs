//! base differential oracle for rule-14 action schemas: tests/data/base-actionschema.json.gz, written by the TypeScript reference
//! (tools/pca-audit/oracles-base/actionschema-oracle.mts; the Java suite replays the same file): generated variants of a fully
//! populated v1 / v2 schema (every member deleted, retyped, at its byte limit), every collection limit, the parameter paths,
//! every declaration rule per type, the confirmation and floors shapes, paramValueViolation over every type and v2 format, and
//! formatCheck. Exact strings; only the strict canonicalizer's own message is language-specific (the "malformed schema:
//! canonicalize: " prefix is compared).
use super::*;
use crate::k042_support::{base_run, Base};
use serde_json::json;

const MALFORMED: &str = "malformed schema: canonicalize: ";
static NUL: Value = Value::Null;

fn text(want: &Value, got: Option<String>) -> Base {
    match (want.as_str(), &got) {
        (Some(w), Some(g)) if w.starts_with(MALFORMED) && g.starts_with(MALFORMED) => Base::Match(true),
        _ => Base::Val(json!(got)),
    }
}

#[test]
fn base_actionschema_matches_the_reference() {
    base_run("actionschema", 15000, |c, f, a| {
        let arg = |i: usize| a.get(i).unwrap_or(&NUL);
        let want = &c["out"];
        match f {
            "shape" => text(want, action_schema_shape_error(arg(0))),
            "shapeUnsigned" => text(want, action_schema_shape_error_unsigned(arg(0))),
            "confirmation" => Base::Val(json!(confirmation_shape_error(arg(0)))),
            "floors" => Base::Val(json!(schema_floors_error(Some(arg(0))))),
            "pvv" => match arg(0).as_object() {
                Some(d) => Base::Val(param_value_violation(d, arg(1)).map_or(Value::Null, |(code, reason)| json!({"code": code, "reason": reason}))),
                None => Base::Throw(None),
            },
            "format" => match (arg(0).as_str(), arg(1).as_str()) {
                (Some(fm), Some(x)) => Base::Val(format_check(fm, x).map_or(json!("unknown"), Value::Bool)),
                _ => Base::Skip("non-string format / value (typed port)"),
            },
            _ => Base::Skip("fn not mapped"),
        }
    });
}
