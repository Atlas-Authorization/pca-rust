//! Shared driver of the differential replays: every case of a reference corpus goes through one dispatch function, which must
//! panic on a function it does not handle.
use serde_json::{json, Value};

pub fn skip(why: &str) -> Value {
    json!({"$skip": why})
}

pub fn thrown(e: impl std::fmt::Display) -> Value {
    json!({"$throws": e.to_string()})
}

/// A reference refusal must be a refusal here (the message is not compared); anything else is compared as canonical JSON.
pub fn differs(want: &Value, got: &Value) -> bool {
    // an XML library's own text after a fail-closed RIM refusal is not part of the contract
    let rim = |v: &Value| -> Value {
        let mut y = v.clone();
        if let Some(r) = y.get_mut("reason") {
            if r.as_str().is_some_and(|t| t.starts_with("RIM: verification error (fail closed): ")) {
                *r = Value::String("RIM: verification error (fail closed)".into());
            }
        }
        y
    };
    if want.get("reason").is_some() {
        return differs_raw(&rim(want), &rim(got));
    }
    differs_raw(want, got)
}

fn differs_raw(want: &Value, got: &Value) -> bool {
    if want.get("$throws").is_some() {
        // an engine crash also passes on a refusal decision; any other expected throw needs a throw here, as before
        if super::expected_throw(want).is_some_and(super::engine_crash) {
            !super::refused(got)
        } else {
            got.get("$throws").is_none()
        }
    } else {
        atlas_pca::canonicalize(want) != atlas_pca::canonicalize(got) && !super::json_close(want, got)
    }
}

/// Replays every case of `test-data/ref-<corpus>.json.gz` through `run(fn, args)` and asserts the case total. A case whose
/// arguments carry a lone surrogate cannot be built as a Rust string, and `run` may answer `{"$skip": reason}` for a case the typed
/// API cannot express: neither is compared, and the number of such cases must equal `not_run`.
pub fn replay(corpus: &str, total: usize, not_run: usize, run: impl Fn(&str, &[Value]) -> Value) {
    replay_cases(corpus, super::ref_cases_seeded(corpus), total, not_run, run)
}

pub fn replay_cases(corpus: &str, cases: Vec<Value>, total: usize, not_run: usize, run: impl Fn(&str, &[Value]) -> Value) {
    assert_eq!(cases.len(), total, "{corpus}: case total");
    let (mut skipped, mut bad) = (0usize, Vec::new());
    for c in &cases {
        if super::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = run(c["fn"].as_str().unwrap_or(""), c["args"].as_array().map(Vec::as_slice).unwrap_or(&[]));
        if let Some(why) = got.get("$skip") {
            eprintln!("{corpus}: {} not run: {why}", c["name"]);
            skipped += 1;
        } else if differs(&c["out"], &got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert_eq!(
        skipped, not_run,
        "{corpus}: cases not run (a lone surrogate in the arguments, or not expressible in the typed API)"
    );
    assert!(bad.is_empty(), "{corpus}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
