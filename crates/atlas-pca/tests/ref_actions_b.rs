//! Differential replay of the action importers (OpenAPI / MCP / JSON Schema / AsyncAPI, GraphQL / gRPC, the suggestion engine and the
//! review / pipeline / evaluation flow) against the TypeScript reference (test-data/ref-actions-import-{core,sdl,suggest,review}.json.gz).
//! One module per corpus under tests/ref_actions_b/. A reference throw requires an error (with the same code when the case has one);
//! cases carrying a lone surrogate are skipped (a Rust string cannot hold one).
#[path = "ref_actions_b/b_core.rs"]
mod b_core;
#[path = "ref_actions_b/b_review.rs"]
mod b_review;
#[path = "ref_actions_b/b_sdl.rs"]
mod b_sdl;
#[path = "ref_actions_b/b_suggest.rs"]
mod b_suggest;
mod common;

use atlas_pca::actions_kit_import::common::ActionKitError;
use atlas_pca::serde_json::Value;

/// Structural equality; numbers compare by value (the reference has one number type).
pub fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x == y || x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w))),
        _ => a == b,
    }
}

pub fn throws(out: &Value) -> bool {
    out.get("$throws").is_some()
}

/// The cases of one function of a corpus.
pub fn cases_of(all: &[Value], f: &str) -> Vec<Value> {
    all.iter().filter(|c| c["fn"].as_str() == Some(f)).cloned().collect()
}

/// Replay `cases` through `call(args)`: `None` skips the case (counted), `Some(Ok(v))` must equal the reference output, `Some(Err(e))`
/// requires the reference to have thrown (with `e.code` equal when the case names one). Returns (ran, skipped); panics listing up to 20
/// mismatches.
pub fn replay(fname: &str, cases: &[Value], call: impl Fn(&[Value]) -> Option<Result<Value, ActionKitError>>) -> (usize, usize) {
    let (mut ran, mut skipped) = (0, 0);
    let mut bad: Vec<String> = vec![];
    for c in cases {
        let args = c["args"].as_array().expect("args");
        let out = &c["out"];
        if args.iter().any(common::has_lone) || common::has_lone(out) {
            skipped += 1;
            continue;
        }
        let Some(r) = call(args) else {
            skipped += 1;
            continue;
        };
        ran += 1;
        let name = c["name"].as_str().unwrap_or("?");
        match r {
            Ok(v) => {
                if throws(out) {
                    bad.push(format!("{name}: returned {} but the reference threw {}", v.to_string().chars().take(200).collect::<String>(), out["$throws"]));
                } else if !same(&v, out) {
                    bad.push(format!(
                        "{name}:\n   native {}\n   ref    {}",
                        v.to_string().chars().take(400).collect::<String>(),
                        out.to_string().chars().take(400).collect::<String>()
                    ));
                }
            }
            Err(e) => {
                if !throws(out) {
                    bad.push(format!(
                        "{name}: raised {}: {} but the reference returned {}",
                        e.code,
                        e.message,
                        out.to_string().chars().take(200).collect::<String>()
                    ));
                } else if let Some(code) = out.get("code").and_then(Value::as_str) {
                    if e.code != code {
                        bad.push(format!("{name}: raised code {} ({}) but the reference raised {code}", e.code, e.message));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{fname}: {} of {ran} differ from the reference:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
    (ran, skipped)
}
