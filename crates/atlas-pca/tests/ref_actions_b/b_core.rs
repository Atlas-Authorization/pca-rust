//! Replay of the OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers (test-data/ref-actions-import-core.json.gz).
//! Skipped (counted, must stay under 10% of the corpus): only cases with a lone surrogate (a Rust string cannot hold one).
use super::common::ref_cases;
use super::{cases_of, replay};
use atlas_pca::actions_kit_import::asyncapi::import_asyncapi;
use atlas_pca::actions_kit_import::common::*;
use atlas_pca::actions_kit_import::jsonschema::import_json_schema;
use atlas_pca::actions_kit_import::mcp::import_mcp;
use atlas_pca::actions_kit_import::openapi::import_openapi;
use atlas_pca::serde_json::Value;

fn text(v: &Value) -> String {
    v.as_str().expect("string arg").to_string()
}

fn call(f: &str, a: &[Value]) -> Option<R<Value>> {
    Some(match f {
        "tokensOf" => Ok(svec(&tokens_of_v(&a[0]))),
        "humanize" => Ok(Value::String(humanize(&js_str(&a[0])))),
        "verbOf" => Ok(Value::String(verb_of(&text(&a[0]), &a[1]))),
        "aliasOf" => Ok(alias_of(&a[0], &text(&a[1])).map_or(Value::Null, Value::String)),
        "paramSeg" => Ok(Value::String(param_seg(&text(&a[0])))),
        "clip" => Ok(Value::String(clipv(Some(&a[0]), a[1].as_u64().expect("max") as usize))),
        "pointer" => Ok(pointer(&a[0], &a[1]).cloned().unwrap_or(Value::Null)),
        "resolveLimits" => resolve_limits(a.first()).map(|l| l.to_json()),
        "checkParsed" => resolve_limits(a.get(1)).and_then(|l| check_parsed(&a[0], &l)).map(Value::from),
        "textSizeCheck" => resolve_limits(a.get(1)).and_then(|l| text_size_check(&a[0], &l)).map(|_| Value::Null),
        "importOpenApi" => import_openapi(&a[0], &a[1]),
        "importMcp" => import_mcp(&a[0], &a[1]),
        "importJsonSchema" => import_json_schema(&a[0], &a[1]),
        "importAsyncApi" => import_asyncapi(&a[0], &a[1]),
        other => panic!("unmapped fn {other}"),
    })
}

const FNS: [&str; 14] = [
    "tokensOf",
    "humanize",
    "verbOf",
    "aliasOf",
    "paramSeg",
    "clip",
    "pointer",
    "resolveLimits",
    "checkParsed",
    "textSizeCheck",
    "importOpenApi",
    "importMcp",
    "importJsonSchema",
    "importAsyncApi",
];

#[test]
fn every_function_is_covered() {
    let all = ref_cases("actions-import-core");
    let mut seen: Vec<String> = all.iter().map(|c| c["fn"].as_str().unwrap().to_string()).collect();
    seen.sort();
    seen.dedup();
    let mut want: Vec<String> = FNS.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(seen, want);
}

#[test]
fn matches_the_reference() {
    let all = ref_cases("actions-import-core");
    let (mut ran, mut skipped) = (0, 0);
    for f in FNS {
        let (r, s) = replay(f, &cases_of(&all, f), |a| call(f, a));
        ran += r;
        skipped += s;
    }
    assert!(skipped * 10 <= ran + skipped, "{skipped} of {} cases skipped", ran + skipped);
}
