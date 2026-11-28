//! Differential replay of the GraphQL and gRPC importers (SDL / introspection / `.proto` / descriptor-set parsers included) against the
//! TypeScript reference corpus (test-data/ref-actions-import-sdl.json.gz).
//! Shortcuts: a parser result is compared in the corpus form (`GqlSchema::to_json`, `ProtoModel::to_json`); a `{"$bytes": b64url}` argument
//! is decoded to bytes. Skips: a case whose text argument is not a string (parseGraphqlSdl / parseProto) or whose bytes argument is not a
//! `$bytes` object (parseDescriptorSet) cannot be typed here and is skipped (the corpus has none); lone-surrogate cases are skipped by the
//! shared replay. Skips stay under 10% of each function.
use super::common::{b64d, ref_cases};
use super::{cases_of, replay};
use atlas_pca::actions_kit_import::common::Source;
use atlas_pca::actions_kit_import::{graphql, grpc};
use atlas_pca::serde_json::Value;

const PKG: &str = "actions-import-sdl";
const FNS: [&str; 6] = ["importGraphql", "parseGraphqlSdl", "fromIntrospection", "importGrpc", "parseProto", "parseDescriptorSet"];

/// The bytes of a `{"$bytes": b64url}` argument.
fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).map(b64d)
}

fn arg(a: &[Value], i: usize) -> Value {
    a.get(i).cloned().unwrap_or(Value::Null)
}

fn check(name: &str, ran: usize, skipped: usize) {
    assert!(ran > 0, "{name}: no case ran");
    assert!(skipped * 10 < ran + skipped, "{name}: {skipped} of {} cases skipped", ran + skipped);
}

#[test]
fn every_function_is_covered() {
    let all = ref_cases(PKG);
    let mut seen: Vec<String> = all.iter().filter_map(|c| c["fn"].as_str().map(String::from)).collect();
    seen.sort();
    seen.dedup();
    let mut want: Vec<String> = FNS.iter().map(|x| x.to_string()).collect();
    want.sort();
    assert_eq!(seen, want);
}

#[test]
fn import_graphql() {
    let cases = cases_of(&ref_cases(PKG), "importGraphql");
    let (ran, skipped) = replay("importGraphql", &cases, |a| Some(graphql::import_graphql(&arg(a, 0), &arg(a, 1))));
    check("importGraphql", ran, skipped);
}

#[test]
fn parse_graphql_sdl() {
    let cases = cases_of(&ref_cases(PKG), "parseGraphqlSdl");
    let (ran, skipped) = replay("parseGraphqlSdl", &cases, |a| {
        let t = a.first()?.as_str()?;
        Some(graphql::parse_graphql_sdl(t).map(|s| s.to_json()))
    });
    check("parseGraphqlSdl", ran, skipped);
}

#[test]
fn from_introspection() {
    let cases = cases_of(&ref_cases(PKG), "fromIntrospection");
    let (ran, skipped) = replay("fromIntrospection", &cases, |a| Some(graphql::from_introspection(&arg(a, 0)).map(|s| s.to_json())));
    check("fromIntrospection", ran, skipped);
}

#[test]
fn import_grpc() {
    let cases = cases_of(&ref_cases(PKG), "importGrpc");
    let (ran, skipped) = replay("importGrpc", &cases, |a| {
        let src = arg(a, 0);
        let opts = arg(a, 1);
        Some(match bytes_of(&src) {
            Some(b) => grpc::import_grpc(Source::Bytes(&b), &opts),
            None => grpc::import_grpc(Source::Json(&src), &opts),
        })
    });
    check("importGrpc", ran, skipped);
}

#[test]
fn parse_proto() {
    let cases = cases_of(&ref_cases(PKG), "parseProto");
    let (ran, skipped) = replay("parseProto", &cases, |a| {
        let t = a.first()?.as_str()?;
        Some(grpc::parse_proto(t).map(|m| m.to_json()))
    });
    check("parseProto", ran, skipped);
}

#[test]
fn parse_descriptor_set() {
    let cases = cases_of(&ref_cases(PKG), "parseDescriptorSet");
    let (ran, skipped) = replay("parseDescriptorSet", &cases, |a| {
        let b = bytes_of(a.first()?)?;
        Some(grpc::parse_descriptor_set(&b).map(|m| m.to_json()))
    });
    check("parseDescriptorSet", ran, skipped);
}

#[test]
fn a_non_text_non_bytes_grpc_source_is_refused() {
    let opts: Value = atlas_pca::serde_json::json!({"ns": "api"});
    for v in [Value::Null, Value::Bool(true), atlas_pca::serde_json::json!(5), atlas_pca::serde_json::json!([]), atlas_pca::serde_json::json!({})] {
        assert!(grpc::import_grpc(Source::Json(&v), &opts).is_err());
    }
}
