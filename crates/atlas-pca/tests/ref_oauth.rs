//! Differential replay of the OAuth / MCP-authorization bridge against the TypeScript reference
//! (test-data/ref-oauth.json.gz: `{fn, name, args, out}`; a `{"$throws"}` out must be refused). A missing file fails.
mod common;
use atlas_pca::oauth::*;
use atlas_pca::serde_json::{json, Value};

/// Messages the reference raises itself are compared exactly; a runtime TypeError of the reference only requires a refusal.
const OWN: [&str; 9] = [
    "prmPathForResource:", "protectedResourceMetadata:", "parseProtectedResourceMetadata:", "pca-oauth:", "wwwAuthenticate:", "encodePcaNeed:",
    "checkResourceIndicator:", "checkTokenAudience:", "buildPcaGrantDetail:",
];

fn same(want: &Value, got: Result<Value, String>) -> bool {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(msg), Err(e)) => !OWN.iter().any(|p| msg.starts_with(p)) || msg == e,
        (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&v),
        _ => false,
    }
}

fn strs(v: &Value) -> Option<Vec<&str>> {
    v.as_array()?.iter().map(Value::as_str).collect()
}

#[test]
fn oauth_vectors() {
    let mut bad = Vec::new();
    let mut skipped = 0;
    let cases = common::ref_cases("oauth");
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let a0 = &a[0];
        let (a1, a2) = (a.get(1), a.get(2));
        let got: Option<Result<Value, String>> = match c["fn"].as_str().unwrap() {
            "resourceIdentifierProblem" => Some(Ok(json!(resource_identifier_problem(a0)))),
            "prmPathForResource" => a0.as_str().map(|s| prm_path_for_resource(s).map(Value::String)),
            "prmUrlForResource" => a0.as_str().map(|s| prm_url_for_resource(s).map(Value::String)),
            "protectedResourceMetadata" => Some(protected_resource_metadata(a0)),
            "oauthDiscoveryHandler" => Some(oauth_discovery_handler(a0)),
            "parseProtectedResourceMetadata" => Some(parse_protected_resource_metadata(a0, a1)),
            "wwwAuthenticate" => Some(www_authenticate(a0, a1).map(Value::String)),
            "mcpUnauthorized" => Some(mcp_unauthorized(a0, a1)),
            "upgradeUnauthorizedChallenge" => Some(upgrade_unauthorized_challenge(a0, a1.unwrap(), a2)),
            "checkResourceIndicator" => Some(check_resource_indicator(a0, a1.unwrap())),
            "checkTokenAudience" => Some(check_token_audience(a0, a1.unwrap())),
            "buildPcaGrantDetail" => match (strs(&a0["chainIds"]), a0.get("locations")) {
                (Some(ids), loc) if loc.is_none_or(Value::is_array) => {
                    Some(build_pca_grant_detail(&ids, a0.get("chainRef"), a0.get("bundleRevision"), loc.and_then(Value::as_array).map(|l| l.as_slice())))
                }
                _ => None,
            },
            "pcaGrantRequestParam" => a0.as_array().map(|d| Ok(Value::String(pca_grant_request_param(d)))),
            "authorizePcaGrantToken" => match (strs(&a0["chainIds"]), a0["resource"].as_str(), a0["proofVerified"].as_bool()) {
                (Some(ids), Some(r), Some(p)) => Some(Ok(authorize_pca_grant_token(&a0["authorizationDetails"], r, &ids, p))),
                _ => None,
            },
            "oauthScopeForAction" => match a1.unwrap().get("granted") {
                Some(g) if !g.is_array() => None,
                g => Some(Ok(oauth_scope_for_action(a0, a1.unwrap().get("provider"), g.and_then(Value::as_array).map(|l| l.as_slice()), a1.unwrap().get("resource")))),
            },
            f => panic!("unknown fn {f}"),
        };
        match got {
            None => skipped += 1,
            Some(g) => {
                let shown = format!("{g:?}");
                if !same(&c["out"], g) {
                    bad.push(format!("{}\n  want {}\n  got  {shown}", c["name"], c["out"]));
                }
            }
        }
    }
    assert!(skipped * 10 < cases.len(), "too many untyped cases skipped: {skipped}");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
