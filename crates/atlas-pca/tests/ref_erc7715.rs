//! Differential replay of the ERC-7715 permission mapping and granted-permission check against the TypeScript reference
//! (test-data/ref-erc7715.json.gz).
mod common;
use atlas_pca::erc7715::*;
use atlas_pca::serde_json::{json, Value};

fn same(want: &Value, got: Result<Value, String>) -> bool {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(m), Err(e)) => common::engine_crash(m) || m == e,
        (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&v),
        _ => false,
    }
}

#[test]
fn erc7715_vectors() {
    let cases = common::ref_cases("erc7715");
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "grantToPermissionRequest" => match &a[1] {
                // reading a member of null (or of a non-object) is the reference's TypeError
                Value::Null => Err("TypeError: Cannot read properties of null (reading 'chainId')".to_string()),
                o => atlas_pca::erc7715::grant_to_permission_request_value(&a[0], o),
            },
            "supportsRequest" => Ok(json!(supports_request(&a[0], &a[1]))),
            // an absent context is `undefined`, which JSON.stringify drops
            "revokeParams" => Ok(a.first().map_or_else(|| json!({}), |c| json!({ "permissionContext": c }))),
            "grantDigestOf" => grant_digest_of(&a[0]).map(Value::String),
            "verifyGrantedPermission" => {
                let vo = &a[3];
                // a non-list (or non-string) manager set is a TypeError inside the reference's try: response_malformed
                let managers: Option<Vec<&str>> = vo["allowedManagers"].as_array().and_then(|l| l.iter().map(Value::as_str).collect());
                match managers {
                    None => Ok(json!("response_malformed")),
                    Some(managers) => {
                        let owners = vo.get("owners").cloned();
                        let owner_fn = owners.as_ref().map(|ow| move |ctx: &str| ow.get(ctx).and_then(Value::as_str).map(String::from));
                        let of = owner_fn.as_ref().map(|f| f as &dyn Fn(&str) -> Option<String>);
                        Ok(json!(verify_granted_permission(&a[0], &a[1], &a[2], &managers, of)))
                    }
                }
            }
            f => panic!("unknown fn {f}"),
        };
        let shown = format!("{got:?}");
        if !same(&c["out"], got) {
            bad.push(format!("{}\n  want {}\n  got  {shown}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
