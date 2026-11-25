//! Differential replay of the AuthZEN PDP, handler and Search APIs (guards, defaultToAction, AARP, PDP refusal / merge paths, handler,
//! search, searchMetadata) against the TypeScript reference (test-data/ref-authzen.json.gz). A reference throw only requires a refusal.
//! The PDP / search cases name a fixed config or provider; the tables below rebuild them. Permit paths that need the Policy-VM, a signed
//! PCActn or the analyzer are not in the corpus. Skipped (counted, must stay under 10%): cases with a lone surrogate.
mod common;
use atlas_pca::authzen::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::Arc;

fn rf(f: impl Fn(&Value) -> Result<Option<PdpContext>, String> + Send + Sync + 'static) -> ResolveFn {
    Arc::new(f)
}

fn jf(f: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static) -> JsonFn {
    Arc::new(f)
}

fn pdp(name: &str) -> AuthzenPdp {
    let resolve: ResolveFn = match name {
        "throws" => rf(|_| Err("boom".to_string())),
        "noauth" | "auth" => rf(|_| Ok(Some(PdpContext { grant: json!({}), policy: json!({}), ..PdpContext::default() }))),
        _ => rf(|_| Ok(None)),
    };
    let mut c = PdpConfig::new(resolve);
    c.now = Some(Arc::new(|| 1_000_000_i64));
    match name {
        "auth" => c.authorizer = Some(jf(|_| Ok(json!({ "allow": true })))),
        "max2" => c.max_evaluations = Some(2.0),
        "toolmap" => c.tool_capability = Some(Arc::new(|n: &str| Ok::<String, String>(format!("cap.{n}")))),
        "toolthrow" => c.tool_capability = Some(Arc::new(|_: &str| Err::<String, String>("bad tool".to_string()))),
        _ => {}
    }
    authzen_pdp(c)
}

fn user(id: &str) -> Value {
    json!({ "type": "user", "id": id })
}

fn provider(name: &str) -> SearchProvider {
    let f = |v: Value| -> SearchFn { jf(move |_| Ok(v.clone())) };
    let mut p = SearchProvider::default();
    match name {
        "full" => {
            p.search_subject = Some(f(json!({ "results": [user("a"), user("b"), { "type": "group", "id": "g" }, user("a"), { "id": "a", "type": "user" }],
                "page": { "next_token": "", "total": 3, "properties": { "k": 1 } }, "context": { "c": 1 } })));
            p.search_resource = Some(f(
                json!({ "results": [{ "type": "doc", "id": "1" }, { "type": "doc", "id": "2" }, { "type": "user", "id": "x" }], "page": { "next_token": "n1" } }),
            ));
            p.search_action =
                Some(f(json!({ "results": [{ "name": "read" }, { "name": "write" }, { "name": "read" }, { "name": "read", "properties": { "p": 1 } }] })));
        }
        "nopage" => {
            p.search_subject = Some(f(json!({ "results": [user("a"), user("b")] })));
            p.search_resource = Some(f(json!({ "results": [] })));
            p.search_action = Some(f(json!({ "results": [] })));
        }
        "emptyprops" => p.search_subject = Some(f(json!({ "results": [user("a")], "page": { "next_token": "z", "properties": {} }, "context": {} }))),
        "bad" => {
            p.search_subject = Some(f(json!({ "results": [null] })));
            p.search_resource = Some(f(json!({ "results": [5] })));
            p.search_action = Some(f(json!({ "results": [null, 5] })));
        }
        "notarray" => {
            p.search_subject = Some(f(json!({ "results": "x" })));
            p.search_resource = Some(f(json!({})));
            p.search_action = Some(f(json!({ "results": null })));
        }
        "throws" => {
            let t: SearchFn = jf(|_| Err("x".to_string()));
            p.search_subject = Some(t.clone());
            p.search_resource = Some(t.clone());
            p.search_action = Some(t);
        }
        "echo" => {
            let t: SearchFn = jf(|r| Ok(json!({ "results": [], "context": { "saw": r } })));
            p.search_subject = Some(t.clone());
            p.search_resource = Some(t.clone());
            p.search_action = Some(t);
        }
        "partial" => p.search_resource = Some(f(json!({ "results": [] }))),
        _ => {}
    }
    p
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let name = |i: usize| a[i].as_str().unwrap().to_string();
    match f {
        "isAuthzenSubject" => Ok(json!(is_authzen_subject(&a[0]))),
        "isAuthzenAction" => Ok(json!(is_authzen_action(&a[0]))),
        "isAuthzenResource" => Ok(json!(is_authzen_resource(&a[0]))),
        "isAccessEvaluationRequest" => Ok(json!(is_access_evaluation_request(&a[0]))),
        "isAccessEvaluationsRequest" => Ok(json!(is_access_evaluations_request(&a[0]))),
        "isCoazToolAuthorizationRequest" => Ok(json!(is_coaz_tool_authorization_request(&a[0]))),
        "isSubjectSearch" => Ok(json!(is_subject_search(&a[0]))),
        "isResourceSearch" => Ok(json!(is_resource_search(&a[0]))),
        "isActionSearch" => Ok(json!(is_action_search(&a[0]))),
        "defaultToAction" => default_to_action(&a[0]),
        "approvalOf" => approval_of(&a[0]),
        "isApprovalRequired" => is_approval_required(&a[0]).map(|b| json!(b)),
        "pdp.evaluate" => Ok(pdp(&name(0)).evaluate(&a[1])),
        "pdp.evaluations" => pdp(&name(0)).evaluations(&a[1]),
        "pdp.evaluateTool" => pdp(&name(0)).evaluate_tool(&a[1]),
        "authzenHandler" => Ok(authzen_handler(&pdp(&name(0)), &a[1])),
        "authzenSearchHandler" => Ok(authzen_search_handler(&provider(&name(0)), &a[1]).unwrap_or(Value::Null)),
        "searchMetadata" => Ok(search_metadata(&name(0), &provider(&name(1)))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn authzen_vectors() {
    let cases = common::ref_cases("authzen");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
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
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
