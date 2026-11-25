//! Differential replay of the SCIM /Agents handler, the passport mapping, the filter and the push adapters against the
//! TypeScript reference (test-data/ref-scim.json.gz). Handler sessions use the reference's named option table.
mod common;
use atlas_pca::scim::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const T0: f64 = 1_700_000_000_000.0;

fn options(name: &str) -> ScimHandlerOptions {
    let fixed = || Some(Box::new(|| T0) as Box<dyn Fn() -> f64 + Send + Sync>);
    let auth = |ok: bool| Some(Box::new(move |_: &Value| ok) as Box<dyn Fn(&Value) -> bool + Send + Sync>);
    match name {
        "open" => ScimHandlerOptions { base_url: Some("https://scim.acme.com/scim/v2".into()), now: fixed(), authenticate: auth(true), ..Default::default() },
        "slash" => {
            ScimHandlerOptions { base_url: Some("https://scim.acme.com/scim/v2///".into()), now: fixed(), authenticate: auth(true), ..Default::default() }
        }
        "nobase" => ScimHandlerOptions { now: fixed(), allow_unauthenticated: true, ..Default::default() },
        "tick" => {
            let tick = Arc::new(AtomicU64::new(0));
            let now = Box::new(move || T0 + 1000.0 * tick.fetch_add(1, Ordering::SeqCst) as f64);
            ScimHandlerOptions { base_url: Some("https://x.example".into()), now: Some(now), authenticate: auth(true), ..Default::default() }
        }
        // deny / a throwing authenticate / a truthy non-`true` answer all refuse
        "deny" | "throwauth" | "truthy" => ScimHandlerOptions { now: fixed(), authenticate: auth(false), ..Default::default() },
        // no authenticate, or a non-function one, and no allowUnauthenticated: construction refuses
        "noauth" | "notfn" => ScimHandlerOptions { now: fixed(), ..Default::default() },
        n => panic!("unknown options {n}"),
    }
}

fn session(a: &[Value]) -> Result<Value, String> {
    let h = ScimHandler::new(options(a[0].as_str().unwrap()))?;
    for r in a[1].as_array().unwrap() {
        h.handle(r)?;
    }
    a[2].as_array().unwrap().iter().map(|r| h.handle(r)).collect::<Result<Vec<_>, _>>().map(Value::Array)
}

fn push(f: &str, agent: &Value, mode: &str, endpoint: &str, token: &str) -> Result<Value, String> {
    let mut calls = Vec::new();
    let mut fetch = |url: &str, init: &Value| {
        calls.push(json!({ "url": url, "init": init }));
        Ok::<_, String>(match mode {
            "ok201" => PushReply { ok: true, status: 201, json: Ok(json!({ "id": "obj-1" })) },
            "err500" => PushReply { ok: false, status: 500, json: Ok(json!({ "detail": "x" })) },
            "badjson" => PushReply { ok: true, status: 204, json: Err("no body".into()) },
            "nullbody" => PushReply { ok: true, status: 200, json: Ok(Value::Null) },
            m => panic!("unknown fetch {m}"),
        })
    };
    let result = match f {
        "pushToEntra" => push_to_entra(agent, endpoint, token, &mut fetch)?,
        "pushToOkta" => push_to_okta(agent, endpoint, token, &mut fetch)?,
        _ => push_provision(&to_entra_agent_payload(agent), endpoint, token, &mut fetch)?,
    };
    Ok(json!({ "result": result, "calls": calls }))
}

fn verr(e: ScimValueError) -> String {
    e.detail
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i).cloned().unwrap_or(Value::Null);
    match f {
        "scimSession" => session(a),
        "passportFingerprint" => passport_fingerprint(&a[0]).map(Value::String),
        "issuePassport" => atlas_pca::agent::issue_passport(&a[0]),
        "passportToScim" if a[2].is_number() => passport_to_scim(&a[0], &a[1], &json!({ "now": a[2] })),
        "passportToScim" => passport_to_scim(&a[0], &a[1], &a[2]),
        "scimToProvisioningRequest" => scim_to_provisioning_request(&a[0]).map_err(verr),
        "parseFilter" => parse_filter(&arg(0)).map_err(verr),
        "scimError" => Ok(scim_error(a[0].as_u64().unwrap() as u16, a[1].as_str().unwrap(), a.get(2).cloned())),
        "scimListResponse" => Ok(scim_list_response(a[0].as_array().unwrap().clone(), a[1].clone(), a[2].clone())),
        "registry" => {
            let all = passport_registry(a[0].as_array().unwrap());
            let get = all.iter().find(|p| p["id"] == a[1]).cloned();
            Ok(json!({ "all": all, "has": get.is_some(), "get": get.unwrap_or(Value::Null) }))
        }
        "toEntraAgentPayload" => Ok(to_entra_agent_payload(&a[0])),
        "toOktaScimPayload" => Ok(to_okta_scim_payload(&a[0])),
        "pushToEntra" | "pushToOkta" => push(a[0].as_str().unwrap(), &a[1], a[2].as_str().unwrap(), "https://dir.example/scim/Agents", "TOK"),
        "pushProvision" => push("pushProvision", &a[0], a[1].as_str().unwrap(), "e", "t"),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn scim_vectors() {
    let cases = common::ref_cases("scim");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        // a lone surrogate cannot live in a Rust string (the loader turns it into a sentinel the reference never sees)
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let ok = match (c["out"].get("$throws").and_then(Value::as_str), &got) {
            // the reference's own value errors are exact; anything else (canonical-profile refusals) only requires a refusal
            (Some(m), Err(e)) => !(c["fn"] == "parseFilter" || c["fn"] == "scimToProvisioningRequest") || m == e,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
