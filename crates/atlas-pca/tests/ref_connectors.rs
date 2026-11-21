//! Differential replay of the connector catalog (manifest validation and digests, the provider registry, authorize URL / PKCE /
//! URL variables, access-token placement, code exchange and refresh into the vault, manifest-to-vault-provider mapping) against the
//! TypeScript reference (test-data/ref-connectors.json.gz). Errors are compared as data (class name and message); a failure that
//! is not a connector error is the generic "Error".
//! Skipped (counted, must stay under 10%): cases with a lone surrogate (a Rust string cannot hold one).
mod common;
use atlas_pca::connect::*;
use atlas_pca::connectors::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn guard(r: Result<Value, ConnectorError>) -> Value {
    match r {
        Ok(v) => json!({ "ok": true, "value": v }),
        Err(e) => e.to_json(),
    }
}

fn with_reg(customs: &Value) -> ProviderRegistry {
    let mut r = create_default_registry();
    for m in customs.as_array().cloned().unwrap_or_default() {
        r.register(&m, None).unwrap();
    }
    r
}

fn transport(script: Option<&Value>, log: Arc<Mutex<Vec<Value>>>) -> Option<FetchFn> {
    let script: Vec<Value> = script.and_then(Value::as_array)?.clone();
    if script.is_empty() {
        return None;
    }
    let n = Arc::new(AtomicUsize::new(0));
    Some(Arc::new(move |url: &str, init: &Value| {
        log.lock().unwrap().push(json!({ "url": url, "method": init["method"], "headers": init["headers"], "body": init["body"] }));
        let r = &script[n.fetch_add(1, Ordering::SeqCst).min(script.len() - 1)];
        if let Some(t) = r.get("throws") {
            return Err(t.as_str().unwrap_or("").to_string());
        }
        let flag = |k: &str| r.get(k).and_then(Value::as_bool) == Some(true);
        Ok(FetchResponse {
            ok: r["ok"].as_bool().unwrap_or(false),
            status: r["status"].as_i64().unwrap_or(0),
            json: if flag("jsonThrows") { Err("bad json".into()) } else { Ok(r.get("json").cloned().unwrap_or(Value::Null)) },
            text: if flag("textThrows") { Err("bad text".into()) } else { Ok(r.get("text").and_then(Value::as_str).unwrap_or("").to_string()) },
        })
    }))
}

fn token_run(c: &Value, exchange: bool) -> Value {
    let log = Arc::new(Mutex::new(vec![]));
    let store = Arc::new(InMemoryConnectionStore::new());
    let now = c["now"].as_i64().unwrap();
    let vault = TokenVault::new(VaultOptions {
        strict: Some(false),
        insecure_skip_plan_root_check: true,
        store: Some(store.clone()),
        now: Some(Arc::new(move || now)),
        ..VaultOptions::default()
    })
    .unwrap();
    let bind = &c["bind"];
    let mut authority = Map::new();
    authority.insert("principal".into(), bind["principal"].clone());
    for k in ["scopes", "audience"] {
        if let Some(v) = bind.get(k) {
            authority.insert(k.into(), v.clone());
        }
    }
    let mut b = Map::new();
    b.insert("agentId".into(), bind["agentId"].clone());
    b.insert("authority".into(), Value::Object(authority));
    if let Some(cid) = bind.get("connectionId") {
        b.insert("connectionId".into(), cid.clone());
    }
    let mut args = c.as_object().unwrap().clone();
    for k in ["bind", "script", "customs"] {
        args.remove(k);
    }
    args.insert("bind".into(), Value::Object(b));
    let args = Value::Object(args);
    let fetch = transport(c.get("script"), log.clone());
    let reg = with_reg(c.get("customs").unwrap_or(&Value::Null));
    let r = if exchange { exchange_code(&args, &vault, fetch.as_ref(), Some(&reg)) } else { refresh(&args, &vault, fetch.as_ref(), Some(&reg)) };
    let result = guard(r);
    let key = json!({ "agentId": bind["agentId"], "provider": c["providerId"], "connectionId": bind.get("connectionId").cloned().unwrap_or(json!("default")) });
    let stored = store.get(&key).unwrap().map_or(Value::Null, |g| clone_connection(&g));
    json!({ "result": result, "fetchCalls": *log.lock().unwrap(), "stored": stored })
}

fn registry_scenario(s: &Value) -> Value {
    let mut r = if s.get("empty").and_then(Value::as_bool) == Some(true) { ProviderRegistry::new() } else { create_default_registry() };
    let mut out = vec![];
    for op in s["ops"].as_array().unwrap() {
        let id = op["id"].as_str().unwrap_or("");
        let res: Result<Value, ConnectorError> = match op["op"].as_str().unwrap() {
            "register" => r.register(&op["manifest"], op.get("opts")),
            "get" => Ok(r.get(id).unwrap_or(Value::Null)),
            "require" => r.require(id),
            "has" => Ok(json!(r.has(id))),
            "list" => Ok(Value::Array(r.list())),
            "ids" => Ok(json!(r.ids())),
            _ => Ok(json!(r.catalog_digest())),
        };
        out.push(guard(res));
    }
    Value::Array(out)
}

fn catalog() -> Value {
    json!({
        "ids": list_providers().iter().map(|m| m["id"].clone()).collect::<Vec<_>>(),
        "manifests": list_providers(),
        "digest": catalog_digest(None),
        "google": get_provider("google"),
        "nope": get_provider("nope"),
    })
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "validateManifest" => validate_manifest(&a[0]),
        "assertManifest" => guard(assert_manifest(&a[0])),
        "manifestDigest" => json!(manifest_digest(&a[0])),
        "catalog" => catalog(),
        "registry" => registry_scenario(&a[0]),
        "substituteVars" => guard(substitute_vars(a[0].as_str().unwrap(), a.get(1)).map(Value::String)),
        "pkceChallenge" => json!({ "ok": true, "value": pkce_challenge(a[0].as_str().unwrap(), a.get(1).and_then(Value::as_str).unwrap_or("S256")) }),
        "buildAuthorizeUrl" => {
            let reg = with_reg(a.get(2).unwrap_or(&Value::Null));
            guard(build_authorize_url(a[0].as_str().unwrap(), &a[1], Some(&reg)))
        }
        "applyAccessToken" => guard(apply_access_token(&a[0], a.get(1).unwrap_or(&Value::Null))),
        "manifestToProviderConfig" => guard(match get_provider(a[0].as_str().unwrap()) {
            Some(m) => manifest_to_provider_config(&m, &a[1]),
            None => Err(ConnectorError::plain("unknown provider")),
        }),
        "buildVaultProviders" => guard(build_vault_providers(&a[0], None)),
        "exchange" => token_run(&a[0], true),
        "refresh" => token_run(&a[0], false),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn connectors_vectors() {
    let cases = common::ref_cases("connectors");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| json!("panic"));
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
