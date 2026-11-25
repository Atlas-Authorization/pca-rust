//! Differential replay of the outbound token vault (atlas_pca::connect: oauth_scope caveats, token refresh, the proxy-mode request
//! extractor, signed release receipts, TokenVault release and proxy scenarios) against the TypeScript reference
//! (test-data/ref-connect-v2.json.gz, the corrected generator connect-v2.mts). A reference throw requires a refusal (and, when it
//! carries a vault `code`, the same code).
//! Skipped (counted, must stay under 10%): cases with a lone surrogate (a Rust string cannot hold one). decryptRecord replays
//! the envelope-encrypted store (atlas_pca::connect_encrypted).
mod common;
use atlas_pca::connect::*;
use atlas_pca::connect_encrypted::{EncryptedConnectionStore, LocalKeyWrapper};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{MemoryStateStore, StateStore};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn seed32(b64: &str) -> [u8; 32] {
    let v = common::b64d(b64);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn plain(e: String) -> VaultError {
    VaultError::plain(e)
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn transport(script: Option<&Value>, log: Arc<Mutex<Vec<Value>>>) -> Option<FetchFn> {
    let script: Vec<Value> = script.and_then(Value::as_array)?.clone();
    if script.is_empty() {
        return None;
    }
    let n = Arc::new(AtomicUsize::new(0));
    Some(Arc::new(move |url: &str, init: &Value| {
        log.lock().unwrap().push(json!({ "url": url, "method": init["method"], "headers": init["headers"], "body": init["body"] }));
        let i = n.fetch_add(1, Ordering::SeqCst).min(script.len() - 1);
        let r = &script[i];
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

fn refresh(c: &Value) -> Value {
    let log = Arc::new(Mutex::new(vec![]));
    let fetch = transport(c.get("script"), log.clone());
    let r = refresh_connection(
        &c["connection"],
        c.get("config"),
        c["refreshToken"].as_str().unwrap_or(""),
        &str_list(&c["requested"]),
        fetch.as_ref(),
        c["now"].as_f64().unwrap_or(0.0),
        c["defaultTokenLifetimeMs"].as_f64().unwrap_or(0.0),
    );
    let calls = Value::Array(log.lock().unwrap().clone());
    match r {
        Ok(v) => json!({ "ok": true, "value": v, "calls": calls }),
        Err(e) => {
            let mut j = e.to_json();
            j["calls"] = calls;
            j
        }
    }
}

fn vault(s: &Value) -> Value {
    let now = Arc::new(AtomicI64::new(s["nowMs"].as_i64().unwrap()));
    let store = Arc::new(InMemoryConnectionStore::new());
    let fetch_log = Arc::new(Mutex::new(vec![]));
    let proxy_log = Arc::new(Mutex::new(vec![]));
    let receipts = Arc::new(Mutex::new(vec![]));
    let empty = json!({});
    let op = s.get("opts").filter(|v| v.is_object()).unwrap_or(&empty);
    let truthy = |k: &str| op.get(k).is_some_and(|v| !matches!(v, Value::Null | Value::Bool(false)));

    let mut o = VaultOptions { strict: Some(false), ..VaultOptions::default() };
    o.store = Some(store.clone());
    let n2 = now.clone();
    o.now = Some(Arc::new(move || n2.load(Ordering::SeqCst)));
    o.fetch = transport(s.get("fetchScript"), fetch_log.clone());
    o.insecure_bearer_release = truthy("insecureBearerRelease");
    o.insecure_skip_plan_root_check = truthy("insecureSkipPlanRootCheck");
    if let Some(r) = op.get("authorizedPlanRoots").filter(|v| v.is_array()) {
        o.authorized_plan_roots = Some(str_list(r));
    }
    o.audience = op.get("audience").and_then(Value::as_str).map(String::from);
    o.expiry_leeway_ms = op.get("expiryLeewayMs").and_then(Value::as_f64);
    o.default_token_lifetime_ms = op.get("defaultTokenLifetimeMs").and_then(Value::as_f64);
    o.require_action_binding = op.get("requireActionBinding").and_then(Value::as_bool);
    o.default_connection_id = op.get("defaultConnectionId").and_then(Value::as_str).map(String::from);
    if let Some(p) = op.get("providers").and_then(Value::as_object) {
        o.providers = p.clone();
    }
    if let Some(p) = op.get("pqPins").and_then(Value::as_object) {
        o.pq_pins = Some(p.iter().filter_map(|(k, v)| v.as_str().map(|x| (k.clone(), x.to_string()))).collect::<HashMap<_, _>>());
    }
    o.max_proxy_response_bytes = op.get("maxProxyResponseBytes").and_then(Value::as_f64);
    if let Some(u) = op.get("useVerb") {
        o.use_verb = match u.as_str() {
            Some(v) => UseVerb::Verb(v.to_string()),
            None => UseVerb::Skip,
        };
    }
    if truthy("replay") {
        o.replay = Some(Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>);
    }
    if let Some(r) = op.get("revoked").and_then(Value::as_str) {
        let r = r.to_string();
        o.is_revoked = Some(Arc::new(move |_p: &Value| if r == "throws" { Err("src down".to_string()) } else { Ok(r == "yes") }));
    }
    if let Some(table) = s.get("actionsTable").filter(|t| t.is_object()) {
        let table = table.clone();
        o.actions = Some(Arc::new(move |verb: &str| {
            let t = table.get(verb)?;
            Some(ActionDef {
                verb: t["verb"].as_str().unwrap_or("").to_string(),
                def_digest: t["def_digest"].clone(),
                confirmed: t["confirmed"].as_bool() == Some(true),
                upstream: t["upstream"].clone(),
                extract: t.get("extract").filter(|e| e.is_object()).and_then(|e| http_extractor(e).ok()),
            })
        }));
    }
    if truthy("proxy") {
        let script: Vec<Value> = s["proxyScript"].as_array().cloned().unwrap_or_default();
        let pi = Arc::new(AtomicUsize::new(0));
        let log = proxy_log.clone();
        o.proxy_fetch = Some(Arc::new(move |req: &Value| {
            log.lock().unwrap().push(json!({ "method": req["method"], "url": req["url"], "headers": req["headers"], "body": req.get("body").cloned().unwrap_or(Value::Null), "redirect": req["redirect"] }));
            let r = &script[pi.fetch_add(1, Ordering::SeqCst).min(script.len() - 1)];
            if r.get("throws").is_some_and(|t| !matches!(t, Value::Null | Value::Bool(false))) {
                return Err("net".to_string());
            }
            Ok(json!({ "status": r["status"], "headers": r["headers"], "body": r["body"] }))
        }));
    }
    if let Some(seed) = op.get("receiptSeed").and_then(Value::as_str) {
        let log = receipts.clone();
        let failing = truthy("failingSink");
        o.receipts = Some(ReceiptConfig {
            secret_key: seed32(seed),
            sink: Some(Arc::new(move |r: &Value| {
                log.lock().unwrap().push(r.clone());
                if failing {
                    Err("sink".to_string())
                } else {
                    Ok(())
                }
            })),
        });
    }
    let v = TokenVault::new(o).unwrap();
    let mut results = vec![];
    let mut rec = |r: Result<Value, VaultError>| {
        results.push(match r {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(e) => e.to_json(),
        })
    };
    for c in s["calls"].as_array().unwrap() {
        match c["op"].as_str().unwrap() {
            "put" => rec(v.put_connection(&c["args"])),
            "get" => rec(v.get_connection_token(&c["pcActn"], &c["args"])),
            "proxy" => rec(v.proxy_call(&c["pcActn"], &c["request"], &c["args"])),
            "delete" => rec(v
                .delete_connection(c["agentId"].as_str().unwrap(), c["provider"].as_str().unwrap(), c.get("connectionId").and_then(Value::as_str))
                .map(|_| Value::Null)),
            "now" => now.store(c["now"].as_i64().unwrap(), Ordering::SeqCst),
            f => panic!("unknown op {f}"),
        }
    }
    let watched: Vec<Value> = s
        .get("watch")
        .and_then(Value::as_array)
        .map(|w| w.iter().map(|k| store.get(k).unwrap().map_or(Value::Null, |c| clone_connection(&c))).collect())
        .unwrap_or_default();
    json!({ "results": results, "store": watched, "receipts": *receipts.lock().unwrap(), "fetchCalls": *fetch_log.lock().unwrap(), "proxyCalls": *proxy_log.lock().unwrap() })
}

fn run(f: &str, a: &[Value]) -> Result<Value, VaultError> {
    match f {
        "oauthScopeCaveat" => Ok(oauth_scope_caveat(a[0].as_str().unwrap(), &str_list(&a[1]))),
        "isOAuthScopeCaveat" => Ok(json!(is_oauth_scope_caveat(&a[0]))),
        "grantedOAuthScopes" => granted_oauth_scopes(&a[0], a[1].as_str().unwrap()).map(|r| match r {
            None => Value::Null,
            Some(mut v) => {
                v.sort_by(|x, y| x.encode_utf16().cmp(y.encode_utf16()));
                json!(v)
            }
        }),
        "httpExtractor" => http_extractor(&a[0]).and_then(|e| e(&a[1])),
        "checkProxyHeaders" => check_proxy_headers(Some(&a[0]), &str_list(&a[1])).map(Value::Object),
        "DEFAULT_PROXY_HEADERS" => Ok(json!(DEFAULT_PROXY_HEADERS)),
        "outboundRequestDigest" => outbound_request_digest(a[0].as_str().unwrap(), a[1].as_str().unwrap(), &a[2], a[3].as_str()).map(Value::String),
        "signReleaseReceipt" => sign_release_receipt(&a[0], &seed32(a[1].as_str().unwrap())),
        "verifyReleaseReceipt" => Ok(json!(verify_release_receipt(&a[0], a[1].as_str().unwrap_or("")))),
        "receiptActionDigest" => receipt_action_digest(&a[0]).map(Value::String),
        "refreshConnection" => Ok(refresh(&a[0])),
        "vault" => Ok(vault(&a[0])),
        f => panic!("unknown fn {f}"),
    }
}

/// EncryptedConnectionStore.get over an inner store holding the given sealed record.
fn decrypt_record(c: &Value) -> Value {
    let ring: Vec<(String, Vec<u8>)> = c["ring"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), common::b64d(v.as_str().unwrap()))).collect();
    let pairs: Vec<(&str, &[u8])> = ring.iter().map(|(k, v)| (k.as_str(), v.as_slice())).collect();
    let wrapper = Arc::new(LocalKeyWrapper::new(&pairs, c["active"].as_str().unwrap()).unwrap());
    let inner = Arc::new(InMemoryConnectionStore::new());
    inner.set(&c["record"]).unwrap();
    let store = EncryptedConnectionStore::new(inner, wrapper);
    match store.get(&c["key"]) {
        Ok(r) => json!({ "ok": true, "value": r.unwrap_or(Value::Null) }),
        Err(e) => {
            let mut v = e.to_json();
            v["ok"] = json!(false);
            v
        }
    }
}

#[test]
fn connect_vectors() {
    let cases = common::ref_cases_seeded("connect-v2");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        if f == "decryptRecord" {
            let got = decrypt_record(&c["args"][0]);
            if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
                bad.push(format!("{}\n  want {}\n  got  {got}", c["name"], c["out"]));
            }
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err(plain("panic".into())));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(e)) => match c["out"].get("code").and_then(Value::as_str) {
                Some(code) if !code.starts_with("ERR_") && !e.code.is_empty() => code == e.code,
                _ => true,
            },
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
