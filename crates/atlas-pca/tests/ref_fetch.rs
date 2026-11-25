//! Differential replay of the runtime-neutral request guard (the reference's `withPCA` / `createPcaFetchGuard`): construction guards
//! and every refusal that happens before the verifier runs (no / undecodable / malformed proof, unknown grant, a resolver that
//! fails). The verifier's own reason text and challenge string belong to the core guard and differ per language, so only their SHAPE
//! is compared (status, whether the handler ran, `decision`, a `PCA realm="` challenge on a 401, content type, sorted body keys,
//! `error` being a string). Nothing is skipped; a reference throw only requires a refusal.
mod common;
use atlas_pca::fetch_adapter::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const AUD: &str = "rs_fetch";

fn options(resolve: &str) -> PcaFetchOptions {
    let throws = resolve == "throws";
    let resolve_grant: ResolveGrant = Arc::new(move |_: &str| -> Result<Option<Value>, String> {
        if throws {
            Err("store down".to_string())
        } else {
            Ok(None)
        }
    });
    PcaFetchOptions { audience: AUD.into(), resolve_grant: Some(resolve_grant), insecure_allow_unbound_operation: true, ..Default::default() }
}

fn handler(ran: Arc<AtomicBool>) -> PcaFetchHandler {
    Arc::new(move |_req: &FetchRequest, _ctx: &PcaContext| {
        ran.store(true, Ordering::SeqCst);
        FetchResponse { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: "{\"ok\":true}".into() }
    })
}

fn construct(kind: &str) -> Result<Value, String> {
    let mut o = options("null");
    match kind {
        "ok" => {}
        "noaudience" => o.audience = String::new(),
        "nooperation" => o.insecure_allow_unbound_operation = false,
        _ => return Err("unknown kind".into()),
    }
    with_pca(o, handler(Arc::new(AtomicBool::new(false)))).map(|_| json!({ "built": true }))
}

fn request(spec: &Value) -> Result<Value, String> {
    let ran = Arc::new(AtomicBool::new(false));
    let guarded = with_pca(options(spec["resolve"].as_str().ok_or("resolve")?), handler(ran.clone()))?;
    let mut req = FetchRequest::new("POST", "http://localhost/refunds");
    if let Some(h) = spec.get("headers").and_then(Value::as_object) {
        req.headers = h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect();
    }
    req.body = spec.get("body").and_then(Value::as_str).map(|b| b.as_bytes().to_vec());
    let res = guarded.handle(&req);
    let body: Option<Value> = atlas_pca::serde_json::from_str(&res.body).ok();
    let www = res.header("www-authenticate");
    let mut keys: Vec<String> = body.as_ref().and_then(Value::as_object).map(|o| o.keys().cloned().collect()).unwrap_or_default();
    keys.sort();
    let challenge = if res.status == 401 { json!(www.is_some_and(|w| w.starts_with("PCA realm=\""))) } else { Value::Null };
    let body_keys = if body.as_ref().is_some_and(Value::is_object) { json!(keys) } else { Value::Null };
    Ok(json!({
        "status": res.status,
        "handlerRan": ran.load(Ordering::SeqCst),
        "decision": body.as_ref().and_then(|b| b.get("decision")).cloned().unwrap_or(Value::Null),
        "challenge": challenge,
        "contentType": res.header("content-type"),
        "bodyKeys": body_keys,
        "errorIsString": body.as_ref().and_then(|b| b.get("error")).is_some_and(Value::is_string),
    }))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "constructScenario" => construct(a[0].as_str().ok_or("kind")?),
        "requestScenario" => request(&a[0]),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn fetch_vectors() {
    let cases = common::ref_cases("fetch");
    let mut bad = Vec::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
