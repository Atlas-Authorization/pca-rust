//! Differential replay of the OIDC bridge against the TypeScript reference (test-data/ref-oidc.json.gz): discovery, ID-token
//! verification across algorithms, the caching JWKS resolver and principal mapping.
//! A reference error with a `code` must be matched by code; its message is compared exactly when it is one of the package's
//! own texts (the JOSE library's internal invalid_token texts and the strict-JSON parser's detail are not); a JavaScript
//! runtime TypeError only requires a refusal.
mod common;
use atlas_pca::oidc::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const OWN: [&str; 8] =
    ["verifyIdToken:", "discoverOidc:", "createOidcJwks:", "oidcPrincipal:", "non-canonical compact JWS:", "id token", "could not fetch", "cannot compute"];
const OWN_CODES: [&str; 13] =
    ["config", "signature", "issuer", "audience", "expired", "issued_at", "not_before", "nonce", "azp", "at_hash", "c_hash", "keys", "claims"];

fn same(want: &Value, got: &Result<Value, OidcError>) -> bool {
    let Some(m) = want.get("$throws").and_then(Value::as_str) else {
        return got.as_ref().is_ok_and(|v| atlas_pca::canonicalize(want) == atlas_pca::canonicalize(v));
    };
    let Err(e) = got else { return false };
    let code = want.get("code").and_then(Value::as_str);
    if code.is_some_and(|c| c != e.code) {
        return false;
    }
    if m.starts_with("non-canonical compact JWS: bad-json") {
        return e.message.starts_with("non-canonical compact JWS: bad-json");
    }
    let own = OWN.iter().any(|p| m.starts_with(p)) && m != "id token verification failed" || code.is_some_and(|c| OWN_CODES.contains(&c));
    !own || m == e.message
}

type Urls = Arc<Mutex<Vec<String>>>;

/// The generator's fetch spec: a sequence of replies, the last one repeating.
fn mk_fetch(spec: &Value, urls: Option<Urls>) -> impl Fn(&str, Option<f64>) -> Result<HttpResponse, String> + Send + Sync {
    let replies = spec["responses"].as_array().cloned().unwrap_or_default();
    let i = AtomicUsize::new(0);
    move |url: &str, _t: Option<f64>| {
        if let Some(u) = &urls {
            u.lock().unwrap().push(url.to_string());
        }
        let r = &replies[i.fetch_add(1, Ordering::SeqCst).min(replies.len() - 1)];
        if r.get("throws") == Some(&json!(true)) {
            return Err("boom".into());
        }
        let headers = r
            .get("headers")
            .and_then(Value::as_object)
            .map(|h| h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
            .unwrap_or_default();
        Ok(HttpResponse { status: r["status"].as_u64().unwrap() as u16, headers, body: r.get("body").and_then(Value::as_str).unwrap_or("").to_string() })
    }
}

fn without(v: &Value, k: &str) -> Value {
    let mut m = v.as_object().cloned().unwrap_or_default();
    m.remove(k);
    Value::Object(m)
}

fn pick(j: &Value) -> Value {
    let mut m = Map::new();
    for k in ["kty", "crv", "x", "y", "n", "e"] {
        if let Some(v) = j.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Value::Object(m)
}

fn step(r: Result<Value, OidcError>) -> Value {
    match r {
        Ok(j) => json!({ "ok": pick(&j) }),
        Err(e) => json!({ "err": if e.code == "keys" { "keys" } else { "other" } }),
    }
}

fn header(v: &Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn verify(t: &Value, opts: &Value) -> Result<Value, OidcError> {
    let fetch = opts.get("fetch").filter(|f| f.is_object()).map(|f| mk_fetch(f, None));
    let fetch_ref = fetch.as_ref().map(|f| f as &dyn HttpFetch);
    let k = match opts.get("key") {
        None => return verify_id_token(t, opts, None, fetch_ref),
        Some(k) => k,
    };
    let local;
    let remote;
    let key = if let Some(b) = k.get("$bytes").and_then(Value::as_str).filter(|_| k.as_object().is_some_and(|m| m.len() == 1)) {
        OidcKey::Secret(common::b64d(b))
    } else if let Some(set) = k.get("jwks") {
        local = LocalJwkSet::new(set).map_err(|m| OidcError { code: "type_error".into(), message: m })?;
        OidcKey::Resolver(&local)
    } else if let Some(r) = k.get("resolver") {
        remote = create_oidc_jwks(&without(r, "fetch"), Some(Box::new(mk_fetch(&r["fetch"], None))), None)?;
        OidcKey::Resolver(&remote)
    } else {
        OidcKey::Jwk(k.clone())
    };
    verify_id_token(t, opts, Some(&key), fetch_ref)
}

fn jwks_sequence(s: &Value) -> Result<Value, OidcError> {
    let clock = Arc::new(AtomicU64::new(0f64.to_bits()));
    let fetches = Arc::new(AtomicUsize::new(0));
    let inner = mk_fetch(&s["fetch"], None);
    let n = fetches.clone();
    let fetch = move |u: &str, t: Option<f64>| {
        n.fetch_add(1, Ordering::SeqCst);
        inner(u, t)
    };
    let mut o = s.get("opts").and_then(Value::as_object).cloned().unwrap_or_default();
    match s.get("jwksUri") {
        Some(u) => o.insert("jwksUri".into(), u.clone()),
        None => o.remove("jwksUri"),
    };
    let c = clock.clone();
    let r = create_oidc_jwks(&Value::Object(o), Some(Box::new(fetch)), Some(Box::new(move || f64::from_bits(c.load(Ordering::SeqCst)))))?;
    let mut steps = Vec::new();
    for st in s["steps"].as_array().unwrap() {
        clock.store(st["atMs"].as_f64().unwrap().to_bits(), Ordering::SeqCst);
        steps.push(step(r.resolve(&header(&st["header"]))));
    }
    Ok(json!({ "steps": steps, "fetches": fetches.load(Ordering::SeqCst) }))
}

fn jwks_from_issuer(s: &Value) -> Result<Value, OidcError> {
    let urls: Urls = Arc::default();
    let opts = s.get("opts").cloned().unwrap_or(json!({}));
    let r = create_oidc_jwks_from_issuer(&s["issuer"], &opts, Some(Box::new(mk_fetch(&s["fetch"], Some(urls.clone())))), None)?;
    let out = step(r.resolve(&header(&s["header"])));
    let urls = urls.lock().unwrap().clone();
    Ok(json!({ "out": out, "urls": urls }))
}

fn discover_calls(issuer: &Value, opts: &Value) -> Result<Value, OidcError> {
    let urls: Urls = Arc::default();
    let f = mk_fetch(&opts["fetch"], Some(urls.clone()));
    let outcome = if discover_oidc(issuer, &without(opts, "fetch"), Some(&f)).is_ok() { "ok" } else { "error" };
    let urls = urls.lock().unwrap().clone();
    Ok(json!({ "urls": urls, "outcome": outcome }))
}

#[test]
fn oidc_vectors() {
    let cases = common::ref_cases("oidc");
    let mut bad = Vec::new();
    let none = Value::Null;
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let arg = |i: usize| a.get(i).unwrap_or(&none);
        let got: Result<Value, OidcError> = match c["fn"].as_str().unwrap() {
            "verifyIdToken" => verify(arg(0), arg(1)),
            "discoveryUrl" => discovery_url(arg(0)).map(Value::String),
            "discoverOidc" => {
                let o = arg(1);
                let f = o.get("fetch").filter(|f| f.is_object()).map(|f| mk_fetch(f, None));
                discover_oidc(arg(0), &if o.is_object() { without(o, "fetch") } else { o.clone() }, f.as_ref().map(|f| f as &dyn HttpFetch))
            }
            "discoverOidcCalls" => discover_calls(arg(0), arg(1)),
            "createOidcJwks" => jwks_sequence(arg(0)),
            "createOidcJwksFromIssuer" => jwks_from_issuer(arg(0)),
            "oidcPrincipal" => oidc_principal(arg(0), a.get(1)),
            "isOidcSubjectCaveat" => Ok(json!(is_oidc_subject_caveat(arg(0)))),
            "constants" => Ok(json!({
                "DEFAULT_ID_TOKEN_ALGS": DEFAULT_ID_TOKEN_ALGS,
                "DEFAULT_MAX_DISCOVERY_BYTES": DEFAULT_MAX_DISCOVERY_BYTES,
                "DEFAULT_JWKS_TIMEOUT_MS": DEFAULT_JWKS_TIMEOUT_MS as u64,
                "OIDC_SUBJECT_CAVEAT": OIDC_SUBJECT_CAVEAT,
            })),
            f => panic!("unknown fn {f}"),
        };
        if !same(&c["out"], &got) {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
