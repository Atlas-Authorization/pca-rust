//! Differential replay of test-data/ref-attest-maa.json.gz (written by the TypeScript reference): the Azure MAA token-signing key trust
//! (JWKS evaluation over real public certificate sets and certificates forged from fixed seeds, the guarded certificate fetch over a
//! scripted transport, the rotation-safe trust store with signed re-pins and the release-signed built-in pins, the durable state adapter
//! and the multi-vantage corroboration). Every function of the corpus has a handler and the per-function totals are asserted. A reference
//! refusal must be a refusal here; a rejection reason that is library text (an OpenSSL `error:` message or a Node type error) is compared
//! by its prefix, every other reason exactly. The corpus stores long strings once in a top-level `blobs` table (`{"$blob": id}`).
mod common;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use atlas_pca::attest::allowlist::AllowlistKv;
use atlas_pca::attest::maa_keys::*;
use atlas_pca::attest::maa_pins::{builtin_maa_pins_issuer_id, builtin_maa_pins_issuer_keys, load_builtin_maa_pins, BUILTIN_CHAIN_LEAF_CN};
use atlas_pca::serde_json::{json, Map, Value};
use common::replay::{replay_cases, thrown};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn hydrate(x: &Value, blobs: &Map<String, Value>) -> Value {
    match x {
        Value::Array(a) => Value::Array(a.iter().map(|e| hydrate(e, blobs)).collect()),
        Value::Object(o) => {
            if o.len() == 1 {
                if let Some(id) = o.get("$blob").and_then(Value::as_str) {
                    return blobs.get(id).cloned().unwrap_or_else(|| panic!("unknown blob {id}"));
                }
            }
            Value::Object(o.iter().map(|(k, v)| (k.clone(), hydrate(v, blobs))).collect())
        }
        other => other.clone(),
    }
}

fn load() -> (Vec<Value>, Map<String, Value>) {
    let path = format!("{}/test-data/ref-attest-maa.json.gz", env!("CARGO_MANIFEST_DIR"));
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}: gzip failed");
    let doc: Value = serde_json::from_str(&common::sanitize_lone_surrogates(&String::from_utf8(o.stdout).expect("utf8"))).expect("parse");
    let blobs = doc["blobs"].as_object().expect("blobs").clone();
    let cases: Vec<Value> = doc["cases"].as_array().expect("cases").iter().map(|c| hydrate(c, &blobs)).collect();
    assert_eq!(cases.len() as u64, doc["count"].as_u64().unwrap(), "case count");
    (cases, blobs)
}

/// The scripted response a corpus step describes.
fn response_of(r: &Value) -> Result<MaaHttpResponse, String> {
    if let Some(e) = r.get("$throws") {
        return Err(text(e).to_string());
    }
    let body = if let Some(b) = r.get("bodyBytes") {
        common::b64d(text(&b["$bytes"]))
    } else if let Some(t) = r.get("body").and_then(|b| b.get("$text")) {
        text(t).as_bytes().to_vec()
    } else {
        match r.get("body") {
            Some(b) => serde_json::to_string(b).unwrap().into_bytes(),
            None => Vec::new(),
        }
    };
    Ok(MaaHttpResponse {
        status: r.get("status").and_then(Value::as_u64).unwrap_or(200) as u16,
        url: r.get("url").and_then(Value::as_str).map(String::from),
        content_length: r.get("contentLength").map(|c| c.to_string()),
        body,
    })
}

/// A transport that answers `steps[min(i, last)]` to the i-th request and logs each URL.
fn scripted(steps: Vec<Value>, log: Arc<Mutex<Vec<String>>>) -> Arc<MaaFetch> {
    let calls = Mutex::new(0usize);
    Arc::new(move |url: &str, init: &FetchInit| {
        log.lock().unwrap().push(format!("{url}{}", if init.redirect_error { " [redirect:error]" } else { "" }));
        let mut i = calls.lock().unwrap();
        let step = &steps[(*i).min(steps.len() - 1)];
        *i += 1;
        // a bare JWKS stands for a response with that body
        if step.get("keys").is_some() && step.get("body").is_none() {
            response_of(&json!({"body": step}))
        } else {
            response_of(step)
        }
    })
}

/// The durable key-value store of the corpus.
#[derive(Default)]
struct MemKv(Mutex<BTreeMap<String, Value>>);

impl AllowlistKv for MemKv {
    fn get(&self, key: &str) -> Option<Value> {
        self.0.lock().unwrap().get(key).cloned()
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Option<Value> {
        let mut m = self.0.lock().unwrap();
        if let Some(next) = f(m.get(key)) {
            m.insert(key.to_string(), next);
        }
        m.get(key).cloned()
    }
}

fn fetch_case(c: &Value) -> Value {
    let log = Arc::new(Mutex::new(Vec::new()));
    let fetch = scripted(vec![c["response"].clone()], log.clone());
    let opts = c.get("opts").cloned().unwrap_or(Value::Null);
    let r = fetch_maa_certs(text(&c["issuer"]), Some(&*fetch), opts["timeoutMs"].as_u64(), opts["maxBytes"].as_f64());
    let mut out = match r {
        Ok(j) => json!({"ok": true, "jwks": j}),
        Err(e) => json!({"ok": false, "error": e}),
    };
    out["requests"] = json!(log.lock().unwrap().clone());
    out
}

fn trust_case(sc: &Value) -> Value {
    let store = Arc::new(create_memory_maa_key_state_store(sc.get("initial").unwrap_or(&Value::Null)));
    let log = Arc::new(Mutex::new(Vec::new()));
    let fetch = scripted(sc["fetches"].as_array().unwrap().clone(), log.clone());
    let trust = match create_maa_key_trust(&sc["policy"], store.clone(), Some(fetch)) {
        Ok(t) => t,
        Err(e) => return thrown(e),
    };
    let results: Vec<Value> =
        sc["calls"].as_array().unwrap().iter().map(|c| trust.get_trust_anchors(text(&c["issuer"]), &c["nowMs"], c.get("repin"))).collect();
    json!({"results": results, "store": store.snapshot(), "fetches": log.lock().unwrap().clone()})
}

fn kv_case(c: &Value) -> Value {
    let store = durable_maa_key_state_store(MemKv::default());
    let results: Vec<Value> = c["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            if let Some(set) = s.get("set") {
                store.set(text(&set[0]), &set[1]);
                Value::Null
            } else {
                store.get(text(&s["get"])).unwrap_or(Value::Null)
            }
        })
        .collect();
    let snapshot: Map<String, Value> = store.0 .0.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    json!({"results": results, "kv": Value::Object(snapshot)})
}

fn build_case(c: &Value) -> Value {
    let store = Arc::new(create_memory_maa_key_state_store(&Value::Null));
    let fetch: Option<Arc<MaaFetch>> = if c["noFetch"] == json!(true) {
        None
    } else {
        Some(Arc::new(|_: &str, _: &FetchInit| Ok(MaaHttpResponse { status: 200, body: b"{}".to_vec(), ..Default::default() })))
    };
    match create_maa_key_trust(&c["policy"], store, fetch) {
        Ok(_) => json!({"built": true}),
        Err(e) => thrown(e),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "BUILTIN_CHAIN_LEAF_CN": BUILTIN_CHAIN_LEAF_CN,
            "BUILTIN_MAA_PINS_ISSUER_ID": builtin_maa_pins_issuer_id(),
            "BUILTIN_MAA_PINS_ISSUER_KEYS": builtin_maa_pins_issuer_keys(),
        }),
        "evaluateMaaJwks" => evaluate_maa_jwks(&a[0], text(&a[1]), &a[2], a[3].as_f64().unwrap()),
        "loadBuiltinMaaPins" => load_builtin_maa_pins(&a[0]["nowMs"], a[0].get("source")),
        "corroborate" => corroborate_maa_key_sets(&a[0], &a[1], &a[2]),
        "fetchCerts" => fetch_case(&a[0]),
        "trust" => trust_case(&a[0]),
        "kvStore" => kv_case(&a[0]),
        "buildTrust" => build_case(&a[0]),
        other => panic!("unhandled corpus function {other}"),
    }
}

/// A refusal is compared as a refusal; a reason that is library text (an OpenSSL message or a Node type error) by its prefix.
fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.contains_key("$throws") => json!({"$throws": true}),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| match (k.as_str(), x.as_str()) {
                    ("reason", Some(r)) if r.starts_with("error:") => (k.clone(), json!("error:")),
                    ("reason", Some(r)) if r.starts_with("The first argument") => (k.clone(), json!("The first argument")),
                    _ => (k.clone(), norm(x)),
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn run_norm(f: &str, a: &[Value]) -> Value {
    norm(&run(f, a))
}

#[test]
fn maa_replay() {
    let (mut cases, _blobs) = load();
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("evaluateMaaJwks", 92),
        ("trust", 60),
        ("fetchCerts", 36),
        ("loadBuiltinMaaPins", 32),
        ("corroborate", 26),
        ("buildTrust", 9),
        ("kvStore", 5),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    for c in cases.iter_mut() {
        let w = norm(&c["out"]);
        c["out"] = w;
    }
    replay_cases("attest-maa", cases, 261, 0, run_norm);
}
