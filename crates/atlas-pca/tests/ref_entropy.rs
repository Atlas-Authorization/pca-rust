//! Differential replay of the entropy module against the TypeScript reference (test-data/ref-entropy.json.gz, 562 cases): the
//! cutoffs and health tests, the response parsers, the HKDF combiner, `secure_seed` and the key-pair helper with the local CSPRNG,
//! the QRNG source and the error hook INJECTED by each case, and the HTTP source over an injected transport. Refusal messages that
//! belong to the module are compared exactly; a reference refusal that is JavaScript runtime text is only required to be a
//! refusal. An argument of a kind this typed API cannot receive (a string or `null` where bytes or a count are expected) is mapped
//! by the harness to the value that draws the reference's refusal. An unknown function fails the test.
mod common;
use atlas_pca::bond_store::num;
use atlas_pca::entropy::*;
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

const OWN: [&str; 4] = ["QRNG", "HttpQrngSource", "mixEntropy", "secureSeed"];

fn bytes(v: &Value) -> Option<Vec<u8>> {
    atlas_pca::decode_b64u_strict(v.get("$bytes")?.as_str()?, None)
}

fn b64(b: &[u8]) -> Value {
    json!({"$bytes": atlas_pca::kem::encode_hybrid_public_key(b)})
}

/// A JSON number or `{"$num": "NaN" | "Infinity" | "-Infinity"}`; anything else is not a number (NaN draws the reference's refusal).
fn number(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        Some(_) => f64::NAN,
        None => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

fn opt_number(o: &Value, k: &str) -> Option<f64> {
    o.get(k).map(number)
}

fn out_number(f: f64) -> Value {
    if f.is_nan() {
        json!({"$num": "NaN"})
    } else if f.is_infinite() {
        json!({"$num": if f > 0.0 { "Infinity" } else { "-Infinity" }})
    } else {
        num(f)
    }
}

fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

fn thrown(e: &EntropyError) -> Value {
    json!({"$throws": e.message})
}

fn thrown_full(e: &EntropyError) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("$throws".into(), json!(e.message));
    m.insert("cls".into(), json!(e.class));
    if let Some(c) = &e.code {
        m.insert("code".into(), json!(c));
    }
    m
}

fn err_rec(e: &EntropyError) -> Value {
    let mut m = json!({"cls": e.class, "message": e.message});
    if let Some(c) = &e.code {
        m["code"] = json!(c);
    }
    m
}

fn health_opts(o: &Value) -> HealthTestOptions {
    HealthTestOptions { h: opt_number(o, "h"), window: opt_number(o, "window") }
}

fn refused() -> Value {
    json!({"$throws": "refused"})
}

struct Source<'a> {
    spec: &'a Value,
    requests: RefCell<Vec<usize>>,
}

impl QrngSource for Source<'_> {
    fn name(&self) -> String {
        self.spec["name"].as_str().unwrap_or("").to_string()
    }
    fn fetch(&self, n: usize) -> Result<Vec<u8>, EntropyError> {
        self.requests.borrow_mut().push(n);
        let message = self.spec["message"].as_str().unwrap_or("").to_string();
        match self.spec["kind"].as_str().unwrap_or("") {
            "bytes" => Ok(bytes(&self.spec["value"]).expect("source bytes")),
            // a bare string rejection: the hook sees its text, and no error class
            "rejectString" => Err(EntropyError { class: "string", code: None, message }),
            "nonbytes" => Err(EntropyError::plain(format!("QRNG: source returned non-bytes, expected {n}"))),
            _ => Err(EntropyError::plain(message)),
        }
    }
}

fn seed_run(o: &Value, keypair: bool) -> Value {
    let source = o.get("source").filter(|s| s.is_object()).map(|spec| Source { spec, requests: RefCell::new(Vec::new()) });
    let locals: RefCell<Vec<usize>> = RefCell::new(Vec::new());
    let errors: RefCell<Vec<Value>> = RefCell::new(Vec::new());
    let local_spec = o.get("local");
    let local = |n: usize| -> Result<Vec<u8>, EntropyError> {
        locals.borrow_mut().push(n);
        let spec = local_spec.expect("local spec");
        match spec["kind"].as_str().unwrap_or("") {
            "fixed" => Ok(bytes(&spec["value"]).expect("local bytes")),
            "throw" => Err(EntropyError::plain(spec["message"].as_str().unwrap_or(""))),
            // not bytes at all: an answer of the wrong length stands in for it
            _ => Ok(vec![0u8; n + 1]),
        }
    };
    let hook_kind = o.get("hook").and_then(Value::as_str).unwrap_or("none");
    let hook = |e: &EntropyError| {
        errors.borrow_mut().push(err_rec(e));
        if hook_kind == "throw" {
            panic!("hook boom");
        }
    };
    let opts = SecureSeedOptions {
        length: opt_number(o, "length"),
        source: source.as_ref().map(|s| s as &dyn QrngSource),
        quantum_bytes: opt_number(o, "quantumBytes"),
        local_bytes: opt_number(o, "localBytes"),
        context: o.get("context").and_then(Value::as_str).map(|c| c.replace(common::LONE, "\u{fffd}")),
        require_quantum: o.get("requireQuantum") == Some(&Value::Bool(true)),
        health_test: o.get("healthTest").filter(|h| h.is_object()).map(health_opts),
        skip_health_test: o.get("healthTest") == Some(&Value::Bool(false)),
        on_qrng_error: if hook_kind == "none" { None } else { Some(&hook) },
        random_bytes: if local_spec.is_some() { Some(&local) } else { None },
    };
    let mut out = if keypair {
        match generate_key_pair_with_entropy(&opts) {
            Ok(k) => json!({"publicKey": b64(&k.public_key), "secretKeySha256": hex(&Sha256::digest(&k.secret_key[..])), "usedQuantum": k.used_quantum}),
            Err(e) => Value::Object(thrown_full(&e)),
        }
    } else {
        match secure_seed(&opts) {
            Ok(r) => json!({"seed": b64(&r.seed), "usedQuantum": r.used_quantum, "quantumByteCount": r.quantum_byte_count, "source": r.source}),
            Err(e) => Value::Object(thrown_full(&e)),
        }
    };
    out["qrngErrors"] = Value::Array(errors.borrow().clone());
    out["localRequested"] = locals.borrow().first().map_or(Value::Null, |n| json!(n));
    out["requests"] = json!(source.as_ref().map(|s| s.requests.borrow().clone()).unwrap_or_default());
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn text_of(o: &Value, k: &str) -> Option<String> {
    o.get(k).and_then(Value::as_str).map(str::to_string)
}

fn http_run(cfg: &Value, n: &Value, tr: &Value) -> Value {
    let log: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let (sink, spec) = (log.clone(), tr.clone());
    let transport = move |url: &str, headers: &[(String, String)], _timeout_ms: u64| -> Result<QrngHttpResponse, TransportFailure> {
        let hs: Map<String, Value> = headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        sink.lock().unwrap().push(json!({"url": url, "headers": hs, "redirect": "error", "signal": true}));
        let status = spec["status"].as_i64().unwrap_or(200);
        let ok = spec["ok"].as_bool().unwrap_or((200..=299).contains(&status));
        let answer = |body| Ok(QrngHttpResponse { ok, status, body });
        let message = spec["message"].as_str().unwrap_or("").to_string();
        match spec["kind"].as_str().unwrap_or("") {
            "json" => answer(Ok(QrngBody::Json(spec["body"].clone()))),
            "text" => answer(Ok(QrngBody::Text(spec["text"].as_str().unwrap_or("").to_string()))),
            "jsonThrows" => answer(Err("bad json".to_string())),
            "textThrows" => answer(Err("read failed".to_string())),
            "throw" => Err(TransportFailure::Failed(message)),
            "throwString" => Err(TransportFailure::Unknown),
            "hang" => Err(TransportFailure::Timeout),
            other => panic!("bad transport spec {other}"),
        }
    };
    let suffix = cfg.get("buildUrl").map(|b| b["suffix"].as_str().unwrap_or("").to_string());
    let config = HttpQrngConfig {
        // a url that is not a string is no url
        url: text_of(cfg, "url").unwrap_or_default(),
        api_key: text_of(cfg, "apiKey"),
        api_key_header: text_of(cfg, "apiKeyHeader"),
        format: text_of(cfg, "format"),
        timeout_ms: opt_number(cfg, "timeoutMs"),
        max_bytes: opt_number(cfg, "maxBytes"),
        length_param: text_of(cfg, "lengthParam"),
        extra_params: cfg.get("extraParams").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| (k.clone(), js_string(v))).collect()).unwrap_or_default(),
        build_url: suffix.map(|s| Box::new(move |base: &str, k: usize| format!("{base}/{k}{s}")) as Box<QrngUrlBuilder>),
        allow_insecure_loopback: cfg.get("allowInsecureLoopback") == Some(&Value::Bool(true)),
        transport: if tr["kind"] == "none" { None } else { Some(Box::new(transport) as Box<QrngTransport>) },
    };
    let src = match HttpQrngSource::new(config) {
        Ok(s) => s,
        Err(e) => return Value::Object(thrown_full(&e)),
    };
    // a count that is not a number at all (a string, null) draws the reference's own refusal of it
    let fetched = if n.is_number() || n.get("$num").is_some() {
        src.fetch_num(number(n))
    } else {
        Err(EntropyError { class: "TypeError", code: None, message: format!("QRNG: numBytes must be a positive integer, got {}", js_string(n)) })
    };
    let requests = Value::Array(log.lock().unwrap().clone());
    match fetched {
        Ok(b) => json!({"name": src.name(), "bytes": b64(&b), "requests": requests}),
        Err(e) => {
            let key = text_of(cfg, "apiKey").filter(|k| !k.is_empty());
            let mut m = thrown_full(&e);
            m.insert("name".into(), json!(src.name()));
            m.insert("requests".into(), requests);
            m.insert("leaksKey".into(), json!(key.is_some_and(|k| e.message.contains(&k))));
            Value::Object(m)
        }
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    let null = Value::Null;
    let arg = |i: usize| a.get(i).unwrap_or(&null);
    match f {
        "constants" => json!({
            "MAX_HKDF_OUTPUT": MAX_HKDF_OUTPUT, "MIN_LOCAL_BYTES": MIN_LOCAL_BYTES, "DEFAULT_SEED_BYTES": DEFAULT_SEED_BYTES,
            "DEFAULT_MAX_QRNG_BYTES": DEFAULT_MAX_QRNG_BYTES, "DEFAULT_TIMEOUT_MS": DEFAULT_TIMEOUT_MS,
        }),
        "repetitionCutoff" => out_number(repetition_cutoff(number(arg(0)))),
        "proportionCutoff" => out_number(proportion_cutoff(number(arg(0)), number(arg(1)))),
        "healthTestBytes" => match (bytes(arg(0)), a.len() > 1 && !arg(1).is_object()) {
            (Some(b), false) => {
                let v = health_test_bytes(&b, &health_opts(arg(1)));
                let mut o = json!({"ok": v.ok});
                if let Some(t) = v.test {
                    o["test"] = json!(t);
                }
                o
            }
            _ => refused(),
        },
        "parseAnuUint8" => parse_anu_uint8(arg(0)).map_or_else(|e| thrown(&e), |b| b64(&b)),
        "parseHex" => match arg(0).as_str() {
            Some(t) => parse_hex(t).map_or_else(|e| thrown(&e), |b| b64(&b)),
            None => json!({"$throws": "QRNG: malformed hex payload"}),
        },
        "parseBase64" => parse_base64(&js_string(arg(0))).map_or_else(|e| thrown(&e), |b| b64(&b)),
        "mixEntropy" => {
            let (local, quantum) = (bytes(arg(0)), bytes(arg(1)));
            let Some(local) = local else { return json!({"$throws": "mixEntropy: `local` must be a Uint8Array"}) };
            let Some(quantum) = quantum else { return json!({"$throws": "mixEntropy: `quantum` must be a Uint8Array"}) };
            if a.len() > 2 && !arg(2).is_object() {
                return refused();
            }
            // a null context is `null.length` in the reference: the typed API has no null, so it is refused here
            if arg(2).get("context").is_some_and(Value::is_null) {
                return json!({"$throws": "Cannot read properties of null (reading 'length')"});
            }
            let opts = MixOptions { length: arg(2).get("length").filter(|v| !v.is_null()).map(number), // `opts.length ?? default`: null is absent
                 context: text_of(arg(2), "context").map(|c| c.replace(common::LONE, "\u{fffd}")) };
            mix_entropy(&local, &quantum, &opts).map_or_else(|e| thrown(&e), |b| b64(&b))
        }
        "secureSeed" => seed_run(arg(0), false),
        "generateKeyPairWithEntropy" => seed_run(arg(0), true),
        "httpQrng" => http_run(arg(0), arg(1), arg(2)),
        "nullQrng" | "unavailableSource" => {
            let s = if f == "nullQrng" { NullQrngSource::new(arg(0).as_str()) } else { unavailable_source(arg(0).as_str()) };
            let e = s.fetch(arg(1).as_u64().unwrap_or(0) as usize).expect_err("a null source never answers");
            json!({"name": s.name(), "$throws": e.message})
        }
        "entropyError" => {
            let e = EntropyError::new(arg(0).as_str().unwrap_or(""), arg(1).as_str().unwrap_or(""));
            json!({"name": e.class, "code": e.code, "message": e.message, "isError": true})
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

/// Blank what is JavaScript runtime text in a reference refusal: a message outside this module, and its error class.
fn comparable(mut v: Value, reference: &Value) -> Value {
    let own = reference.get("$throws").and_then(Value::as_str).is_some_and(|m| OWN.iter().any(|p| m.starts_with(p)));
    if reference.get("$throws").is_some() && !own && v.get("$throws").is_some() {
        v["$throws"] = json!("*");
        if v.get("cls").is_some() {
            v["cls"] = json!("*");
        }
        if let Some(o) = v.as_object_mut() {
            o.remove("code");
        }
    }
    v
}

#[test]
fn the_entropy_module_matches_the_reference() {
    let cases = common::ref_cases("entropy");
    assert_eq!(cases.len(), 562, "case total");
    let mut bad = Vec::new();
    for c in &cases {
        let args = c["args"].as_array().cloned().unwrap_or_default();
        let name = c["fn"].as_str().unwrap_or("");
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(name, &args))).unwrap_or_else(|_| json!({"$panic": true}));
        let (want, got) = (comparable(c["out"].clone(), &c["out"]), comparable(got, &c["out"]));
        if atlas_pca::canonicalize(&want) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], want, got));
        }
    }
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn the_platform_csprng_seeds_differ_and_a_required_source_fails_closed() {
    let (a, b) = (secure_seed(&SecureSeedOptions::default()).unwrap(), secure_seed(&SecureSeedOptions::default()).unwrap());
    assert_eq!((a.seed.len(), a.used_quantum, a.source.clone()), (32, false, None));
    assert_ne!(a.seed, b.seed);
    let none = unavailable_source(None);
    let e = secure_seed(&SecureSeedOptions { source: Some(&none), require_quantum: true, ..Default::default() }).err().expect("refused");
    assert_eq!((e.class, e.code.as_deref()), ("EntropyError", Some("quantum_required")));
    let fallback = secure_seed(&SecureSeedOptions { source: Some(&none), ..Default::default() }).unwrap();
    assert_eq!((fallback.used_quantum, fallback.source.as_deref()), (false, Some("null-qrng")));
}
