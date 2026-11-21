//! Differential replay of the SIEM exporters (OCSF / CEF / ECS mapping, formatDecision, scrubError, httpSink / consoleSink,
//! exportBatch) against the TypeScript reference (test-data/ref-siem.json.gz). A reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate, and formatDecision calls whose format is not a string
//! (the Rust API takes &str). exportBatch messages that quote a host-language TypeError for a hostile record are not compared.
mod common;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::siem::*;
use std::sync::{Arc, Mutex};

fn opts(a: &[Value]) -> Option<&Value> {
    a.get(1).filter(|v| !v.is_null())
}

fn result_value(v: Value) -> Value {
    v
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "toOcsfEvent" => to_ocsf_event(&a[0], opts(a), None),
        "toCef" => to_cef(&a[0], opts(a), None).map(Value::String),
        "toEcs" => to_ecs(&a[0], opts(a), None),
        "formatDecision" => {
            let fmt = a[1].as_str().ok_or("skip")?;
            format_decision(&a[0], fmt, a.get(2).filter(|v| !v.is_null()), None)
        }
        "scrubError" => Ok(Value::String(scrub_error(&a[0]))),
        "httpSinkScenario" => Ok(http_scenario(&a[0])),
        "consoleSinkScenario" => Ok(console_scenario(&a[0])),
        "exportScenario" => Ok(export_scenario(&a[0])),
        f => panic!("unknown fn {f}"),
    }
}

fn http_scenario(s: &Value) -> Value {
    let mode = s["mode"].as_str().unwrap().to_string();
    let format = s["format"].as_str().unwrap().to_string();
    let calls: Arc<Mutex<Vec<(String, FetchInit)>>> = Arc::new(Mutex::new(vec![]));
    let calls2 = calls.clone();
    let fetch: FetchFn = Arc::new(move |url, init| {
        calls2.lock().unwrap().push((url.to_string(), init.clone()));
        if mode == "ok" {
            return Ok(FetchResponse { ok: true, status: 200, status_text: None });
        }
        if let Some(rest) = mode.strip_prefix("st:") {
            let mut p = rest.splitn(2, ':');
            let status: i64 = p.next().unwrap().parse().unwrap();
            return Ok(FetchResponse { ok: false, status, status_text: p.next().map(String::from) });
        }
        if let Some(m) = mode.strip_prefix("throws:") {
            return Err(m.to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(500)); // hang: outlive the sink's timeout
        Ok(FetchResponse { ok: true, status: 200, status_text: None })
    });
    let mut o = HttpSinkOptions::default();
    if let Some(h) = s.get("headers").and_then(Value::as_object) {
        o.headers = h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
    }
    o.content_type = s.get("contentType").and_then(Value::as_str).map(String::from);
    o.name = s.get("name").and_then(Value::as_str).map(String::from);
    o.timeout_ms = s.get("timeoutMs").and_then(Value::as_f64);
    let sink = http_sink(s["url"].as_str().unwrap(), &format, fetch, o);
    let events: Vec<Value> = s["events"].as_array().unwrap().iter().map(|r| format_decision(r, &format, None, None).unwrap()).collect();
    let res = (sink.deliver)(&events).unwrap();
    let mut out = Map::new();
    out.insert("name".into(), json!(sink.name));
    out.insert("format".into(), json!(sink.format));
    out.insert("result".into(), res);
    if let Some((url, init)) = calls.lock().unwrap().first() {
        let headers: Map<String, Value> = init.headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        out.insert("request".into(), json!({ "url": url, "method": init.method, "headers": headers, "body": init.body }));
    }
    Value::Object(out)
}

fn console_scenario(s: &Value) -> Value {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let lines2 = lines.clone();
    let throws = s.get("throws").and_then(Value::as_str).map(String::from);
    let logger: Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync> = Arc::new(move |l| {
        if let Some(t) = &throws {
            return Err(t.clone());
        }
        lines2.lock().unwrap().push(l.to_string());
        Ok(())
    });
    let sink = console_sink(s.get("format").and_then(Value::as_str), logger, s.get("name").and_then(Value::as_str));
    let events: Vec<Value> = s["records"].as_array().unwrap().iter().map(|r| format_decision(r, &sink.format, None, None).unwrap()).collect();
    let res = (sink.deliver)(&events).unwrap();
    json!({ "name": sink.name, "format": sink.format, "result": res, "lines": *lines.lock().unwrap() })
}

fn export_scenario(s: &Value) -> Value {
    let mode = s["sinkMode"].as_str().unwrap().to_string();
    let format = s["format"].as_str().unwrap().to_string();
    let delivered: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let d2 = delivered.clone();
    let deliver: DeliverFn = Arc::new(move |events: &[Value]| {
        for e in events {
            d2.lock().unwrap().push(e["line"].as_str().unwrap().to_string());
        }
        match mode.as_str() {
            "ok" => Ok(json!({ "ok": true })),
            "fail" => Ok(json!({ "ok": false, "error": "collector said no token=abcdef123" })),
            "failNoError" => Ok(json!({ "ok": false })),
            _ => Err("deliver exploded Bearer abcdefghij".to_string()),
        }
    });
    let sink = SiemSink { name: "s1".into(), format, deliver };
    let cb_throws = s["sinkMode"] == "throwsOnError" || s.get("onErrorThrows") == Some(&Value::Bool(true));
    let errors: Mutex<Vec<Value>> = Mutex::new(vec![]);
    let on_error = |m: &str, sink: &str, count: usize| {
        let m = if m.starts_with("record could not be serialized") { "record could not be serialized" } else { m };
        errors.lock().unwrap().push(json!({ "message": m, "sink": sink, "count": count }));
        if cb_throws {
            Err("cb".to_string())
        } else {
            Ok(())
        }
    };
    let records: Vec<Value> = s["records"].as_array().unwrap().clone();
    let res = export_batch(&records, &sink, Some(&on_error), s.get("serialize").filter(|v| !v.is_null()), None);
    json!({ "result": res, "errors": *errors.lock().unwrap(), "delivered": *delivered.lock().unwrap() })
}

/// Normalize the one message the reference words with its own runtime's TypeError.
fn norm(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(es) = v.get_mut("errors").and_then(Value::as_array_mut) {
        for e in es {
            if e["message"].as_str().is_some_and(|m| m.starts_with("record could not be serialized")) {
                e["message"] = json!("record could not be serialized");
            }
        }
    }
    v
}

#[test]
fn siem_vectors() {
    let cases = common::ref_cases("siem");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) || (f == "formatDecision" && !c["args"][1].is_string()) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&norm(&c["out"])) == atlas_pca::canonicalize(&norm(v)),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got.map(|v| result_value(v))));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
