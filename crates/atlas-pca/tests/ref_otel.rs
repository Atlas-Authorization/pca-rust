//! Differential replay of the OpenTelemetry instrumentation (redactSecrets, pcaSpanAttributes, instrumentGuard over scripted tracers,
//! meters and guards) against the TypeScript reference (test-data/ref-otel.json.gz). The tracer / meter / guard are rebuilt from the
//! corpus' declarative scenario (mode strings choose where the exporter throws); the event log is compared in call order. The error
//! NAME of a recorded exception is not compared (the Rust span has no name to set). A reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate (no Rust string). Nothing else is skipped.
mod common;
use atlas_pca::otel::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<Value>>>;

fn boom() -> Result<(), String> {
    Err("exporter boom".to_string())
}

fn throw_if(cond: bool) -> Result<(), String> {
    if cond {
        boom()
    } else {
        Ok(())
    }
}

struct Span {
    log: Log,
    mode: String,
}

impl OtelSpan for Span {
    fn set_attribute(&self, k: &str, v: &Value) -> Result<(), String> {
        self.log.lock().unwrap().push(json!({ "ev": "setAttribute", "k": k, "v": v }));
        throw_if(self.mode == "attrThrows")
    }
    fn set_status(&self, code: i64, message: Option<&str>) -> Result<(), String> {
        let mut e = json!({ "ev": "setStatus", "code": code });
        if let Some(m) = message {
            e["message"] = json!(m);
        }
        self.log.lock().unwrap().push(e);
        throw_if(self.mode == "statusThrows")
    }
    fn record_exception(&self, message: &str) -> Result<(), String> {
        self.log.lock().unwrap().push(json!({ "ev": "recordException", "message": message, "noStack": true }));
        throw_if(self.mode == "recordThrows")
    }
    fn end(&self) -> Result<(), String> {
        self.log.lock().unwrap().push(json!({ "ev": "end" }));
        throw_if(self.mode == "endThrows")
    }
}

struct Tracer {
    log: Log,
    mode: String,
}

impl OtelTracer for Tracer {
    fn start_span(&self, name: &str) -> Result<Arc<dyn OtelSpan>, String> {
        self.log.lock().unwrap().push(json!({ "ev": "startSpan", "name": name }));
        throw_if(self.mode == "startThrows")?;
        Ok(Arc::new(Span { log: self.log.clone(), mode: self.mode.clone() }))
    }
}

/// A JSON number the way JavaScript prints it: an integral value is an integer.
fn num(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9e15 {
        json!(v as i64)
    } else {
        json!(v)
    }
}

struct Counter {
    log: Log,
    mode: String,
}

impl OtelCounter for Counter {
    fn add(&self, v: f64, attrs: &Map<String, Value>) -> Result<(), String> {
        self.log.lock().unwrap().push(json!({ "ev": "add", "v": num(v), "a": attrs }));
        throw_if(self.mode == "addThrows")
    }
}

struct Histogram {
    log: Log,
    mode: String,
}

impl OtelHistogram for Histogram {
    fn record(&self, v: f64, attrs: &Map<String, Value>) -> Result<(), String> {
        self.log.lock().unwrap().push(json!({ "ev": "record", "v": num(v), "a": attrs }));
        throw_if(self.mode == "recordThrows")
    }
}

struct Meter {
    log: Log,
    mode: String,
}

impl OtelMeter for Meter {
    fn create_counter(&self, name: &str) -> Result<Arc<dyn OtelCounter>, String> {
        self.log.lock().unwrap().push(json!({ "ev": "createCounter", "name": name }));
        throw_if(self.mode == "createThrows")?;
        Ok(Arc::new(Counter { log: self.log.clone(), mode: self.mode.clone() }))
    }
    fn create_histogram(&self, name: &str) -> Result<Arc<dyn OtelHistogram>, String> {
        self.log.lock().unwrap().push(json!({ "ev": "createHistogram", "name": name }));
        Ok(Arc::new(Histogram { log: self.log.clone(), mode: self.mode.clone() }))
    }
}

fn mode_fn(mode: &str) -> Option<Arc<dyn Fn(&str) -> String + Send + Sync>> {
    match mode {
        "identity" => Some(Arc::new(|s: &str| s.to_string())),
        "upper" => Some(Arc::new(|s: &str| s.to_uppercase())),
        "brackets" => Some(Arc::new(|s: &str| format!("<{s}>"))),
        _ => None,
    }
}

fn scenario(spec: &Value) -> Value {
    let log: Log = Arc::new(Mutex::new(vec![]));
    let mode = |k: &str| spec.get(k).and_then(Value::as_str).unwrap_or("ok").to_string();
    let mut o = InstrumentOptions::default();
    if spec["tracer"] == json!(true) {
        o.tracer = Some(Arc::new(Tracer { log: log.clone(), mode: mode("tracerMode") }));
    }
    if spec["meter"] == json!(true) {
        o.meter = Some(Arc::new(Meter { log: log.clone(), mode: mode("meterMode") }));
    }
    o.span_name = spec.get("spanName").and_then(Value::as_str).map(String::from);
    o.redact = spec.get("redact").and_then(Value::as_str).and_then(mode_fn);
    let g = spec["guard"].clone();
    let guard: OtelGuard = Arc::new(move |_req: &Value| match g.get("throws").and_then(Value::as_str) {
        Some(m) => Err(m.to_string()),
        None => Ok(g.get("result").cloned().unwrap_or(Value::Null)),
    });
    let wrapped = match instrument_guard(guard, o) {
        Ok(w) => w,
        Err(m) => return json!({ "wrap": m, "events": *log.lock().unwrap() }),
    };
    let outcome = match (*wrapped)(&json!("req")) {
        Ok(r) => json!({ "result": r }),
        Err(m) => json!({ "threw": m }),
    };
    json!({ "outcome": outcome, "events": *log.lock().unwrap() })
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "redactSecrets" => Ok(Value::String(redact_secrets(a[0].as_str().ok_or("not a string")?))),
        "pcaSpanAttributes" => {
            let red = mode_fn(a.get(1).and_then(Value::as_str).unwrap_or(""));
            let attrs = match &red {
                Some(r) => pca_span_attributes(&a[0], Some(&**r)),
                None => pca_span_attributes(&a[0], None),
            };
            Ok(Value::Object(attrs))
        }
        "instrumentScenario" => Ok(scenario(&a[0])),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn otel_vectors() {
    let cases = common::ref_cases("otel");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
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
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
