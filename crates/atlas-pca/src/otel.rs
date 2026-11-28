//! OpenTelemetry-style instrumentation for PCA (the reference's `@atlasauth/pca-otel`): wrap a verification guard so every decision
//! emits a span and two metrics. No OpenTelemetry crate is involved: [`pca_span_attributes`] maps a guard result to plain attribute
//! data, and the small [`OtelTracer`] / [`OtelMeter`] traits are what a real exporter is adapted to. This OBSERVES, it never
//! decides: a tracer, meter or redactor that fails or panics never changes what the guard returned. With no tracer and no meter the
//! wrapper is a transparent pass-through.
//!
//! A guard result is a JSON value; only a small structural slice is read (`ok`, `status`, `verdict.{r, requiredThreshold.t, reasons}`
//! and `pcactn.action.{verb, resource}`).
//!
//! shortcut: the first element of a string `verdict.reasons` (JavaScript indexes a string by UTF-16 unit) is the first character,
//! whole; an astral character is not split into a lone surrogate (a Rust string cannot hold one).
use regex::{Captures, Regex};
use serde_json::{json, Map, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

/// OpenTelemetry `SpanStatusCode`: OK.
pub const STATUS_OK: i64 = 1;
/// OpenTelemetry `SpanStatusCode`: ERROR.
pub const STATUS_ERROR: i64 = 2;
const MAX_TEXT: usize = 256;

// the JavaScript `\s` class, for use inside a bracket class
const WS: &str = r"\t\n\x0b\x0c\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

struct Patterns {
    jwt: Regex,
    auth: Regex,
    scheme: Regex,
    url: Regex,
    kv: Regex,
    run: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |s: String| Regex::new(&s).expect("otel redaction pattern");
        Patterns {
            jwt: mk(r"(?-u:\b)eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*".to_string()),
            auth: mk(format!(r#"(?-u:\b)((?i-u:authorization)["']?[{WS}]*[:=][{WS}]*)[^\n"']*"#)),
            scheme: mk(format!(r"(?-u:\b)((?i-u:Bearer|Basic|Token))[{WS}]+[A-Za-z0-9_.~+/=-]{{6,}}")),
            url: mk(format!(r"((?i-u:[a-z][a-z0-9+.-]*)://)[^{WS}/@]*:[^{WS}/@]*@")),
            kv: mk(format!(
                r#"(?-u:\b)((?i-u:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)["']?[{WS}]*[:=][{WS}]*)("[^"]*"|'[^']*'|[^{WS}"'&,;]+)"#
            )),
            run: mk(r"[A-Za-z0-9_-]{32,}".to_string()),
        }
    })
}

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Remove what looks like a credential from text bound for telemetry: JWTs, `Bearer` / `Basic` / `Token` credentials, an
/// `authorization` value, URL userinfo (`scheme://user:pass@host`), `name=value` / `"name": "value"` pairs whose name is token,
/// secret, password, key, signature, credential or auth, and long unbroken base64url or hex runs (32+ characters). The result is
/// cut to 256 UTF-16 units. A pattern list is a net, not a proof: keep secrets out of resources and reasons in the first place.
pub fn redact_secrets(text: &str) -> String {
    let p = patterns();
    let t = p.jwt.replace_all(text, "[redacted]");
    let t = p.auth.replace_all(&t, "${1}[redacted]");
    let t = p.scheme.replace_all(&t, "${1} [redacted]");
    let t = p.url.replace_all(&t, "${1}[redacted]@");
    let t = p.kv.replace_all(&t, |c: &Captures| {
        let q = match c[2].chars().next() {
            Some(q @ ('"' | '\'')) => q.to_string(),
            _ => String::new(),
        };
        format!("{}{q}[redacted]{q}", &c[1])
    });
    let t = p.run.replace_all(&t, "[redacted]").into_owned();
    if u16len(&t) > MAX_TEXT {
        let cut: Vec<u16> = t.encode_utf16().take(MAX_TEXT).collect();
        format!("{}...", String::from_utf16_lossy(&cut))
    } else {
        t
    }
}

fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(k),
        _ => None,
    }
}

fn finite_number(v: Option<&Value>) -> Option<&Value> {
    v.filter(|n| n.as_f64().is_some_and(f64::is_finite))
}

fn is_ok(result: &Value) -> bool {
    get(result, "ok") == Some(&Value::Bool(true))
}

/// `result?.verdict?.reasons?.[0]`, including JavaScript indexing into a string or an object keyed "0".
fn first_reason(result: &Value) -> Option<Value> {
    let reasons = get(get(result, "verdict")?, "reasons")?;
    match reasons {
        Value::Array(a) => a.first().cloned(),
        Value::String(s) => s.chars().next().map(|c| Value::String(c.to_string())),
        Value::Object(m) => m.get("0").cloned(),
        _ => None,
    }
}

/// The span attributes of a guard result, in order: `pca.decision` (anything but an explicit `ok: true` is a deny), `pca.status`,
/// `pca.tier`, `pca.risk` (finite numbers only), `pca.verb`, `pca.resource` (redacted) and, on deny only, `pca.reason` (the first
/// reason, redacted). Absent fields are omitted. `redact` defaults to [`redact_secrets`].
pub fn pca_span_attributes(result: &Value, redact: Option<&dyn Fn(&str) -> String>) -> Map<String, Value> {
    let red = |s: &str| redact.map_or_else(|| redact_secrets(s), |f| f(s));
    let mut attrs = Map::new();
    attrs.insert("pca.decision".into(), json!(if is_ok(result) { "allow" } else { "deny" }));
    if let Some(n) = finite_number(get(result, "status")) {
        attrs.insert("pca.status".into(), n.clone());
    }
    let verdict = get(result, "verdict");
    if let Some(n) = finite_number(verdict.and_then(|v| get(v, "requiredThreshold")).and_then(|t| get(t, "t"))) {
        attrs.insert("pca.tier".into(), n.clone());
    }
    if let Some(n) = finite_number(verdict.and_then(|v| get(v, "r"))) {
        attrs.insert("pca.risk".into(), n.clone());
    }
    let action = get(result, "pcactn").and_then(|p| get(p, "action"));
    if let Some(Value::String(s)) = action.and_then(|a| get(a, "verb")) {
        attrs.insert("pca.verb".into(), json!(red(s)));
    }
    if let Some(Value::String(s)) = action.and_then(|a| get(a, "resource")) {
        attrs.insert("pca.resource".into(), json!(red(s)));
    }
    if !is_ok(result) {
        if let Some(Value::String(s)) = first_reason(result) {
            attrs.insert("pca.reason".into(), json!(red(&s)));
        }
    }
    attrs
}

/// The slice of a tracing span the instrumentation uses. An `Err` is an exporter failure and is swallowed.
pub trait OtelSpan: Send + Sync {
    fn set_attribute(&self, key: &str, value: &Value) -> Result<(), String>;
    /// `message` is `None` when the status carries none.
    fn set_status(&self, code: i64, message: Option<&str>) -> Result<(), String>;
    fn record_exception(&self, message: &str) -> Result<(), String>;
    fn end(&self) -> Result<(), String>;
}

/// Starts spans.
pub trait OtelTracer: Send + Sync {
    fn start_span(&self, name: &str) -> Result<Arc<dyn OtelSpan>, String>;
}

/// The instruments the guard reports to.
pub trait OtelCounter: Send + Sync {
    fn add(&self, v: f64, attrs: &Map<String, Value>) -> Result<(), String>;
}

pub trait OtelHistogram: Send + Sync {
    fn record(&self, v: f64, attrs: &Map<String, Value>) -> Result<(), String>;
}

/// Creates instruments.
pub trait OtelMeter: Send + Sync {
    fn create_counter(&self, name: &str) -> Result<Arc<dyn OtelCounter>, String>;
    fn create_histogram(&self, name: &str) -> Result<Arc<dyn OtelHistogram>, String>;
}

/// A verification guard: one request in, a result (the JSON verdict object) or an error message out.
pub type OtelGuard = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

/// Options of [`instrument_guard`]; every field is optional (`span_name` `None` is `pca.verify`, `redact` `None` is
/// [`redact_secrets`]).
#[derive(Default, Clone)]
pub struct InstrumentOptions {
    pub tracer: Option<Arc<dyn OtelTracer + Send + Sync>>,
    pub meter: Option<Arc<dyn OtelMeter + Send + Sync>>,
    pub span_name: Option<String>,
    /// Applied to every string that leaves in a span attribute, a status message or a recorded exception.
    pub redact: Option<Arc<dyn Fn(&str) -> String + Send + Sync>>,
}

/// The exporter's failure, panic included, is never the guard's decision.
fn safe(f: impl FnOnce() -> Result<(), String>) {
    let _ = catch_unwind(AssertUnwindSafe(f));
}

/// Wrap a verification guard so each decision emits a span (default name `pca.verify`, OK status on allow, ERROR status plus the
/// redacted first reason on deny, always ended) and metrics (a `pca.verifications` counter and a `pca.verify.risk` histogram,
/// created once, both tagged `decision`). The wrapper returns the guard's result and error unchanged; an error is first recorded on
/// the span as a fresh, redacted message. Creating an instrument may fail: then the wrap fails (as in the reference); once wrapped,
/// nothing the exporter does can alter the outcome.
pub fn instrument_guard(guard: OtelGuard, opts: InstrumentOptions) -> Result<OtelGuard, String> {
    let name = opts.span_name.clone().unwrap_or_else(|| "pca.verify".to_string());
    let redact: Arc<dyn Fn(&str) -> String + Send + Sync> = opts.redact.clone().unwrap_or_else(|| Arc::new(redact_secrets));
    let (counter, histogram) = match &opts.meter {
        Some(m) => (Some(m.create_counter("pca.verifications")?), Some(m.create_histogram("pca.verify.risk")?)),
        None => (None, None),
    };
    let tracer = opts.tracer.clone();
    Ok(Arc::new(move |req: &Value| {
        let mut span: Option<Arc<dyn OtelSpan>> = None;
        if let Some(t) = &tracer {
            safe(|| {
                span = Some(t.start_span(&name)?);
                Ok(())
            });
        }
        let outcome = guard(req);
        match &outcome {
            Ok(result) => {
                if let Some(sp) = &span {
                    safe(|| {
                        for (k, v) in pca_span_attributes(result, Some(&*redact)) {
                            sp.set_attribute(&k, &v)?;
                        }
                        if is_ok(result) {
                            sp.set_status(STATUS_OK, None)
                        } else if let Some(Value::String(r)) = first_reason(result) {
                            sp.set_status(STATUS_ERROR, Some(&(*redact)(&r)))
                        } else {
                            sp.set_status(STATUS_ERROR, None)
                        }
                    });
                }
                let mut attrs = Map::new();
                attrs.insert("decision".into(), json!(if is_ok(result) { "allow" } else { "deny" }));
                if let Some(c) = &counter {
                    safe(|| c.add(1.0, &attrs));
                }
                if let (Some(h), Some(r)) = (&histogram, finite_number(get(result, "verdict").and_then(|v| get(v, "r"))).and_then(Value::as_f64)) {
                    safe(|| h.record(r, &attrs));
                }
            }
            Err(msg) => {
                if let Some(sp) = &span {
                    safe(|| {
                        // a fresh message: the original may carry credentials
                        let clean = (*redact)(msg);
                        sp.record_exception(&clean)?;
                        sp.set_status(STATUS_ERROR, Some(&clean))
                    });
                }
            }
        }
        if let Some(sp) = &span {
            safe(|| sp.end());
        }
        outcome
    }))
}
