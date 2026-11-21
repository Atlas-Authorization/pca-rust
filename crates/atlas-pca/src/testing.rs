//! Testing kit for Proof-Carrying Authority: the acceptance constants and route mapping, a fake verifier (the REAL core verifier
//! rooted at the PCActn's own grant, accepting its own audience by default), the expect helpers, tampering and an in-memory state
//! store. Nothing here authorizes anything: `fake_verify` is `verify_pcactn_core` unchanged, so a swapped verb or a mutated
//! parameter is caught exactly as in production. A grant lifted from the artifact is never trusted for a post-quantum root.
//!
//! Not ported: the agent factories (`testAgent`, `makePCActn`: use the crate's agent API directly) and the per-adapter acceptance
//! matrix runner (it needs the caller's adapter).
use crate::{canonicalize, js_stringify, strict_parse, Verdict, ARTIFACT_SIZE_REASON, MAX_ARTIFACT_BYTES};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub const ADAPTER_ACCEPTANCE_AUDIENCE: &str = "payments-rs";

/// The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches.
pub fn adapter_acceptance_expected() -> Value {
    let refused = json!({"status": 403, "handlerRan": false, "bound": false});
    let mut m = Map::new();
    for k in ["over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store"] {
        m.insert(k.into(), refused.clone());
    }
    m.insert("valid_first".into(), json!({"status": 200, "handlerRan": true, "bound": true}));
    m.insert("replay_second".into(), refused);
    Value::Object(m)
}

/// The server's mapping from request to operation: a route table on method + path (the WHATWG URL pathname, resolved against a
/// base origin), the JSON body as params. `req` is `{method, url, body}`. `Ok(None)` for an unknown route or a body that is not an
/// object; `Err` where the URL parser rejects the URL (the reference throws).
pub fn acceptance_operation(req: &Value) -> Result<Option<Value>, String> {
    let path = match req.get("url") {
        Some(Value::String(u)) => {
            let base = url::Url::parse("http://adapter.invalid").map_err(|e| e.to_string())?;
            // WHATWG: a special scheme ignores every slash after the first two ("///x" is host "x"); the url crate reads an empty host
            let t = u.trim_start_matches(|c: char| c <= ' ');
            let slashes = t.chars().take_while(|c| matches!(c, '/' | '\\')).count();
            let u = if slashes >= 2 { format!("//{}", &t[slashes..]) } else { u.clone() };
            url::Url::options().base_url(Some(&base)).parse(&u).map_err(|e| format!("Invalid URL: {e}"))?.path().to_string()
        }
        _ => String::new(),
    };
    let method = req.get("method").map(crate::oauth::js_str).unwrap_or_else(|| "undefined".into()).to_uppercase();
    let verb = match format!("{method} {path}").as_str() {
        "POST /payments" => "payments.send",
        "POST /refunds" => "payments.refund",
        _ => return Ok(None),
    };
    match req.get("body") {
        Some(b @ Value::Object(_)) => Ok(Some(json!({"verb": verb, "resource": "payments", "params": b}))),
        _ => Ok(None),
    }
}

const NO_GRANT: &str = "fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant";

/// `pcactn.cap_chain[0]` as JavaScript reads it; `Err` where JavaScript would throw or find nothing.
fn lift_grant(pcactn: &Value) -> Result<Value, String> {
    let first = match pcactn {
        Value::Object(o) => match o.get("cap_chain") {
            Some(Value::Array(a)) => a.first().cloned(),
            Some(Value::String(s)) => s.chars().next().map(|c| Value::String(c.to_string())),
            Some(Value::Object(m)) => m.get("0").cloned(),
            _ => None,
        },
        Value::Null => return Err("Cannot read properties of null (reading 'cap_chain')".into()),
        _ => None,
    };
    match first {
        Some(f) if crate::oauth::truthy(Some(&f)) => Ok(f),
        _ => Err(NO_GRANT.into()),
    }
}

/// Run the real core verifier against `pcactn`. `opts`: `audience` (absent or null = accept the PCActn's own `aud`; a mismatching
/// string forces the audience check to fail), `now` (epoch ms; the wall clock when absent), `grant` (the root to verify against;
/// default the PCActn's own chain root, never trusted for a post-quantum root).
pub fn fake_verify(pcactn: &Value, opts: &Value) -> Result<Verdict, String> {
    let grant_opt = opts.get("grant").filter(|g| !g.is_null());
    let root = match grant_opt {
        Some(g) => g.clone(),
        None => lift_grant(pcactn)?,
    };
    let own = pcactn.get("aud").and_then(Value::as_str).unwrap_or("");
    let aud = match opts.get("audience") {
        Some(Value::String(a)) => a.as_str(),
        _ => own, // absent, or the explicit opt-out: the PCActn's own audience (a non-string one fails the wire check)
    };
    let now = opts
        .get("now")
        .and_then(Value::as_f64)
        .map(|f| f as i64)
        .unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0));
    if !root.is_object() {
        return Ok(failing("wire", "wire: the grant is not an object"));
    }
    if grant_opt.is_none() && root.get("alg").is_some_and(|a| a.as_str() != Some("ed25519")) {
        return Ok(failing("cap_chain", "cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it"));
    }
    Ok(verify_pcactn_core_opts(pcactn, &root, now, aud))
}

fn failing(check: &str, reason: &str) -> Verdict {
    let mut checks = std::collections::BTreeMap::new();
    checks.insert(check.to_string(), false);
    Verdict { allow: false, checks, reason: reason.into(), reasons: Vec::new(), legacy_model_polarity: false }
}

fn verify_pcactn_core_opts(pcactn: &Value, root: &Value, now: i64, aud: &str) -> Verdict {
    // a test double, never a production verifier: the plan root is not pinned
    let opts = crate::VerifyOptions { insecure_skip_plan_root_check: true, ..crate::VerifyOptions::default() };
    crate::verify_pcactn_core_with(pcactn, root, now, aud, &opts)
}

fn failing_checks(v: &Verdict) -> Vec<&str> {
    v.checks.iter().filter(|(_, ok)| !**ok).map(|(k, _)| k.as_str()).collect()
}

/// Assert that `pcactn` verifies: `Err` names the failing checks (and the verifier's reason) when it is denied.
pub fn expect_verifies(pcactn: &Value, opts: &Value) -> Result<Verdict, String> {
    let v = fake_verify(pcactn, opts)?;
    if !v.allow {
        let reason = if v.reason.is_empty() { String::new() } else { format!(" \u{2014} {}", v.reason) };
        return Err(format!("expectVerifies: PCActn was denied. failing checks: [{}]{reason}", failing_checks(&v).join(", ")));
    }
    Ok(v)
}

/// The inverse of [`expect_verifies`]: `Err` when `pcactn` unexpectedly verifies.
pub fn expect_denied(pcactn: &Value, opts: &Value) -> Result<Verdict, String> {
    let v = fake_verify(pcactn, opts)?;
    if v.allow {
        let checks: Map<String, Value> = v.checks.iter().map(|(k, ok)| (k.clone(), json!(if *ok { "pass" } else { "fail" }))).collect();
        return Err(format!("expectDenied: PCActn verified but was expected to be denied. checks: {}", js_stringify(&Value::Object(checks))));
    }
    Ok(v)
}

fn decode_pcactn(s: &str) -> Result<Map<String, Value>, String> {
    if s.len() > MAX_ARTIFACT_BYTES {
        return Err(ARTIFACT_SIZE_REASON.into()); // FIRST: before any parsing
    }
    match strict_parse(s)? {
        Value::Object(o) => Ok(o),
        _ => Err("decodePCActn: not an object".into()),
    }
}

/// Decode an encoded PCActn (strict profile, size-capped), let `mutate` corrupt it, then re-encode it so a test can assert the
/// corruption is caught. A change touching the signed body breaks `leaf_signature`.
pub fn tamper(encoded: &str, mutate: impl FnOnce(&mut Map<String, Value>) -> Result<(), String>) -> Result<String, String> {
    let mut rec = decode_pcactn(encoded)?;
    mutate(&mut rec)?;
    Ok(canonicalize(&Value::Object(decode_pcactn(&js_stringify(&Value::Object(rec)))?)))
}

/// An in-memory per-holder state store (replay counter, budget). Nothing persists beyond the process.
#[derive(Default)]
pub struct MemoryStateStore {
    m: HashMap<String, Value>,
}

impl MemoryStateStore {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.m.get(key)
    }
    pub fn put(&mut self, key: &str, state: Value) {
        self.m.insert(key.to_string(), state);
    }
}

pub fn memory_state_store() -> MemoryStateStore {
    MemoryStateStore::default()
}
