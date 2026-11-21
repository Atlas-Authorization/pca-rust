//! Step-up lifecycle events and signed webhooks: content-addressed events (`id` = digest of the content), the HMAC-SHA256
//! `PCA-Signature: t=<unix>,v1=<hex>` header (several `v1` for secret rotation), tolerance-checked verification and the
//! replay-guarded delivery check (one delivery per event id through a [`StateStore`]'s consume-once).
use crate::{hash_canonical, StateStore};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const EVENT_TYPES: [&str; 4] = ["step_up.created", "step_up.approved", "step_up.denied", "step_up.expired"];
pub const MIN_SECRET_BYTES: usize = 16;
const MAX_HEADER_CHARS: usize = 2048;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn event_id(e: &Value) -> String {
    let mut m = Map::new();
    m.insert("d".into(), json!("atlas-pca/stepup-event/v1"));
    for k in ["type", "at", "grant_ref"] {
        m.insert(k.into(), e[k].clone());
    }
    m.insert("action".into(), json!({ "verb": e["action"]["verb"], "resource": e["action"]["resource"] }));
    m.insert("tier".into(), e["tier"].clone());
    if let Some(a) = e.get("actor") {
        m.insert("actor".into(), a.clone());
    }
    hash_canonical(&Value::Object(m))
}

/// A step-up event (`buildStepUpEvent`): `data` = `{at?, grant_ref, action: {verb, resource}, tier, actor?}` (`at` defaults to
/// now in ms). Members in the reference's order (`type, at, grant_ref, action, tier, actor?, id`).
pub fn build_step_up_event(kind: &str, data: &Value) -> Value {
    build_step_up_event_value(&json!(kind), data)
}

/// [`build_step_up_event`] for a `type` of any JSON kind: the reference copies it verbatim into the event and its id.
#[doc(hidden)]
pub fn build_step_up_event_value(kind: &Value, data: &Value) -> Value {
    let at = match data.get("at") {
        Some(a) if !a.is_null() => a.clone(),
        _ => json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)),
    };
    let mut e = Map::new();
    e.insert("type".into(), kind.clone());
    e.insert("at".into(), at);
    e.insert("grant_ref".into(), data.get("grant_ref").cloned().unwrap_or(Value::Null));
    e.insert("action".into(), json!({ "verb": data["action"]["verb"], "resource": data["action"]["resource"] }));
    e.insert("tier".into(), data.get("tier").cloned().unwrap_or(Value::Null));
    if let Some(a) = data.get("actor") {
        e.insert("actor".into(), a.clone());
    }
    let mut v = Value::Object(e);
    let id = event_id(&v);
    v["id"] = json!(id);
    v
}

/// `JSON.stringify(event)`.
pub fn serialize_event(e: &Value) -> String {
    crate::js_stringify(e)
}

/// Parse and check a delivered event (`parseEvent`): every member typed, and the `id` must match the content.
pub fn parse_event(text: &str) -> Result<Value, String> {
    let raw: Value = serde_json::from_str(text).map_err(|e| format!("parseEvent: invalid JSON ({e})"))?;
    let empty = Map::new();
    let o = match &raw {
        Value::Object(m) => m,
        Value::Array(_) => &empty,
        _ => return Err("parseEvent: not an object".into()),
    };
    let id = o.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("parseEvent: bad id")?;
    let kind = o.get("type").and_then(Value::as_str).filter(|t| EVENT_TYPES.contains(t)).ok_or("parseEvent: bad type")?;
    let at = o.get("at").filter(|a| a.is_number()).ok_or("parseEvent: bad at")?;
    let grant_ref = o.get("grant_ref").filter(|g| g.is_string()).ok_or("parseEvent: bad grant_ref")?;
    let a = match o.get("action") {
        Some(Value::Object(m)) => m,
        Some(Value::Array(_)) => &empty,
        _ => return Err("parseEvent: bad action".into()),
    };
    let (Some(verb), Some(resource)) = (a.get("verb").filter(|v| v.is_string()), a.get("resource").filter(|v| v.is_string())) else {
        return Err("parseEvent: bad action fields".into());
    };
    let tier = match o.get("tier").and_then(Value::as_f64) {
        Some(t) if t == 2.0 => 2,
        Some(t) if t == 3.0 => 3,
        _ => return Err("parseEvent: bad tier".into()),
    };
    let actor = o.get("actor");
    if actor.is_some_and(|x| !x.is_string()) {
        return Err("parseEvent: bad actor".into());
    }
    let mut e = Map::new();
    e.insert("id".into(), json!(id));
    e.insert("type".into(), json!(kind));
    e.insert("at".into(), at.clone());
    e.insert("grant_ref".into(), grant_ref.clone());
    e.insert("action".into(), json!({ "verb": verb, "resource": resource }));
    e.insert("tier".into(), json!(tier));
    if let Some(x) = actor {
        e.insert("actor".into(), x.clone());
    }
    let ev = Value::Object(e);
    if event_id(&ev) != id {
        return Err("parseEvent: id does not match the event content".into());
    }
    Ok(ev)
}

fn key_ok(secret: &[u8]) -> Option<&[u8]> {
    (secret.len() >= MIN_SECRET_BYTES).then_some(secret)
}

fn mac(key: &[u8], t: u64, payload: &str) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(format!("{t}.{payload}").as_bytes());
    m.finalize().into_bytes().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `t` and every `v1` of a signature header; `None` when malformed (over 2048 characters, a bad or conflicting `t`, no `v1`).
fn parse_signature_header(h: &str) -> Option<(u64, Vec<String>)> {
    if h.encode_utf16().count() > MAX_HEADER_CHARS {
        return None;
    }
    let (mut t, mut v1) = (None, Vec::new());
    for part in h.split(',') {
        let Some(eq) = part.find('=') else { continue };
        let (key, val) = (js_trim(&part[..eq]), js_trim(&part[eq + 1..]));
        if key == "t" {
            if val.is_empty() || val.len() > 15 || !val.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: u64 = val.parse().ok()?;
            if t.is_some_and(|x| x != n) {
                return None;
            }
            t = Some(n);
        } else if key == "v1" {
            v1.push(val.to_string());
        }
    }
    Some((t?, v1)).filter(|(_, v)| !v.is_empty())
}

/// `String.prototype.trim`: JavaScript whitespace and line terminators.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

/// The `PCA-Signature` header for `payload` (`signWebhook`): `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<payload>")>`.
/// `timestamp` defaults to now; a secret under 16 bytes or a timestamp that is not a non-negative safe integer is refused.
pub fn sign_webhook(secret: &[u8], payload: &str, timestamp: Option<f64>) -> Result<String, String> {
    let key = key_ok(secret).ok_or_else(|| format!("signWebhook: the secret must be at least {MIN_SECRET_BYTES} bytes"))?;
    let t = timestamp.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64));
    if t.fract() != 0.0 || !(0.0..=MAX_SAFE).contains(&t) {
        return Err("signWebhook: timestamp must be a non-negative integer (unix seconds)".into());
    }
    Ok(format!("t={},v1={}", t as u64, hex(&mac(key, t as u64, payload))))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Verify a `PCA-Signature` header (`verifyWebhook`): the timestamp within `tolerance_sec` (default 300) of `now` (default the
/// clock) and some `v1` equal to the expected HMAC, compared in constant time over every candidate. Never errs: false.
pub fn verify_webhook(secret: &[u8], payload: &str, header: &str, tolerance_sec: Option<f64>, now: Option<f64>) -> bool {
    let Some(key) = key_ok(secret) else { return false };
    let Some((t, v1)) = parse_signature_header(header) else { return false };
    let tol = tolerance_sec.unwrap_or(300.0);
    let now = now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64));
    if !tol.is_finite() || tol < 0.0 || !now.is_finite() || (now - t as f64).abs() > tol {
        return false;
    }
    let expected = mac(key, t, payload);
    let mut matched = false;
    for v in &v1 {
        if let Some(p) = hex_bytes(v) {
            matched |= crate::attest::util::timing_safe_eq(&expected, &p);
        }
    }
    matched
}

/// The content-addressed replay key (`replayKey`): `<namespace>:base64url(SHA-256(len32be(part) || part ...))` over the
/// namespace and every part.
pub fn replay_key(namespace: &str, parts: &[&str]) -> String {
    let mut buf = Vec::new();
    for p in std::iter::once(&namespace).chain(parts.iter()) {
        buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        buf.extend_from_slice(p.as_bytes());
    }
    format!("{namespace}:{}", crate::b64_encode(&Sha256::digest(&buf)))
}

/// One webhook delivery (`verifyDelivery`): the signature, the event, and a first consume of the event id in `replay` (kept
/// until the timestamp's tolerance has passed). `{ok: true, event}` or `{ok: false, reason}`.
pub fn verify_delivery(secret: &[u8], payload: &str, header: &str, replay: &dyn StateStore, tolerance_sec: Option<f64>, now: Option<f64>) -> Value {
    let fail = |r: &str| json!({ "ok": false, "reason": r });
    if !verify_webhook(secret, payload, header, tolerance_sec, now) {
        return fail("bad signature");
    }
    let event = match parse_event(payload) {
        Ok(e) => e,
        Err(m) => return fail(&m),
    };
    let Some((t, _)) = parse_signature_header(header) else { return fail("bad signature") };
    let now_sec = now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64));
    let tol = tolerance_sec.unwrap_or(300.0);
    let key = replay_key("pca-stepup-event/v1", &[event["id"].as_str().unwrap_or("")]);
    match replay.consume_once(&key, ((t as f64 + tol) * 1000.0 + 1.0) as i64, (now_sec * 1000.0) as i64) {
        Ok(true) => json!({ "ok": true, "event": event }),
        Ok(false) => fail("replayed delivery"),
        Err(_) => fail("replay store unavailable"),
    }
}

/// The headers of a signed delivery (`webhookHeaders`).
pub fn webhook_headers(secret: &[u8], payload: &str, timestamp: Option<f64>) -> Result<Value, String> {
    Ok(json!({ "PCA-Signature": sign_webhook(secret, payload, timestamp)?, "content-type": "application/json" }))
}
