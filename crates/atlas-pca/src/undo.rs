//! UNDO WINDOWS: reversible actions execute at once and the principal gets a veto window in which they can undo them.
//!
//! This is the PURE, language-neutral layer (the coordinator that admits, writes the durable ledger, compensates and notifies
//! runs in the TypeScript reference or the hosted ledger): the compensation digest, the signed one-click undo token, the signed and
//! hash-chained audit receipts, the record state machine and the window clamp. Same wire and decisions as the TypeScript
//! reference (`undo.ts`); the shared vectors `undo-vectors.json` pin them. Every function is total (no panic, no I/O, no clock).
//!
//! ```text
//! open --veto (now <= window_end)--> vetoed --compensated--> compensated
//!   |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
//!   |                                  |                                   \--compensated--> compensated
//!   +--finalize (now > window_end)--> finalized
//!   +--abort (the effect never ran)--> finalized
//! ```
//!
//! Signatures are plain Ed25519 over `UTF-8(domain) || strict-canonical JSON of the body` (every member but `sig`).

use serde_json::{json, Map, Value};

use crate::agent::KeyPair;
use crate::{canonicalize_strict, decode_b64u_strict, hash_canonical_strict, safe_int, strict_parse, verify_b64u};

pub const UNDO_TOKEN_DOMAIN: &str = "atlas-pca/undo-token/v1\0";
pub const UNDO_RECEIPT_DOMAIN: &str = "atlas-pca/undo-receipt/v1\0";
pub const UNDO_COMPENSATION_DOMAIN: &str = "atlas-pca/undo-compensation/v1";
pub const UNDO_RECEIPT_REF_DOMAIN: &str = "atlas-pca/undo-receipt-ref/v1";
pub const UNDO_TOKEN_REF_DOMAIN: &str = "atlas-pca/undo-token-ref/v1";
pub const UNDO_TOKEN_KIND: &str = "pca-undo-token";
pub const UNDO_RECEIPT_KIND: &str = "pca-undo-receipt";

/// The realistic floor of a veto window: a human must be able to react.
pub const UNDO_MIN_WINDOW_MS: i64 = 30_000;
pub const UNDO_DEFAULT_WINDOW_MS: i64 = 15 * 60_000;
pub const UNDO_MAX_WINDOW_MS: i64 = 24 * 60 * 60_000;

pub const UNDO_STATES: [&str; 5] = ["open", "vetoed", "compensated", "compensation_failed", "finalized"];
pub const UNDO_EVENTS: [&str; 8] = ["opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect"];
pub const VETO_VIAS: [&str; 4] = ["token", "operator", "fraud_proof", "revocation"];

const TOKEN_MEMBERS: [&str; 10] = ["v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig"];
const RECEIPT_MEMBERS: [&str; 11] = ["v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer", "sig"];

/// A record id: a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F).
pub fn undo_id_ok(v: Option<&Value>) -> bool {
    match v.and_then(Value::as_str) {
        Some(x) => {
            let n = x.encode_utf16().count();
            n > 0 && n <= 256 && !x.chars().any(|c| (c as u32) < 0x20)
        }
        None => false,
    }
}

fn domain_bytes(domain: &str, body: &Value) -> Option<Vec<u8>> {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body).ok()?.as_bytes());
    Some(m)
}

/// `now` as a safe integer (finite, integral, |n| <= 2^53-1), else `None`.
fn safe_now(now: f64) -> Option<i64> {
    (now.is_finite() && now.fract() == 0.0 && now.abs() <= 9_007_199_254_740_991.0).then_some(now as i64)
}

fn b64u(b: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b)
}

fn str_of<'a>(o: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    o.get(k).and_then(Value::as_str)
}

fn exact_members(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
}

/// The body a signature covers: the object without `sig`.
fn without_sig(o: &Map<String, Value>) -> Value {
    let mut b = o.clone();
    b.remove("sig");
    Value::Object(b)
}

// ---- digests --------------------------------------------------------------------------------------------------------------

/// `hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?})` of a compensation `{verb, resource, params,
/// undo_of, def_digest, target_param?}` (`target_param` only when present). `None` when a required member is missing or the value
/// is outside the strict profile.
pub fn compensation_digest(c: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), json!(UNDO_COMPENSATION_DOMAIN));
    for k in ["verb", "resource", "params", "undo_of", "def_digest"] {
        m.insert(k.into(), c.get(k)?.clone());
    }
    if let Some(t) = c.get("target_param") {
        m.insert("target_param".into(), t.clone());
    }
    hash_canonical_strict(&Value::Object(m))
}

// ---- the one-click undo token ---------------------------------------------------------------------------------------------

/// Sign a one-click undo token for a record `{id, aud, principal, compensation_digest, render_digest?, window_end}` with the undo
/// service key. `exp` is the record's `window_end`; `render_digest` is `""` when the record has none.
pub fn sign_undo_token(record: &Value, key: &KeyPair) -> Result<Value, String> {
    let get = |k: &str| record.get(k).cloned().ok_or_else(|| format!("sign_undo_token: the record has no {k}"));
    let mut body = json!({"v": 1, "kind": UNDO_TOKEN_KIND, "record": get("id")?, "aud": get("aud")?, "principal": get("principal")?,
        "compensation_digest": get("compensation_digest")?, "render_digest": record.get("render_digest").cloned().unwrap_or(json!("")),
        "exp": get("window_end")?, "signer": key.public});
    let msg = domain_bytes(UNDO_TOKEN_DOMAIN, &body).ok_or("sign_undo_token: the record is outside the strict JSON profile")?;
    body["sig"] = json!(b64u(&key.sign(&msg)));
    Ok(body)
}

/// Check a token against the pinned undo service key and the stored record `{id, aud, principal, compensation_digest,
/// render_digest?, window_end}` at `now`. Returns the FIRST failing check, in order: `malformed` (shape), `signer` (not the pinned
/// key), `signature`, `record` (another record id), `binding` (aud, principal, compensation, render or window end differ), `expired`
/// (`now` not a safe integer, or `now > exp`: valid through `exp` inclusive); `ok` when none. Total.
pub fn undo_token_check(token: &Value, expected_signer: &str, record: &Value, now: f64) -> &'static str {
    let Some(t) = token.as_object() else { return "malformed" };
    if !exact_members(t, &TOKEN_MEMBERS) {
        return "malformed";
    }
    let strs = ["aud", "principal", "compensation_digest", "render_digest", "signer"];
    if safe_int(&t["v"]) != Some(1)
        || str_of(t, "kind") != Some(UNDO_TOKEN_KIND)
        || !undo_id_ok(t.get("record"))
        || !strs.iter().all(|k| t[*k].is_string())
        || safe_int(&t["exp"]).is_none()
        || !str_of(t, "sig").is_some_and(|x| decode_b64u_strict(x, Some(64)).is_some())
    {
        return "malformed";
    }
    if str_of(t, "signer") != Some(expected_signer) {
        return "signer";
    }
    let ok = domain_bytes(UNDO_TOKEN_DOMAIN, &without_sig(t)).is_some_and(|m| verify_b64u(expected_signer, &m, str_of(t, "sig").unwrap_or("")));
    if !ok {
        return "signature";
    }
    if record.get("id").and_then(Value::as_str) != str_of(t, "record") {
        return "record";
    }
    let rec_render = match record.get("render_digest") {
        None | Some(Value::Null) => Some(""),
        Some(r) => r.as_str(),
    };
    if record.get("aud").and_then(Value::as_str) != str_of(t, "aud")
        || record.get("principal").and_then(Value::as_str) != str_of(t, "principal")
        || record.get("compensation_digest").and_then(Value::as_str) != str_of(t, "compensation_digest")
        || rec_render != str_of(t, "render_digest")
        || record.get("window_end").and_then(safe_int) != safe_int(&t["exp"])
    {
        return "binding";
    }
    match safe_now(now) {
        Some(n) if n <= safe_int(&t["exp"]).unwrap_or(i64::MIN) => "ok",
        _ => "expired",
    }
}

/// The token as a URL-safe string: base64url of its strict-canonical JSON (for a one-click link).
pub fn encode_undo_token(token: &Value) -> Result<String, String> {
    Ok(b64u(canonicalize_strict(token)?.as_bytes()))
}

/// Inverse of [`encode_undo_token`]: a non-empty string of at most 4096 characters, strict base64url, strict UTF-8 and a JSON
/// object; `None` for anything else.
pub fn decode_undo_token(s: &str) -> Option<Value> {
    if s.is_empty() || s.encode_utf16().count() > 4096 {
        return None;
    }
    let raw = decode_b64u_strict(s, None)?;
    let v = strict_parse(std::str::from_utf8(&raw).ok()?).ok()?;
    v.is_object().then_some(v)
}

/// `hashCanonical({d: "atlas-pca/undo-token-ref/v1", t})`.
pub fn undo_token_digest(token: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": UNDO_TOKEN_REF_DOMAIN, "t": token}))
}

// ---- receipts -------------------------------------------------------------------------------------------------------------

/// `hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r})` (the receipt WITH its signature).
pub fn undo_receipt_digest(r: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": UNDO_RECEIPT_REF_DOMAIN, "r": r}))
}

/// Sign the receipt of one transition: `body` is `{record, event, state, at, compensation_digest, prev, note}` (`v`, `kind` and
/// `signer` are added).
pub fn sign_undo_receipt(body: &Value, key: &KeyPair) -> Result<Value, String> {
    let get = |k: &str| body.get(k).cloned().ok_or_else(|| format!("sign_undo_receipt: the body has no {k}"));
    let mut b = json!({"v": 1, "kind": UNDO_RECEIPT_KIND, "record": get("record")?, "event": get("event")?, "state": get("state")?, "at": get("at")?,
        "compensation_digest": get("compensation_digest")?, "prev": get("prev")?, "note": get("note")?, "signer": key.public});
    let msg = domain_bytes(UNDO_RECEIPT_DOMAIN, &b).ok_or("sign_undo_receipt: the body is outside the strict JSON profile")?;
    b["sig"] = json!(b64u(&key.sign(&msg)));
    Ok(b)
}

/// True iff `r` is a well-formed receipt (exactly its 11 members, a known event and state, a valid record id, signer equal to
/// `expected_signer`, a 64-byte signature) signed by `expected_signer` over exactly its content. Total.
pub fn verify_undo_receipt(r: &Value, expected_signer: &str) -> bool {
    let Some(x) = r.as_object() else { return false };
    let shape = safe_int(&x.get("v").cloned().unwrap_or(Value::Null)) == Some(1)
        && str_of(x, "kind") == Some(UNDO_RECEIPT_KIND)
        && undo_id_ok(x.get("record"))
        && str_of(x, "event").is_some_and(|e| UNDO_EVENTS.contains(&e))
        && str_of(x, "state").is_some_and(|e| UNDO_STATES.contains(&e))
        && x.get("at").and_then(safe_int).is_some()
        && ["compensation_digest", "prev", "note"].iter().all(|k| x.get(*k).is_some_and(Value::is_string))
        && str_of(x, "signer") == Some(expected_signer)
        && str_of(x, "sig").is_some_and(|s| decode_b64u_strict(s, Some(64)).is_some());
    if !shape || !exact_members(x, &RECEIPT_MEMBERS) {
        return false;
    }
    domain_bytes(UNDO_RECEIPT_DOMAIN, &without_sig(x)).is_some_and(|m| verify_b64u(expected_signer, &m, str_of(x, "sig").unwrap_or("")))
}

/// Verify a record's receipt chain (`record` = `{id, compensation_digest, state, receipts}`): every receipt verifies, names this
/// record and its compensation, `prev` links each to the one before (`""` for the first), the first is `opened`, `at` never
/// decreases, and the last receipt's state is the record's state. `None` when sound, else the reason.
pub fn undo_receipt_chain_error(record: &Value, expected_signer: &str) -> Option<String> {
    let rs = match record.get("receipts").and_then(Value::as_array) {
        Some(rs) if !rs.is_empty() => rs,
        _ => return Some("no receipts".into()),
    };
    let mut prev = String::new();
    let mut at = i64::MIN;
    for (i, r) in rs.iter().enumerate() {
        if !verify_undo_receipt(r, expected_signer) {
            return Some(format!("receipt {i} does not verify"));
        }
        if r.get("record") != record.get("id") || r.get("compensation_digest") != record.get("compensation_digest") {
            return Some(format!("receipt {i} is for another record"));
        }
        if r.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            return Some(format!("receipt {i} does not link to the previous one"));
        }
        if i == 0 && r.get("event").and_then(Value::as_str) != Some("opened") {
            return Some("the first receipt is not opened".into());
        }
        let t = r.get("at").and_then(safe_int).unwrap_or(i64::MIN);
        if t < at {
            return Some(format!("receipt {i} goes back in time"));
        }
        prev = match undo_receipt_digest(r) {
            Some(d) => d,
            None => return Some(format!("receipt {i} is not canonical")),
        };
        at = t;
    }
    if rs[rs.len() - 1].get("state") == record.get("state") {
        None
    } else {
        Some("the last receipt does not state the record state".into())
    }
}

// ---- the pure transitions -------------------------------------------------------------------------------------------------

/// The outcome of [`undo_transition`].
#[derive(Debug, Clone, PartialEq)]
pub enum UndoTransition {
    /// The next record (version bumped; the receipt is NOT appended: the store layer signs and links it) and the receipt's event
    /// and note.
    Applied { record: Value, event: &'static str, note: String },
    /// The same transition already happened (a retry): nothing to write.
    Replayed,
    /// `window_closed`, `window_open`, `finalized`, `not_vetoed`, `vetoed`, `effect_recorded`, `not_failed` or `invalid`.
    Refused { code: &'static str, reason: String },
}

fn refused(code: &'static str, reason: impl Into<String>) -> UndoTransition {
    UndoTransition::Refused { code, reason: reason.into() }
}

/// The first `n` UTF-16 code units of `s` (the reference's `String(x).slice(0, n)`; a split surrogate pair is dropped).
fn clip_units(s: &str, n: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        used += c.len_utf16();
        if used > n {
            break;
        }
        out.push(c);
    }
    out
}

/// The reference's `String(v)` of an event's `reason` (a string as is; absent = `undefined`).
fn reason_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(other) => crate::intent_v2::js_value_string(other),
        None => "undefined".into(),
    }
}

/// The record state machine, pure: `record` is not modified. Fields read: `state`, `window_end`, `ver`, `attempt`, `effect`
/// (present or absent) and `outcome.status`. `event` is `{kind: veto, veto: {at, via, by, evidence?}}`, `{kind: finalize}`,
/// `{kind: abort, reason}`, `{kind: effect, result?}`, `{kind: compensated, result?}`, `{kind: compensation_failed, reason}` or
/// `{kind: retry}`; `now` is the trusted server clock (a safe integer, else `invalid`). Every applied transition sets
/// `ver = ver + 1`. Total.
pub fn undo_transition(record: &Value, event: &Value, now: f64) -> UndoTransition {
    let Some(rec) = record.as_object() else { return refused("invalid", "malformed record") };
    let state = match str_of(rec, "state") {
        Some(s) if UNDO_STATES.contains(&s) => s,
        _ => return refused("invalid", "malformed record"),
    };
    let (Some(window_end), Some(ver)) = (rec.get("window_end").and_then(safe_int), rec.get("ver").and_then(safe_int)) else {
        return refused("invalid", "malformed record");
    };
    let Some(now) = safe_now(now) else { return refused("invalid", "now must be a safe integer") };
    let next = |patch: Vec<(&str, Value)>, ev: &'static str, note: String| {
        let mut r = rec.clone();
        for (k, v) in patch {
            r.insert(k.into(), v);
        }
        r.insert("ver".into(), json!(ver + 1));
        UndoTransition::Applied { record: Value::Object(r), event: ev, note }
    };
    let has_effect = rec.contains_key("effect");
    let with_result = |mut base: Value, result: Option<&Value>| {
        if let Some(r) = result {
            base["result"] = r.clone();
        }
        base
    };
    match event.get("kind").and_then(Value::as_str) {
        Some("veto") => {
            let v = event.get("veto");
            let ok = v.and_then(Value::as_object).is_some_and(|v| {
                v.get("at").and_then(safe_int).is_some()
                    && str_of(v, "via").is_some_and(|x| VETO_VIAS.contains(&x))
                    && str_of(v, "by").is_some_and(|x| !x.is_empty())
            });
            if !ok {
                return refused("invalid", "malformed veto");
            }
            match state {
                "vetoed" | "compensated" | "compensation_failed" => UndoTransition::Replayed,
                "finalized" => refused("finalized", "the window is closed and the action is final"),
                _ if now > window_end => refused("window_closed", format!("the veto window closed at {window_end}")),
                _ => {
                    let via = v.and_then(|v| v.get("via")).and_then(Value::as_str).unwrap_or("").to_string();
                    next(vec![("state", json!("vetoed")), ("veto", v.cloned().unwrap_or(Value::Null))], "vetoed", via)
                }
            }
        }
        Some("finalize") => match state {
            "finalized" => UndoTransition::Replayed,
            "open" if now <= window_end => refused("window_open", format!("the veto window is open until {window_end}")),
            "open" => next(vec![("state", json!("finalized")), ("outcome", json!({"at": now, "status": "finalized"}))], "finalized", String::new()),
            s => refused("vetoed", format!("a {s} record is not finalized")),
        },
        Some("abort") => {
            let aborted = rec.get("outcome").and_then(|o| o.get("status")).and_then(Value::as_str) == Some("aborted");
            if state == "finalized" && aborted {
                return UndoTransition::Replayed;
            }
            if state != "open" && state != "vetoed" {
                return refused("finalized", format!("a {state} record cannot be aborted"));
            }
            if has_effect {
                return refused("effect_recorded", "the effect ran: it can only be compensated or finalized");
            }
            let why = reason_text(event.get("reason"));
            next(
                vec![("state", json!("finalized")), ("outcome", json!({"at": now, "status": "aborted", "reason": clip_units(&why, 512)}))],
                "aborted",
                clip_units(&why, 128),
            )
        }
        Some("effect") => {
            if has_effect {
                return UndoTransition::Replayed;
            }
            if state != "open" && state != "vetoed" {
                return refused("finalized", format!("a {state} record takes no effect report"));
            }
            next(vec![("effect", with_result(json!({"at": now}), event.get("result")))], "effect", String::new())
        }
        Some("compensated") => match state {
            "compensated" => UndoTransition::Replayed,
            "vetoed" | "compensation_failed" => next(
                vec![("state", json!("compensated")), ("outcome", with_result(json!({"at": now, "status": "compensated"}), event.get("result")))],
                "compensated",
                String::new(),
            ),
            s => refused("not_vetoed", format!("a {s} record is not being compensated")),
        },
        Some("compensation_failed") => match state {
            "compensation_failed" => UndoTransition::Replayed,
            "vetoed" => {
                let why = reason_text(event.get("reason"));
                next(
                    vec![("state", json!("compensation_failed")), ("outcome", json!({"at": now, "status": "compensation_failed", "reason": clip_units(&why, 512)}))],
                    "compensation_failed",
                    clip_units(&why, 128),
                )
            }
            s => refused("not_vetoed", format!("a {s} record is not being compensated")),
        },
        Some("retry") => {
            if state != "compensation_failed" {
                return refused("not_failed", format!("a {state} record is not retried"));
            }
            // a malformed attempt counter cannot be incremented: refuse rather than invent one
            match rec.get("attempt").and_then(safe_int) {
                Some(a) => next(vec![("state", json!("vetoed")), ("attempt", json!(a + 1))], "retried", String::new()),
                None => refused("invalid", "malformed record"),
            }
        }
        _ => refused("invalid", "unknown event"),
    }
}

// ---- the window -----------------------------------------------------------------------------------------------------------

/// Host bounds for [`resolve_undo_window`] (each `None` = the protocol value).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UndoWindowPolicy {
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub default_ms: Option<f64>,
}

/// Clamp a requested window into `[max(30 s, min_ms), min(max_ms, 24 h)]` (a host maximum below the minimum is the minimum);
/// absent or non-finite -> `default_ms`, else 15 minutes. The result is floored to whole milliseconds.
pub fn resolve_undo_window(requested_ms: Option<f64>, policy: &UndoWindowPolicy) -> i64 {
    let min = (UNDO_MIN_WINDOW_MS as f64).max(policy.min_ms.unwrap_or(UNDO_MIN_WINDOW_MS as f64));
    let max = min.max(policy.max_ms.unwrap_or(UNDO_MAX_WINDOW_MS as f64).min(UNDO_MAX_WINDOW_MS as f64));
    let want = match requested_ms {
        Some(r) if r.is_finite() => r,
        _ => policy.default_ms.unwrap_or(UNDO_DEFAULT_WINDOW_MS as f64),
    };
    want.max(min).min(max).floor() as i64
}

// ---- the admission an authorize hook returns ---------------------------------------------------------------------------------

/// The compensating action of an admitted undo window (what a veto runs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoCompensationRef {
    pub verb: String,
    pub resource: String,
}

/// An escalation converted into an undo window by the `authorize` undo hook (see `AuthorizeInput::undo`): the durable record `id`,
/// the window end (epoch ms) and the compensation a veto runs. The hook returns one ONLY after the window's record is durably
/// opened by the caller's undo coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoAdmission {
    pub id: String,
    pub window_end: i64,
    pub compensation: UndoCompensationRef,
}

impl UndoAdmission {
    /// The `undo_window` obligation an allow under this window carries: `{kind: "undo_window", params: {id, window_end}, due: window_end}`.
    pub fn obligation(&self) -> Value {
        json!({"kind": "undo_window", "params": {"id": self.id, "window_end": self.window_end}, "due": self.window_end})
    }
}
