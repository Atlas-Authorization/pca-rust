//! Shared Signals Framework (SSF / CAEP) for PCA: build and verify Security Event Tokens (RFC 8417, EdDSA), the subscriber-side
//! revocation state, the replay-guarded receive path, standard CAEP / RISC revocations, the `authorize()` revocation adapters,
//! snapshot / restore, SSF stream health, verification, poll queue and push responses, CAEP level-change events, and the SSF
//! stream management API.
//!
//! JSON-valued like the other ported packages: options and events cross as `serde_json::Value` with the reference's member names;
//! refusal texts are the reference's own. Differences from the reference, all fail-closed or by construction:
//! - keys are a 32-byte Ed25519 seed (signing) and a public JWK (verifying); there is no key-object type to misuse;
//! - a revocation state is a typed struct, so the reference's "state must come from createRevocationState()" check cannot fail;
//! - an `events` map given to `build_set` as an array is refused (the reference builds a token its own verifier rejects);
//! - description text is cut at 256 UTF-16 units and a cut inside a surrogate pair yields U+FFFD (a Rust string cannot hold a lone
//!   surrogate).
use crate::intent_v2::js_number_string;
use crate::jose::{self, now_unix_sec};
use crate::oauth::truthy;
use crate::sdjwt::{jwt_verify_with, Claims, SdJwtKey};
use crate::serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fmt;

pub const SET_TYP: &str = "secevent+jwt";
pub const SET_ALG: &str = "EdDSA";
pub const SET_INMEMORY_MAX_ENTRIES: f64 = 100_000.0;
pub const DELIVERY_PUSH: &str = "urn:ietf:rfc:8935";
pub const DELIVERY_POLL: &str = "urn:ietf:rfc:8936";
pub const STREAM_STATUSES: [&str; 3] = ["enabled", "paused", "disabled"];

pub const EV_SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
pub const EV_CREDENTIAL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
pub const EV_GRANT_REVOKED: &str = "https://atlasauth.net/caep/grant-revoked";
pub const EV_KILL_SWITCH: &str = "https://atlasauth.net/caep/kill-switch";
pub const EV_INTENT_REVOKED: &str = "https://atlasauth.net/caep/intent-revoked";
pub const EV_VERIFICATION: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";
pub const EV_RISK_LEVEL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
pub const EV_ASSURANCE_LEVEL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

pub const RISC_SESSIONS_REVOKED: &str = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";
pub const RISC_ACCOUNT_DISABLED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
pub const RISC_ACCOUNT_PURGED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
pub const RISC_CREDENTIAL_COMPROMISE: &str = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
const RISC_TYPES: [&str; 4] = [RISC_SESSIONS_REVOKED, RISC_ACCOUNT_DISABLED, RISC_ACCOUNT_PURGED, RISC_CREDENTIAL_COMPROMISE];

/// The package constants as one JSON object (`EVENT_TYPES`, `RISC_EVENT_TYPES`, the delivery URIs, ...).
pub fn constants() -> Value {
    json!({
        "SET_TYP": SET_TYP,
        "SET_ALG": SET_ALG,
        "EVENT_TYPES": {
            "sessionRevoked": EV_SESSION_REVOKED, "credentialChange": EV_CREDENTIAL_CHANGE, "grantRevoked": EV_GRANT_REVOKED,
            "killSwitch": EV_KILL_SWITCH, "intentRevoked": EV_INTENT_REVOKED, "verification": EV_VERIFICATION,
            "riskLevelChange": EV_RISK_LEVEL_CHANGE, "assuranceLevelChange": EV_ASSURANCE_LEVEL_CHANGE,
        },
        "RISC_EVENT_TYPES": {
            "sessionsRevoked": RISC_SESSIONS_REVOKED, "accountDisabled": RISC_ACCOUNT_DISABLED,
            "accountPurged": RISC_ACCOUNT_PURGED, "credentialCompromise": RISC_CREDENTIAL_COMPROMISE,
        },
        "SET_INMEMORY_MAX_ENTRIES": 100000,
        "DELIVERY_PUSH": DELIVERY_PUSH,
        "DELIVERY_POLL": DELIVERY_POLL,
        "STREAM_STATUSES": STREAM_STATUSES,
    })
}

/// A refusal. `code` is the reference's `SignalsError.code` (`misconfigured`, `bad_snapshot`, `unmapped_subject`); a plain
/// error or a JavaScript runtime error carries none.
#[derive(Debug, Clone, PartialEq)]
pub struct SignalsError {
    pub code: Option<&'static str>,
    pub message: String,
}

impl SignalsError {
    fn plain(m: impl Into<String>) -> Self {
        SignalsError { code: None, message: m.into() }
    }
    fn coded(code: &'static str, m: impl Into<String>) -> Self {
        SignalsError { code: Some(code), message: m.into() }
    }
}

impl fmt::Display for SignalsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SignalsError {}

// ---------------------------------------------------------------------------------------------------- JavaScript helpers

/// JavaScript `\s` (WhiteSpace + LineTerminator).
fn js_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `/^https:\/\/[^\s]+$/`.
fn https_url_ok(s: &str) -> bool {
    s.strip_prefix("https://").is_some_and(|r| !r.is_empty() && !r.chars().any(js_ws))
}

fn num_value(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

/// `typeof x === 'number'` -> the number.
fn number(v: Option<&Value>) -> Option<f64> {
    v.filter(|x| x.is_number()).and_then(Value::as_f64)
}

fn is_safe_nonneg_int(f: f64) -> bool {
    f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 && f >= 0.0 && !(f == 0.0 && f.is_sign_negative())
}

/// `Object.entries(v)`: object members, array elements by index, string characters; anything else has none.
fn entries(v: &Value) -> Vec<(String, Value)> {
    match v {
        Value::Object(m) => m.iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => Vec::new(),
    }
}

/// `Object.entries(parsed.events)`; a missing / null `events` (or a non-object `parsed`) is a TypeError.
fn events_of(parsed: &Value) -> Result<Vec<(String, Value)>, SignalsError> {
    match parsed.get("events") {
        None | Some(Value::Null) => Err(SignalsError::plain("Cannot convert undefined or null to object")),
        Some(e) => Ok(entries(e)),
    }
}

/// `typeof ev.event_timestamp === 'number' ? it : 0`; reading a member of `null` is a TypeError.
fn event_ts(ev: &Value) -> Result<f64, SignalsError> {
    if ev.is_null() {
        return Err(SignalsError::plain("Cannot read properties of null (reading 'event_timestamp')"));
    }
    Ok(number(ev.get("event_timestamp")).unwrap_or(0.0))
}

fn uuid_v4() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

fn norm_typ(t: &str) -> String {
    let l = t.to_lowercase();
    l.strip_prefix("application/").map(String::from).unwrap_or(l)
}

// ---------------------------------------------------------------------------------------------------- build / verify a SET

/// `buildSET({events, issuer, audience, subject?, key})`: an EdDSA-signed SET (`typ: secevent+jwt`) with a random `jti` and the
/// wall-clock `iat`. `args` carries `events` (non-empty object), `issuer`, `audience`, optional `subject`; `seed` is the
/// transmitter's Ed25519 seed.
pub fn build_set(args: &Value, seed: &[u8; 32]) -> Result<String, String> {
    let events = match args.get("events") {
        // shortcut: an array `events` is refused; the reference signs it and then fails its own verification
        Some(Value::Object(m)) if !m.is_empty() => m.clone(),
        _ => return Err("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)".into()),
    };
    let subject = args.get("subject");
    let mut p = Map::new();
    p.insert("events".into(), Value::Object(events));
    if let Some(s) = subject {
        p.insert("sub_id".into(), json!({ "format": "opaque", "id": s }));
    }
    if let Some(i) = args.get("issuer") {
        p.insert("iss".into(), i.clone());
    }
    p.insert("iat".into(), num_value(now_unix_sec()));
    p.insert("jti".into(), Value::String(uuid_v4()?));
    if let Some(a) = args.get("audience") {
        p.insert("aud".into(), a.clone());
    }
    if let Some(s) = subject {
        p.insert("sub".into(), s.clone());
    }
    Ok(jose::sign_ed25519_jws(&json!({ "alg": SET_ALG, "typ": SET_TYP }), &Value::Object(p), seed))
}

fn parse_events(raw: Option<&Value>) -> Result<Value, String> {
    let Some(Value::Object(m)) = raw else { return Err("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)".into()) };
    if m.is_empty() {
        return Err("SET invalid: `events` claim is empty (RFC 8417 §2.2)".into());
    }
    for (k, v) in m {
        if !v.is_object() {
            return Err(format!("SET invalid: event payload for `{k}` is not a JSON object (RFC 8417 §2.2)"));
        }
    }
    Ok(Value::Object(m.clone()))
}

/// `verifySET(set, key, opts)`: canonical compact JWS, EdDSA signature under the public JWK `key`, `typ`, `iss` / `aud` / time
/// claims, then the SET shape. `opts` members: `issuer`, `audience`, `clockTolerance`, `currentDate` (epoch ms), `typ`,
/// `requireTyp`. Returns `{events, iss, jti, sub?, payload}`. A `null` options value is a TypeError, as in the reference.
pub fn verify_set(set: &Value, key: &Value, opts: &Value) -> Result<Value, String> {
    let empty = Map::new();
    let o = match opts {
        Value::Object(m) => m,
        Value::Null => return Err("Cannot read properties of null (reading 'issuer')".into()),
        _ => &empty,
    };
    let jws = jose::assert_canonical_compact_jws(set, 3, jose::DEFAULT_MAX_JWS_BYTES, true)?;
    let now_sec = match o.get("currentDate") {
        None => now_unix_sec(),
        Some(v) => (v.as_f64().ok_or("Invalid time value")? / 1000.0).floor(),
    };
    let want_typ: Option<String> = if o.get("requireTyp") == Some(&Value::Bool(false)) {
        None
    } else {
        match o.get("typ") {
            None | Some(Value::Null) => Some(SET_TYP.to_string()),
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("typ must be a string".into()),
        }
    };
    let claims = Claims { audience: o.get("audience"), tolerance: o.get("clockTolerance"), now_sec };
    jwt_verify_with(&jws, &|_| Ok(SdJwtKey::Jwk(key.clone())), &json!([SET_ALG]), &claims)?;
    if let Some(t) = want_typ.filter(|t| !t.is_empty()) {
        if !jws.header.get("typ").and_then(Value::as_str).is_some_and(|h| norm_typ(h) == norm_typ(&t)) {
            return Err("unexpected \"typ\" JWT header value".into());
        }
    }
    let payload = jws.payload.as_ref().expect("json payload");
    if let Some(iv) = o.get("issuer") {
        if !payload.contains_key("iss") {
            return Err("missing required \"iss\" claim".into());
        }
        if truthy(Some(iv)) {
            let list: Vec<&Value> = match iv {
                Value::Array(a) => a.iter().collect(),
                v => vec![v],
            };
            let iss = payload.get("iss");
            if !list.iter().any(|x| !x.is_object() && !x.is_array() && Some(*x) == iss) {
                return Err("unexpected \"iss\" claim value".into());
            }
        }
    }
    let Some(iss) = payload.get("iss").and_then(Value::as_str) else { return Err("SET invalid: missing or non-string `iss`".into()) };
    let Some(jti) = payload.get("jti").and_then(Value::as_str) else {
        return Err("SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)".into());
    };
    let events = parse_events(payload.get("events"))?;
    let mut out = Map::new();
    out.insert("events".into(), events);
    out.insert("iss".into(), Value::String(iss.to_string()));
    out.insert("jti".into(), Value::String(jti.to_string()));
    if let Some(sub) = payload.get("sub").filter(|s| s.is_string()) {
        out.insert("sub".into(), sub.clone());
    }
    out.insert("payload".into(), Value::Object(payload.clone()));
    Ok(Value::Object(out))
}

// ---------------------------------------------------------------------------------------------------- revocation state

/// An insertion-ordered map from key to the max event timestamp seen (a JavaScript `Map<string, number>`).
#[derive(Debug, Clone, Default)]
pub struct TsMap {
    items: Vec<(String, f64)>,
    index: HashMap<String, usize>,
}

impl TsMap {
    pub fn contains(&self, k: &str) -> bool {
        self.index.contains_key(k)
    }
    pub fn get(&self, k: &str) -> Option<f64> {
        self.index.get(k).map(|i| self.items[*i].1)
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    /// Entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> {
        self.items.iter().map(|(k, v)| (k.as_str(), *v))
    }
    /// Revocation is monotone: a key keeps the max timestamp seen and is never removed.
    pub fn record_max(&mut self, k: &str, ts: f64) {
        match self.index.get(k) {
            Some(i) => {
                if ts > self.items[*i].1 {
                    self.items[*i].1 = ts;
                }
            }
            None => {
                self.index.insert(k.to_string(), self.items.len());
                self.items.push((k.to_string(), ts));
            }
        }
    }
    fn pairs(&self) -> Value {
        Value::Array(self.items.iter().map(|(k, v)| json!([k, num_value(*v)])).collect())
    }
}

/// Subscriber-side revocation state: revoked grants, killed agents, and (created on first use) revoked intent ids.
#[derive(Debug, Clone, Default)]
pub struct RevocationState {
    pub revoked_grants: TsMap,
    pub killed_agents: TsMap,
    pub revoked_intent_ids: Option<TsMap>,
}

pub fn create_revocation_state() -> RevocationState {
    RevocationState::default()
}

fn nonempty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// `applySET`: fold a parsed SET into the state (max timestamp per key, monotone). A null event payload is a TypeError raised
/// at that entry; entries before it stay applied, as in the reference.
pub fn apply_set(state: &mut RevocationState, parsed: &Value) -> Result<(), SignalsError> {
    for (ty, ev) in events_of(parsed)? {
        let ts = event_ts(&ev)?;
        if ty == EV_GRANT_REVOKED {
            if let Some(g) = nonempty_str(ev.get("grant_ref")) {
                state.revoked_grants.record_max(g, ts);
            }
        } else if ty == EV_KILL_SWITCH {
            if let Some(a) = nonempty_str(ev.get("agent")) {
                state.killed_agents.record_max(a, ts);
            }
            if let Some(g) = nonempty_str(ev.get("grant_ref")) {
                state.revoked_grants.record_max(g, ts);
            }
        } else if ty == EV_INTENT_REVOKED {
            if let Some(Value::Array(ids)) = ev.get("ids") {
                for id in ids.iter().filter_map(Value::as_str).filter(|s| s.starts_with("pca-intent:")) {
                    state.revoked_intent_ids.get_or_insert_with(TsMap::default).record_max(id, ts);
                }
            }
        }
    }
    Ok(())
}

pub fn is_intent_revoked(state: &RevocationState, id: &str) -> bool {
    state.revoked_intent_ids.as_ref().is_some_and(|m| m.contains(id))
}

pub fn is_revoked(state: &RevocationState, grant_ref: &str, agent: Option<&str>) -> bool {
    state.revoked_grants.contains(grant_ref) || agent.is_some_and(|a| state.killed_agents.contains(a))
}

fn set_timestamp(p: &Value) -> Result<f64, SignalsError> {
    let mut min = f64::INFINITY;
    for (_, ev) in events_of(p)? {
        if ev.is_null() {
            return Err(SignalsError::plain("Cannot read properties of null (reading 'event_timestamp')"));
        }
        if let Some(t) = number(ev.get("event_timestamp")) {
            if t < min {
                min = t;
            }
        }
    }
    Ok(if min.is_finite() { min } else { 0.0 })
}

/// `streamProcessor`: fold SETs into `state` in ascending `event_timestamp` order (stable). `sets` must be an array (a string
/// spreads to its characters, as in the reference; anything else is not iterable).
pub fn stream_processor(sets: &Value, state: &mut RevocationState) -> Result<(), SignalsError> {
    let items: Vec<Value> = match sets {
        Value::Array(a) => a.clone(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        _ => return Err(SignalsError::plain("parsedSets is not iterable")),
    };
    let mut keyed: Vec<(f64, Value)> = Vec::with_capacity(items.len());
    // a one-element sort never calls its comparator, so the timestamp is only read when there are two or more
    for it in items.iter() {
        keyed.push((if items.len() > 1 { set_timestamp(it)? } else { 0.0 }, it.clone()));
    }
    keyed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    for (_, p) in &keyed {
        apply_set(state, p)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------- replay store

/// A `jti` replay store for received SETs. `add_if_absent` must be atomic; an entry may be dropped once `now >= expires`.
pub trait SetReplayStore {
    fn add_if_absent(&mut self, jti: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String>;
}

/// Single-process, bounded store: when `max_entries` live entries are held a further new `jti` is an error, never an eviction.
#[derive(Debug, Clone)]
pub struct InMemorySetReplayStore {
    max: f64,
    seen: HashMap<String, f64>,
}

/// `createInMemorySetReplayStore(opts)`: `opts` (None = `{}`) may carry `maxEntries` (a positive integer; absent or null = 100000).
pub fn create_in_memory_set_replay_store(opts: Option<&Value>) -> Result<InMemorySetReplayStore, SignalsError> {
    let max = match opts {
        None => Value::Null,
        Some(Value::Null) => return Err(SignalsError::plain("Cannot read properties of null (reading 'maxEntries')")),
        Some(o) => o.get("maxEntries").cloned().unwrap_or(Value::Null),
    };
    let max = if max.is_null() {
        SET_INMEMORY_MAX_ENTRIES
    } else {
        number(Some(&max))
            .filter(|f| f.fract() == 0.0 && *f >= 1.0)
            .ok_or_else(|| SignalsError::coded("misconfigured", "maxEntries must be a positive integer"))?
    };
    Ok(InMemorySetReplayStore { max, seen: HashMap::new() })
}

impl SetReplayStore for InMemorySetReplayStore {
    fn add_if_absent(&mut self, jti: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String> {
        if !now_sec.is_finite() || !expires_at_sec.is_finite() {
            return Ok(false);
        }
        let held = self.seen.get(jti).copied();
        if held.is_some_and(|h| !(now_sec >= h)) {
            return Ok(false);
        }
        if held.is_none() && self.seen.len() as f64 >= self.max {
            self.seen.retain(|_, exp| !(now_sec >= *exp));
            if self.seen.len() as f64 >= self.max {
                return Err("replay store is full".into());
            }
        }
        self.seen.insert(jti.to_string(), expires_at_sec);
        Ok(true)
    }
}

/// `runSetReplayStoreConformance(make)`: the failed checks (empty = conformant). `make` returns a FRESH empty store each call. A
/// store error propagates, as the reference's rejection does.
pub fn run_set_replay_store_conformance(make: &mut dyn FnMut() -> Box<dyn SetReplayStore>) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    let mut check = |ok: bool, name: &str| {
        if !ok {
            failures.push(name.to_string());
        }
    };
    let mut s = make();
    check(s.add_if_absent("a", 200.0, 100.0)?, "first sight of a jti returns true");
    check(!s.add_if_absent("a", 200.0, 101.0)?, "second sight of the same jti returns false");
    check(s.add_if_absent("b", 200.0, 101.0)?, "a different jti is independent");
    check(!s.add_if_absent("a", 200.0, 199.0)?, "still seen one second before expiry");
    let mut t = make();
    t.add_if_absent("c", 200.0, 100.0)?;
    check(t.add_if_absent("c", 400.0, 200.0)?, "an expired entry may be added again (nowSec >= expiresAtSec)");
    let mut u = make();
    let mut wins = 0;
    for _ in 0..16 {
        if u.add_if_absent("race", 200.0, 100.0)? {
            wins += 1;
        }
    }
    check(wins == 1, &format!("16 concurrent adds of one jti: exactly one wins (got {wins})"));
    Ok(failures)
}

// ---------------------------------------------------------------------------------------------------- standard revocations

/// How standard events become revocation entries. `subject_to_agent` returns the agent id, or `None` when the subject names no
/// agent (a mapper that throws or returns a non-string is `None`); the default maps an `opaque` subject's `id`.
#[derive(Default)]
pub struct StdOptions<'a> {
    pub subject_to_agent: Option<&'a dyn Fn(&Value) -> Option<String>>,
    pub fail_on_unmapped: bool,
}

/// What [`plan_standard_revocations`] decided.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StdPlan {
    pub agents: Vec<(String, f64)>,
    pub unmapped: Vec<String>,
}

impl StdPlan {
    pub fn to_value(&self) -> Value {
        json!({
            "agents": self.agents.iter().map(|(a, t)| json!([a, num_value(*t)])).collect::<Vec<_>>(),
            "unmapped": self.unmapped,
        })
    }
}

fn default_subject_to_agent(s: &Value) -> Option<String> {
    (s.get("format").and_then(Value::as_str) == Some("opaque")).then(|| nonempty_str(s.get("id")).map(String::from)).flatten()
}

fn is_revoking_standard_event(ty: &str, ev: &Value) -> Result<bool, SignalsError> {
    if ty == EV_SESSION_REVOKED {
        return Ok(true);
    }
    if ty == EV_CREDENTIAL_CHANGE {
        if ev.is_null() {
            return Err(SignalsError::plain("Cannot read properties of null (reading 'change_type')"));
        }
        return Ok(ev.get("change_type").and_then(Value::as_str) != Some("create"));
    }
    Ok(RISC_TYPES.contains(&ty))
}

/// `planStandardRevocations`: which agents a verified SET's CAEP session-revoked / credential-change (any change but `create`)
/// and RISC events revoke, without touching any state.
pub fn plan_standard_revocations(parsed: &Value, opts: &StdOptions) -> Result<StdPlan, SignalsError> {
    let payload = match parsed.get("payload") {
        None | Some(Value::Null) => return Err(SignalsError::plain("Cannot read properties of undefined (reading 'sub_id')")),
        Some(p) => p,
    };
    let set_subject = payload.get("sub_id").filter(|s| s.is_object());
    let mut plan = StdPlan::default();
    for (ty, ev) in events_of(parsed)? {
        if !is_revoking_standard_event(&ty, &ev)? {
            continue;
        }
        if ev.is_null() {
            return Err(SignalsError::plain("Cannot read properties of null (reading 'subject')"));
        }
        let own = ev.get("subject").filter(|s| s.is_object()).or(set_subject);
        let mut agent: Option<String> = None;
        if let Some(own) = own.filter(|o| o.get("format").is_some_and(Value::is_string)) {
            agent = match opts.subject_to_agent {
                Some(f) => f(own),
                None => default_subject_to_agent(own),
            };
        }
        match agent.filter(|a| !a.is_empty()) {
            None => {
                if opts.fail_on_unmapped {
                    return Err(SignalsError::coded("unmapped_subject", format!("event '{ty}' names no mappable agent")));
                }
                plan.unmapped.push(ty);
            }
            Some(a) => plan.agents.push((a, number(ev.get("event_timestamp")).unwrap_or(0.0))),
        }
    }
    Ok(plan)
}

fn apply_standard_plan(state: &mut RevocationState, plan: &StdPlan) {
    for (a, ts) in &plan.agents {
        state.killed_agents.record_max(a, *ts);
    }
}

/// `applyStandardRevocations`: plan, then apply (monotone, max timestamp). Returns the plan that was applied.
pub fn apply_standard_revocations(state: &mut RevocationState, parsed: &Value, opts: &StdOptions) -> Result<StdPlan, SignalsError> {
    let plan = plan_standard_revocations(parsed, opts)?;
    apply_standard_plan(state, &plan);
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------------- receive

/// The recommended receive path: size cap, canonical spelling, EdDSA signature, `typ`, `iss` and `aud`, `iat` freshness, the
/// atomic `jti` replay guard, then the fold into `state`. Every refusal is a value `{ok: false, code, reason}`; a store that
/// errors refuses too (`replay_store_error`) and the SET is not applied. `opts` members: `issuer`, `audience`, `maxAgeSec`
/// (required), `clockSkewSec`, `nowSec`, `maxBytes`. A missing store or state is `misconfigured`.
pub fn receive_set(
    set: &Value,
    key: &Value,
    opts: Option<&Value>,
    store: Option<&mut dyn SetReplayStore>,
    state: Option<&mut RevocationState>,
    std_opts: Option<&StdOptions>,
) -> Value {
    fn fails(code: &str, reason: impl Into<String>) -> Value {
        json!({ "ok": false, "code": code, "reason": reason.into() })
    }
    let max_age = opts.and_then(|o| number(o.get("maxAgeSec"))).filter(|m| *m > 0.0);
    let (Some(o), Some(store), Some(state), Some(max_age)) = (opts.filter(|o| o.is_object()), store, state, max_age) else {
        return fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required");
    };
    if o.get("issuer").is_none() || o.get("audience").is_none() {
        return fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required");
    }
    let max_bytes = match o.get("maxBytes") {
        None | Some(Value::Null) => 16384.0,
        Some(v) => v.as_f64().unwrap_or(f64::NAN),
    };
    let Some(set_str) = set.as_str().filter(|s| (s.encode_utf16().count() as f64) <= max_bytes) else {
        return fails("oversize", "SET is not a string or exceeds maxBytes");
    };
    let _ = set_str;
    if let Err(e) = jose::assert_canonical_compact_jws(set, 3, jose::DEFAULT_MAX_JWS_BYTES, true) {
        return fails("malformed", e);
    }
    let now_sec = number(o.get("nowSec")).unwrap_or_else(now_unix_sec);
    let vopts = json!({ "issuer": o["issuer"], "audience": o["audience"], "currentDate": now_sec * 1000.0 });
    let parsed = match verify_set(set, key, &vopts) {
        Ok(p) => p,
        Err(e) => return fails("verify_failed", e),
    };
    let Some(iat) = number(parsed["payload"].get("iat")) else { return fails("iat_missing", "SET has no numeric iat") };
    let skew = number(o.get("clockSkewSec")).unwrap_or(60.0);
    if !(now_sec.is_finite() && skew.is_finite() && iat <= now_sec + skew) {
        return fails("iat_future", "SET iat is in the future");
    }
    if !(now_sec - iat <= max_age) {
        return fails("iat_stale", format!("SET is older than {}s", js_number_string(max_age)));
    }
    let plan = match std_opts {
        Some(so) => match plan_standard_revocations(&parsed, so) {
            Ok(p) => Some(p),
            Err(e) => return fails("unmapped_subject", e.message),
        },
        None => None,
    };
    let jti = parsed["jti"].as_str().unwrap_or("");
    let fresh = match store.add_if_absent(jti, iat + max_age + skew, now_sec) {
        Ok(f) => f,
        Err(e) => return fails("replay_store_error", e),
    };
    if !fresh {
        return fails("replay", format!("jti '{jti}' has already been received"));
    }
    let _ = apply_set(state, &parsed);
    if let Some(p) = &plan {
        apply_standard_plan(state, p);
    }
    json!({ "ok": true, "parsed": parsed })
}

// ---------------------------------------------------------------------------------------------------- authorize() adapters

/// The agent id a kill-switch names for a verification context: `None` when it cannot be determined; `Err` is a throw
/// (fail closed). Default: the PCActn's leaf holder.
pub type AgentOf<'a> = &'a dyn Fn(&Value, &Value) -> Result<Option<String>, String>;

fn leaf_holder_agent(pcactn: &Value, _grant: &Value) -> Result<Option<String>, String> {
    let chain = match pcactn.get("cap_chain") {
        None | Some(Value::Null) => return Err("Cannot read properties of undefined (reading 'length')".into()),
        Some(c) => c,
    };
    Ok(match chain {
        Value::Array(a) => a.last().and_then(|l| l.get("holder")).and_then(Value::as_str).map(String::from),
        _ => None,
    })
}

/// The reason a PCActn under `grant` is revoked by `state`, or `None` when it is not. Anything undecidable is a reason.
pub fn revocation_reason(state: &RevocationState, pcactn: &Value, grant: &Value, agent_of: Option<AgentOf>) -> Option<String> {
    if pcactn.is_null() {
        return Some("revocation check error (fail closed)".into());
    }
    let Some(r) = nonempty_str(pcactn.get("grant_ref")) else { return Some("grant_ref is missing".into()) };
    if state.revoked_grants.contains(r) {
        return Some("grant revoked by signal".into());
    }
    if grant.get("id").and_then(Value::as_str).is_some_and(|g| state.revoked_grants.contains(g)) {
        return Some("grant revoked by signal".into());
    }
    let agent = match agent_of {
        Some(f) => f(pcactn, grant),
        None => leaf_holder_agent(pcactn, grant),
    };
    match agent {
        Err(_) => Some("revocation check error (fail closed)".into()),
        Ok(a) => match a.filter(|s| !s.is_empty()) {
            None => Some("agent could not be determined".into()),
            Some(a) if state.killed_agents.contains(&a) => Some("agent killed by signal".into()),
            Some(_) => None,
        },
    }
}

/// The `hooks.revocation` result: always `enforced`; a revoked or undeterminable grant denies with its reason.
pub fn revocation_hook(state: &RevocationState, pcactn: &Value, grant: &Value, agent_of: Option<AgentOf>) -> Value {
    match revocation_reason(state, pcactn, grant, agent_of) {
        None => json!({ "enforced": true, "ok": true }),
        Some(r) => json!({ "enforced": true, "ok": false, "reason": r }),
    }
}

/// `createIsRevoked`: true when revoked or when the answer cannot be determined (fail closed).
pub fn is_revoked_adapter(state: &RevocationState, grant: &Value, pcactn: &Value, agent_of: Option<AgentOf>) -> bool {
    revocation_reason(state, pcactn, grant, agent_of).is_some()
}

// ---------------------------------------------------------------------------------------------------- snapshot / restore

/// A serialisable copy of the state, for the caller to persist after every accepted SET.
pub fn snapshot_revocation_state(state: &RevocationState) -> Value {
    json!({
        "v": 1,
        "grants": state.revoked_grants.pairs(),
        "agents": state.killed_agents.pairs(),
        "intents": state.revoked_intent_ids.as_ref().map_or_else(|| json!([]), TsMap::pairs),
    })
}

fn snapshot_pairs(v: Option<&Value>, what: &str) -> Result<Vec<(String, f64)>, SignalsError> {
    let Some(Value::Array(a)) = v else { return Err(SignalsError::coded("bad_snapshot", format!("{what} is not an array"))) };
    a.iter()
        .map(|p| {
            let ok = p.as_array().filter(|x| x.len() == 2).and_then(|x| Some((nonempty_str(x.first())?.to_string(), number(x.get(1))?)));
            ok.ok_or_else(|| SignalsError::coded("bad_snapshot", format!("{what} holds an entry that is not [string, number]")))
        })
        .collect()
}

fn js_index_key(k: &str) -> Option<u32> {
    let n: u32 = k.parse().ok()?;
    (n != u32::MAX && n.to_string() == k).then_some(n)
}

/// `restoreRevocationState`: merge a snapshot into `into`. Strict: any shape error is `bad_snapshot` and `into` is untouched.
/// Merging is monotone, so restoring never un-revokes anything.
pub fn restore_revocation_state(snapshot: &Value, into: &mut RevocationState) -> Result<(), SignalsError> {
    let bad = || SignalsError::coded("bad_snapshot", "snapshot is not a version 1 object");
    let Value::Object(m) = snapshot else { return Err(bad()) };
    if number(m.get("v")) != Some(1.0) {
        return Err(bad());
    }
    let mut idx: Vec<(u32, &String)> = m.keys().filter_map(|k| js_index_key(k).map(|n| (n, k))).collect();
    idx.sort();
    let ordered = idx.into_iter().map(|(_, k)| k).chain(m.keys().filter(|k| js_index_key(k).is_none()));
    if let Some(extra) = ordered.filter(|k| !["v", "grants", "agents", "intents"].contains(&k.as_str())).next() {
        return Err(SignalsError::coded("bad_snapshot", format!("snapshot has unknown member '{extra}'")));
    }
    let grants = snapshot_pairs(m.get("grants"), "grants")?;
    let agents = snapshot_pairs(m.get("agents"), "agents")?;
    let intents = snapshot_pairs(m.get("intents"), "intents")?;
    for (k, t) in grants {
        into.revoked_grants.record_max(&k, t);
    }
    for (k, t) in agents {
        into.killed_agents.record_max(&k, t);
    }
    for (k, t) in intents {
        into.revoked_intent_ids.get_or_insert_with(TsMap::default).record_max(&k, t);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------- SSF stream

/// `validateStreamConfig`: the list of problems (empty = valid).
pub fn validate_stream_config(c: &Value) -> Vec<String> {
    let Some(o) = c.as_object() else { return vec!["not an object".into()] };
    let non_empty = |v: Option<&Value>| nonempty_str(v).is_some();
    fn strs(v: Option<&Value>) -> Option<Vec<&str>> {
        v?.as_array()?.iter().map(|x| x.as_str().filter(|s| !s.is_empty())).collect()
    }
    let mut e: Vec<String> = Vec::new();
    if !non_empty(o.get("stream_id")) {
        e.push("stream_id is required".into());
    }
    if !non_empty(o.get("iss")) {
        e.push("iss is required".into());
    }
    let aud = o.get("aud");
    if !(non_empty(aud) || aud.and_then(Value::as_array).is_some_and(|a| !a.is_empty() && a.iter().all(|x| non_empty(Some(x))))) {
        e.push("aud must be a non-empty string or array".into());
    }
    let delivered = strs(o.get("events_delivered"));
    if delivered.as_ref().is_none_or(|d| d.is_empty()) {
        e.push("events_delivered must be a non-empty array of event type URIs".into());
    }
    let supported = strs(o.get("events_supported"));
    if o.get("events_supported").is_some() && supported.is_none() {
        e.push("events_supported must be an array of URIs".into());
    }
    if o.get("events_requested").is_some() && strs(o.get("events_requested")).is_none_or(|r| r.is_empty()) {
        e.push("events_requested must be a non-empty array of URIs".into());
    }
    if let (Some(d), Some(s)) = (&delivered, &supported) {
        if !d.iter().all(|x| s.contains(x)) {
            e.push("events_delivered must be a subset of events_supported".into());
        }
    }
    let d = o.get("delivery").filter(|d| truthy(Some(d)));
    let method = d.and_then(|d| d.get("method")).and_then(Value::as_str);
    match d {
        Some(d) if method == Some(DELIVERY_PUSH) || method == Some(DELIVERY_POLL) => {
            if !d.get("endpoint_url").and_then(Value::as_str).is_some_and(https_url_ok) {
                e.push("delivery.endpoint_url must be an https URL".into());
            }
        }
        _ => e.push("delivery.method must be the RFC 8935 or RFC 8936 URI".into()),
    }
    if let Some(m) = o.get("min_verification_interval") {
        if !number(Some(m)).is_some_and(is_safe_nonneg_int) {
            e.push("min_verification_interval must be a non-negative integer (seconds)".into());
        }
    }
    e
}

/// Tunables of [`StreamHealth`] (`None` = the default: 60 s verify timeout, 300 s verified window, 3 failures, 16 pending).
#[derive(Debug, Clone, Default)]
pub struct StreamHealthOptions {
    pub verify_timeout_sec: Option<f64>,
    pub verified_within_sec: Option<f64>,
    pub fail_after: Option<f64>,
    pub max_pending: Option<f64>,
}

impl StreamHealthOptions {
    /// From the reference's option object (`verifyTimeoutSec`, `verifiedWithinSec`, `failAfter`, `maxPending`).
    pub fn from_value(v: &Value) -> Self {
        StreamHealthOptions {
            verify_timeout_sec: number(v.get("verifyTimeoutSec")),
            verified_within_sec: number(v.get("verifiedWithinSec")),
            fail_after: number(v.get("failAfter")),
            max_pending: number(v.get("maxPending")),
        }
    }
}

/// Health of one stream: status, last event / verification, pending verification states, consecutive timeouts.
#[derive(Debug, Clone)]
pub struct StreamHealth {
    min_interval: f64,
    o: StreamHealthOptions,
    status: &'static str,
    last_event: Option<f64>,
    last_verified: Option<f64>,
    last_requested: Option<f64>,
    fails: u64,
    rejected: u64,
    pending: HashMap<String, f64>,
}

impl StreamHealth {
    pub fn new(config: &Value, o: StreamHealthOptions) -> Self {
        StreamHealth {
            min_interval: number(config.get("min_verification_interval")).unwrap_or(0.0),
            o,
            status: "enabled",
            last_event: None,
            last_verified: None,
            last_requested: None,
            fails: 0,
            rejected: 0,
            pending: HashMap::new(),
        }
    }

    pub fn set_status(&mut self, s: &Value) -> Result<(), String> {
        match s.as_str().and_then(|x| STREAM_STATUSES.iter().find(|k| **k == x)) {
            Some(k) => {
                self.status = k;
                Ok(())
            }
            None => Err("unknown stream status".into()),
        }
    }

    pub fn record_event(&mut self, now: f64) {
        self.last_event = Some(self.last_event.unwrap_or(0.0).max(now));
    }

    fn expire(&mut self, now: f64) {
        let before = self.pending.len();
        self.pending.retain(|_, exp| !(now > *exp));
        self.fails += (before - self.pending.len()) as u64;
    }

    /// A fresh verification `state`, or `None` when the stream is not enabled, a request came too soon, or too many are pending.
    pub fn request_verification(&mut self, now: f64) -> Result<Option<String>, String> {
        if self.status != "enabled" || !now.is_finite() {
            return Ok(None);
        }
        if self.last_requested.is_some_and(|l| !(now - l >= self.min_interval)) {
            return Ok(None);
        }
        self.expire(now);
        if !((self.pending.len() as f64) < self.o.max_pending.unwrap_or(16.0)) {
            return Ok(None);
        }
        let exp = now + self.o.verify_timeout_sec.unwrap_or(60.0);
        if !exp.is_finite() {
            return Ok(None); // a NaN or infinite timeout would leave the request pending forever
        }
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
        let state = crate::b64_encode(&b);
        self.pending.insert(state.clone(), exp);
        self.last_requested = Some(now);
        Ok(Some(state))
    }

    /// Acknowledge a verification `state` (a non-string or unknown one is counted as rejected).
    pub fn ack_verification(&mut self, state: &Value, now: f64) -> bool {
        if !now.is_finite() {
            self.rejected += 1;
            return false;
        }
        self.expire(now);
        if state.as_str().is_some_and(|s| self.pending.remove(s).is_some()) {
            self.last_verified = Some(now);
            self.last_event = Some(self.last_event.unwrap_or(0.0).max(now));
            self.fails = 0;
            true
        } else {
            self.rejected += 1;
            false
        }
    }

    pub fn report(&mut self, now: f64) -> Value {
        self.expire(now);
        let within = self.o.verified_within_sec.unwrap_or(300.0);
        let (state, reason): (&str, Option<String>) = if self.status == "disabled" {
            ("disabled", Some("stream is disabled: no events are transmitted or held".into()))
        } else if self.status == "paused" {
            ("paused", Some("stream is paused: events may be delayed".into()))
        } else if !((self.fails as f64) < self.o.fail_after.unwrap_or(3.0)) {
            ("failing", Some(format!("{} consecutive verification requests timed out", self.fails)))
        } else if self.last_verified.is_none() {
            ("unverified", Some("no verification round trip has completed".into()))
        } else if !(now.is_finite() && now - self.last_verified.unwrap_or(0.0) <= within) {
            ("degraded", Some(format!("last verified {}s ago, over {}s", js_number_string(now - self.last_verified.unwrap_or(0.0)), js_number_string(within))))
        } else {
            ("healthy", None)
        };
        let mut m = Map::new();
        m.insert("state".into(), json!(state));
        m.insert("status".into(), json!(self.status));
        m.insert("reasons".into(), json!(reason.into_iter().collect::<Vec<_>>()));
        m.insert("pending_verifications".into(), json!(self.pending.len()));
        m.insert("consecutive_verification_failures".into(), json!(self.fails));
        m.insert("rejected_verifications".into(), json!(self.rejected));
        if let Some(t) = self.last_event {
            m.insert("last_event_at".into(), num_value(t));
        }
        if let Some(t) = self.last_verified {
            m.insert("last_verified_at".into(), num_value(t));
        }
        Value::Object(m)
    }

    pub fn revocation_fresh_within(&self, max_age_sec: f64, now: f64) -> bool {
        self.status == "enabled" && now.is_finite() && self.last_verified.is_some_and(|l| now - l <= max_age_sec)
    }
}

/// A stream known to the transmitter: its `config` and the time of its last verification.
#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub config: Value,
    pub last_verification: Option<f64>,
}

/// `handleVerificationRequest`: a signed verification SET echoing the receiver's `state`, or `{status, error}`.
/// `seed = None` models a missing key (the SET build fails, after the request was recorded, as in the reference).
pub fn handle_verification_request(streams: &mut HashMap<String, StreamEntry>, req: &Value, now: f64, seed: Option<&[u8; 32]>) -> Result<Value, String> {
    let bad = || Ok(json!({ "status": 400, "error": "stream_id (string) is required; state must be a string" }));
    let Some(r) = req.as_object() else { return bad() };
    let Some(id) = r.get("stream_id").and_then(Value::as_str) else { return bad() };
    let state = match r.get("state") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return bad(),
    };
    let Some(s) = streams.get_mut(id) else { return Ok(json!({ "status": 404, "error": "no such stream" })) };
    if s.config.is_null() {
        return Err("Cannot read properties of undefined (reading 'min_verification_interval')".into());
    }
    let min = number(s.config.get("min_verification_interval")).unwrap_or(0.0);
    if s.last_verification.is_some_and(|l| !(now.is_finite() && now - l >= min)) {
        return Ok(json!({ "status": 429, "error": "verification requested too soon" }));
    }
    s.last_verification = Some(now);
    let mut args = Map::new();
    args.insert("events".into(), json!({ EV_VERIFICATION: state.map_or_else(|| json!({}), |st| json!({ "state": st })) }));
    for (to, from) in [("issuer", "iss"), ("audience", "aud"), ("subject", "stream_id")] {
        if let Some(v) = s.config.get(from) {
            args.insert(to.into(), v.clone());
        }
    }
    let seed = seed.ok_or("Key for the EdDSA algorithm must be a key object")?;
    let set = build_set(&Value::Object(args), seed)?;
    Ok(json!({ "status": 204, "set": set }))
}

/// A poll-delivery queue (RFC 8936): enqueue SETs by `jti`, `poll` with acks and error reports.
#[derive(Debug, Clone, Default)]
pub struct PollQueue {
    q: Vec<(String, String)>,
    pub errors: Vec<Value>,
}

impl PollQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// A repeated `jti` replaces the token and keeps its place.
    pub fn enqueue(&mut self, jti: &str, set: &str) {
        match self.q.iter_mut().find(|(j, _)| j == jti) {
            Some(e) => e.1 = set.to_string(),
            None => self.q.push((jti.to_string(), set.to_string())),
        }
    }

    pub fn depth(&self) -> usize {
        self.q.len()
    }

    fn delete(&mut self, jti: &str) -> bool {
        let n = self.q.len();
        self.q.retain(|(j, _)| j != jti);
        self.q.len() != n
    }

    /// `poll({maxEvents?, ack?, setErrs?})` -> `{sets, moreAvailable?}`. A bad `maxEvents` is a RangeError; a null `setErrs`
    /// entry for a queued `jti` is a TypeError after that SET has been dropped, as in the reference.
    pub fn poll(&mut self, req: &Value) -> Result<Value, String> {
        if req.is_null() {
            return Err("Cannot read properties of null (reading 'maxEvents')".into());
        }
        if let Some(m) = req.get("maxEvents") {
            if !number(Some(m)).is_some_and(is_safe_nonneg_int) {
                return Err("maxEvents must be a non-negative integer".into());
            }
        }
        match req.get("ack") {
            None | Some(Value::Null) => {}
            Some(Value::Array(a)) => {
                for j in a.iter().filter_map(Value::as_str) {
                    self.delete(j);
                }
            }
            Some(Value::String(s)) => {
                for c in s.chars() {
                    self.delete(&c.to_string());
                }
            }
            Some(_) => return Err("req.ack is not iterable".into()),
        }
        if let Some(se) = req.get("setErrs").filter(|v| !v.is_null()) {
            for (jti, e) in entries(se) {
                if self.delete(&jti) {
                    if e.is_null() {
                        return Err("Cannot read properties of null (reading 'err')".into());
                    }
                    let mut m = Map::new();
                    m.insert("jti".into(), Value::String(jti));
                    for k in ["err", "description"] {
                        if let Some(v) = e.get(k) {
                            m.insert(k.into(), v.clone());
                        }
                    }
                    self.errors.push(Value::Object(m));
                }
            }
        }
        let max = number(req.get("maxEvents")).unwrap_or(f64::INFINITY);
        let mut sets = Map::new();
        let mut n = 0usize;
        for (jti, set) in &self.q {
            if n as f64 >= max {
                break;
            }
            sets.insert(jti.clone(), Value::String(set.clone()));
            n += 1;
        }
        let mut out = Map::new();
        out.insert("sets".into(), Value::Object(sets));
        if self.q.len() > n {
            out.insert("moreAvailable".into(), Value::Bool(true));
        }
        Ok(Value::Object(out))
    }
}

/// `pushResponse(result)`: the RFC 8935 HTTP answer for a `receiveSET` result. A `null` result is a TypeError.
pub fn push_response(r: &Value) -> Result<Value, String> {
    if r.is_null() {
        return Err("Cannot read properties of null (reading 'ok')".into());
    }
    if truthy(r.get("ok")) {
        return Ok(json!({ "status": 202 }));
    }
    let err = match r.get("code").and_then(Value::as_str) {
        Some("verify_failed") => "invalid_key",
        Some("malformed") | Some("oversize") => "invalid_request",
        Some("misconfigured") | Some("replay_store_error") => "access_denied",
        _ => "invalid_request",
    };
    let mut body = Map::new();
    body.insert("err".into(), json!(err));
    if let Some(d) = r.get("reason") {
        body.insert("description".into(), d.clone());
    }
    Ok(json!({ "status": 400, "body": body }))
}

/// `riskLevelChangeSET({issuer, audience, event})` signed with `seed`.
pub fn risk_level_change_set(a: &Value, seed: &[u8; 32]) -> Result<String, String> {
    level_set(a, EV_RISK_LEVEL_CHANGE, a.get("event").cloned(), seed)
}

/// `assuranceLevelChangeSET({issuer, audience, event, order?})`: `change_direction` is derived from `order` (lowest to highest)
/// when the event names a `previous_level` and no direction.
pub fn assurance_level_change_set(a: &Value, seed: &[u8; 32]) -> Result<String, String> {
    let mut e = a.get("event").cloned().unwrap_or_else(|| json!({}));
    if let (Some(em), Some(order)) = (e.as_object_mut(), a.get("order").filter(|o| o.is_array())) {
        if em.contains_key("previous_level") && !em.contains_key("change_direction") {
            let order = order.as_array().expect("array");
            let (p, c) = (em.get("previous_level"), em.get("current_level"));
            let at = |v: Option<&Value>| v.and_then(|v| order.iter().position(|x| x == v));
            if let (Some(i), Some(j)) = (at(p), at(c)) {
                if i != j {
                    em.insert("change_direction".into(), json!(if j > i { "increase" } else { "decrease" }));
                }
            }
        }
    }
    level_set(a, EV_ASSURANCE_LEVEL_CHANGE, Some(e), seed)
}

fn level_set(a: &Value, ty: &str, event: Option<Value>, seed: &[u8; 32]) -> Result<String, String> {
    let mut args = Map::new();
    if let Some(i) = a.get("issuer") {
        args.insert("issuer".into(), i.clone());
    }
    if let Some(i) = a.get("audience") {
        args.insert("audience".into(), i.clone());
    }
    // shortcut: an absent `event` yields an empty events map, which build_set refuses (the reference signs an empty one)
    let mut ev = Map::new();
    if let Some(e) = event {
        ev.insert(ty.into(), e);
    }
    args.insert("events".into(), Value::Object(ev));
    build_set(&Value::Object(args), seed)
}

// ---------------------------------------------------------------------------------------------------- SSF management API

/// Where stream records live. A record is a JSON object `{receiver, config, events_requested?, status, status_reason?,
/// subjects, lastVerification?}`; the store keeps its own copy.
pub trait StreamStore {
    fn get(&self, id: &str) -> Option<Value>;
    fn put(&mut self, id: &str, record: Value);
    fn delete(&mut self, id: &str);
    fn list_by_receiver(&self, receiver: &Value) -> Vec<(String, Value)>;
}

/// An insertion-ordered in-memory [`StreamStore`].
#[derive(Debug, Clone, Default)]
pub struct MemoryStreamStore {
    m: Vec<(String, Value)>,
}

impl StreamStore for MemoryStreamStore {
    fn get(&self, id: &str) -> Option<Value> {
        self.m.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    }
    fn put(&mut self, id: &str, record: Value) {
        match self.m.iter_mut().find(|(k, _)| k == id) {
            Some(e) => e.1 = record,
            None => self.m.push((id.to_string(), record)),
        }
    }
    fn delete(&mut self, id: &str) {
        self.m.retain(|(k, _)| k != id);
    }
    fn list_by_receiver(&self, receiver: &Value) -> Vec<(String, Value)> {
        self.m.iter().filter(|(_, r)| r.get("receiver") == Some(receiver)).cloned().collect()
    }
}

/// A fresh 12-byte base64url stream id (the default for [`SsfManageOptions::new_id`]).
pub fn random_stream_id() -> String {
    let mut b = [0u8; 12];
    let _ = getrandom::getrandom(&mut b);
    crate::b64_encode(&b)
}

/// Options of the SSF management handler.
pub struct SsfManageOptions<'a> {
    pub store: &'a mut dyn StreamStore,
    pub issuer: String,
    pub events_supported: Vec<String>,
    /// Default: push and poll.
    pub delivery_methods: Option<Vec<String>>,
    pub poll_endpoint: &'a dyn Fn(&str) -> String,
    pub signing_seed: [u8; 32],
    /// Hands a verification SET to the stream's delivery; an error is a 500.
    pub deliver: &'a mut dyn FnMut(&Value, &str) -> Result<(), String>,
    /// Default 1.
    pub max_streams_per_receiver: Option<f64>,
    /// Default 10000.
    pub max_subjects_per_stream: Option<f64>,
    pub now: &'a dyn Fn() -> f64,
    pub new_id: &'a mut dyn FnMut() -> String,
}

/// `transmitterMetadata`: the SSF transmitter configuration document.
pub fn transmitter_metadata(issuer: &str, delivery_methods: Option<&[String]>, base: &str, jwks_uri: Option<&str>) -> Value {
    let mut m = Map::new();
    m.insert("spec_version".into(), json!("1_0"));
    m.insert("issuer".into(), json!(issuer));
    if let Some(j) = jwks_uri.filter(|j| !j.is_empty()) {
        m.insert("jwks_uri".into(), json!(j));
    }
    let dm: Vec<String> = delivery_methods.map_or_else(|| vec![DELIVERY_PUSH.to_string(), DELIVERY_POLL.to_string()], <[String]>::to_vec);
    m.insert("delivery_methods_supported".into(), json!(dm));
    for (k, p) in [
        ("configuration_endpoint", "configuration"),
        ("status_endpoint", "status"),
        ("add_subject_endpoint", "add_subject"),
        ("remove_subject_endpoint", "remove_subject"),
        ("verification_endpoint", "verification"),
    ] {
        m.insert(k.into(), json!(format!("{base}/ssf/{p}")));
    }
    m.insert("default_subjects".into(), json!("NONE"));
    Value::Object(m)
}

fn resp(status: u16, body: Value) -> Value {
    json!({ "status": status, "body": body })
}

fn bad(m: &str) -> Value {
    resp(400, json!({ "error": "invalid_request", "description": m }))
}

fn not_found() -> Value {
    resp(404, json!({ "error": "not_found" }))
}

fn method_not_allowed() -> Value {
    resp(405, json!({ "error": "method_not_allowed" }))
}

fn events_requested_ok(v: &Value) -> Option<Vec<String>> {
    let a = v.as_array().filter(|a| !a.is_empty())?;
    a.iter().map(|e| e.as_str().filter(|s| !s.is_empty()).map(String::from)).collect()
}

fn subject_key(s: Option<&Value>) -> Option<String> {
    let m = s?.as_object()?;
    if m.get("format").and_then(Value::as_str).is_none_or(str::is_empty) {
        return None;
    }
    let mut es: Vec<(&String, &Value)> = m.iter().collect();
    es.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    let sorted: Map<String, Value> = es.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    Some(crate::js_stringify(&Value::Object(sorted)))
}

fn methods_of(o: &SsfManageOptions) -> Vec<String> {
    o.delivery_methods.clone().unwrap_or_else(|| vec![DELIVERY_PUSH.to_string(), DELIVERY_POLL.to_string()])
}

fn delivered(o: &SsfManageOptions, requested: Option<&[String]>) -> Vec<String> {
    match requested {
        None => o.events_supported.clone(),
        Some(r) => o.events_supported.iter().filter(|e| r.contains(e)).cloned().collect(),
    }
}

fn delivery_for(o: &SsfManageOptions, id: &str, d: Option<&Value>) -> Result<Value, &'static str> {
    let methods = methods_of(o);
    let Some(d) = d else {
        if !methods.iter().any(|m| m == DELIVERY_POLL) {
            return Err("delivery is required: this transmitter does not support poll");
        }
        return Ok(json!({ "method": DELIVERY_POLL, "endpoint_url": (o.poll_endpoint)(id) }));
    };
    let method = d.get("method").and_then(Value::as_str).filter(|m| methods.iter().any(|x| x == m));
    let Some(method) = method else { return Err("delivery.method is not supported by this transmitter") };
    if method == DELIVERY_POLL {
        return Ok(json!({ "method": DELIVERY_POLL, "endpoint_url": (o.poll_endpoint)(id) }));
    }
    match d.get("endpoint_url").and_then(Value::as_str).filter(|u| https_url_ok(u)) {
        Some(u) => Ok(json!({ "method": DELIVERY_PUSH, "endpoint_url": u })),
        None => Err("push delivery needs an https endpoint_url"),
    }
}

fn build_config(o: &SsfManageOptions, id: &str, rcv: &Value, requested: Option<&[String]>, delivery: Value, description: Option<&str>) -> Map<String, Value> {
    let mut c = Map::new();
    c.insert("stream_id".into(), json!(id));
    c.insert("iss".into(), json!(o.issuer));
    if let Some(a) = rcv.get("aud") {
        c.insert("aud".into(), a.clone());
    }
    c.insert("events_supported".into(), json!(o.events_supported));
    c.insert("events_delivered".into(), json!(delivered(o, requested)));
    c.insert("delivery".into(), delivery);
    if let Some(d) = description {
        let units: Vec<u16> = d.encode_utf16().take(256).collect();
        c.insert("description".into(), Value::String(String::from_utf16_lossy(&units)));
    }
    c
}

fn own(o: &SsfManageOptions, rcv: &Value, id: Option<&Value>) -> Option<Value> {
    let r = o.store.get(id?.as_str()?)?;
    (r.get("receiver") == rcv.get("id")).then_some(r)
}

fn status_body(id: &str, s: &Value) -> Value {
    let mut m = Map::new();
    m.insert("stream_id".into(), json!(id));
    m.insert("status".into(), s["status"].clone());
    if let Some(r) = s.get("status_reason") {
        m.insert("reason".into(), r.clone());
    }
    Value::Object(m)
}

fn route(o: &mut SsfManageOptions, req: &Value, rcv: &Value) -> Result<Value, String> {
    let ty = |m: &str| format!("Cannot read properties of undefined (reading '{m}')");
    let path = req.get("path").and_then(Value::as_str).ok_or_else(|| ty("split"))?;
    let seg = path.split('/').filter(|s| !s.is_empty()).next_back().unwrap_or("");
    let query = req.get("query");
    let qid = query.and_then(|q| q.get("stream_id"));
    let b = req.get("body").filter(|b| b.is_object());
    let m = req.get("method").and_then(Value::as_str).ok_or_else(|| ty("toUpperCase"))?.to_uppercase();
    if !["configuration", "status", "add_subject", "remove_subject", "verification"].contains(&seg) {
        return Ok(not_found());
    }
    let rid = rcv.get("id").cloned().unwrap_or(Value::Null);
    let receiver_supplied = ["events_requested", "delivery", "description"];
    let transmitter_supplied = ["stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval"];

    if seg == "configuration" {
        if m == "POST" {
            let Some(b) = b else { return Ok(bad("a JSON object body is required")) };
            for k in b.as_object().expect("object").keys() {
                if !receiver_supplied.contains(&k.as_str()) {
                    return Ok(bad(&format!("'{k}' is not a receiver-supplied member")));
                }
            }
            let requested: Option<Vec<String>> = match b.get("events_requested") {
                None => None,
                Some(v) => match events_requested_ok(v) {
                    Some(r) => Some(r),
                    None => return Ok(bad("events_requested must be a non-empty array of event type URIs")),
                },
            };
            if b.get("description").is_some_and(|d| !d.is_string()) {
                return Ok(bad("description must be a string"));
            }
            let max_streams = o.max_streams_per_receiver.unwrap_or(1.0);
            if !((o.store.list_by_receiver(&rid).len() as f64) < max_streams) {
                return Ok(resp(409, json!({ "error": "conflict", "description": "this receiver already has the maximum number of streams" })));
            }
            let id = (o.new_id)();
            let delivery = match delivery_for(o, &id, b.get("delivery")) {
                Ok(d) => d,
                Err(why) => return Ok(bad(why)),
            };
            if delivered(o, requested.as_deref()).is_empty() {
                return Ok(bad("none of events_requested is supported by this transmitter"));
            }
            let config = Value::Object(build_config(o, &id, rcv, requested.as_deref(), delivery, b.get("description").and_then(Value::as_str)));
            let problems = validate_stream_config(&config);
            if !problems.is_empty() {
                return Ok(bad(&problems.join("; ")));
            }
            let mut rec = Map::new();
            rec.insert("receiver".into(), rid.clone());
            rec.insert("config".into(), config.clone());
            if let Some(r) = &requested {
                rec.insert("events_requested".into(), json!(r));
            }
            rec.insert("status".into(), json!("enabled"));
            rec.insert("subjects".into(), json!({}));
            o.store.put(&id, Value::Object(rec));
            return Ok(resp(201, config));
        }
        if m == "GET" {
            if qid.is_none() {
                let list: Vec<Value> = o.store.list_by_receiver(&rid).into_iter().map(|(_, r)| r["config"].clone()).collect();
                return Ok(resp(200, Value::Array(list)));
            }
            return Ok(match own(o, rcv, qid) {
                Some(s) => resp(200, s["config"].clone()),
                None => not_found(),
            });
        }
        if m == "PATCH" || m == "PUT" {
            let Some(b) = b else { return Ok(bad("a JSON object body is required")) };
            let s = own(o, rcv, b.get("stream_id"));
            let Some(sid) = b.get("stream_id").and_then(Value::as_str) else { return Ok(bad("stream_id is required")) };
            let Some(mut s) = s else { return Ok(not_found()) };
            for k in b.as_object().expect("object").keys() {
                if !receiver_supplied.contains(&k.as_str()) && !transmitter_supplied.contains(&k.as_str()) {
                    return Ok(bad(&format!("unknown member '{k}'")));
                }
            }
            for k in transmitter_supplied {
                let Some(v) = b.get(k) else { continue };
                let same = s["config"].get(k).is_some_and(|e| crate::js_stringify(v) == crate::js_stringify(e));
                if !same {
                    return Ok(bad(&format!("'{k}' is transmitter-supplied and does not match")));
                }
            }
            if let Some(v) = b.get("events_requested") {
                if events_requested_ok(v).is_none() {
                    return Ok(bad("events_requested must be a non-empty array of event type URIs"));
                }
            }
            if b.get("description").is_some_and(|d| !d.is_string()) {
                return Ok(bad("description must be a string"));
            }
            let mut delivery = s["config"]["delivery"].clone();
            if b.get("delivery").is_some() || m == "PUT" {
                let d = match delivery_for(o, sid, b.get("delivery")) {
                    Ok(d) => d,
                    Err(why) => return Ok(bad(why)),
                };
                if d.get("method") != delivery.get("method") {
                    return Ok(bad("delivery.method cannot be changed: create a new stream"));
                }
                delivery = d;
            }
            let requested: Option<Vec<String>> = if m == "PUT" {
                b.get("events_requested").and_then(events_requested_ok)
            } else if b.get("events_requested").is_some() {
                b.get("events_requested").and_then(events_requested_ok)
            } else {
                s.get("events_requested").and_then(events_requested_ok)
            };
            let description: Option<String> = if m == "PUT" {
                b.get("description").and_then(Value::as_str).map(String::from)
            } else if let Some(d) = b.get("description") {
                d.as_str().map(String::from)
            } else {
                s["config"].get("description").and_then(Value::as_str).map(String::from)
            };
            if delivered(o, requested.as_deref()).is_empty() {
                return Ok(bad("none of events_requested is supported by this transmitter"));
            }
            let mut next = build_config(o, sid, rcv, requested.as_deref(), delivery, description.as_deref());
            if let Some(mi) = s["config"].get("min_verification_interval") {
                next.insert("min_verification_interval".into(), mi.clone());
            }
            let next = Value::Object(next);
            let sm = s.as_object_mut().expect("record");
            sm.insert("config".into(), next.clone());
            match &requested {
                Some(r) => {
                    sm.insert("events_requested".into(), json!(r));
                }
                None => {
                    sm.remove("events_requested");
                }
            }
            o.store.put(sid, s);
            return Ok(resp(200, next));
        }
        if m == "DELETE" {
            if own(o, rcv, qid).is_none() {
                return Ok(not_found());
            }
            o.store.delete(qid.and_then(Value::as_str).unwrap_or(""));
            return Ok(json!({ "status": 204 }));
        }
        return Ok(method_not_allowed());
    }

    if seg == "status" {
        if m == "GET" {
            return Ok(match own(o, rcv, qid) {
                Some(s) => resp(200, status_body(qid.and_then(Value::as_str).unwrap_or(""), &s)),
                None if qid.is_none() => bad("stream_id is required"),
                None => not_found(),
            });
        }
        if m == "POST" {
            let Some((b, sid)) = b.and_then(|b| Some((b, b.get("stream_id")?.as_str()?))) else { return Ok(bad("stream_id is required")) };
            let st = b.get("status").and_then(Value::as_str).filter(|s| STREAM_STATUSES.contains(s));
            let Some(st) = st else { return Ok(bad("status must be 'enabled', 'paused' or 'disabled'")) };
            if b.get("reason").is_some_and(|r| !r.is_string()) {
                return Ok(bad("reason must be a string"));
            }
            let Some(mut s) = own(o, rcv, b.get("stream_id")) else { return Ok(not_found()) };
            let sm = s.as_object_mut().expect("record");
            sm.insert("status".into(), json!(st));
            match b.get("reason") {
                Some(r) => {
                    sm.insert("status_reason".into(), r.clone());
                }
                None => {
                    sm.remove("status_reason");
                }
            }
            let body = status_body(sid, &s);
            o.store.put(sid, s);
            return Ok(resp(200, body));
        }
        return Ok(method_not_allowed());
    }

    if seg == "add_subject" || seg == "remove_subject" {
        if m != "POST" {
            return Ok(method_not_allowed());
        }
        let Some((b, sid)) = b.and_then(|b| Some((b, b.get("stream_id")?.as_str()?))) else { return Ok(bad("stream_id is required")) };
        let Some(key) = subject_key(b.get("subject")) else { return Ok(bad("subject must be a Subject Identifier object with a format")) };
        if b.get("verified").is_some_and(|v| !v.is_boolean()) {
            return Ok(bad("verified must be a boolean"));
        }
        let Some(mut s) = own(o, rcv, b.get("stream_id")) else { return Ok(not_found()) };
        let subjects = s.as_object_mut().expect("record").entry("subjects").or_insert_with(|| json!({}));
        let sub = subjects.as_object_mut().expect("subjects");
        if seg == "add_subject" {
            if !sub.contains_key(&key) && sub.len() as f64 >= o.max_subjects_per_stream.unwrap_or(10_000.0) {
                return Ok(resp(429, json!({ "error": "too_many_requests", "description": "subject limit reached" })));
            }
            sub.insert(key, Value::Bool(b.get("verified").and_then(Value::as_bool).unwrap_or(true)));
            o.store.put(sid, s);
            return Ok(json!({ "status": 200 }));
        }
        sub.remove(&key);
        o.store.put(sid, s);
        return Ok(json!({ "status": 204 }));
    }

    // verification
    if m != "POST" {
        return Ok(method_not_allowed());
    }
    let Some(b) = b else { return Ok(bad("a JSON object body is required")) };
    let Some(mut s) = own(o, rcv, b.get("stream_id")) else {
        return Ok(if b.get("stream_id").is_some_and(Value::is_string) { not_found() } else { bad("stream_id is required") });
    };
    if s["status"] == "disabled" {
        return Ok(bad("the stream is disabled"));
    }
    let sid = b["stream_id"].as_str().unwrap_or("").to_string();
    let mut view = HashMap::new();
    view.insert(
        s["config"]["stream_id"].as_str().unwrap_or("").to_string(),
        StreamEntry { config: s["config"].clone(), last_verification: number(s.get("lastVerification")) },
    );
    let mut vreq = Map::new();
    vreq.insert("stream_id".into(), json!(sid));
    if let Some(st) = b.get("state") {
        vreq.insert("state".into(), st.clone());
    }
    let out = handle_verification_request(&mut view, &Value::Object(vreq), (o.now)(), Some(&o.signing_seed))?;
    let status = out["status"].as_u64().unwrap_or(500);
    if status != 204 {
        let err = if status == 429 { "too_many_requests" } else { "invalid_request" };
        return Ok(json!({ "status": status, "body": { "error": err, "description": out["error"] } }));
    }
    s.as_object_mut().expect("record").insert("lastVerification".into(), num_value((o.now)()));
    let cfg_id = s["config"]["stream_id"].as_str().unwrap_or("").to_string();
    o.store.put(&cfg_id, s.clone());
    let set = out["set"].as_str().unwrap_or("").to_string();
    (o.deliver)(&s, &set)?;
    Ok(json!({ "status": 204 }))
}

/// The SSF management API (OpenID SSF 1.0 §8.1): stream create / read / update / replace / delete, status, subjects and
/// verification, for the receiver `authenticate` names. `req` is `{method, path, query?, body?}`; the answer is
/// `{status, body?}`. No receiver is 401; any internal failure (a malformed request object, a store or delivery error) is a
/// 500 `server_error` and never leaks detail.
pub fn ssf_management_handler(o: &mut SsfManageOptions, req: &Value, authenticate: &dyn Fn(&Value) -> Result<Option<Value>, String>) -> Value {
    let rcv = match authenticate(req) {
        Ok(Some(r)) => r,
        Ok(None) => return resp(401, json!({ "error": "unauthenticated" })),
        Err(_) => return resp(500, json!({ "error": "server_error" })),
    };
    route(o, req, &rcv).unwrap_or_else(|_| resp(500, json!({ "error": "server_error" })))
}
