//! The trusted question channel of the wallet (PCA Intent Layer v2) with its delivery transports and wire handlers. One [`TrustedChannel`]
//! per session. SELECTION belongs to the verifier (questions enter only as a site-signed `intent_required`, re-derived by the wallet, or as
//! a structured agent clarification whose cell the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with
//! harm; canaries are inserted with probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate
//! bound the questions; a cell is asked at most once per session; under estimated noise an irreversible cell needs two confirmations.
//! A port of the reference (@atlasauth/pca-wallet: channel, delivery and handlers), part 2; part 1 is [`crate::wallet`].
//!
//! Values are plain JSON with the reference's member names; the options, the grant view, the clock and the randomness are injected
//! closures. A thrown Error of the reference is an `Err(String)` (the state mutated before it stays, as in the reference).
//!
//! API: [`verify_intent_required`] (the verifier side of the site-signed question), delivery ([`site_question_notice`],
//! [`clarification_notice`], [`question_text`], [`QuestionChannel`], [`question_webhook_channel`], [`question_text_channel`],
//! [`QuestionDispatcher`]), the channel ([`ChannelOptions`], [`ChannelView`], [`Device`], [`TrustedChannel`]) and the wire handlers
//! ([`question_handler`], [`clarify_handler`]).
//!
//! shortcut: the options `reversibility` (a per-box reversibility callback) and `harm` (a custom harm model) of the reference are not
//! offered; the outcome space's own reversibility and the default harm model apply. [`crate::wallet_card`] has the same harm limit.
use crate::intent_suite::{domain_message, suite_of, verify_pinned_suite};
use crate::missing_context::js_keys;
use crate::wallet::{
    action_values_of, admission_policy, box_cells, box_size, cell_in_box, cell_key, cell_of_action, coords_error, coords_of_cell, default_fatigue,
    device_challenge, double_confirmed, flat_index, friction_for, friction_rank, max_friction, noise_state, pca_action_digest, pick_canary, record_canary,
    resolve_coords, sign_intent_answer, typed_digest, BoxResult, CellAt, Confirmation, PickCtx, SlidingWindowCounter, MIN_HOLD_MS,
};
use crate::wallet_card::{
    clean_str, expected_typed, normalize_typed, parse_clarify_request, partial_error, plan_clarification, render_card, ClarifyView, PlanInput,
};
use crate::wallet_omega::{cell_rep, cell_stats, is_int, is_safe_int, num, truthy};
pub use crate::wallet_population::Rand;
use crate::webauthn::{verify_assertion, Assertion, Challenge, CredentialPublicKey, VerifyExpectations};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

const INTENT_REQUIRED_DOMAIN: &str = "atlas-pca/intent-required/v1\0";
const IR_KEYS: [&str; 14] = [
    "v",
    "kind",
    "session",
    "map_digest",
    "schema",
    "pcactn_digest",
    "action_digest",
    "cell",
    "reason",
    "question_id",
    "friction",
    "delivered_to",
    "expires_at",
    "sig",
];
const B64U: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn s_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// A JSON number from a double: an integral one is written as an integer.
fn n_json(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

// ---- the verifier side of a site-signed question ----------------------------------------------------------------------------------

/// Shape of a signed `pca-intent-required` v1 body (`None` when well formed).
pub(crate) fn intent_required_shape_error(b: &Value) -> Option<String> {
    let Some(o) = b.as_object() else { return Some("not an object".into()) };
    for k in js_keys(o) {
        if !IR_KEYS.contains(&k.as_str()) {
            return Some(format!("unknown member '{k}'"));
        }
    }
    if o.get("v").and_then(num) != Some(1.0) || o.get("kind").and_then(Value::as_str) != Some("pca-intent-required") {
        return Some("not a pca-intent-required v1".into());
    }
    for k in ["session", "map_digest", "schema", "pcactn_digest", "action_digest"] {
        if !o.get(k).is_some_and(crate::wallet::is_b64u32) {
            return Some(format!("{k} must be canonical base64url (32 bytes)"));
        }
    }
    let cell = o.get("cell").and_then(Value::as_object);
    let cell_ok = cell.is_some_and(|c| c.len() == 2 && c.contains_key("coords") && c.get("verb").and_then(Value::as_str).is_some_and(|v| !v.is_empty()));
    let Some(cell) = cell.filter(|_| cell_ok) else { return Some("cell must be {verb, coords}".into()) };
    if let Some(e) = coords_error(&cell["coords"]) {
        return Some(e);
    }
    if o.get("reason").and_then(Value::as_str) != Some("uncertain") {
        return Some("reason must be 'uncertain'".into());
    }
    let qid_ok = o
        .get("question_id")
        .and_then(Value::as_str)
        .is_some_and(|q| (1..=64).contains(&q.len()) && q.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'));
    if !qid_ok {
        return Some("question_id must match [A-Za-z0-9_-]{1,64}".into());
    }
    if !o.get("friction").and_then(Value::as_str).is_some_and(|f| ["tap", "hold", "typed", "device"].contains(&f)) {
        return Some("unknown friction tier".into());
    }
    if !o.get("delivered_to").and_then(Value::as_str).is_some_and(|d| d == "wallet" || d == "agent") {
        return Some("delivered_to must be 'wallet' or 'agent'".into());
    }
    if !o.get("expires_at").is_some_and(|e| is_int(e) && num(e).is_some_and(|f| f >= 0.0)) {
        return Some("expires_at must be a non-negative safe integer".into());
    }
    let sig_msg = "sig must be {alg, kid, value, pq_value?}";
    let Some(s) = o.get("sig").and_then(Value::as_object) else { return Some(sig_msg.into()) };
    if let Err(e) = suite_of(s.get("alg")) {
        return Some(format!("sig.alg: {e}"));
    }
    if s.get("pq_value").is_some_and(|p| !p.is_string()) {
        return Some("sig.pq_value must be a string".into());
    }
    let members = ["alg", "kid", "value", "pq_value"];
    if s.keys().any(|k| !members.contains(&k.as_str())) || !s.get("kid").is_some_and(Value::is_string) || !s.get("value").is_some_and(Value::is_string) {
        return Some(sig_msg.into());
    }
    None
}

fn verify_ir_inner(b: &Value, keys: Option<&Value>, now: Option<&Value>) -> Result<(), String> {
    let Some(now_f) = now.filter(|n| is_safe_int(n)).and_then(num) else { return Err("the verifier clock is not a safe integer (fail closed)".into()) };
    if let Some(e) = intent_required_shape_error(b) {
        return Err(e);
    }
    let Some(keys) = keys.and_then(Value::as_array) else { return Err("the site keys must be an array".into()) };
    let sig = b["sig"].as_object().ok_or("sig must be {alg, kid, value, pq_value?}")?;
    let kid = sig.get("kid").and_then(Value::as_str).unwrap_or("");
    let Some(key) = keys.iter().find(|k| k.as_object().is_some_and(|m| m.get("kid").and_then(Value::as_str) == Some(kid))) else {
        return Err(format!("no site key with kid '{kid}'"));
    };
    let ka = suite_of(key.get("alg")).map_err(|e| format!("site key: {e}"))?;
    let sa = suite_of(sig.get("alg")).map_err(|_| "sig.alg does not match the pinned key suite".to_string())?;
    if ka.alg != sa.alg {
        return Err("sig.alg does not match the pinned key suite".into());
    }
    let mut body = b.as_object().cloned().unwrap_or_default();
    body.remove("sig");
    let msg = domain_message(INTENT_REQUIRED_DOMAIN, body).ok_or("malformed intent_required: not strictly canonical")?;
    let invalid = || "site signature invalid".to_string();
    let Some(pk) = key.get("pk").and_then(Value::as_str) else { return Err(invalid()) };
    let pin = match (key.get("pk"), key.get("pq_pk")) {
        (Some(_), Some(pq)) => Some((pk, pq)),
        _ => None,
    };
    let alg_v = Value::String(ka.alg.to_string());
    match verify_pinned_suite(Some(&alg_v), pk, key.get("pq_pk"), &msg, sig.get("value"), sig.get("pq_value"), pin) {
        Err(e) => return Err(e),
        Ok(false) => return Err(invalid()),
        Ok(true) => {}
    }
    if !(now_f <= num(&b["expires_at"]).unwrap_or(f64::NAN)) {
        return Err("the question has expired".into());
    }
    Ok(())
}

/// Verify a site-signed `intent_required` against the site's discovery keys and the clock (a safe integer: refused, never coerced).
/// Total: `{ok: true}` or `{ok: false, reason}`.
pub fn verify_intent_required(b: &Value, keys: Option<&Value>, now: Option<&Value>) -> Value {
    match verify_ir_inner(b, keys, now) {
        Ok(()) => json!({ "ok": true }),
        Err(reason) => json!({ "ok": false, "reason": reason }),
    }
}

// ---- delivery -----------------------------------------------------------------------------------------------------------------------

/// A notice for a site-signed question. `ctx` is `{keys, now, site?, inboxUrl?}`; `Err` when the signature or expiry does not verify
/// (nothing unsigned leaves).
pub fn site_question_notice(ir: &Value, ctx: &Value) -> Result<Value, String> {
    let v = verify_intent_required(ir, ctx.get("keys"), ctx.get("now"));
    if v["ok"] != json!(true) {
        return Err(format!("siteQuestionNotice: {}", s_of(&v["reason"])));
    }
    let mut out = Map::new();
    out.insert("type".into(), json!("pca.intent.question"));
    for (k, from) in [("session", "session"), ("question_id", "question_id")] {
        out.insert(k.into(), ir[from].clone());
    }
    if let Some(site) = ctx.get("site") {
        out.insert("site".into(), site.clone());
    }
    for k in ["friction", "expires_at"] {
        out.insert(k.into(), ir[k].clone());
    }
    out.insert("intent_required".into(), ir.clone());
    if let Some(u) = ctx.get("inboxUrl").filter(|u| truthy(u)) {
        out.insert("inbox_url".into(), u.clone());
    }
    Ok(Value::Object(out))
}

/// A notice for a wallet-originated question (a clarification): ids only.
pub fn clarification_notice(session: &str, question_id: &str, inbox_url: Option<&str>) -> Value {
    let mut out = json!({ "type": "pca.intent.clarification", "session": session, "question_id": question_id });
    if let Some(u) = inbox_url.filter(|u| !u.is_empty()) {
        out["inbox_url"] = json!(u);
    }
    out
}

/// `encodeURIComponent`.
fn uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The fixed text of a text-surface notice: `{subject, text}`.
pub fn question_text(notice: &Value, site_name: &str) -> Value {
    let is_q = notice["type"] == json!("pca.intent.question");
    let who = if is_q {
        let c = clean_str(site_name, 64);
        if c.is_empty() {
            "A site".to_string()
        } else {
            c
        }
    } else {
        "Your agent".to_string()
    };
    let subject = if is_q { format!("{who} has a question about your request") } else { format!("{who} needs a decision about your request") };
    let link = notice
        .get("inbox_url")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
        .map(|inbox| format!("{inbox}{}question={}", if inbox.contains('?') { "&" } else { "?" }, uri_component(s_of(&notice["question_id"]))));
    let last = match link {
        Some(l) => format!("Open your wallet to answer: {l}"),
        None => "Open your wallet to answer.".to_string(),
    };
    let text = [subject.as_str(), "", last.as_str()].join("\n");
    json!({ "subject": subject, "text": text })
}

pub type Notify = Box<dyn FnMut(&Value) -> Result<Value, String>>;

/// One delivery channel: `kind`, `enabled` and `notify(notice) -> delivery`.
pub struct QuestionChannel {
    pub kind: String,
    pub enabled: bool,
    notify_fn: Notify,
}

impl QuestionChannel {
    pub fn notify(&mut self, notice: &Value) -> Result<Value, String> {
        (self.notify_fn)(notice)
    }
}

/// The response of a webhook transport.
pub struct FetchResponse {
    pub ok: bool,
    pub status: Value,
}

/// `fetch(url, {method, headers, body}) -> response`; `Err` is a transport failure.
pub type Fetch = Box<dyn FnMut(&str, &Value) -> Result<FetchResponse, String>>;

#[derive(Default)]
pub struct WebhookConfig {
    pub url: Option<String>,
    pub headers: Option<Value>,
    pub fetch: Option<Fetch>,
}

fn delivery_base(kind: &str, notice: &Value, payload: Value) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("kind".into(), json!(kind));
    if let Some(q) = notice.get("question_id") {
        m.insert("questionId".into(), q.clone());
    }
    m.insert("payload".into(), payload);
    m
}

fn reason_of(e: String, fallback: &str) -> String {
    if e.is_empty() {
        fallback.to_string()
    } else {
        e
    }
}

/// Webhook delivery (the principal's own wallet push endpoint): the JSON notice, the signed question included. With no `fetch` the
/// delivery reports "no fetch available" and never touches the network.
pub fn question_webhook_channel(cfg: WebhookConfig) -> QuestionChannel {
    let url = cfg.url.filter(|u| !u.is_empty());
    let enabled = url.is_some();
    let mut headers = Map::new();
    headers.insert("content-type".into(), json!("application/json"));
    if let Some(Value::Object(h)) = cfg.headers {
        for (k, v) in h {
            headers.insert(k, v);
        }
    }
    let headers = Value::Object(headers);
    let mut fetch = cfg.fetch;
    let notify_fn: Notify = Box::new(move |notice: &Value| {
        let mut out = delivery_base("webhook", notice, notice.clone());
        let Some(url) = url.as_deref() else {
            out.insert("delivered".into(), json!(false));
            out.insert("reason".into(), json!("webhook channel not configured"));
            return Ok(Value::Object(out));
        };
        let init = json!({ "method": "POST", "headers": headers, "body": crate::js_stringify(notice) });
        let res = match fetch.as_mut() {
            Some(f) => f(url, &init),
            None => Err("no fetch available: pass a FetchLike transport".to_string()),
        };
        match res {
            Ok(r) if r.ok => {
                out.insert("delivered".into(), json!(true));
                out.insert("status".into(), r.status);
            }
            Ok(r) => {
                out.insert("delivered".into(), json!(false));
                out.insert("reason".into(), json!(format!("webhook returned {}", crate::intent_v2::js_value_string(&r.status))));
                out.insert("status".into(), r.status);
            }
            Err(e) => {
                out.insert("delivered".into(), json!(false));
                out.insert("reason".into(), json!(reason_of(e, "webhook transport error")));
            }
        }
        Ok(Value::Object(out))
    });
    QuestionChannel { kind: "webhook".into(), enabled, notify_fn }
}

/// The sender port of a text channel: `send({subject, text})`.
pub type Sender = Box<dyn FnMut(&Value) -> Result<(), String>>;

/// Email / SMS / push delivery through the per-instance sender port (fixed text only).
pub fn question_text_channel(kind: &str, site_name: &str, send: Option<Sender>) -> QuestionChannel {
    let enabled = send.is_some();
    let kind_s = kind.to_string();
    let site_name = site_name.to_string();
    let mut send = send;
    let notify_fn: Notify = Box::new(move |notice: &Value| {
        let body = question_text(notice, &site_name);
        let mut out = delivery_base(&kind_s, notice, body.clone());
        match send.as_mut() {
            None => {
                out.insert("delivered".into(), json!(false));
                out.insert("reason".into(), json!(format!("{kind_s} channel not configured")));
            }
            Some(s) => match s(&body) {
                Ok(()) => {
                    out.insert("delivered".into(), json!(true));
                }
                Err(e) => {
                    out.insert("delivered".into(), json!(false));
                    out.insert("reason".into(), json!(reason_of(e, &format!("{kind_s} send error"))));
                }
            },
        }
        Ok(Value::Object(out))
    });
    QuestionChannel { kind: kind.to_string(), enabled, notify_fn }
}

pub struct QuestionDispatcher {
    pub channels: Vec<QuestionChannel>,
}

impl QuestionDispatcher {
    /// Fan a notice out to every enabled channel (disabled channels are skipped).
    pub fn notify_all(&mut self, notice: &Value) -> Result<Vec<Value>, String> {
        let mut out = vec![];
        for c in self.channels.iter_mut().filter(|c| c.enabled) {
            out.push(c.notify(notice)?);
        }
        Ok(out)
    }
}

pub fn create_question_dispatcher(channels: Vec<QuestionChannel>) -> QuestionDispatcher {
    QuestionDispatcher { channels }
}

// ---- the channel ---------------------------------------------------------------------------------------------------------------------

/// What the channel reads of the principal's grant, by verb and cell index.
pub struct ChannelView {
    pub p: Box<dyn Fn(&str, &[usize]) -> f64>,
    pub vetoed: Box<dyn Fn(&str, &[usize]) -> bool>,
    pub outside_ceiling: Box<dyn Fn(&str, &[usize]) -> bool>,
    /// Cells inside the effective grant.
    pub confirmed: Box<dyn Fn() -> Vec<CellAt>>,
}

/// The device tier's trust: the relying party, the allowed origins, the enrolled credentials (credential id -> JWK) and the counters.
pub struct Device {
    pub rp_id: String,
    pub origins: Vec<String>,
    pub credentials: Value,
    /// credential id -> last counter; `None` records no counters (a stored count of 0 is used and nothing is updated).
    pub sign_counts: Option<Map<String, Value>>,
}

pub type Lift = Box<dyn Fn(&Value) -> Result<Value, String>>;

pub struct ChannelOptions {
    /// The wallet's outcome space.
    pub omega: Value,
    pub session: String,
    pub map_digest: Box<dyn Fn() -> String>,
    pub principal_secret: [u8; 32],
    /// `{origin, name, keys}`: the verified site identity and its discovery keys.
    pub site: Value,
    pub view: ChannelView,
    /// The per-hour question counter shared across sessions.
    pub hourly: SlidingWindowCounter,
    pub noise: Box<dyn Fn() -> Value>,
    pub on_noise: Box<dyn FnMut(Value)>,
    pub rand: Rand,
    pub now: Box<dyn Fn() -> f64>,
    pub statement_text: Option<String>,
    pub units: Option<Value>,
    pub sensitivity: Option<Value>,
    pub identity_paths: Vec<String>,
    /// `{perSession?: 6, perHour?: 12}`.
    pub caps: Option<Value>,
    pub rho: Option<f64>,
    pub fatigue: Option<Value>,
    /// Friction thresholds `{hTap, hDevice}`.
    pub friction: Option<Value>,
    pub max_per_screen: Option<f64>,
    pub max_box_cells: Option<f64>,
    pub device: Option<Device>,
    pub lift: Option<Lift>,
    pub lift_candidate: Option<Lift>,
}

impl ChannelOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        omega: Value,
        session: String,
        map_digest: Box<dyn Fn() -> String>,
        principal_secret: [u8; 32],
        site: Value,
        view: ChannelView,
        hourly: SlidingWindowCounter,
        noise: Box<dyn Fn() -> Value>,
        on_noise: Box<dyn FnMut(Value)>,
        rand: Rand,
        now: Box<dyn Fn() -> f64>,
    ) -> Self {
        Self {
            omega,
            session,
            map_digest,
            principal_secret,
            site,
            view,
            hourly,
            noise,
            on_noise,
            rand,
            now,
            statement_text: None,
            units: None,
            sensitivity: None,
            identity_paths: vec![],
            caps: None,
            rho: None,
            fatigue: None,
            friction: None,
            max_per_screen: None,
            max_box_cells: None,
            device: None,
            lift: None,
            lift_candidate: None,
        }
    }
}

#[derive(Clone)]
struct Item {
    id: String,
    /// "real" | "canary" | "confirmation"
    kind: String,
    /// "elicitation" | "clarification"
    source: String,
    verb: String,
    box_: Vec<Vec<usize>>,
    coords: Value,
    card: Value,
    action: Value,
    action_digest: Option<String>,
    irreversible: bool,
    expected: u8,
    weight: f64,
    jit: bool,
    expires_at: Option<f64>,
    shown_on: Option<f64>,
    not_before: Option<f64>,
    first: Option<Value>,
    flat: usize,
}

impl Item {
    fn friction(&self) -> &Value {
        &self.card["friction"]
    }
}

pub struct TrustedChannel {
    o: ChannelOptions,
    pending: Vec<Item>,
    asked: HashSet<String>,
    canary_used: HashSet<String>,
    known_yes: Vec<CellAt>,
    confirmations: HashMap<String, Vec<Confirmation>>,
    refused_while_frozen: Vec<Value>,
    session_questions: u64,
    canaries: u64,
    screen_no: f64,
}

fn rank(t: &str) -> i64 {
    friction_rank(&json!(t))
}

impl TrustedChannel {
    pub fn new(o: ChannelOptions) -> Self {
        Self {
            o,
            pending: vec![],
            asked: HashSet::new(),
            canary_used: HashSet::new(),
            known_yes: vec![],
            confirmations: HashMap::new(),
            refused_while_frozen: vec![],
            session_questions: 0,
            canaries: 0,
            screen_no: 0.0,
        }
    }

    // ---- options ------------------------------------------------------------------------------------------------------------------

    fn cap(&self, k: &str, default: f64) -> f64 {
        self.o.caps.as_ref().and_then(|c| c.get(k)).filter(|v| !v.is_null()).and_then(num).unwrap_or(default)
    }

    fn fatigue(&self) -> Value {
        self.o.fatigue.clone().unwrap_or_else(default_fatigue)
    }

    fn now(&self) -> f64 {
        (self.o.now)()
    }

    /// The current noise state (eta+ under load, frozen?).
    pub fn noise(&mut self) -> Result<Value, String> {
        let counts = (self.o.noise)();
        let recent = self.o.hourly.count(self.now()) as f64;
        noise_state(&counts, recent, Some(&self.fatigue()))
    }

    /// The admission policy the learner should use now (tau, eta+, eta-; double confirmation).
    pub fn admission(&mut self) -> Result<Value, String> {
        let state = self.noise()?;
        admission_policy(&state, Some(&self.fatigue()))
    }

    pub fn questions_asked(&self) -> u64 {
        self.session_questions
    }

    /// The device tier's counters after the answers so far (`null` for a channel with no device trust).
    pub fn device_sign_counts(&self) -> Value {
        match &self.o.device {
            Some(Device { sign_counts: Some(m), .. }) => Value::Object(m.clone()),
            _ => Value::Null,
        }
    }

    fn new_id(&mut self) -> Result<String, String> {
        loop {
            let mut s = String::from("q_");
            for _ in 0..10 {
                let r = (self.o.rand)()?;
                s.push(B64U[((r * 64.0).floor() as usize) % 64] as char);
            }
            if !self.pending.iter().any(|p| p.id == s) {
                return Ok(s);
            }
        }
    }

    /// `(weight, mean harm)` of a box, `None` when it holds more cells than allowed.
    fn box_stats(&self, vs: &Value, box_: &[Vec<usize>]) -> Option<(f64, f64)> {
        if box_size(box_) as f64 > self.o.max_box_cells.unwrap_or(4096.0) {
            return None;
        }
        let (mut m, mut mh) = (0.0, 0.0);
        for idx in box_cells(box_) {
            let s = cell_stats(vs, &idx);
            m += s.mass;
            mh += s.mass * s.harm;
        }
        Some((mh, if m > 0.0 { mh / m } else { 0.0 }))
    }

    fn friction_of(&mut self, vs: &Value, box_: &[Vec<usize>], mean_harm: f64, site_min: Option<&str>, irreversible: bool) -> Result<String, String> {
        let mut provenance: Vec<Value> = vec![];
        let mut widens_identity = false;
        let sens = self.o.sensitivity.clone().unwrap_or(Value::Null);
        for (k, d) in vs["dims"].as_array().map(Vec::as_slice).unwrap_or(&[]).iter().enumerate() {
            let path = s_of(&d["path"]);
            let cat = s_of(&d["kind"]) == "cat";
            if cat {
                if let Some(param) = path.strip_prefix("env.prov.") {
                    let mut levels: Vec<Value> = vec![];
                    for i in &box_[k] {
                        let v = &d["values"][*i];
                        let text = if s_of(&v["kind"]) == "prefix" { format!("{}*", s_of(&v["value"])) } else { s_of(&v["value"]).to_string() };
                        levels.extend(text.split(['|', ',']).map(|x| json!(x)));
                    }
                    let sv = sens.get(param).filter(|x| truthy(x)).cloned().unwrap_or_else(|| json!("material"));
                    provenance.push(json!({ "path": param, "sensitivity": sv, "levels": levels }));
                }
                // widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones
                if self.o.identity_paths.iter().any(|p| p == path) && box_[k].iter().any(|i| s_of(&d["values"][*i]["kind"]) != "exact") {
                    widens_identity = true;
                }
            }
        }
        let mut inp =
            json!({ "reversibility": vs["reversibility"], "expectedHarm": mean_harm, "provenance": provenance, "widensCriticalIdentity": widens_identity });
        if let Some(m) = site_min {
            inp["siteMin"] = json!(m);
        }
        let mut tier = s_of(&friction_for(&inp, self.o.friction.as_ref())?["tier"]).to_string();
        if irreversible && self.admission()?["doubleConfirmIrreversible"] == json!(true) {
            tier = s_of(&max_friction(&[json!(tier), json!("typed")])).to_string();
        }
        Ok(tier)
    }

    /// The card for a question (`None` when it cannot be rendered); a typed question with no value to type is raised to the device tier.
    #[allow(clippy::too_many_arguments)]
    fn render(
        &self,
        kind: &str,
        verb: &str,
        coords: &Value,
        friction: &str,
        action: Option<&Value>,
        vs: &Value,
        reason: Option<&str>,
    ) -> Result<Option<Value>, String> {
        let mut base = Map::new();
        base.insert("omega".into(), self.o.omega.clone());
        base.insert("verb".into(), json!(verb));
        base.insert("coords".into(), coords.clone());
        base.insert("site".into(), json!({ "origin": self.o.site["origin"], "name": self.o.site["name"] }));
        if let Some(t) = &self.o.statement_text {
            base.insert("statementText".into(), json!(t));
        }
        base.insert("reversibility".into(), vs["reversibility"].clone());
        if let Some(u) = self.o.units.as_ref().filter(|u| truthy(u)) {
            base.insert("units".into(), u.clone());
        }
        if let Some(a) = action {
            base.insert("action".into(), a.clone());
        }
        base.insert("kind".into(), json!(kind));
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            base.insert("reason".into(), json!(r));
        }
        let with = |f: &str| {
            let mut b = base.clone();
            b.insert("friction".into(), json!(f));
            render_card(&Value::Object(b))
        };
        let mut r = with(friction)?;
        if r["ok"] == json!(true) && rank(friction) == rank("typed") && !truthy(&r["card"]["typed"]) {
            r = with("device")?;
        }
        Ok(if r["ok"] == json!(true) { Some(r["card"].clone()) } else { None })
    }

    fn gate(&mut self) -> Result<Value, String> {
        if self.noise()?["frozen"] == json!(true) {
            return Ok(
                json!({ "ok": false, "code": "frozen", "reason": "the estimated false-yes rate is above \u{3b7}_stop: no more questions this session" }),
            );
        }
        let per_session = self.cap("perSession", 6.0);
        if !((self.session_questions as f64) < per_session) {
            return Ok(
                json!({ "ok": false, "code": "cap_session", "reason": format!("at most {} questions per session", crate::intent_v2::js_number_string(per_session)) }),
            );
        }
        let per_hour = self.cap("perHour", 12.0);
        let now = self.now();
        if !(now.is_finite() && (self.o.hourly.count(now) as f64) < per_hour) {
            return Ok(
                json!({ "ok": false, "code": "cap_hour", "reason": format!("at most {} questions per hour", crate::intent_v2::js_number_string(per_hour)) }),
            );
        }
        Ok(json!({ "ok": true }))
    }

    fn enqueue(&mut self, mut it: Item, vs: &Value) {
        it.flat = box_cells(&it.box_).iter().map(|idx| flat_index(vs, idx)).min().unwrap_or(usize::MAX);
        self.pending.push(it);
    }

    fn count(&mut self) -> Result<(), String> {
        self.session_questions += 1;
        let now = self.now();
        if !self.o.hourly.try_add(now, MAX_SAFE)? {
            return Err("unreachable".into());
        }
        Ok(())
    }

    fn verb_space(&self, verb: &str) -> Result<Value, String> {
        self.o.omega["verbs"].as_array().and_then(|vs| vs.iter().find(|v| s_of(&v["verb"]) == verb)).cloned().ok_or_else(|| "no such verb".to_string())
    }

    /// Insert a canary with probability rho (rendered and ordered like a real question).
    fn maybe_canary(&mut self) -> Result<(), String> {
        let mut exclude: HashSet<String> = self.canary_used.clone();
        for p in &self.pending {
            for idx in box_cells(&p.box_) {
                exclude.insert(cell_key(&p.verb, &idx));
            }
        }
        let hold = rank("hold");
        let low_harm = self.pending.iter().all(|p| p.kind != "real" || friction_rank(p.friction()) <= hold);
        let confirmed = (self.o.view.confirmed)();
        let choice = {
            let o = &mut self.o;
            let view = &o.view;
            let known_no = |verb: &str, idx: &[usize]| -> Option<String> {
                if (view.outside_ceiling)(verb, idx) {
                    Some("ceiling".to_string())
                } else if (view.vetoed)(verb, idx) {
                    Some("veto".to_string())
                } else {
                    None
                }
            };
            let mut ctx = PickCtx {
                omega: &o.omega,
                confirmed: &confirmed,
                known_no: &known_no,
                known_yes: &self.known_yes,
                exclude: &exclude,
                rand: &mut *o.rand,
                rho: o.rho,
                low_harm_session: low_harm,
                canaries_so_far: self.canaries,
            };
            pick_canary(&mut ctx)?
        };
        let Some(c) = choice else { return Ok(()) };
        let vs = self.verb_space(&c.verb)?;
        let box_: Vec<Vec<usize>> = c.idx.iter().map(|i| vec![*i]).collect();
        let Some((weight, mean_harm)) = self.box_stats(&vs, &box_) else { return Ok(()) };
        let coords = coords_of_cell(&vs, &c.idx)?;
        let action = json!({ "verb": c.verb, "values": cell_rep(&vs, &c.idx)["values"] });
        let friction = self.friction_of(&vs, &box_, mean_harm, None, false)?;
        let Some(card) = self.render("question", &c.verb, &coords, &friction, Some(&action), &vs, None)? else { return Ok(()) };
        self.canaries += 1;
        self.canary_used.insert(cell_key(&c.verb, &c.idx));
        let id = self.new_id()?;
        let it = Item {
            id,
            kind: "canary".into(),
            source: "elicitation".into(),
            verb: c.verb.clone(),
            box_,
            coords,
            card,
            action,
            action_digest: None,
            irreversible: false,
            expected: c.expected,
            weight,
            jit: false,
            expires_at: None,
            shown_on: None,
            not_before: None,
            first: None,
            flat: 0,
        };
        self.enqueue(it, &vs);
        Ok(())
    }

    /// Receive a site-signed `intent_required` (delivered directly, or relayed unchanged by the agent) together with the action the agent
    /// attempted. Every check fails closed: `{ok: true, questionId, friction}` or `{ok: false, code, reason}`.
    pub fn receive(&mut self, ir: &Value, action: &Value) -> Result<Value, String> {
        let refuse = |code: &str, reason: &str| Ok(json!({ "ok": false, "code": code, "reason": reason }));
        let now = self.now();
        let v = verify_intent_required(ir, self.o.site.get("keys"), Some(&n_json(now)));
        if v["ok"] != json!(true) {
            return refuse("bad_site_signature", s_of(&v["reason"]));
        }
        if s_of(&ir["session"]) != self.o.session {
            return refuse("wrong_session", "the question is for another session");
        }
        if s_of(&ir["map_digest"]) != (self.o.map_digest)() {
            return refuse("stale_map", "the question names another map version");
        }
        let cell_verb = s_of(&ir["cell"]["verb"]).to_string();
        if action.get("verb") != ir["cell"].get("verb") || Some(pca_action_digest(action)?.as_str()) != ir["action_digest"].as_str() {
            return refuse("action_mismatch", "the action does not match the signed action digest");
        }
        let lifted = match &self.o.lift {
            Some(l) => l(action)?,
            None => action_values_of(action)?,
        };
        let (vs, box_) = match resolve_coords(&self.o.omega, &cell_verb, &ir["cell"]["coords"])? {
            BoxResult::Ok { vs, box_ } => (vs.clone(), box_),
            BoxResult::Refused(reason) => return refuse("cell_mismatch", &reason),
        };
        let at = cell_of_action(&self.o.omega, &lifted)?.map(|(_, idx)| idx);
        let Some(at) = at.filter(|idx| cell_in_box(&box_, idx)) else {
            return refuse("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names");
        };
        let Some((weight, mean_harm)) = self.box_stats(&vs, &box_) else { return refuse("cell_too_large", "the question covers too many cells") };
        let cells = box_cells(&box_);
        let verb = s_of(&vs["verb"]).to_string();
        for idx in &cells {
            if (self.o.view.outside_ceiling)(verb.as_str(), idx.as_slice()) {
                return refuse("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it");
            }
            if (self.o.view.vetoed)(verb.as_str(), idx.as_slice()) {
                return refuse("not_uncertain", "the cell was vetoed");
            }
        }
        let pa = (self.o.view.p)(verb.as_str(), at.as_slice());
        if !(pa > 0.0 && pa < 1.0) {
            return refuse("not_uncertain", if pa <= 0.0 { "the cell is denied" } else { "the cell is already in the grant" });
        }
        if cells.iter().any(|idx| self.asked.contains(&cell_key(&verb, idx))) {
            return refuse("already_asked", "a cell is asked at most once per session");
        }
        let g = self.gate()?;
        if g["ok"] != json!(true) {
            if g["code"] == json!("frozen") {
                self.refused_while_frozen.push(json!({ "verb": verb, "coords": ir["cell"]["coords"] }));
            }
            return Ok(g);
        }
        let irreversible = s_of(&vs["reversibility"]) == "irreversible";
        let friction = self.friction_of(&vs, &box_, mean_harm, ir["friction"].as_str(), irreversible)?;
        let Some(card) = self.render("question", &cell_verb, &ir["cell"]["coords"], &friction, Some(&lifted), &vs, None)? else {
            return refuse("render_failed", "the card could not be rendered");
        };
        let qid = s_of(&ir["question_id"]).to_string();
        if self.pending.iter().any(|p| p.id == qid) {
            return refuse("already_asked", "duplicate question id");
        }
        for idx in &cells {
            self.asked.insert(cell_key(&verb, idx));
        }
        self.count()?;
        let shown_friction = card["friction"].clone();
        let it = Item {
            id: qid.clone(),
            kind: "real".into(),
            source: "elicitation".into(),
            verb: cell_verb,
            box_,
            coords: ir["cell"]["coords"].clone(),
            card,
            action: lifted,
            action_digest: ir["action_digest"].as_str().map(String::from),
            irreversible,
            expected: 0,
            weight,
            jit: true,
            expires_at: num(&ir["expires_at"]),
            shown_on: None,
            not_before: None,
            first: None,
            flat: 0,
        };
        self.enqueue(it, &vs);
        self.maybe_canary()?;
        Ok(json!({ "ok": true, "questionId": qid, "friction": shown_friction }))
    }

    /// An agent clarification: `{candidates: [<= 8 structured actions], reason}`, no text. Certain cells are answered at once (dry run); among
    /// the uncertain ones the wallet picks the most informative and asks it. Returns `{status, verdicts, questionId?, refused?, error?}`.
    pub fn clarify(&mut self, body: &Value) -> Result<Value, String> {
        let parsed = parse_clarify_request(body);
        if parsed["ok"] != json!(true) {
            return Ok(json!({ "status": 400, "verdicts": [], "error": parsed["error"] }));
        }
        let st = self.noise()?;
        let num_of = |k: &str| num(&st[k]).unwrap_or(f64::NAN);
        let (eta_pos, eta_neg) = (js_min(0.5 - 1e-9, num_of("etaPosBar")), js_min(0.5 - 1e-9, num_of("etaNegBar")));
        let cands: Vec<Value> = parsed["request"]["candidates"].as_array().cloned().unwrap_or_default();
        let plan = {
            let o = &self.o;
            let view = ClarifyView { p: &*o.view.p, vetoed: &*o.view.vetoed, outside_ceiling: &*o.view.outside_ceiling };
            plan_clarification(&PlanInput {
                omega: &o.omega,
                view,
                candidates: &cands,
                lift: o.lift_candidate.as_deref(),
                asked: &self.asked,
                eta_pos,
                eta_neg,
            })?
        };
        let verdicts = plan["verdicts"].clone();
        let Some(ask) = plan.get("ask").filter(|a| !a.is_null()) else { return Ok(json!({ "status": 200, "verdicts": verdicts })) };
        let g = self.gate()?;
        if g["ok"] != json!(true) {
            let status = if g["code"] == json!("frozen") { 200 } else { 429 };
            return Ok(json!({ "status": status, "verdicts": verdicts, "refused": g["code"] }));
        }
        let ask_verb = s_of(&ask["verb"]).to_string();
        let ask_idx: Vec<usize> = ask["idx"].as_array().map(|a| a.iter().map(|x| num(x).unwrap_or(0.0) as usize).collect()).unwrap_or_default();
        let vs = self.verb_space(&ask_verb)?;
        let box_: Vec<Vec<usize>> = ask_idx.iter().map(|i| vec![*i]).collect();
        let (weight, mean_harm) = self.box_stats(&vs, &box_).ok_or("Cannot read properties of null (reading 'meanHarm')")?;
        let coords = coords_of_cell(&vs, &ask_idx)?;
        let raw = &cands[num(&ask["index"]).unwrap_or(0.0) as usize];
        let action = match &self.o.lift_candidate {
            Some(l) => l(raw)?,
            None => raw.clone(),
        };
        let irreversible = s_of(&vs["reversibility"]) == "irreversible";
        let friction = self.friction_of(&vs, &box_, mean_harm, None, irreversible)?;
        let reason = s_of(&parsed["request"]["reason"]).to_string();
        let verb = s_of(&vs["verb"]).to_string();
        let Some(card) = self.render("clarification", &verb, &coords, &friction, Some(&action), &vs, Some(&reason))? else {
            return Ok(json!({ "status": 200, "verdicts": verdicts, "refused": "render_failed" }));
        };
        let qid = self.new_id()?;
        self.asked.insert(cell_key(&verb, &ask_idx));
        self.count()?;
        let it = Item {
            id: qid.clone(),
            kind: "real".into(),
            source: "clarification".into(),
            verb: verb.clone(),
            box_,
            coords,
            card,
            action,
            action_digest: None,
            irreversible,
            expected: 0,
            weight,
            jit: false,
            expires_at: None,
            shown_on: None,
            not_before: None,
            first: None,
            flat: 0,
        };
        self.enqueue(it, &vs);
        self.maybe_canary()?;
        Ok(json!({ "status": 200, "verdicts": verdicts, "questionId": qid }))
    }

    /// Pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc.
    fn ordered(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.pending.len()).collect();
        idx.sort_by(|&a, &b| {
            let (x, y) = (&self.pending[a], &self.pending[b]);
            friction_rank(y.friction())
                .cmp(&friction_rank(x.friction()))
                .then(y.weight.partial_cmp(&x.weight).unwrap_or(std::cmp::Ordering::Equal))
                .then(x.flat.cmp(&y.flat))
                .then_with(|| x.id.encode_utf16().cmp(y.id.encode_utf16()))
        });
        idx
    }

    /// The next screen (`null` when nothing is waiting). A typed or device question is always alone; tap/hold questions share up to
    /// `maxPerScreen`.
    pub fn next_screen(&mut self) -> Result<Value, String> {
        let now = self.now();
        self.pending.retain(|it| !it.expires_at.is_some_and(|e| !(now.is_finite() && now <= e)));
        let items: Vec<usize> = self.ordered().into_iter().filter(|i| self.pending[*i].shown_on.is_none()).collect();
        if items.is_empty() {
            return Ok(Value::Null);
        }
        let nxt = self.screen_no + 1.0;
        let eligible: Vec<usize> = items.into_iter().filter(|i| self.pending[*i].not_before.map_or(true, |nb| nxt >= nb)).collect();
        self.screen_no = nxt;
        if eligible.is_empty() {
            return Ok(json!({ "screen": n_json(nxt), "kind": "interstitial", "questions": [] }));
        }
        let first = eligible[0];
        let mut picked = vec![first];
        let hold = rank("hold");
        if friction_rank(self.pending[first].friction()) <= hold {
            let mx = self.o.max_per_screen.unwrap_or(3.0);
            for &i in &eligible[1..] {
                if picked.len() as f64 >= mx {
                    break;
                }
                if friction_rank(self.pending[i].friction()) <= hold {
                    picked.push(i);
                }
            }
        }
        for &i in &picked {
            self.pending[i].shown_on = Some(nxt);
        }
        let questions: Vec<Value> = picked.iter().map(|&i| json!({ "questionId": self.pending[i].id, "card": self.pending[i].card })).collect();
        Ok(json!({ "screen": n_json(nxt), "kind": "questions", "questions": questions }))
    }

    /// The principal's response to a shown question: `{ok, kind, answer(s)}` or `{ok: false, code, reason}`.
    pub fn answer(&mut self, question_id: &str, response: &Value) -> Result<Value, String> {
        let refuse = |code: &str, reason: &str| Ok(json!({ "ok": false, "code": code, "reason": reason }));
        let Some(pos) = self.pending.iter().position(|p| p.id == question_id) else { return refuse("unknown_question", "no such pending question") };
        let Some(shown_on) = self.pending[pos].shown_on else { return refuse("not_shown", "the question was never shown") };
        let now = self.now();
        if self.pending[pos].expires_at.is_some_and(|e| !(now.is_finite() && now <= e)) {
            self.pending.remove(pos);
            return refuse("expired", "the question expired");
        }
        let it = self.pending[pos].clone();
        let resp = response.as_object().ok_or("Cannot read properties of undefined (reading 'answer')")?;
        let mut partial: Option<Value> = None;
        let y: i64 = match resp.get("answer").and_then(Value::as_str) {
            Some("no") => 0,
            Some("partly") => {
                let p = resp.get("partial").ok_or("Cannot read properties of undefined (reading 'path')")?;
                if let Some(e) = partial_error(&it.card, p)? {
                    return refuse("bad_response", &e);
                }
                partial = Some(p.clone());
                1
            }
            _ => 1,
        };
        let tier = s_of(it.friction()).to_string();
        let mut ux = Map::new();
        ux.insert("tier".into(), json!(tier));
        ux.insert("rendered_digest".into(), it.card["rendered_digest"].clone());
        ux.insert("canary".into(), json!(it.kind == "canary"));
        if y == 1 {
            let ev = self.tier_evidence(&it, response, question_id)?;
            if ev["ok"] != json!(true) {
                return Ok(ev);
            }
            if let Some(extra) = ev["ux"].as_object() {
                for (k, v) in extra {
                    ux.insert(k.clone(), v.clone());
                }
            }
        }
        let plain_yes = y == 1 && partial.is_none();
        let digest_bound = it.action_digest.as_deref().filter(|d| !d.is_empty());
        if it.kind != "canary" && it.jit && it.irreversible && plain_yes && digest_bound.is_some() && friction_rank(it.friction()) >= rank("typed") {
            ux.insert("action_digest".into(), json!(digest_bound));
            ux.insert("consent_for_action".into(), json!(true));
        }
        let mut body = Map::new();
        body.insert("map_digest".into(), json!((self.o.map_digest)()));
        body.insert("session".into(), json!(self.o.session));
        body.insert("question_id".into(), json!(question_id));
        body.insert("verb".into(), json!(it.verb));
        body.insert("cell".into(), it.coords.clone());
        body.insert("y".into(), json!(y));
        if let Some(p) = &partial {
            body.insert("partial".into(), p.clone());
        }
        body.insert("source".into(), json!(it.source));
        body.insert("observed_at".into(), n_json(now));
        body.insert("ux".into(), Value::Object(ux));
        let answer = sign_intent_answer(&Value::Object(body), &self.o.principal_secret)?;
        self.pending.retain(|p| p.id != question_id);
        if it.kind == "canary" {
            let counts = (self.o.noise)();
            let updated = record_canary(&counts, &json!(it.expected), &json!(y))?;
            (self.o.on_noise)(updated);
            return Ok(json!({ "ok": true, "kind": "canary", "answer": answer }));
        }
        if y == 0 {
            return Ok(json!({ "ok": true, "kind": "veto", "answer": answer }));
        }
        if plain_yes && friction_rank(it.friction()) >= rank("typed") && it.box_.iter().all(|ids| ids.len() == 1) {
            // a verified high-friction yes: a source of known-yes canaries
            self.known_yes.push(CellAt { verb: it.verb.clone(), idx: it.box_.iter().map(|ids| ids[0]).collect() });
        }
        if plain_yes && it.irreversible && self.admission()?["doubleConfirmIrreversible"] == json!(true) {
            let key = format!("{}|{}", it.verb, crate::js_stringify(&it.coords));
            let recs = self.confirmations.entry(key).or_default();
            recs.push(Confirmation { screen: shown_on, tier: tier.clone() });
            if it.kind == "confirmation" {
                if let Some(first) = &it.first {
                    if double_confirmed(recs) {
                        return Ok(json!({ "ok": true, "kind": "confirmed", "answers": [first, answer] }));
                    }
                }
                return Ok(json!({ "ok": true, "kind": "pending_confirmation", "answer": answer }));
            }
            // schedule the second, independent confirmation: at least one other screen in between
            let mut second = it.clone();
            second.id = self.new_id()?;
            second.kind = "confirmation".into();
            second.first = Some(answer.clone());
            second.not_before = Some(shown_on + 2.0);
            second.shown_on = None;
            self.pending.push(second);
            return Ok(json!({ "ok": true, "kind": "pending_confirmation", "answer": answer }));
        }
        Ok(json!({ "ok": true, "kind": "answer", "answer": answer }))
    }

    fn device_challenge_of(&self, it: &Item, question_id: &str) -> Result<String, String> {
        let bound = it.action_digest.as_deref().filter(|d| !d.is_empty()).filter(|_| it.jit && it.irreversible);
        device_challenge(question_id, s_of(&it.card["rendered_digest"]), 1, bound)
    }

    fn tier_evidence(&mut self, it: &Item, response: &Value, question_id: &str) -> Result<Value, String> {
        let r = response;
        let fail = |code: &str, reason: &str| Ok(json!({ "ok": false, "code": code, "reason": reason }));
        match s_of(it.friction()) {
            "tap" => Ok(json!({ "ok": true, "ux": {} })),
            "hold" => {
                let hm = r.get("holdMs").filter(|h| h.is_number());
                match hm.and_then(num).filter(|f| f.is_finite() && *f == f.floor() && *f >= MIN_HOLD_MS as f64) {
                    Some(_) => Ok(json!({ "ok": true, "ux": { "hold_ms": hm } })),
                    None => fail("tier_evidence", &format!("hold for at least {MIN_HOLD_MS} ms")),
                }
            }
            "typed" => {
                let t = it.card.get("typed").filter(|t| truthy(t));
                let typed = r.get("typed").and_then(Value::as_str);
                let (Some(t), true, Some(typed)) = (t, truthy(&it.action), typed) else { return fail("tier_evidence", "type the value shown on the card") };
                let want = expected_typed(&it.card, &it.action)?;
                let path = s_of(&t["path"]);
                let unit = self.o.units.as_ref().and_then(|u| u.get(path));
                let got = normalize_typed(typed, s_of(&t["mode"]), unit);
                match (want, got) {
                    (Some(w), Some(g)) if w == g => Ok(json!({ "ok": true, "ux": { "typed_digest": typed_digest(question_id, &g)? } })),
                    _ => fail("typed_mismatch", "the typed value does not match the card"),
                }
            }
            "device" => {
                let wa = r.get("webauthn").filter(|w| truthy(w));
                let challenge = self.device_challenge_of(it, question_id)?;
                let (Some(wa), Some(dev)) = (wa, self.o.device.as_mut()) else { return fail("tier_evidence", "a security-key assertion is required") };
                let cred = wa.get("credential_id").and_then(Value::as_str);
                let pk = cred.and_then(|c| dev.credentials.get(c)).filter(|p| truthy(p));
                let dec = |k: &str| wa.get(k).and_then(Value::as_str).and_then(|s| crate::decode_b64u_strict(s, None));
                let (ad, cd, sg) = (dec("authenticator_data"), dec("client_data_json"), dec("signature"));
                let (Some(cred), Some(pk), Some(ad), Some(cd), Some(sg)) = (cred, pk, ad, cd, sg) else {
                    return fail("tier_evidence", "unknown credential or malformed assertion");
                };
                let stored = dev.sign_counts.as_ref().map_or(0.0, |m| m.get(cred).and_then(num).unwrap_or(0.0));
                let origins: Vec<&str> = dev.origins.iter().map(String::as_str).collect();
                let res = verify_assertion(
                    &Assertion { authenticator_data: &ad, client_data_json: &cd, signature: &sg, public_key: CredentialPublicKey::Jwk(pk) },
                    &VerifyExpectations {
                        expected_challenge: Some(Challenge::B64u(&challenge)),
                        rp_id: &dev.rp_id,
                        origins: &origins,
                        require_uv: true,
                        stored_sign_count: Some(stored),
                        ..Default::default()
                    },
                );
                if res["ok"] != json!(true) {
                    return fail("tier_evidence", &format!("security key: {}", s_of(&res["reason"])));
                }
                if let Some(m) = dev.sign_counts.as_mut() {
                    m.insert(cred.to_string(), res["signCount"].clone());
                }
                Ok(json!({ "ok": true, "ux": { "webauthn": wa } }))
            }
            _ => Err("unknown friction tier".into()),
        }
    }

    /// The WebAuthn challenge the wallet UI passes to `navigator.credentials.get` for a shown device-tier question.
    pub fn device_challenge_for(&self, question_id: &str) -> Result<Option<String>, String> {
        let Some(it) = self.pending.iter().find(|p| p.id == question_id) else { return Ok(None) };
        if it.shown_on.is_none() || s_of(it.friction()) != "device" {
            return Ok(None);
        }
        Ok(Some(self.device_challenge_of(it, question_id)?))
    }

    /// The end-of-session summary shown instead of questions once the session froze.
    pub fn summary(&mut self) -> Result<Value, String> {
        let frozen = self.noise()?["frozen"].clone();
        Ok(json!({ "frozen": frozen, "refused": self.refused_while_frozen, "asked": self.session_questions, "canaries": self.canaries }))
    }

    /// A stable digest of the channel's pending state (for tests and audit logs).
    pub fn state_digest(&self) -> Result<String, String> {
        let p: Vec<Value> = self
            .ordered()
            .into_iter()
            .map(|i| json!({ "id": self.pending[i].id, "k": self.pending[i].kind, "d": self.pending[i].card["rendered_digest"] }))
            .collect();
        let mut a: Vec<&String> = self.asked.iter().collect();
        a.sort_by(|x, y| x.encode_utf16().cmp(y.encode_utf16()));
        crate::hash_canonical_strict(&json!({ "d": "atlas-pca/wallet-channel-state/v1", "p": p, "a": a, "n": self.session_questions }))
            .ok_or_else(|| "canonicalize: value outside the strict profile".to_string())
    }
}

// ---- wire handlers --------------------------------------------------------------------------------------------------------------------

fn status_of_refusal(code: &str) -> i64 {
    match code {
        "bad_site_signature" => 401,
        "wrong_session" | "stale_map" | "not_uncertain" | "already_asked" => 409,
        "action_mismatch" | "cell_mismatch" | "cell_too_large" | "render_failed" => 422,
        "frozen" | "cap_session" | "cap_hour" => 429,
        _ => 400,
    }
}

fn action_of(v: Option<&Value>) -> Option<Value> {
    let m = v?.as_object()?;
    let verb = m.get("verb").filter(|x| x.is_string())?;
    let resource = m.get("resource").filter(|x| x.is_string())?;
    let rev = m.get("reversibility_class").filter(|x| x.is_string())?;
    let params = m.get("params").filter(|x| x.is_object())?;
    if m.keys().any(|k| !["verb", "resource", "params", "reversibility_class"].contains(&k.as_str())) {
        return None;
    }
    Some(json!({ "verb": verb, "resource": resource, "params": params, "reversibility_class": rev }))
}

/// The question endpoint: a site delivers (or an agent relays unchanged) a site-signed `intent_required` plus the raw action. `ch` is the
/// session's channel (`None`: unknown session). Returns `{status, body}`; neither response carries p or any map content.
pub fn question_handler(ch: Option<&mut TrustedChannel>, body: &Value) -> Result<Value, String> {
    let Some(ch) = ch else { return Ok(json!({ "status": 404, "body": { "error": "unknown_session" } })) };
    let Some(m) = body.as_object() else { return Ok(json!({ "status": 400, "body": { "error": "bad_request" } })) };
    for k in js_keys(m) {
        if k != "intent_required" && k != "action" {
            return Ok(json!({ "status": 400, "body": { "error": "bad_request", "detail": format!("unknown member \"{k}\"") } }));
        }
    }
    let action = action_of(m.get("action"));
    let ir = m.get("intent_required").filter(|v| v.is_object());
    let (Some(action), Some(ir)) = (action, ir) else { return Ok(json!({ "status": 400, "body": { "error": "bad_request" } })) };
    let r = ch.receive(ir, &action)?;
    if r["ok"] == json!(true) {
        return Ok(json!({ "status": 202, "body": { "question_id": r["questionId"], "friction": r["friction"] } }));
    }
    Ok(json!({ "status": status_of_refusal(s_of(&r["code"])), "body": { "error": r["code"] } }))
}

/// The clarification endpoint. Returns `{status, body}`.
pub fn clarify_handler(ch: Option<&mut TrustedChannel>, body: &Value) -> Result<Value, String> {
    let Some(ch) = ch else { return Ok(json!({ "status": 404, "body": { "error": "unknown_session" } })) };
    let r = ch.clarify(body)?;
    if let Some(e) = r.get("error").filter(|e| !e.is_null()) {
        return Ok(json!({ "status": 400, "body": { "error": "bad_request", "detail": e } }));
    }
    let mut out = Map::new();
    out.insert("verdicts".into(), r["verdicts"].clone());
    if let Some(q) = r.get("questionId").filter(|q| !q.is_null()) {
        out.insert("question_id".into(), q.clone());
    }
    if let Some(x) = r.get("refused").filter(|x| !x.is_null()) {
        out.insert("refused".into(), x.clone());
    }
    Ok(json!({ "status": r["status"], "body": out }))
}
