//! Approval-notification channels for PCA step-ups (`approval-channels.ts`). [`crate::approvals`] is the headless core; this is the channel
//! layer: given a pending step-up request (which carries its goal lineage), each channel FORMATS a human-readable notification (action
//! summary, the "because you asked to ..." lineage, an approve/deny affordance or a link to the inbox) and DISPATCHES it over an injected
//! transport. Channels are gated by config (an unconfigured one reports `enabled() == false` and never dispatches), offline-testable (the
//! HTTP transport is injected as a [`FetchLike`]; there is no default client, so a channel without one reports why instead of sending), and
//! secret-free in their output (a delivery never carries the webhook URL, token or signing secret).
//!
//! A channel only REPORTS a step-up the verifier already produced. It authorizes nothing.
use crate::adapters::js_json;
use crate::approval::binding_words;
use crate::approvals::describe_goal_lineage;
use crate::ciba_unicode::{contains, CC_CF};
use crate::intent_v2::js_number_string;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// The HTTP request a channel makes.
#[derive(Clone, Debug, PartialEq)]
pub struct FetchRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// What a channel needs from the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchResponse {
    pub ok: bool,
    pub status: u16,
}

/// The minimal HTTP transport, injected so channels stay offline-testable. `Err` is a transport failure.
pub type FetchLike = dyn Fn(&FetchRequest) -> Result<FetchResponse, String> + Send + Sync;

/// Where the human approves, and the clock.
#[derive(Clone, Debug, Default)]
pub struct NotifyContext {
    /// Absolute URL of the approval inbox (the "open to approve or deny" link).
    pub inbox_url: Option<String>,
    pub now: Option<i64>,
}

/// The common channel contract.
pub trait ApprovalChannel: Send + Sync {
    /// `slack`, `webhook`, `email`, `push` or `sms`.
    fn kind(&self) -> &str;
    /// `true` iff the channel is configured enough to deliver (the config gate).
    fn enabled(&self) -> bool;
    /// Format the step-up for this channel and dispatch it. Never fails: the outcome is `{kind, requestId, delivered, payload, status?, reason?}`
    /// and carries the formatted payload, never a secret.
    fn notify(&self, request: &Value, ctx: &NotifyContext) -> Value;
}

fn delivery(kind: &str, request: &Value, delivered: bool, payload: Value, status: Option<u16>, reason: Option<String>) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), json!(kind));
    m.insert("requestId".into(), request.get("id").cloned().unwrap_or(Value::Null));
    m.insert("delivered".into(), json!(delivered));
    m.insert("payload".into(), payload);
    if let Some(s) = status {
        m.insert("status".into(), json!(s));
    }
    if let Some(r) = reason {
        m.insert("reason".into(), json!(r));
    }
    Value::Object(m)
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// JavaScript `Number.prototype.toFixed(2)` for a finite number (ties go away from zero, unlike Rust's round-half-even formatting).
fn to_fixed2(x: f64) -> String {
    if !x.is_finite() {
        return js_number_string(x);
    }
    let a = x.abs();
    let wide = format!("{a:.30}");
    let (int, frac) = wide.split_once('.').unwrap_or((&wide, ""));
    let tie = frac.as_bytes().get(2) == Some(&b'5') && frac[3..].bytes().all(|b| b == b'0');
    let body = if tie {
        let scaled: u128 = format!("{int}{}", &frac[..2]).parse::<u128>().unwrap_or(0) + 1;
        format!("{}.{:02}", scaled / 100, scaled % 100)
    } else {
        format!("{a:.2}")
    };
    if x < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

/// One-line action summary: `verb on resource (tier N, risk R)`.
pub fn action_summary(request: &Value) -> String {
    let tier = request.get("tier").map_or(String::new(), |t| crate::adapters::js_string(t));
    format!(
        "{} on {} (tier {tier}, risk {})",
        text(request, "verb"),
        text(request, "resource"),
        to_fixed2(request.get("r").and_then(Value::as_f64).unwrap_or(f64::NAN))
    )
}

/// The goal-lineage lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal, authority, action chain, then
/// the canonical render. `Err` when the request carries a render digest that is not a canonical 32-byte value.
pub fn lineage_lines(request: &Value) -> Result<Vec<String>, String> {
    let lineage = request.get("lineage").unwrap_or(&Value::Null);
    let mut out = vec![text(lineage, "because").to_string()];
    out.extend(describe_goal_lineage(lineage));
    out.extend(render_lines(request)?);
    Ok(out)
}

fn escape_controls(s: &str) -> String {
    s.chars().map(|c| if contains(&CC_CF, c) || c == '\u{2028}' || c == '\u{2029}' { format!("\\u{{{:x}}}", c as u32) } else { c.to_string() }).collect()
}

/// The canonical render, one line per field (nothing omitted), the banner for an unreviewed action, and the speakable binding words of
/// H(R). Empty when the request carries no render. Every channel shows the same lines.
pub fn render_lines(request: &Value) -> Result<Vec<String>, String> {
    let (Some(r), Some(digest)) = (request.get("render").filter(|r| !r.is_null()), request.get("renderDigest").and_then(Value::as_str)) else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    if r.get("unreviewed") == Some(&json!(true)) {
        out.push("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.".to_string());
    }
    for f in r.get("fields").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let u = match f.get("unit") {
            Some(u) if u.get("kind") == Some(&json!("money")) => {
                format!(" {} (minor units, exponent {})", text(u, "ccy"), u.get("exp").map_or(String::new(), |e| crate::adapters::js_string(e)))
            }
            _ => String::new(),
        };
        out.push(format!("{} [{}]: {}{u}", text(f, "id"), text(f, "class"), escape_controls(&js_json(f.get("value").unwrap_or(&Value::Null)))));
    }
    out.push(format!("Match code: {}", binding_words(digest)?));
    Ok(out)
}

/// `encodeURIComponent`.
fn encode_component(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Add query parameters before any `#fragment` (an approval link may carry its token in the fragment, which must stay last).
fn append_query(url: &str, params: &[(&str, &str)]) -> String {
    let query = params.iter().map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v))).collect::<Vec<_>>().join("&");
    let (base, fragment) = match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    format!("{base}{}{query}{fragment}", if base.contains('?') { '&' } else { '?' })
}

fn inbox(ctx: &NotifyContext) -> Option<&str> {
    ctx.inbox_url.as_deref().filter(|u| !u.is_empty())
}

// ---- Slack (Block Kit over an incoming webhook) ----------------------------------------------------------------------------------------

/// The Block Kit message for a step-up: action summary, goal lineage, approve/deny affordance.
pub fn build_slack_message(request: &Value, ctx: &NotifyContext) -> Result<Value, String> {
    let bullets = lineage_lines(request)?.iter().map(|l| format!("\u{2022} {l}")).collect::<Vec<_>>().join("\n");
    let id = text(request, "id");
    let mut blocks = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": format!("Approval needed \u{b7} tier {}", request.get("tier").map_or(String::new(), |t| crate::adapters::js_string(t))), "emoji": true}}),
        json!({"type": "section", "text": {"type": "mrkdwn", "text": format!("*{}* on `{}`\n_{}_", text(request, "verb"), text(request, "resource"), text(request, "reason"))}}),
        json!({"type": "section", "text": {"type": "mrkdwn", "text": format!("*Why this is requested*\n{bullets}")}}),
    ];
    match inbox(ctx) {
        Some(url) => blocks.push(json!({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve", "emoji": true}, "url": append_query(url, &[("stepup", id), ("decision", "approve")]), "style": "primary", "action_id": "pca_approve"},
            {"type": "button", "text": {"type": "plain_text", "text": "Deny", "emoji": true}, "url": append_query(url, &[("stepup", id), ("decision", "deny")]), "style": "danger", "action_id": "pca_deny"},
        ]})),
        None => blocks.push(json!({"type": "context", "elements": [{"type": "mrkdwn", "text": format!("Approve or deny step-up `{id}` in your Atlas inbox.")}]})),
    }
    Ok(json!({"text": format!("Approval needed: {}", action_summary(request)), "blocks": blocks}))
}

fn post(kind: &str, request: &Value, payload: Value, url: &str, headers: Vec<(String, String)>, fetch: Option<&Arc<FetchLike>>, what: &str) -> Value {
    let Some(fetch) = fetch else {
        return delivery(kind, request, false, payload, None, Some("no fetch available: pass a FetchLike transport to the channel".into()));
    };
    let req = FetchRequest { url: url.to_string(), method: "POST".into(), headers, body: js_json(&payload) };
    match fetch(&req) {
        Ok(res) if res.ok => delivery(kind, request, true, payload, Some(res.status), None),
        Ok(res) => delivery(kind, request, false, payload, Some(res.status), Some(format!("{what} returned {}", res.status))),
        Err(e) => delivery(kind, request, false, payload, None, Some(if e.is_empty() { format!("{what} transport error") } else { e })),
    }
}

/// Slack approval channel. Disabled (and a no-op) unless a webhook URL is configured.
pub struct SlackChannel {
    webhook_url: Option<String>,
    fetch: Option<Arc<FetchLike>>,
}

/// Configure a Slack channel (`webhook_url`: the incoming-webhook URL, absent or empty = disabled).
pub fn slack_approval_channel(webhook_url: Option<&str>, fetch: Option<Arc<FetchLike>>) -> SlackChannel {
    SlackChannel { webhook_url: webhook_url.filter(|u| !u.is_empty()).map(String::from), fetch }
}

impl ApprovalChannel for SlackChannel {
    fn kind(&self) -> &str {
        "slack"
    }
    fn enabled(&self) -> bool {
        self.webhook_url.is_some()
    }
    fn notify(&self, request: &Value, ctx: &NotifyContext) -> Value {
        let message = match build_slack_message(request, ctx) {
            Ok(m) => m,
            Err(e) => return delivery("slack", request, false, Value::Null, None, Some(e)),
        };
        match &self.webhook_url {
            None => delivery("slack", request, false, message, None, Some("slack channel not configured".into())),
            Some(url) => post("slack", request, message, url, vec![("content-type".into(), "application/json".into())], self.fetch.as_ref(), "slack webhook"),
        }
    }
}

// ---- webhook (signed JSON POST, the channel Slack mirrors) --------------------------------------------------------------------------------

/// The webhook JSON body: the step-up plus its pre-formatted human summary and lineage.
pub fn build_webhook_body(request: &Value, ctx: &NotifyContext) -> Result<Value, String> {
    let mut m = Map::new();
    m.insert("type".into(), json!("pca.step_up.created"));
    m.insert("stepup".into(), request.clone());
    m.insert("summary".into(), json!(action_summary(request)));
    m.insert("lineage".into(), json!(lineage_lines(request)?));
    if let Some(u) = inbox(ctx) {
        m.insert("inbox_url".into(), json!(u));
    }
    Ok(Value::Object(m))
}

/// Generic webhook approval channel.
pub struct WebhookChannel {
    url: Option<String>,
    fetch: Option<Arc<FetchLike>>,
    headers: Vec<(String, String)>,
}

/// Configure a webhook channel (`url` absent or empty = disabled). `headers` are extra request headers (e.g. a caller-computed signature
/// header, never logged); one named `content-type` replaces the default.
pub fn webhook_approval_channel(url: Option<&str>, fetch: Option<Arc<FetchLike>>, headers: &[(&str, &str)]) -> WebhookChannel {
    let mut hs: Vec<(String, String)> = vec![("content-type".into(), "application/json".into())];
    for (k, v) in headers {
        match hs.iter_mut().find(|(n, _)| n == k) {
            Some(h) => h.1 = v.to_string(),
            None => hs.push((k.to_string(), v.to_string())),
        }
    }
    WebhookChannel { url: url.filter(|u| !u.is_empty()).map(String::from), fetch, headers: hs }
}

impl ApprovalChannel for WebhookChannel {
    fn kind(&self) -> &str {
        "webhook"
    }
    fn enabled(&self) -> bool {
        self.url.is_some()
    }
    fn notify(&self, request: &Value, ctx: &NotifyContext) -> Value {
        let body = match build_webhook_body(request, ctx) {
            Ok(b) => b,
            Err(e) => return delivery("webhook", request, false, Value::Null, None, Some(e)),
        };
        match &self.url {
            None => delivery("webhook", request, false, body, None, Some("webhook channel not configured".into())),
            Some(url) => post("webhook", request, body, url, self.headers.clone(), self.fetch.as_ref(), "webhook"),
        }
    }
}

// ---- text channels (email / sms / push) over an injected sender ----------------------------------------------------------------------------

/// Deliver a formatted text body (`subject`, `text`). `Ok` carries an optional channel-native message id; `Err` a failure.
pub type TextSender = dyn Fn(&str, &str) -> Result<Option<String>, String> + Send + Sync;

/// The plain-text body (subject and text) shared by the email, sms and push surfaces.
pub fn build_text_body(request: &Value, ctx: &NotifyContext) -> Result<Value, String> {
    let mut lines = vec![action_summary(request), String::new()];
    lines.extend(lineage_lines(request)?);
    if let Some(u) = inbox(ctx) {
        lines.push(String::new());
        lines.push(format!("Approve or deny: {}", append_query(u, &[("stepup", text(request, "id"))])));
    }
    Ok(json!({"subject": format!("Approval needed: {} on {}", text(request, "verb"), text(request, "resource")), "text": lines.join("\n")}))
}

/// A text-formatter channel (email, sms or push).
pub struct TextChannel {
    kind: String,
    send: Option<Arc<TextSender>>,
}

/// Configure a text channel. `kind` is `email`, `sms` or `push`; without a sender the channel is disabled.
pub fn text_approval_channel(kind: &str, send: Option<Arc<TextSender>>) -> TextChannel {
    TextChannel { kind: kind.to_string(), send }
}

impl ApprovalChannel for TextChannel {
    fn kind(&self) -> &str {
        &self.kind
    }
    fn enabled(&self) -> bool {
        self.send.is_some()
    }
    fn notify(&self, request: &Value, ctx: &NotifyContext) -> Value {
        let body = match build_text_body(request, ctx) {
            Ok(b) => b,
            Err(e) => return delivery(&self.kind, request, false, Value::Null, None, Some(e)),
        };
        let Some(send) = &self.send else { return delivery(&self.kind, request, false, body, None, Some(format!("{} channel not configured", self.kind))) };
        match send(text(&body, "subject"), text(&body, "text")) {
            Ok(_) => delivery(&self.kind, request, true, body, None, None),
            Err(e) => delivery(&self.kind, request, false, body, None, Some(if e.is_empty() { format!("{} send error", self.kind) } else { e })),
        }
    }
}

// ---- registry / dispatcher --------------------------------------------------------------------------------------------------------------------

/// Registers a set of channels behind one dispatcher. Disabled channels are skipped.
pub struct ApprovalDispatcher {
    pub channels: Vec<Box<dyn ApprovalChannel>>,
}

/// Register a set of channels behind one dispatcher.
pub fn create_approval_dispatcher(channels: Vec<Box<dyn ApprovalChannel>>) -> ApprovalDispatcher {
    ApprovalDispatcher { channels }
}

impl ApprovalDispatcher {
    /// Fan a step-up out to every ENABLED channel; one delivery per channel, in registration order.
    pub fn notify_all(&self, request: &Value, ctx: &NotifyContext) -> Vec<Value> {
        self.channels.iter().filter(|c| c.enabled()).map(|c| c.notify(request, ctx)).collect()
    }
}
