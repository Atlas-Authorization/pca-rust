//! The CIBA client (packages/pca-ciba/src/client.ts): `initiate` a backchannel authentication request at the OP, then `poll` /
//! `wait` the token endpoint with the interval, `slow_down` and transient-failure rules of CIBA Core. The transport (and the
//! sleep) are injected, as everywhere in this crate: the client owns no HTTP stack. Calls are synchronous; a PING callback
//! (`verify_ping_callback`) is followed by [`CibaPoller::notify`] and a `poll`.
use crate::agent::rand_bytes;
use crate::ciba::to_ciba_auth_request;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::fmt;

const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";
/// CIBA Core 11: on `slow_down` the interval grows by at least 5 seconds.
const SLOW_DOWN_STEP_SEC: f64 = 5.0;
const MIN_NOTIFICATION_TOKEN_CHARS: usize = 22;
const MAX_NOTIFICATION_TOKEN_CHARS: usize = 1024;
const DEFAULT_TIMEOUT_MS: f64 = 30_000.0;
const MAX_BACKOFF_MS: f64 = 60_000.0;
const MAX_CONSECUTIVE_TRANSIENT: u32 = 5;

/// An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply.
#[derive(Debug, Clone, PartialEq)]
pub struct CibaProviderError {
    pub status: u16,
    pub error: String,
    pub error_description: Option<String>,
    /// Worth retrying (network error, timeout, 5xx, non-JSON reply); not a definitive OP answer.
    pub retryable: bool,
}

impl CibaProviderError {
    fn new(status: u16, error: &str, desc: Option<&str>, retryable: bool) -> Self {
        CibaProviderError { status, error: error.into(), error_description: desc.map(String::from), retryable }
    }
}

impl fmt::Display for CibaProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ciba: provider returned {} {}", self.status, self.error)?;
        match &self.error_description {
            Some(d) => write!(f, " ({d})"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for CibaProviderError {}

/// Every way a client call can fail.
#[derive(Debug, Clone, PartialEq)]
pub enum CibaError {
    /// A caller mistake (a bad endpoint, hint count, notification token).
    Range(String),
    Provider(CibaProviderError),
    /// The step-up could not be turned into a request.
    Request(String),
}

impl fmt::Display for CibaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CibaError::Range(m) | CibaError::Request(m) => f.write_str(m),
            CibaError::Provider(p) => p.fmt(f),
        }
    }
}

impl std::error::Error for CibaError {}

fn provider(status: u16, error: &str, desc: &str, retryable: bool) -> CibaError {
    CibaError::Provider(CibaProviderError::new(status, error, Some(desc), retryable))
}

/// One POST of a form to the OP.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// The transport: `Err` is a network failure (the client reports it as the retryable `network_error`).
pub type Transport = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, String>>;

pub struct CibaClientConfig {
    pub backchannel_authentication_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub transport: Transport,
    /// Sleep for `ms` (default `std::thread::sleep`).
    pub sleep: Option<Box<dyn Fn(u64)>>,
    /// Clock in ms (default the system clock).
    pub now: Option<Box<dyn Fn() -> f64>>,
    /// Per-request timeout handed to the transport (default 30000).
    pub timeout_ms: f64,
    /// Permit `http://` endpoints: the client secret and `auth_req_id` travel on these requests, so local test providers only.
    pub allow_insecure_http: bool,
}

impl CibaClientConfig {
    pub fn new(backchannel_authentication_endpoint: &str, token_endpoint: &str, client_id: &str, client_secret: &str, transport: Transport) -> Self {
        CibaClientConfig {
            backchannel_authentication_endpoint: backchannel_authentication_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            transport,
            sleep: None,
            now: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            allow_insecure_http: false,
        }
    }
}

/// Options of [`CibaClient::initiate`]. Exactly one of the three hints is required (CIBA Core 7.1).
#[derive(Default, Clone)]
pub struct CibaInitiateOptions {
    pub login_hint: Option<String>,
    pub login_hint_token: Option<String>,
    pub id_token_hint: Option<String>,
    /// `true`: `ping` delivery (a `client_notification_token` is sent, generated when not given); default `poll`.
    pub ping: bool,
    pub client_notification_token: Option<String>,
    pub acr_values: Option<String>,
    pub user_code: Option<String>,
    /// Further options of [`to_ciba_auth_request`] (`expiresInSec`, `stepUpScope`, `bindingMessage`, `interval`, `actsFor`, `authReqId`).
    pub request: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct CibaFlow {
    pub auth_req_id: String,
    pub expires_in_sec: i64,
    pub interval_sec: i64,
    /// ms epoch the OP answered.
    pub started_at: f64,
    pub ping: bool,
    pub client_notification_token: Option<String>,
    /// The request PCA derived (scope, binding message, ...) that was sent.
    pub request: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CibaPollResult {
    Pending { interval_sec: f64 },
    Approved { tokens: Value },
    Denied { error: String },
    Expired,
}

/// A fresh `client_notification_token` (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 chars).
pub fn new_client_notification_token() -> Result<String, String> {
    Ok(crate::b64_encode(&rand_bytes::<32>()?))
}

/// JavaScript's `encodeURIComponent` over UTF-8.
fn encode_uri_component(s: &str) -> String {
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

fn check_endpoint(name: &str, value: &str, allow_insecure: bool) -> Result<(), CibaError> {
    let u = url::Url::parse(value).map_err(|_| CibaError::Range(format!("ciba: {name} is not a valid URL")))?;
    if u.scheme() == "https" || (u.scheme() == "http" && allow_insecure) {
        return Ok(());
    }
    Err(CibaError::Range(format!("ciba: {name} must be an https:// URL (set allowInsecureHttp only for a local test provider)")))
}

fn read_json(res: &HttpResponse) -> Result<Map<String, Value>, CibaError> {
    match serde_json::from_str::<Value>(&res.body) {
        Err(_) => Err(provider(res.status, "invalid_response", "the provider reply was not JSON", true)),
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(provider(res.status, "invalid_response", "the provider reply was not a JSON object", false)),
    }
}

fn provider_error(status: u16, body: &Map<String, Value>) -> CibaProviderError {
    let error = body.get("error").and_then(Value::as_str).unwrap_or("invalid_response");
    CibaProviderError::new(status, error, body.get("error_description").and_then(Value::as_str), false)
}

fn positive_int(v: Option<&Value>, name: &str, status: u16) -> Result<i64, CibaError> {
    match v.and_then(Value::as_i64) {
        Some(n) if n > 0 && n <= 9_007_199_254_740_991 => Ok(n),
        _ => Err(provider(status, "invalid_response", &format!("{name} must be a positive integer"), false)),
    }
}

pub struct CibaClient {
    cfg: CibaClientConfig,
    basic: String,
}

/// `createCibaClient`: validates the endpoints and timeout.
pub fn create_ciba_client(cfg: CibaClientConfig) -> Result<CibaClient, CibaError> {
    if !cfg.timeout_ms.is_finite() || cfg.timeout_ms <= 0.0 {
        return Err(CibaError::Range("ciba: timeoutMs must be a positive number".into()));
    }
    check_endpoint("backchannelAuthenticationEndpoint", &cfg.backchannel_authentication_endpoint, cfg.allow_insecure_http)?;
    check_endpoint("tokenEndpoint", &cfg.token_endpoint, cfg.allow_insecure_http)?;
    let cred = format!("{}:{}", encode_uri_component(&cfg.client_id), encode_uri_component(&cfg.client_secret));
    let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(cred));
    Ok(CibaClient { cfg, basic })
}

fn system_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

impl CibaClient {
    fn now(&self) -> f64 {
        self.cfg.now.as_ref().map_or_else(system_now, |f| f())
    }

    fn post(&self, url: &str, form: &[(&str, &str)]) -> Result<HttpResponse, CibaError> {
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
        let req = HttpRequest {
            url: url.into(),
            headers: vec![
                ("authorization".into(), self.basic.clone()),
                ("content-type".into(), "application/x-www-form-urlencoded".into()),
                ("accept".into(), "application/json".into()),
            ],
            body,
            timeout_ms: self.cfg.timeout_ms as u64,
        };
        (self.cfg.transport)(&req).map_err(|e| provider(0, "network_error", &e, true))
    }

    /// Send the backchannel authentication request for `step_up` and return the flow the OP opened.
    pub fn initiate(&self, step_up: &Value, opts: &CibaInitiateOptions) -> Result<CibaFlow, CibaError> {
        let hints = [&opts.login_hint, &opts.login_hint_token, &opts.id_token_hint].iter().filter(|h| h.is_some()).count();
        if hints != 1 {
            return Err(CibaError::Range("ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)".into()));
        }
        let notification = if opts.ping {
            Some(opts.client_notification_token.clone().map_or_else(new_client_notification_token, Ok).map_err(CibaError::Request)?)
        } else {
            None
        };
        if let Some(t) = &opts.client_notification_token {
            if t.len() < MIN_NOTIFICATION_TOKEN_CHARS || t.len() > MAX_NOTIFICATION_TOKEN_CHARS || !t.bytes().all(|c| (0x21..=0x7E).contains(&c)) {
                return Err(CibaError::Range(format!(
                    "ciba: clientNotificationToken must be {MIN_NOTIFICATION_TOKEN_CHARS}..{MAX_NOTIFICATION_TOKEN_CHARS} printable characters (>= 128 bits, CIBA Core 7.1)"
                )));
            }
        }
        let mut ro = opts.request.clone().filter(Value::is_object).unwrap_or_else(|| json!({}));
        if let Some(h) = &opts.login_hint {
            ro["loginHint"] = json!(h);
        }
        let request = to_ciba_auth_request(step_up, &ro).map_err(CibaError::Request)?;
        let s = |k: &str| request.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
        let (scope, binding, expiry) = (s("scope"), s("binding_message"), s("requested_expiry"));
        let mut form: Vec<(&str, &str)> = vec![("scope", &scope), ("binding_message", &binding), ("requested_expiry", &expiry)];
        for (k, v) in [
            ("login_hint", &opts.login_hint),
            ("login_hint_token", &opts.login_hint_token),
            ("id_token_hint", &opts.id_token_hint),
            ("acr_values", &opts.acr_values),
            ("user_code", &opts.user_code),
        ] {
            if let Some(v) = v {
                form.push((k, v));
            }
        }
        if let Some(t) = &notification {
            form.push(("client_notification_token", t));
        }
        let res = self.post(&self.cfg.backchannel_authentication_endpoint, &form)?;
        let body = read_json(&res)?;
        if !(200..300).contains(&res.status) {
            return Err(CibaError::Provider(provider_error(res.status, &body)));
        }
        let auth_req_id = match body.get("auth_req_id").and_then(Value::as_str) {
            Some(a) if !a.is_empty() => a.to_string(),
            _ => return Err(provider(res.status, "invalid_response", "auth_req_id missing", false)),
        };
        let expires_in_sec = positive_int(body.get("expires_in"), "expires_in", res.status)?;
        // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds
        let interval_sec = if body.get("interval").is_none() { 5 } else { positive_int(body.get("interval"), "interval", res.status)? };
        Ok(CibaFlow { auth_req_id, expires_in_sec, interval_sec, started_at: self.now(), ping: opts.ping, client_notification_token: notification, request })
    }

    pub fn poller<'a>(&'a self, flow: &CibaFlow) -> CibaPoller<'a> {
        let interval_ms = flow.interval_sec as f64 * 1000.0;
        CibaPoller {
            client: self,
            auth_req_id: flow.auth_req_id.clone(),
            interval_ms,
            next_at: flow.started_at + interval_ms,
            deadline: flow.started_at + flow.expires_in_sec as f64 * 1000.0,
            settled: None,
            failures: 0,
        }
    }
}

pub struct CibaPoller<'a> {
    client: &'a CibaClient,
    auth_req_id: String,
    interval_ms: f64,
    next_at: f64,
    deadline: f64,
    settled: Option<CibaPollResult>,
    failures: i32,
}

impl CibaPoller<'_> {
    /// Current poll interval in seconds (grows on `slow_down`).
    pub fn interval_sec(&self) -> f64 {
        self.interval_ms / 1000.0
    }

    /// A PING arrived: the next `poll()` may go out immediately.
    pub fn notify(&mut self) {
        self.next_at = self.client.now();
    }

    fn backoff(&mut self) {
        self.failures += 1;
        let delay = MAX_BACKOFF_MS.min(self.interval_ms * 2f64.powi(self.failures.min(6)));
        self.next_at = self.client.now() + delay;
    }

    fn sleep(&self, ms: f64) {
        match &self.client.cfg.sleep {
            Some(f) => f(ms as u64),
            None => std::thread::sleep(std::time::Duration::from_millis(ms as u64)),
        }
    }

    /// Sleep until the interval allows it, then ask the token endpoint once.
    pub fn poll(&mut self) -> Result<CibaPollResult, CibaError> {
        if let Some(s) = &self.settled {
            return Ok(s.clone());
        }
        let wait = self.next_at - self.client.now();
        if wait > 0.0 {
            self.sleep(wait);
        }
        if !(self.client.now() < self.deadline && self.client.now().is_finite() && self.deadline.is_finite()) {
            self.settled = Some(CibaPollResult::Expired);
            return Ok(CibaPollResult::Expired);
        }
        let attempt = (|| -> Result<(HttpResponse, Map<String, Value>), CibaError> {
            let res = self.client.post(&self.client.cfg.token_endpoint, &[("grant_type", CIBA_GRANT), ("auth_req_id", &self.auth_req_id)])?;
            if res.status >= 500 {
                return Err(provider(res.status, "server_error", "the provider answered with a server error", true));
            }
            let body = read_json(&res)?;
            Ok((res, body))
        })();
        let (res, body) = match attempt {
            Ok(x) => x,
            Err(e) => {
                if matches!(&e, CibaError::Provider(p) if p.retryable) {
                    self.backoff();
                }
                return Err(e);
            }
        };
        self.failures = 0;
        self.next_at = self.client.now() + self.interval_ms;
        if (200..300).contains(&res.status) {
            if body.get("access_token").and_then(Value::as_str).is_none() || body.get("token_type").and_then(Value::as_str).is_none() {
                return Err(provider(res.status, "invalid_response", "token response lacks access_token / token_type", false));
            }
            let r = CibaPollResult::Approved { tokens: Value::Object(body) };
            self.settled = Some(r.clone());
            return Ok(r);
        }
        let err = provider_error(res.status, &body);
        match err.error.as_str() {
            "authorization_pending" => Ok(CibaPollResult::Pending { interval_sec: self.interval_ms / 1000.0 }),
            "slow_down" => {
                self.interval_ms += SLOW_DOWN_STEP_SEC * 1000.0;
                self.next_at = self.client.now() + self.interval_ms;
                Ok(CibaPollResult::Pending { interval_sec: self.interval_ms / 1000.0 })
            }
            "access_denied" => {
                let r = CibaPollResult::Denied { error: err.error };
                self.settled = Some(r.clone());
                Ok(r)
            }
            "expired_token" => {
                self.settled = Some(CibaPollResult::Expired);
                Ok(CibaPollResult::Expired)
            }
            _ => Err(CibaError::Provider(err)),
        }
    }

    /// Poll until the flow settles. A retryable failure is tried again, up to five in a row.
    pub fn wait(&mut self) -> Result<CibaPollResult, CibaError> {
        let mut transient = 0;
        loop {
            match self.poll() {
                Ok(CibaPollResult::Pending { .. }) => transient = 0,
                Ok(r) => return Ok(r),
                Err(CibaError::Provider(p)) if p.retryable => {
                    transient += 1;
                    if transient >= MAX_CONSECUTIVE_TRANSIENT {
                        return Err(CibaError::Provider(p));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    fn step_up() -> Value {
        json!({"verb": "mail.send", "resource": "acct", "params": {}, "goal": "send the mail"})
    }

    fn client(script: Vec<(u16, &'static str)>, clock: Rc<Cell<f64>>, slept: Rc<RefCell<Vec<u64>>>) -> CibaClient {
        let q = RefCell::new(script.into_iter());
        let mut cfg = CibaClientConfig::new(
            "https://op.example/bc",
            "https://op.example/token",
            "cid",
            "sec",
            Box::new(move |_| q.borrow_mut().next().map(|(s, b)| HttpResponse { status: s, body: b.into() }).ok_or_else(|| "script exhausted".to_string())),
        );
        let c = clock.clone();
        cfg.now = Some(Box::new(move || c.get()));
        cfg.sleep = Some(Box::new(move |ms| {
            slept.borrow_mut().push(ms);
            clock.set(clock.get() + ms as f64);
        }));
        create_ciba_client(cfg).unwrap()
    }

    #[test]
    fn endpoints_and_hints_are_checked() {
        let t: Transport = Box::new(|_| Err("x".into()));
        assert!(matches!(create_ciba_client(CibaClientConfig::new("http://op/bc", "https://op/t", "a", "b", t)), Err(CibaError::Range(_))));
        assert_eq!(encode_uri_component("a b/é"), "a%20b%2F%C3%A9");
        assert!(new_client_notification_token().unwrap().len() >= MIN_NOTIFICATION_TOKEN_CHARS);
    }

    #[test]
    fn initiate_then_poll_through_pending_slow_down_and_approval() {
        let clock = Rc::new(Cell::new(1_000.0));
        let slept = Rc::new(RefCell::new(vec![]));
        let c = client(
            vec![
                (200, r#"{"auth_req_id":"r1","expires_in":120,"interval":2}"#),
                (400, r#"{"error":"authorization_pending"}"#),
                (400, r#"{"error":"slow_down"}"#),
                (200, r#"{"access_token":"at","token_type":"Bearer"}"#),
            ],
            clock,
            slept.clone(),
        );
        let opts = CibaInitiateOptions { login_hint: Some("alice".into()), ..Default::default() };
        let f = c.initiate(&step_up(), &opts).unwrap();
        assert_eq!((f.auth_req_id.as_str(), f.interval_sec, f.expires_in_sec), ("r1", 2, 120));
        let mut p = c.poller(&f);
        assert_eq!(p.poll().unwrap(), CibaPollResult::Pending { interval_sec: 2.0 });
        assert_eq!(p.poll().unwrap(), CibaPollResult::Pending { interval_sec: 7.0 });
        assert!(matches!(p.poll().unwrap(), CibaPollResult::Approved { .. }));
        // settled: no further request is made
        assert!(matches!(p.poll().unwrap(), CibaPollResult::Approved { .. }));
        assert_eq!(slept.borrow().as_slice(), &[2000, 2000, 7000]);
    }

    #[test]
    fn denied_and_provider_failures() {
        let clock = Rc::new(Cell::new(0.0));
        let c = client(vec![(200, r#"{"auth_req_id":"r","expires_in":60}"#), (400, r#"{"error":"access_denied"}"#)], clock, Rc::new(RefCell::new(vec![])));
        let f = c.initiate(&step_up(), &CibaInitiateOptions { login_hint: Some("a".into()), ..Default::default() }).unwrap();
        assert_eq!(f.interval_sec, 5);
        assert_eq!(c.poller(&f).wait().unwrap(), CibaPollResult::Denied { error: "access_denied".into() });
        let c = client(vec![(500, "x")], Rc::new(Cell::new(0.0)), Rc::new(RefCell::new(vec![])));
        let e = c.initiate(&step_up(), &CibaInitiateOptions::default()).unwrap_err();
        assert!(matches!(e, CibaError::Range(_)), "{e}");
    }
}
