//! Step-up client for the principal's device: list, approve and deny a PCA step-up (a threshold-3 action waiting for the
//! principal's signature), as the mobile SDKs do.
//!
//! * [`PrincipalDeviceKey`] is the principal's Ed25519 key, persisted through a [`SecretStore`] you provide (an OS keystore, an
//!   encrypted file, ...). The key is a SOFTWARE key: once loaded the 32-byte seed is in process memory. Gate every approval
//!   behind a user-presence check in your application.
//! * [`StepUpClient`] talks to two hosts: the dashboard API (`dashboard_url`, with a dashboard bearer token, serving the list
//!   and the deny route) and the Atlas instance the agent talks to (`instance_url`, serving the public, self-authenticating
//!   `POST /v1/pca/stepups/:id/cosign`; the device signature is the credential).
//! * HTTP is yours: implement [`StepUpTransport`] over `reqwest`, `ureq`, `hyper` or a mock. This crate adds no HTTP dependency.

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::{b64_encode, decode_b64u_strict};

/// Everything the step-up module can return as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpError {
    /// No principal key is stored yet: call [`PrincipalDeviceKey::generate_with`] or [`PrincipalDeviceKey::import_secret`].
    NoDeviceKey,
    /// The principal secret is not a base64url 32-byte Ed25519 seed.
    InvalidSecret,
    /// The server's `threshold_message` is not valid base64url.
    InvalidThresholdMessage,
    /// HTTP 403: this device key is not the grant's principal key. The text is the server's guidance.
    PrincipalMismatch(String),
    /// Any other non-2xx answer (409 already approved / denied / expired, 401, 404, 422, ...).
    Api { status: u16, message: String },
    /// A network failure, an unreadable body, or the secret store failing.
    Transport(String),
}

impl std::fmt::Display for StepUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepUpError::NoDeviceKey => f.write_str("No principal device key is stored on this device."),
            StepUpError::InvalidSecret => f.write_str("The principal secret must be a base64url-encoded 32-byte Ed25519 seed."),
            StepUpError::InvalidThresholdMessage => f.write_str("The step-up's threshold message is not valid base64url."),
            StepUpError::PrincipalMismatch(m) | StepUpError::Transport(m) => f.write_str(m),
            StepUpError::Api { status, message } => write!(f, "HTTP {status}: {message}"),
        }
    }
}

impl std::error::Error for StepUpError {}

/// Where the 32-byte Ed25519 seed is persisted.
pub trait SecretStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn save(&self, secret: &[u8]) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

/// In-memory store, for tests and demos only.
#[derive(Debug, Default)]
pub struct InMemorySecretStore {
    value: Mutex<Option<Vec<u8>>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.value.lock().map_err(|_| "the secret store lock is poisoned".to_string())?.clone())
    }

    fn save(&self, secret: &[u8]) -> Result<(), String> {
        *self.value.lock().map_err(|_| "the secret store lock is poisoned".to_string())? = Some(secret.to_vec());
        Ok(())
    }

    fn delete(&self) -> Result<(), String> {
        *self.value.lock().map_err(|_| "the secret store lock is poisoned".to_string())? = None;
        Ok(())
    }
}

/// The principal's Ed25519 device key.
pub struct PrincipalDeviceKey {
    store: Box<dyn SecretStore>,
}

fn store_err(e: String) -> StepUpError {
    StepUpError::Transport(format!("secret store: {e}"))
}

impl PrincipalDeviceKey {
    pub fn new(store: impl SecretStore + 'static) -> Self {
        PrincipalDeviceKey { store: Box::new(store) }
    }

    /// True when a key is stored.
    pub fn exists(&self) -> bool {
        matches!(self.store.load(), Ok(Some(_)))
    }

    /// Generate a fresh key from 32 bytes of CSPRNG output that `fill` writes (this crate carries no random source; pass
    /// `getrandom::fill` or your platform's secure random), replacing any existing one. Returns the public key (base64url) to
    /// register as the grant's principal.
    pub fn generate_with(&self, fill: impl FnOnce(&mut [u8; 32])) -> Result<String, StepUpError> {
        let mut seed = [0u8; 32];
        fill(&mut seed);
        if seed == [0u8; 32] {
            return Err(StepUpError::InvalidSecret); // an all-zero fill is a broken random source, never a key
        }
        self.store.save(&seed).map_err(store_err)?;
        Ok(public_of(&seed))
    }

    /// Import an existing principal secret (base64url 32-byte seed, as `@atlasauth/pca` encodes `secretKey`). It MUST match the
    /// grant's principal. Returns the public key.
    pub fn import_secret(&self, secret_b64u: &str) -> Result<String, StepUpError> {
        let raw = decode_b64u_strict(secret_b64u, Some(32)).ok_or(StepUpError::InvalidSecret)?;
        self.store.save(&raw).map_err(store_err)?;
        let seed: [u8; 32] = raw.try_into().map_err(|_| StepUpError::InvalidSecret)?;
        Ok(public_of(&seed))
    }

    /// Export the secret (base64url seed) for backup or migration. Treat it like a password.
    pub fn export_secret(&self) -> Result<String, StepUpError> {
        Ok(b64_encode(&self.load_seed()?))
    }

    /// The public key (base64url), as registered on the grant.
    pub fn public_key(&self) -> Result<String, StepUpError> {
        Ok(public_of(&self.load_seed()?))
    }

    /// Ed25519-sign `message`; returns the signature as base64url.
    pub fn sign(&self, message: &[u8]) -> Result<String, StepUpError> {
        let key = SigningKey::from_bytes(&self.load_seed()?);
        Ok(b64_encode(&key.sign(message).to_bytes()))
    }

    /// Remove the key from secure storage.
    pub fn delete(&self) -> Result<(), StepUpError> {
        self.store.delete().map_err(store_err)
    }

    fn load_seed(&self) -> Result<[u8; 32], StepUpError> {
        let raw = self.store.load().map_err(store_err)?.ok_or(StepUpError::NoDeviceKey)?;
        raw.try_into().map_err(|_| StepUpError::InvalidSecret)
    }
}

fn public_of(seed: &[u8; 32]) -> String {
    b64_encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

/// A t=3 action waiting for the principal's device signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStepUp {
    pub id: String,
    pub grant_ref: String,
    pub action_verb: String,
    pub action_resource: String,
    pub required_t: i64,
    /// base64url of the exact bytes the principal key must sign.
    pub threshold_message_b64u: String,
    /// Expiry as epoch milliseconds.
    pub expires_at: i64,
}

impl PendingStepUp {
    /// Human summary for a confirmation sheet, for example `payments.refund on order/1234`.
    pub fn summary(&self) -> String {
        format!("{} on {}", self.action_verb, self.action_resource)
    }
}

/// Result of an approval. `anchored` is true once enough roles signed and the action was released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveResult {
    pub status: String,
    pub anchored: bool,
    pub http_status: u16,
}

/// One HTTP request the client wants sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// `"GET"` or `"POST"`.
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// The answer to an [`HttpRequest`]: any HTTP status is an answer (the client maps non-2xx itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Your HTTP stack. `Err` is a network failure.
pub trait StepUpTransport: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

/// Lists, approves and denies PCA step-ups from the principal's device.
pub struct StepUpClient {
    dashboard: String,
    instance: String,
    account_id: String,
    instance_id: String,
    key: PrincipalDeviceKey,
    token: Box<dyn Fn() -> String + Send + Sync>,
    transport: Arc<dyn StepUpTransport>,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

/// Percent-encode one URL path segment.
fn segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// `2026-10-06T18:00:00.123Z` (fraction optional, always UTC from the API) as epoch milliseconds; `None` when unreadable.
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || !s.is_char_boundary(19) || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r).filter(|t| t.bytes().all(|c| c.is_ascii_digit())).and_then(|t| t.parse::<i64>().ok());
    let (y, mo, d, h, mi, sec) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let frac = match s[19..].strip_prefix('.') {
        Some(rest) => {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                return None;
            }
            format!("{digits:0<3}")[..3].parse::<i64>().ok()?
        }
        None => 0,
    };
    Some(((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60_000 + sec * 1000 + frac)
}

fn unreadable_entry() -> StepUpError {
    StepUpError::Transport("Unreadable step-up entry.".into())
}

impl StepUpClient {
    /// `token()` returns the dashboard bearer token (a `dsk_` service key or console session token), called per request.
    pub fn new(
        dashboard_url: &str,
        instance_url: &str,
        account_id: impl Into<String>,
        instance_id: impl Into<String>,
        key: PrincipalDeviceKey,
        token: impl Fn() -> String + Send + Sync + 'static,
        transport: Arc<dyn StepUpTransport>,
    ) -> Self {
        StepUpClient {
            dashboard: dashboard_url.trim_end_matches('/').to_string(),
            instance: instance_url.trim_end_matches('/').to_string(),
            account_id: account_id.into(),
            instance_id: instance_id.into(),
            key,
            token: Box::new(token),
            transport,
            now: Box::new(|| {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
            }),
        }
    }

    /// Override the clock (epoch ms) used to drop expired step-ups.
    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Box::new(now);
        self
    }

    /// The device key (to read its public key for registration).
    pub fn key(&self) -> &PrincipalDeviceKey {
        &self.key
    }

    fn stepups_url(&self) -> String {
        format!("{}/v1/dashboard/accounts/{}/instances/{}/pca/stepups", self.dashboard, segment(&self.account_id), segment(&self.instance_id))
    }

    fn call(&self, req: HttpRequest) -> Result<HttpResponse, StepUpError> {
        let resp = self.transport.send(req).map_err(StepUpError::Transport)?;
        if (200..300).contains(&resp.status) {
            return Ok(resp);
        }
        // the section 9.1 envelope: { errors: [{ code, message }] }
        let message = serde_json::from_str::<Value>(&resp.body)
            .ok()
            .and_then(|v| v["errors"][0]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| "The request failed.".to_string());
        Err(if resp.status == 403 { StepUpError::PrincipalMismatch(message) } else { StepUpError::Api { status: resp.status, message } })
    }

    fn bearer(&self) -> (String, String) {
        ("Authorization".to_string(), format!("Bearer {}", (self.token)()))
    }

    /// Pending, not-yet-expired step-ups.
    pub fn pending(&self) -> Result<Vec<PendingStepUp>, StepUpError> {
        let req = HttpRequest { method: "GET", url: format!("{}?status=pending", self.stepups_url()), headers: vec![self.bearer()], body: None };
        let body = self.call(req)?.body;
        let doc: Value = serde_json::from_str(&body).map_err(|_| StepUpError::Transport("Unreadable step-up list.".into()))?;
        let list = doc["stepups"].as_array().ok_or_else(|| StepUpError::Transport("Unreadable step-up list.".into()))?;
        let t = (self.now)();
        let mut out = Vec::new();
        for el in list {
            let s = |v: &Value| v.as_str().map(str::to_string).ok_or_else(unreadable_entry);
            let exp = parse_iso_ms(el["expires_at"].as_str().ok_or_else(unreadable_entry)?).ok_or_else(unreadable_entry)?;
            if exp <= t {
                continue;
            }
            out.push(PendingStepUp {
                id: s(&el["id"])?,
                grant_ref: s(&el["grant_ref"])?,
                action_verb: s(&el["action"]["verb"])?,
                action_resource: s(&el["action"]["resource"])?,
                required_t: el["required_t"].as_i64().ok_or_else(unreadable_entry)?,
                threshold_message_b64u: s(&el["threshold_message"])?,
                expires_at: exp,
            });
        }
        Ok(out)
    }

    /// Sign the step-up's threshold message with the device key and submit it. [`StepUpError::PrincipalMismatch`] (server 403)
    /// means this key is not the grant's principal.
    pub fn approve(&self, step_up: &PendingStepUp) -> Result<ApproveResult, StepUpError> {
        let message = decode_b64u_strict(step_up.threshold_message_b64u.trim_end_matches('='), None).ok_or(StepUpError::InvalidThresholdMessage)?;
        let payload = json!({"role": "principal", "publicKey": self.key.public_key()?, "sig": self.key.sign(&message)?}).to_string();
        let req = HttpRequest {
            method: "POST",
            url: format!("{}/v1/pca/stepups/{}/cosign", self.instance, segment(&step_up.id)),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(payload),
        };
        let resp = self.call(req)?;
        let obj = serde_json::from_str::<Value>(&resp.body).ok();
        // 200 + allow:true = anchored; 202 = more roles still required
        Ok(ApproveResult {
            status: obj.as_ref().and_then(|o| o["status"].as_str()).unwrap_or("").to_string(),
            anchored: obj.as_ref().and_then(|o| o["allow"].as_bool()).unwrap_or(false),
            http_status: resp.status,
        })
    }

    /// Deny a pending step-up (dashboard endpoint; audited; owner or admin).
    pub fn deny(&self, step_up: &PendingStepUp, reason: Option<&str>) -> Result<(), StepUpError> {
        let payload = reason.map_or_else(|| json!({}), |r| json!({"reason": r})).to_string();
        let req = HttpRequest {
            method: "POST",
            url: format!("{}/{}/deny", self.stepups_url(), segment(&step_up.id)),
            headers: vec![self.bearer(), ("Content-Type".to_string(), "application/json".to_string())],
            body: Some(payload),
        };
        self.call(req).map(|_| ())
    }
}
