//! Quantum entropy as an ADDITION to key generation, never a trust dependency. Every seed is
//! `HKDF-SHA256(local CSPRNG || quantum)`, so a hostile or broken quantum source cannot lower the result below the local CSPRNG.
//!
//! Parts: an HTTP QRNG source over an INJECTED transport ([`HttpQrngSource`]: ANU-style JSON, hex or base64 bodies, strict
//! fail-closed validation, https only, the API key never in an error), the unavailable-source stub ([`NullQrngSource`]), the
//! SP 800-90B section 4.4 continuous health tests ([`health_test_bytes`]: repetition count and adaptive proportion), the combiner
//! ([`mix_entropy`]), [`secure_seed`] (CSPRNG plus best-effort health-tested QRNG, optionally required) and an Ed25519 key-pair
//! helper ([`generate_key_pair_with_entropy`]). This crate carries no network client: the caller supplies the transport.
//!
//! Counts and lengths in the option structs are `f64`, validated here exactly as the reference validates a number (an integer in
//! range, else a refusal), so a caller that forwards an untrusted number cannot slip a fraction or a non-finite value through.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroizing;

pub const MAX_HKDF_OUTPUT: usize = 255 * 32;
pub const MIN_LOCAL_BYTES: usize = 16;
pub const DEFAULT_SEED_BYTES: usize = 32;
pub const DEFAULT_MAX_QRNG_BYTES: usize = 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

const MIX_LABEL: &str = "atlas-pca/entropy/mix/v1";
const MIX_SALT: &[u8] = b"atlas-pca/entropy/salt/v1";

/// A refusal of this module. `class` is `EntropyError` (then `code` is `quantum_required`, `health_test_failed` or
/// `insecure_transport`), `RangeError` or `TypeError` (an argument outside its range or of the wrong kind) or `Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError {
    pub class: &'static str,
    pub code: Option<String>,
    pub message: String,
}

impl EntropyError {
    /// An `EntropyError` with a code.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        EntropyError { class: "EntropyError", code: Some(code.to_string()), message: message.into() }
    }
    /// A plain failure (class `Error`).
    pub fn plain(message: impl Into<String>) -> Self {
        EntropyError { class: "Error", code: None, message: message.into() }
    }
    fn range(message: impl Into<String>) -> Self {
        EntropyError { class: "RangeError", code: None, message: message.into() }
    }
    fn type_error(message: impl Into<String>) -> Self {
        EntropyError { class: "TypeError", code: None, message: message.into() }
    }
}

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EntropyError {}

fn is_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0
}

// ---- health tests (SP 800-90B section 4.4) ------------------------------------------------------------------------------------------

/// `h` = the claimed min-entropy per byte (default 8, valid 1..=8); `window` = the adaptive-proportion window (default 512, an
/// integer >= 2).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HealthTestOptions {
    pub h: Option<f64>,
    pub window: Option<f64>,
}

/// `test` names the failed test: `repetition-count` or `adaptive-proportion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthVerdict {
    pub ok: bool,
    pub test: Option<&'static str>,
}

/// The repetition-count cutoff `1 + ceil(20 / h)` (false-positive rate 2^-20).
pub fn repetition_cutoff(h: f64) -> f64 {
    1.0 + (20.0 / h).ceil()
}

/// The largest window of [`proportion_cutoff`] (the tail is exact integer arithmetic over w * 61 bits).
pub const PROPORTION_MAX_WINDOW: f64 = 65_536.0;

/// 2^-h for h a multiple of 1/8 in [1/8, 64], by operations every platform computes identically: 0.5 multiplied floor(8h / 8) times
/// (exact), then by sqrt(0.5) if bit 4 of (8h mod 8) is set, then by sqrt(sqrt(0.5)) if bit 2 is set, then by sqrt(sqrt(sqrt(0.5)))
/// if bit 1 is set, in that order (`*` and sqrt are exactly rounded IEEE operations; pow is not).
fn proportion_p(h: f64) -> Result<f64, String> {
    let n = h * 8.0;
    if !(n.is_finite() && n.fract() == 0.0 && (1.0..=512.0).contains(&n)) {
        return Err("proportionCutoff: h must be a multiple of 1/8 in [1/8, 64]".into());
    }
    let mut p = 1.0f64;
    for _ in 0..(n / 8.0).floor() as u32 {
        p *= 0.5;
    }
    let f = (n % 8.0) as u32;
    let s1 = 0.5f64.sqrt();
    let s2 = s1.sqrt();
    let s3 = s2.sqrt();
    if f & 4 != 0 {
        p *= s1;
    }
    if f & 2 != 0 {
        p *= s2;
    }
    if f & 1 != 0 {
        p *= s3;
    }
    Ok(p)
}

/// `b^n` by square and multiply.
fn pow_big(b: &rsa::BigUint, mut n: u64) -> rsa::BigUint {
    let (mut base, mut acc) = (b.clone(), rsa::BigUint::from(1u8));
    while n > 0 {
        if n & 1 == 1 {
            acc = &acc * &base;
        }
        n >>= 1;
        if n > 0 {
            base = &base * &base;
        }
    }
    acc
}

/// The adaptive-proportion cutoff (SP 800-90B 4.4.2) for min-entropy `h` and window `w`: one more than the smallest k with
/// P[X <= k] >= 1 - 2^-20 for X ~ Bin(w, 2^-h) (k = w at most). Computed EXACTLY: p (the double [`proportion_p`] gives) is the dyadic
/// rational m / 2^e, every binomial term is an integer over 2^(e*w), and the comparison with 1 - 2^-20 is an integer comparison, so no
/// pow, exp or log can move the cutoff. Domain: h a multiple of 1/8 in [1/8, 64] and w an integer in [2, 65536]; anything else is
/// refused, never rounded.
pub fn proportion_cutoff(h: f64, w: f64) -> Result<f64, String> {
    use rsa::BigUint;
    if !(is_integer(w) && (2.0..=PROPORTION_MAX_WINDOW).contains(&w)) {
        return Err("proportionCutoff: the window must be an integer in [2, 65536]".into());
    }
    let bits = proportion_p(h)?.to_bits();
    let m = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let e = (1075 - (bits >> 52)) as usize; // p = m / 2^e (p is a normal double in [2^-64, 1/2])
    let big = |n: u64| BigUint::from(n);
    let d = big(1) << e;
    let q = &d - big(m); // 1 - p = q / d
    let wn = w as u64;
    let scale = pow_big(&d, wn); // every term over d^w
    let target = big((1 << 20) - 1) * &scale; // cdf >= 1 - 2^-20  <=>  cdf_numerator * 2^20 >= (2^20 - 1) * d^w
    let mut term = pow_big(&q, wn); // C(w,0) m^0 q^w
    let mut cdf = term.clone();
    let mut k = 0u64;
    while (cdf.clone() << 20usize) < target && k < wn {
        term = (term * big(wn - k) * big(m)) / (big(k + 1) * &q); // exact: the next term is an integer
        k += 1;
        cdf += &term;
    }
    Ok((1 + k) as f64)
}

/// Run both continuous health tests over `bytes`. FAILS CLOSED: invalid parameters and an empty buffer report a
/// `repetition-count` failure. The repetition test covers the whole buffer; the proportion test covers every COMPLETE window of
/// `min(window, len)` bytes.
pub fn health_test_bytes(bytes: &[u8], opts: &HealthTestOptions) -> HealthVerdict {
    let fail = |test: &'static str| HealthVerdict { ok: false, test: Some(test) };
    let h = opts.h.unwrap_or(8.0);
    let w0 = opts.window.unwrap_or(512.0);
    // an h that is not a multiple of 1/8 in [1, 8] is a bad parameter (the proportion cutoff is exact only on that grid)
    if !(h >= 1.0 && h <= 8.0 && is_integer(h * 8.0)) || !is_integer(w0) || w0 < 2.0 || bytes.is_empty() {
        return fail("repetition-count");
    }
    let rc = repetition_cutoff(h);
    let mut run = 1.0;
    for i in 1..bytes.len() {
        run = if bytes[i] == bytes[i - 1] { run + 1.0 } else { 1.0 };
        if run >= rc {
            return fail("repetition-count");
        }
    }
    let w = w0.min(bytes.len() as f64).min(PROPORTION_MAX_WINDOW) as usize;
    if w < 2 {
        // a window of one byte can never reach the cutoff (1 + CRITBINOM >= 2 for any p above 2^-20)
        return HealthVerdict { ok: true, test: None };
    }
    let Ok(ac) = proportion_cutoff(h, w as f64) else { return fail("repetition-count") };
    for win in bytes.chunks_exact(w) {
        let count = win.iter().filter(|b| **b == win[0]).count();
        if count as f64 >= ac {
            return fail("adaptive-proportion");
        }
    }
    HealthVerdict { ok: true, test: None }
}

// ---- response parsers ---------------------------------------------------------------------------------------------------------------

/// The bytes of an ANU-style body `{success?: true, data: [0..255, ...]}`.
pub fn parse_anu_uint8(body: &Value) -> Result<Vec<u8>, EntropyError> {
    let not_array = || EntropyError::plain("QRNG: response `data` is not an array");
    let rec = match body {
        Value::Object(m) => m,
        Value::Array(_) => return Err(not_array()),
        _ => return Err(EntropyError::plain("QRNG: response body is not a JSON object")),
    };
    if rec.get("success").is_some_and(|s| s != &Value::Bool(true)) {
        return Err(EntropyError::plain("QRNG: response reports success=false"));
    }
    let data = rec.get("data").and_then(Value::as_array).ok_or_else(not_array)?;
    let mut out = Vec::with_capacity(data.len());
    for (i, v) in data.iter().enumerate() {
        match v.as_f64().filter(|f| v.is_number() && is_integer(*f) && (0.0..=255.0).contains(f)) {
            Some(f) => out.push(f as u8),
            None => return Err(EntropyError::plain(format!("QRNG: response data[{i}] is not a 0..255 integer"))),
        }
    }
    Ok(out)
}

/// The bytes of a hex body (either case, even length; empty is empty).
pub fn parse_hex(text: &str) -> Result<Vec<u8>, EntropyError> {
    let b = text.as_bytes();
    if !b.iter().all(u8::is_ascii_hexdigit) || b.len() % 2 != 0 {
        return Err(EntropyError::plain("QRNG: malformed hex payload"));
    }
    let nib = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    Ok(b.chunks_exact(2).map(|p| (nib(p[0]) << 4) | nib(p[1])).collect())
}

/// The bytes of a standard-alphabet base64 body, decoded the forgiving way browsers do: padding may be absent, padding that is
/// present must fit the length, a length of 1 mod 4 is refused, non-canonical trailing bits are dropped. The url-safe alphabet and
/// whitespace are refused.
pub fn parse_base64(text: &str) -> Result<Vec<u8>, EntropyError> {
    let bad = || EntropyError::plain("QRNG: malformed base64 payload");
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut b = text.as_bytes();
    let pad = b.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 || b[..b.len() - pad].iter().any(|c| val(*c).is_none()) {
        return Err(bad());
    }
    if b.len() % 4 == 0 {
        b = &b[..b.len() - pad];
    }
    if b.len() % 4 == 1 {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in b {
        acc = (acc << 6) | u32::from(val(*c).ok_or_else(bad)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---- the combiner -------------------------------------------------------------------------------------------------------------------

/// HKDF-SHA256 (RFC 5869) over the `hmac` crate.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("hmac accepts any key length");
    extract.update(ikm);
    let prk = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
    let mut out = Vec::with_capacity(length + 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&prk[..]).expect("hmac accepts any key length");
        m.update(&prev);
        m.update(info);
        m.update(&[counter]);
        prev = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// `length` = the output length (default: the length of `local`; an integer in 1..=8160); `context` = an optional domain label.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MixOptions {
    pub length: Option<f64>,
    pub context: Option<String>,
}

fn output_length(length: Option<f64>, default: usize, who: &str) -> Result<usize, EntropyError> {
    match length {
        None => Ok(default),
        Some(l) if is_integer(l) && l > 0.0 && l <= MAX_HKDF_OUTPUT as f64 => Ok(l as usize),
        Some(_) => Err(EntropyError::range(format!("{who}: length must be an integer in 1..{MAX_HKDF_OUTPUT}"))),
    }
}

/// Combine local CSPRNG bytes and quantum bytes: `HKDF-SHA256(ikm = u32be(len(local)) || u32be(len(quantum)) || local || quantum,
/// salt = "atlas-pca/entropy/salt/v1", info = label || u32be(length))`. `local` shorter than 16 bytes is refused (fail closed);
/// `quantum` may be empty.
pub fn mix_entropy(local: &[u8], quantum: &[u8], opts: &MixOptions) -> Result<Vec<u8>, EntropyError> {
    if local.len() < MIN_LOCAL_BYTES {
        return Err(EntropyError::range(format!("mixEntropy: local CSPRNG must be >= {MIN_LOCAL_BYTES} bytes (fail-closed)")));
    }
    let length = match output_length(opts.length, local.len(), "mixEntropy") {
        Ok(l) if l > 0 && l <= MAX_HKDF_OUTPUT => l,
        _ => return Err(EntropyError::range(format!("mixEntropy: length must be an integer in 1..{MAX_HKDF_OUTPUT}"))),
    };
    let mut ikm = Zeroizing::new(Vec::with_capacity(8 + local.len() + quantum.len()));
    ikm.extend_from_slice(&(local.len() as u32).to_be_bytes());
    ikm.extend_from_slice(&(quantum.len() as u32).to_be_bytes());
    ikm.extend_from_slice(local);
    ikm.extend_from_slice(quantum);
    let mut info = match opts.context.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => format!("{MIX_LABEL}/{c}").into_bytes(),
        None => MIX_LABEL.as_bytes().to_vec(),
    };
    info.extend_from_slice(&(length as u32).to_be_bytes());
    Ok(hkdf_sha256(&ikm, MIX_SALT, &info, length))
}

// ---- sources ------------------------------------------------------------------------------------------------------------------------

/// A source of quantum random bytes. `fetch(n)` answers exactly `n` bytes or fails.
pub trait QrngSource {
    fn name(&self) -> String;
    fn fetch(&self, num_bytes: usize) -> Result<Vec<u8>, EntropyError>;
}

/// A source that is never available (the explicit "no QRNG configured" value).
#[derive(Debug, Clone)]
pub struct NullQrngSource {
    reason: String,
}

impl NullQrngSource {
    /// `reason` defaults to `no QRNG source configured`; an empty reason is kept as given.
    pub fn new(reason: Option<&str>) -> Self {
        NullQrngSource { reason: reason.unwrap_or("no QRNG source configured").to_string() }
    }
}

impl QrngSource for NullQrngSource {
    fn name(&self) -> String {
        "null-qrng".into()
    }
    fn fetch(&self, _num_bytes: usize) -> Result<Vec<u8>, EntropyError> {
        Err(EntropyError::plain(format!("QRNG unavailable: {}", self.reason)))
    }
}

/// [`NullQrngSource::new`].
pub fn unavailable_source(reason: Option<&str>) -> NullQrngSource {
    NullQrngSource::new(reason)
}

/// What a transport answers: `ok` (the status was a success), the status, and the body already read as JSON or as text (`Err` when
/// reading it failed).
#[derive(Debug, Clone)]
pub struct QrngHttpResponse {
    pub ok: bool,
    pub status: i64,
    pub body: Result<QrngBody, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QrngBody {
    Json(Value),
    Text(String),
}

/// Why a transport did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportFailure {
    /// The request did not finish within the timeout it was given.
    Timeout,
    /// A failure with a message (it is scrubbed of the API key before it is reported).
    Failed(String),
    /// A failure that carries no usable description.
    Unknown,
}

/// The injected HTTP transport: `(url, headers, timeout_ms)`. It MUST NOT follow redirects and MUST give up after `timeout_ms`
/// with [`TransportFailure::Timeout`].
pub type QrngTransport = dyn Fn(&str, &[(String, String)], u64) -> Result<QrngHttpResponse, TransportFailure> + Send + Sync;

/// A custom URL builder `(base, num_bytes) -> url`; its result goes through the same transport checks.
pub type QrngUrlBuilder = dyn Fn(&str, usize) -> String + Send + Sync;

/// Configuration of an [`HttpQrngSource`]. Defaults: header `x-api-key`, format `anu-uint8` (`hex` is the other named one; any
/// other value reads the body as base64), timeout 5000 ms, at most 1024 bytes per request, length parameter `length`.
#[derive(Default)]
pub struct HttpQrngConfig {
    pub url: String,
    pub api_key: Option<String>,
    pub api_key_header: Option<String>,
    pub format: Option<String>,
    pub timeout_ms: Option<f64>,
    pub max_bytes: Option<f64>,
    pub length_param: Option<String>,
    /// Extra query parameters, set in order after the length parameter (one named like it overrides it).
    pub extra_params: Vec<(String, String)>,
    pub build_url: Option<Box<QrngUrlBuilder>>,
    /// Allow plain `http` for `localhost`, `127.0.0.1` and `[::1]` only.
    pub allow_insecure_loopback: bool,
    /// The transport. Without one every fetch fails.
    pub transport: Option<Box<QrngTransport>>,
}

/// A QRNG reached over HTTPS through the injected transport.
pub struct HttpQrngSource {
    name: String,
    cfg: HttpQrngConfig,
    timeout_ms: u64,
    max_bytes: f64,
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// `searchParams.set`: replace the first pair named `key` in place and drop the others, else append.
fn set_param(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    match pairs.iter().position(|(k, _)| k == key) {
        Some(i) => {
            pairs[i].1 = value.to_string();
            let mut at = 0;
            pairs.retain(|(k, _)| {
                at += 1;
                at - 1 <= i || k != key
            });
        }
        None => pairs.push((key.to_string(), value.to_string())),
    }
}

fn assert_secure_transport(url: &str, allow_loopback: bool) -> Result<(), EntropyError> {
    let u = url::Url::parse(url).map_err(|_| EntropyError::new("insecure_transport", "QRNG: endpoint URL is not a valid URL"))?;
    if u.scheme() == "https" {
        return Ok(());
    }
    let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if u.scheme() == "http" && allow_loopback && loopback {
        return Ok(());
    }
    Err(EntropyError::new("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)"))
}

impl HttpQrngSource {
    /// Refuses an empty URL and a `max_bytes` / `timeout_ms` that is not a positive integer. An unparsable URL is not refused
    /// here (the source is then named `http-qrng(unknown)` and every fetch fails).
    pub fn new(config: HttpQrngConfig) -> Result<Self, EntropyError> {
        if config.url.is_empty() {
            return Err(EntropyError::type_error("HttpQrngSource: `url` must be a non-empty string"));
        }
        let max_bytes = config.max_bytes.unwrap_or(DEFAULT_MAX_QRNG_BYTES as f64);
        if !is_integer(max_bytes) || max_bytes <= 0.0 {
            return Err(EntropyError::type_error("HttpQrngSource: `maxBytes` must be a positive integer"));
        }
        let timeout = config.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS as f64);
        if !is_integer(timeout) || timeout <= 0.0 {
            return Err(EntropyError::type_error("HttpQrngSource: `timeoutMs` must be a positive integer"));
        }
        let host = url::Url::parse(&config.url).ok().and_then(|u| {
            let h = u.host_str()?.to_string();
            Some(match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h,
            })
        });
        let name = format!("http-qrng({})", host.filter(|h| !h.is_empty()).unwrap_or_else(|| "unknown".to_string()));
        Ok(HttpQrngSource { name, cfg: config, timeout_ms: timeout as u64, max_bytes })
    }

    fn build_url(&self, n: usize) -> Result<String, EntropyError> {
        if let Some(b) = &self.cfg.build_url {
            return Ok(b(&self.cfg.url, n));
        }
        let mut u = url::Url::parse(&self.cfg.url).map_err(|_| EntropyError { class: "TypeError", code: Some("ERR_INVALID_URL".into()), message: "Invalid URL".into() })?;
        let mut pairs: Vec<(String, String)> = u.query_pairs().into_owned().collect();
        set_param(&mut pairs, self.cfg.length_param.as_deref().unwrap_or("length"), &n.to_string());
        for (k, v) in &self.cfg.extra_params {
            set_param(&mut pairs, k, v);
        }
        u.query_pairs_mut().clear().extend_pairs(pairs.iter());
        Ok(u.to_string())
    }

    /// [`QrngSource::fetch`] for a count that arrives as a number: anything but a positive integer is refused, as is a count
    /// above the per-request cap, before anything else happens.
    pub fn fetch_num(&self, num_bytes: f64) -> Result<Vec<u8>, EntropyError> {
        if !is_integer(num_bytes) || num_bytes <= 0.0 {
            return Err(EntropyError::type_error(format!("QRNG: numBytes must be a positive integer, got {}", crate::intent_v2::js_number_string(num_bytes))));
        }
        if num_bytes > self.max_bytes {
            return Err(EntropyError::range(format!(
                "QRNG: requested {} bytes exceeds per-request cap {}",
                crate::intent_v2::js_number_string(num_bytes),
                crate::intent_v2::js_number_string(self.max_bytes)
            )));
        }
        let n = num_bytes as usize;
        let transport = self.cfg.transport.as_ref().ok_or_else(|| EntropyError::plain("QRNG: no fetch implementation available in this runtime"))?;
        let url = self.build_url(n)?;
        assert_secure_transport(&url, self.cfg.allow_insecure_loopback)?;
        let key = self.cfg.api_key.as_deref().filter(|k| !k.is_empty());
        let mut headers = vec![("accept".to_string(), "application/json, text/plain".to_string())];
        if let Some(k) = key {
            headers.push((self.cfg.api_key_header.clone().unwrap_or_else(|| "x-api-key".to_string()), k.to_string()));
        }
        let res = match catch_unwind(AssertUnwindSafe(|| transport(&url, &headers, self.timeout_ms))) {
            Ok(Ok(r)) => r,
            Ok(Err(f)) => {
                let why = match f {
                    TransportFailure::Timeout => "timeout".to_string(),
                    TransportFailure::Failed(m) => m,
                    TransportFailure::Unknown => "unknown error".to_string(),
                };
                // the key never reaches an error message
                let why = match key {
                    Some(k) => why.replace(k, "[redacted]"),
                    None => why,
                };
                return Err(EntropyError::plain(format!("QRNG: fetch failed ({why})")));
            }
            Err(_) => return Err(EntropyError::plain("QRNG: fetch failed (unknown error)")),
        };
        if !res.ok {
            return Err(EntropyError::plain(format!("QRNG: endpoint returned HTTP {}", res.status)));
        }
        let body = res.body.map_err(EntropyError::plain)?;
        let bytes = match (self.cfg.format.as_deref().unwrap_or("anu-uint8"), body) {
            ("anu-uint8", QrngBody::Json(v)) => parse_anu_uint8(&v)?,
            ("anu-uint8", QrngBody::Text(t)) => parse_anu_uint8(&serde_json::from_str(&t).map_err(|_| EntropyError::plain("QRNG: response body is not valid JSON"))?)?,
            (_, QrngBody::Json(_)) => return Err(EntropyError::plain("QRNG: response body is not text")),
            ("hex", QrngBody::Text(t)) => parse_hex(js_trim(&t))?,
            (_, QrngBody::Text(t)) => parse_base64(js_trim(&t))?,
        };
        if bytes.len() != n {
            return Err(EntropyError::plain(format!("QRNG: expected {n} bytes, response decoded to {}", bytes.len())));
        }
        Ok(bytes)
    }
}

impl QrngSource for HttpQrngSource {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn fetch(&self, num_bytes: usize) -> Result<Vec<u8>, EntropyError> {
        self.fetch_num(num_bytes as f64)
    }
}

// ---- secure seed --------------------------------------------------------------------------------------------------------------------

/// Options of [`secure_seed`]. Defaults: `length` 32, `local_bytes` and `quantum_bytes` `max(32, length)`, the health test on with
/// its default parameters, the platform CSPRNG.
#[derive(Default)]
pub struct SecureSeedOptions<'a> {
    pub length: Option<f64>,
    pub source: Option<&'a dyn QrngSource>,
    pub quantum_bytes: Option<f64>,
    pub local_bytes: Option<f64>,
    pub context: Option<String>,
    /// Fail (code `quantum_required`) unless health-tested quantum bytes were mixed in.
    pub require_quantum: bool,
    /// Parameters of the health test of the quantum bytes (`None`: the defaults). Invalid parameters REJECT the source.
    pub health_test: Option<HealthTestOptions>,
    /// Skip the health test of the quantum bytes.
    pub skip_health_test: bool,
    /// Told why a source was not used. A hook that panics is ignored: observability never breaks key generation.
    pub on_qrng_error: Option<&'a dyn Fn(&EntropyError)>,
    /// The local CSPRNG (tests inject one). It must answer exactly the requested number of bytes.
    pub random_bytes: Option<&'a dyn Fn(usize) -> Result<Vec<u8>, EntropyError>>,
}

pub struct SecureSeedResult {
    pub seed: Zeroizing<Vec<u8>>,
    pub used_quantum: bool,
    pub quantum_byte_count: usize,
    /// The name of the configured source, used or not.
    pub source: Option<String>,
}

fn draw_local(imp: Option<&dyn Fn(usize) -> Result<Vec<u8>, EntropyError>>, n: usize) -> Result<Zeroizing<Vec<u8>>, EntropyError> {
    let bytes = match imp {
        Some(f) => Zeroizing::new(f(n)?),
        None => {
            let mut b = Zeroizing::new(vec![0u8; n]);
            getrandom::getrandom(&mut b).map_err(|_| EntropyError::plain("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)"))?;
            b
        }
    };
    if bytes.len() != n {
        return Err(EntropyError::plain("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)"));
    }
    Ok(bytes)
}

/// A seed of `length` bytes from the local CSPRNG mixed with quantum bytes when a source is configured, answers exactly the
/// requested count and passes the health test. Any source failure falls back to the local CSPRNG alone (and tells the hook),
/// unless `require_quantum` is set.
pub fn secure_seed(opts: &SecureSeedOptions<'_>) -> Result<SecureSeedResult, EntropyError> {
    let length = output_length(opts.length, DEFAULT_SEED_BYTES, "secureSeed")?;
    let default_draw = DEFAULT_SEED_BYTES.max(length) as f64;
    let local_bytes = opts.local_bytes.unwrap_or(default_draw);
    if !is_integer(local_bytes) || local_bytes < MIN_LOCAL_BYTES as f64 {
        return Err(EntropyError::range(format!("secureSeed: localBytes must be an integer >= {MIN_LOCAL_BYTES}")));
    }
    let quantum_bytes = opts.quantum_bytes.unwrap_or(default_draw);
    if !is_integer(quantum_bytes) || quantum_bytes <= 0.0 {
        return Err(EntropyError::range("secureSeed: quantumBytes must be a positive integer"));
    }
    let want = quantum_bytes as usize;
    let local = draw_local(opts.random_bytes, local_bytes as usize)?;
    let mut quantum: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut used_quantum = false;
    let source_name = opts.source.map(|s| s.name());
    if let Some(source) = opts.source {
        let fetched = catch_unwind(AssertUnwindSafe(|| source.fetch(want))).unwrap_or_else(|_| Err(EntropyError::plain("QRNG: the source failed")));
        let checked = fetched.and_then(|q| {
            if q.len() != want {
                return Err(EntropyError::plain(format!("QRNG: source returned {}, expected {want}", q.len())));
            }
            if !opts.skip_health_test {
                let v = health_test_bytes(&q, &opts.health_test.unwrap_or_default());
                if !v.ok {
                    return Err(EntropyError::new("health_test_failed", format!("QRNG: {} test failed; source rejected", v.test.unwrap_or("health"))));
                }
            }
            Ok(q)
        });
        match checked {
            Ok(q) => {
                quantum = Zeroizing::new(q);
                used_quantum = true;
            }
            Err(e) => {
                if let Some(hook) = opts.on_qrng_error {
                    let _ = catch_unwind(AssertUnwindSafe(|| hook(&e)));
                }
            }
        }
    }
    if opts.require_quantum && !used_quantum {
        return Err(EntropyError::new("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)"));
    }
    let seed = mix_entropy(&local, &quantum, &MixOptions { length: Some(length as f64), context: opts.context.clone() })?;
    Ok(SecureSeedResult { seed: Zeroizing::new(seed), used_quantum, quantum_byte_count: quantum.len(), source: source_name })
}

/// An Ed25519 key pair whose 32-byte secret is a [`secure_seed`].
pub struct EntropyKeyPair {
    pub secret_key: Zeroizing<Vec<u8>>,
    /// The raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
    pub used_quantum: bool,
}

/// An Ed25519 key pair from [`secure_seed`] with `length` 32 (a caller `length` is ignored) and context `ed25519-key` unless the
/// caller names one (an explicit empty context stays empty).
pub fn generate_key_pair_with_entropy(opts: &SecureSeedOptions<'_>) -> Result<EntropyKeyPair, EntropyError> {
    let seeded = secure_seed(&SecureSeedOptions {
        length: Some(32.0),
        source: opts.source,
        quantum_bytes: opts.quantum_bytes,
        local_bytes: opts.local_bytes,
        context: Some(opts.context.clone().unwrap_or_else(|| "ed25519-key".to_string())),
        require_quantum: opts.require_quantum,
        health_test: opts.health_test,
        skip_health_test: opts.skip_health_test,
        on_qrng_error: opts.on_qrng_error,
        random_bytes: opts.random_bytes,
    })?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seeded.seed);
    let public = crate::agent::KeyPair::from_seed(&seed).public;
    let public_key = crate::decode_b64u_strict(&public, Some(32)).ok_or_else(|| EntropyError::plain("generateKeyPairWithEntropy: malformed public key"))?;
    Ok(EntropyKeyPair { secret_key: seeded.seed, public_key, used_quantum: seeded.used_quantum })
}

#[cfg(test)]
mod exact_cutoff_tests {
    use super::*;

    #[test]
    fn the_cutoffs_are_exact_where_the_float_recurrence_underflowed() {
        assert_eq!(proportion_cutoff(1.0, 2000.0), Ok(1107.0)); // the float form returned 2001, which disabled the test
        assert_eq!(proportion_cutoff(8.0, 512.0), Ok(13.0));
        assert_eq!(proportion_cutoff(0.5, 512.0), Ok(410.0));
    }

    #[test]
    fn a_domain_violation_is_refused_never_rounded() {
        let w = "proportionCutoff: the window must be an integer in [2, 65536]";
        let h = "proportionCutoff: h must be a multiple of 1/8 in [1/8, 64]";
        for bad in [1.0, 2.5, 65537.0, 0.0, -2.0, f64::NAN, f64::INFINITY] {
            assert_eq!(proportion_cutoff(1.0, bad), Err(w.to_string()), "window {bad}");
        }
        for bad in [0.0, 0.1, 0.126, 64.125, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(proportion_cutoff(bad, 512.0), Err(h.to_string()), "h {bad}");
        }
        assert!(proportion_cutoff(0.125, 2.0).is_ok() && proportion_cutoff(64.0, 65536.0).is_ok());
    }

    #[test]
    fn health_test_bytes_treats_a_bad_h_as_a_failed_repetition_and_skips_a_one_byte_window() {
        let bytes: Vec<u8> = (0..64u32).map(|i| (i * 7 % 251) as u8).collect();
        let o = |h: f64, w: f64| HealthTestOptions { h: Some(h), window: Some(w) };
        assert_eq!(health_test_bytes(&bytes, &o(8.5, 8.0)).test, Some("repetition-count"));
        assert_eq!(health_test_bytes(&bytes, &o(7.3, 8.0)).test, Some("repetition-count"));
        assert!(health_test_bytes(&bytes, &o(8.0, 512.0)).ok); // the window clamps to the buffer
        assert!(health_test_bytes(&[7u8], &o(8.0, 512.0)).ok); // a one-byte window skips the proportion test
    }
}
