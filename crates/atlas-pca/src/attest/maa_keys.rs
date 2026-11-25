//! Rotation-safe key trust for Azure MAA token-signing keys (port of `attest-maa-keys.ts`).
//!
//! `createAzureMaaVerifier` needs trust anchors (SPKI pins); MAA instance signing certificates ROTATE, so a hard-coded pin silently breaks
//! (or gets "fixed" by pinning whatever the service returns). This module derives `{rootSpkiSha256: [..]}` from a freshly fetched
//! `<issuer>/certs` JWKS under an explicit rotation policy, persists the accepted set, and fails closed when the policy is violated.
//!
//! GUARANTEED: network I/O only when the caller asks, only for the HTTPS issuers pinned in `policy.trustedIssuers`, with redirects
//! refused, a response-URL check, a body-size limit and the transport's own timeout; `fetch` is injected, never taken from a global.
//! Every certificate that contributes an anchor is validated (a self-signed instance certificate: subject EXACTLY `CN=<issuer URL>`,
//! genuinely self-signed, inside its validity window plus skew, no older than `maxKeyAgeMs`, RSA 2048..8192 bits or EC P-256 / P-384 /
//! P-521; a Microsoft-chained key only through a pinned chain root and, when pinned, a pinned intermediate). The accepted anchor set may
//! only change by ROTATION (a bounded number of unseen keys per fetch and, by default, at least one key in common with the previous
//! unexpired set); a total replacement needs an operator-signed re-pin manifest, whose `revoked` tombstones also strip a key the JWKS
//! still serves. Results are cached for `ttlMs`; a TRANSPORT failure serves the last accepted set for at most `maxStaleMs`, a policy
//! violation never falls back to stale data. The persisted state is validated on load and `fetchedAtMs` is monotone.
//!
//! NOT guaranteed: the offline root for the self-signed instance keys is the release signing key plus the recorded multi-vantage
//! corroboration ([`super::maa_pins`]), not Microsoft; a self-signed instance certificate proves "served from this TLS origin" only; no
//! CRL or Microsoft revocation is consulted; a slow in-policy rotation chain is accepted by design.
//!
//! JSON-valued where the reference's shapes are (`serde_json::Value` in, the reference's member names out); the fetch, the state store
//! and the timeout are seams, synchronous.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use super::allowlist::{project_allowlist, verify_allowlist_manifest, AllowlistKv, VerifyOptions};
use super::der::{der_validity_ms, strict_chain_error};
use super::maa_pins::{load_builtin_maa_pins, BUILTIN_CHAIN_LEAF_CN};
use super::util::b64_lenient;
use super::x509::{Cert, EcCurve, PubKey};

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;
const MAX_JWKS_KEYS: usize = 32;
const MAX_X5C: usize = 8;
const MAX_X5C_B64: usize = 131_072;

/// `^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`.
fn issuer_url_ok(l: &str) -> bool {
    let Some(rest) = l.strip_prefix("https://") else { return false };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if port.is_some_and(|p| !(1..=5).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_digit() || b.is_ascii_lowercase();
    let b = host.as_bytes();
    !b.is_empty() && alnum(b[0]) && alnum(b[b.len() - 1]) && b.iter().all(|c| alnum(*c) || *c == b'.' || *c == b'-')
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn safe_integer(v: &Value) -> Option<f64> {
    v.as_f64().filter(|n| n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0)
}

// ---- the state store -------------------------------------------------------------------------------------------------------------

/// Caller-supplied persistence of the accepted key sets (one JSON state per issuer).
pub trait MaaKeyStateStore: Send + Sync {
    fn get(&self, issuer: &str) -> Option<Value>;
    fn set(&self, issuer: &str, state: &Value);
}

/// A simple in-memory store (tests, single process). Production callers persist durably.
#[derive(Default)]
pub struct MemoryMaaKeyStateStore(Mutex<BTreeMap<String, Value>>);

/// `createMemoryMaaKeyStateStore`, pre-seeded with `initial` (issuer to raw state).
pub fn create_memory_maa_key_state_store(initial: &Value) -> MemoryMaaKeyStateStore {
    let s = MemoryMaaKeyStateStore::default();
    for (k, v) in initial.as_object().into_iter().flatten() {
        s.0.lock().unwrap().insert(k.clone(), v.clone());
    }
    s
}

impl MemoryMaaKeyStateStore {
    /// The current content, issuer to state.
    pub fn snapshot(&self) -> Value {
        Value::Object(self.0.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}

impl MaaKeyStateStore for MemoryMaaKeyStateStore {
    fn get(&self, issuer: &str) -> Option<Value> {
        self.0.lock().unwrap().get(issuer).cloned()
    }
    fn set(&self, issuer: &str, state: &Value) {
        self.0.lock().unwrap().insert(issuer.to_string(), state.clone());
    }
}

/// A key state store over durable key-value state (key `maa-keys/<issuer>`). Writes are atomic read-modify-write and MONOTONE in
/// `fetchedAtMs`: a stale writer can never move the stored state backwards. A corrupt stored record is returned as is, so the trust
/// store fails closed (`corrupt-state`).
pub struct DurableMaaKeyStateStore<K: AllowlistKv + Send + Sync>(pub K);

/// `durableMaaKeyStateStore(kv)`.
pub fn durable_maa_key_state_store<K: AllowlistKv + Send + Sync>(kv: K) -> DurableMaaKeyStateStore<K> {
    DurableMaaKeyStateStore(kv)
}

impl<K: AllowlistKv + Send + Sync> MaaKeyStateStore for DurableMaaKeyStateStore<K> {
    fn get(&self, issuer: &str) -> Option<Value> {
        self.0.get(&format!("maa-keys/{issuer}"))
    }
    fn set(&self, issuer: &str, state: &Value) {
        let at = state.get("fetchedAtMs").and_then(Value::as_f64).unwrap_or(f64::NAN);
        self.0.update(&format!("maa-keys/{issuer}"), &mut |prev: Option<&Value>| {
            let newer_stored = prev.and_then(|p| parse_state(p, issuer)).is_some_and(|p| p["fetchedAtMs"].as_f64().unwrap_or(f64::NAN) > at);
            (!newer_stored).then(|| state.clone())
        });
    }
}

// ---- the guarded fetch -----------------------------------------------------------------------------------------------------------

/// What the transport is asked for: redirects are an error, the body is JSON, and the call is bounded by `timeout_ms` (the transport
/// enforces it).
#[derive(Clone, Debug)]
pub struct FetchInit {
    pub redirect_error: bool,
    pub timeout_ms: u64,
}

/// The transport's answer.
#[derive(Clone, Debug, Default)]
pub struct MaaHttpResponse {
    pub status: u16,
    /// The final URL the response came from, when the transport knows it.
    pub url: Option<String>,
    /// The `content-length` header, when present.
    pub content_length: Option<String>,
    pub body: Vec<u8>,
}

/// An injected transport: a URL and the request options in, the response out; `Err` is a transport failure.
pub type MaaFetch = dyn Fn(&str, &FetchInit) -> Result<MaaHttpResponse, String> + Send + Sync;

fn parse_jwks(x: &Value) -> Result<Value, String> {
    let raw = x.get("keys").and_then(Value::as_array).ok_or("MAA certs: response has no keys array")?;
    if raw.len() > MAX_JWKS_KEYS {
        return Err("MAA certs: too many keys".into());
    }
    let mut keys = Vec::new();
    for k in raw {
        let Some(r) = k.as_object() else { return Err("MAA certs: malformed key entry".into()) };
        let x5c = r.get("x5c").and_then(Value::as_array).filter(|a| {
            !a.is_empty() && a.len() <= MAX_X5C && a.iter().all(|c| c.as_str().is_some_and(|s| !s.is_empty() && s.encode_utf16().count() <= MAX_X5C_B64))
        });
        let Some(x5c) = x5c else { return Err("MAA certs: key without a well-formed x5c".into()) };
        let mut m = Map::new();
        for f in ["kid", "kty", "alg"] {
            if let Some(s) = r.get(f).filter(|v| v.is_string()) {
                m.insert(f.into(), s.clone());
            }
        }
        m.insert("x5c".into(), Value::Array(x5c.clone()));
        keys.push(Value::Object(m));
    }
    Ok(json!({"keys": keys}))
}

/// Fetch `<issuer>/certs` with HTTPS only, no redirects, a size limit and the transport's timeout. `Err` on any problem. `timeout_ms`
/// (default 10 s) and `max_bytes` (default 1 MiB) are the limits.
pub fn fetch_maa_certs(issuer: &str, fetch: Option<&MaaFetch>, timeout_ms: Option<u64>, max_bytes: Option<f64>) -> Result<Value, String> {
    let Some(fetch) = fetch else { return Err("fetchMaaCerts: a fetch implementation must be injected".into()) };
    if !issuer_url_ok(issuer) {
        return Err("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)".into());
    }
    let max = max_bytes.unwrap_or(1_048_576.0);
    let url = format!("{issuer}/certs");
    let res = fetch(&url, &FetchInit { redirect_error: true, timeout_ms: timeout_ms.unwrap_or(10_000) })?;
    if !(200..=299).contains(&res.status) {
        return Err(format!("MAA certs fetch failed: HTTP {}", res.status));
    }
    if res.url.as_deref().is_some_and(|u| !u.is_empty() && u != url) {
        return Err("MAA certs fetch: response URL differs from the request (redirect)".into());
    }
    // Number(content-length ?? '0'): an empty header is 0, a non-numeric one NaN (not finite: ignored)
    let declared = match res.content_length.as_deref().map(str::trim) {
        None | Some("") => 0.0,
        Some(h) => h.parse::<f64>().unwrap_or(f64::NAN),
    };
    if declared.is_finite() && declared > max {
        return Err("MAA certs response exceeds the size limit".into());
    }
    if res.body.len() as f64 > max {
        return Err("MAA certs response exceeds the size limit".into());
    }
    let not_json = || "MAA certs response is not valid UTF-8 JSON".to_string();
    let text = std::str::from_utf8(&res.body).map_err(|_| not_json())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let parsed: Value = crate::ap2::parse_no_duplicates(text).map_err(|_| not_json())?; // no duplicate member
    parse_jwks(&parsed)
}

// ---- JWKS evaluation -------------------------------------------------------------------------------------------------------------

fn parse_cert(entry: &Value) -> Result<Cert, String> {
    match entry.as_str() {
        Some(b64) => Cert::from_der(&b64_lenient(b64)),
        None => Err(format!(
            "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received {}",
            received(entry)
        )),
    }
}

/// Node's `Received ...` suffix of a type error for a non-string argument.
fn received(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Number(n) => format!("type number ({n})"),
        Value::Bool(b) => format!("type boolean ({b})"),
        Value::Array(_) => "an instance of Array".into(),
        _ => "an instance of Object".into(),
    }
}

fn spki_of(c: &Cert) -> Result<String, String> {
    Ok(c.public_key()?.spki_sha256_hex())
}

/// The exponent of an RSA key as a number (`None` when it needs more than 64 bits).
fn exponent(e: &[u8]) -> Option<u64> {
    let t: Vec<u8> = e.iter().copied().skip_while(|b| *b == 0).collect();
    (t.len() <= 8).then(|| t.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
}

fn modulus_bits(n: &[u8]) -> usize {
    match n.iter().position(|b| *b != 0) {
        Some(i) => (n.len() - i) * 8 - n[i].leading_zeros() as usize,
        None => 0,
    }
}

/// `rsaKeyOk`: an RSA key is usable only with 512..16384 bits and an odd exponent of at least 3 and below 2^32.
fn rsa_key_ok(k: &PubKey) -> bool {
    match k {
        PubKey::Rsa { n, e } | PubKey::RsaPss { n, e, .. } => {
            let bits = modulus_bits(n);
            (512..=16384).contains(&bits) && exponent(e).is_some_and(|e| e & 1 == 1 && e >= 3 && e < (1u64 << 32))
        }
        _ => true,
    }
}

fn key_strength_error(k: &PubKey) -> Option<String> {
    match k {
        PubKey::Rsa { n, e } => {
            let bits = modulus_bits(n);
            if !(2048..=8192).contains(&bits) {
                return Some(format!("RSA key size {bits} outside 2048..8192"));
            }
            (!rsa_key_ok(&PubKey::Rsa { n: n.clone(), e: e.clone() })).then(|| "RSA public exponent must be odd, at least 3 and at most 32 bits".to_string())
        }
        PubKey::Ec { curve, .. } => match curve {
            EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => None,
            EcCurve::Other => Some("EC curve '' not allowed".into()),
        },
        other => Some(format!("key type '{}' not allowed", other.type_name())),
    }
}

fn safe_verify(c: &Cert, k: &PubKey) -> bool {
    rsa_key_ok(k) && c.verify(k)
}

/// The subject CN when the subject is exactly one CN RDN.
fn sole_cn(subject: &str) -> Option<String> {
    let lines: Vec<&str> = subject.split('\n').filter(|l| !l.is_empty()).collect();
    if lines.len() != 1 {
        return None;
    }
    lines[0].strip_prefix("CN=").map(String::from)
}

fn leaf_cn(subject: &str) -> Option<String> {
    subject.split('\n').find_map(|l| l.strip_prefix("CN=")).map(String::from)
}

fn num_member(v: &Value, k: &str, default: f64) -> f64 {
    v.get(k).filter(|x| !x.is_null()).and_then(Value::as_f64).unwrap_or(default)
}

fn lower_list(v: Option<&Value>) -> BTreeSet<String> {
    v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_lowercase).collect()
}

#[derive(Clone)]
struct Accepted {
    spki: String,
    kind: &'static str,
    not_before: f64,
    not_after: f64,
}

fn validity(c: &Cert) -> (f64, f64) {
    let (f, t) = der_validity_ms(&c.raw);
    (f.map_or(f64::NAN, |x| x as f64), t.map_or(f64::NAN, |x| x as f64))
}

fn evaluate_key(key: &Value, issuer: &str, policy: &Value, now_ms: f64, accepted: &mut Vec<Accepted>) -> Result<(), String> {
    let skew = num_member(policy, "clockSkewMs", 60_000.0);
    let max_age = num_member(policy, "maxKeyAgeMs", 400.0 * DAY);
    let roots = lower_list(policy.get("chainRootSpkiSha256"));
    let inters = lower_list(policy.get("chainIntermediateSpkiSha256"));
    let x5c = key.get("x5c").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or("no x5c")?;
    let certs: Vec<Cert> = x5c.iter().map(parse_cert).collect::<Result<_, _>>()?;
    let leaf = &certs[0];
    for (j, c) in certs.iter().enumerate() {
        let (from, to) = validity(c);
        if !from.is_finite() || !to.is_finite() {
            return Err(format!("cert {j}: unparsable validity"));
        }
        if !(now_ms.is_finite() && skew.is_finite() && now_ms + skew >= from) {
            return Err(format!("cert {j}: not yet valid"));
        }
        if !(now_ms.is_finite() && skew.is_finite() && now_ms - skew <= to) {
            return Err(format!("cert {j}: expired"));
        }
    }
    let (lv_from, lv_to) = validity(leaf);
    let leaf_key = leaf.public_key()?;
    if let Some(e) = key_strength_error(&leaf_key) {
        return Err(e);
    }
    let upsert = |accepted: &mut Vec<Accepted>, a: Accepted| match accepted.iter_mut().find(|x| x.spki == a.spki) {
        Some(slot) => *slot = a,
        None => accepted.push(a),
    };
    if certs.len() == 1 {
        if !(now_ms - lv_from <= max_age) {
            return Err("key older than maxKeyAgeMs".into());
        }
        let subject = leaf.subject_string();
        let cn = sole_cn(&subject).ok_or("subject is not a single CN")?;
        if cn.contains('*') {
            return Err("wildcard CN rejected".into());
        }
        if cn != issuer {
            return Err("subject CN does not equal the issuer URL".into());
        }
        if leaf.issuer_string() != subject || !safe_verify(leaf, &leaf_key) {
            return Err("not a genuine self-signed cert".into());
        }
        let spki = leaf_key.spki_sha256_hex();
        upsert(accepted, Accepted { spki, kind: "self-signed", not_before: lv_from, not_after: lv_to });
        return Ok(());
    }
    // a chained key: only under an explicitly pinned root (and, when configured, a pinned intermediate)
    if roots.is_empty() {
        return Err("chained key ignored (no chainRootSpkiSha256 configured)".into());
    }
    let keys: Vec<PubKey> = certs.iter().map(Cert::public_key).collect::<Result<_, _>>()?;
    for j in 0..certs.len() - 1 {
        if !safe_verify(&certs[j], &keys[j + 1]) {
            return Err(format!("chain link {j} is not signed by the next cert"));
        }
    }
    if let Some(p) = strict_chain_error(&certs.iter().map(|c| c.raw.clone()).collect::<Vec<_>>()) {
        return Err(format!("chain profile: {p}"));
    }
    let top = &certs[certs.len() - 1];
    let top_key = &keys[keys.len() - 1];
    if top.issuer_string() != top.subject_string() || !safe_verify(top, top_key) {
        return Err("chain does not end in a self-signed root".into());
    }
    let root_spki = top_key.spki_sha256_hex();
    if !roots.contains(&root_spki) {
        return Err("chain root is not pinned".into());
    }
    if let Some(allowed) = policy.get("chainLeafCn").filter(|a| a.is_array()) {
        let cn = leaf_cn(&leaf.subject_string()).unwrap_or_else(|| "\u{0}".into());
        if !allowed.as_array().into_iter().flatten().any(|a| a.as_str() == Some(cn.as_str())) {
            return Err("chained leaf CN not allowed".into());
        }
    }
    let (top_from, top_to) = validity(top);
    let (mut anchor_spki, mut kind, mut from, mut to) = (root_spki, "chained-root", top_from, top_to);
    if !inters.is_empty() {
        // the pinned intermediate must sit strictly between leaf and root; it (not the shared root) becomes the anchor
        let mid = (1..certs.len() - 1).find(|i| inters.contains(&keys[*i].spki_sha256_hex()));
        let Some(mid) = mid else { return Err("chain does not pass through a pinned intermediate".into()) };
        let (mf, mt) = validity(&certs[mid]);
        anchor_spki = keys[mid].spki_sha256_hex();
        kind = "chained-intermediate";
        from = mf;
        to = mt;
    }
    let prev = accepted.iter().find(|a| a.spki == anchor_spki).cloned();
    let record = Accepted {
        spki: anchor_spki,
        kind,
        not_before: prev.as_ref().map_or(from, |p| p.not_before.min(from)),
        not_after: to.min(prev.as_ref().map_or(0.0, |p| p.not_after).max(lv_to)),
    };
    upsert(accepted, record);
    Ok(())
}

fn record_json(a: &Accepted) -> Value {
    json!({"spki": a.spki, "kind": a.kind, "notBeforeMs": a.not_before, "notAfterMs": a.not_after})
}

/// Pure validation of every key of a JWKS (`{keys: [{kid?, kty?, alg?, x5c: [base64 DER]}]}`) against `policy` at `now_ms`: `{accepted:
/// [{spki, kind, notBeforeMs, notAfterMs}], rejected: [{kid, reason}]}`. `kind` is `self-signed`, `chained-root` or
/// `chained-intermediate`. Never fails.
pub fn evaluate_maa_jwks(jwks: &Value, issuer: &str, policy: &Value, now_ms: f64) -> Value {
    let mut accepted: Vec<Accepted> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for (i, key) in jwks.get("keys").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let kid = key.get("kid").filter(|k| !k.is_null()).cloned().unwrap_or_else(|| json!(format!("#{i}")));
        if let Err(reason) = evaluate_key(key, issuer, policy, now_ms, &mut accepted) {
            rejected.push(json!({"kid": kid, "reason": reason}));
        }
    }
    json!({"accepted": accepted.iter().map(record_json).collect::<Vec<_>>(), "rejected": rejected})
}

// ---- the trust store -------------------------------------------------------------------------------------------------------------

/// The persisted state of an issuer, validated: `{v: 1, issuer, fetchedAtMs, anchors: [{spki, kind, notBeforeMs, notAfterMs,
/// firstSeenMs}]}` with safe-integer times (never `-0`), lowercase 64-hex SPKIs and a known `kind`.
fn parse_state(x: &Value, issuer: &str) -> Option<Value> {
    let s = x.as_object()?;
    let int = |v: Option<&Value>| v.and_then(safe_integer).filter(|n| !(*n == 0.0 && n.is_sign_negative()));
    if s.get("v") != Some(&json!(1)) || s.get("issuer").and_then(Value::as_str) != Some(issuer) || int(s.get("fetchedAtMs")).is_none() {
        return None;
    }
    let mut anchors = Vec::new();
    for a in s.get("anchors")?.as_array()? {
        let r = a.as_object()?;
        let spki = r.get("spki").and_then(Value::as_str).filter(|p| hex64(p))?;
        let kind = r.get("kind").and_then(Value::as_str).filter(|k| ["self-signed", "chained-root", "chained-intermediate"].contains(k))?;
        let (nb, na, fs) = (int(r.get("notBeforeMs"))?, int(r.get("notAfterMs"))?, int(r.get("firstSeenMs"))?);
        anchors.push(json!({"spki": spki, "kind": kind, "notBeforeMs": nb, "notAfterMs": na, "firstSeenMs": fs}));
    }
    Some(json!({"v": 1, "issuer": issuer, "fetchedAtMs": s["fetchedAtMs"], "anchors": anchors}))
}

/// A key trust bound to a policy, a state store and a transport.
pub struct MaaKeyTrust {
    policy: Value,
    store: Arc<dyn MaaKeyStateStore>,
    fetch: Arc<MaaFetch>,
}

/// Build the trust: `policy` is `{trustedIssuers, ttlMs?, maxStaleMs?, maxNewKeysPerFetch?, maxInitialKeys?, maxKeyAgeMs?, requireOverlap?,
/// allowTrustOnFirstUse?, initialPins?, chainRootSpkiSha256?, chainIntermediateSpkiSha256?, builtinPins?, chainLeafCn?, clockSkewMs?,
/// fetchTimeoutMs?, maxBodyBytes?}`. `Err` without a transport or without a non-empty list of https origin issuers.
pub fn create_maa_key_trust(policy: &Value, store: Arc<dyn MaaKeyStateStore>, fetch: Option<Arc<MaaFetch>>) -> Result<MaaKeyTrust, String> {
    let Some(fetch) = fetch else { return Err("createMaaKeyTrust: fetch must be injected".into()) };
    let issuers = policy.get("trustedIssuers").and_then(Value::as_array);
    if !issuers.is_some_and(|l| !l.is_empty() && l.iter().all(|i| i.as_str().is_some_and(issuer_url_ok))) {
        return Err("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs".into());
    }
    Ok(MaaKeyTrust { policy: policy.clone(), store, fetch })
}

fn fail(code: &str, reason: impl Into<String>) -> Value {
    json!({"ok": false, "code": code, "reason": reason.into()})
}

/// An insertion-ordered set of strings.
#[derive(Default)]
struct OrderedSet(Vec<String>);

impl OrderedSet {
    fn add(&mut self, s: &str) {
        if !self.has(s) {
            self.0.push(s.to_string());
        }
    }
    fn has(&self, s: &str) -> bool {
        self.0.iter().any(|x| x == s)
    }
}

impl MaaKeyTrust {
    /// The trust anchors of `issuer` at `now_ms` (a safe integer), optionally with an operator-signed re-pin `{manifest, verify}`:
    /// `{ok: true, trustAnchors: {rootSpkiSha256}, source: cache | fetched | stale-cache, anchors, newKeys, removedKeys, rejected}` or
    /// `{ok: false, code, reason}` (`untrusted-issuer`, `corrupt-state`, `clock-regression`, `fetch-failed`, `stale-exceeded`,
    /// `no-valid-keys`, `no-baseline`, `too-many-new-keys`, `no-overlap`, `repin-invalid`, `builtin-pins-invalid`).
    pub fn get_trust_anchors(&self, issuer: &str, now_ms: &Value, repin: Option<&Value>) -> Value {
        let policy = &self.policy;
        if !policy["trustedIssuers"].as_array().is_some_and(|l| l.iter().any(|i| i.as_str() == Some(issuer))) {
            return fail("untrusted-issuer", "issuer is not in policy.trustedIssuers");
        }
        let Some(now) = safe_integer(now_ms) else { return fail("clock-regression", "nowMs must be an integer") };
        let ttl = num_member(policy, "ttlMs", HOUR);
        let max_stale = num_member(policy, "maxStaleMs", DAY);
        let max_new = num_member(policy, "maxNewKeysPerFetch", 2.0);
        let max_initial = num_member(policy, "maxInitialKeys", 8.0);
        let skew = num_member(policy, "clockSkewMs", 60_000.0);
        let require_overlap = policy.get("requireOverlap").filter(|x| !x.is_null()) != Some(&json!(false));
        let live = |a: &[Value]| -> Vec<Value> {
            a.iter()
                .filter(|r| now.is_finite() && skew.is_finite() && now - skew <= r["notAfterMs"].as_f64().unwrap_or(f64::NAN) && now + skew >= r["notBeforeMs"].as_f64().unwrap_or(f64::NAN))
                .cloned()
                .collect()
        };
        let build = |source: &str, anchors: Vec<Value>, new_keys: Vec<String>, removed: Vec<String>, rejected: Vec<Value>| -> Value {
            let spkis: BTreeSet<&str> = anchors.iter().filter_map(|a| a["spki"].as_str()).collect();
            if spkis.is_empty() {
                return fail("no-valid-keys", "no unexpired, un-revoked signing keys remain");
            }
            let list: Vec<&str> = spkis.into_iter().collect();
            json!({"ok": true, "trustAnchors": {"rootSpkiSha256": list}, "source": source, "anchors": anchors, "newKeys": new_keys, "removedKeys": removed, "rejected": rejected})
        };

        // operator approvals / revocations (re-pin manifest)
        let mut approved = OrderedSet::default();
        let mut denied = OrderedSet::default();
        if let Some(r) = repin {
            let verify = r.get("verify").cloned().unwrap_or(Value::Null);
            let mut opts = VerifyOptions::from_json(&verify);
            opts.now_ms = super::allowlist::JsNum::Num(now);
            let v = verify_allowlist_manifest(r.get("manifest").unwrap_or(&Value::Null), verify.get("issuerKeys").unwrap_or(&Value::Null), &opts);
            if v["ok"] != json!(true) {
                return fail("repin-invalid", format!("{}: {}", v["code"].as_str().unwrap_or(""), v["reason"].as_str().unwrap_or("")));
            }
            let p = project_allowlist(&v, now);
            for s in p["maaSigningSpkis"].get(issuer).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                approved.add(s);
            }
            for r in p["revoked"].as_array().into_iter().flatten() {
                if r["kind"] == json!("maa-signing-spki") && r["label"].as_str() == Some(issuer) {
                    denied.add(r["value"].as_str().unwrap_or(""));
                }
            }
        }
        // built-in release-signed pins (default on): the offline root of the first accepted set
        let mut eff_policy = policy.clone();
        let mut builtin_baseline: Vec<String> = Vec::new();
        let mut builtin_reason: Option<String> = None;
        if policy.get("builtinPins") != Some(&json!(false)) {
            let source = policy.get("builtinPins").filter(|b| b.is_object());
            let b = load_builtin_maa_pins(&json!(now), source);
            if b["ok"] == json!(true) {
                builtin_baseline = b["maaSigningSpkis"].get(issuer).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
                for r in b["revokedSigningSpkis"].get(issuer).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                    denied.add(r);
                }
                let pick = |k: &str, fallback: &Value| policy.get(k).filter(|x| !x.is_null()).cloned().unwrap_or_else(|| fallback.clone());
                eff_policy["chainRootSpkiSha256"] = pick("chainRootSpkiSha256", &b["maaChainRootSpkis"]);
                eff_policy["chainIntermediateSpkiSha256"] = pick("chainIntermediateSpkiSha256", &b["maaChainIntermediateSpkis"]);
                eff_policy["chainLeafCn"] = pick("chainLeafCn", &json!(BUILTIN_CHAIN_LEAF_CN));
                // the pinned Microsoft intermediate only counts for issuers the release actually pinned (no leak to others)
                if !builtin_baseline.is_empty() {
                    builtin_baseline.extend(b["maaChainIntermediateSpkis"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
                }
            } else {
                builtin_reason = Some(b["reason"].as_str().unwrap_or("").to_string());
            }
        }
        let allow = |a: Vec<Value>| -> Vec<Value> { a.into_iter().filter(|r| !denied.has(r["spki"].as_str().unwrap_or(""))).collect() };

        let raw_state = self.store.get(issuer);
        let mut state: Option<Value> = None;
        if let Some(raw) = raw_state {
            let Some(parsed) = parse_state(&raw, issuer) else { return fail("corrupt-state", "persisted MAA key state failed validation") };
            if !(now.is_finite() && skew.is_finite() && now >= parsed["fetchedAtMs"].as_f64().unwrap_or(f64::NAN) - skew) {
                return fail("clock-regression", "clock is behind the last persisted fetch time");
            }
            state = Some(parsed);
        }
        let state_anchors: Vec<Value> = state.as_ref().and_then(|s| s["anchors"].as_array().cloned()).unwrap_or_default();
        let state_fetched = state.as_ref().map_or(f64::NAN, |s| s["fetchedAtMs"].as_f64().unwrap_or(f64::NAN));

        // 1. a fresh cache
        if state.is_some() && now.is_finite() && now - state_fetched < ttl && now >= state_fetched {
            let a = allow(live(&state_anchors));
            if !a.is_empty() {
                return build("cache", a, vec![], vec![], vec![]);
            }
        }

        // 2. refresh
        let timeout = policy.get("fetchTimeoutMs").and_then(Value::as_f64).map(|t| t as u64);
        let jwks = match fetch_maa_certs(issuer, Some(&*self.fetch), timeout, policy.get("maxBodyBytes").and_then(Value::as_f64)) {
            Ok(j) => j,
            Err(why) => {
                if state.is_none() {
                    return fail("fetch-failed", format!("{why}; no cached key set"));
                }
                if !(now - state_fetched <= max_stale) {
                    return fail("stale-exceeded", format!("{why}; cached set is older than maxStaleMs"));
                }
                let a = allow(live(&state_anchors));
                if a.is_empty() {
                    return fail("stale-exceeded", format!("{why}; every cached key has expired or been revoked"));
                }
                return build("stale-cache", a, vec![], vec![], vec![]);
            }
        };
        let ev = evaluate_maa_jwks(&jwks, issuer, &eff_policy, now);
        let accepted: Vec<Value> = ev["accepted"].as_array().into_iter().flatten().filter(|r| !denied.has(r["spki"].as_str().unwrap_or(""))).cloned().collect();
        if accepted.is_empty() {
            let why: Vec<String> = ev["rejected"].as_array().into_iter().flatten().map(|r| format!("{}: {}", crate::intent_strict::js_opt_string(r.get("kid")), r["reason"].as_str().unwrap_or(""))).collect();
            return fail("no-valid-keys", format!("no JWKS key passed validation ({})", if why.is_empty() { "empty JWKS".to_string() } else { why.join("; ") }));
        }

        // 3. the rotation policy
        let prev_anchors = if state.is_some() { live(&state_anchors) } else { Vec::new() };
        let mut baseline = OrderedSet::default();
        for a in &prev_anchors {
            baseline.add(a["spki"].as_str().unwrap_or(""));
        }
        if state.is_none() {
            for p in policy.get("initialPins").and_then(|m| m.get(issuer)).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                baseline.add(&p.to_lowercase());
            }
            for p in &builtin_baseline {
                baseline.add(p);
            }
        }
        for p in &builtin_baseline {
            approved.add(p);
        }
        let mut accepted_set = OrderedSet::default();
        for a in &accepted {
            accepted_set.add(a["spki"].as_str().unwrap_or(""));
        }
        let approved_here: Vec<&String> = accepted_set.0.iter().filter(|s| approved.has(s)).collect();
        let unapproved_new = accepted_set.0.iter().filter(|s| !baseline.has(s) && !approved.has(s)).count();
        if baseline.0.is_empty() {
            if approved_here.is_empty() && policy.get("allowTrustOnFirstUse") != Some(&json!(true)) {
                if let Some(r) = builtin_reason {
                    return fail("builtin-pins-invalid", format!("built-in pins unusable ({r}); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use"));
                }
                return fail("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use");
            }
            if accepted_set.0.len() as f64 > max_initial && approved_here.len() < accepted_set.0.len() {
                return fail("too-many-new-keys", format!("initial set of {} keys exceeds maxInitialKeys", accepted_set.0.len()));
            }
        } else {
            if unapproved_new as f64 > max_new {
                return fail("too-many-new-keys", format!("{unapproved_new} new keys exceed maxNewKeysPerFetch={max_new}"));
            }
            let overlap = accepted_set.0.iter().any(|s| baseline.has(s)) || !approved_here.is_empty();
            if require_overlap && !overlap {
                return fail("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin");
            }
        }

        // 4. persist (monotone fetchedAtMs) and return
        let first_seen = |spki: &str| state_anchors.iter().find(|a| a["spki"].as_str() == Some(spki)).and_then(|a| a["firstSeenMs"].as_f64());
        let records: Vec<Value> = accepted
            .iter()
            .map(|a| {
                let mut r = a.clone();
                r["firstSeenMs"] = json!(first_seen(a["spki"].as_str().unwrap_or("")).unwrap_or(now));
                r
            })
            .collect();
        let fetched_at = if state.is_some() { state_fetched.max(now) } else { now };
        self.store.set(issuer, &json!({"v": 1, "issuer": issuer, "fetchedAtMs": fetched_at, "anchors": records}));
        let new_keys: Vec<String> = records.iter().filter(|r| !baseline.has(r["spki"].as_str().unwrap_or(""))).filter_map(|r| r["spki"].as_str().map(String::from)).collect();
        let removed: Vec<String> = baseline.0.iter().filter(|s| !accepted_set.has(s)).cloned().collect();
        build("fetched", records, new_keys, removed, ev["rejected"].as_array().cloned().unwrap_or_default())
    }
}

// ---- multi-vantage corroboration -------------------------------------------------------------------------------------------------

fn bad(code: &str, reason: impl Into<String>) -> Value {
    json!({"ok": false, "code": code, "reason": reason.into()})
}

/// Accept a FIRST-USE key set only if at least `k` (an integer of at least 2) DISTINCT vantage points observed the same issuer and ALL
/// supplied observations (`{vantage, issuer, jwks}`) validate to the IDENTICAL SPKI set; any disagreement, even from a vantage beyond the
/// k, fails closed. `opts` is `{issuer, nowMs, policy?}`. The result `{ok, issuer, spkis, vantages, k}` is directly usable as
/// `initialPins[issuer]`. It defeats an attacker who controls ONE network path to the issuer, not one who controls k of them;
/// independence is the caller's claim, not proven here.
pub fn corroborate_maa_key_sets(sets: &Value, k: &Value, opts: &Value) -> Value {
    let Some(kk) = safe_integer(k).filter(|k| *k >= 2.0) else { return bad("malformed", "k must be an integer >= 2") };
    let issuer = opts.get("issuer").and_then(Value::as_str).filter(|i| issuer_url_ok(i));
    let now = opts.get("nowMs").and_then(safe_integer);
    let (Some(issuer), Some(now)) = (issuer, now) else { return bad("malformed", "issuer/nowMs invalid") };
    let Some(observations) = sets.as_array() else { return bad("malformed", "sets must be an array") };
    let mut policy = json!({"trustedIssuers": [issuer]});
    for (m, v) in opts.get("policy").and_then(Value::as_object).into_iter().flatten() {
        policy[m.as_str()] = v.clone();
    }
    let mut by_vantage: Vec<(String, String)> = Vec::new();
    for o in observations {
        let Some(vantage) = o.get("vantage").and_then(Value::as_str).filter(|v| !v.is_empty() && v.encode_utf16().count() <= 100) else {
            // a null observation: the reference reads `o?.vantage`
            return bad("malformed", "vantage label must be a non-empty string");
        };
        if o.get("issuer").and_then(Value::as_str) != Some(issuer) {
            return bad("malformed", format!("observation from '{vantage}' is for a different issuer"));
        }
        let ev = evaluate_maa_jwks(o.get("jwks").unwrap_or(&Value::Null), issuer, &policy, now);
        let accepted = ev["accepted"].as_array().cloned().unwrap_or_default();
        if accepted.is_empty() {
            let why: Vec<&str> = ev["rejected"].as_array().into_iter().flatten().filter_map(|r| r["reason"].as_str()).collect();
            return bad("no-valid-keys", format!("vantage '{vantage}' observed no valid key ({})", if why.is_empty() { "empty".to_string() } else { why.join("; ") }));
        }
        let mut spkis: Vec<&str> = accepted.iter().filter_map(|a| a["spki"].as_str()).collect();
        spkis.sort_unstable();
        let fp = spkis.join(",");
        match by_vantage.iter().find(|(v, _)| v == vantage) {
            Some((_, prior)) if *prior != fp => return bad("vantage-disagreement", format!("vantage '{vantage}' supplied two different key sets")),
            Some(_) => {}
            None => by_vantage.push((vantage.to_string(), fp)),
        }
    }
    if (by_vantage.len() as f64) < kk {
        return bad("insufficient-vantages", format!("{} distinct vantage(s) < k={kk}", by_vantage.len()));
    }
    let distinct: BTreeSet<&str> = by_vantage.iter().map(|(_, f)| f.as_str()).collect();
    if distinct.len() != 1 {
        let parts: Vec<String> = by_vantage.iter().map(|(v, f)| format!("{v}={}", f.split(',').map(|x| &x[..x.len().min(8)]).collect::<Vec<_>>().join("+"))).collect();
        return bad("vantage-disagreement", format!("vantages disagree: {}", parts.join(" | ")));
    }
    let spkis: Vec<&str> = distinct.into_iter().next().unwrap_or("").split(',').collect();
    let mut vantages: Vec<&str> = by_vantage.iter().map(|(v, _)| v.as_str()).collect();
    vantages.sort_unstable();
    json!({"ok": true, "issuer": issuer, "spkis": spkis, "vantages": vantages, "k": kk})
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::*;

    fn fetch_of(body: &'static str) -> Box<MaaFetch> {
        Box::new(move |_, _| Ok(MaaHttpResponse { status: 200, body: body.as_bytes().to_vec(), ..Default::default() }))
    }

    #[test]
    fn a_duplicate_member_is_refused_and_other_number_spellings_parse() {
        let fetch = |body| fetch_maa_certs("https://maa.example.net", Some(&*fetch_of(body)), None, None);
        assert_eq!(fetch(r#"{"keys":[],"keys":[]}"#), Err("MAA certs response is not valid UTF-8 JSON".to_string()));
        // past the parse: the reader reaches its own checks (no keys array here), so 8.0 and 1e3 are not a JSON refusal
        assert_eq!(fetch(r#"{"n":8.0,"e":1e3}"#), Err("MAA certs: response has no keys array".to_string()));
    }
}
