//! The software attestation layer (port of `attestation.ts`): the report-data binding hash, the dev attestor and its signed documents, the
//! document registry, the bounded single-use nonce store and the nonce entropy gate, the agent-binding match, the total attestation
//! verifier and its hook, the multi-root N-of-M verifier, and anchoring of verified evidence in the transparency ledger.
//!
//! SOFTWARE mode is a real, checkable attestation for development and CI, but its measurements are SELF-ASSERTED by the signer: it proves
//! that a key the verifier trusts vouched for them, not that silicon runs them. HARDWARE mode delegates authenticity to a vendor verifier
//! (a [`HardwareVerifierFn`], e.g. the ones in [`crate::attest`]) whose measured identity then feeds the same freshness, binding and
//! `agent_binding` checks.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`; the verifiers are total. A post-quantum or
//! hybrid document verifies only under the PQ key PINNED for its attestor (`pqPins`); the reference's legacy unbound opt-out
//! (`allowUnboundPq`) is deliberately not offered. A number that is not finite is the `{"$num": "NaN" | "Infinity" | "-Infinity"}` marker
//! of the reference's JSON where a clock, a skew or a size is READ; the canonical (signed or hashed) forms never contain one.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::attest::util::{is_hex, sha512};
use crate::intent_suite::{suite_of, verify_pinned_suite};
use crate::intent_v2::{js_number_string, js_value_string};
use crate::ledger_store::TransparencyLedger;

/// Domain separator of the report-data binding hash.
pub const ATTEST_BIND_DOMAIN: &str = "atlas-pca/attest-bind/v1\0";
/// Domain separator of the anchored attestation-evidence digest.
pub const ATTEST_ANCHOR_DOMAIN: &str = "atlas-pca/attest-anchor/v1\0";
/// Hard ceiling (ms) on the age of a server-issued attestation nonce at verification time.
pub const MAX_ATTESTATION_AGE_MS: f64 = 300_000.0;
/// Default retention (ms) of a consumed nonce in the in-memory store: 12x the quote-age ceiling.
pub const DEFAULT_NONCE_RETENTION_MS: f64 = 3_600_000.0;
/// Default bound of the in-memory nonce store.
pub const DEFAULT_MAX_NONCES: f64 = 100_000.0;
/// Minimum entropy (bytes) of a server-issued attestation nonce: 128 bits.
pub const MIN_ATTESTATION_NONCE_BYTES: f64 = 16.0;
const DOC_DOMAIN: &str = "atlas-pca/attest/v1\0";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A vendor or composite hardware verifier: `{document, ctx, nowMs, expected}` in, the `HardwareAttestationResult`
/// (`{ok, reason?, measured?, bound?, hostAsserted?}`) out; an `Err` is a throw (a refusal).
pub type HardwareVerifierFn = dyn Fn(&Value) -> Result<Value, String> + Send + Sync;

// ---- JavaScript value semantics ---------------------------------------------------------------------------------------------------

/// `o?.k`: an absent or non-object receiver has no member.
fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object()?.get(k)
}

fn get_opt<'a>(o: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    get(o?, k)
}

/// `{"$num": ...}` read as that double.
fn marker(v: &Value) -> Option<f64> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    match m.get("$num").and_then(Value::as_str)? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

/// A value of JavaScript type `number`: a JSON number or the non-finite marker.
fn number_of(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if v.is_number() {
        v.as_f64()
    } else {
        marker(v)
    }
}

/// `Number.isFinite(v)` (no coercion): the number when `v` is a finite number.
fn finite(v: Option<&Value>) -> Option<f64> {
    number_of(v).filter(|f| f.is_finite())
}

/// `Number.isSafeInteger(v)` (no coercion).
fn safe_int(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if !v.is_number() {
        return None;
    }
    v.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

fn is_true(v: Option<&Value>) -> bool {
    v == Some(&Value::Bool(true))
}

/// ECMAScript `ToNumber` of a JSON value (what `Math.max(x, 16)` reads).
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().ok().filter(|_| !t.contains(['_', 'n', 'N', 'i'])).unwrap_or(f64::NAN)
            }
        }
        other => number_of(other).unwrap_or(f64::NAN),
    }
}

/// `a === b` for two values of separately parsed documents: numbers by value, objects and arrays only to themselves (never equal here),
/// an absent member is `undefined` (`===` only itself).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Null), Some(Value::Null)) => true,
        _ => false,
    }
}

/// SameValueZero (`Array.prototype.includes`): `strict_eq` where NaN equals NaN and an absent member equals nothing in a JSON list.
fn same_value_zero(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => false,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (x, y) => strict_eq(x, y),
    }
}

fn includes(list: &[Value], x: Option<&Value>) -> bool {
    list.iter().any(|e| same_value_zero(Some(e), x))
}

/// `Array.isArray(x) && x.length > 0`: the list, or empty.
fn non_empty_list(x: Option<&Value>) -> &[Value] {
    x.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn undefined_or(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

fn hash_strict(v: &Value) -> Result<String, String> {
    let c = crate::canonicalize_strict(v)?;
    Ok(crate::b64_encode(&crate::sha(c.as_bytes())))
}

/// A canonical number member (an integer prints without a fraction).
fn jnum(f: f64) -> Result<Value, String> {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE {
        Ok(json!(f as i64))
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).ok_or_else(|| "canonicalize: non-finite number".to_string())
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

// ---- the binding ------------------------------------------------------------------------------------------------------------------

fn lp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The report_data a quote is bound to: `SHA-512(ATTEST_BIND_DOMAIN || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce))`,
/// `lp(x) = u32be(len) || utf8(x)`: 64 bytes, exactly the SEV-SNP report_data width. A quote captured for one holder, grant, epoch or nonce
/// cannot be relayed for another. `expected` is `{holderPub, grantRef, epoch, nonce}`; `Err` on a malformed one.
pub fn attestation_binding(expected: &Value) -> Result<Vec<u8>, String> {
    let nonempty = |k: &str| get(expected, k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let Some(holder) = nonempty("holderPub").filter(|_| truthy(Some(expected))) else { return Err("binding: holderPub required".into()) };
    let Some(grant) = nonempty("grantRef") else { return Err("binding: grantRef required".into()) };
    let Some(nonce) = nonempty("nonce") else { return Err("binding: nonce required".into()) };
    let Some(epoch) = safe_int(get(expected, "epoch")).filter(|e| *e >= 0.0) else {
        return Err("binding: epoch must be a non-negative safe integer".into());
    };
    let mut buf = ATTEST_BIND_DOMAIN.as_bytes().to_vec();
    lp(&mut buf, holder);
    lp(&mut buf, grant);
    buf.extend_from_slice(&(epoch as u64).to_be_bytes());
    lp(&mut buf, nonce);
    Ok(sha512(&buf))
}

/// The base64url form of [`attestation_binding`] (what software-mode documents carry in `binding`).
pub fn attestation_binding_b64u(expected: &Value) -> Result<String, String> {
    Ok(crate::b64_encode(&attestation_binding(expected)?))
}

/// The signed message of a document body: the domain, then the strict canonical bytes (both signature members excluded, `alg` and `pq_pk`
/// signed).
fn document_message(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = DOC_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

/// base64url(sha256(strict canonical(document))): a content address for the full signed quote.
pub fn attestation_digest(doc: &Value) -> Result<String, String> {
    hash_strict(doc)
}

// ---- the dev attestor -------------------------------------------------------------------------------------------------------------

/// A SOFTWARE-mode attestor for development and CI: signs documents with its key (and, for a post-quantum suite, its PQ key). The verifier
/// trusts it by listing its `public_key` in `trustedAttestorKeys`.
pub struct DevAttestor<'a> {
    /// The base64url Ed25519 public key clients register in `trustedAttestorKeys`.
    pub public_key: String,
    key: KeyPair,
    suite: Suite<'a>,
}

/// Build a dev attestor over `key` (Ed25519 identity) and `suite` (default ed25519; a PQ or hybrid suite needs its key pair, which a
/// missing one reports when a document is minted). `Err` for an unknown signature suite.
pub fn create_dev_attestor<'a>(key: KeyPair, suite: Suite<'a>) -> Result<DevAttestor<'a>, String> {
    if let Some(alg) = suite.alg {
        if suite_of(Some(&json!(alg))).is_err() {
            return Err(format!("createDevAttestor: unknown signature alg '{alg}'"));
        }
    }
    Ok(DevAttestor { public_key: key.public.clone(), key, suite })
}

impl DevAttestor<'_> {
    /// Sign a SOFTWARE-mode document over `claims` (`model_id`, `weights_digest`, `runtime_measurement`, `operator`, `nonce`, `issued_at`,
    /// `expires_at`, optional `system_prompt_digest` / `tool_manifest_digest`, and `holder_pub` + `grant_ref` + `epoch` together to bind
    /// the document to them and its nonce). A claim the reference leaves `undefined` is an `Err` (it has no canonical form).
    pub fn attest(&self, claims: &Value) -> Result<Value, String> {
        let undefined = || "canonicalize: unsupported type undefined".to_string();
        let mut body = Map::new();
        for k in ["model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at"] {
            body.insert(k.into(), get(claims, k).ok_or_else(undefined)?.clone());
        }
        body.insert("attestor".into(), json!(self.public_key));
        body.insert("mode".into(), json!("software"));
        // additive: the digests are carried only when supplied, so a document minted without them signs byte-identically to before
        for k in ["system_prompt_digest", "tool_manifest_digest"] {
            if let Some(v) = get(claims, k) {
                body.insert(k.into(), v.clone());
            }
        }
        if let (Some(h), Some(g), Some(e)) = (get(claims, "holder_pub"), get(claims, "grant_ref"), get(claims, "epoch")) {
            let exp = json!({"holderPub": h, "grantRef": g, "epoch": e, "nonce": claims["nonce"]});
            body.insert("binding".into(), json!(attestation_binding_b64u(&exp)?));
        }
        sign_artifact(DOC_DOMAIN, &Value::Object(body), &self.key, &Suite { alg: self.suite.alg, pq: self.suite.pq })
    }
}

// ---- registry, nonce store, entropy ----------------------------------------------------------------------------------------------

/// A resolver of the attestation document of an action (the verifier context in, the document or `None` out).
pub type AttestationResolver = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

/// A resolver over known documents: the one whose `nonce` equals the PCActn's `attestation.quote_digest` (a later duplicate for a nonce
/// overwrites an earlier one; entries that are not documents with a string nonce are ignored).
pub fn attestation_registry(docs: &Value) -> AttestationResolver {
    let mut by_nonce: HashMap<String, Value> = HashMap::new();
    for d in docs.as_array().map_or(&[][..], Vec::as_slice) {
        if let (true, Some(n)) = (truthy(Some(d)), get(d, "nonce").and_then(Value::as_str)) {
            by_nonce.insert(n.to_string(), d.clone());
        }
    }
    Arc::new(move |ctx: &Value| {
        let key = get_opt(get_opt(get(ctx, "pcactn"), "attestation"), "quote_digest").and_then(Value::as_str)?;
        by_nonce.get(key).cloned()
    })
}

/// Single-use store for server-issued attestation nonces. `consume` MUST be atomic: `true` for the first call with a nonce, `false` for
/// every later one (a replay). Back it with a database in production; [`MemoryNonceStore`] is the single-process reference.
pub trait AttestationNonceStore: Send + Sync {
    fn consume(&self, nonce: &str) -> bool;
}

struct NonceState {
    /// nonce -> (sequence, time consumed); the sequence orders entries by insertion
    seen: HashMap<String, (u64, f64)>,
    order: BTreeMap<u64, String>,
    next: u64,
}

/// The in-memory, single-process nonce store. A consumed nonce is NEVER re-accepted inside the retention window; the store is bounded by
/// `max` entries and, when full of still-retained nonces, REFUSES new ones (fail closed) rather than evict a live one. Only integer epoch
/// milliseconds are accepted from the clock; anything else refuses the nonce.
pub struct MemoryNonceStore {
    max: f64,
    retention: f64,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
    state: Mutex<NonceState>,
}

impl MemoryNonceStore {
    /// `max` must be a positive safe integer and `retention_ms` (default one hour) a positive safe integer (a store that remembers nothing
    /// gives no replay protection); `now` is the clock (default the system clock).
    pub fn new(max: f64, retention_ms: Option<f64>, now: Option<Box<dyn Fn() -> f64 + Send + Sync>>) -> Result<Self, String> {
        let safe = |f: f64| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE;
        if !safe(max) || max < 1.0 {
            return Err("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)".into());
        }
        let retention = retention_ms.unwrap_or(DEFAULT_NONCE_RETENTION_MS);
        if !safe(retention) || retention <= 0.0 {
            return Err("memoryNonceStore: retentionMs must be a positive integer (ms)".into());
        }
        Ok(Self {
            max,
            retention,
            clock: now.unwrap_or_else(|| Box::new(now_ms)),
            state: Mutex::new(NonceState { seen: HashMap::new(), order: BTreeMap::new(), next: 0 }),
        })
    }
}

impl AttestationNonceStore for MemoryNonceStore {
    fn consume(&self, nonce: &str) -> bool {
        let t = (self.clock)();
        if !(t.is_finite() && t.fract() == 0.0 && t.abs() <= MAX_SAFE) {
            return false; // integer epoch ms only, as a clock; anything else fails closed
        }
        let Ok(mut st) = self.state.lock() else { return false };
        if let Some(&(seq, at)) = st.seen.get(nonce) {
            if t - at < self.retention {
                return false; // retained: a replay
            }
            st.seen.remove(nonce); // aged out of retention: treated as new
            st.order.remove(&seq);
        }
        if st.seen.len() as f64 >= self.max {
            // make room ONLY from entries that aged out of retention; never evict a live one
            let mut aged: Vec<(u64, String)> = Vec::new();
            for (seq, key) in &st.order {
                let at = st.seen[key].1;
                if t - at < self.retention {
                    break;
                }
                aged.push((*seq, key.clone()));
            }
            for (seq, key) in aged {
                st.seen.remove(&key);
                st.order.remove(&seq);
            }
            if st.seen.len() as f64 >= self.max {
                return false; // full of live nonces: fail closed
            }
        }
        let seq = st.next;
        st.next += 1;
        st.seen.insert(nonce.to_string(), (seq, t));
        st.order.insert(seq, nonce.to_string());
        true
    }
}

/// Whether `nonce` plausibly carries at least `min_bytes` (floor 16) bytes of entropy: hex (>= 2 x min digits) or base64url (>= ceil
/// ratio characters), with at least 8 distinct characters (rejects `aaaa...`, counters, words). A syntactic floor only: the server must
/// still generate nonces from a CSPRNG. `min_bytes` absent is 16.
pub fn nonce_entropy_ok(nonce: &Value, min_bytes: Option<&Value>) -> bool {
    let Some(n) = nonce.as_str() else { return false };
    let wanted = min_bytes.map_or(MIN_ATTESTATION_NONCE_BYTES, |v| to_number(Some(v)));
    let need = if wanted.is_nan() { f64::NAN } else { wanted.max(MIN_ATTESTATION_NONCE_BYTES) };
    let hex = is_hex(n);
    let b64 = !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    if !hex && !b64 {
        return false;
    }
    let len = units(n) as f64;
    let bytes = if hex { len / 2.0 } else { (len * 3.0 / 4.0).floor() };
    if bytes < need {
        return false;
    }
    n.encode_utf16().collect::<HashSet<u16>>().len() >= 8
}

/// `true` iff the grant's `agent_binding` constrains anything (an attestation is then REQUIRED). An absent or `null` binding constrains
/// nothing; a present `min_measurement` other than `""` constrains (a malformed one fails closed in the match).
pub fn requires_attestation(binding: &Value) -> bool {
    let ne = |k: &str| get(binding, k).and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    get(binding, "min_measurement").is_some_and(|m| m.as_str() != Some(""))
        || ne("model_allowlist")
        || get(binding, "operator").and_then(Value::as_str).is_some_and(|o| !o.is_empty())
        || ne("weights_allowlist")
        || ne("system_prompt_allowlist")
        || ne("tool_manifest_allowlist")
        || is_true(get(binding, "require_hardware"))
        || is_true(get(binding, "require_measured_weights"))
}

/// `true` iff `doc.nonce` is the nonce the PCActn declares in `attestation.quote_digest`.
pub fn nonce_binds(doc: &Value, ctx: &Value) -> bool {
    get(doc, "nonce").is_some_and(Value::is_string)
        && strict_eq(get(doc, "nonce"), get_opt(get_opt(get(ctx, "pcactn"), "attestation"), "quote_digest"))
}

// ---- agent-binding match ----------------------------------------------------------------------------------------------------------

/// The measured SVN of a runtime measurement: the canonical decimal text of a safe integer, else `None`.
fn measured_svn(runtime: Option<&Value>) -> Option<f64> {
    let s = runtime?.as_str()?;
    let canonical = s == "0" || (s.as_bytes().first().is_some_and(|c| (b'1'..=b'9').contains(c)) && s.bytes().all(|c| c.is_ascii_digit()));
    if !canonical {
        return None;
    }
    s.parse::<f64>().ok().filter(|n| *n <= MAX_SAFE)
}

/// `{svn: n}` exactly (one own member), `n` a safe non-negative integer JSON number that is not `-0`.
fn svn_bound(mm: &Value) -> Option<f64> {
    let m = mm.as_object().filter(|m| m.len() == 1)?;
    let n = safe_int(m.get("svn"))?;
    (n >= 0.0 && !(n == 0.0 && n.is_sign_negative())).then_some(n)
}

/// Match a measured identity against the grant's `agent_binding`: the reason for the first failing constraint (model allowlist, the
/// minimum measurement, the pinned operator, hardware-measured weights, the weights, system prompt and tool manifest allowlists), else
/// `None`. A malformed `min_measurement` fails closed. `Err` for an identity that is `null` (the reference throws reading it).
pub fn match_agent_binding(id: &Value, binding: &Value) -> Result<Option<String>, String> {
    if id.is_null() {
        return Err("Cannot read properties of null (reading 'model_id')".into());
    }
    let (model, weights, runtime) = (get(id, "model_id"), get(id, "weights_digest"), get(id, "runtime_measurement"));
    let ml = non_empty_list(get(binding, "model_allowlist"));
    if !ml.is_empty() && !includes(ml, model) {
        return Ok(Some(format!("model_id {} not in model_allowlist", undefined_or(model))));
    }
    match get(binding, "min_measurement") {
        None => {}
        Some(Value::String(s)) if s.is_empty() => {}
        Some(Value::String(s)) => {
            if runtime.and_then(Value::as_str) != Some(s.as_str()) {
                return Ok(Some("runtime_measurement does not match required min_measurement".into()));
            }
        }
        Some(mm) => {
            let Some(svn) = svn_bound(mm) else {
                return Ok(Some(
                    "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)".into(),
                ));
            };
            let shown = js_number_string(svn);
            let Some(got) = measured_svn(runtime) else {
                return Ok(Some(format!("runtime_measurement {} is not an integer SVN (required min svn {shown})", undefined_or(runtime))));
            };
            if got < svn {
                return Ok(Some(format!("runtime_measurement svn {} is below required min svn {shown}", js_number_string(got))));
            }
        }
    }
    if let Some(op) = get(binding, "operator").and_then(Value::as_str).filter(|o| !o.is_empty()) {
        if get(id, "operator").and_then(Value::as_str) != Some(op) {
            return Ok(Some(format!("operator {} is not the bound operator", undefined_or(get(id, "operator")))));
        }
    }
    if is_true(get(binding, "require_measured_weights")) && !is_true(get(id, "weights_measured")) {
        return Ok(Some(
            "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)".into(),
        ));
    }
    let wl = non_empty_list(get(binding, "weights_allowlist"));
    if !wl.is_empty() && !includes(wl, weights) {
        return Ok(Some("weights_digest not in weights_allowlist (model swap / fine-tune?)".into()));
    }
    let sp = get(id, "system_prompt_digest");
    let sl = non_empty_list(get(binding, "system_prompt_allowlist"));
    if !sl.is_empty() && !(sp.is_some_and(Value::is_string) && includes(sl, sp)) {
        return Ok(Some("system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)".into()));
    }
    let tm = get(id, "tool_manifest_digest");
    let tl = non_empty_list(get(binding, "tool_manifest_allowlist"));
    if !tl.is_empty() && !(tm.is_some_and(Value::is_string) && includes(tl, tm)) {
        return Ok(Some("tool_manifest_digest not in tool_manifest_allowlist (tools changed?)".into()));
    }
    Ok(None)
}

// ---- verification -----------------------------------------------------------------------------------------------------------------

fn nonce_age_reason(issued: Option<&Value>, now: f64, skew: f64, max_age: f64) -> Option<String> {
    let Some(i) = finite(issued) else { return Some("server nonce issue time unknown (cannot establish freshness)".into()) };
    if !(now.is_finite() && skew.is_finite() && now + skew >= i) {
        return Some("nonce issued in the future".into());
    }
    if !(now - i <= max_age + skew && (now - i).is_finite() && (max_age + skew).is_finite()) {
        return Some("attestation nonce expired (stale quote)".into());
    }
    None
}

#[derive(PartialEq)]
enum Window {
    Malformed,
    NotYet,
    Expired,
    Valid,
}

fn window_decision(now: f64, skew: f64, iat: Option<&Value>, exp: Option<&Value>) -> Window {
    let (Some(i), Some(e)) = (finite(iat), finite(exp)) else { return Window::Malformed };
    if e < i {
        return Window::Malformed;
    }
    if !(now.is_finite() && skew.is_finite() && now + skew >= i) {
        return Window::NotYet;
    }
    if !(now - skew <= e) {
        return Window::Expired;
    }
    Window::Valid
}

/// The `agent_binding` of the grant carried in the context (`ctx.grant`), or `None` when it has no readable envelope.
fn agent_binding_of(ctx: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(ctx) = ctx.filter(|c| !c.is_null()) else { return Err("Cannot read properties of undefined (reading 'grant')".into()) };
    Ok(crate::authorize::read_envelope(get(ctx, "grant").unwrap_or(&Value::Null)).and_then(|e| e.get("agent_binding").cloned()))
}

fn software_identity(d: &Value) -> Value {
    let mut o = Map::new();
    for k in ["model_id", "weights_digest", "runtime_measurement", "operator"] {
        if let Some(v) = get(d, k) {
            o.insert(k.into(), v.clone());
        }
    }
    for k in ["system_prompt_digest", "tool_manifest_digest"] {
        if let Some(v) = get(d, k).filter(|v| v.is_string()) {
            o.insert(k.into(), v.clone());
        }
    }
    Value::Object(o)
}

/// The core verification, total: `{ok, present, bound, reason?, identity?}`. `input` is `{document, ctx, expected, nowMs,
/// trustedAttestorKeys, pqPins?, maxNonceAgeMs?, clockSkewMs?}`; `hardware` (when given) roots authenticity in a hardware verifier. The
/// stages run in this order and the first failure wins: a document is present, the binding is constructible, the PCActn's grant_ref, epoch
/// and quote_digest and the document nonce match `expected`, hardware is required but missing, then either the hardware path (nonce age,
/// verifier ok, bound, measured) or the software path (mode, trusted attestor, known suite, signature, binding present and equal, validity
/// window, nonce age when an issue time is supplied), then the `agent_binding` match on the established identity. Freshness comes from the
/// server's nonce clock, never from a document date, in hardware mode. Any failure is `ok: false, bound: false`.
pub fn verify_attestation(input: &Value, hardware: Option<&HardwareVerifierFn>) -> Value {
    let doc = get(input, "document");
    let present = matches!(doc, Some(Value::Object(_) | Value::Array(_)));
    let fail = |reason: String| json!({"ok": false, "present": present, "bound": false, "reason": reason});
    match verify_inner(input, hardware, present) {
        Ok(v) => v,
        Err(e) => fail(format!("attestation verification error (fail closed): {}", if e.is_empty() { "unknown" } else { &e })),
    }
}

fn verify_inner(input: &Value, hardware: Option<&HardwareVerifierFn>, present: bool) -> Result<Value, String> {
    let fail = |reason: String| Ok(json!({"ok": false, "present": present, "bound": false, "reason": reason}));
    let ctx = get(input, "ctx");
    let expected = get(input, "expected");
    // an unreadable clock would make every window and nonce-age comparison false, i.e. pass: refuse
    let Some(now) = finite(get(input, "nowMs")) else { return fail("verifier clock is not a finite time (fail closed)".into()) };
    let trusted: HashSet<String> = match get(input, "trustedAttestorKeys") {
        None | Some(Value::Null) => HashSet::new(),
        Some(Value::Array(a)) => a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect(),
        Some(Value::String(s)) => s.chars().map(String::from).collect(),
        Some(_) => return Err("object is not iterable (cannot read property Symbol(Symbol.iterator))".into()),
    };
    let skew = finite(get(input, "clockSkewMs")).map_or(0.0, |s| s.max(0.0));
    let max_age = finite(get(input, "maxNonceAgeMs")).filter(|m| *m > 0.0).unwrap_or(MAX_ATTESTATION_AGE_MS).min(MAX_ATTESTATION_AGE_MS);
    let has_hw = hardware.is_some();
    let d = doc_of(input);
    let pc = get_opt(ctx, "pcactn");
    let att = get_opt(pc, "attestation");

    if !present {
        return fail("no attestation document for this action".into());
    }
    let expected_binding = match attestation_binding_b64u(expected.unwrap_or(&Value::Null)) {
        Ok(b) => b,
        Err(e) => return fail(format!("attestation binding not constructible: {}", if e.is_empty() { "invalid" } else { &e })),
    };
    let exp = |k: &str| get_opt(expected, k);
    if !strict_eq(get_opt(pc, "grant_ref"), exp("grantRef")) {
        return fail("attestation binding: PCActn grant_ref differs from expected grant".into());
    }
    if !strict_eq(get_opt(att, "epoch"), exp("epoch")) {
        return fail("attestation binding: PCActn attestation epoch differs from expected epoch".into());
    }
    if !strict_eq(get_opt(att, "quote_digest"), exp("nonce")) {
        return fail("attestation nonce does not bind to this PCActn".into());
    }
    if !strict_eq(get_opt(d, "nonce"), exp("nonce")) {
        return fail("attestation nonce does not match the server-issued nonce".into());
    }
    let binding = agent_binding_of(ctx)?;
    let require_hw = is_true(get_opt(binding.as_ref(), "require_hardware"));
    if require_hw && !has_hw {
        return fail("agent_binding.require_hardware: no hardware verifier is configured (fail closed)".into());
    }
    if require_hw && get_opt(d, "mode").and_then(Value::as_str) != Some("hardware") {
        return fail("agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)".into());
    }

    let identity: Value;
    if let Some(hw) = hardware {
        if let Some(r) = nonce_age_reason(exp("nonceIssuedAt"), now, skew, max_age) {
            return fail(r);
        }
        let mut call = Map::new();
        if let Some(doc) = d {
            call.insert("document".into(), doc.clone());
        }
        if let Some(c) = ctx {
            call.insert("ctx".into(), c.clone());
        }
        call.insert("nowMs".into(), get(input, "nowMs").cloned().unwrap_or(Value::Null));
        if let Some(e) = expected {
            call.insert("expected".into(), e.clone());
        }
        let res = hw(&Value::Object(call))?;
        if res.is_null() {
            return Err("Cannot read properties of null (reading 'ok')".into());
        }
        if !truthy(get(&res, "ok")) {
            let why = get(&res, "reason").filter(|r| !r.is_null()).map_or_else(|| "invalid".to_string(), js_value_string);
            return fail(format!("hardware attestation rejected: {why}"));
        }
        if !is_true(get(&res, "bound")) {
            return fail("hardware verifier did not confirm report_data binding".into());
        }
        if !truthy(get(&res, "measured")) {
            return fail("hardware verifier returned no measured identity".into());
        }
        identity = get(&res, "measured").cloned().unwrap_or(Value::Null);
    } else {
        let d = d.unwrap_or(&Value::Null);
        if get(d, "mode").and_then(Value::as_str) != Some("software") {
            return fail(format!("document mode {} needs a hardwareVerifier", undefined_or(get(d, "mode"))));
        }
        let attestor = get(d, "attestor").and_then(Value::as_str);
        let Some(attestor) = attestor.filter(|a| trusted.contains(*a)) else { return fail("attestor key is not trusted".into()) };
        if get(d, "alg").is_some() && suite_of(get(d, "alg")).is_err() {
            return fail("attestation declares an unknown signature alg".into());
        }
        let signed = match get(d, "sig").and_then(Value::as_str) {
            None => false,
            Some(_) => {
                let mut body = d.as_object().cloned().unwrap_or_default();
                body.remove("sig");
                body.remove("pq_sig");
                let msg = document_message(&Value::Object(body))?;
                let pin = get_opt(get(input, "pqPins"), attestor).filter(|p| p.is_string()).map(|p| (attestor, p));
                verify_pinned_suite(get(d, "alg"), attestor, get(d, "pq_pk"), &msg, get(d, "sig"), get(d, "pq_sig"), pin).unwrap_or(false)
            }
        };
        if !signed {
            return fail("attestation signature does not verify".into());
        }
        if !get(d, "binding").and_then(Value::as_str).is_some_and(|b| !b.is_empty()) {
            return fail("attestation is not bound (binding absent)".into());
        }
        if get(d, "binding").and_then(Value::as_str) != Some(expected_binding.as_str()) {
            return fail("attestation binding mismatch (holder/grant/epoch/nonce)".into());
        }
        match window_decision(now, skew, get(d, "issued_at"), get(d, "expires_at")) {
            Window::Malformed => return fail("malformed attestation validity window".into()),
            Window::NotYet => return fail("attestation not yet valid".into()),
            Window::Expired => return fail("attestation expired".into()),
            Window::Valid => {}
        }
        if number_of(exp("nonceIssuedAt")).is_some() {
            if let Some(r) = nonce_age_reason(exp("nonceIssuedAt"), now, skew, max_age) {
                return fail(r);
            }
        }
        identity = software_identity(d);
    }
    if let Some(reason) = match_agent_binding(&identity, binding.as_ref().unwrap_or(&Value::Null))? {
        return fail(reason);
    }
    Ok(json!({"ok": true, "present": true, "bound": true, "identity": identity}))
}

fn doc_of(input: &Value) -> Option<&Value> {
    get(input, "document")
}

/// The hosts a verifier hook is wired to (everything the reference takes as a function or an object rather than as data).
#[derive(Default, Clone)]
pub struct AttestationHooks {
    /// Single-use nonce store: with it the nonce is consumed ONCE, only after the attestation verified and is bound.
    pub nonce_store: Option<Arc<dyn AttestationNonceStore>>,
    /// Supplied: HARDWARE mode (authenticity is delegated to this verifier instead of the signature).
    pub hardware: Option<Arc<HardwareVerifierFn>>,
    /// How to find the document for an action (default: resolves nothing).
    pub resolve_document: Option<AttestationResolver>,
    /// The SERVER-SUPPLIED expected binding for this action (the holder, grant and epoch of the verified PCActn and the nonce from the
    /// server's issued-nonce store); `Err` is a throw. Required: without it (and without the insecure opt-out) the hook fails closed.
    pub expected_binding: Option<Arc<dyn Fn(&Value) -> Result<Option<Value>, String> + Send + Sync>>,
    /// The clock, epoch ms (default the system clock).
    pub now: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
}

/// The verifier hook: the verifier context `{pcactn, grant}` in, `{enforced: true, ok, reason?, present, bound}` out.
pub type AttestationHook = Arc<dyn Fn(&Value) -> Value + Send + Sync>;

/// Build the attestation verifier hook over [`verify_attestation`]. `opts` is `{trustedAttestorKeys, minNonceBytes?, maxNonceAgeMs?,
/// clockSkewMs?, pqPins?, insecure_selfDeclaredNonce?}`. The expected binding comes from `hooks.expected_binding`; with neither it nor the
/// loud `insecure_selfDeclaredNonce` opt-out (the PCActn's own `quote_digest` as the nonce: replay protection is void) the hook fails
/// closed. The result carries `present` and `bound` so a server can fail closed when `agent_binding` is non-empty.
pub fn create_attestation_verifier(opts: &Value, hooks: AttestationHooks) -> AttestationHook {
    let trusted = match get(opts, "trustedAttestorKeys") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    let opts = opts.clone();
    let insecure = is_true(get(&opts, "insecure_selfDeclaredNonce"));
    Arc::new(move |ctx: &Value| {
        let fin = |ok: bool, present: bool, bound: bool, reason: Option<&str>| {
            let mut o = json!({"enforced": true, "ok": ok});
            if let Some(r) = reason.filter(|r| !r.is_empty()) {
                o["reason"] = json!(r);
            }
            o["present"] = json!(present);
            o["bound"] = json!(bound);
            o
        };
        let error = |e: String| {
            fin(
                false,
                false,
                false,
                Some(&format!("attestation verification error (fail closed): {}", if e.is_empty() { "unknown" } else { &e })),
            )
        };
        let document = hooks.resolve_document.as_ref().and_then(|r| r(ctx));
        let expected: Option<Value> = if let Some(eb) = &hooks.expected_binding {
            match eb(ctx) {
                Ok(e) => e,
                Err(e) => return error(e),
            }
        } else if insecure {
            let pc = get(ctx, "pcactn");
            let chain = get_opt(pc, "cap_chain").and_then(Value::as_array).filter(|c| !c.is_empty());
            let leaf = chain.and_then(|c| c.last()).or_else(|| get(ctx, "grant"));
            let mut e = Map::new();
            e.insert("holderPub".into(), json!(get_opt(leaf, "holder").and_then(Value::as_str).unwrap_or("")));
            for (k, v) in [
                ("grantRef", get_opt(pc, "grant_ref")),
                ("epoch", get_opt(get_opt(pc, "attestation"), "epoch")),
                ("nonce", get_opt(get_opt(pc, "attestation"), "quote_digest")),
            ] {
                if let Some(v) = v {
                    e.insert(k.into(), v.clone());
                }
            }
            Some(Value::Object(e))
        } else {
            None
        };
        let present = truthy(document.as_ref());
        let Some(expected) = expected.filter(|e| truthy(Some(e))) else {
            return fin(false, present, false, Some("no server-issued attestation nonce/binding available (fail closed)"));
        };
        if !insecure && !nonce_entropy_ok(get(&expected, "nonce").unwrap_or(&Value::Null), get(&opts, "minNonceBytes")) {
            return fin(
                false,
                present,
                false,
                Some("attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)"),
            );
        }
        let clock = hooks.now.as_ref().map_or_else(now_ms, |c| c());
        let mut input = Map::new();
        if let Some(d) = &document {
            input.insert("document".into(), d.clone());
        }
        input.insert("ctx".into(), ctx.clone());
        input.insert("expected".into(), expected.clone());
        input.insert("nowMs".into(), jnum(clock).unwrap_or(Value::Null)); // a non-finite clock is no JSON number: refused by the verifier
        input.insert("trustedAttestorKeys".into(), Value::Array(trusted.clone()));
        for k in ["pqPins", "maxNonceAgeMs", "clockSkewMs"] {
            if let Some(v) = get(&opts, k) {
                input.insert(k.into(), v.clone());
            }
        }
        let verdict = verify_attestation(&Value::Object(input), hooks.hardware.as_deref());
        let (ok, bound, vpresent) = (is_true(verdict.get("ok")), is_true(verdict.get("bound")), is_true(verdict.get("present")));
        if ok && bound {
            if let Some(store) = &hooks.nonce_store {
                if !store.consume(get(&expected, "nonce").and_then(Value::as_str).unwrap_or("")) {
                    return fin(false, vpresent, false, Some("attestation nonce already consumed (replay)"));
                }
            }
        }
        fin(ok, vpresent, bound, verdict.get("reason").and_then(Value::as_str))
    })
}

/// The hook as an `authorize` attestation verifier (`(pcactn, grant, now)` in, an enforced verdict out).
pub fn authorize_hook(hook: AttestationHook) -> impl Fn(&Value, &Value, i64) -> crate::HookResult + Send + Sync + 'static {
    move |pcactn: &Value, grant: &Value, _now: i64| {
        let r = hook(&json!({"pcactn": pcactn, "grant": grant}));
        crate::HookResult::Enforced {
            ok: is_true(r.get("ok")),
            reason: r.get("reason").and_then(Value::as_str).map(str::to_string),
            t: None,
        }
    }
}

// ---- multi-root N-of-M ------------------------------------------------------------------------------------------------------------

/// One independent attestation root (a distinct hardware or software trust anchor) of a multi-root policy.
pub struct AttestationRoot {
    /// A stable, non-empty string id (`'amd-sev-snp'`, `'intel-tdx'`, `'pq-harness'`) for de-duplication and audit.
    pub id: Value,
    pub verifier: Arc<HardwareVerifierFn>,
    /// This root MUST verify (ok, bound and measured); a required root that does not denies.
    pub required: bool,
    /// Audit-only label of the root's suite family.
    pub suite: Option<String>,
}

impl AttestationRoot {
    pub fn new(id: &str, verifier: Arc<HardwareVerifierFn>) -> Self {
        Self { id: json!(id), verifier, required: false, suite: None }
    }
}

const IDENT_FIELDS: [&str; 6] =
    ["model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"];

fn is_obj(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

/// A hardware verifier that enforces an N-of-M policy over independent attestation roots: every root runs against the same action; a root
/// passes when it is ok, bound and measured; a REQUIRED root that does not pass denies (naming it); fewer than `threshold` passing roots
/// denies; passing roots that disagree on a measured field deny. The verdict carries the reconciled identity. `Err` at construction for an
/// empty root set, a threshold that is not an integer in `[1, roots]`, or a missing, empty or duplicate id.
pub fn create_multi_root_verifier(threshold: f64, roots: Vec<AttestationRoot>) -> Result<Arc<HardwareVerifierFn>, String> {
    if roots.is_empty() {
        return Err("createMultiRootVerifier: at least one attestation root is required".into());
    }
    if !(threshold.is_finite() && threshold.fract() == 0.0 && threshold >= 1.0 && threshold <= roots.len() as f64) {
        return Err("createMultiRootVerifier: threshold must be an integer in [1, roots.length]".into());
    }
    let mut ids = HashSet::new();
    for r in &roots {
        let Some(id) = r.id.as_str().filter(|s| !s.is_empty()) else {
            return Err("createMultiRootVerifier: each root needs a non-empty id".into());
        };
        if !ids.insert(id.to_string()) {
            return Err(format!("createMultiRootVerifier: duplicate root id '{id}'"));
        }
    }
    let threshold = threshold as usize;
    let id_of = |roots: &[AttestationRoot], i: usize| roots[i].id.as_str().unwrap_or("").to_string();
    Ok(Arc::new(move |input: &Value| {
        let mut passed: Vec<(usize, Value)> = Vec::new();
        let mut results: Vec<Value> = Vec::new();
        let mut host = Map::new();
        let mut required_failed: Option<usize> = None;
        for (i, root) in roots.iter().enumerate() {
            let res = match (root.verifier)(input) {
                Ok(v) => v,
                Err(e) => {
                    json!({"ok": false, "reason": format!("root '{}' threw (fail closed): {}", id_of(&roots, i), if e.is_empty() { "unknown" } else { &e })})
                }
            };
            let passes = is_obj(&res) && is_true(get(&res, "ok")) && is_true(get(&res, "bound")) && truthy(get(&res, "measured"));
            if passes {
                passed.push((i, get(&res, "measured").cloned().unwrap_or(Value::Null)));
                if let Some(ha) = get(&res, "hostAsserted").filter(|h| h.is_object()) {
                    for (k, v) in ha.as_object().into_iter().flatten() {
                        host.insert(format!("{}.{k}", id_of(&roots, i)), v.clone());
                    }
                }
                results.push(res);
            } else {
                results.push(res);
                if root.required {
                    required_failed = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = required_failed {
            let ri = &results[i];
            let why = if is_obj(ri) {
                get(ri, "reason").filter(|r| !r.is_null()).map_or_else(|| "invalid".to_string(), js_value_string)
            } else {
                format!("root '{}' returned a malformed result (fail closed)", id_of(&roots, i))
            };
            return Ok(json!({"ok": false, "reason": format!("required attestation root '{}' failed: {why}", id_of(&roots, i))}));
        }
        if passed.len() < threshold {
            return Ok(
                json!({"ok": false, "reason": format!("multi-root attestation below threshold ({}/{threshold} independent roots corroborated)", passed.len())}),
            );
        }
        let mut merged: Vec<String> = Vec::new();
        for name in IDENT_FIELDS {
            let mut chosen: Option<(String, usize)> = None;
            for (i, m) in &passed {
                let Some(v) = get(m, name).and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
                match &chosen {
                    None => chosen = Some((v.to_string(), *i)),
                    Some((c, who)) if c != v => {
                        return Ok(json!({"ok": false, "reason": format!(
                            "multi-root attestation identity conflict: roots '{}' and '{}' disagree on {name}", id_of(&roots, *who), id_of(&roots, *i))}));
                    }
                    Some(_) => {}
                }
            }
            merged.push(chosen.map_or_else(String::new, |(v, _)| v));
        }
        let weights_measured = !merged[1].is_empty()
            && passed.iter().any(|(_, m)| {
                is_true(get(m, "weights_measured")) && get(m, "weights_digest").and_then(Value::as_str) == Some(merged[1].as_str())
            });
        let mut measured = json!({"model_id": merged[0], "weights_digest": merged[1], "weights_measured": weights_measured, "runtime_measurement": merged[2], "operator": merged[3]});
        for (k, v) in [("system_prompt_digest", &merged[4]), ("tool_manifest_digest", &merged[5])] {
            if !v.is_empty() {
                measured[k] = json!(v);
            }
        }
        let mut out = json!({"ok": true, "bound": true, "measured": measured});
        if !host.is_empty() {
            out["hostAsserted"] = Value::Object(host);
        }
        Ok(out)
    }))
}

// ---- accountability anchoring -----------------------------------------------------------------------------------------------------

/// The domain-separated, canonical digest of a verified attestation: the opaque commitment leaf appended to the transparency ledger. It
/// binds the measured identity AND the holder, grant, epoch and nonce, so two verifications that measured different identities (or bound to
/// different actions) anchor to different leaves. `ev` is `{identity, binding, rootIds?, suite?, verifiedAt}`; `Err` where the reference
/// throws (a missing member has no canonical form).
pub fn attestation_evidence_digest(ev: &Value) -> Result<String, String> {
    let undefined = || "canonicalize: unsupported type undefined".to_string();
    let (binding, identity) = (get(ev, "binding"), get(ev, "identity"));
    let member = |o: Option<&Value>, k: &str, what: &str| -> Result<Value, String> {
        let Some(o) = o.filter(|o| !o.is_null()) else {
            return Err(format!("Cannot read properties of undefined (reading '{k}' of {what})"));
        };
        get(o, k).cloned().ok_or_else(undefined)
    };
    let or_empty = |o: Option<&Value>, k: &str| -> Value { get_opt(o, k).filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("")) };
    let mut roots: Vec<Value> = match get(ev, "rootIds") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        Some(_) => return Err("object is not iterable (cannot read property Symbol(Symbol.iterator))".into()),
    };
    roots.sort_by(|a, b| js_value_string(a).encode_utf16().cmp(js_value_string(b).encode_utf16()));
    hash_strict(&json!({
        "domain": ATTEST_ANCHOR_DOMAIN,
        "holder": member(binding, "holderPub", "binding")?,
        "grant": member(binding, "grantRef", "binding")?,
        "epoch": member(binding, "epoch", "binding")?,
        "nonce": member(binding, "nonce", "binding")?,
        "model_id": member(identity, "model_id", "identity")?,
        "weights_digest": member(identity, "weights_digest", "identity")?,
        "weights_measured": is_true(get_opt(identity, "weights_measured")),
        "runtime_measurement": member(identity, "runtime_measurement", "identity")?,
        "operator": member(identity, "operator", "identity")?,
        "system_prompt_digest": or_empty(identity, "system_prompt_digest"),
        "tool_manifest_digest": or_empty(identity, "tool_manifest_digest"),
        "roots": roots,
        "suite": or_empty(Some(ev), "suite"),
        "verified_at": get(ev, "verifiedAt").cloned().ok_or_else(undefined)?,
    }))
}

/// What anchoring needs beside the ledger.
#[derive(Default)]
pub struct AnchorOptions<'a> {
    /// Signs the tree head over the post-append log. A post-quantum or hybrid `suite` makes the accountability record post-quantum.
    pub guardian: Option<&'a KeyPair>,
    pub suite: Suite<'a>,
    /// Instance id recorded in the tree head (default `""`).
    pub instance_id: Option<&'a str>,
    /// The tree-head timestamp, epoch ms (default the system clock).
    pub now: Option<f64>,
    /// Anchoring MUST fully succeed (ledger present, commitment appended, tree head signed) or fail.
    pub required: bool,
}

fn sign_tree_head(
    guardian: &KeyPair,
    ledger: &TransparencyLedger,
    head: &Value,
    prev_root: &Value,
    opts: &AnchorOptions<'_>,
) -> Result<Value, String> {
    let now = opts.now.unwrap_or_else(now_ms);
    let body = json!({
        "instance_id": opts.instance_id.unwrap_or(""),
        "principal": ledger.principal(),
        "size": head["size"],
        "root": head["root"],
        "prev_root": prev_root,
        "timestamp": jnum(now)?,
    });
    let signed = sign_artifact(crate::ledger::STH_DOMAIN, &body, guardian, &Suite { alg: opts.suite.alg, pq: opts.suite.pq })?;
    let mut sth = body.clone();
    sth["guardian"] = json!(guardian.public);
    for (k, v) in signed.as_object().into_iter().flatten() {
        if body.get(k).is_none() {
            sth[k] = v.clone();
        }
    }
    Ok(sth)
}

/// Anchor a VERIFIED attestation into the transparency ledger for accountability. Appends the evidence digest as an opaque commitment and,
/// when a guardian key is supplied, signs the resulting tree head with the (possibly post-quantum) suite. Detection and attribution after the
/// fact, not prevention. FAIL-CLOSED when `required`: a missing ledger or guardian key, or a failed signature, is an `Err`. Returns
/// `{index, commit, sth?}`.
pub fn anchor_attestation_evidence(ev: &Value, ledger: Option<&mut TransparencyLedger>, opts: &AnchorOptions<'_>) -> Result<Value, String> {
    let fail = |m: &str| Err(format!("attestation anchoring (fail closed): {m}"));
    let Some(ledger) = ledger else { return fail("no transparency ledger available") };
    if opts.required && opts.guardian.is_none() {
        return fail("required anchoring needs a guardian secret to sign the tree head");
    }
    let commit = attestation_evidence_digest(ev)?;
    let prev_root = ledger.head()["root"].clone();
    let index = ledger.append_commitment(&commit)?["index"].clone();
    let head = ledger.head();
    let mut out = json!({"index": index, "commit": commit});
    if let Some(g) = opts.guardian {
        match sign_tree_head(g, ledger, &head, &prev_root, opts) {
            Ok(sth) => out["sth"] = sth,
            Err(e) if opts.required => return fail(&format!("tree-head signing failed: {}", if e.is_empty() { "unknown" } else { &e })),
            Err(_) => {}
        }
    }
    Ok(out)
}
