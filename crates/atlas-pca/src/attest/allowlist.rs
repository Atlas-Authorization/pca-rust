//! Signed, versioned, expiring measurement-allowlist manifests for the hardware-attestation verifiers (port of `attest-allowlist.ts`).
//!
//! An operator PUBLISHES one signed manifest of golden measurements (TDX MRTD / RTMR, SEV-SNP launch measurement, workload image digest,
//! NVIDIA driver version and measurements, Azure MAA signing / chain SPKI pins, a signed multi-vantage corroboration record); a relying
//! party VERIFIES it and PROJECTS it into the policy field shapes the vendor verifiers take. Given a trustworthy issuer registry and a
//! trustworthy clock: the body was signed, over a domain-separated canonical encoding, by a REGISTERED issuer key under the algorithm
//! registered FOR THAT ISSUER (no downgrade; a hybrid needs BOTH halves); the manifest is inside its `[notBefore, expiresAt]` window (plus
//! an optional skew) and not older than `minVersion` / `lastSeenVersion` (a rollback is refused; the same version with another body digest
//! is a conflict); values are well-formed and unique per kind, unknown kinds and members are refused; revoked and per-entry-expired
//! entries are NEVER projected.
//!
//! NOT guaranteed: who the issuer is (the registry is the caller's root of trust), or that an accepted measurement is secure. Rollback
//! protection has three layers: the `lastSeen*` options (stateless), [`verify_allowlist_durable`] (a persisted high-water mark) and the
//! transparency anchor ([`crate::allowlist_anchor`]); without all three a fresh process can be served an older, still-unexpired manifest.
//!
//! JSON-valued (the reference's member names). Options that the reference reads as JavaScript numbers are [`JsNum`]s, so a non-finite or
//! mistyped option is refused rather than coerced.
use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::agent::{sign_with_suite, KeyPair, PqKeyPair, Suite};
use crate::{canonicalize_strict, hash_canonical_strict};

/// The closed set of allowlist entry kinds.
pub const ALLOWLIST_KINDS: [&str; 10] = [
    "tdx-mrtd",
    "tdx-rtmr",
    "sev-snp-measurement",
    "gcp-image-digest",
    "nvidia-measurement",
    "nvidia-driver-version",
    "maa-signing-spki",
    "maa-chain-root-spki",
    "maa-chain-intermediate-spki",
    "attest-corroboration",
];

/// The domain the manifest body is signed under.
pub const ALLOWLIST_DOMAIN: &str = "pca-attest-allowlist/v1\n";

const BODY_KEYS: [&str; 5] = ["version", "issuedAt", "notBefore", "expiresAt", "entries"];
const ENTRY_KEYS: [&str; 5] = ["kind", "value", "label", "notAfter", "revoked"];
const MANIFEST_KEYS: [&str; 5] = ["body", "issuer", "alg", "sig", "pq_sig"];
const MAX_ENTRIES: usize = 10_000;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A JavaScript value an option is read as: absent, a number (possibly non-finite), or anything else (a string, `null`, ...).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JsNum {
    Undefined,
    Num(f64),
    Other,
}

fn is_safe_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_SAFE
}

/// The options of a verification (`VerifyAllowlistOptions` without the registry, which is passed beside them).
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub now_ms: JsNum,
    /// Deployment-shipped floor: versions below it are refused.
    pub min_version: JsNum,
    /// The highest version this relying party accepted before (persisted by the caller).
    pub last_seen_version: JsNum,
    /// The digest of the manifest at `last_seen_version`.
    pub last_seen_digest: Option<String>,
    pub clock_skew_ms: JsNum,
    /// Refuse manifests whose `expiresAt - notBefore` exceeds this (bounds the rollback window).
    pub max_lifetime_ms: JsNum,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            now_ms: JsNum::Undefined,
            min_version: JsNum::Undefined,
            last_seen_version: JsNum::Undefined,
            last_seen_digest: None,
            clock_skew_ms: JsNum::Undefined,
            max_lifetime_ms: JsNum::Undefined,
        }
    }
}

impl VerifyOptions {
    /// Read the options from a JSON object with the reference's member names (`nowMs`, `minVersion`, `lastSeenVersion`, `lastSeenDigest`,
    /// `clockSkewMs`, `maxLifetimeMs`): an absent member is `undefined`, a number is a number, anything else is [`JsNum::Other`].
    pub fn from_json(o: &Value) -> Self {
        let num = |k: &str| match o.get(k) {
            None => JsNum::Undefined,
            Some(Value::Number(n)) => JsNum::Num(n.as_f64().unwrap_or(f64::NAN)),
            Some(_) => JsNum::Other,
        };
        VerifyOptions {
            now_ms: num("nowMs"),
            min_version: num("minVersion"),
            last_seen_version: num("lastSeenVersion"),
            last_seen_digest: o.get("lastSeenDigest").and_then(Value::as_str).map(String::from),
            clock_skew_ms: num("clockSkewMs"),
            max_lifetime_ms: num("maxLifetimeMs"),
        }
    }
}

// ---- value rules -----------------------------------------------------------------------------------------------------------------

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn hex_lower(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$` and at most 16 characters.
fn driver_version_ok(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    v.len() <= 16 && (2..=4).contains(&parts.len()) && parts.iter().all(|p| (1..=6).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

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

/// `^vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}$`.
fn corroboration_label_ok(l: &str) -> bool {
    let Some(rest) = l.strip_prefix("vantages=") else { return false };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=3).contains(&digits) || rest.as_bytes()[0] == b'0' {
        return false;
    }
    let Some(method) = rest[digits..].strip_prefix(";method=") else { return false };
    (1..=150).contains(&method.len()) && method.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Validate a value for its kind: the reason, or `None`.
fn value_error(kind: &str, value: &str, label: &str) -> Option<String> {
    match kind {
        "tdx-mrtd" | "tdx-rtmr" | "sev-snp-measurement" | "nvidia-measurement" => (!hex_lower(value, 96)).then(|| format!("{kind} must be 96 lowercase hex chars")),
        "gcp-image-digest" => {
            (!value.strip_prefix("sha256:").is_some_and(|h| hex_lower(h, 64))).then(|| "gcp-image-digest must be sha256:<64 lowercase hex>".to_string())
        }
        "nvidia-driver-version" => (!driver_version_ok(value)).then(|| "nvidia-driver-version must be a dotted version of at most 16 chars".to_string()),
        "maa-signing-spki" => {
            if !hex_lower(value, 64) {
                return Some("maa-signing-spki must be 64 lowercase hex chars".into());
            }
            (!issuer_url_ok(label)).then(|| "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)".to_string())
        }
        "maa-chain-root-spki" | "maa-chain-intermediate-spki" => (!hex_lower(value, 64)).then(|| format!("{kind} must be 64 lowercase hex chars")),
        "attest-corroboration" => {
            if !hex_lower(value, 64) {
                return Some("attest-corroboration must be a 64 lowercase hex evidence digest".into());
            }
            (!corroboration_label_ok(label)).then(|| "attest-corroboration label must be vantages=<n>;method=<text>".to_string())
        }
        _ => Some("unknown kind".into()),
    }
}

/// An integer epoch in milliseconds: a safe integer, not negative, never `-0`.
fn epoch(v: Option<&Value>) -> Option<f64> {
    let f = v?.as_f64()?;
    (is_safe_integer(f) && f >= 0.0 && !(f == 0.0 && f.is_sign_negative())).then_some(f)
}

fn only_keys(o: &Map<String, Value>, allowed: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Strictly validate and copy an untrusted body. `Err` carries the first violation.
pub fn parse_body(x: &Value) -> Result<Value, String> {
    let o = x.as_object().filter(|o| only_keys(o, &BODY_KEYS)).ok_or("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries")?;
    let version = o.get("version").and_then(Value::as_f64).filter(|v| is_safe_integer(*v) && *v >= 1.0).ok_or("version must be a positive integer")?;
    let (Some(issued_at), Some(not_before), Some(expires_at)) = (epoch(o.get("issuedAt")), epoch(o.get("notBefore")), epoch(o.get("expiresAt"))) else {
        return Err("issuedAt/notBefore/expiresAt must be integer epoch ms".into());
    };
    if !(not_before < expires_at) {
        return Err("notBefore must be before expiresAt".into());
    }
    if !(issued_at <= expires_at) {
        return Err("issuedAt must not be after expiresAt".into());
    }
    let entries = o.get("entries").and_then(Value::as_array).filter(|e| e.len() <= MAX_ENTRIES).ok_or("entries must be an array (bounded)")?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let eo = e.as_object().filter(|m| only_keys(m, &ENTRY_KEYS)).ok_or_else(|| format!("entry {i}: unexpected shape"))?;
        let kind = eo.get("kind").and_then(Value::as_str).filter(|k| ALLOWLIST_KINDS.contains(k)).ok_or_else(|| format!("entry {i}: unknown kind"))?;
        let (Some(value), Some(label)) = (eo.get("value").and_then(Value::as_str), eo.get("label").and_then(Value::as_str)) else {
            return Err(format!("entry {i}: value and label must be strings"));
        };
        let len = utf16_len(label);
        if len < 1 || len > 200 || label.chars().any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f) {
            return Err(format!("entry {i}: label must be 1..200 printable chars"));
        }
        if let Some(ve) = value_error(kind, value, label) {
            return Err(format!("entry {i}: {ve}"));
        }
        let not_after = eo.get("notAfter");
        if not_after.is_some() && epoch(not_after).is_none() {
            return Err(format!("entry {i}: notAfter must be integer epoch ms"));
        }
        let revoked = eo.get("revoked");
        if revoked.is_some() && revoked != Some(&json!(true)) {
            return Err(format!("entry {i}: revoked, when present, must be true"));
        }
        let dup = format!("{kind}\0{}{value}", if kind == "maa-signing-spki" { format!("{label}\0") } else { String::new() });
        if !seen.insert(dup) {
            return Err(format!("entry {i}: duplicate {kind} value"));
        }
        let mut m = Map::new();
        m.insert("kind".into(), json!(kind));
        m.insert("value".into(), json!(value));
        m.insert("label".into(), json!(label));
        if let Some(n) = not_after {
            m.insert("notAfter".into(), n.clone());
        }
        if revoked.is_some() {
            m.insert("revoked".into(), json!(true));
        }
        out.push(Value::Object(m));
    }
    Ok(json!({"version": o["version"], "issuedAt": o["issuedAt"], "notBefore": o["notBefore"], "expiresAt": o["expiresAt"], "entries": out}))
}

fn signed_bytes(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = ALLOWLIST_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

fn fail(code: &str, reason: impl Into<String>) -> Value {
    json!({"ok": false, "code": code, "reason": reason.into()})
}

/// The PQ public-key slot of an issuer registration a suite uses.
fn pq_slot(alg: &str) -> &'static str {
    match crate::resolve_sig_alg(Some(&json!(alg))).and_then(|s| s.pq) {
        Some(crate::Pq::MlDsa65) => "mlDsaPub",
        Some(crate::Pq::Slh128f) => "slhDsaPub",
        Some(crate::Pq::MlDsa87) => "mlDsa87Pub",
        Some(crate::Pq::Slh256s) => "slhDsa256sPub",
        Some(crate::Pq::FnDsa512) => "fnDsa512Pub",
        Some(crate::Pq::FnDsa1024) => "fnDsa1024Pub",
        _ => "lessCat1Pub",
    }
}

fn verify_signature(alg: &str, keys: &Value, msg: &[u8], sig: &str, pq_sig: Option<&Value>) -> bool {
    let Some(suite) = crate::resolve_sig_alg(Some(&json!(alg))) else { return false };
    let ed_pub = keys.get("edPub").and_then(Value::as_str).unwrap_or("");
    // the registered PQ key (verifier-side configuration) is the one the signature verifies under
    let pq_key = if suite.needs_pq_pk { keys.get(pq_slot(alg)).and_then(Value::as_str).and_then(crate::pinned::PinnedPq::caller_vouched) } else { None };
    crate::verify_suite(Some(&json!(suite.alg)), ed_pub, pq_key.as_ref(), msg, Some(&json!(sig)), pq_sig)
}

/// Verify a signed manifest against the issuer registry `issuer_keys` (`{<issuerId>: {alg, keys: {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?,
/// slhDsa256sPub?}, notAfter?}}`). Never fails: `{ok: true, body, issuer, alg, version, digest}` or `{ok: false, code, reason}` with `code`
/// one of `malformed`, `unknown-issuer`, `issuer-expired`, `alg-mismatch`, `bad-signature`, `not-yet-valid`, `expired`, `rollback`,
/// `below-min-version`, `conflict`, `lifetime-too-long`. The checks run in the reference's order (the first failure wins).
pub fn verify_allowlist_manifest(manifest: &Value, issuer_keys: &Value, opts: &VerifyOptions) -> Value {
    let Some(m) = manifest.as_object().filter(|m| only_keys(m, &MANIFEST_KEYS)) else { return fail("malformed", "manifest has an unexpected shape") };
    let now = match opts.now_ms {
        JsNum::Num(n) if is_safe_integer(n) => n,
        _ => return fail("malformed", "nowMs must be an integer"),
    };
    let Some(issuer) = m.get("issuer").and_then(Value::as_str).filter(|i| !i.is_empty() && utf16_len(i) <= 200) else {
        return fail("malformed", "issuer must be a string");
    };
    let Some(alg) = m.get("alg").and_then(Value::as_str).filter(|a| crate::REGISTERED_SUITES.contains(a)) else {
        return fail("malformed", "unknown signature alg");
    };
    let Some(sig) = m.get("sig").and_then(Value::as_str) else { return fail("malformed", "sig must be a string") };
    let pq_sig = m.get("pq_sig");
    if pq_sig.is_some_and(|p| !p.is_string()) {
        return fail("malformed", "pq_sig must be a string");
    }
    let needs_pq_sig = crate::resolve_sig_alg(Some(&json!(alg))).map_or_else(|| alg.starts_with("hybrid-"), |s| s.needs_pq_sig);
    if needs_pq_sig != pq_sig.is_some() {
        return fail("malformed", "pq_sig presence does not match the suite");
    }
    let body = match parse_body(m.get("body").unwrap_or(&Value::Null)) {
        Ok(b) => b,
        Err(e) => return fail("malformed", e),
    };
    let Some(registry) = issuer_keys.as_object() else { return fail("malformed", "Cannot convert undefined or null to object") };
    let Some(reg) = registry.get(issuer) else { return fail("unknown-issuer", format!("issuer '{issuer}' is not registered")) };
    if reg.get("alg").and_then(Value::as_str) != Some(alg) {
        return fail("alg-mismatch", format!("issuer is registered for '{}', manifest claims '{alg}'", crate::intent_strict::js_opt_string(reg.get("alg"))));
    }
    if let Some(na) = reg.get("notAfter") {
        // `nowMs > notAfter` with a non-number coerced as JavaScript does (null -> 0, anything else NaN)
        let na = match na {
            Value::Null => 0.0,
            other => other.as_f64().unwrap_or(f64::NAN),
        };
        if !(now.is_finite() && now <= na) {
            return fail("issuer-expired", "issuer key is past its notAfter");
        }
    }
    let keys = reg.get("keys").unwrap_or(&Value::Null);
    if keys.is_null() {
        return fail("malformed", "Cannot read properties of undefined (reading 'edPub')");
    }
    let msg = match signed_bytes(&body) {
        Ok(m) => m,
        Err(e) => return fail("malformed", e),
    };
    if !verify_signature(alg, keys, &msg, sig, pq_sig) {
        return fail("bad-signature", "signature does not verify under the registered issuer key");
    }
    // The signature is good from here on; the remaining checks are policy over authentic content. Numeric options are validated, never
    // coerced: a NaN skew would make BOTH window comparisons false (an expired manifest verifying ok).
    let finite = |n: JsNum| matches!(n, JsNum::Undefined) || matches!(n, JsNum::Num(x) if x.is_finite());
    let integral = |n: JsNum| matches!(n, JsNum::Undefined) || matches!(n, JsNum::Num(x) if is_safe_integer(x));
    if !finite(opts.clock_skew_ms) {
        return fail("malformed", "clockSkewMs must be a finite number");
    }
    if !finite(opts.max_lifetime_ms) {
        return fail("malformed", "maxLifetimeMs must be a finite number");
    }
    if !integral(opts.min_version) {
        return fail("malformed", "minVersion must be an integer");
    }
    if !integral(opts.last_seen_version) {
        return fail("malformed", "lastSeenVersion must be an integer");
    }
    let skew = match opts.clock_skew_ms {
        JsNum::Num(s) => s.max(0.0),
        _ => 0.0,
    };
    let (not_before, expires_at, version) = (body["notBefore"].as_f64().unwrap_or(f64::NAN), body["expiresAt"].as_f64().unwrap_or(f64::NAN), body["version"].as_f64().unwrap_or(f64::NAN));
    if !(now.is_finite() && skew.is_finite() && now + skew >= not_before) {
        return fail("not-yet-valid", "manifest is not yet valid");
    }
    if !(now.is_finite() && skew.is_finite() && now - skew <= expires_at) {
        return fail("expired", "manifest has expired");
    }
    if let JsNum::Num(max) = opts.max_lifetime_ms {
        if !(expires_at - not_before <= max) {
            return fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs");
        }
    }
    if let JsNum::Num(min) = opts.min_version {
        if version < min {
            return fail("below-min-version", format!("version {version} < minVersion {min}"));
        }
    }
    let Some(digest) = hash_canonical_strict(&body) else { return fail("malformed", "canonicalize: the body is not strictly canonical") };
    if let JsNum::Num(last) = opts.last_seen_version {
        if version < last {
            return fail("rollback", format!("version {version} is older than last seen {last}"));
        }
        if version == last && opts.last_seen_digest.as_deref().is_some_and(|d| d != digest) {
            return fail("conflict", "same version as last seen but a different body");
        }
    }
    json!({"ok": true, "body": body, "issuer": issuer, "alg": alg, "version": body["version"], "digest": digest})
}

// ---- the durable high-water mark -------------------------------------------------------------------------------------------------

/// A durable key-value store with an atomic read-modify-write (`DurableKv` of the reference): `update` runs `f` under the store's lock with
/// the current value and stores what it returns (`None` leaves the key unchanged), returning the value now stored.
pub trait AllowlistKv {
    fn get(&self, key: &str) -> Option<Value>;
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Option<Value>;
}

#[derive(Clone, PartialEq, Debug)]
enum Hw {
    Missing,
    Corrupt,
    Val(i64, String),
}

/// A persisted high-water mark: exactly a safe integer `version` (not `-0`) and a canonical 43-character base64url `digest`.
fn parse_hw(x: &Value) -> Option<(i64, String)> {
    let o = x.as_object()?;
    let v = o.get("version")?.as_f64().filter(|v| is_safe_integer(*v) && !(*v == 0.0 && v.is_sign_negative()))?;
    let d = o.get("digest")?.as_str().filter(|d| d.len() == 43 && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))?;
    Some((v as i64, d.to_string()))
}

fn hw_of(raw: Option<&Value>) -> Hw {
    match raw {
        None => Hw::Missing,
        Some(v) => parse_hw(v).map_or(Hw::Corrupt, |(v, d)| Hw::Val(v, d)),
    }
}

/// The proved updater (append-only): a corrupt record is left alone, and so is one whose version is already at least ours.
fn update_fn(cur: &Hw, v: i64, d: &str) -> Hw {
    match cur {
        Hw::Corrupt => Hw::Corrupt,
        Hw::Val(cv, _) if *cv >= v => cur.clone(),
        _ => Hw::Val(v, d.to_string()),
    }
}

/// [`verify_allowlist_manifest`] with the rollback high-water mark `{version, digest}` per issuer kept in `kv` (key `allowlist/<issuer>`):
/// the stored mark is fed in as `lastSeen*` and an accepted manifest atomically advances it (monotone: a concurrent newer acceptance
/// turns this one into a `rollback`, a same-version different-digest record into a `conflict`). A corrupt stored mark fails closed as
/// `malformed`; only the LOCAL state is wiped by deleting it, which the transparency anchor covers.
pub fn verify_allowlist_durable(manifest: &Value, issuer_keys: &Value, opts: &VerifyOptions, kv: &dyn AllowlistKv) -> Value {
    let Some(issuer) = manifest.as_object().and_then(|m| m.get("issuer")).and_then(Value::as_str).filter(|i| utf16_len(i) <= 200) else {
        return fail("malformed", "issuer must be a string");
    };
    let key = format!("allowlist/{issuer}");
    let raw = kv.get(&key);
    let read = hw_of(raw.as_ref());
    if read == Hw::Corrupt {
        return fail("malformed", "persisted allowlist high-water mark is corrupt");
    }
    let mut o = opts.clone();
    if let Hw::Val(v, d) = &read {
        o.last_seen_version = JsNum::Num(*v as f64);
        o.last_seen_digest = Some(d.clone());
    }
    let v = verify_allowlist_manifest(manifest, issuer_keys, &o);
    if v["ok"] != json!(true) {
        return v;
    }
    let (ver, digest) = (v["version"].as_i64().unwrap_or(0), v["digest"].as_str().unwrap_or("").to_string());
    let mut now_kv: Option<Hw> = None;
    let stored = kv.update(&key, &mut |cur: Option<&Value>| {
        let c = hw_of(cur);
        let next = update_fn(&c, ver, &digest);
        let write = matches!(next, Hw::Val(..)) && next != c;
        now_kv = Some(c);
        write.then(|| json!({"version": ver, "digest": digest}))
    });
    let now_kv = match now_kv {
        Some(n) => n,
        // a store may answer without running the updater: the returned record IS the record at update time; nothing parseable stored
        // means our acceptance was never recorded: fail closed, never accept unpersisted
        None => match stored.as_ref().and_then(parse_hw) {
            Some((sv, sd)) => Hw::Val(sv, sd),
            None => return fail("rollback", "a newer manifest was accepted concurrently"),
        },
    };
    match update_fn(&now_kv, ver, &digest) {
        Hw::Val(av, _) if av > ver => fail("rollback", "a newer manifest was accepted concurrently"),
        Hw::Val(av, ad) if av == ver && ad != digest => fail("conflict", "same version as the stored high-water mark but a different body"),
        Hw::Val(..) => v,
        _ => fail("rollback", "a newer manifest was accepted concurrently"),
    }
}

// ---- operator tools --------------------------------------------------------------------------------------------------------------

/// Validate operator input and return a canonical body. `Err` on any violation.
pub fn create_allowlist_manifest(input: &Value) -> Result<Value, String> {
    parse_body(input)
}

/// Sign a body with an issuer key under `alg`: `{body, issuer, alg, sig, pq_sig?}`. `Err` when the body is invalid or the key material for
/// the suite is missing (`ed` for an Ed25519 or hybrid suite, `pq` of the suite's family for a post-quantum one).
pub fn sign_allowlist_manifest(body: &Value, issuer: &str, alg: &str, ed: Option<&KeyPair>, pq: Option<&PqKeyPair>) -> Result<Value, String> {
    let clean = parse_body(body)?;
    let (sig, pq_sig) = sign_with_suite(&Suite { alg: Some(alg), pq }, ed, &signed_bytes(&clean)?)?;
    let mut out = json!({"body": clean, "issuer": issuer, "alg": alg, "sig": sig});
    if let Some(p) = pq_sig {
        out["pq_sig"] = json!(p);
    }
    Ok(out)
}

/// Derive the next body that revokes `rev` (`{kind, value, label?}`: adds or flips a tombstone) with `version + 1` and the given times
/// (`{issuedAt, notBefore, expiresAt}`). The result must be re-signed. `Err` if the value is not well-formed for its kind.
pub fn revoke_allowlist_entry(prev: &Value, rev: &Value, times: &Value) -> Result<Value, String> {
    let mut entries: Vec<Value> = prev.get("entries").and_then(Value::as_array).cloned().ok_or("Cannot read properties of undefined (reading 'map')")?;
    let (kind, value, label) = (rev.get("kind"), rev.get("value"), rev.get("label"));
    let maa = kind == Some(&json!("maa-signing-spki"));
    let hit = entries.iter_mut().find(|e| e.get("kind") == kind && e.get("value") == value && (!maa || (label.is_some() && e.get("label") == label)));
    match hit {
        Some(h) => {
            if let Some(m) = h.as_object_mut() {
                m.insert("revoked".into(), json!(true));
            }
        }
        None => entries.push(json!({"kind": kind, "value": value, "label": label.cloned().unwrap_or(json!("revoked")), "revoked": true})),
    }
    let version = prev.get("version").and_then(Value::as_f64).map_or(f64::NAN, |v| v + 1.0);
    let mut next = Map::new();
    next.insert("version".into(), if version.is_finite() && version.fract() == 0.0 { json!(version as i64) } else { Value::Null });
    for (k, v) in times.as_object().into_iter().flatten() {
        next.insert(k.clone(), v.clone());
    }
    next.insert("entries".into(), Value::Array(entries));
    parse_body(&Value::Object(next))
}

/// Zero-padded 16-byte-slot hex of a dotted driver version (the form `NvidiaCcPolicy.driverVersions` takes).
pub fn driver_version_slot_hex(version: &str) -> Result<String, String> {
    if !driver_version_ok(version) {
        return Err("invalid driver version".into());
    }
    let mut hex: String = version.bytes().map(|b| format!("{b:02x}")).collect();
    while hex.len() < 32 {
        hex.push('0');
    }
    Ok(hex)
}

// ---- projection ------------------------------------------------------------------------------------------------------------------

/// Project a VERIFIED manifest (the `ok` result of [`verify_allowlist_manifest`]) into policy arrays at `now_ms`. Revoked entries and
/// entries past their own `notAfter` are excluded; a value revoked anywhere (for its kind) is excluded even where it appears elsewhere.
pub fn project_allowlist(verified: &Value, now_ms: f64) -> Value {
    let body = &verified["body"];
    let entries: Vec<&Value> = body["entries"].as_array().into_iter().flatten().collect();
    let text = |e: &Value, k: &str| e[k].as_str().unwrap_or("").to_string();
    let mut tdx_mrtds = Vec::new();
    let (mut tdx_rtmrs, mut sev, mut images, mut nv, mut nv_drv, mut nv_cc) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut roots, mut inters, mut corr, mut revoked, mut expired) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut maa: Map<String, Value> = Map::new();
    let mut denied: BTreeSet<(String, String)> = BTreeSet::new();
    for e in &entries {
        if e.get("revoked") == Some(&json!(true)) {
            denied.insert((text(e, "kind"), text(e, "value")));
            revoked.push(json!({"kind": e["kind"], "value": e["value"], "label": e["label"]}));
        }
    }
    for e in &entries {
        if e.get("revoked") == Some(&json!(true)) || denied.contains(&(text(e, "kind"), text(e, "value"))) {
            continue;
        }
        if e.get("notAfter").and_then(Value::as_f64).is_some_and(|na| !(now_ms.is_finite() && now_ms <= na)) {
            expired.push(json!({"kind": e["kind"], "value": e["value"], "label": e["label"]}));
            continue;
        }
        let value = text(e, "value");
        match text(e, "kind").as_str() {
            "tdx-mrtd" => tdx_mrtds.push(json!(value)),
            "tdx-rtmr" => tdx_rtmrs.push(json!(value)),
            "sev-snp-measurement" => sev.push(json!(value)),
            "gcp-image-digest" => images.push(json!(value)),
            "nvidia-measurement" => nv.push(json!(value)),
            "nvidia-driver-version" => {
                nv_cc.push(json!(driver_version_slot_hex(&value).unwrap_or_default()));
                nv_drv.push(json!(value));
            }
            "maa-signing-spki" => {
                let slot = maa.entry(text(e, "label")).or_insert_with(|| json!([]));
                slot.as_array_mut().expect("array").push(json!(value));
            }
            "maa-chain-root-spki" => roots.push(json!(value)),
            "maa-chain-intermediate-spki" => inters.push(json!(value)),
            "attest-corroboration" => corr.push(json!({"value": value, "label": e["label"]})),
            _ => {}
        }
    }
    json!({
        "tdxMrtds": tdx_mrtds,
        "tdxRtmrs": tdx_rtmrs,
        "sevSnpMeasurements": sev,
        "imageDigests": images,
        "nvidiaMeasurements": nv,
        "nvidiaDriverVersions": nv_drv,
        "nvidiaCcDriverVersions": nv_cc,
        "maaSigningSpkis": Value::Object(maa),
        "maaChainRootSpkis": roots,
        "maaChainIntermediateSpkis": inters,
        "corroboration": corr,
        "revoked": revoked,
        "expired": expired,
        "version": body["version"],
        "manifestExpiresAt": body["expiresAt"],
    })
}

fn list(p: &Value, k: &str) -> Vec<Value> {
    p[k].as_array().cloned().unwrap_or_default()
}

fn put_nonempty(out: &mut Map<String, Value>, key: &str, v: Vec<Value>) {
    if !v.is_empty() {
        out.insert(key.into(), Value::Array(v));
    }
}

/// Spreadable fields for the Azure MAA verifier's policy. Empty lists are omitted.
pub fn azure_maa_policy_fields(p: &Value) -> Value {
    let mut o = Map::new();
    put_nonempty(&mut o, "tdxMrtds", list(p, "tdxMrtds"));
    put_nonempty(&mut o, "sevSnpMeasurements", list(p, "sevSnpMeasurements"));
    put_nonempty(&mut o, "tdxRtmrs", list(p, "tdxRtmrs"));
    Value::Object(o)
}

/// Spreadable fields for the Intel DCAP verifier's policy. `mrtds` is always present (empty makes the verifier refuse to be built).
pub fn intel_dcap_policy_fields(p: &Value) -> Value {
    let mut o = Map::new();
    o.insert("mrtds".into(), Value::Array(list(p, "tdxMrtds")));
    put_nonempty(&mut o, "rtmrs", list(p, "tdxRtmrs"));
    Value::Object(o)
}

/// Spreadable fields for the SEV-SNP verifiers' policy.
pub fn sev_snp_policy_fields(p: &Value) -> Value {
    json!({"measurements": list(p, "sevSnpMeasurements")})
}

/// Spreadable fields for the GCP Confidential Space verifier's policy.
pub fn gcp_cs_policy_fields(p: &Value) -> Value {
    json!({"imageDigests": list(p, "imageDigests")})
}

/// Spreadable fields for the NVIDIA CC policy (the driver gate is omitted when no driver entries exist).
pub fn nvidia_cc_policy_fields(p: &Value) -> Value {
    let mut o = Map::new();
    o.insert("measurements".into(), Value::Array(list(p, "nvidiaMeasurements")));
    put_nonempty(&mut o, "driverVersions", list(p, "nvidiaCcDriverVersions"));
    Value::Object(o)
}
