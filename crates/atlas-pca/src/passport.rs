//! Signed agent passport verification (wire level), the native counterpart of `verifyPassport` in `@atlasauth/pca`.
//! Same reason codes and check order; the reason text is not part of the contract. Every signature suite this crate
//! implements for PCActns (`supported_suites()`) is accepted, the post-quantum ones only under a PQ key pinned for the
//! issuer (`pq_pins`); a suite it does not implement is refused with `unsupported_suite`. Hardware evidence: the age rule,
//! the binding handed to the verifier and the identity comparison are enforced here, but the crate ships no vendor
//! attestation verifier: supply one as `attest`. Without it a `hardware_rooted` passport that passes every other check
//! is refused with `hardware_verifier_missing` (fail closed, never a software pass).

use super::attest::{Binding, HardwareVerifier};
use super::{canonicalize_strict, hash_canonical_strict, pinned, resolve_sig_alg, safe_int, verify_suite};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

const SIG_DOMAIN: &[u8] = b"atlas-pca/passport-sig/v1\0";
const DEFAULT_EVIDENCE_AGE_MS: i64 = 24 * 3_600_000;
const MAX_SKEW_MS: i64 = 60_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// What the quote's bound value must equal: holder = the subject key, grant = `passport:<id>`, epoch 0.
pub struct PassportBinding {
    pub holder_pub: String,
    pub grant_ref: String,
    pub epoch: i64,
    pub nonce: String,
}

/// A hardware verifier's answer. `measured` holds `model_id`, `operator`, `weights_digest`, `weights_measured`,
/// `runtime_measurement`, `system_prompt_digest` and `tool_manifest_digest` as the hardware measured them.
pub struct PassportAttestation {
    pub ok: bool,
    pub bound: bool,
    pub measured: Option<Map<String, Value>>,
}

pub type AttestFn<'a> = &'a dyn Fn(&Value, &PassportBinding) -> Result<PassportAttestation, ()>;

#[derive(Clone, Copy)]
pub struct PassportOptions<'a> {
    pub trusted_issuers: &'a [String],
    pub now_ms: i64,
    pub clock_skew_ms: Option<i64>,
    pub max_evidence_age_ms: Option<i64>,
    /// When set, must equal the passport's `sub`.
    pub subject: Option<&'a str>,
    /// PQ public keys pinned per issuer key (required for every non-Ed25519 suite).
    pub pq_pins: Option<&'a HashMap<String, String>>,
    /// An integrator-supplied hardware-attestation verifier. It wins over `default_verifier`.
    pub attest: Option<AttestFn<'a>>,
    /// The crate's own vendor verifier, used for a hardware-rooted passport when `attest` is `None`. Build it with
    /// `attest::verifier_from_config(vendor, config)` and give it the evidence with `with_evidence`; `None` means none.
    pub default_verifier: Option<&'a HardwareVerifier>,
    /// `Some(Ok(true))` = revoked; `None` (no source) or `Err` = `revocation_unavailable`.
    pub revoked: Option<&'a dyn Fn(&str, &str, &str) -> Result<bool, ()>>,
}

fn nonempty(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty())
}

/// `Ok(())` when the passport verifies, else the reason code.
pub fn verify_passport(sp: &Value, o: &PassportOptions) -> Result<(), &'static str> {
    let s = sp.as_object().ok_or("malformed")?;
    let p = s.get("passport").and_then(Value::as_object);
    if s.get("typ").and_then(Value::as_str) != Some("atlas-pca/passport") || p.is_none() {
        return Err("malformed");
    }
    let p = p.unwrap();
    if s.get("ver").and_then(safe_int) != Some(1) {
        return Err("unsupported_version");
    }
    if resolve_sig_alg(s.get("alg")).is_none() {
        return Err("unsupported_suite");
    }
    let (iss, sub, id) = match (s.get("iss").and_then(nonempty), s.get("sub").and_then(nonempty), s.get("sig").and_then(nonempty), p.get("id").and_then(nonempty)) {
        (Some(a), Some(b), Some(_), Some(d)) => (a, b, d),
        _ => return Err("malformed"),
    };
    let hw = p.get("hardware_rooted").and_then(Value::as_bool);
    if p.get("model_id").and_then(nonempty).is_none() || p.get("operator").and_then(nonempty).is_none() || hw.is_none() {
        return Err("malformed");
    }
    let hw = hw.unwrap();
    let (nbf, exp, iat) = (s.get("nbf").and_then(safe_int), s.get("exp").and_then(safe_int), s.get("iat").and_then(safe_int));
    match (nbf, exp, iat) {
        (Some(nbf), Some(exp), Some(_)) if exp > nbf && o.now_ms.unsigned_abs() <= MAX_SAFE as u64 => {}
        _ => return Err("malformed"),
    }
    let (nbf, exp) = (nbf.unwrap(), exp.unwrap());
    if !o.trusted_issuers.iter().any(|t| t == iss) {
        return Err("unknown_issuer");
    }
    let mut body = s.clone();
    body.remove("sig");
    body.remove("pq_sig");
    let canon = canonicalize_strict(&Value::Object(body)).map_err(|_| "malformed")?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(canon.as_bytes());
    let pq = pinned::resolve_pq_key(Some(iss), s.get("pq_pk"), None, o.pq_pins, None);
    if !verify_suite(s.get("alg"), iss, pq.as_ref(), &msg, s.get("sig"), s.get("pq_sig")) {
        return Err("bad_signature");
    }
    let get = |k: &str| p.get(k).cloned().unwrap_or(Value::Null);
    let fp = json!({
        "d": "atlas-pca/passport/v1", "model_id": get("model_id"), "weights_digest": get("weights_digest"),
        "system_prompt_digest": get("system_prompt_digest"), "tool_manifest_digest": get("tool_manifest_digest"),
        "runtime_measurement": get("runtime_measurement"), "operator": get("operator"), "hardware_rooted": hw,
    });
    if hash_canonical_strict(&fp).as_deref() != Some(id) {
        return Err("id_mismatch");
    }
    let skew = o.clock_skew_ms.map_or(0, |k| k.clamp(0, MAX_SKEW_MS));
    if o.now_ms + skew < nbf {
        return Err("not_yet_valid");
    }
    if o.now_ms - skew >= exp {
        return Err("expired");
    }
    if let Some(want) = o.subject {
        if want != sub {
            return Err("subject_mismatch");
        }
    }
    match o.revoked {
        None => return Err("revocation_unavailable"),
        // passport.ts:309-311: a hook that throws is unavailable, never a pass
        Some(f) => match catch_unwind(AssertUnwindSafe(|| f(id, iss, sub))) {
            Ok(Ok(true)) => return Err("revoked"),
            Ok(Ok(false)) => {}
            _ => return Err("revocation_unavailable"),
        },
    }
    if hw {
        let ev = s.get("evidence").and_then(Value::as_object);
        let nonce = ev.and_then(|e| e.get("document")).and_then(Value::as_object).and_then(|d| d.get("nonce")).and_then(nonempty);
        let at = ev.and_then(|e| e.get("at")).and_then(safe_int);
        let (Some(nonce), Some(at)) = (nonce, at) else { return Err("hardware_evidence_missing") };
        let max_age = o.max_evidence_age_ms.unwrap_or(DEFAULT_EVIDENCE_AGE_MS);
        if max_age < 0 || o.now_ms - at > max_age || at - o.now_ms > skew {
            return Err("hardware_evidence_stale");
        }
        if o.attest.is_none() && o.default_verifier.is_none() {
            return Err("hardware_verifier_missing");
        }
        let doc = ev.and_then(|e| e.get("document")).unwrap();
        let binding = PassportBinding { holder_pub: sub.to_string(), grant_ref: format!("passport:{id}"), epoch: 0, nonce: nonce.to_string() };
        // passport.ts:325-328: a verifier that throws fails the attestation
        let answer = match (o.attest, o.default_verifier) {
            (Some(attest), _) => catch_unwind(AssertUnwindSafe(|| attest(doc, &binding))),
            (None, Some(v)) => catch_unwind(AssertUnwindSafe(|| Ok::<_, ()>(run_default(v, &binding, o.now_ms)))),
            (None, None) => return Err("hardware_verifier_missing"),
        };
        match answer {
            Ok(Ok(r)) if r.ok && r.bound => {
                if !identity_matches(p, r.measured.as_ref()) {
                    return Err("hardware_identity_mismatch");
                }
            }
            _ => return Err("hardware_attestation_failed"),
        }
    }
    Ok(())
}

/// Run the crate's default vendor verifier for a passport binding (holder = the subject key, grant = `passport:<id>`, epoch 0).
fn run_default(v: &HardwareVerifier, b: &PassportBinding, now_ms: i64) -> PassportAttestation {
    let bind = Binding { holder_pub: b.holder_pub.clone(), grant_ref: b.grant_ref.clone(), epoch: b.epoch as f64, nonce: b.nonce.clone() };
    let r = v.verify(now_ms, &bind);
    PassportAttestation { ok: r.ok, bound: r.bound == Some(true), measured: r.measured }
}

/// The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
/// measurement when the passport states them; measured weights when it claims them).
fn identity_matches(p: &Map<String, Value>, m: Option<&Map<String, Value>>) -> bool {
    let Some(m) = m else { return false };
    let eq = |k: &str| matches!((p.get(k).and_then(Value::as_str), m.get(k).and_then(Value::as_str)), (Some(a), Some(b)) if a == b);
    if !eq("model_id") || !eq("operator") {
        return false;
    }
    for k in ["weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"] {
        if p.contains_key(k) && !eq(k) {
            return false;
        }
    }
    !(p.get("weights_measured") == Some(&Value::Bool(true)) && m.get("weights_measured") != Some(&Value::Bool(true)))
}

// ---- the rest of the passport module over JSON ------------------------------------------------------------------------------------
//
// The binding match, the registry, the trust score, the evidence binding, signing, a verifier that reports the reference's `detail`, and
// the assurance label, with the reference's JavaScript semantics (an allowlist that is a string is a substring test, `Math.max` coerces its
// operands, a non-finite number is the `{"$num"}` marker of the reference's JSON).

/// The wire version of a signed passport.
pub const PASSPORT_VERSION: u64 = 1;
/// The signing domain of a passport (the NUL is part of it).
pub const PASSPORT_SIG_DOMAIN: &str = "atlas-pca/passport-sig/v1\0";
/// Default ceiling on the age of the hardware quote a passport carries.
pub const DEFAULT_PASSPORT_EVIDENCE_AGE_MS: f64 = 24.0 * 3_600_000.0;

fn marker_number(v: &Value) -> Option<f64> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    match m.get("$num").and_then(Value::as_str)? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

/// `typeof v === 'number'` as a double.
fn js_number(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if v.is_number() {
        v.as_f64()
    } else {
        marker_number(v)
    }
}

/// ECMAScript `ToNumber` of a JSON value (`undefined` is NaN).
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
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
        other => js_number(other).unwrap_or(f64::NAN),
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

/// `String(v)`.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => match marker_number(x) {
            Some(f) => crate::intent_v2::js_number_string(f),
            None => crate::intent_v2::js_value_string(x),
        },
    }
}

/// `a === b` for values of separately parsed documents (objects are never identical; an absent member is `undefined`).
fn strictly_equal(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Null), Some(Value::Null)) => true,
        _ => false,
    }
}

/// `list.includes(x)` where the list is an array (SameValueZero) or a string (a substring test, `x` read as a string).
fn includes(list: &Value, x: Option<&Value>) -> bool {
    match list {
        Value::Array(a) => a.iter().any(|e| strictly_equal(Some(e), x)),
        Value::String(s) => s.contains(js_string(x).as_str()),
        _ => false,
    }
}

/// `list && list.length > 0`: an array or a string that is not empty.
fn non_empty(list: Option<&Value>) -> Option<&Value> {
    list.filter(|l| match l {
        Value::Array(a) => !a.is_empty(),
        Value::String(s) => !s.is_empty(),
        _ => false,
    })
}

/// Does the passport satisfy the grant's `agent_binding`? `{ok, reasons}`: each allowlist (when non-empty) needs the matching digest
/// present AND listed; a pinned operator must equal; `require_hardware` demands a hardware-rooted passport, `require_measured_weights`
/// measured weights; `min_measurement` is an equality pin (string) or a monotone lower bound `{svn: n}` on the integer SVN parsed from
/// `runtime_measurement` (anything else fails closed). `Err` for a `null` passport or binding (the reference throws reading it).
pub fn matches_binding(p: &Value, b: &Value) -> Result<Value, String> {
    if p.is_null() || b.is_null() {
        return Err("Cannot read properties of null".into());
    }
    let mut reasons: Vec<String> = Vec::new();
    let pm = |k: &str| p.get(k);
    if let Some(l) = non_empty(b.get("model_allowlist")) {
        if !includes(l, pm("model_id")) {
            reasons.push(format!("model_id '{}' not in allowlist", js_string(pm("model_id"))));
        }
    }
    for (list, value, label) in [
        ("weights_allowlist", "weights_digest", "weights_digest"),
        ("system_prompt_allowlist", "system_prompt_digest", "system_prompt_digest"),
        ("tool_manifest_allowlist", "tool_manifest_digest", "tool_manifest_digest"),
    ] {
        if let Some(l) = non_empty(b.get(list)) {
            match pm(value) {
                None => reasons.push(format!("{label} required by binding but absent from passport")),
                Some(v) if !includes(l, Some(v)) => reasons.push(format!("{label} '{}' not in allowlist", js_string(Some(v)))),
                Some(_) => {}
            }
        }
    }
    if let Some(op) = b.get("operator") {
        if !strictly_equal(pm("operator"), Some(op)) {
            reasons.push(format!("operator '{}' != required '{}'", js_string(pm("operator")), js_string(Some(op))));
        }
    }
    if truthy(b.get("require_hardware")) && !truthy(pm("hardware_rooted")) {
        reasons.push("binding requires a hardware-rooted attestation".into());
    }
    if truthy(b.get("require_measured_weights")) && !truthy(pm("weights_measured")) {
        reasons.push("binding requires hardware-measured weights".into());
    }
    if let Some(mm) = b.get("min_measurement") {
        if let Value::String(want) = mm {
            if pm("runtime_measurement").and_then(Value::as_str) != Some(want.as_str()) {
                reasons.push("runtime_measurement does not equal the pinned measurement".into());
            }
        } else {
            let bound = mm.as_object().filter(|m| m.len() == 1).and_then(|m| m.get("svn"));
            let bound = bound.and_then(|v| v.as_f64().filter(|f| v.is_number() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0));
            match bound.filter(|f| *f >= 0.0 && !(*f == 0.0 && f.is_sign_negative())) {
                None => reasons.push(
                    "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)".into(),
                ),
                Some(bound) => {
                    let rm = pm("runtime_measurement");
                    let canonical = |s: &str| s == "0" || (s.starts_with(|c: char| ('1'..='9').contains(&c)) && s.bytes().all(|c| c.is_ascii_digit()));
                    let svn = rm.and_then(Value::as_str).filter(|s| canonical(s)).and_then(|s| s.parse::<f64>().ok()).filter(|n| *n <= 9_007_199_254_740_991.0);
                    if svn.is_none_or(|n| n < bound) {
                        reasons.push(format!("runtime SVN {} < required {}", js_string(rm), crate::intent_v2::js_number_string(bound)));
                    }
                }
            }
        }
    }
    Ok(json!({"ok": reasons.is_empty(), "reasons": reasons}))
}

/// A passport registry: `get`, `has` and `all` over passports by id; a later duplicate id replaces the earlier one in place.
pub struct PassportRegistry {
    order: Vec<String>,
    by_id: HashMap<String, Value>,
}

fn id_key(v: Option<&Value>) -> String {
    match v {
        None => "u".into(),
        Some(Value::Null) => "z".into(),
        Some(Value::String(s)) => format!("s{s}"),
        Some(other) => format!("o{}", js_string(Some(other))),
    }
}

/// Build a registry from passports (a passport with no id keys under `undefined`).
pub fn build_passport_registry(passports: &[Value]) -> PassportRegistry {
    let mut r = PassportRegistry { order: Vec::new(), by_id: HashMap::new() };
    for p in passports {
        let k = id_key(p.get("id"));
        if !r.by_id.contains_key(&k) {
            r.order.push(k.clone());
        }
        r.by_id.insert(k, p.clone());
    }
    r
}

impl PassportRegistry {
    pub fn get(&self, id: &str) -> Option<&Value> {
        self.by_id.get(&format!("s{id}"))
    }
    pub fn has(&self, id: &str) -> bool {
        self.by_id.contains_key(&format!("s{id}"))
    }
    pub fn all(&self) -> Vec<Value> {
        self.order.iter().filter_map(|k| self.by_id.get(k).cloned()).collect()
    }
}

/// A coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation): the hardware root
/// dominates, measured provenance and a known operator add confidence. `opts`: `{knownOperators?}`.
pub fn passport_trust_score(p: &Value, opts: &Value) -> f64 {
    let mut s: f64 = 0.0;
    if truthy(p.get("hardware_rooted")) {
        s += 0.4;
    }
    if truthy(p.get("weights_digest")) {
        s += if truthy(p.get("weights_measured")) { 0.2 } else { 0.1 };
    }
    if truthy(p.get("system_prompt_digest")) {
        s += 0.1;
    }
    if truthy(p.get("tool_manifest_digest")) {
        s += 0.1;
    }
    if opts.get("knownOperators").is_some_and(|l| includes(l, p.get("operator"))) {
        s += 0.2;
    }
    s.clamp(0.0, 1.0)
}

/// The binding a hardware quote must carry for a passport: holder = the subject key, grant = `passport:<id>`, epoch 0, the evidence nonce.
pub fn passport_evidence_binding(passport_id: &str, subject: &str, nonce: &str) -> Value {
    json!({"holderPub": subject, "grantRef": format!("passport:{passport_id}"), "epoch": 0, "nonce": nonce})
}

fn is_safe_integer(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    v.as_f64().filter(|f| v.is_number() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0)
}

fn passport_message(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = PASSPORT_SIG_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

/// Sign a passport as `issuer` over `o` = `{subject, iat?, nbf?, exp, evidence?}` under `suite`. Throws (a signer never emits a weaker or
/// inconsistent artifact): an id that is not the fingerprint of the identity, `hardware_rooted` without evidence, a bad window, an unknown
/// suite.
pub fn sign_passport_value(passport: &Value, o: &Value, issuer: &crate::agent::KeyPair, suite: &crate::agent::Suite) -> Result<Value, String> {
    let fingerprint = crate::agent::passport_fingerprint(passport)?;
    if passport.get("id").and_then(Value::as_str) != Some(fingerprint.as_str()) {
        return Err("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)".into());
    }
    let evidence = o.get("evidence").filter(|e| truthy(Some(e)));
    if truthy(passport.get("hardware_rooted")) && evidence.is_none() {
        return Err("signPassport: hardware_rooted requires attestation evidence (fail closed)".into());
    }
    if let Some(at) = evidence.and_then(|e| e.get("at")) {
        if is_safe_integer(Some(at)).is_none() {
            return Err("signPassport: evidence.at must be a safe integer".into());
        }
    }
    let alg = suite.alg.map(|a| json!(a));
    if crate::intent_suite::suite_of(alg.as_ref()).is_err() {
        return Err(format!("signPassport: unknown signature alg '{}'", suite.alg.unwrap_or("undefined")));
    }
    let iat = o.get("iat").filter(|v| !v.is_null()).or_else(|| passport.get("issued_at"));
    let nbf = o.get("nbf").filter(|v| !v.is_null()).or(iat);
    let exp = o.get("exp");
    let evidence = evidence.map(|e| {
        let mut m = e.as_object().cloned().unwrap_or_default();
        if m.get("at").is_none_or(Value::is_null) {
            m.insert("at".into(), iat.cloned().unwrap_or(Value::Null));
        }
        Value::Object(m)
    });
    let ints = [iat, nbf, exp].map(is_safe_integer);
    let (Some(_), Some(nbf_n), Some(exp_n)) = (ints[0], ints[1], ints[2]) else {
        return Err("signPassport: iat/nbf/exp must be safe integers with exp > nbf".into());
    };
    if exp_n <= nbf_n {
        return Err("signPassport: iat/nbf/exp must be safe integers with exp > nbf".into());
    }
    let mut body = Map::new();
    body.insert("typ".into(), json!("atlas-pca/passport"));
    body.insert("ver".into(), json!(PASSPORT_VERSION));
    body.insert("passport".into(), passport.clone());
    body.insert("iss".into(), json!(issuer.public));
    if let Some(sub) = o.get("subject") {
        body.insert("sub".into(), sub.clone());
    }
    body.insert("iat".into(), iat.cloned().unwrap_or(Value::Null));
    body.insert("nbf".into(), nbf.cloned().unwrap_or(Value::Null));
    body.insert("exp".into(), exp.cloned().unwrap_or(Value::Null));
    if let Some(e) = evidence {
        body.insert("evidence".into(), e);
    }
    crate::agent::sign_artifact(PASSPORT_SIG_DOMAIN, &Value::Object(body), issuer, suite)
}

/// The revocation source: `{id, iss, sub}` in, whether the passport is revoked out; an `Err` is a throw (the passport is then refused).
pub type RevocationFn = dyn Fn(&Value) -> Result<bool, String> + Send + Sync;

fn denial(reason: &str, detail: Option<String>) -> Value {
    let mut o = json!({"ok": false, "reason": reason});
    if let Some(d) = detail.filter(|d| !d.is_empty()) {
        o["detail"] = json!(d);
    }
    o
}

/// Verify a signed passport. Total, fail closed with a distinct reason: `{ok: true, passport, iss, sub, exp, hardware_verified}` or `{ok:
/// false, reason, detail?}`. `o`: `{trustedIssuers, now, clockSkewMs?, subject?, maxEvidenceAgeMs?, pqPins?}` (a post-quantum or hybrid
/// passport verifies only under the key pinned for its issuer; the reference's unbound opt-out is not offered). Order: shape, suite,
/// issuer, signature, id, validity window, subject, revocation (a missing or failing source is `revocation_unavailable`), then, for a
/// hardware-rooted passport, the evidence (present, fresh, verified and bound by `attestation_verifier`, and measuring the claimed
/// identity).
pub fn verify_passport_value(
    sp: &Value,
    o: &Value,
    revocation: Option<&RevocationFn>,
    attestation_verifier: Option<&crate::attestation::HardwareVerifierFn>,
) -> Value {
    match verify_passport_inner(sp, o, revocation, attestation_verifier) {
        Ok(v) => v,
        Err(e) => denial("malformed", Some(e)),
    }
}

fn verify_passport_inner(
    sp: &Value,
    o: &Value,
    revocation: Option<&RevocationFn>,
    attestation_verifier: Option<&crate::attestation::HardwareVerifierFn>,
) -> Result<Value, String> {
    let bad = |reason: &str| Ok(denial(reason, None));
    let s = sp;
    if s.get("typ").and_then(Value::as_str) != Some("atlas-pca/passport") || s.get("passport").is_none_or(Value::is_null) {
        return bad("malformed");
    }
    if s.get("ver").and_then(Value::as_f64) != Some(1.0) {
        return Ok(denial("unsupported_version", Some(js_string(s.get("ver")))));
    }
    if let Some(alg) = s.get("alg") {
        if !alg.as_str().is_some_and(crate::pq::is_known_sig_alg) {
            return Ok(denial("unsupported_suite", Some(js_string(Some(alg)))));
        }
    }
    let p = &s["passport"];
    let is_str = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|x| !x.is_empty());
    if !is_str(s.get("iss"))
        || !is_str(s.get("sub"))
        || !is_str(s.get("sig"))
        || !is_str(p.get("id"))
        || !is_str(p.get("model_id"))
        || !is_str(p.get("operator"))
        || !p.get("hardware_rooted").is_some_and(Value::is_boolean)
    {
        return bad("malformed");
    }
    let (iss, sub) = (s["iss"].as_str().unwrap_or(""), s["sub"].as_str().unwrap_or(""));
    let times = [s.get("iat"), s.get("nbf"), s.get("exp"), o.get("now")].map(is_safe_integer);
    let (Some(nbf), Some(exp), Some(now)) = (times[1], times[2], times[3]) else { return Ok(denial("malformed", Some("times".into()))) };
    if times[0].is_none() || exp <= nbf {
        return Ok(denial("malformed", Some("times".into())));
    }
    let trusted = o.get("trustedIssuers").and_then(Value::as_array);
    if !trusted.is_some_and(|t| t.iter().any(|k| k.as_str() == Some(iss))) {
        return bad("unknown_issuer");
    }
    let mut body = s.as_object().cloned().unwrap_or_default();
    body.remove("sig");
    body.remove("pq_sig");
    let msg = passport_message(&Value::Object(body))?;
    let pin = o.get("pqPins").and_then(|p| p.get(iss)).filter(|p| p.is_string()).map(|p| (iss, p));
    if !crate::intent_suite::verify_pinned_suite(s.get("alg"), iss, s.get("pq_pk"), &msg, s.get("sig"), s.get("pq_sig"), pin).unwrap_or(false) {
        return bad("bad_signature");
    }
    if p.get("id").and_then(Value::as_str) != Some(crate::agent::passport_fingerprint(p)?.as_str()) {
        return bad("id_mismatch");
    }
    // `Math.min(Math.max(o.clockSkewMs ?? 0, 0), 60000)`: a NaN skew falls back to none
    let skew_in = match o.get("clockSkewMs").filter(|v| !v.is_null()) {
        None => 0.0,
        Some(v) => to_number(Some(v)),
    };
    let skew = if skew_in.is_nan() { 0.0 } else { skew_in.clamp(0.0, MAX_SKEW_MS as f64) };
    if now + skew < nbf {
        return bad("not_yet_valid");
    }
    if now - skew >= exp {
        return bad("expired");
    }
    if let Some(want) = o.get("subject") {
        if !strictly_equal(Some(want), s.get("sub")) {
            return bad("subject_mismatch");
        }
    }
    let Some(revocation) = revocation else { return Ok(denial("revocation_unavailable", Some("no revocation source".into()))) };
    let revoked = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| revocation(&json!({"id": p["id"], "iss": iss, "sub": sub})))) {
        Ok(Ok(r)) => r,
        _ => return bad("revocation_unavailable"),
    };
    if revoked {
        return bad("revoked");
    }
    let hardware_rooted = p.get("hardware_rooted") == Some(&json!(true));
    if hardware_rooted {
        let ev = s.get("evidence");
        let doc = ev.and_then(|e| e.get("document"));
        let Some(nonce) = doc.and_then(|d| d.get("nonce")).and_then(Value::as_str).filter(|n| !n.is_empty()) else { return bad("hardware_evidence_missing") };
        let Some(at) = is_safe_integer(ev.and_then(|e| e.get("at"))) else { return Ok(denial("hardware_evidence_missing", Some("evidence.at".into()))) };
        let max_age = match o.get("maxEvidenceAgeMs").filter(|v| !v.is_null()) {
            None => DEFAULT_PASSPORT_EVIDENCE_AGE_MS,
            Some(v) => js_number(Some(v)).filter(|f| f.is_finite()).unwrap_or(f64::NAN),
        };
        if max_age.is_nan() || max_age < 0.0 || now - at > max_age || at - now > skew {
            return bad("hardware_evidence_stale");
        }
        let Some(verifier) = attestation_verifier else { return bad("hardware_verifier_missing") };
        let mut expected = passport_evidence_binding(p["id"].as_str().unwrap_or(""), sub, nonce);
        expected["nonceIssuedAt"] = o["now"].clone();
        let call = json!({"document": doc, "ctx": {}, "nowMs": o["now"], "expected": expected});
        let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verifier(&call))) {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Ok(denial("hardware_attestation_failed", Some(if e.is_empty() { "error".to_string() } else { e }))),
            Err(_) => return Ok(denial("hardware_attestation_failed", Some("error".into()))),
        };
        if r.get("ok") != Some(&json!(true)) || r.get("bound") != Some(&json!(true)) {
            let detail = r.get("reason").filter(|d| truthy(Some(d))).map(|d| js_string(Some(d)));
            return Ok(denial("hardware_attestation_failed", detail));
        }
        let m = r.get("measured").filter(|m| truthy(Some(m)));
        let differs = |k: &str| p.get(k).is_some() && !strictly_equal(m.and_then(|m| m.get(k)), p.get(k));
        let mismatch = m.is_none()
            || !strictly_equal(m.and_then(|m| m.get("model_id")), p.get("model_id"))
            || !strictly_equal(m.and_then(|m| m.get("operator")), p.get("operator"))
            || differs("weights_digest")
            || differs("runtime_measurement")
            || differs("system_prompt_digest")
            || differs("tool_manifest_digest")
            || (p.get("weights_measured") == Some(&json!(true)) && m.and_then(|m| m.get("weights_measured")) != Some(&json!(true)));
        if mismatch {
            return bad("hardware_identity_mismatch");
        }
    }
    Ok(json!({"ok": true, "passport": p, "iss": iss, "sub": sub, "exp": s["exp"], "hardware_verified": hardware_rooted}))
}

/// The assurance label of a verified passport: `{level: "software"}` unless the evidence verified through a hardware verifier, then that
/// verifier's `label` (`{level, vendor?}`; none: level `unknown`).
pub fn passport_assurance_value(verdict: &Value, label: Option<&Value>) -> Value {
    if !truthy(verdict.get("hardware_verified")) {
        return json!({"level": "software"});
    }
    let level = label.and_then(|l| l.get("level")).filter(|l| !l.is_null()).cloned().unwrap_or_else(|| json!("unknown"));
    let mut out = json!({"level": level});
    if let Some(v) = label.and_then(|l| l.get("vendor")).filter(|v| truthy(Some(v))) {
        out["vendor"] = v.clone();
    }
    out
}
