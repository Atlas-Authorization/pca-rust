//! The safety certificate (port of `safety-certificate.ts`): a signed, machine-readable statement of the risk-budget bound of a
//! grant. From the risk policy `{bMax, kappa}` it derives the bound `bMax / kappa` (0 when kappa <= 0), a human statement and
//! optional check rows, signed by the guardian (Ed25519, a post-quantum suite or a hybrid). Verification recomputes the bound from
//! the certificate's own parameters and refuses any mismatch.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`; the verifier is total.
use serde_json::{json, Map, Value};

use crate::agent::{KeyPair, Suite};

pub const SAFETY_CERT_DOMAIN: &str = "atlas-pca/safety-cert/v1\0";
pub const SAFETY_CERT_VERSION: u64 = 1;
pub const SAFETY_CERT_SCOPE: &str = "risk-budget-bound";
pub const MAX_SAFETY_CHECKS: usize = 64;
const MAX_CHECK_ID: usize = 64;
const MAX_EVIDENCE_URL: usize = 2048;

fn finite(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The problem of a list of check rows `{id, status, evidence: {kind, ref}, at}` (`None` = well formed): at most 64 rows, distinct
/// ids of 1..64 characters, a status of `passed` / `failed` / `not_run`, a natural time, and evidence that is a sha256 digest (64
/// lowercase hex) or a plain https URL without credentials.
pub fn validate_safety_checks(checks: &Value) -> Option<String> {
    let Some(list) = checks.as_array() else {
        return Some("checks must be an array".into());
    };
    if list.len() > MAX_SAFETY_CHECKS {
        return Some(format!("more than {MAX_SAFETY_CHECKS} checks"));
    }
    let mut seen: Vec<&str> = Vec::new();
    for c in list {
        if !(c.is_object() || c.is_array()) {
            return Some("check is not an object".into());
        }
        let Some(id) = c.get("id").and_then(Value::as_str).filter(|id| (1..=MAX_CHECK_ID).contains(&units(id))) else {
            return Some("check id must be a 1..64 char string".into());
        };
        if seen.contains(&id) {
            return Some(format!("duplicate check id '{id}'"));
        }
        seen.push(id);
        if !matches!(c.get("status").and_then(Value::as_str), Some("passed" | "failed" | "not_run")) {
            return Some(format!("check '{id}' has an invalid status"));
        }
        if !finite(c.get("at")).is_some_and(|t| t.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&t) && !t.is_sign_negative()) {
            return Some(format!("check '{id}' has an invalid time"));
        }
        let evidence = c.get("evidence").filter(|e| e.is_object() || e.is_array());
        let Some(reference) = evidence.and_then(|e| e.get("ref")).and_then(Value::as_str) else {
            return Some(format!("check '{id}' has no evidence link"));
        };
        match evidence.and_then(|e| e.get("kind")).and_then(Value::as_str) {
            Some("sha256") => {
                if !(reference.len() == 64 && reference.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
                    return Some(format!("check '{id}' evidence digest is not 64 lowercase hex"));
                }
            }
            Some("url") => {
                let plain =
                    url::Url::parse(reference).is_ok_and(|u| u.scheme() == "https" && u.username().is_empty() && !u.password().is_some_and(|p| !p.is_empty()));
                if units(reference) > MAX_EVIDENCE_URL || !plain {
                    return Some(format!("check '{id}' evidence URL must be a plain https URL"));
                }
            }
            _ => return Some(format!("check '{id}' has an invalid evidence kind")),
        }
    }
    None
}

/// The bound a risk policy implies between two human co-signs: `bMax / kappa`, 0 when kappa is not positive.
pub fn safety_certificate_bound(b_max: f64, kappa: f64) -> f64 {
    crate::risk::safety_bound(b_max, kappa)
}

/// The human statement a certificate carries for `bound`.
pub fn safety_certificate_statement(bound: f64) -> String {
    format!(
        "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ {} (= B_max / κ). This is not a claim that the agent or the system is safe.",
        crate::intent_v2::js_number_string(bound)
    )
}

/// The signed message of a certificate (or of its claim): the domain prefix, then the canonical claim without `sig` / `pq_sig`.
pub fn safety_certificate_message(c: &Value) -> Vec<u8> {
    let mut claim = c.as_object().cloned().unwrap_or_default();
    claim.remove("sig");
    claim.remove("pq_sig");
    let mut m = SAFETY_CERT_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize(&Value::Object(claim)).as_bytes());
    m
}

fn bound_of(params: &Value) -> f64 {
    safety_certificate_bound(finite(params.get("bMax")).unwrap_or(f64::NAN), finite(params.get("kappa")).unwrap_or(f64::NAN))
}

/// A member that is given: present and not `null`.
fn given<'a>(args: &'a Value, k: &str) -> Option<&'a Value> {
    args.get(k).filter(|v| !v.is_null())
}

/// Issue a certificate for `args.policy` (a risk policy), signed by `guardian` under `suite`. `args` may carry `grantRef`,
/// `instance`, `checks` and `issuedAt` (epoch ms; the system clock when absent). `Err` on a malformed policy or checks, or a suite
/// this build cannot sign.
pub fn issue_safety_certificate(args: &Value, guardian: &KeyPair, suite: &Suite) -> Result<Value, String> {
    let policy = args.get("policy").unwrap_or(&Value::Null);
    if let Some(bad) = crate::risk::validate_risk_policy(policy) {
        return Err(format!("issueSafetyCertificate: {bad}"));
    }
    if let Some(bad) = given(args, "checks").and_then(validate_safety_checks) {
        return Err(format!("issueSafetyCertificate: {bad}"));
    }
    let bound = crate::prohibitions::num_value(bound_of(policy));
    let mut claim = Map::new();
    claim.insert("v".into(), json!(SAFETY_CERT_VERSION));
    claim.insert("statement".into(), json!(safety_certificate_statement(bound_of(policy))));
    claim.insert("scope".into(), json!(SAFETY_CERT_SCOPE));
    if let Some(checks) = given(args, "checks").and_then(Value::as_array) {
        let rows: Vec<Value> = checks
            .iter()
            .map(|c| json!({"id": c["id"], "status": c["status"], "evidence": {"kind": c["evidence"]["kind"], "ref": c["evidence"]["ref"]}, "at": c["at"]}))
            .collect();
        claim.insert("checks".into(), Value::Array(rows));
    }
    let mut params = Map::new();
    for k in ["bMax", "kappa", "theta1", "theta2", "lambda", "rho", "weights"] {
        params.insert(k.into(), policy[k].clone());
    }
    claim.insert("params".into(), Value::Object(params));
    claim.insert("bound".into(), bound.clone());
    claim.insert("blastRadiusPerCheckpoint".into(), bound);
    for (member, k) in [("grant_ref", "grantRef"), ("instance", "instance")] {
        if let Some(v) = given(args, k) {
            claim.insert(member.into(), v.clone());
        }
    }
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_millis() as f64)
    };
    claim.insert(
        "issued_at".into(),
        given(args, "issuedAt").cloned().unwrap_or_else(|| crate::prohibitions::num_value(now())),
    );
    claim.insert("guardian".into(), json!(guardian.public));
    if suite.alg.unwrap_or("ed25519") != "ed25519" {
        claim.insert("alg".into(), json!(suite.alg.unwrap_or("ed25519")));
        claim.insert(
            "pq_pk".into(),
            json!(suite.pq.ok_or("issueSafetyCertificate: a post-quantum suite needs a key pair")?.public),
        );
    }
    let (sig, pq_sig) = crate::agent::sign_with_suite(suite, Some(guardian), &safety_certificate_message(&Value::Object(claim.clone())))
        .map_err(|e| format!("issueSafetyCertificate: {e}"))?;
    claim.insert("sig".into(), json!(sig));
    if let Some(p) = pq_sig {
        claim.insert("pq_sig".into(), json!(p));
    }
    Ok(Value::Object(claim))
}

/// What a verifier pins and requires of a certificate.
#[derive(Debug, Clone, Default)]
pub struct SafetyCertificateOptions {
    /// The guardian key the certificate must be signed by.
    pub guardian: Option<String>,
    /// Check ids that must be present with status `passed`.
    pub require_checks: Vec<String>,
    /// Maximum age (ms); with it the certificate must not be issued in the future.
    pub max_age_ms: Option<f64>,
    /// The time to judge the age at (epoch ms); the system clock when absent.
    pub now: Option<f64>,
    /// Post-quantum keys pinned by guardian identity: `{identity: pq public key}`.
    pub pq_pins: Option<Value>,
}

fn signature_holds(cert: &Value, guardian: &str, opts: &SafetyCertificateOptions) -> bool {
    let Some(suite) = crate::resolve_sig_alg(cert.get("alg")) else { return false };
    let (alg, msg) = (json!(suite.alg), safety_certificate_message(cert));
    if !suite.needs_pq_pk {
        return crate::verify_suite(Some(&alg), guardian, None, &msg, cert.get("sig"), cert.get("pq_sig"));
    }
    let Some(artifact) = cert.get("pq_pk").and_then(Value::as_str) else {
        return false;
    };
    // only the identity's own pin vouches for a post-quantum key: the certificate's own `pq_pk` is never accepted without one (the
    // reference keeps a legacy insecure opt-out for this; it is deliberately not ported)
    let vouched = opts.pq_pins.as_ref().and_then(Value::as_object).and_then(|p| p.get(guardian)).is_some_and(|pin| pin.as_str() == Some(artifact));
    let key = if vouched { crate::pinned::PinnedPq::caller_vouched(artifact) } else { None };
    key.is_some() && crate::verify_suite(Some(&alg), guardian, key.as_ref(), &msg, cert.get("sig"), cert.get("pq_sig"))
}

/// Verify a certificate. Total: `{ok: true, recomputedBound}` or `{ok: false, reason, recomputedBound?}`. Checks the shape, the
/// check rows, the parameters, that the stated bound and blast radius equal `bMax / kappa` recomputed from the certificate's own
/// parameters, the guardian pin, the signature (a post-quantum key only under a pin), the age and the required checks.
pub fn verify_safety_certificate(cert: &Value, opts: &SafetyCertificateOptions) -> Value {
    let fail = |reason: String, bound: Option<f64>| {
        let mut o = json!({"ok": false, "reason": reason});
        if let Some(b) = bound {
            o["recomputedBound"] = crate::prohibitions::num_value(b);
        }
        o
    };
    if finite(cert.get("v")) != Some(SAFETY_CERT_VERSION as f64) {
        return fail("malformed certificate".into(), None);
    }
    let (Some(_), Some(guardian)) = (cert.get("sig").and_then(Value::as_str), cert.get("guardian").and_then(Value::as_str)) else {
        return fail("missing guardian/signature".into(), None);
    };
    if cert.get("scope").and_then(Value::as_str) != Some(SAFETY_CERT_SCOPE) {
        return fail("unknown scope".into(), None);
    }
    if let Some(bad) = cert.get("checks").and_then(validate_safety_checks) {
        return fail(format!("invalid checks: {bad}"), None);
    }
    let params = cert.get("params").filter(|p| p.is_object()).cloned().unwrap_or_else(|| json!({}));
    if let Some(bad) = crate::risk::validate_risk_policy(&params) {
        return fail(format!("invalid parameters: {bad}"), None);
    }
    let recomputed = bound_of(&params);
    let some = Some(recomputed);
    if finite(cert.get("bound")) != some {
        return fail("stated bound does not equal B_max/κ recomputed from the parameters".into(), some);
    }
    if cert.get("blastRadiusPerCheckpoint").filter(|b| b.is_number()).and_then(Value::as_f64) != some {
        return fail("blastRadiusPerCheckpoint does not equal the recomputed bound".into(), some);
    }
    if opts.guardian.as_deref().is_some_and(|g| g != guardian) {
        return fail("guardian key is not the pinned key".into(), some);
    }
    if crate::resolve_sig_alg(cert.get("alg")).is_none() {
        return fail("unknown signature alg".into(), some);
    }
    if !signature_holds(cert, guardian, opts) {
        return fail("guardian signature does not verify".into(), some);
    }
    if let Some(max_age) = opts.max_age_ms {
        let now = opts.now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(f64::NAN, |d| d.as_millis() as f64)
        });
        let Some(issued) = finite(cert.get("issued_at")).filter(|_| max_age.is_finite() && now.is_finite()) else {
            return fail("invalid age policy or issue time".into(), some);
        };
        if !(issued <= now) {
            return fail("certificate is issued in the future".into(), some);
        }
        if !(now - issued <= max_age && (now - issued).is_finite()) {
            return fail("certificate is older than maxAgeMs".into(), some);
        }
    }
    for id in &opts.require_checks {
        let row = cert
            .get("checks")
            .and_then(Value::as_array)
            .and_then(|l| l.iter().find(|k| k["id"].as_str() == Some(id)));
        match row.map(|c| c["status"].as_str().unwrap_or("")) {
            None => return fail(format!("required check '{id}' is not present"), some),
            Some("passed") => {}
            Some(status) => return fail(format!("required check '{id}' is {status}"), some),
        }
    }
    json!({"ok": true, "recomputedBound": crate::prohibitions::num_value(recomputed)})
}

/// The wire form of a certificate: canonical JSON.
pub fn encode_safety_certificate(cert: &Value) -> String {
    crate::canonicalize(cert)
}

/// Parse a certificate from its wire form: `None` for text over the JSON size limit, text that is not JSON, or a value without the
/// certificate's version, signature, guardian and parameters. The result is NOT verified.
pub fn decode_safety_certificate(text: &str) -> Option<Value> {
    if text.len() > crate::consts::MAX_JSON_BYTES {
        return None;
    }
    let v: Value = serde_json::from_str(text).ok()?;
    let shaped = v.is_object()
        && finite(v.get("v")) == Some(SAFETY_CERT_VERSION as f64)
        && v.get("sig").is_some_and(Value::is_string)
        && v.get("guardian").is_some_and(Value::is_string)
        && v.get("params").is_some_and(|p| p.is_object() || p.is_array());
    shaped.then_some(v)
}

/// The compliance evidence row of a VERIFIED certificate (`None` when it does not verify): `{control, guardian, issued_at, bound,
/// checks: [{id, status, evidence}]}`, a digest evidence written `sha256:<hex>`.
pub fn safety_certificate_for_compliance(cert: &Value, opts: &SafetyCertificateOptions) -> Option<Value> {
    if verify_safety_certificate(cert, opts)["ok"] != true {
        return None;
    }
    let checks: Vec<Value> = cert
        .get("checks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| {
            let reference = c["evidence"]["ref"].as_str().unwrap_or("");
            let evidence = if c["evidence"]["kind"] == "sha256" {
                format!("sha256:{reference}")
            } else {
                reference.to_string()
            };
            json!({"id": c["id"], "status": c["status"], "evidence": evidence})
        })
        .collect();
    Some(json!({"control": SAFETY_CERT_SCOPE, "guardian": cert["guardian"], "issued_at": cert["issued_at"], "bound": cert["bound"], "checks": checks}))
}
