//! The post-quantum software / HSM attestation root (port of `attest-pq-software.ts`): a statement over the measured workload, bound to
//! holder, grant, epoch and nonce, signed by an HSM-held root under a post-quantum or hybrid suite (ML-DSA, SLH-DSA, optionally with
//! Ed25519), and its verifier, which plugs into the same seam as the hardware roots (and the multi-root policy of
//! [`crate::attestation`]).
//!
//! SOFTWARE, NOT SILICON: the measurements are software-measured by the harness and then signed, so the identity a verified statement
//! yields has `weights_measured: false`: it can satisfy a plain weights allowlist but never `require_measured_weights`.
//!
//! JSON-valued (`&Value` in, the reference's member names out); a reference throw is an `Err`. The PQ key of a statement verifies only
//! when it is in the verifier's configured trusted set, and the suite's own downgrade rules apply: `alg`, `pq_pk` and `attestor_ed25519`
//! are signed into the statement, a hybrid needs BOTH halves to verify.
use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::agent::{sign_with_suite, KeyPair, PqKeyPair, Suite};
use crate::attestation::{attestation_binding, attestation_binding_b64u, HardwareVerifierFn};

/// Domain separator of the signed statement body.
pub const PQ_ATTEST_DOMAIN: &str = "atlas-pca/attest-pq/v1\0";

/// The family of the PQ key a suite signs with, and whether the suite carries Ed25519 (hybrid or classical): `None` for a suite without a
/// post-quantum component this root accepts (ed25519, FN-DSA, LESS).
fn suite_parts(alg: Option<&str>) -> Result<(&'static str, Option<&'static str>, bool), String> {
    let suite = crate::resolve_sig_alg(alg.map(|a| json!(a)).as_ref())
        .ok_or_else(|| format!("unknown signature alg '{}'", alg.unwrap_or("undefined")))?;
    let family = match suite.pq {
        Some(crate::Pq::MlDsa65) => Some("ML-DSA-65"),
        Some(crate::Pq::MlDsa87) => Some("ML-DSA-87"),
        Some(crate::Pq::Slh128f) => Some("SLH-DSA-SHA2-128f"),
        Some(crate::Pq::Slh256s) => Some("SLH-DSA-SHA2-256s"),
        _ => None,
    };
    Ok((suite.alg, family, suite.pq.is_none() || suite.needs_pq_sig))
}

fn statement_message(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = PQ_ATTEST_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

/// A PQ-software attestor over a PROVIDED HSM-held key (never generated here).
pub struct PqSoftwareAttestor {
    /// The HSM root's PQ public key (base64url) the verifier must trust.
    pub pq_public_key: String,
    /// The HSM root's Ed25519 public key (base64url), for the hybrid suites.
    pub ed25519_public_key: Option<String>,
    alg: &'static str,
    pq: PqKeyPair,
    ed: Option<KeyPair>,
}

/// Build an attestor. The suite MUST carry a post-quantum component (a classical-only suite is refused: this is the post-quantum root),
/// `pq` must be the key pair of the suite's family, and a hybrid suite also needs `ed`. `Err` otherwise.
pub fn create_pq_software_attestor(alg: Option<&str>, pq: Option<PqKeyPair>, ed: Option<KeyPair>) -> Result<PqSoftwareAttestor, String> {
    let (name, family, has_ed) = suite_parts(alg).map_err(|e| format!("createPqSoftwareAttestor: {e}"))?;
    let Some(family) = family else {
        return Err(format!("createPqSoftwareAttestor: '{name}' is classical; the PQ root requires a post-quantum suite"));
    };
    let pq = pq
        .filter(|p| p.family() == family)
        .ok_or_else(|| format!("createPqSoftwareAttestor: '{name}' requires the matching PQ key material"))?;
    if has_ed && ed.is_none() {
        return Err(format!("createPqSoftwareAttestor: hybrid suite '{name}' requires edSecret"));
    }
    Ok(PqSoftwareAttestor {
        pq_public_key: pq.public.clone(),
        ed25519_public_key: ed.as_ref().map(|k| k.public.clone()),
        alg: name,
        pq,
        ed,
    })
}

impl PqSoftwareAttestor {
    /// Mint a signed statement over `claims` (`measurement`, `holder_pub`, `grant_ref`, `epoch`, `nonce`; optional `weights_digest`,
    /// `system_prompt_digest`, `tool_manifest_digest`, `model_id`, `operator`). `Err` for claims that are not a valid binding or have no
    /// canonical form.
    pub fn attest(&self, claims: &Value) -> Result<Value, String> {
        let get = |k: &str| claims.as_object().and_then(|o| o.get(k));
        let mut expected = Map::new();
        for (to, from) in [("holderPub", "holder_pub"), ("grantRef", "grant_ref"), ("epoch", "epoch"), ("nonce", "nonce")] {
            if let Some(v) = get(from) {
                expected.insert(to.into(), v.clone());
            }
        }
        let binding = attestation_binding_b64u(&Value::Object(expected))?;
        let mut body = Map::new();
        body.insert("measurement".into(), get("measurement").ok_or("canonicalize: unsupported type undefined")?.clone());
        body.insert("binding".into(), json!(binding));
        body.insert("alg".into(), json!(self.alg));
        body.insert("pq_pk".into(), json!(self.pq_public_key));
        if let Some(e) = &self.ed25519_public_key {
            body.insert("attestor_ed25519".into(), json!(e));
        }
        for k in ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator"] {
            if let Some(v) = get(k) {
                body.insert(k.into(), v.clone());
            }
        }
        let body = Value::Object(body);
        let (sig, pq_sig) =
            sign_with_suite(&Suite { alg: Some(self.alg), pq: Some(&self.pq) }, self.ed.as_ref(), &statement_message(&body)?)?;
        let mut out = body;
        out["sig"] = json!(sig);
        if let Some(p) = pq_sig {
            out["pq_sig"] = json!(p);
        }
        Ok(out)
    }
}

/// The evidence seam: the attestation document and verifier context in, the signed statement (or `None`) out. `Err` is a throw.
pub type PqEvidenceFn = dyn Fn(&Value, &Value) -> Result<Option<Value>, String> + Send + Sync;

fn is_str_in(set: &[Value], v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| set.iter().any(|e| e.as_str() == Some(s)))
}

/// Build the verifier. `config` is `{trustedPqPublicKeys, trustedEd25519PublicKeys?, requirePq?, requireHybrid?, allowedSuites?,
/// policy: {measurements, weightsMeasurements?}}`; `resolve_evidence` is the seam (without it every verification fails closed). `Err` at
/// construction for an empty measurement allowlist (no accept-all) or no trusted PQ key.
///
/// A verification: the statement is resolved; the suite is known and satisfies `requirePq` (default true: a classical-only statement is
/// denied) / `requireHybrid` / `allowedSuites` (checked before the signature); its attestor keys are in the configured trusted sets; the
/// signature verifies over the canonical body; its binding equals `attestationBinding(expected)`; the measurement (and weights digest,
/// when that list is non-empty) is in the policy. The verdict is `{ok, bound, measured, hostAsserted: {suite}}` or `{ok: false, reason}`.
pub fn create_pq_software_verifier(config: &Value, resolve_evidence: Option<Arc<PqEvidenceFn>>) -> Result<Arc<HardwareVerifierFn>, String> {
    let policy = config.get("policy");
    let measurements: Vec<Value> = match policy.and_then(|p| p.get("measurements")).and_then(Value::as_array) {
        Some(m) if !m.is_empty() => m.clone(),
        _ => return Err("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)".into()),
    };
    let weights: Option<Vec<Value>> = policy.and_then(|p| p.get("weightsMeasurements")).and_then(Value::as_array).cloned();
    let trusted_pq: Vec<Value> = config.get("trustedPqPublicKeys").and_then(Value::as_array).cloned().unwrap_or_default();
    if trusted_pq.is_empty() {
        return Err("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)".into());
    }
    let trusted_ed: Vec<Value> = config.get("trustedEd25519PublicKeys").and_then(Value::as_array).cloned().unwrap_or_default();
    let require_pq = config.get("requirePq") != Some(&json!(false));
    let require_hybrid = config.get("requireHybrid") == Some(&json!(true));
    // absent: no policy; any present value is a policy: [] refuses everything, a non-array fails closed (an empty set)
    let allowed: Option<HashSet<String>> = config
        .get("allowedSuites")
        .map(|a| a.as_array().map(|l| l.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default());
    Ok(Arc::new(move |input: &Value| {
        let fail = |reason: String| Ok(json!({"ok": false, "reason": reason}));
        let error =
            |e: String| fail(format!("pq-software verification error (fail closed): {}", if e.is_empty() { "unknown" } else { &e }));
        let Some(resolve) = &resolve_evidence else { return fail("no PQ-software evidence resolver configured (fail closed)".into()) };
        let st = match resolve(input.get("document").unwrap_or(&Value::Null), input.get("ctx").unwrap_or(&Value::Null)) {
            Ok(s) => s,
            Err(e) => return error(e),
        };
        let Some(st) = st.filter(|s| (s.is_object() || s.is_array()) && s.get("alg").is_some_and(Value::is_string)) else {
            return fail("no PQ-software attestation statement for this action".into());
        };
        let alg = st["alg"].as_str().unwrap_or("");
        // (1) suite and the PQ requirement
        let Ok((name, family, has_ed)) = suite_parts(Some(alg)) else {
            return fail(format!("PQ statement declares an unknown signature alg '{alg}'"));
        };
        if require_pq && family.is_none() {
            return fail(format!("PQ required: a classical-only suite '{name}' is not accepted by the post-quantum root"));
        }
        if require_hybrid && !(has_ed && family.is_some()) {
            return fail(format!("hybrid required: suite '{name}' is not a classical+PQ hybrid"));
        }
        if allowed.as_ref().is_some_and(|a| !a.contains(name)) {
            return fail(format!("suite '{name}' is not in the allowed-suites list"));
        }
        // (2) trusted attestor keys
        let needs_pq_pk = family.is_some();
        if needs_pq_pk && !is_str_in(&trusted_pq, st.get("pq_pk")) {
            return fail("PQ attestor key is not trusted".into());
        }
        if has_ed && !is_str_in(&trusted_ed, st.get("attestor_ed25519")) {
            return fail("hybrid Ed25519 attestor key is not trusted".into());
        }
        // (3) the signature over the canonical body (both signature members excluded)
        let mut body = st.as_object().cloned().unwrap_or_default();
        body.remove("sig");
        body.remove("pq_sig");
        let message = match statement_message(&Value::Object(body)) {
            Ok(m) => m,
            Err(e) => return error(e),
        };
        // the PQ key is vouched for by the verifier's own trusted set (checked above)
        let pq_key =
            if needs_pq_pk { st.get("pq_pk").and_then(Value::as_str).and_then(crate::pinned::PinnedPq::caller_vouched) } else { None };
        let ed_pub = st.get("attestor_ed25519").and_then(Value::as_str).unwrap_or("");
        let verified = crate::verify_suite(Some(&json!(name)), ed_pub, pq_key.as_ref(), &message, st.get("sig"), st.get("pq_sig"));
        if !verified || (needs_pq_pk && pq_key.is_none()) {
            return fail("PQ attestation signature does not verify".into());
        }
        // (4) the binding
        let Some(expected) = input.get("expected").filter(|e| !e.is_null()) else {
            return fail("no expected attestation binding supplied".into());
        };
        let expected_b64u = match attestation_binding(expected) {
            Ok(b) => crate::b64_encode(&b),
            Err(e) => return fail(format!("binding not constructible: {}", if e.is_empty() { "invalid" } else { &e })),
        };
        if !st.get("binding").and_then(Value::as_str).is_some_and(|b| !b.is_empty()) {
            return fail("PQ statement is not bound (binding absent)".into());
        }
        if st.get("binding").and_then(Value::as_str) != Some(expected_b64u.as_str()) {
            return fail("PQ statement binding mismatch (holder/grant/epoch/nonce)".into());
        }
        // (5) the policy
        let measurement = st.get("measurement");
        if !measurement.is_some_and(|m| measurements.iter().any(|e| e == m)) {
            return fail("measurement not in policy allowlist".into());
        }
        if let Some(w) = weights.as_ref().filter(|w| !w.is_empty()) {
            if !is_str_in(w, st.get("weights_digest")) {
                return fail("measured weights digest not in policy allowlist".into());
            }
        }
        Ok(json!({"ok": true, "bound": true, "measured": default_identity(&st), "hostAsserted": {"suite": name}}))
    }))
}

/// The default identity of a verified statement: `weights_measured` is ALWAYS false (software / HSM attested, not silicon measured).
pub fn default_identity(st: &Value) -> Value {
    let text = |k: &str| st.get(k).and_then(Value::as_str).map(str::to_string);
    let mut m = json!({
        "model_id": text("model_id").unwrap_or_default(),
        "weights_digest": text("weights_digest").unwrap_or_default(),
        "weights_measured": false,
        "runtime_measurement": st.get("measurement").cloned().unwrap_or(Value::Null),
        "operator": text("operator").unwrap_or_default(),
    });
    for k in ["system_prompt_digest", "tool_manifest_digest"] {
        if let Some(v) = text(k) {
            m[k] = json!(v);
        }
    }
    m
}
