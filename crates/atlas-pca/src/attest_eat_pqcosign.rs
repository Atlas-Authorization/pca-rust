//! Post-quantum co-signature of a verified attestation verdict. After the classical AMD SEV-SNP hardware root has been verified, the
//! verdict's security-relevant fields (tier, trustworthy bit, measured identity, nonce and iat freshness anchor, issuer, co-sign time)
//! are bound under an ML-DSA-65 signature by default (or a hybrid / nested-hybrid / category-5 suite). This does NOT make AMD's root
//! post-quantum: it makes the recorded verdict forward-secure against a later break of the classical root. A classical-only suite is
//! refused. The signed bytes are `utf8(JSON(obj))` over a fixed field order with a domain-separating `typ`, every optional field
//! emitted explicitly (its value or null).
//!
//! A JavaScript `undefined` is `None`; a reference throw is `Err(message)`.
use crate::agent::{sign_with_suite, KeyPair, PqKeyPair, Suite};
use crate::attest_eat::{as_str, clock_ms, ct_eq, fin, g, is_record, jnum, js_string, U};
use crate::js_stringify;
use serde_json::{json, Map, Value};

pub const PQCOSIGN_DOMAIN: &str = "atlas-pca/attest-cosign/v1";
pub const DEFAULT_PQ_COSIGN_SUITE: &str = "ml-dsa-65";
pub const PQ_COSIGN_SUITES: [&str; 9] = [
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-256s",
    "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65",
    "hybrid-ed25519-ml-dsa-87",
    "hybrid-ed25519-slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-256s",
];

/// One of the accepted post-quantum suites (rejects ed25519, unknown names and non-strings).
pub fn is_pq_co_sign_suite(x: U) -> bool {
    as_str(x).is_some_and(|s| PQ_COSIGN_SUITES.contains(&s))
}

fn string_or_null(v: U) -> Value {
    match v {
        Some(s @ Value::String(_)) => s.clone(),
        _ => Value::Null,
    }
}

fn canonical_measured(m: U) -> Result<Value, String> {
    if m.is_none() {
        return Ok(Value::Null);
    }
    let mut out = Map::new();
    for k in ["model_id", "weights_digest"] {
        if let Some(v) = g(m, k)? {
            out.insert(k.into(), v.clone());
        }
    }
    let wm = match g(m, "weights_measured")? {
        Some(b @ Value::Bool(_)) => b.clone(),
        _ => Value::Null,
    };
    out.insert("weights_measured".into(), wm);
    for k in ["runtime_measurement", "operator"] {
        if let Some(v) = g(m, k)? {
            out.insert(k.into(), v.clone());
        }
    }
    out.insert("system_prompt_digest".into(), string_or_null(g(m, "system_prompt_digest")?));
    out.insert("tool_manifest_digest".into(), string_or_null(g(m, "tool_manifest_digest")?));
    Ok(Value::Object(out))
}

/// The CANONICAL, DETERMINISTIC bytes the co-signature is computed over (fixed field order, null for every absent optional).
pub fn canonical_verdict_bytes(verdict: U, cosigned_at: U) -> Result<Vec<u8>, String> {
    let mut c = Map::new();
    c.insert("typ".into(), json!(PQCOSIGN_DOMAIN));
    if let Some(t) = g(verdict, "tier")? {
        c.insert("tier".into(), t.clone());
    }
    c.insert("trustworthy".into(), json!(g(verdict, "trustworthy")? == Some(&Value::Bool(true))));
    c.insert("measurement".into(), string_or_null(g(verdict, "measurement")?));
    c.insert("measured".into(), canonical_measured(g(verdict, "measured")?)?);
    c.insert("nonce".into(), string_or_null(g(verdict, "nonce")?));
    let iat = match g(verdict, "iat")? {
        Some(n) if fin(Some(n)).is_some() => n.clone(),
        _ => Value::Null,
    };
    c.insert("iat".into(), iat);
    c.insert("issuer".into(), string_or_null(g(verdict, "issuer")?));
    if let Some(a) = cosigned_at {
        c.insert("cosignedAt".into(), a.clone());
    }
    Ok(js_stringify(&Value::Object(c)).into_bytes())
}

/// An attestation verdict from an `appraise` result plus the EAT claims (tier, trustworthy, measured identity / launch measurement,
/// nonce, iat, issuer).
pub fn verdict_from_appraisal(result: U, claims: U) -> Result<Value, String> {
    let mut v = Map::new();
    if let Some(t) = g(result, "tier")? {
        v.insert("tier".into(), t.clone());
    }
    if let Some(t) = g(result, "trustworthy")? {
        v.insert("trustworthy".into(), t.clone());
    }
    let measured = g(claims, "measured")?;
    if let Some(m) = measured {
        v.insert("measured".into(), m.clone());
    }
    let rm = if matches!(measured, None | Some(Value::Null)) { None } else { g(measured, "runtime_measurement")? };
    let use_rm = matches!(rm, Some(Value::String(s)) if !s.is_empty()) || matches!(rm, Some(Value::Array(a)) if !a.is_empty());
    let measurement = if use_rm {
        rm
    } else {
        let sevsnp = g(claims, "sevsnp")?;
        if matches!(sevsnp, None | Some(Value::Null)) {
            None
        } else {
            g(sevsnp, "measurement")?
        }
    };
    if let Some(m) = measurement {
        if m.as_str().is_some_and(|s| !s.is_empty()) {
            v.insert("measurement".into(), m.clone());
        }
    }
    if let Some(n @ Value::String(_)) = g(claims, "eat_nonce")? {
        v.insert("nonce".into(), n.clone());
    }
    if let Some(i) = g(claims, "iat")? {
        if fin(Some(i)).is_some() {
            v.insert("iat".into(), i.clone());
        }
    }
    if let Some(i @ Value::String(_)) = g(claims, "iss")? {
        v.insert("issuer".into(), i.clone());
    }
    Ok(Value::Object(v))
}

/// The secret key material of a co-signature: the Ed25519 identity (hybrid suites) and the post-quantum key pair of the suite's family.
pub struct CoSignKeys<'a> {
    pub ed: Option<&'a KeyPair>,
    pub pq: Option<&'a PqKeyPair>,
}

fn pq_family(suite: &str) -> &'static str {
    if suite.contains("ml-dsa-87") {
        "ML-DSA-87"
    } else if suite.contains("ml-dsa-65") {
        "ML-DSA-65"
    } else if suite.contains("slh-dsa-sha2-128f") {
        "SLH-DSA-SHA2-128f"
    } else {
        "SLH-DSA-SHA2-256s"
    }
}

/// Co-sign a verified verdict under a post-quantum suite (default `ml-dsa-65`). Call this AFTER the classical hardware check passed.
/// Fails closed on misconfiguration: a classical-only or unknown suite, or missing key material for the suite, errs. `now` pins the
/// co-sign time (epoch ms, default the clock). The artifact is `{verdict, cosig: {cosignedAt, sig, pq_sig?}, suite, signer_pub: {pq, ed?}}`.
pub fn co_sign_attestation(verdict: &Value, suite: U, keys: Option<&CoSignKeys>, now: U) -> Result<Value, String> {
    let suite_v = suite.filter(|v| !v.is_null());
    let name = match suite_v {
        None => DEFAULT_PQ_COSIGN_SUITE,
        Some(v) if is_pq_co_sign_suite(Some(v)) => as_str(Some(v)).unwrap_or(DEFAULT_PQ_COSIGN_SUITE),
        Some(v) => return Err(format!("coSignAttestation: '{}' is not an accepted post-quantum co-sign suite", js_string(Some(v)))),
    };
    let keys = keys.ok_or("coSignAttestation: secretKey material is required")?;
    let cosigned_at = match fin(now) {
        Some(_) => now.cloned().unwrap_or(Value::Null),
        None => jnum(clock_ms()),
    };
    let msg = canonical_verdict_bytes(Some(verdict), Some(&cosigned_at))?;
    let family = pq_family(name);
    let pq = keys.pq.filter(|p| p.family() == family).ok_or_else(|| format!("coSignAttestation: suite '{name}' requires {family} key material"))?;
    let mut signer_pub = Map::new();
    signer_pub.insert("pq".into(), json!(pq.public));
    let ed = if name.starts_with("hybrid") {
        let ed = keys.ed.ok_or_else(|| format!("coSignAttestation: hybrid suite '{name}' requires edSecret"))?;
        signer_pub.insert("ed".into(), json!(ed.public));
        Some(ed)
    } else {
        None
    };
    let (sig, pq_sig) = sign_with_suite(&Suite { alg: Some(name), pq: Some(pq) }, ed, &msg)?;
    let mut cosig = Map::new();
    cosig.insert("cosignedAt".into(), cosigned_at);
    cosig.insert("sig".into(), json!(sig));
    if let Some(p) = pq_sig {
        cosig.insert("pq_sig".into(), json!(p));
    }
    Ok(json!({"verdict": verdict, "cosig": Value::Object(cosig), "suite": name, "signer_pub": Value::Object(signer_pub)}))
}

fn parse_signer_pub(v: U) -> Option<Map<String, Value>> {
    let Some(Value::Object(m)) = v else { return None };
    let pq = m.get("pq").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let mut out = Map::new();
    out.insert("pq".into(), json!(pq));
    if let Some(ed) = m.get("ed").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        out.insert("ed".into(), json!(ed));
    }
    Some(out)
}

fn signer_matches(expected: &Value, got: &Map<String, Value>) -> Result<bool, String> {
    let exp_pq = if expected.is_string() { Some(expected) } else { g(Some(expected), "pq")? };
    let got_pq = got.get("pq").and_then(Value::as_str).unwrap_or("");
    if as_str(exp_pq).is_none() || !ct_eq(exp_pq, got_pq)? {
        return Ok(false);
    }
    if !expected.is_string() {
        if let Some(e @ Value::String(_)) = g(Some(expected), "ed")? {
            match got.get("ed").and_then(Value::as_str) {
                Some(ged) if ct_eq(Some(e), ged)? => {}
                _ => return Ok(false),
            }
        }
    }
    Ok(true)
}

/// Verify a co-signed attestation: recompute the canonical bytes from the artifact's OWN verdict and co-sign time and check the
/// post-quantum signature under the embedded signer key. Fails closed (a result with a `reason`, never an error) on a malformed
/// artifact, a classical-only / unknown suite, a tampered verdict field, a wrong key, an `expectedSigner` mismatch (a string: the
/// post-quantum key; or `{pq, ed?}`), a co-signature older than `maxAgeMs`. Without `expectedSigner` it proves only that the
/// signature matches the key EMBEDDED in the artifact. `opts`: `expectedSigner`, `maxAgeMs`, `now`.
pub fn verify_co_signed_attestation(cosigned: U, opts: U) -> Value {
    match co_verify(cosigned, opts) {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "reason": format!("co-signature verification error (fail closed): {e}")}),
    }
}

fn co_verify(cosigned: U, opts: U) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let opts = Some(opts.unwrap_or(&empty));
    let fail = |r: &str| Ok(json!({"ok": false, "reason": r}));
    if !is_record(cosigned) {
        return fail("co-signed attestation is not an object");
    }
    let verdict = g(cosigned, "verdict")?;
    if !is_record(verdict) || as_str(g(verdict, "tier")?).is_none() || !matches!(g(verdict, "trustworthy")?, Some(Value::Bool(_))) {
        return fail("verdict is missing or has a non-string tier / non-boolean trustworthy");
    }
    let cosig = g(cosigned, "cosig")?;
    let cosigned_at = if is_record(cosig) { g(cosig, "cosignedAt")? } else { None };
    if !is_record(cosig) || fin(cosigned_at).is_none() || as_str(g(cosig, "sig")?).is_none() {
        return fail("cosig is missing or has a non-numeric cosignedAt / non-string sig");
    }
    let suite_v = g(cosigned, "suite")?;
    if !is_pq_co_sign_suite(suite_v) {
        return Ok(json!({"ok": false, "reason": format!("suite '{}' is not an accepted post-quantum co-sign suite", js_string(suite_v))}));
    }
    let suite = as_str(suite_v).unwrap_or("");
    let Some(signer) = parse_signer_pub(g(cosigned, "signer_pub")?) else {
        return fail("signer_pub is missing or has no post-quantum public key");
    };
    let now = fin(g(opts, "now")?).unwrap_or_else(clock_ms);
    let at = fin(cosigned_at).unwrap_or(0.0);
    let age = now - at;
    let partial = |ok: bool, reason: Option<&str>| {
        let mut m = Map::new();
        m.insert("ok".into(), json!(ok));
        if let Some(r) = reason {
            m.insert("reason".into(), json!(r));
        }
        m.insert("suite".into(), json!(suite));
        m.insert("verdict".into(), verdict.cloned().unwrap_or(Value::Null));
        m.insert("signer_pub".into(), Value::Object(signer.clone()));
        m.insert("cosignedAt".into(), cosigned_at.cloned().unwrap_or(Value::Null));
        m.insert("ageMs".into(), jnum(age));
        Value::Object(m)
    };
    if let Some(exp) = g(opts, "expectedSigner")? {
        if !signer_matches(exp, &signer)? {
            return Ok(partial(false, Some("co-signer public key does not match the expected signer")));
        }
    }
    if let Some(m) = g(opts, "maxAgeMs")? {
        let max = match fin(Some(m)) {
            Some(x) if x > 0.0 => x,
            _ => return Ok(partial(false, Some("invalid maxAgeMs"))),
        };
        if !(now.is_finite() && at <= now) {
            return Ok(partial(false, Some("co-sign timestamp is in the future")));
        }
        if !(age.is_finite() && age <= max) {
            return Ok(partial(false, Some("co-signature is stale (older than maxAgeMs)")));
        }
    }
    let msg = canonical_verdict_bytes(verdict, cosigned_at)?;
    let hybrid = suite.starts_with("hybrid");
    let mut art = Map::new();
    art.insert("alg".into(), json!(suite));
    art.insert("sig".into(), g(cosig, "sig")?.cloned().unwrap_or(Value::Null));
    art.insert("pq_pk".into(), signer.get("pq").cloned().unwrap_or(Value::Null));
    // the reference reads `pq_sig` only where the suite has a post-quantum half beside the Ed25519 one
    if hybrid {
        if let Some(p) = g(cosig, "pq_sig")? {
            art.insert("pq_sig".into(), p.clone());
        }
    }
    let ed_pub = if hybrid { signer.get("ed").and_then(Value::as_str).unwrap_or("") } else { "" };
    if !crate::verify_artifact_suite(&Value::Object(art), ed_pub, &msg) {
        return Ok(partial(false, Some("post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)")));
    }
    Ok(partial(true, None))
}
