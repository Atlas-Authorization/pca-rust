//! Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class.
//! Valid only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
//! `verified_evidence`), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
//! "none". Total: no function panics.
use crate::fresh_at::verify_body;
use crate::safe_int;
use serde_json::{Map, Value};

pub const RUNTIME_CLAIM_DOMAIN: &str = "atlas-pca/runtime-class-claim/v1\0";
const CLASSES: [&str; 4] = ["none", "os_confined", "egress_default_deny", "wasi_no_ambient"];
const KEYS: [&str; 8] = ["v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"];

fn s(v: Option<&Value>, max: usize) -> Option<&str> {
    v.and_then(Value::as_str).filter(|x| !x.is_empty() && x.encode_utf16().count() <= max)
}
fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}

/// The class the claim proves, or `"none"`.
pub fn verified_runtime_class(claim: &Value, pinned_attestors: &[String], passport_digest: &str, verified_evidence: &[String], now: i64) -> &'static str {
    let Some(c) = claim.as_object() else { return "none" };
    if c.len() != KEYS.len() || !c.keys().all(|k| KEYS.contains(&k.as_str())) || c.get("v").and_then(safe_int) != Some(1) {
        return "none";
    }
    let Some(class) = c.get("class").and_then(Value::as_str).and_then(|x| CLASSES.iter().find(|k| **k == x)) else { return "none" };
    let (Some(attestor), Some(pd), Some(ev), Some(iat), Some(exp)) = (s(c.get("attestor"), 128), s(c.get("passport_digest"), 128), s(c.get("evidence_digest"), 128), nat(c.get("iat")), nat(c.get("exp"))) else { return "none" };
    if now < 0 || !pinned_attestors.iter().any(|a| a == attestor) || pd != passport_digest || !verified_evidence.iter().any(|e| e == ev) || !(iat <= now && now < exp) {
        return "none";
    }
    let body: Map<String, Value> = c.iter().filter(|(k, _)| k.as_str() != "sig").map(|(k, v)| (k.clone(), v.clone())).collect();
    if verify_body(RUNTIME_CLAIM_DOMAIN, &Value::Object(body), attestor, c.get("sig").and_then(Value::as_str)) {
        class
    } else {
        "none"
    }
}
