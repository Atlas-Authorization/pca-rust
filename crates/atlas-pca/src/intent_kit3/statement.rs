//! Intent capture and commitment: the principal's own words plus the structured reading, signed, with a content address (the
//! intent ref); the goal string that binds a grant to a statement (`statement.ts` over the core intent extension). Ed25519 signing
//! only; verification goes through the verifier-pinned suite dispatch.
use crate::intent_suite::{bind_suite_fields, domain_message, verify_pinned_suite};
use serde_json::{json, Map, Value};

pub const INTENT_SIG_DOMAIN: &str = "atlas-pca/intent/v1\0";
pub const INTENT_REF_DOMAIN: &str = "atlas-pca/intent-ref/v1";
pub const INTENT_GOAL_PREFIX: &str = "pca-intent:v1:";
pub const INTENT_SOURCE_KINDS: [&str; 5] = ["conversation", "ticket", "document", "form", "other"];
const KEYS: [&str; 7] = ["v", "principal", "text", "slots", "sources", "created_at", "nonce"];

/// The signed body: suite fields and the signature are excluded (the ref names the content). `-0` is normalised to `0`.
pub fn statement_body(s: &Value) -> Result<Map<String, Value>, String> {
    let m = s.as_object().ok_or("intent statement is not an object")?;
    let mut b = Map::new();
    for k in KEYS {
        if let Some(v) = m.get(k) {
            b.insert(k.to_string(), plain(v));
        }
    }
    Ok(b)
}

fn plain(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), plain(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(plain).collect()),
        Value::Number(n) if n.as_f64() == Some(0.0) && n.as_i64().is_none() => json!(0),
        _ => v.clone(),
    }
}

/// Content address of an intent statement.
pub fn intent_ref(s: &Value) -> Result<String, String> {
    let body = statement_body(s)?;
    crate::hash_canonical_strict(&json!({ "d": INTENT_REF_DOMAIN, "s": Value::Object(body) })).ok_or_else(|| "intentRef: not strict-canonical".to_string())
}

fn b32(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| crate::decode_b64u_strict(s, Some(32)).is_some())
}

fn shape_error(s: &Value) -> Option<String> {
    let m = s.as_object().map_or_else(|| Some("intent statement is not an object".to_string()), |_| None);
    if m.is_some() {
        return m;
    }
    if !s.get("v").is_some_and(|v| v.is_number() && v.as_f64() == Some(1.0)) {
        return Some("unsupported intent statement version".into());
    }
    if !b32(s.get("principal")) {
        return Some("principal is not canonical base64url (32 bytes)".into());
    }
    if !s.get("text").and_then(Value::as_str).is_some_and(|t| !t.is_empty()) {
        return Some("text must be a non-empty string".into());
    }
    if !s.get("slots").is_some_and(Value::is_object) {
        return Some("slots must be an object".into());
    }
    let sources = match s.get("sources") {
        Some(Value::Array(a)) => a,
        _ => return Some("sources must be an array".into()),
    };
    for (i, src) in sources.iter().enumerate() {
        if !src.is_object() || !src.get("kind").and_then(Value::as_str).is_some_and(|k| INTENT_SOURCE_KINDS.contains(&k)) {
            return Some(format!("sources[{i}] has an unknown kind"));
        }
        if src.get("uri").is_some_and(|u| !u.is_string()) {
            return Some(format!("sources[{i}].uri must be a string"));
        }
        if !b32(src.get("digest")) {
            return Some(format!("sources[{i}].digest is not canonical base64url (32 bytes)"));
        }
    }
    let ca = s.get("created_at");
    if !ca.is_some_and(crate::wallet_omega::is_safe_int) || ca.and_then(Value::as_f64).is_some_and(|x| x < 0.0) {
        return Some("created_at must be a non-negative safe integer (epoch ms)".into());
    }
    if !s.get("nonce").and_then(Value::as_str).is_some_and(|t| !t.is_empty()) {
        return Some("nonce must be a non-empty string".into());
    }
    None
}

fn suite_fields_error(a: &Value) -> Option<String> {
    let alg = a.get("alg");
    if let Some(al) = alg {
        if !al.as_str().is_some_and(|x| crate::REGISTERED_SUITES.contains(&x)) {
            return Some("unknown signature suite".into());
        }
    }
    let classical = alg.is_none() || alg.and_then(Value::as_str) == Some("ed25519");
    if classical && (a.get("pq_pk").is_some() || a.get("pq_sig").is_some()) {
        return Some("an ed25519 artifact must not carry pq_pk / pq_sig".into());
    }
    None
}

/// Sign a statement as its principal (an Ed25519 seed); `principal` defaults to the key of the seed.
pub fn sign_intent(s: &Value, principal_seed: &[u8; 32]) -> Result<Value, String> {
    let principal = crate::wallet::ed_public_b64u(principal_seed);
    let m = s.as_object().ok_or("intent statement is not an object")?;
    if m.get("principal").is_some_and(|p| p != &json!(principal)) {
        return Err("signIntentStatement: principal key mismatch".into());
    }
    let mut with = m.clone();
    with.insert("principal".into(), json!(principal));
    let body = statement_body(&Value::Object(with))?;
    if let Some(bad) = shape_error(&Value::Object(body.clone())) {
        return Err(format!("signIntentStatement: {bad}"));
    }
    let msg = domain_message(INTENT_SIG_DOMAIN, body.clone()).ok_or("signIntentStatement: statement is not strict-canonical")?;
    let mut out = body;
    out.insert("sig".into(), json!(crate::wallet::ed_sign(principal_seed, &msg)));
    Ok(Value::Object(out))
}

/// Verify a signed statement (shape, signer, suite signature; a PQ key must be pinned via `opts.pqPins`). Never errs: `{ok, reason?}`.
pub fn verify_intent(s: &Value, opts: &Value) -> Value {
    let fail = |r: String| json!({ "ok": false, "reason": r });
    if let Some(bad) = shape_error(s) {
        return fail(bad);
    }
    let principal = s["principal"].as_str().unwrap_or("");
    if let Some(exp) = opts.get("expectedSigner").filter(|e| !e.is_null()) {
        if exp.as_str() != Some(principal) {
            return fail("principal mismatch".into());
        }
    }
    if let Some(se) = suite_fields_error(s) {
        return fail(se);
    }
    let mut body = match statement_body(s) {
        Ok(b) => b,
        Err(e) => return fail(format!("malformed intent statement: {e}")),
    };
    match bind_suite_fields(&mut body, s.get("alg"), s.get("pq_pk")) {
        Ok(true) => {}
        Ok(false) => return fail("malformed intent statement: canonicalize: unsupported type undefined".into()),
        Err(e) => return fail(format!("malformed intent statement: {e}")),
    }
    let Some(msg) = domain_message(INTENT_SIG_DOMAIN, body) else { return fail("malformed intent statement: not strict-canonical".into()) };
    let pin = opts.get("pqPins").and_then(Value::as_object).and_then(|p| p.get(principal)).map(|v| (principal, v));
    match verify_pinned_suite(s.get("alg"), principal, s.get("pq_pk"), &msg, s.get("sig"), s.get("pq_sig"), pin) {
        Ok(true) => json!({ "ok": true }),
        _ => fail("bad signature".into()),
    }
}

/// The goal string that binds a grant to an intent statement (and optionally an Intent Map).
pub fn intent_goal(r#ref: &str, map_digest: Option<&str>) -> String {
    match map_digest {
        Some(m) if !m.is_empty() => format!("{INTENT_GOAL_PREFIX}{}:{m}", r#ref),
        _ => format!("{INTENT_GOAL_PREFIX}{}", r#ref),
    }
}

/// Parse an intent goal string: `{intentRef, mapDigest?}` or `None` when it is not one.
pub fn parse_intent_goal(goal: &Value) -> Option<Value> {
    let rest = goal.as_str()?.strip_prefix(INTENT_GOAL_PREFIX)?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts[0].is_empty() || parts.len() > 2 {
        return None;
    }
    match parts.get(1).filter(|m| !m.is_empty()) {
        Some(m) => Some(json!({ "intentRef": parts[0], "mapDigest": m })),
        None => Some(json!({ "intentRef": parts[0] })),
    }
}
