//! Escalation on the wire: a port of packages/pca/src/escalation.ts (security contract C-51). A decision of `escalate` is
//! admitted only with a principal-signed answer bound to (policy digest, action digest, history head), spent by the replay
//! counter, never upgrading a deny. EVERY signature suite this build implements is accepted (Ed25519, ML-DSA, SLH-DSA, FN-DSA
//! and the hybrids) under the TypeScript pin rules: the principal is pinned by its Ed25519 key, and a post-quantum / hybrid
//! answer verifies only against the PQ key pinned for that principal. A suite this build cannot run is refused
//! (`unsupported_suite`). Total: never panics.

use super::intent_strict::{artifact_suite_error, verify_artifact_sig};
use super::{decode_b64u_strict, hash_canonical_strict};
use serde_json::{json, Value};

pub const ESCALATION_ANSWER_DOMAIN: &str = "atlas-pca/escalation-answer/v1\0";
pub const ESCALATION_MAX_LIFETIME_MS: i64 = 86_400_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;

pub fn escalation_policy_digest(grant: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": "atlas-pca/escalation-policy/v1", "grant": grant}))
}

pub fn escalation_action_digest(pcactn: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": "atlas-pca/escalation-action/v1", "pcactn": pcactn}))
}

/// The head of the holder's history: its last admitted counter (`None` = none yet).
pub fn escalation_history_head(last: Option<u64>) -> Option<String> {
    hash_canonical_strict(&json!({"d": "atlas-pca/escalation-history/v1", "last_counter": last}))
}

/// A Rust `String` cannot hold a lone surrogate, which `s.slice(0, n)` of a JavaScript string can produce when the cut falls inside
/// a surrogate pair. Such a unit is carried as `U+FDD0`, its four lowercase hex digits, `U+FDD1` (two Unicode noncharacters, never
/// valid text), and written as `\udXXXX` by [`escalation_reasons_wire`] / [`restore_lone_surrogates`], as the reference does.
const LONE_OPEN: char = '\u{FDD0}';
const LONE_CLOSE: char = '\u{FDD1}';

/// `s.slice(0, n)` of a JavaScript string: at most `n` UTF-16 code units; a cut inside a surrogate pair keeps the LONE high
/// surrogate (carried as described above).
fn trunc_utf16(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in s.chars() {
        let w = c.len_utf16();
        if units + w > n {
            if w == 2 && units + 1 == n {
                let high = 0xD800 + ((c as u32 - 0x10000) >> 10);
                out.push(LONE_OPEN);
                out.push_str(&format!("{high:04x}"));
                out.push(LONE_CLOSE);
            }
            break;
        }
        units += w;
        out.push(c);
    }
    out
}

/// Replace every carried lone surrogate in serialized JSON text by its `\udXXXX` escape (what `JSON.stringify` writes).
pub fn restore_lone_surrogates(json_text: &str) -> String {
    let mut out = String::with_capacity(json_text.len());
    let mut rest = json_text;
    while let Some(i) = rest.find(LONE_OPEN) {
        out.push_str(&rest[..i]);
        let tail = &rest[i + LONE_OPEN.len_utf8()..];
        match tail.get(..4).filter(|h| {
            h.bytes().all(|b| b.is_ascii_hexdigit()) && tail[4..].starts_with(LONE_CLOSE)
        }) {
            Some(h) => {
                out.push_str("\\u");
                out.push_str(h);
                rest = &tail[4 + LONE_CLOSE.len_utf8()..];
            }
            None => {
                out.push(LONE_OPEN);
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `JSON.stringify(request.reasons)`: strings escaped as the reference writes them (quote, backslash, controls, a lone surrogate
/// as `\udXXXX`; everything else, non-ASCII included, raw).
pub fn escalation_reasons_wire(request: &Value) -> String {
    let mut out = String::from("[");
    for (i, r) in request["reasons"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        for c in r.as_str().unwrap_or_default().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    restore_lone_surrogates(&out)
}

/// How long an issued request is valid when the caller sets no TTL (one hour).
pub const DEFAULT_ESCALATION_REQUEST_TTL_MS: i64 = 3_600_000;

/// The request a refused escalate carries for the principal. `ttl_ms`: its lifetime (`None` or <= 0: one hour).
pub fn build_escalation_request(
    aud: &str,
    grant: &Value,
    pcactn: &Value,
    last: Option<u64>,
    reasons: &[String],
    now: i64,
    ttl_ms: Option<i64>,
) -> Option<Value> {
    build_escalation_request_with_render(aud, grant, pcactn, last, reasons, now, ttl_ms, None)
}

/// [`build_escalation_request`] carrying the verifier's recomputed render digest (K7).
#[allow(clippy::too_many_arguments)]
pub fn build_escalation_request_with_render(
    aud: &str,
    grant: &Value,
    pcactn: &Value,
    last: Option<u64>,
    reasons: &[String],
    now: i64,
    ttl_ms: Option<i64>,
    render_digest: Option<&str>,
) -> Option<Value> {
    let act = pcactn.get("action");
    let show = |k: &str| match act.and_then(|a| a.get(k)) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "undefined".to_string(),
    };
    let rs: Vec<Value> = reasons
        .iter()
        .take(16)
        .map(|r| Value::String(trunc_utf16(r, 512)))
        .collect();
    let mut req = json!({
        "v": 1, "kind": "pca-escalation-request", "aud": aud,
        "policy_digest": escalation_policy_digest(grant)?, "action_digest": escalation_action_digest(pcactn)?,
        "history_head": escalation_history_head(last)?, "verb": show("verb"), "resource": show("resource"),
        "reasons": rs, "expires_at": now + ttl_ms.filter(|t| *t > 0).unwrap_or(DEFAULT_ESCALATION_REQUEST_TTL_MS),
    });
    if let Some(rd) = render_digest {
        req["render_digest"] = Value::String(rd.to_string());
    }
    Some(req)
}

// a parsed JSON `2.0` or `1e3` is the integer 2 / 1000 (JavaScript has one number type): the crate's `safe_int` reads it so
use super::safe_int;

/// `None` for a well-formed answer, else the reason.
pub fn escalation_answer_shape_error(a: &Value) -> Option<String> {
    let m = match a.as_object() {
        Some(m) => m,
        None => return Some("not an object".into()),
    };
    const REQUIRED: [&str; 11] = [
        "v",
        "kind",
        "principal",
        "policy_digest",
        "action_digest",
        "history_head",
        "decision",
        "iat",
        "expires_at",
        "nonce",
        "sig",
    ];
    const OPTIONAL: [&str; 4] = ["alg", "pq_pk", "pq_sig", "render_digest"];
    for k in m.keys() {
        if !REQUIRED.contains(&k.as_str()) && !OPTIONAL.contains(&k.as_str()) {
            return Some(format!("unknown member 'answer.{k}'"));
        }
    }
    for k in REQUIRED {
        if !m.contains_key(k) {
            return Some(format!("missing member 'answer.{k}'"));
        }
    }
    if safe_int(&m["v"]) != Some(1) || m["kind"] != "pca-escalation-answer" {
        return Some("not a pca-escalation-answer v1".into());
    }
    let b32 = |v: &Value| {
        v.as_str()
            .and_then(|s| decode_b64u_strict(s, Some(32)))
            .is_some()
    };
    if !b32(&m["principal"]) {
        return Some("principal must be canonical base64url (32 bytes)".into());
    }
    for k in ["policy_digest", "action_digest", "history_head"] {
        if !b32(&m[k]) {
            return Some(format!("{k} must be canonical base64url (32 bytes)"));
        }
    }
    if m["decision"] != "allow" && m["decision"] != "deny" {
        return Some("decision must be 'allow' or 'deny'".into());
    }
    let (iat, exp) = (
        safe_int(&m["iat"]).filter(|i| *i >= 0),
        safe_int(&m["expires_at"]).filter(|i| *i >= 0),
    );
    let (iat, exp) = match (iat, exp) {
        (Some(a), Some(b)) => (a, b),
        _ => return Some("iat and expires_at must be non-negative safe integers".into()),
    };
    if exp <= iat {
        return Some("expires_at must be greater than iat".into());
    }
    if exp - iat > ESCALATION_MAX_LIFETIME_MS {
        return Some(format!(
            "an answer lives at most {ESCALATION_MAX_LIFETIME_MS} ms"
        ));
    }
    if m.contains_key("render_digest") && !b32(&m["render_digest"]) {
        return Some("render_digest must be canonical base64url (32 bytes)".into());
    }
    if !m["nonce"]
        .as_str()
        .and_then(|s| decode_b64u_strict(s, None))
        .is_some_and(|b| b.len() >= 16)
    {
        return Some("nonce must be canonical base64url of at least 16 bytes".into());
    }
    if !m["sig"].is_string() {
        return Some("sig must be a string".into());
    }
    artifact_suite_error(m)
}

/// A pinned answering principal: its Ed25519 identity and, for a post-quantum or hybrid suite, the PQ public key (b64u) the
/// verifier pins for it. `pq_pk: None` pins no PQ key: such a principal's PQ / hybrid answers are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedSigner {
    pub pk: String,
    pub pq_pk: Option<String>,
}

impl PinnedSigner {
    /// A principal pinned by its Ed25519 key alone.
    pub fn ed25519(pk: impl Into<String>) -> Self {
        PinnedSigner {
            pk: pk.into(),
            pq_pk: None,
        }
    }

    /// A principal pinned with the PQ key it signs with (ML-DSA, SLH-DSA, FN-DSA or a hybrid).
    pub fn with_pq(pk: impl Into<String>, pq_pk: impl Into<String>) -> Self {
        PinnedSigner {
            pk: pk.into(),
            pq_pk: Some(pq_pk.into()),
        }
    }
}

/// What an answer must be bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationBinding {
    pub policy_digest: String,
    pub action_digest: String,
    pub history_head: String,
    /// K7: the H(R) the verifier recomputed from the executed parameters and its own definition. When set, the answer MUST
    /// carry exactly it; when `None`, an answer that carries a `render_digest` is refused (the verifier did not check what was shown).
    pub render_digest: Option<String>,
}

/// The result of [`verify_escalation_answer`]. A valid deny answer is `Ok` with `decision == "deny"`: never admit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationVerdict {
    Ok { principal: String, decision: String },
    Refused(String),
}

/// Check an answer against the verifier's pinned principals and the binding of THIS decision.
pub fn verify_escalation_answer(
    answer: &Value,
    principals: &[PinnedSigner],
    bind: &EscalationBinding,
    now: i64,
) -> EscalationVerdict {
    let no = |r: &str| EscalationVerdict::Refused(r.to_string());
    if now.abs() > MAX_SAFE {
        return no("the verifier clock is not a safe integer (fail closed)");
    }
    if let Some(e) = escalation_answer_shape_error(answer) {
        return EscalationVerdict::Refused(format!("malformed escalation answer: {e}"));
    }
    if principals.is_empty() {
        return no("no principal is pinned for escalation answers");
    }
    let principal = answer["principal"].as_str().unwrap_or_default();
    // the first pin naming the principal decides (the reference's find)
    let pin = match principals.iter().find(|p| p.pk == principal) {
        Some(p) => p,
        None => return no("the answering principal is not pinned by this verifier"),
    };
    let pq = pin.pq_pk.clone().map(Value::String);
    let signed = match answer.as_object() {
        Some(m) => verify_artifact_sig(ESCALATION_ANSWER_DOMAIN, m, &pin.pk, pq.as_ref()),
        None => false,
    };
    if !signed {
        return no("escalation answer signature invalid");
    }
    if answer["policy_digest"] != bind.policy_digest.as_str() {
        return no("the answer is bound to another policy");
    }
    if answer["action_digest"] != bind.action_digest.as_str() {
        return no("the answer is bound to another action");
    }
    if answer["history_head"] != bind.history_head.as_str() {
        return no("the answer is bound to another state of the history");
    }
    match (&bind.render_digest, answer.get("render_digest")) {
        (Some(_), None) => return no("the answer is not bound to the canonical approval render"),
        (Some(want), Some(got)) if got != want.as_str() => return no("the answer was given for another approval render"),
        (None, Some(_)) => return no("the answer carries an approval render this verifier did not recompute"),
        _ => {}
    }
    if now < safe_int(&answer["iat"]).unwrap_or(0) {
        return no("the answer is from the future");
    }
    if now > safe_int(&answer["expires_at"]).unwrap_or(0) {
        return no("the answer has expired");
    }
    EscalationVerdict::Ok {
        principal: principal.to_string(),
        decision: answer["decision"].as_str().unwrap_or("deny").to_string(),
    }
}
