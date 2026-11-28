//! `@atlasauth/pca-a2a` signed Agent Cards (a2a-card.ts + the card half of index.ts): RFC 8785 JCS bytes, the A2A 1.0 `AgentCard`
//! schema check, `issueSignedAgentCard` and `verifyAgentCard`. The JCS, schema and signing code is the one already native in
//! [`crate::agentcard`] (the two TypeScript packages carry the same a2a-card.ts); this module adds what differs in the A2A package's
//! `verifyAgentCard`: a signature entry that is not an object with string `protected` / `signature` is `signature N is malformed`
//! (not a JOSE failure), and the result never carries `pcaProof`. Keys are JWKs (JSON values), results are JSON values.
use crate::agentcard;
use crate::oauth::truthy;
use serde_json::{json, Map, Value};

pub use crate::agentcard::{jcs_bytes, validate_agent_card1};

/// `issueSignedAgentCard(card, signingKey, opts)`: `opts` is `{alg?, passport?, kid?, profile?, schema?}`; the error text is the
/// reference's (the package's own `issueSignedAgentCard:` messages compare exactly, a JOSE library text only has to be a refusal).
pub fn issue_signed_agent_card(card: &Value, signing_key: &Value, opts: &Value) -> Result<Value, String> {
    agentcard::issue_signed_agent_card(card, signing_key, opts)
}

fn without_signatures(card: &Value) -> Value {
    match card {
        Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| k.as_str() != "signatures").map(|(k, v)| (k.clone(), v.clone())).collect()),
        x => x.clone(),
    }
}

/// `verifyAgentCard(card, opts)`; `opts` is `{jwks?, key?, alg?, schema?}`. `{ok, reason?, passportRef?, passport?}`.
pub fn verify_agent_card(card: &Value, opts: &Value) -> Value {
    let fail = |r: String| json!({ "ok": false, "reason": r });
    if !matches!(card, Value::Object(_) | Value::Array(_)) {
        return fail("agent card is not an object".into());
    }
    let sigs = match card.get("signatures").and_then(Value::as_array) {
        Some(s) if !s.is_empty() => s,
        _ => return fail("agent card carries no signatures".into()),
    };
    if opts.get("schema").and_then(Value::as_str) == Some("a2a-1.0") {
        let problems = validate_agent_card1(card);
        if !problems.is_empty() {
            return fail(format!("agent card does not match the A2A 1.0 schema: {}", problems.join("; ")));
        }
    }
    if let Err(e) = agentcard::resolve_verify_key(opts) {
        return fail(e);
    }
    if let Err(e) = jcs_bytes(&without_signatures(card)) {
        return fail(format!("agent card has no canonical form: {e}"));
    }
    // each signature is checked alone (the key and the payload are the same for all), in order, so the first failure wins
    let mut sub_opts = opts.as_object().cloned().unwrap_or_default();
    sub_opts.remove("schema");
    let sub_opts = Value::Object(sub_opts);
    let mut passport_ref: Option<String> = None;
    for (i, sig) in sigs.iter().enumerate() {
        let well_formed = sig.get("protected").is_some_and(Value::is_string) && sig.get("signature").is_some_and(Value::is_string);
        if !well_formed {
            return fail(format!("signature {i} is malformed"));
        }
        let mut one = card.as_object().cloned().unwrap_or_default();
        one.insert("signatures".into(), Value::Array(vec![sig.clone()]));
        let r = agentcard::verify_agent_card(&Value::Object(one), &sub_opts);
        if r.get("ok") != Some(&Value::Bool(true)) {
            let reason = r.get("reason").and_then(Value::as_str).unwrap_or("signature did not verify");
            return fail(match reason.strip_prefix("signature 0 did not verify") {
                Some(rest) => format!("signature {i} did not verify{rest}"),
                None => reason.to_string(),
            });
        }
        if passport_ref.is_none() {
            passport_ref = r.get("passportRef").and_then(Value::as_str).map(String::from);
        }
    }
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    if let Some(r) = passport_ref {
        out.insert("passportRef".into(), json!(r));
    }
    if truthy(card.get("pcaPassport")) {
        out.insert("passport".into(), card["pcaPassport"].clone());
    }
    Value::Object(out)
}
