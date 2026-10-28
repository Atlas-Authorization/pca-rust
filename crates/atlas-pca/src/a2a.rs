//! The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
//! push-token binding and signed task-update receipts. Total: no function panics. Per-hop PCActn verification is the ordinary
//! verifier's job; this is what surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
use crate::fresh_at::verify_body;
use crate::pca_grant::chain_digest;
use crate::{decode_b64u_strict, hash_canonical_strict, safe_int, strict_parse};
use serde_json::{json, Map, Value};

pub const RECEIPT_DOMAIN: &str = "atlas-pca/a2a-receipt/v1\0";
const NEED_MEMBERS: [&str; 10] = ["v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest"];
const TERMINAL: [&str; 4] = ["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"];
const STATES: [&str; 8] = ["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED", "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"];

fn s(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|x| !x.is_empty() && x.encode_utf16().count() <= max)
}
fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}

/// `None` when valid, else the refusal code.
pub fn need_error(v: &Value) -> Option<&'static str> {
    let Some(x) = v.as_object() else { return Some("bad_shape") };
    if x.keys().any(|k| !NEED_MEMBERS.contains(&k.as_str())) {
        return Some("unknown_member");
    }
    if x.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Some("bad_version");
    }
    let kind = x.get("kind").and_then(Value::as_str).unwrap_or("");
    if !["scope", "grant", "discharge", "escalate"].contains(&kind) {
        return Some("bad_kind");
    }
    if !s(x.get("verb"), 128) || !s(x.get("resource"), 512) {
        return Some("bad_field");
    }
    if let Some(sc) = x.get("scopes") {
        match sc.as_array() {
            Some(a) if a.len() <= 16 && a.iter().all(|e| s(Some(e), 128) && !e.as_str().unwrap_or("").chars().any(char::is_whitespace)) => {}
            _ => return Some("bad_field"),
        }
    }
    for k in ["grant_ref", "policy_digest"] {
        if x.get(k).is_some() && !s(x.get(k), 128) {
            return Some("bad_field");
        }
    }
    if let Some(t) = x.get("tier") {
        if !matches!(t.as_f64(), Some(2.0 | 3.0)) || kind != "escalate" {
            return Some("bad_field");
        }
    }
    if let Some(l) = x.get("limits") {
        match l.as_object() {
            Some(o) if o.len() <= 16 && o.iter().all(|(k, e)| !k.is_empty() && k.encode_utf16().count() <= 64 && e.as_f64().is_some_and(|f| f >= 0.0)) => {}
            _ => return Some("bad_field"),
        }
    }
    if let Some(d) = x.get("discharges") {
        match d.as_array() {
            Some(a) if a.len() <= 16 && a.iter().all(|e| e.as_object().is_some_and(|o| o.keys().all(|k| k == "issuer" || k == "claim") && s(o.get("issuer"), 512) && s(o.get("claim"), 256))) => {}
            _ => return Some("bad_field"),
        }
    }
    if kind == "escalate" && !x.contains_key("tier") {
        return Some("bad_field");
    }
    None
}

/// The decoded need, or the refusal code.
pub fn decode_need(value: &Value) -> Result<Value, &'static str> {
    let Some(text) = value.as_str().filter(|t| !t.is_empty()) else { return Err("bad_base64") };
    if text.len() > 2048 {
        return Err("too_long");
    }
    let raw = decode_b64u_strict(text, None).ok_or("bad_base64")?;
    let json_text = std::str::from_utf8(&raw).map_err(|_| "bad_utf8")?;
    let parsed = strict_parse(json_text).map_err(|_| "bad_json")?;
    match need_error(&parsed) {
        Some(c) => Err(c),
        None => Ok(parsed),
    }
}

pub fn need_digest(need: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": "atlas-pca/need/v1", "need": need }))
}

/// `Ok(())` or `(failed_hop, reason)`.
pub fn check_chain_extension(chains: &[Vec<String>]) -> Result<(), (usize, &'static str)> {
    for (i, ids) in chains.iter().enumerate() {
        if ids.is_empty() {
            return Err((i, "no_chain"));
        }
        if i > 0 {
            let prev = &chains[i - 1];
            if ids.len() < prev.len() || ids[..prev.len()] != prev[..] {
                return Err((i, "chain_does_not_extend_previous_hop"));
            }
        }
    }
    Ok(())
}

/// `None` when the full verifier may now be asked, else the refusal code.
pub fn resume_gate(state: &str, need_encoded: &Value, answer_digest: &Value, proof_action: Option<(&str, &str)>) -> Option<&'static str> {
    if state != "TASK_STATE_AUTH_REQUIRED" && state != "auth-required" {
        return Some("task_not_auth_required");
    }
    let need = if need_encoded.is_null() { None } else { decode_need(need_encoded).ok() };
    let Some(need) = need else { return Some("no_valid_need") };
    if answer_digest.as_str() != need_digest(&need).as_deref() {
        return Some("answer_not_bound_to_need");
    }
    let Some((verb, resource)) = proof_action else { return Some("no_proof") };
    if need["verb"].as_str() != Some(verb) || need["resource"].as_str() != Some(resource) {
        return Some("action_mismatch");
    }
    None
}

/// `None` where the reference throws (a salt shorter than 16 characters).
pub fn push_token(task_id: &str, chain_ids: &[&str], salt: &str) -> Option<String> {
    if salt.encode_utf16().count() < 16 {
        return None;
    }
    hash_canonical_strict(&json!({ "d": "atlas-pca/a2a-push/v1", "task_id": task_id, "chain": chain_digest(chain_ids)?, "salt": salt }))
}

/// `Ok(())` or the reason.
pub fn check_push(task_id: &str, chain_ids: &[&str], salt: &str, token: &Value, payload: &Value) -> Result<(), &'static str> {
    let Some(t) = token.as_str().filter(|t| !t.is_empty()) else { return Err("no_token") };
    if push_token(task_id, chain_ids, salt).as_deref() != Some(t) {
        return Err("token_mismatch");
    }
    for (key, field) in [("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId")] {
        if let Some(v) = payload.get(key).and_then(|c| c.get(field)).filter(|v| !v.is_null()) {
            return if v.as_str() == Some(task_id) { Ok(()) } else { Err("task_mismatch") };
        }
    }
    Err("task_mismatch")
}

pub fn receipt_digest(r: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": "atlas-pca/a2a-receipt-ref/v1", "r": r }))
}

pub fn verify_receipt(v: &Value, signer: &str) -> bool {
    let Some(r) = v.as_object() else { return false };
    if r.get("v").and_then(Value::as_f64) != Some(1.0) || r.get("signer").and_then(Value::as_str) != Some(signer) {
        return false;
    }
    if !s(r.get("task_id"), 4096) || !r.get("state").and_then(Value::as_str).is_some_and(|x| STATES.contains(&x)) {
        return false;
    }
    let (Some(seq), Some(_)) = (nat(r.get("seq")), nat(r.get("issued_at"))) else { return false };
    if !r.get("chain").and_then(Value::as_str).is_some_and(|c| decode_b64u_strict(c, Some(32)).is_some()) {
        return false;
    }
    let prev = r.get("prev").unwrap_or(&Value::Null);
    if !prev.is_null() && !prev.as_str().is_some_and(|p| decode_b64u_strict(p, Some(32)).is_some()) {
        return false;
    }
    if (seq == 0) != prev.is_null() {
        return false;
    }
    let mut body = Map::new();
    for k in ["v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer"] {
        body.insert(k.to_string(), r.get(k).cloned().unwrap_or(Value::Null));
    }
    verify_body(RECEIPT_DOMAIN, &Value::Object(body), signer, r.get("sig").and_then(Value::as_str))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptChain {
    Ok { terminal: bool, last_state: String },
    Refused { code: &'static str, at: Option<usize> },
}

pub fn check_receipt_chain(receipts: &[Value], signer: &str, task_id: &str, chain_ids: &[&str]) -> ReceiptChain {
    let refuse = |code, at| ReceiptChain::Refused { code, at: Some(at) };
    if receipts.is_empty() {
        return ReceiptChain::Refused { code: "empty", at: None };
    }
    let chain = chain_digest(chain_ids);
    let mut prev: Option<&Value> = None;
    for (i, r) in receipts.iter().enumerate() {
        if !verify_receipt(r, signer) {
            return refuse("bad_receipt", i);
        }
        if r["task_id"].as_str() != Some(task_id) {
            return refuse("wrong_task", i);
        }
        if r["chain"].as_str() != chain.as_deref() {
            return refuse("wrong_chain", i);
        }
        let seq = nat(r.get("seq")).unwrap_or(-1);
        match prev {
            None => {
                if seq != 0 {
                    return refuse("bad_start", i);
                }
            }
            Some(p) => {
                if TERMINAL.contains(&p["state"].as_str().unwrap_or("")) {
                    return refuse("after_terminal", i);
                }
                if seq != nat(p.get("seq")).unwrap_or(-2) + 1 || r["prev"].as_str() != receipt_digest(p).as_deref() {
                    return refuse("broken_link", i);
                }
            }
        }
        prev = Some(r);
    }
    let last = prev.map(|p| p["state"].as_str().unwrap_or("").to_string()).unwrap_or_default();
    ReceiptChain::Ok { terminal: TERMINAL.contains(&last.as_str()), last_state: last }
}

pub fn may_trigger_next(receipts: &[Value], signer: &str, task_id: &str, chain_ids: &[&str]) -> bool {
    matches!(check_receipt_chain(receipts, signer, task_id, chain_ids), ReceiptChain::Ok { last_state, .. } if last_state == "TASK_STATE_COMPLETED")
}
