//! The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
//! push-token binding and signed task-update receipts. Total: no function panics. Per-hop PCActn verification is the ordinary
//! verifier's job; this is what surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
use crate::attest::util::timing_safe_eq;
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
            Some(a) if a.len() <= 16 && a.iter().all(|e| s(Some(e), 128) && !e.as_str().unwrap_or("").chars().any(crate::action_schema::is_js_ws)) => {}
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
    // pca-need.ts:107 counts UTF-16 units, so a short non-ASCII value is bad_base64, not too_long.
    if text.encode_utf16().count() > 2048 {
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
    if !push_token(task_id, chain_ids, salt).is_some_and(|want| timing_safe_eq(want.as_bytes(), t.as_bytes())) {
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
    // a2a-receipt.ts:82: an absent prev is not null. Stripping it from a signed seq-0 receipt must not verify.
    let Some(prev) = r.get("prev") else { return false };
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
        let Some(seq) = nat(r.get("seq")) else { return refuse("bad_receipt", i) };
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
                if Some(seq) != nat(p.get("seq")).map(|n| n + 1) || r["prev"].as_str() != receipt_digest(p).as_deref() {
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

#[cfg(test)]
mod kill_tests {
    use super::*;
    use crate::agent::KeyPair;
    use crate::attest::util::b64url_enc;
    use crate::fresh_at::domain_bytes;
    use serde_json::json;

    const EMOJI: &str = "\u{1F600}";

    fn key() -> KeyPair {
        KeyPair::from_seed(&[7u8; 32])
    }
    /// A receipt validly signed over whatever members it ends up with, so only the clause under test can refuse it.
    fn rec(over: Value) -> Value {
        let mut r = json!({"v": 1, "task_id": "t", "state": "TASK_STATE_WORKING", "seq": 0, "prev": null, "chain": chain_digest(&["a"]).unwrap(), "issued_at": 1_800_000_000_000i64, "signer": key().public});
        for (k, v) in over.as_object().unwrap() {
            r[k] = v.clone();
        }
        let sig = b64url_enc(&key().sign(&domain_bytes(RECEIPT_DOMAIN, &r).unwrap()));
        r["sig"] = json!(sig);
        r
    }
    fn verifies(over: Value) -> bool {
        verify_receipt(&rec(over), &key().public)
    }
    /// A signed seq-0 receipt followed by a signed second receipt.
    fn after_first(second: Value) -> ReceiptChain {
        check_receipt_chain(&[rec(json!({})), rec(second)], &key().public, "t", &["a"])
    }
    fn first_digest() -> String {
        receipt_digest(&rec(json!({}))).unwrap()
    }
    /// The encoding of a valid need whose JSON is exactly `total` bytes.
    fn encoded(total: usize) -> String {
        let scopes = vec!["s".repeat(128); 8];
        let fixed = json!({"v": 1, "kind": "scope", "verb": "r", "resource": "", "scopes": scopes}).to_string().len();
        let need = json!({"v": 1, "kind": "scope", "verb": "r", "resource": "/".repeat(total - fixed), "scopes": scopes});
        b64url_enc(need.to_string().as_bytes())
    }

    /// a2a-receipt.ts:80: each clause alone refuses a validly signed receipt.
    #[test]
    fn verify_receipt_version_and_signer_each_refuse_alone() {
        assert!(verifies(json!({})));
        assert!(!verifies(json!({"v": 2})));
        assert!(!verifies(json!({"signer": "someone-else"})));
    }

    /// a2a-receipt.ts:80: task_id is 1 to 4096 UTF-16 units, state is one of the eight.
    #[test]
    fn verify_receipt_task_and_state_each_refuse_alone() {
        assert!(verifies(json!({"task_id": "x".repeat(4096)})));
        assert!(verifies(json!({"task_id": EMOJI.repeat(2048)})));
        assert!(!verifies(json!({"task_id": ""})));
        assert!(!verifies(json!({"task_id": "x".repeat(4097)})));
        assert!(!verifies(json!({"task_id": EMOJI.repeat(2049)})));
        for st in STATES {
            assert!(verifies(json!({"state": st})), "{st}");
        }
        assert!(!verifies(json!({"state": "TASK_STATE_UNKNOWN"})));
    }

    /// a2a-receipt.ts:82: prev is null exactly at seq 0, and absent is not null even with a valid signature.
    #[test]
    fn verify_receipt_prev_must_be_present_and_match_seq() {
        let d = first_digest();
        assert!(verifies(json!({"seq": 1, "prev": d})));
        assert!(!verifies(json!({"seq": 1})));
        assert!(!verifies(json!({"prev": d})));
        let mut stripped = rec(json!({}));
        stripped.as_object_mut().unwrap().remove("prev");
        assert!(!verify_receipt(&stripped, &key().public));
    }

    /// a2a-receipt.ts:111: a wrong seq with the right prev and the right seq with a wrong prev each break the link.
    #[test]
    fn receipt_link_needs_both_seq_and_prev() {
        let broken = ReceiptChain::Refused { code: "broken_link", at: Some(1) };
        let d = first_digest();
        assert_eq!(after_first(json!({"seq": 1, "prev": d})), ReceiptChain::Ok { terminal: false, last_state: "TASK_STATE_WORKING".into() });
        assert_eq!(after_first(json!({"seq": 2, "prev": d})), broken);
        assert_eq!(after_first(json!({"seq": 1, "prev": b64url_enc(&[9u8; 32])})), broken);
    }

    /// a2a-receipt.ts:108: a chain whose first receipt is validly signed at seq 1 is bad_start.
    #[test]
    fn receipt_chain_starts_at_zero() {
        let first = rec(json!({"seq": 1, "prev": first_digest()}));
        assert_eq!(check_receipt_chain(&[first], &key().public, "t", &["a"]), ReceiptChain::Refused { code: "bad_start", at: Some(0) });
    }

    /// pca-need.ts:72-73: optional and, when present, 1 to 128 UTF-16 units.
    #[test]
    fn need_grant_ref_and_policy_digest() {
        let err = |k: &str, v: Value| {
            let mut n = json!({"v": 1, "kind": "scope", "verb": "read", "resource": "/r"});
            n[k] = v;
            need_error(&n)
        };
        for k in ["grant_ref", "policy_digest"] {
            assert_eq!(err(k, json!("g")), None, "{k}");
            assert_eq!(err(k, json!("g".repeat(128))), None, "{k}");
            assert_eq!(err(k, json!(EMOJI.repeat(64))), None, "{k}");
            for bad in [json!(""), json!("g".repeat(129)), json!(EMOJI.repeat(65)), json!(1), Value::Null] {
                assert_eq!(err(k, bad.clone()), Some("bad_field"), "{k} {bad}");
            }
        }
    }

    /// pca-need.ts:20,107: at most 2048 UTF-16 units; the cap counts units, not bytes.
    #[test]
    fn decode_need_length_boundary() {
        let at_cap = encoded(1536);
        assert_eq!(at_cap.len(), 2048);
        assert!(decode_need(&json!(at_cap)).is_ok());
        let over = encoded(1539);
        assert_eq!(over.len(), 2052);
        assert_eq!(decode_need(&json!(over)), Err("too_long"));
        assert_eq!(decode_need(&json!("A".repeat(2049))), Err("too_long"));
        assert_eq!(decode_need(&json!("\u{e9}".repeat(2048))), Err("bad_base64"));
        assert_eq!(decode_need(&json!("\u{e9}".repeat(2049))), Err("too_long"));
    }

    /// a2a-auth.ts:267: at least 16 UTF-16 units.
    #[test]
    fn push_token_salt_boundary() {
        let tok = |salt: String| push_token("t", &["a"], &salt);
        assert!(tok("x".repeat(16)).is_some());
        assert!(tok(EMOJI.repeat(8)).is_some());
        assert!(tok("x".repeat(15)).is_none());
        assert!(tok("\u{e9}".repeat(15)).is_none());
        assert!(tok(format!("{}x", EMOJI.repeat(7))).is_none());
    }
}
