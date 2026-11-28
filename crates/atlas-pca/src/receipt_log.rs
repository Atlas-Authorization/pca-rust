//! Action receipts (`receipt.ts`): the principal's own tamper-evident, hash-chained log of what their agents did and how each action was
//! verified, so they hold independently checkable evidence without trusting the server to replay history. Each receipt commits to the
//! previous one, so a dropped or altered entry is detectable. Pure (hashing only). Receipts are JSON values with the reference's members.
use crate::hash_canonical_strict;
use serde_json::{json, Map, Value};

fn body(r: &Value) -> Value {
    let g = |k: &str| r.get(k).cloned().unwrap_or(Value::Null);
    json!({"d": "atlas-pca/receipt/v1", "seq": g("seq"), "at": g("at"), "actionDigest": g("actionDigest"), "verb": g("verb"), "resource": g("resource"),
        "outcome": g("outcome"), "checks": g("checks"), "prev": g("prev")})
}

/// The next receipt of a chain for a verified action. `verify` is `{allow, checks?}`; `at` defaults to the PCActn's `iat`. `Err` when the
/// PCActn is outside the strict JSON profile.
pub fn receipt_for(prev_hash: &str, seq: i64, pcactn: &Value, verify: &Value, at: Option<i64>) -> Result<Value, String> {
    let digest = hash_canonical_strict(pcactn).ok_or("receiptFor: the PCActn is outside the strict JSON profile")?;
    let mut r = Map::new();
    r.insert("seq".into(), json!(seq));
    r.insert("at".into(), at.map_or_else(|| pcactn.get("iat").cloned().unwrap_or(Value::Null), |a| json!(a)));
    r.insert("actionDigest".into(), json!(digest));
    r.insert("verb".into(), pcactn["action"]["verb"].clone());
    r.insert("resource".into(), pcactn["action"]["resource"].clone());
    r.insert("outcome".into(), json!(if verify.get("allow") == Some(&json!(true)) { "allow" } else { "deny" }));
    if let Some(c) = verify.get("checks").filter(|c| !c.is_null()) {
        r.insert("checks".into(), c.clone());
    }
    r.insert("prev".into(), json!(prev_hash));
    let hash = hash_canonical_strict(&body(&Value::Object(r.clone()))).ok_or("receiptFor: the receipt is outside the strict JSON profile")?;
    r.insert("hash".into(), json!(hash));
    Ok(Value::Object(r))
}

/// The head hash of a log: one value that commits to the entire history (`""` for an empty log).
pub fn receipt_head(log: &[Value]) -> String {
    log.last().and_then(|r| r.get("hash")).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Append a verified action to a receipt log, chaining to the last entry.
pub fn append_receipt(log: &[Value], pcactn: &Value, verify: &Value, at: Option<i64>) -> Result<Vec<Value>, String> {
    let seq = log.last().and_then(|r| r.get("seq")).and_then(Value::as_i64).unwrap_or(-1) + 1;
    let mut out = log.to_vec();
    out.push(receipt_for(&receipt_head(log), seq, pcactn, verify, at)?);
    Ok(out)
}

/// `Ok(())` when the log is an intact hash chain (sequential, correctly linked, every hash matches); else `Err((seq of the first broken
/// link, reason))`. A receipt the reference cannot even hash (a missing member) is reported as a tampered body, which refuses all the same.
pub fn verify_receipt_chain(log: &[Value]) -> Result<(), (Value, String)> {
    match verify_receipt_chain_js(log) {
        Ok(Ok(())) => Ok(()),
        Ok(Err((seq, why))) => Err((seq.unwrap_or(Value::Null), why)),
        Err(_) => Err((Value::Null, "hash mismatch (tampered body)".to_string())),
    }
}

/// [`verify_receipt_chain`] with the reference's exact outcomes: the outer `Err` is where `verifyReceiptChain` throws (a receipt with a
/// missing member cannot be canonicalised), and a broken link at a missing `seq` has no `brokenAt` (`None`, JavaScript `undefined`).
#[allow(clippy::type_complexity)]
pub fn verify_receipt_chain_js(log: &[Value]) -> Result<Result<(), (Option<Value>, String)>, String> {
    let mut prev = String::new();
    for (i, r) in log.iter().enumerate() {
        let seq = r.get("seq").cloned();
        let shown = seq.as_ref().map_or_else(|| "undefined".to_string(), crate::adapters::js_string);
        if r.get("seq").and_then(Value::as_i64) != Some(i as i64) {
            return Ok(Err((seq, format!("seq {shown} out of order (expected {i})"))));
        }
        if r.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            return Ok(Err((seq, format!("prev link mismatch at seq {shown}"))));
        }
        // every member of the hashed body except `checks` is read as-is: an absent one is `undefined`, which the canonicalizer refuses
        if ["at", "actionDigest", "verb", "resource", "outcome"].iter().any(|k| r.get(*k).is_none()) {
            return Err("canonicalize: only JSON values are allowed".into());
        }
        let hash = r.get("hash").and_then(Value::as_str).unwrap_or("");
        match hash_canonical_strict(&body(r)) {
            Some(h) if h == hash => {}
            Some(_) => return Ok(Err((seq, format!("hash mismatch at seq {shown} (tampered body)")))),
            None => return Err("canonicalize: out of the strict profile".into()),
        }
        prev = hash.to_string();
    }
    Ok(Ok(()))
}
