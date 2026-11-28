//! Detector adapters: vendor guardrail responses (Lakera Guard v2, Prompt Security, a generic `{flagged, categories?}`) to
//! signed, tighten-only detector receipts, and the receipt machinery they need (`detector_input_digest`,
//! `detector_receipt_ref`, `detector_receipt_shape_error`, `sign_detector_receipt`). A response is `no_finding` only when it
//! is well-formed AND says nothing was detected; anything malformed or ambiguous becomes `suspicious` / `detector_error`.
//! The receipt is signed under domain `atlas-pca/detector-receipt/v1\0` with the gateway's Ed25519 key.
use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::dataflow::category_id;
use crate::hash_canonical_strict;
use crate::intent_strict::{artifact_suite_error, b32, bstr, closed_members_error, nonneg, num};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const DETECTOR_RECEIPT_DOMAIN: &str = "atlas-pca/detector-receipt/v1\0";
pub const DETECTOR_RECEIPT_REF_DOMAIN: &str = "atlas-pca/detector-receipt-ref/v1";
pub const DETECTOR_VERDICTS: [&str; 2] = ["suspicious", "no_finding"];

/// `^[a-z][a-z0-9_]{0,63}$`
fn id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// b64u(sha256(strictCanonical({d, content}))): the digest a receipt binds. Err when `content` is outside the strict profile.
pub fn detector_input_digest(content: &Value) -> Result<String, String> {
    hash_canonical_strict(&json!({"d": "atlas-pca/detector-input/v1", "content": content}))
        .ok_or_else(|| "canonicalize: content is outside the strict JSON profile".to_string())
}

/// Content address of a receipt (signature included).
pub fn detector_receipt_ref(r: &Value) -> Result<String, String> {
    hash_canonical_strict(&json!({"d": DETECTOR_RECEIPT_REF_DOMAIN, "receipt": r}))
        .ok_or_else(|| "canonicalize: receipt is outside the strict JSON profile".to_string())
}

/// `None` when the receipt is well-formed, else the reference's reason.
pub fn detector_receipt_shape_error(r: &Value) -> Option<String> {
    let Some(o) = r.as_object() else { return Some("receipt must be an object".into()) };
    if let Some(e) = closed_members_error(
        o,
        &["v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig"],
        &["session", "calibration_ref", "alg", "pq_pk", "pq_sig"],
        "receipt",
    ) {
        return Some(e);
    }
    if num(o.get("v")) != Some(1.0) || o.get("kind").and_then(Value::as_str) != Some("pca-detector-receipt") {
        return Some("not a pca-detector-receipt v1".into());
    }
    if !o.get("detector").and_then(Value::as_str).is_some_and(id_ok) {
        return Some("detector id is malformed".into());
    }
    if !bstr(o.get("version"), 64) {
        return Some("version must be 1..64 bytes".into());
    }
    if !b32(o.get("input_digest")) {
        return Some("input_digest must be a b64u 32-byte digest".into());
    }
    let verdict = o.get("verdict").and_then(Value::as_str).filter(|v| DETECTOR_VERDICTS.contains(v));
    let Some(verdict) = verdict else { return Some("verdict must be 'suspicious' or 'no_finding'".into()) };
    let cats: Option<Vec<&str>> =
        o.get("categories").and_then(Value::as_array).filter(|c| c.len() <= 8).and_then(|c| c.iter().map(|x| x.as_str().filter(|s| id_ok(s))).collect());
    let Some(cats) = cats else { return Some("categories must be 0..8 ids".into()) };
    if cats.windows(2).any(|w| w[0] >= w[1]) {
        return Some("categories must be sorted and distinct".into());
    }
    if verdict == "no_finding" && !cats.is_empty() {
        return Some("a no_finding receipt carries no categories".into());
    }
    if nonneg(o.get("iat")).is_none() {
        return Some("iat must be a non-negative integer".into());
    }
    if o.get("session").is_some() && !b32(o.get("session")) {
        return Some("session must be a b64u 32-byte id".into());
    }
    if o.get("calibration_ref").is_some() && !bstr(o.get("calibration_ref"), 256) {
        return Some("calibration_ref must be 1..256 bytes".into());
    }
    if !o.get("sig").is_some_and(Value::is_string) {
        return Some("sig must be a string".into());
    }
    artifact_suite_error(o)
}

/// Sign a receipt body with the detector gateway's Ed25519 key. Err on a body outside the strict profile or a malformed
/// receipt (`signDetectorReceipt: <reason>`).
pub fn sign_detector_receipt(body: &Value, key: &KeyPair) -> Result<Value, String> {
    let signed = sign_artifact(DETECTOR_RECEIPT_DOMAIN, body, key, &Suite { alg: None, pq: None })?;
    match detector_receipt_shape_error(&signed) {
        Some(e) => Err(format!("signDetectorReceipt: {e}")),
        None => Ok(signed),
    }
}

/// What an adapter needs besides the vendor response. `now` / `session` / `calibration_ref` are JSON values so a hostile
/// one (a fractional clock, a null session) reaches the same shape check as in the reference; `session` and
/// `calibration_ref` are present when `Some` (even `Some(Null)`).
pub struct AdapterContext<'a> {
    /// Policy id of the detector (`^[a-z][a-z0-9_]{0,63}$`).
    pub detector: String,
    /// Model / ruleset version (1..64 bytes).
    pub version: String,
    /// The exact content sent to the detector.
    pub content: Value,
    /// The gateway's signing key.
    pub secret_key: &'a KeyPair,
    /// Epoch ms.
    pub now: Value,
    pub session: Option<Value>,
    pub calibration_ref: Option<Value>,
}

fn receipt(ctx: &AdapterContext, suspicious: bool, categories: &BTreeSet<String>) -> Result<Value, String> {
    let cats: Vec<&String> = if suspicious { categories.iter().take(8).collect() } else { vec![] };
    let mut b = Map::new();
    b.insert("v".into(), json!(1));
    b.insert("kind".into(), json!("pca-detector-receipt"));
    b.insert("detector".into(), json!(ctx.detector));
    b.insert("version".into(), json!(ctx.version));
    b.insert("input_digest".into(), json!(detector_input_digest(&ctx.content)?));
    b.insert("verdict".into(), json!(if suspicious { "suspicious" } else { "no_finding" }));
    b.insert("categories".into(), json!(cats));
    b.insert("iat".into(), ctx.now.clone());
    if let Some(s) = &ctx.session {
        b.insert("session".into(), s.clone());
    }
    if let Some(c) = &ctx.calibration_ref {
        b.insert("calibration_ref".into(), c.clone());
    }
    sign_detector_receipt(&Value::Object(b), ctx.secret_key)
}

fn error_receipt(ctx: &AdapterContext) -> Result<Value, String> {
    receipt(ctx, true, &BTreeSet::from(["detector_error".to_string()]))
}

fn flagged(r: &Value) -> Option<bool> {
    r.as_object()?.get("flagged")?.as_bool()
}

/// Lakera Guard v2 `/guard` response: `{flagged, breakdown?:[{detector_type, detected}]}`.
pub fn lakera_receipt(response: &Value, ctx: &AdapterContext) -> Result<Value, String> {
    let Some(fl) = flagged(response) else { return error_receipt(ctx) };
    let mut cats = BTreeSet::new();
    if let Some(b) = response.get("breakdown") {
        let Some(items) = b.as_array() else { return error_receipt(ctx) };
        for it in items {
            let Some(detected) = it.as_object().and_then(|o| o.get("detected")).and_then(Value::as_bool) else { return error_receipt(ctx) };
            if detected {
                cats.insert(category_id(it.get("detector_type").unwrap_or(&Value::Null)));
            }
        }
    }
    let suspicious = fl || !cats.is_empty();
    if suspicious && cats.is_empty() {
        cats.insert("flagged".to_string());
    }
    receipt(ctx, suspicious, &cats)
}

/// Prompt Security `/api/protect` response (both published integration shapes: `result.action`, `result.prompt.action` /
/// `.violations`). Clean only when no action is `block` or `modify` and no violation is listed.
pub fn prompt_security_receipt(response: &Value, ctx: &AdapterContext) -> Result<Value, String> {
    let Some(r) = response.as_object().and_then(|o| o.get("result")).filter(|r| r.is_object()) else { return error_receipt(ctx) };
    let p = r.get("prompt");
    if p.is_some_and(|p| !p.is_object()) {
        return error_receipt(ctx);
    }
    let actions: Vec<&Value> = r.get("action").into_iter().chain(p.and_then(|p| p.get("action"))).collect();
    if actions.is_empty() || !actions.iter().all(|a| a.is_string()) {
        return error_receipt(ctx);
    }
    let mut cats = BTreeSet::new();
    match p.and_then(|p| p.get("violations")) {
        None => {}
        Some(Value::Array(vs)) => cats.extend(vs.iter().map(category_id)),
        Some(_) => return error_receipt(ctx),
    }
    if actions.iter().any(|a| a.as_str() == Some("block")) {
        cats.insert("blocked".to_string());
    }
    if actions.iter().any(|a| a.as_str() == Some("modify")) {
        cats.insert("modified".to_string());
    }
    receipt(ctx, !cats.is_empty(), &cats)
}

/// Any detector that answers `{flagged, categories?}`.
pub fn generic_receipt(response: &Value, ctx: &AdapterContext) -> Result<Value, String> {
    let Some(fl) = flagged(response) else { return error_receipt(ctx) };
    let mut cats = BTreeSet::new();
    match response.get("categories") {
        None => {}
        Some(Value::Array(cs)) => cats.extend(cs.iter().map(category_id)),
        Some(_) => return error_receipt(ctx),
    }
    if !fl && !cats.is_empty() {
        return error_receipt(ctx); // categories on a clean answer: ambiguous
    }
    if fl && cats.is_empty() {
        cats.insert("flagged".to_string());
    }
    receipt(ctx, fl, &cats)
}

// ---- the tighten-only fold of detector receipts --------------------------------------------------------------------------------------

/// Most receipts one fold accepts.
pub const MAX_DETECTOR_RECEIPTS: usize = 32;

/// `None` when the detector policy `{detectors: [{id, keys, on_suspicious, max_age_ms, categories?}]}` is well-formed, else the reason.
pub fn detector_policy_error(p: &Value) -> Option<String> {
    let ok_policy = p.as_object().is_some_and(|o| closed_members_error(o, &["detectors"], &[], "object").is_none());
    if !ok_policy {
        return Some("policy must be {detectors}".into());
    }
    let Some(ds) = p["detectors"].as_array().filter(|d| d.len() <= 16) else { return Some("detectors must hold at most 16 entries".into()) };
    let mut ids = BTreeSet::new();
    for d in ds {
        let Some(o) = d.as_object().filter(|o| closed_members_error(o, &["id", "keys", "on_suspicious", "max_age_ms"], &["categories"], "object").is_none())
        else {
            return Some("detector entry is malformed".into());
        };
        let id = o["id"].as_str().filter(|s| id_ok(s) && *s != "invalid" && !ids.contains(*s));
        let Some(id) = id else { return Some("detector ids must be distinct ids other than \"invalid\"".into()) };
        ids.insert(id.to_string());
        let keys_ok = o["keys"].as_array().is_some_and(|k| {
            (1..=8).contains(&k.len())
                && k.iter().all(|x| x.as_object().is_some_and(|m| m.get("pk").is_some_and(Value::is_string) && m.get("pq_pk").is_none_or(Value::is_string)))
        });
        if !keys_ok {
            return Some(format!("detector '{id}': keys must hold 1..8 pins"));
        }
        if !matches!(o["on_suspicious"].as_str(), Some("escalate" | "deny")) {
            return Some(format!("detector '{id}': on_suspicious must be escalate or deny"));
        }
        if let Some(c) = o.get("categories") {
            if !c.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|x| x.as_str().is_some_and(id_ok))) {
                return Some(format!("detector '{id}': categories must be 1+ ids"));
            }
        }
        if !crate::safe_int(&o["max_age_ms"]).is_some_and(|m| (1..=86_400_000).contains(&m)) {
            return Some(format!("detector '{id}': max_age_ms must be 1..86400000"));
        }
    }
    None
}

/// What [`detector_signal`] reads. `receipts` and `now` are JSON values so a hostile one (a non-array, a fractional clock) reaches the
/// same refusal as in the reference.
pub struct DetectorInput<'a> {
    pub receipts: Option<&'a Value>,
    pub policy: &'a Value,
    /// Digests ([`detector_input_digest`]) of the content the action carries: a receipt about anything else is not about this action.
    pub input_digests: &'a [String],
    /// The session the action belongs to, when receipts are session-bound.
    pub session: Option<&'a str>,
    pub now: &'a Value,
}

/// The fold's outcome: never something that raises a decision, fold it with [`crate::decision::tighten`].
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorOutcome {
    /// `ok` (no friction), `escalate` or `deny`.
    pub signal: &'static str,
    /// `{"detect": {<detector id>: flagged?, ..., "invalid": <rejected count>}}` for `tighten[]` rules.
    pub env: Value,
    /// Detector ids whose valid suspicious receipt acted, sorted.
    pub flagged: Vec<String>,
    /// Why each receipt was not used (`-1` is the list, the clock or the policy itself).
    pub rejected: Vec<(i64, String)>,
}

fn signal_rank(s: &str) -> u8 {
    match s {
        "ok" => 2,
        "escalate" => 1,
        _ => 0,
    }
}

fn receipt_problem(r: &Value, detectors: &[Value], digests: &[String], session: Option<&str>, now: i64) -> Option<String> {
    if let Some(e) = detector_receipt_shape_error(r) {
        return Some(format!("malformed: {e}"));
    }
    let rc = r.as_object()?;
    let name = rc["detector"].as_str()?;
    let Some(d) = detectors.iter().find(|x| x["id"].as_str() == Some(name)) else { return Some(format!("undeclared detector '{name}'")) };
    let signed = d["keys"]
        .as_array()?
        .iter()
        .any(|k| k["pk"].as_str().is_some_and(|pk| crate::intent_strict::verify_artifact_sig(DETECTOR_RECEIPT_DOMAIN, rc, pk, k.get("pq_pk"))));
    if !signed {
        return Some(format!("detector '{name}': no pinned key signed it"));
    }
    if !rc["input_digest"].as_str().is_some_and(|x| digests.iter().any(|d| d == x)) {
        return Some(format!("detector '{name}': the receipt is about other content"));
    }
    if let Some(s) = rc.get("session") {
        if s.as_str() != session {
            return Some(format!("detector '{name}': bound to another session"));
        }
    }
    let iat = crate::safe_int(&rc["iat"])?;
    if iat > now {
        return Some(format!("detector '{name}': from the future"));
    }
    if now.saturating_sub(iat) > crate::safe_int(&d["max_age_ms"])? {
        return Some(format!("detector '{name}': stale"));
    }
    None
}

/// The tighten-only fold of detector receipts. Total. A malformed policy is `deny`. Per receipt: shape, declared detector, a pinned key's
/// signature, content in `input_digests`, session, `iat <= now`, age `<= max_age_ms`. A valid `suspicious` with an acting category lowers the
/// signal to the detector's `on_suspicious`; a valid `no_finding` does nothing; an invalid receipt lowers it to `escalate`. So the outcome with
/// any set of receipts is at most the outcome with none, and adding valid `no_finding` receipts never changes it.
pub fn detector_signal(input: &DetectorInput) -> DetectorOutcome {
    if let Some(pe) = detector_policy_error(input.policy) {
        return DetectorOutcome { signal: "deny", env: json!({"detect": {"invalid": 0}}), flagged: vec![], rejected: vec![(-1, format!("policy: {pe}"))] };
    }
    let detectors: Vec<Value> = input.policy["detectors"].as_array().cloned().unwrap_or_default();
    let mut env = Map::new();
    for d in &detectors {
        env.insert(d["id"].as_str().unwrap_or("").to_string(), json!(false));
    }
    let (mut signal, mut flagged, mut rejected) = ("ok", BTreeSet::new(), Vec::new());
    let lower = |s: &'static str, signal: &mut &'static str| {
        if signal_rank(s) < signal_rank(signal) {
            *signal = s;
        }
    };
    match (input.receipts.map_or(Some(&[][..]), |r| r.as_array().map(Vec::as_slice)), crate::safe_int(input.now)) {
        (Some(receipts), Some(now)) if receipts.len() <= MAX_DETECTOR_RECEIPTS => {
            for (index, r) in receipts.iter().enumerate() {
                if let Some(why) = receipt_problem(r, &detectors, input.input_digests, input.session, now) {
                    rejected.push((index as i64, why));
                    lower("escalate", &mut signal);
                    continue;
                }
                if r["verdict"].as_str() != Some("suspicious") {
                    continue;
                }
                let Some(d) = detectors.iter().find(|x| x["id"] == r["detector"]) else { continue };
                let cats: Vec<&str> = r["categories"].as_array().map(|c| c.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                if let Some(acting) = d.get("categories").and_then(Value::as_array) {
                    if !cats.is_empty() && !cats.iter().any(|c| acting.iter().any(|a| a.as_str() == Some(c))) {
                        continue;
                    }
                }
                let id = d["id"].as_str().unwrap_or("").to_string();
                env.insert(id.clone(), json!(true));
                flagged.insert(id);
                lower(if d["on_suspicious"].as_str() == Some("deny") { "deny" } else { "escalate" }, &mut signal);
            }
        }
        _ => {
            lower("escalate", &mut signal);
            rejected.push((-1, "receipt list or clock malformed".into()));
        }
    }
    env.insert("invalid".into(), json!(rejected.len()));
    DetectorOutcome { signal, env: json!({"detect": Value::Object(env)}), flagged: flagged.into_iter().collect(), rejected }
}
