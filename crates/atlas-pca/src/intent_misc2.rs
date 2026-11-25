//! JSON-valued entry points of the Intent Layer helpers that the typed modules keep crate-private: the strict-artifact value tests and
//! lookups, the RFC 9457 problem of an intent outcome, the classifier verdict checks, and the receipt / key-set / monitor helpers. Each
//! takes and returns the reference's own member shapes (`serde_json::Value`); where the reference throws, a function returns `Err`.
use serde_json::{json, Map, Value};

use super::intent_acc::{acc_receipt_digest, monitor_states, sequencer_key_set_digest, ACC_RECEIPT_CORE_DOMAIN};
use super::intent_strict::*;
use super::{canonicalize_strict, hash_canonical_strict};

/// The base of a problem `type` URI.
pub const PROBLEM_BASE: &str = "https://atlasauth.net/pca/problems/";
/// The outcomes an intent problem answers.
pub const INTENT_PROBLEM_KINDS: [&str; 4] = ["intent-required", "intent-denied", "schema-violation", "ceiling"];
/// The friction tiers of a question.
pub const FRICTIONS: [&str; 4] = ["tap", "hold", "typed", "device"];
/// The event statuses a session history records, and the ones that count against an accumulator.
pub const EVENT_STATUSES: [&str; 4] = ["reserved", "committed", "released", "reverted"];
pub const COUNTED_STATUSES: [&str; 2] = ["reserved", "committed"];

// ---- strict-artifact helpers -----------------------------------------------------------------------------------------------------

/// `isPlainObject`: a JSON object that is not an array (a JSON value has no prototype).
pub fn is_plain_object(v: &Value) -> bool {
    v.is_object()
}

/// `isSafeInt` / `isClock`: a safe integer that is not `-0`.
pub fn is_safe_int(v: &Value) -> bool {
    sint(Some(v)).is_some()
}

/// `isScalar`: a string, a boolean or a safe integer.
pub fn is_scalar_value(v: &Value) -> bool {
    is_scalar(Some(v))
}

/// `utf8Len`: the number of UTF-8 bytes.
pub fn utf8_len(s: &str) -> usize {
    s.len()
}

/// `isBoundedString(v, max)`: a non-empty string of at most `max` UTF-8 bytes (`max` is any double: a NaN or negative one admits nothing).
pub fn is_bounded_string(v: &Value, max: f64) -> bool {
    matches!(v, Value::String(s) if !s.is_empty() && (s.len() as f64) <= max)
}

/// `isDigest`: canonical base64url of exactly 32 bytes.
pub fn is_digest(v: &Value) -> bool {
    b32(Some(v))
}

/// `isPathSegment(v)`: the segment regexp is tested on `String(v)` (a number or `null` is coerced, as the reference does).
pub fn is_path_segment_value(v: &Value) -> bool {
    is_path_segment(&super::intent_v2::js_value_string(v))
}

/// `isParamPath`.
pub fn is_param_path_value(v: &Value) -> bool {
    is_param_path(Some(v))
}

/// `closedMembers(o, required, optional, where)`: `Null` when closed, else the reason (`where` defaults to `object`).
pub fn closed_members_value(o: &Value, required: &[&str], optional: &[&str], wher: Option<&str>) -> Value {
    match o.as_object() {
        Some(m) => closed_members_error(m, required, optional, wher.unwrap_or("object")).map_or(Value::Null, Value::String),
        None => Value::String("not an object".into()),
    }
}

/// `pinPqOk`.
pub fn pin_pq_ok_value(v: &Value) -> bool {
    // an absent pin member is not expressible as a value: `null` is the malformed JSON null
    pin_pq_ok(Some(v))
}

/// `artifactSuiteError(a)`: `Null` when usable, else the reason.
pub fn artifact_suite_error_value(a: &Value) -> Value {
    match a.as_object() {
        Some(m) => artifact_suite_error(m).map_or(Value::Null, Value::String),
        None => Value::String("artifact must be an object".into()),
    }
}

/// `artifactMessage(domain, artifact)`: the bytes an artifact signature covers. `Err` where the body is not strictly canonical.
pub fn artifact_message_bytes(domain: &str, artifact: &Value) -> Result<Vec<u8>, String> {
    let m = artifact.as_object().ok_or("artifact must be an object")?;
    artifact_message(domain, m).ok_or_else(|| "the body is not strictly canonical".to_string())
}

/// `verifyArtifactSig(domain, artifact, pin)`: `pin` is the pinned Ed25519 key (a string) or `{pk, pq_pk?}`. Total.
pub fn verify_artifact_sig_value(domain: &str, artifact: &Value, pin: &Value) -> bool {
    let Some(m) = artifact.as_object() else { return false };
    let (pk, pq) = match pin {
        Value::String(pk) => (pk.as_str(), None),
        Value::Object(p) => match p.get("pk").and_then(Value::as_str) {
            Some(pk) => (pk, p.get("pq_pk")),
            None => return false,
        },
        _ => return false,
    };
    verify_artifact_sig(domain, m, pk, pq)
}

/// `artifactRef(refDomain, slot, artifact)`. `Err` where the reference throws (a value outside the strict profile).
pub fn artifact_ref_value(ref_domain: &str, slot: &str, artifact: &Value) -> Result<String, String> {
    artifact_ref(ref_domain, slot, artifact).ok_or_else(|| "the artifact is not strictly canonical".to_string())
}

/// `resolveParamPath(params, path)`: `{found, value?}`.
pub fn resolve_param_path_value(params: &Value, path: &Value) -> Value {
    match path.as_str().and_then(|p| resolve_param_path(params, p)) {
        Some(v) => json!({"found": true, "value": v}),
        None => json!({"found": false}),
    }
}

/// `setNested({root, path, value})`: `{ok, root}` with the root as left by the call (it is mutated in place, a collision leaves what was
/// created on the way).
pub fn set_nested_value(root: &Value, path: &str, value: &Value) -> Value {
    let mut r = root.as_object().cloned().unwrap_or_default();
    let ok = super::intent_wb::set_nested(&mut r, path, value.clone());
    json!({"ok": ok, "root": Value::Object(r)})
}

/// `ownGet(o, k)`: the own member `k` of `o`, `null` when `o` is not an object or lacks it.
pub fn own_get(o: &Value, k: &str) -> Value {
    o.as_object().and_then(|m| m.get(k)).cloned().unwrap_or(Value::Null)
}

// ---- the signed question and its problem -----------------------------------------------------------------------------------------

/// `cellCoordsError(coords)`.
pub fn cell_coords_error_value(c: &Value) -> Value {
    super::signers_more::cell_coords_error(c).map_or(Value::Null, Value::String)
}

/// `intentRequiredShapeError(b, {signed})`: the signed shape unless `signed` is `false`.
pub fn intent_required_shape_error_value(b: &Value, signed: bool) -> Value {
    let e = if signed { super::wallet_channel::intent_required_shape_error(b) } else { super::signers_more::intent_required_body_error(b) };
    e.map_or(Value::Null, Value::String)
}

/// `verifyIntentRequiredAt(b, keys, now)`: the clock is required, a `now` that is not a safe integer is the denial
/// `the verifier clock is not a safe integer (fail closed)`.
pub fn verify_intent_required_at(b: &Value, keys: &Value, now: &Value) -> Value {
    super::wallet_channel::verify_intent_required(b, Some(keys), Some(now))
}

fn js_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

/// `intentProblem(kind, {detail?, body?})`: the RFC 9457 response of an intent outcome, `{status: 403, headers, body}`. `Err` for an
/// `intent-required` problem without the signed body. A kind this module does not know yields a problem without a title and with
/// `error="undefined"`, as the reference does.
pub fn intent_problem(kind: &Value, opts: &Value) -> Result<Value, String> {
    let name = super::intent_v2::js_value_string(kind);
    let (error, title) = match kind.as_str() {
        Some("intent-required") => (Some("intent_required"), Some("Principal confirmation required for this action")),
        Some("intent-denied") => (Some("intent_denied"), Some("The principal does not intend this action")),
        Some("schema-violation") => (Some("schema_violation"), Some("The action does not conform to the site action schema")),
        Some("ceiling") => (Some("ceiling"), Some("The action is outside a ceiling the principal cannot widen")),
        _ => (None, None),
    };
    let detail = opts.get("detail").filter(|d| !d.is_null());
    let body = opts.get("body").filter(|b| js_truthy(Some(*b)));
    let mut params = vec![format!("error=\"{}\"", error.unwrap_or("undefined"))];
    if kind.as_str() == Some("intent-required") {
        let b = body.ok_or("intentProblem: intent-required needs the signed body")?;
        params.push(format!("session=\"{}\"", js_opt_string(b.get("session"))));
        params.push(format!("question=\"{}\"", js_opt_string(b.get("question_id"))));
    }
    let mut out = Map::new();
    out.insert("type".into(), json!(format!("{PROBLEM_BASE}{name}")));
    if let Some(t) = title {
        out.insert("title".into(), json!(t));
    }
    out.insert("status".into(), json!(403));
    if let Some(d) = detail {
        out.insert("detail".into(), d.clone());
    }
    if let Some(b) = body {
        out.insert("pca".into(), b.clone());
    }
    Ok(json!({
        "status": 403,
        "headers": {"WWW-Authenticate": format!("PCA {}", params.join(", ")), "Content-Type": "application/problem+json"},
        "body": Value::Object(out),
    }))
}

// ---- classifier verdicts ---------------------------------------------------------------------------------------------------------

/// `validateClassifierVerdictWire(v)`: `Null` when well-formed, else the reason.
pub fn validate_classifier_verdict_wire(v: &Value) -> Value {
    super::intent_wb::verdict_wire_error(v).map_or(Value::Null, Value::String)
}

/// `classifierContentDigest(value)`: b64u(sha256(strictCanonical(value))). `Err` outside the strict profile.
pub fn classifier_content_digest(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "the content is not strictly canonical".to_string())
}

/// `classifierVerdictRef(v)`: the content address committed in `intent_session.classes[]`.
pub fn classifier_verdict_ref(v: &Value) -> Result<String, String> {
    artifact_ref_value(super::intent_wb::CLASSIFIER_REF_DOMAIN, "c", v)
}

/// `validateClassifierPolicy(p)`: `Null` when well-formed, else the reason.
pub fn validate_classifier_policy(p: &Value) -> Value {
    super::intent_wb::validate_classifier_policy(p).map_or(Value::Null, Value::String)
}

/// `classifierCheckActive(input)`: true iff `committed` or `policy.classifiers` is a non-empty array.
pub fn classifier_check_active(input: &Value) -> bool {
    let Some(o) = input.as_object() else { return false };
    super::intent_wb::classifier_check_active(o.get("committed"), o.get("policy").and_then(|p| p.get("classifiers")))
}

/// `decideClassifierDimensions(input)`: `{ok: true, classes, votes}` or `{ok: false, reason}`.
pub fn decide_classifier_dimensions_value(input: &Value) -> Value {
    let d = super::intent_wb::decide_classifier_dimensions(input);
    if d.ok {
        json!({"ok": true, "classes": Value::Object(d.classes), "votes": Value::Object(d.votes)})
    } else {
        json!({"ok": false, "reason": d.reason})
    }
}

/// `verifyClassifierAttestation(v, attestation, approved)`: bind the verdict's signed `measurement` to a verified measured TEE.
pub fn verify_classifier_attestation(v: &Value, attestation: &Value, approved: &Value) -> Value {
    if !v.is_object() {
        return json!({"ok": false, "reason": "verdict must be an object"});
    }
    super::intent_kit4::semantic::verify_judge_attestation(v.get("measurement").unwrap_or(&Value::Null), attestation, approved)
}

// ---- monitors, distinct keys, receipts -------------------------------------------------------------------------------------------

/// `monitorStates(m)`: the state set of a monitor.
pub fn monitor_states_value(m: &Value) -> Value {
    // the reference's switch has no default: an unknown kind returns `undefined` (null in JSON), not an empty list
    if !matches!(s(m.get("kind")), Some("requires_prior" | "precedes" | "never" | "always" | "responds_within")) {
        return Value::Null;
    }
    json!(monitor_states(m))
}

/// `monitorInitialState(m)`.
pub fn monitor_initial_state(m: &Value) -> &'static str {
    match s(m.get("kind")) {
        Some("requires_prior") | Some("precedes") => "unmet",
        Some("never") => "clean",
        Some("always") => "ok",
        _ => "idle",
    }
}

/// `distinctKey(x)`: the strict canonical JSON text of a string or a safe integer, else `None`.
pub fn distinct_key(x: &Value) -> Option<String> {
    match x {
        Value::String(_) => canonicalize_strict(x).ok(),
        _ if sint(Some(x)).is_some() => canonicalize_strict(x).ok(),
        _ => None,
    }
}

/// `sortedDistinct(keys)`: the distinct keys in UTF-8 byte order.
pub fn sorted_distinct(keys: &[String]) -> Vec<String> {
    let mut v: Vec<String> = keys.to_vec();
    sort_utf8(&mut v);
    v.dedup();
    v
}

/// `accReceiptCoreDigest(r)`: the receipt's log leaf content, without its `ledger` position, `kid` and signature fields.
pub fn acc_receipt_core_digest(r: &Value) -> Result<String, String> {
    let mut core = Map::new();
    for k in ["v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at"] {
        if let Some(x) = r.get(k) {
            core.insert(k.into(), x.clone());
        }
    }
    hash_canonical_strict(&json!({"d": ACC_RECEIPT_CORE_DOMAIN, "r": Value::Object(core)}))
        .ok_or_else(|| "the receipt is not strictly canonical".to_string())
}

/// `accReceiptDigest(r)`.
pub fn acc_receipt_digest_value(r: &Value) -> Result<String, String> {
    acc_receipt_digest(r).ok_or_else(|| "the receipt is not strictly canonical".to_string())
}

/// `sequencerKeySetDigest(k)`.
pub fn sequencer_key_set_digest_value(k: &Value) -> Result<String, String> {
    sequencer_key_set_digest(k).ok_or_else(|| "the key set is not strictly canonical".to_string())
}

/// The reference's exported constants of the five intent modules, with the regular expressions as `{"$regex": source}`.
pub fn constants() -> Value {
    use super::intent_acc::*;
    use super::intent_wb::*;
    let re = |src: &str| json!({ "$regex": src });
    json!({
        "DATA_CLASS_RE": re("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*$"),
        "INTENT_NAME_RE": re("^[a-z][a-z0-9_]{0,63}$"),
        "PARAM_SEGMENT_RE": re("^[A-Za-z0-9_-]{1,64}$"),
        "SUITE_MEMBERS": SUITE_MEMBERS,
        "FRICTIONS": FRICTIONS,
        "INTENT_ACTION_DOMAIN": super::intent_kit::jit::INTENT_ACTION_DOMAIN,
        "INTENT_PROBLEM_KINDS": INTENT_PROBLEM_KINDS,
        "INTENT_REQUIRED_DOMAIN": super::signers_more::INTENT_REQUIRED_DOMAIN,
        "PROBLEM_BASE": PROBLEM_BASE,
        "INTENT_CLASSIFIER_DOMAIN": CLASSIFIER_DOMAIN,
        "INTENT_CLASSIFIER_REF_DOMAIN": CLASSIFIER_REF_DOMAIN,
        "MAX_CLASSIFIER_LABELS": MAX_CLASSIFIER_LABELS,
        "MAX_COMMITTED_CLASSES": MAX_COMMITTED_CLASSES,
        "ACC_AGGS": ACC_AGGS,
        "ACC_ID_RE": re("^[A-Za-z0-9_]{1,64}$"),
        "ACC_RECEIPT_CORE_DOMAIN": ACC_RECEIPT_CORE_DOMAIN,
        "ACC_RECEIPT_DOMAIN": ACC_RECEIPT_DOMAIN,
        "ACC_RECEIPT_REF_DOMAIN": ACC_RECEIPT_REF_DOMAIN,
        "ACC_RESERVE_DOMAIN": ACC_RESERVE_DOMAIN,
        "ACC_SCOPES": ACC_SCOPES,
        "DEFAULT_MAX_KEYSET_AGE_MS": DEFAULT_MAX_KEYSET_AGE_MS,
        "DEFAULT_MAX_RECEIPT_AGE_MS": DEFAULT_MAX_RECEIPT_AGE_MS,
        "KID_RE": re("^[A-Za-z0-9_.:-]{1,64}$"),
        "MAX_MONITOR_WITHIN": MAX_MONITOR_WITHIN,
        "MAX_RECEIPT_LIFETIME_MS": MAX_RECEIPT_LIFETIME_MS,
        "MAX_SESSION_ACCUMULATORS": MAX_SESSION_ACCUMULATORS,
        "MAX_SESSION_MONITORS": MAX_SESSION_MONITORS,
        "MONITOR_KINDS": MONITOR_KINDS,
        "RECEIPT_SKEW_MS": RECEIPT_SKEW_MS,
        "SEQUENCER_KEYS_DOMAIN": SEQUENCER_KEYS_DOMAIN,
        "SEQUENCER_KEYS_REF_DOMAIN": SEQUENCER_KEYS_REF_DOMAIN,
        "COUNTED_STATUSES": COUNTED_STATUSES,
        "EVENT_STATUSES": EVENT_STATUSES,
    })
}
