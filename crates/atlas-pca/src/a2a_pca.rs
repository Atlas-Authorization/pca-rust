//! `@atlasauth/pca-a2a` (the adapter half): proof-carrying A2A tasks, the AUTH_REQUIRED mapping (typed need parked on a task, resumed
//! by an answer), the extension declaration on an Agent Card, per-hop delegation, push-notification tokens, signed task-update
//! receipts, the extended Agent Card and the AP2 payment-mandate envelope. The need / push / receipt primitives are the ones in
//! [`crate::a2a`]; signed Agent Cards and JCS are in [`crate::a2a_card`].
//!
//! Tasks, messages, cards and options are JSON values with the reference's member names (`expectedRootIssuer`, `requireChecks`,
//! `humanSignerSet`, ...). Where the reference throws, the function returns `Err` with the reference's message (a JavaScript
//! `TypeError` text for a null where an object is read). A refusal is `{ok: false, reason}`. Per-hop PCActn verification is the core
//! verifier ([`crate::verify_pcactn_core_with`]) plus the caller's revocation hook ([`A2aHooks`]): the stateless verifier cannot see
//! revocation, so by default (no hook) the required `revocation` check is not met and the PCActn is refused (fail closed).
//!
//! shortcut: `context` is a JSON value (the reference also accepts a function of the PCActn); hooks other than `revocation`
//! (attestation, threshold, zk) are not wired; `human_present` accepts an agent share only as an explicit threshold share (never the
//! leaf signature stand-in); `authRequiredStatus` takes `now` as epoch milliseconds only. All of these refuse more, never less.
use crate::a2a;
use crate::action_schema::is_js_ws;
use crate::agent::KeyPair;
use crate::agentcard::iso_string;
use crate::fresh_at::domain_bytes;
use crate::oauth::truthy;
use crate::pca_grant::{chain_digest, parse_details};
use crate::{b64_encode, canonicalize_strict, hash_canonical_strict, verify_pcactn_core_with, VerifyOptions};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

pub const PCA_A2A_EXTENSION_URI: &str = "https://atlasauth.net/a2a/ext/pca/v2";
pub const TASK_STATE_AUTH_REQUIRED: &str = "TASK_STATE_AUTH_REQUIRED";
pub const TASK_STATE_INPUT_REQUIRED: &str = "TASK_STATE_INPUT_REQUIRED";
/// Where the typed need rides on a status message, and the answer's digest of it on the answering message.
pub const NEED_KEY: &str = "https://atlasauth.net/a2a/ext/pca/v2#need";
/// Where a signed task-update receipt rides on a status update / message / task.
pub const RECEIPT_KEY: &str = "https://atlasauth.net/a2a/ext/pca/v2#receipt";
pub const A2A_AP2_CONTEXT: [&str; 2] = ["https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2"];
pub const A2A_RECEIPT_DOMAIN: &str = a2a::RECEIPT_DOMAIN;
/// The error of a verifier configured with no authority.
pub const AUTHORITY_ERROR: &str = "pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority";

const PARAM_KEYS: [&str; 4] = ["aud", "suites", "grants", "policy_digest"];
const TERMINAL: [&str; 4] = ["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"];
const STATES: [&str; 8] = [
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_AUTH_REQUIRED",
];
/// The reference's stateless required checks: without a revocation hook a task is refused.
const DEFAULT_REQUIRED_CHECKS: [&str; 6] = ["counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"];

pub fn constants() -> Value {
    json!({
        "PCA_A2A_EXTENSION_URI": PCA_A2A_EXTENSION_URI,
        "TASK_STATE_AUTH_REQUIRED": TASK_STATE_AUTH_REQUIRED,
        "TASK_STATE_INPUT_REQUIRED": TASK_STATE_INPUT_REQUIRED,
        "A2A_AP2_CONTEXT": A2A_AP2_CONTEXT,
        "A2A_RECEIPT_DOMAIN": A2A_RECEIPT_DOMAIN,
        "RECEIPT_KEY": RECEIPT_KEY,
    })
}

// ---- JavaScript value semantics the reference relies on --------------------------------------------------------------------

/// `v.k` for an object (anything else, and a missing member, is `undefined`).
fn gv<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

fn gvo<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    v.and_then(|x| gv(x, k))
}

/// `x.k`: a `TypeError` for null / undefined, `undefined` for a missing member or a non-object.
fn read<'a>(x: Option<&'a Value>, k: &str) -> Result<Option<&'a Value>, String> {
    match x {
        None => Err(format!("Cannot read properties of undefined (reading '{k}')")),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{k}')")),
        Some(v) => Ok(gv(v, k)),
    }
}

/// `isObj(v) ? v : undefined`.
fn objv(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| x.is_object())
}

fn nullish(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// `a === b` (an object or array is never equal to another).
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) | (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        _ => false,
    }
}

/// `Number.isSafeInteger(v)` (so -0 passes), as the number.
fn safe_int(v: Option<&Value>) -> Option<f64> {
    let f = v.filter(|x| x.is_number())?.as_f64()?;
    (f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f)
}

fn neg_zero(v: Option<&Value>) -> bool {
    v.and_then(Value::as_f64).is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

/// `Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0)`.
fn uint(v: Option<&Value>) -> Option<f64> {
    safe_int(v).filter(|f| *f >= 0.0 && !neg_zero(v))
}

fn utf16(s: &str) -> usize {
    s.encode_utf16().count()
}

fn str_in(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| utf16(s) > 0 && utf16(s) <= max)
}

/// `{...v}`: the own enumerable members of an object, the index members of an array or a string, nothing for the rest.
fn spread_obj(v: &Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m.clone(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            units.iter().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[*u])))).collect()
        }
        _ => Map::new(),
    }
}

/// `{...(v ?? {})}`.
fn spread_or_empty(v: Option<&Value>) -> Map<String, Value> {
    v.filter(|x| !x.is_null()).map(spread_obj).unwrap_or_default()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `new Date(now).toISOString()`: a RangeError for anything that is not a time-valid number.
fn iso_of(now: Option<&Value>) -> Result<String, String> {
    now.filter(|n| n.is_number()).and_then(Value::as_f64).and_then(iso_string).ok_or_else(|| "Invalid time value".to_string())
}

// ---- proof-carrying tasks --------------------------------------------------------------------------------------------------

fn with_key(metadata: Option<&Value>, key: &str, v: &Value) -> Value {
    let mut m = spread_or_empty(metadata);
    m.insert(key.to_string(), v.clone());
    Value::Object(m)
}

/// A copy of the task with the PCActn on its metadata (the input is not mutated). `Err` for a null task.
pub fn attach_pca_to_a2a_task(task: &Value, pca: &Value) -> Result<Value, String> {
    let md = read(Some(task), "metadata")?;
    let mut out = spread_obj(task);
    out.insert("metadata".into(), with_key(md, PCA_A2A_EXTENSION_URI, pca));
    Ok(Value::Object(out))
}

pub fn attach_pca_to_a2a_message(message: &Value, pca: &Value) -> Result<Value, String> {
    attach_pca_to_a2a_task(message, pca)
}

fn read_pca(metadata: Option<&Value>) -> Option<&Value> {
    gvo(metadata, PCA_A2A_EXTENSION_URI).filter(|v| v.is_object())
}

/// The PCActn a task carries: its metadata, then the status message, then the most recent history message.
pub fn extract_pca(task: &Value) -> Option<Value> {
    if let Some(p) = read_pca(gv(task, "metadata")) {
        return Some(p.clone());
    }
    let status = gv(task, "status");
    if let Some(p) = read_pca(gvo(gvo(status, "message"), "metadata")) {
        return Some(p.clone());
    }
    if let Some(h) = gv(task, "history").and_then(Value::as_array) {
        for m in h.iter().rev() {
            if let Some(p) = read_pca(gv(m, "metadata")) {
                return Some(p.clone());
            }
        }
    }
    None
}

pub fn extract_pca_from_message(message: &Value) -> Option<Value> {
    read_pca(gv(message, "metadata")).cloned()
}

fn assert_authority(opts: &Value) -> Result<(), String> {
    let has_grant = gv(opts, "grant").is_some_and(|g| g.is_object() || g.is_array());
    let has_issuer = gv(opts, "expectedRootIssuer").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if has_grant || has_issuer {
        Ok(())
    } else {
        Err(AUTHORITY_ERROR.to_string())
    }
}

/// The caller's hooks for the per-hop verification. `revocation(ctx)` gets `{pcactn, grant, context}` and returns
/// `{enforced, ok, reason?}`; without one the (required) `revocation` check is not met.
#[derive(Clone, Copy, Default)]
pub struct A2aHooks<'a> {
    pub revocation: Option<&'a dyn Fn(&Value) -> Result<Value, String>>,
}

/// `(allow, checks, reasons)` of the core verifier, the revocation hook and the `params_digest` binding.
fn core_verdict(p: &Value, grant: &Value, opts: &Value, context: &Value, hooks: &A2aHooks) -> (bool, BTreeMap<String, bool>, Vec<String>) {
    let deny = |why: &str| (false, BTreeMap::new(), vec![why.to_string()]);
    let Some(aud) = gv(opts, "aud").and_then(Value::as_str) else { return deny("audience is required (fail closed)") };
    let now = match gv(opts, "now") {
        None | Some(Value::Null) => now_ms(),
        Some(n) if n.is_number() => n.as_f64().unwrap_or(0.0) as i64,
        Some(_) => return deny("now must be a number (fail closed)"),
    };
    let allowed: Option<Vec<String>> =
        gv(opts, "allowedSuites").and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect());
    let pins: Option<HashMap<String, String>> =
        gv(opts, "pqPins").and_then(Value::as_object).map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect());
    let plan = gv(context, "plan").filter(|p| p.is_object());
    let authorized = gv(context, "planAuthorized") == Some(&Value::Bool(true)) || gv(context, "plan_authorized") == Some(&Value::Bool(true));
    let roots: Vec<String> = match (authorized, plan.and_then(|p| gv(p, "root")).and_then(Value::as_str)) {
        (true, Some(r)) => vec![r.to_string()],
        _ => Vec::new(),
    };
    let vopts =
        VerifyOptions { allowed: allowed.as_deref(), authorized_plan_roots: Some(roots.as_slice()), pq_pins: pins.as_ref(), ..VerifyOptions::default() };
    let v = verify_pcactn_core_with(p, grant, now, aud, &vopts);
    let mut checks: BTreeMap<String, bool> = v.checks.clone();
    let mut reasons: Vec<String> = if v.reasons.is_empty() && !v.reason.is_empty() { vec![v.reason.clone()] } else { v.reasons.clone() };
    let mut allow = v.allow;
    let res = hooks.revocation.map(|h| h(&json!({ "pcactn": p, "grant": grant, "context": context })));
    match res {
        Some(Ok(r)) if gv(&r, "enforced") == Some(&Value::Bool(true)) => {
            let ok = gv(&r, "ok") == Some(&Value::Bool(true));
            checks.insert("revocation".into(), ok);
            if !ok {
                allow = false;
                reasons.push(gv(&r, "reason").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("rejected").to_string());
            }
        }
        Some(Err(e)) => {
            checks.insert("revocation".into(), false);
            allow = false;
            reasons.push(format!("revocation hook failed: {e}"));
        }
        _ => {
            checks.insert("revocation".into(), false); // not enforced is not a pass
        }
    }
    if let (Some(params), Some(action)) = (gv(context, "params").filter(|x| x.is_object()), gv(p, "action").filter(|x| x.is_object())) {
        let want = gv(action, "params_digest").and_then(Value::as_str);
        checks.insert("params_digest".into(), hash_canonical_strict(params).is_some_and(|d| Some(d.as_str()) == want));
    }
    (allow, checks, reasons)
}

/// PCActn authorization shared by the task and payment-mandate surfaces, under a known authority: the stored grant, or the chain root
/// only when its issuer is the expected principal. Fail closed: every required check must have PASSED.
fn verify_pcactn(p: &Value, opts: &Value, extra: &[&str], hooks: &A2aHooks) -> Result<Value, String> {
    assert_authority(opts)?;
    if !(p.is_object() || p.is_array()) {
        return Ok(json!({ "ok": false, "reason": "PCActn is not an object" }));
    }
    let root = gv(p, "cap_chain").and_then(Value::as_array).and_then(|c| c.first()).filter(|r| truthy(Some(*r)));
    let Some(root) = root else { return Ok(json!({ "ok": false, "reason": "PCActn carries no capability chain", "pcActn": p })) };
    if let Some(exp) = gv(opts, "expectedRootIssuer") {
        if !same(gv(root, "issuer"), Some(exp)) {
            return Ok(json!({ "ok": false, "reason": "chain root issuer does not match the expected principal", "pcActn": p }));
        }
    }
    let grant = gv(opts, "grant").filter(|g| !g.is_null()).unwrap_or(root);
    let empty = json!({});
    let context = gv(opts, "context").filter(|c| !c.is_null()).unwrap_or(&empty);
    let mut names: Vec<String> = match gv(opts, "requireChecks") {
        None | Some(Value::Null) => DEFAULT_REQUIRED_CHECKS.iter().map(|s| s.to_string()).collect(),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect(),
        Some(_) => return Err("requireChecks is not iterable".to_string()),
    };
    for e in extra {
        if !names.iter().any(|n| n == e) {
            names.push(e.to_string());
        }
    }
    let (verdict_allow, checks, reasons) = core_verdict(p, grant, opts, context, hooks);
    let allow = verdict_allow && names.iter().all(|n| checks.get(n) == Some(&true));
    let reason = if allow {
        None
    } else {
        let joined = reasons.iter().filter(|r| !r.is_empty()).cloned().collect::<Vec<_>>().join("; ");
        Some(if joined.is_empty() { "PCActn verification failed".to_string() } else { joined })
    };
    let mut result = json!({ "allow": allow, "checks": checks, "reasons": reasons });
    if let Some(r) = &reason {
        result["reason"] = json!(r);
    }
    Ok(match reason {
        None => json!({ "ok": true, "result": result, "pcActn": p }),
        Some(r) => json!({ "ok": false, "reason": r, "result": result, "pcActn": p }),
    })
}

/// `{ok, reason?, result?, pcActn?}`: verify the proof-carrying action on a task. Fail closed: no PCActn, or one that does not
/// verify, is refused. `Err` when `opts` names no authority.
pub fn verify_a2a_task(task: &Value, opts: &Value) -> Result<Value, String> {
    verify_a2a_task_with(task, opts, &A2aHooks::default())
}

pub fn verify_a2a_task_with(task: &Value, opts: &Value, hooks: &A2aHooks) -> Result<Value, String> {
    assert_authority(opts)?;
    match extract_pca(task) {
        None => Ok(json!({ "ok": false, "reason": "no proof-carrying action attached to this task" })),
        Some(p) => verify_pcactn(&p, opts, &[], hooks),
    }
}

/// The guard `pcaA2AMiddleware(opts)(task)`: `opts.require` (default true) refuses a task with no proof; with false it passes, but a
/// task that DOES carry a proof must still verify.
pub fn middleware(task: &Value, opts: &Value) -> Result<Value, String> {
    assert_authority(opts)?;
    let require = match gv(opts, "require") {
        None | Some(Value::Null) => true,
        Some(r) => truthy(Some(r)),
    };
    match extract_pca(task) {
        None if require => Ok(json!({ "ok": false, "reason": "proof-carrying action required but none attached to task" })),
        None => Ok(json!({ "ok": true })),
        Some(p) => verify_pcactn(&p, opts, &[], &A2aHooks::default()),
    }
}

// ---- extension declaration -------------------------------------------------------------------------------------------------

/// The `capabilities.extensions[]` entry that declares PCA support.
pub fn pca_extension_declaration(params: &Value, required: bool) -> Value {
    json!({
        "uri": PCA_A2A_EXTENSION_URI,
        "description": "Per-action proofs of authority (PCActn) on tasks and messages",
        "required": required,
        "params": params,
    })
}

/// Read and validate the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess.
pub fn read_pca_extension(card: &Value) -> Value {
    let bad = |code: &str| json!({ "ok": false, "code": code });
    let exts = gv(card, "capabilities").and_then(|c| gv(c, "extensions")).and_then(Value::as_array);
    let Some(exts) = exts else { return bad("not_declared") };
    let found: Vec<&Value> = exts.iter().filter(|e| e.is_object() && gv(e, "uri").and_then(Value::as_str) == Some(PCA_A2A_EXTENSION_URI)).collect();
    if found.is_empty() {
        return bad("not_declared");
    }
    if found.len() > 1 {
        return bad("bad_declaration");
    }
    let e = found[0];
    if gv(e, "required").is_some_and(|r| !r.is_boolean()) {
        return bad("bad_declaration");
    }
    let p = gv(e, "params");
    let Some(pm) = p.and_then(Value::as_object) else { return bad("bad_params") };
    if pm.keys().any(|k| !PARAM_KEYS.contains(&k.as_str())) || !str_in(pm.get("aud"), 512) {
        return bad("bad_params");
    }
    if let Some(s) = pm.get("suites") {
        if !s.as_array().is_some_and(|a| a.len() <= 16 && a.iter().all(|x| str_in(Some(x), 64))) {
            return bad("bad_params");
        }
    }
    if let Some(d) = pm.get("policy_digest") {
        if !str_in(Some(d), 128) {
            return bad("bad_params");
        }
    }
    let grants = match pm.get("grants") {
        None => Vec::new(),
        Some(g) => match parse_details(g) {
            Ok(d) => d,
            Err(_) => return bad("bad_grants"),
        },
    };
    json!({ "ok": true, "required": gv(e, "required") == Some(&Value::Bool(true)), "params": p, "grants": grants })
}

/// True iff the `A2A-Extensions` service parameter lists the PCA extension (exact URI in a comma-separated list).
pub fn client_opts_into_pca(header: &Value) -> bool {
    header.as_str().is_some_and(|h| h.split(',').any(|u| u.trim_matches(is_js_ws) == PCA_A2A_EXTENSION_URI))
}

// ---- AUTH_REQUIRED mapping -------------------------------------------------------------------------------------------------

pub fn is_auth_required(state: &Value) -> bool {
    matches!(state.as_str(), Some(TASK_STATE_AUTH_REQUIRED) | Some("auth-required"))
}

/// The unpadded base64url of a need's strict canonical JSON. `Err` for a malformed need or an over-long value.
pub fn encode_pca_need(need: &Value) -> Result<String, String> {
    if let Some(code) = a2a::need_error(need) {
        return Err(format!("encodePcaNeed: malformed need ({code})"));
    }
    let enc = b64_encode(canonicalize_strict(need)?.as_bytes());
    if enc.len() > 2048 {
        return Err("encodePcaNeed: the need is too large for a header".to_string());
    }
    Ok(enc)
}

/// The TaskStatus an agent sets to ask for authority: AUTH_REQUIRED plus a message carrying the typed need. `o` is
/// `{messageId, now, text?}`; `Err` on a need the codec would refuse or a `now` that is no valid time.
pub fn auth_required_status(need: &Value, o: &Value) -> Result<Value, String> {
    let enc = encode_pca_need(need)?;
    let stamp = iso_of(gv(o, "now"))?;
    let default_text = format!("Authority needed: {} on {}", need["verb"].as_str().unwrap_or(""), need["resource"].as_str().unwrap_or(""));
    let text = gv(o, "text").filter(|t| !t.is_null()).cloned().unwrap_or(Value::String(default_text));
    let mut msg = Map::new();
    if let Some(id) = gv(o, "messageId") {
        msg.insert("messageId".into(), id.clone());
    }
    msg.insert("role".into(), json!("agent"));
    msg.insert("parts".into(), json!([{ "kind": "text", "text": text }]));
    msg.insert("extensions".into(), json!([PCA_A2A_EXTENSION_URI]));
    msg.insert("metadata".into(), json!({ NEED_KEY: enc }));
    Ok(json!({ "state": TASK_STATE_AUTH_REQUIRED, "timestamp": stamp, "message": Value::Object(msg) }))
}

/// The need parked in a task status message, decoded: `{ok: true, need}` / `{ok: false, code}`; null when there is none.
pub fn read_auth_required_need(task: &Value) -> Value {
    let msg = objv(gvo(objv(gvo(objv(Some(task)), "status")), "message"));
    match objv(gvo(msg, "metadata")).and_then(|m| gv(m, NEED_KEY)) {
        None => Value::Null,
        Some(v) => match a2a::decode_need(v) {
            Ok(need) => json!({ "ok": true, "need": need }),
            Err(code) => json!({ "ok": false, "code": code }),
        },
    }
}

/// The answer message: a PCActn for exactly the parked need, plus the need's digest.
pub fn answer_message(need: &Value, pca: &Value, message_id: &Value) -> Result<Value, String> {
    let digest = a2a::need_digest(need).ok_or("canonicalize: value has no strict canonical form")?;
    Ok(json!({
        "role": "user",
        "messageId": message_id,
        "parts": [{ "kind": "text", "text": "authority provided" }],
        "metadata": { PCA_A2A_EXTENSION_URI: pca, NEED_KEY: digest },
    }))
}

/// `resumeGate({state, needEncoded, answerNeedDigest, proofAction})`: `None` when the full verifier may now be asked, else the
/// refusal code. An absent `proofAction` is no proof, a null one is a TypeError (as in the reference).
pub fn resume_gate(o: &Value) -> Result<Option<&'static str>, String> {
    if !gv(o, "state").is_some_and(is_auth_required) {
        return Ok(Some("task_not_auth_required"));
    }
    let need = match gv(o, "needEncoded") {
        None => None,
        Some(v) => a2a::decode_need(v).ok(),
    };
    let Some(need) = need else { return Ok(Some("no_valid_need")) };
    let want = a2a::need_digest(&need).ok_or("canonicalize: value has no strict canonical form")?;
    if !gv(o, "answerNeedDigest").is_some_and(|d| d.as_str() == Some(want.as_str())) {
        return Ok(Some("answer_not_bound_to_need"));
    }
    let Some(action) = gv(o, "proofAction") else { return Ok(Some("no_proof")) };
    let verb = read(Some(action), "verb")?;
    if !same(verb, need.get("verb")) || !same(gv(action, "resource"), need.get("resource")) {
        return Ok(Some("action_mismatch"));
    }
    Ok(None)
}

/// Resume a Task parked in AUTH_REQUIRED. Allowed only when the task is in AUTH_REQUIRED, its status carries a decodable need, the
/// answer cites that need's digest, the answer carries a PCActn for the need's exact verb and resource, and that PCActn passes the
/// verifier for THIS agent. `{ok: true, verification}` / `{ok: false, reason}`.
pub fn resume_auth_required(task: &Value, answer: &Value, opts: &Value) -> Result<Value, String> {
    let status = objv(gv(task, "status"));
    let status_md = objv(gvo(objv(gvo(status, "message")), "metadata"));
    let md = objv(gv(answer, "metadata"));
    let p = extract_pca_from_message(answer);
    let mut gate = Map::new();
    if let Some(s) = gvo(status, "state") {
        gate.insert("state".into(), s.clone());
    }
    if let Some(n) = gvo(status_md, NEED_KEY) {
        gate.insert("needEncoded".into(), n.clone());
    }
    if let Some(d) = gvo(md, NEED_KEY) {
        gate.insert("answerNeedDigest".into(), d.clone());
    }
    if let Some(a) = p.as_ref().and_then(|p| gv(p, "action")) {
        gate.insert("proofAction".into(), a.clone());
    }
    if let Some(refusal) = resume_gate(&Value::Object(gate))? {
        return Ok(json!({ "ok": false, "reason": refusal }));
    }
    let id = read(Some(task), "id")?.cloned();
    let mut carrier = Map::new();
    if let Some(id) = id {
        carrier.insert("id".into(), id);
    }
    carrier.insert("status".into(), json!({ "state": "TASK_STATE_WORKING" }));
    carrier.insert("metadata".into(), json!({ PCA_A2A_EXTENSION_URI: p }));
    let v = verify_a2a_task(&Value::Object(carrier), opts)?;
    if v["ok"] == Value::Bool(true) {
        return Ok(json!({ "ok": true, "verification": v }));
    }
    Ok(json!({ "ok": false, "reason": v.get("reason").filter(|r| !r.is_null()).cloned().unwrap_or(json!("proof_rejected")) }))
}

// ---- per-hop delegation ----------------------------------------------------------------------------------------------------

/// `next` extends `prev`: at least as long, and every earlier id is where it was.
pub fn chain_extends(prev: &[Value], next: &[Value]) -> bool {
    next.len() >= prev.len() && prev.iter().enumerate().all(|(k, id)| same(Some(id), next.get(k)))
}

/// `{ok: true}` or `{ok: false, failedHop, reason}` (`no_chain` | `chain_does_not_extend_previous_hop`). `Err` for a null.
pub fn check_chain_extension(chains: &Value) -> Result<Value, String> {
    let items: Vec<Value> = match chains {
        Value::Array(a) => a.clone(),
        Value::String(s) => s.encode_utf16().map(|u| Value::String(String::from_utf16_lossy(&[u]))).collect(),
        Value::Null => return Err("Cannot read properties of null (reading 'length')".to_string()),
        _ => Vec::new(), // no `.length`: the loop never runs
    };
    for (i, ids) in items.iter().enumerate() {
        let Some(ids) = ids.as_array().filter(|a| !a.is_empty()) else {
            return Ok(json!({ "ok": false, "failedHop": i, "reason": "no_chain" }));
        };
        if i > 0 {
            if let Some(prev) = items[i - 1].as_array() {
                if !chain_extends(prev, ids) {
                    return Ok(json!({ "ok": false, "failedHop": i, "reason": "chain_does_not_extend_previous_hop" }));
                }
            }
        }
    }
    Ok(json!({ "ok": true }))
}

/// Verify a chain of delegated tasks, one per A2A hop (`hops` = `[{task, opts}]`), each on its own (its own PCActn, audience and
/// authority); the capability chain must EXTEND the previous hop's. Stops at the first failure; empty input is refused.
pub fn verify_a2a_delegation(hops: &Value) -> Result<Value, String> {
    let hops = hops.as_array().ok_or("Cannot read properties of undefined (reading 'length')")?;
    let mut chains: Vec<Vec<Value>> = Vec::new();
    if hops.is_empty() {
        return Ok(json!({ "ok": false, "reason": "no_hops", "chains": chains }));
    }
    let null = Value::Null;
    for (i, h) in hops.iter().enumerate() {
        let task = read(Some(h), "task")?.unwrap_or(&null);
        let opts = gv(h, "opts").unwrap_or(&null);
        let v = verify_a2a_task(task, opts)?;
        if v["ok"] != Value::Bool(true) {
            let reason = v.get("reason").filter(|r| !r.is_null()).cloned().unwrap_or(json!("rejected"));
            return Ok(json!({ "ok": false, "failedHop": i, "reason": reason, "chains": chains }));
        }
        let ids: Option<Vec<Value>> = match extract_pca(task).as_ref().and_then(|p| gv(p, "cap_chain")).and_then(Value::as_array) {
            None => None,
            Some(c) => {
                let mut out = Vec::new();
                for x in c {
                    out.push(read(Some(x), "id")?.cloned().unwrap_or(Value::Null));
                }
                Some(out)
            }
        };
        let Some(ids) = ids else { return Ok(json!({ "ok": false, "failedHop": i, "reason": "no_chain", "chains": chains })) };
        if let Some(prev) = chains.last() {
            if !chain_extends(prev, &ids) {
                return Ok(json!({ "ok": false, "failedHop": i, "reason": "chain_does_not_extend_previous_hop", "chains": chains }));
            }
        }
        chains.push(ids);
    }
    Ok(json!({ "ok": true, "chains": chains }))
}

// ---- push notifications and anti-enumeration ---------------------------------------------------------------------------------

/// The per-task push token. `Err` for a salt that is not a string of at least 16 characters.
pub fn pca_push_token(task_id: &Value, chain_ids: &Value, salt: &Value) -> Result<String, String> {
    let Some(salt) = salt.as_str().filter(|s| utf16(s) >= 16) else {
        return Err("pcaPushToken: the salt must be a secret of at least 16 characters".to_string());
    };
    let ids: Vec<&str> =
        chain_ids.as_array().ok_or("chain ids must be an array")?.iter().map(|x| x.as_str().ok_or("chain id must be a string")).collect::<Result<_, _>>()?;
    let chain = chain_digest(&ids).ok_or("canonicalize: value has no strict canonical form")?;
    hash_canonical_strict(&json!({ "d": "atlas-pca/a2a-push/v1", "task_id": task_id, "chain": chain, "salt": salt }))
        .ok_or_else(|| "canonicalize: value has no strict canonical form".to_string())
}

/// Receiver-side check of a delivered push notification (`expected` = `{taskId, chainIds, salt}`, `delivered` = `{token, payload}`):
/// the token must be the one recomputed from the task, the chain and the salt, and the payload must be about that task.
/// `{ok: true}` / `{ok: false, reason: no_token | token_mismatch | task_mismatch}`; `Err` for a salt under 16 characters.
pub fn check_push_notification(expected: &Value, delivered: &Value) -> Result<Value, String> {
    let Some(token) = gv(delivered, "token").and_then(Value::as_str).filter(|t| !t.is_empty()) else {
        return Ok(json!({ "ok": false, "reason": "no_token" }));
    };
    let null = Value::Null;
    let want = pca_push_token(gv(expected, "taskId").unwrap_or(&null), gv(expected, "chainIds").unwrap_or(&null), gv(expected, "salt").unwrap_or(&null))?;
    if want.len() != token.len() || !crate::attest::util::timing_safe_eq(want.as_bytes(), token.as_bytes()) {
        return Ok(json!({ "ok": false, "reason": "token_mismatch" }));
    }
    let payload = delivered.get("payload").filter(|p| p.is_object());
    let mut id: Option<&Value> = None;
    for (key, field) in [("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId")] {
        let v = gvo(gvo(payload, key).filter(|c| c.is_object()), field);
        if !nullish(v) {
            id = v;
            break;
        }
    }
    Ok(if same(id, gv(expected, "taskId")) { json!({ "ok": true }) } else { json!({ "ok": false, "reason": "task_mismatch" }) })
}

/// The one error servers return for "no such task" and "not yours" alike (no existence leak).
pub fn uniform_task_not_found() -> Value {
    json!({ "code": "TaskNotFoundError", "message": "task not found" })
}

// ---- signed task-update receipts ---------------------------------------------------------------------------------------------

pub fn receipt_digest(r: &Value) -> Result<String, String> {
    a2a::receipt_digest(r).ok_or_else(|| "canonicalize: value has no strict canonical form".to_string())
}

/// Sign a receipt with the Ed25519 `secret` seed. `o` = `{taskId, state, chainIds, issuedAt, prev?}` (`prev`: the previous receipt of
/// the same task). `Err` for malformed input, a `prev` of another task or one already terminal.
pub fn sign_task_receipt(secret: &[u8; 32], o: &Value) -> Result<Value, String> {
    let task_id = gv(o, "taskId");
    let state = gv(o, "state").and_then(Value::as_str);
    let ids = read(Some(o), "chainIds")?.and_then(Value::as_array).ok_or("Cannot read properties of undefined (reading 'length')")?;
    let id_ok = task_id.and_then(Value::as_str).is_some_and(|t| utf16(t) > 0 && utf16(t) <= 256);
    let issued = uint(gv(o, "issuedAt"));
    if !id_ok || !state.is_some_and(|s| STATES.contains(&s)) || issued.is_none() || ids.is_empty() {
        return Err("signTaskReceipt: malformed input".to_string());
    }
    let prev = gv(o, "prev").filter(|p| truthy(Some(*p)));
    if let Some(p) = prev {
        if !same(gv(p, "task_id"), task_id) || gv(p, "state").and_then(Value::as_str).is_some_and(|s| TERMINAL.contains(&s)) {
            return Err("signTaskReceipt: prev is for another task or already terminal".to_string());
        }
    }
    let seq = match prev {
        Some(p) => json!((gv(p, "seq").and_then(Value::as_f64).ok_or("canonicalize: value has no strict canonical form")? + 1.0) as i64),
        None => json!(0),
    };
    let id_strs: Vec<&str> = ids.iter().map(|x| x.as_str().ok_or("canonicalize: value has no strict canonical form")).collect::<Result<_, _>>()?;
    let kp = KeyPair::from_seed(secret);
    let mut base = Map::new();
    base.insert("v".into(), json!(1));
    base.insert("task_id".into(), task_id.cloned().unwrap_or(Value::Null));
    base.insert("state".into(), json!(state));
    base.insert("seq".into(), seq);
    base.insert(
        "prev".into(),
        match prev {
            Some(p) => json!(receipt_digest(p)?),
            None => Value::Null,
        },
    );
    base.insert("chain".into(), json!(chain_digest(&id_strs).ok_or("canonicalize: value has no strict canonical form")?));
    base.insert("issued_at".into(), gv(o, "issuedAt").cloned().unwrap_or(Value::Null));
    base.insert("signer".into(), json!(kp.public));
    let body = Value::Object(base.clone());
    let msg = domain_bytes(A2A_RECEIPT_DOMAIN, &body).ok_or("canonicalize: value has no strict canonical form")?;
    base.insert("sig".into(), json!(b64_encode(&kp.sign(&msg))));
    Ok(Value::Object(base))
}

/// Does `r` carry a valid signature of `signer` and a well-formed body? Total.
pub fn verify_task_receipt(r: &Value, signer: &str) -> bool {
    a2a::verify_receipt(r, signer)
}

/// Check a chain of receipts of one task under one chain: `{ok: true, last, terminal}` or `{ok: false, code, at?}`
/// (`empty | bad_receipt | wrong_task | wrong_chain | broken_link | after_terminal | bad_start`).
pub fn check_receipt_chain(receipts: &Value, signer: &str, task_id: &str, chain_ids: &[&str]) -> Value {
    let Some(list) = receipts.as_array().filter(|a| !a.is_empty()) else { return json!({ "ok": false, "code": "empty" }) };
    match a2a::check_receipt_chain(list, signer, task_id, chain_ids) {
        a2a::ReceiptChain::Ok { terminal, .. } => json!({ "ok": true, "last": list[list.len() - 1], "terminal": terminal }),
        a2a::ReceiptChain::Refused { code, at: Some(at) } => json!({ "ok": false, "code": code, "at": at }),
        a2a::ReceiptChain::Refused { code, at: None } => json!({ "ok": false, "code": code }),
    }
}

/// A chain that ends in COMPLETED may trigger the next hop; nothing else does.
pub fn may_trigger_next(receipts: &Value, signer: &str, task_id: &str, chain_ids: &[&str]) -> bool {
    receipts.as_array().is_some_and(|l| a2a::may_trigger_next(l, signer, task_id, chain_ids))
}

/// A copy of a status update / message with the receipt on its metadata. `Err` for a null carrier.
pub fn attach_receipt(carrier: &Value, receipt: &Value) -> Result<Value, String> {
    let md = read(Some(carrier), "metadata")?;
    let mut out = spread_obj(carrier);
    out.insert("metadata".into(), with_key(md, RECEIPT_KEY, receipt));
    Ok(Value::Object(out))
}

/// The (unverified) receipt a push or stream payload carries (`statusUpdate`, `task` or `message` metadata), else null.
pub fn receipt_of_payload(payload: &Value) -> Value {
    for k in ["statusUpdate", "task", "message"] {
        let md = gv(payload, k).filter(|c| c.is_object()).and_then(|c| gv(c, "metadata")).filter(|m| m.is_object());
        if let Some(r) = md.and_then(|m| gv(m, RECEIPT_KEY)) {
            return r.clone();
        }
    }
    Value::Null
}

// ---- extended Agent Card -----------------------------------------------------------------------------------------------------

/// `(s.tags ?? []).find(x => typeof x === 'string' && x.startsWith('pca-verb:'))` without the prefix.
fn default_verb_of(s: &Value) -> Result<Option<String>, String> {
    match read(Some(s), "tags")? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(t)) => Ok(t.iter().find_map(|x| x.as_str().and_then(|x| x.strip_prefix("pca-verb:")).map(String::from))),
        Some(_) => Err("(s.tags ?? []).find is not a function".to_string()),
    }
}

/// The card an authenticated caller gets (A2A 13.3): the public card plus the hidden skills its envelopes allow (tagged
/// `pca:autonomous` / `pca:needs-approval`) and the policy digest on the PCA extension. `o` = `{authenticated, hiddenSkills,
/// envelopes}` (a skill's verb is its `pca-verb:<verb>` tag).
pub fn extended_agent_card(public_card: &Value, o: &Value) -> Result<Value, String> {
    if gv(o, "authenticated") != Some(&Value::Bool(true)) {
        return Err("extendedAgentCard: the caller must be authenticated (A2A 13.3)".to_string());
    }
    let envelopes = gv(o, "envelopes").and_then(Value::as_array).ok_or("envelopes is not iterable")?;
    let mut digests: Vec<Option<&Value>> = Vec::new();
    let mut by_verb: Vec<(Option<&Value>, &Value)> = Vec::new();
    for e in envelopes {
        let d = read(Some(e), "policyDigest")?;
        if !digests.iter().any(|x| same(*x, d)) {
            digests.push(d);
        }
        let verb = gv(e, "verb");
        match by_verb.iter().position(|(k, _)| same(*k, verb)) {
            Some(i) => by_verb[i].1 = e,
            None => by_verb.push((verb, e)),
        }
    }
    if digests.len() > 1 {
        return Err("extendedAgentCard: envelopes were computed against different policies".to_string());
    }
    let hidden = gv(o, "hiddenSkills").and_then(Value::as_array).ok_or("hiddenSkills is not iterable")?;
    let mut revealed: Vec<Value> = Vec::new();
    for s in hidden {
        let verb = default_verb_of(s)?;
        let env = verb.as_ref().and_then(|v| by_verb.iter().find(|(k, _)| k.and_then(Value::as_str) == Some(v.as_str())).map(|(_, e)| *e));
        let Some(env) = env else { continue };
        let status = gv(env, "status").and_then(Value::as_str);
        if status == Some("denied") {
            continue;
        }
        let mut tags = gv(s, "tags").and_then(Value::as_array).cloned().unwrap_or_default();
        tags.push(json!(if status == Some("autonomous") { "pca:autonomous" } else { "pca:needs-approval" }));
        let mut skill = spread_obj(s);
        skill.insert("tags".into(), Value::Array(tags));
        revealed.push(Value::Object(skill));
    }
    if public_card.is_null() {
        return Err("Cannot destructure property 'signatures' of 'publicCard' as it is null".to_string());
    }
    let mut rest = spread_obj(public_card);
    rest.remove("signatures");
    let caps_in = rest.get("capabilities").filter(|c| !c.is_null()).cloned().unwrap_or(json!({}));
    let exts: Vec<Value> = gv(&caps_in, "extensions").and_then(Value::as_array).cloned().unwrap_or_default();
    let next_exts: Vec<Value> = match digests.first().copied().flatten() {
        None => exts,
        Some(d) => {
            let mut out = Vec::new();
            for e in exts {
                if read(Some(&e), "uri")?.and_then(Value::as_str) == Some(PCA_A2A_EXTENSION_URI) {
                    let mut params = gv(&e, "params").map(spread_obj).unwrap_or_default();
                    params.insert("policy_digest".into(), d.clone());
                    let mut ne = spread_obj(&e);
                    ne.insert("params".into(), Value::Object(params));
                    out.push(Value::Object(ne));
                } else {
                    out.push(e);
                }
            }
            out
        }
    };
    let mut caps = spread_obj(&caps_in);
    caps.insert("extensions".into(), Value::Array(next_exts));
    let mut skills = rest.get("skills").and_then(Value::as_array).cloned().unwrap_or_default();
    skills.extend(revealed);
    rest.insert("capabilities".into(), Value::Object(caps));
    rest.insert("skills".into(), Value::Array(skills));
    Ok(Value::Object(rest))
}

// ---- AP2 payment-mandate envelope ----------------------------------------------------------------------------------------------

/// True only when the PCActn's threshold shares verify at t=3 (agent, guardian and principal) under `signer_set`. The agent role needs
/// an explicit agent share (the leaf-signature stand-in of the reference is not accepted: stricter). Never panics.
fn verified_human_present(p: &Value, signer_set: &Value) -> bool {
    let Some(set) = signer_set.as_array() else { return false };
    let roles: Vec<&str> = set.iter().filter_map(|e| gv(e, "role").and_then(Value::as_str)).collect();
    let roles_ok = ["agent", "guardian", "principal"].iter().all(|r| roles.contains(r));
    let (Some(pm), true) = (p.as_object(), roles_ok) else { return false };
    let Ok(msg) = crate::threshold_message(pm) else { return false };
    let tm = b64_encode(&msg);
    let shares = pm.get("threshold").and_then(|t| gv(t, "shares")).and_then(Value::as_array);
    let verified = |role: &str| {
        shares.is_some_and(|sh| {
            sh.iter().any(|s| {
                gv(s, "role").and_then(Value::as_str) == Some(role)
                    && crate::verify_threshold_share(&json!({ "role": role, "t": 3, "share": s, "threshold_message": tm, "signer_set": signer_set }))
            })
        })
    };
    ["agent", "guardian", "principal"].iter().all(|r| verified(r))
}

/// The AP2 payment-mandate envelope of a PCActn; its authority is carried BY REFERENCE (`x_pca.pcactn_digest`). `opts` =
/// `{amount: {currency, value}, paymentMethod, merchant?, humanPresent?, humanSignerSet?, issuerPublic?, now?}`; the amount is an
/// integer in minor units. `Err` for anything the envelope cannot honestly carry.
pub fn a2a_payment_mandate_from_pca(pca: &Value, opts: &Value) -> Result<Value, String> {
    let chain = read(Some(pca), "cap_chain")?.and_then(Value::as_array);
    let leaf: Option<&Value> = chain.and_then(|c| c.last()).and_then(|l| gv(l, "holder"));
    let issuer = read(Some(opts), "issuerPublic")?.filter(|i| !i.is_null()).or(leaf);
    let Some(issuer) = issuer else { return Err("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain".to_string()) };
    let amount = read(Some(opts), "amount")?;
    let value = read(amount, "value")?;
    if !safe_int(value).is_some_and(|f| f >= 0.0) {
        return Err("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units".to_string());
    }
    let human_present = match gv(opts, "humanPresent").filter(|h| !h.is_null()) {
        Some(h) => h.clone(),
        None => match gv(opts, "humanSignerSet").filter(|s| truthy(Some(*s))) {
            Some(s) => json!(verified_human_present(pca, s)),
            None => json!(false),
        },
    };
    let now_v = gv(opts, "now").filter(|n| !n.is_null()).cloned().unwrap_or_else(|| json!(now_ms()));
    let issued = iso_of(Some(&now_v))?;
    let digest = hash_canonical_strict(pca).ok_or("canonicalize: value has no strict canonical form")?;
    let action = read(Some(pca), "action")?;
    let mut x_pca = Map::new();
    x_pca.insert("pcactn_digest".into(), json!(digest));
    for (k, v) in [
        ("aud", gv(pca, "aud")),
        ("verb", read(action, "verb")?),
        ("resource", gvo(action, "resource")),
        ("params_digest", gvo(action, "params_digest")),
        ("grant_ref", gv(pca, "grant_ref")),
    ] {
        if let Some(v) = v {
            x_pca.insert(k.into(), v.clone());
        }
    }
    x_pca.insert("leaf_holder".into(), leaf.filter(|l| !l.is_null()).unwrap_or(issuer).clone());
    let mut contents = Map::new();
    contents.insert("amount".into(), Value::Object(amount.map(spread_obj).unwrap_or_default()));
    contents.insert("payment_method".into(), Value::Object(gv(opts, "paymentMethod").map(spread_obj).unwrap_or_default()));
    contents.insert("human_present".into(), human_present);
    if let Some(m) = gv(opts, "merchant") {
        contents.insert("merchant".into(), m.clone());
    }
    contents.insert("x_pca".into(), Value::Object(x_pca));
    Ok(json!({
        "@context": A2A_AP2_CONTEXT,
        "type": ["VerifiableCredential", "PaymentMandate"],
        "issuer": issuer,
        "issuanceDate": issued,
        "credentialSubject": Value::Object(contents),
    }))
}

/// The PCA binding read back out of a payment mandate (the round trip of `x_pca`). `Err` for a mandate with no credentialSubject.
pub fn pca_binding_from_a2a_payment_mandate(mandate: &Value) -> Result<Value, String> {
    let cs = read(Some(mandate), "credentialSubject")?;
    let x = read(cs, "x_pca")?;
    Ok(Value::Object(spread_or_empty(x)))
}

fn own<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    gv(o, k)
}

fn mandate_binding_error(m: &Value, pca: &Value, params: &Value, opts: &Value) -> Option<String> {
    let Some(x) = gv(m, "x_pca").filter(|x| x.is_object()) else { return Some("payment mandate carries no x_pca binding".to_string()) };
    let leaf = gv(pca, "cap_chain").and_then(Value::as_array).and_then(|c| c.last());
    let leaf_holder = leaf.filter(|l| l.is_object()).and_then(|l| gv(l, "holder"));
    let action = gv(pca, "action");
    let bound: [(&str, Option<&Value>); 6] = [
        ("aud", gv(pca, "aud")),
        ("verb", gvo(action, "verb")),
        ("resource", gvo(action, "resource")),
        ("params_digest", gvo(action, "params_digest")),
        ("grant_ref", gv(pca, "grant_ref")),
        ("leaf_holder", leaf_holder),
    ];
    for (k, v) in bound {
        let xv = own(x, k);
        if !xv.is_some_and(Value::is_string) || !same(xv, v) {
            return Some(format!("payment mandate x_pca.{k} is not the PCActn's"));
        }
    }
    let amt = gv(m, "amount").filter(|a| a.is_object()).filter(|a| uint(gv(a, "value")).is_some() && gv(a, "currency").is_some_and(Value::is_string));
    let Some(amt) = amt else { return Some("payment mandate amount is malformed (value must be a non-negative integer in minor units)".to_string()) };
    if uint(own(params, "amount")).is_none() {
        return Some("the PCActn params carry no integer minor-unit amount to bind the mandate amount to".to_string());
    }
    if !own(params, "currency").is_some_and(Value::is_string) {
        return Some("the PCActn params carry no currency to bind the mandate currency to".to_string());
    }
    if !same(gv(amt, "value"), own(params, "amount")) || !same(gv(amt, "currency"), own(params, "currency")) {
        return Some("payment mandate amount / currency differ from the authorized PCActn params".to_string());
    }
    if !same(own(m, "merchant"), own(params, "merchant")) {
        return Some("payment mandate merchant differs from the authorized PCActn params".to_string());
    }
    if let Some(pm) = own(params, "payment_method") {
        let a = own(m, "payment_method").and_then(hash_canonical_strict);
        if a.is_none() || a != hash_canonical_strict(pm) {
            return Some("payment mandate payment_method differs from the authorized PCActn params".to_string());
        }
    }
    let Some(hp) = gv(m, "human_present").and_then(Value::as_bool) else { return Some("payment mandate human_present must be a boolean".to_string()) };
    if hp && !gv(opts, "humanSignerSet").is_some_and(|hs| hs.is_array() && verified_human_present(pca, hs)) {
        return Some("payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)".to_string());
    }
    None
}

/// Verify a payment mandate against the PCActn it references. The mandate is NOT signed: every field a payer acts on must be
/// authorized by the PCActn (digest and `x_pca` fields, the opened params' amount, currency, merchant and payment method, a verified
/// t=3 co-signature for `human_present`), and the PCActn itself must verify, with `params_digest` required. `opts` carries
/// `context: {params}` (the PCActn params plaintext) and the verifier options.
pub fn verify_a2a_payment_mandate(mandate: &Value, pca: &Value, opts: &Value) -> Result<Value, String> {
    verify_a2a_payment_mandate_with(mandate, pca, opts, &A2aHooks::default())
}

pub fn verify_a2a_payment_mandate_with(mandate: &Value, pca: &Value, opts: &Value, hooks: &A2aHooks) -> Result<Value, String> {
    assert_authority(opts)?;
    let malformed = |e: String| Ok(json!({ "ok": false, "reason": format!("malformed payment mandate or PCActn: {e}") }));
    let bound = match read(Some(mandate), "credentialSubject").and_then(|c| read(c, "x_pca")).and_then(|x| read(x, "pcactn_digest")) {
        Ok(b) => b,
        Err(e) => return malformed(e),
    };
    let Some(digest) = hash_canonical_strict(pca) else { return malformed("canonicalize: value has no strict canonical form".to_string()) };
    if bound.and_then(Value::as_str) != Some(digest.as_str()) {
        return Ok(json!({ "ok": false, "reason": "payment mandate is not bound to this PCActn (pcactn_digest mismatch)", "pcActn": pca }));
    }
    if !(pca.is_object() || pca.is_array()) {
        return Ok(json!({ "ok": false, "reason": "PCActn is not an object" }));
    }
    let empty = json!({});
    let context = gv(opts, "context").filter(|c| !c.is_null()).unwrap_or(&empty);
    let Some(params) = gv(context, "params").filter(|p| p.is_object()) else {
        return Ok(json!({ "ok": false, "reason": "context.params (the PCActn params plaintext) is required to bind the payment mandate", "pcActn": pca }));
    };
    let null = Value::Null;
    let cs = gv(mandate, "credentialSubject").unwrap_or(&null);
    if let Some(why) = mandate_binding_error(cs, pca, params, opts) {
        return Ok(json!({ "ok": false, "reason": why, "pcActn": pca }));
    }
    let mut o = opts.as_object().cloned().unwrap_or_default();
    o.insert("context".into(), context.clone());
    verify_pcactn(pca, &Value::Object(o), &["params_digest"], hooks)
}
