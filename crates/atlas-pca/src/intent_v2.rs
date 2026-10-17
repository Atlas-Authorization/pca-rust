//! The Intent Layer v2 checks of the core verifier, in their normative order after `intent` (rule 12):
//! `schema` (rule 14) -> `intent_session` (rule 13) -> `layers` (V5) -> `accumulators` (rule 15) -> `facts` (16) ->
//! `provenance` (17) -> `classes` (18). Mirrors `packages/pca/src/intent-v2.ts` (`decideIntentV2`).
//!
//! REPORTING (back-compat): `schema` iff the PCActn carries `intent_session` or `policy.schema.closed_world` is true;
//! `intent_session` iff it carries the member or `policy.session.require` is true; `layers` iff it carries the member
//! and the verifier configured `layers`; `accumulators` iff it carries the member; `facts` / `provenance` / `classes`
//! iff it carries the member and their member is present or their policy is active (the first W-B failure ends W-B; a
//! rule-17 `question` reports `provenance` as failed). Checks 1-4 are independent. A PCActn without the member, under a
//! verifier without an active v2 policy, verifies exactly as before.

use serde_json::{Map, Value};

use super::action_schema::{action_schema_digest, canon_projection, conform_action, schema_verb, verify_action_schema};
use super::intent_acc::*;
use super::intent_strict::*;
use super::intent_revocation::*;
use super::intent_map::decide_map_disclosure;
use super::intent_session::{grant_session_caveat, intent_session_caveat_error, session_root_digest, verify_session_root_pinned, MAP_FORM_COMMIT};
use super::intent_wb::{decide_intent_wb, WbCheck};
use super::intent_suite::suite_of;
use super::predicates::{evaluate_predicates, Ctx};
use super::MAX_SAFE;

/// The verifier state the v2 checks read (`IntentV2Context`): `{policy?, params?, schema?: {docs, keys}, session?:
/// {root, grants, revocation?}, layers?, wb?: {artifacts?, policy?}, acc?: {state?, monitors?, receipts?, last_seq?,
/// sequencer_keys?}}`. All of it is VERIFIER state (its store, its configuration), never the agent's. It is kept as
/// the JSON the host supplies and read strictly: an absent member is empty / default, a member that is JSON `null` or of
/// the wrong type is malformed and fails, closed, the check that owns it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntentV2Context {
    raw: Value,
}

impl IntentV2Context {
    /// Construction from the PRESENT member `context.intent_v2` (pass nothing when it is absent). A value that is not a
    /// JSON object (JSON `null` included) is a MALFORMED context, never "no context": every v2 check that would be
    /// reported fails with "malformed v2 context: the v2 verifier context must be an object", as in the reference. (It
    /// used to be `None`, which a caller's `.and_then(from_json)` turned into no context: v2 enforcement silently off on
    /// a misconfigured verifier.) Always `Some`; the `Option` is kept for API compatibility.
    pub fn from_json(v: &Value) -> Option<IntentV2Context> {
        Some(IntentV2Context { raw: v.clone() })
    }

    /// Parse raw JSON text and apply [`IntentV2Context::from_json`].
    pub fn from_json_text(text: &str) -> Result<IntentV2Context, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("intent_v2 context: {e}"))?;
        if !v.is_object() {
            return Err("intent_v2 context: not a JSON object".to_string());
        }
        IntentV2Context::from_json(&v).ok_or_else(|| "intent_v2 context: not a JSON object".to_string())
    }

    /// The context as JSON.
    pub fn as_json(&self) -> &Value {
        &self.raw
    }

    /// The member at `path`: `Ok(None)` when absent; `Err` (malformed, fail closed) when it is JSON `null` or an
    /// enclosing member is not an object.
    fn member(&self, path: &[&str]) -> Result<Option<&Value>, String> {
        let mut cur = &self.raw;
        for (i, k) in path.iter().enumerate() {
            let m = cur.as_object().ok_or_else(|| format!("context.intent_v2.{} must be an object", path[..i].join(".")))?;
            cur = match m.get(*k) {
                None => return Ok(None),
                Some(Value::Null) => return Err(format!("context.intent_v2.{} is null (malformed)", path[..=i].join("."))),
                Some(v) => v,
            };
        }
        Ok(Some(cur))
    }
}

/// A verifier-state member (`Ok(None)` when absent or when there is no context).
fn member<'a>(ctx: Option<&'a IntentV2Context>, path: &[&str]) -> Result<Option<&'a Value>, String> {
    match ctx {
        Some(c) => c.member(path),
        None => Ok(None),
    }
}

/// A verifier-state member that must be a JSON object when present.
fn member_obj<'a>(ctx: Option<&'a IntentV2Context>, path: &[&str]) -> Result<Option<&'a Map<String, Value>>, String> {
    match member(ctx, path)? {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(format!("context.intent_v2.{} must be an object", path.join("."))),
    }
}

/// A verifier-state member that must be a JSON array when present (absent = empty).
fn member_list<'a>(ctx: Option<&'a IntentV2Context>, path: &[&str]) -> Result<&'a [Value], String> {
    match member(ctx, path)? {
        None => Ok(&[]),
        Some(Value::Array(a)) => Ok(a.as_slice()),
        Some(_) => Err(format!("context.intent_v2.{} must be an array", path.join("."))),
    }
}

/// A policy flag is ON only when it is the JSON boolean `true` (anything else, `null` included, leaves it off).
fn flag_on(ctx: Option<&IntentV2Context>, path: &[&str]) -> bool {
    matches!(member(ctx, path), Ok(Some(Value::Bool(true))))
}

/// One reported v2 check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentV2Check {
    pub name: &'static str,
    pub ok: bool,
    pub reason: String,
}

/// The v2 decision: the reported checks in pipeline order and the verifier-computed predicate `env` (`canon` when
/// `schema` passed, `acc` / `mon` when `accumulators` passed, `world` / `prov` / `class` when W-B admits or asks).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntentV2Decision {
    pub checks: Vec<IntentV2Check>,
    pub env: Map<String, Value>,
}

type Step = Result<(), String>;

fn opt_obj(v: Option<&Value>) -> bool {
    v.is_none_or(Value::is_object)
}
fn opt_arr(v: Option<&Value>) -> bool {
    v.is_none_or(Value::is_array)
}

/// The whole v2 context (`intentV2ContextError`): an ABSENT member is empty / default; a member PRESENT with JSON `null`
/// or of the wrong JSON type is malformed. Covers the policy (and its members), params, schema, session, acc, the
/// `layers` ceilings (each `{predicates: [...]}`) and the W-B members passed through.
pub fn intent_v2_context_error(ctx: &Value) -> Option<String> {
    let c = match ctx.as_object() {
        Some(c) => c,
        None => return Some("the v2 verifier context must be an object".into()),
    };
    if let Some(pol) = c.get("policy") {
        let pol = match pol.as_object() {
            Some(p) => p,
            None => return Some("policy must be an object".into()),
        };
        // closed member sets; every flag a JSON boolean, the age a non-negative safe integer (absent = default)
        if let Some(k) = pol.keys().find(|k| !["session", "schema", "acc", "map"].contains(&k.as_str())) {
            return Some(format!("policy: unknown member '{k}'"));
        }
        if let Some(ps) = pol.get("session") {
            let o = match ps.as_object() {
                Some(o) => o,
                None => return Some("policy.session must be an object".into()),
            };
            if let Some(k) = o.keys().find(|k| *k != "require" && *k != "max_revocation_age_s") {
                return Some(format!("policy.session: unknown member '{k}'"));
            }
            if o.get("require").is_some_and(|x| !x.is_boolean()) {
                return Some("policy.session.require must be a boolean".into());
            }
            if o.get("max_revocation_age_s").is_some() && nonneg(o.get("max_revocation_age_s")).is_none() {
                return Some("policy.session.max_revocation_age_s must be a non-negative safe integer".into());
            }
        }
        if let Some(pc) = pol.get("schema") {
            let o = match pc.as_object() {
                Some(o) => o,
                None => return Some("policy.schema must be an object".into()),
            };
            if let Some(k) = o.keys().find(|k| *k != "closed_world") {
                return Some(format!("policy.schema: unknown member '{k}'"));
            }
            if o.get("closed_world").is_some_and(|x| !x.is_boolean()) {
                return Some("policy.schema.closed_world must be a boolean".into());
            }
        }
        if let Some(pa) = pol.get("acc") {
            let o = match pa.as_object() {
                Some(o) => o,
                None => return Some("policy.acc must be an object".into()),
            };
            if let Some(k) = o.keys().find(|k| *k != "max_receipt_age_s" && *k != "max_keyset_age_s") {
                return Some(format!("policy.acc: unknown member '{k}'"));
            }
            for k in ["max_receipt_age_s", "max_keyset_age_s"] {
                if o.get(k).is_some() && nonneg(o.get(k)).is_none() {
                    return Some(format!("policy.acc.{k} must be a non-negative safe integer"));
                }
            }
        }
        if let Some(pm) = pol.get("map") {
            let o = match pm.as_object() {
                Some(o) => o,
                None => return Some("policy.map must be an object".into()),
            };
            if let Some(k) = o.keys().find(|k| *k != "require" && *k != "max_residual_risk_ppm") {
                return Some(format!("policy.map: unknown member '{k}'"));
            }
            if o.get("require").is_some_and(|x| !x.is_boolean()) {
                return Some("policy.map.require must be a boolean".into());
            }
            if o.get("max_residual_risk_ppm").is_some() && nonneg(o.get("max_residual_risk_ppm")).is_none() {
                return Some("policy.map.max_residual_risk_ppm must be a non-negative safe integer".into());
            }
        }
    }
    if !opt_obj(c.get("params")) {
        return Some("params must be an object".into());
    }
    for k in ["schema", "session", "acc"] {
        if !opt_obj(c.get(k)) {
            return Some(format!("{k} must be an object"));
        }
    }
    if let Some(m) = c.get("map") {
        let m = match m.as_object() {
            Some(m) => m,
            None => return Some("map must be an object".into()),
        };
        if let Some(k) = m.keys().find(|k| *k != "disclosure") {
            return Some(format!("map: unknown member '{k}'"));
        }
    }
    if let Some(l) = c.get("layers") {
        let l = match l.as_object() {
            Some(l) => l,
            None => return Some("layers must be an object".into()),
        };
        for (k, v) in l {
            if !["org", "site", "std"].contains(&k.as_str()) {
                return Some(format!("layers: unknown member '{k}'"));
            }
            if !v.as_object().is_some_and(|o| o.get("predicates").is_some_and(Value::is_array)) {
                return Some(format!("layers.{k} must be {{predicates: [...]}}"));
            }
        }
    }
    if let Some(wb) = c.get("wb") {
        let wb = match wb.as_object() {
            Some(w) => w,
            None => return Some("wb must be an object".into()),
        };
        if !opt_obj(wb.get("artifacts")) {
            return Some("wb.artifacts must be an object".into());
        }
        if let Some(a) = wb.get("artifacts").and_then(Value::as_object) {
            for k in ["facts", "labels", "verdicts"] {
                if !opt_arr(a.get(k)) {
                    return Some(format!("wb.artifacts.{k} must be an array"));
                }
            }
            if !opt_obj(a.get("offer_set")) {
                return Some("wb.artifacts.offer_set must be an object".into());
            }
        }
        if !opt_obj(wb.get("policy")) {
            return Some("wb.policy must be an object".into());
        }
        if let Some(p) = wb.get("policy").and_then(Value::as_object) {
            if !opt_obj(p.get("world")) || !opt_obj(p.get("provenance")) {
                return Some("wb.policy.world / provenance must be objects".into());
            }
            if !opt_arr(p.get("classifiers")) {
                return Some("wb.policy.classifiers must be an array".into());
            }
        }
    }
    None
}

/// `schemaCtxError`: a present schema context is `{docs: [...], keys: [...]}`.
fn schema_ctx_error(ctx: Option<&IntentV2Context>) -> Step {
    match member(ctx, &["schema"])? {
        None => Ok(()),
        Some(sc) if sc.get("docs").is_some_and(Value::is_array) && sc.get("keys").is_some_and(Value::is_array) => Ok(()),
        Some(_) => Err("the schema context must be {docs: [...], keys: [...]}".into()),
    }
}

/// `sessionCtxError`: grants an array, the revocation evidence an object (when present).
fn session_ctx_error(ctx: Option<&IntentV2Context>) -> Step {
    match member(ctx, &["session"])? {
        None => Ok(()),
        Some(se) => {
            if !opt_arr(se.get("grants")) {
                return Err("the session grants must be an array".into());
            }
            if !opt_obj(se.get("revocation")) {
                return Err("the session revocation evidence must be an object".into());
            }
            if !opt_obj(se.get("revocation_last")) {
                return Err("the tracked last revocation epoch must be an object".into());
            }
            if let Some(pp) = se.get("pq_pins") {
                if !pp.as_object().is_some_and(|m| m.values().all(Value::is_string)) {
                    return Err("the session pq_pins must be an object of strings".into());
                }
            }
            Ok(())
        }
    }
}

/// `accCtxError`: state / monitors / last_seq objects, receipts / sequencer_keys arrays, last_seq values non-negative
/// safe integers.
fn acc_ctx_error(ctx: Option<&IntentV2Context>) -> Step {
    let a = match member(ctx, &["acc"])? {
        None => return Ok(()),
        Some(a) => a,
    };
    for k in ["state", "monitors", "last_seq", "keyset_versions"] {
        if !opt_obj(a.get(k)) {
            return Err(format!("acc.{k} must be an object"));
        }
    }
    if let Some(kv) = a.get("keyset_versions").and_then(Value::as_object) {
        if let Some(e) = kv.values().find_map(tracked_key_set_error) {
            return Err(format!("acc.keyset_versions: {e}"));
        }
    }
    for k in ["receipts", "sequencer_keys"] {
        if !opt_arr(a.get(k)) {
            return Err(format!("acc.{k} must be an array"));
        }
    }
    if let Some(ls) = a.get("last_seq").and_then(Value::as_object) {
        if !ls.values().all(|v| nonneg(Some(v)).is_some()) {
            return Err("acc.last_seq values must be non-negative safe integers".into());
        }
    }
    Ok(())
}

/// `docs.find((d) => actionSchemaDigest(d) === digest)`.
fn schema_by_digest<'a>(docs: &'a [Value], digest: Option<&str>) -> Option<&'a Value> {
    docs.iter().find(|d| action_schema_digest(d).is_some_and(|x| Some(x.as_str()) == digest))
}

/// The PCActn's (wire-valid) action string member.
/// ECMAScript String(p.action?.<k>), as the reference builds the action: absent => "undefined".
fn action_str(p: &Map<String, Value>, k: &str) -> String {
    match p.get("action").and_then(|a| a.get(k)) {
        None => "undefined".into(),
        Some(v) => js_value_string(v),
    }
}

/// ECMAScript String(v) of a JSON value.
fn js_value_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|e| if e.is_null() { String::new() } else { js_value_string(e) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f == f.trunc() && f.abs() < 1e21 { format!("{f:.0}") } else { format!("{f}") }
            }
        }
    }
}

/// Rule 14 (`schema`); on success the matched schema and its `env.canon`.
fn schema_step<'a>(p: &Map<String, Value>, ctx: Option<&'a IntentV2Context>) -> Result<(&'a Value, Map<String, Value>), String> {
    schema_ctx_error(ctx)?;
    let docs = member_list(ctx, &["schema", "docs"])?;
    let keys = Value::Array(member_list(ctx, &["schema", "keys"])?.to_vec());
    let params = member_obj(ctx, &["params"])?;
    if docs.is_empty() {
        return Err("this verifier has no action schema configured".into());
    }
    let doc = match p.get("intent_session") {
        Some(is) => schema_by_digest(docs, s(is.get("schema"))).ok_or("intent_session.schema names no schema this verifier accepts")?,
        None => &docs[0],
    };
    verify_action_schema(doc, &keys).map_err(|e| format!("schema does not verify: {e}"))?;
    if !same(doc.get("aud"), p.get("aud")) {
        return Err("schema aud does not match the PCActn aud".into());
    }
    let params = params.ok_or("no plaintext params to check against the schema (closed world needs them)")?;
    let pv = Value::Object(params.clone());
    let digest = digest_of(&pv);
    if digest.is_none() || digest.as_deref() != s(p.get("action").and_then(|a| a.get("params_digest"))) {
        return Err("params do not hash to action.params_digest".into());
    }
    let verb = action_str(p, "verb");
    let c = conform_action(doc, &verb, &pv);
    if !c.ok {
        return Err(format!("schema_violation: {}: {}", c.code.unwrap_or_default(), c.reason));
    }
    Ok((doc, canon_projection(doc, &verb, params)?))
}

/// The bound, verified session root (shared by rules 13 and 15).
fn bound_root<'a>(is: &Value, ctx: Option<&'a IntentV2Context>, now: i64) -> Result<&'a Value, String> {
    let root = member(ctx, &["session", "root"])?.ok_or("no session root for this session")?;
    // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
    let pins = member(ctx, &["session", "pq_pins"]).ok().flatten();
    verify_session_root_pinned(root, pins).map_err(|e| format!("session root: {e}"))?;
    if session_root_digest(root).as_deref() != s(is.get("root")) {
        return Err("intent_session.root is not the digest of the session root".into());
    }
    if !same(root.get("session"), is.get("session")) {
        return Err("the session root names another session".into());
    }
    if !sint(root.get("expires_at")).is_some_and(|e| now < e) {
        return Err("the session root has expired".into());
    }
    Ok(root)
}

/// Rule 13 (`intent_session`).
fn session_step(p: &Map<String, Value>, grant: &Value, ctx: Option<&IntentV2Context>, now: i64) -> Step {
    let max_age_s = match member(ctx, &["policy", "session", "max_revocation_age_s"])? {
        None => None,
        Some(v) => Some(nonneg(Some(v)).ok_or("session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)")?),
    };
    let is = p.get("intent_session").ok_or("this verifier requires an intent_session but the PCActn carries none")?;
    session_ctx_error(ctx)?;
    let prior = member_list(ctx, &["session", "grants"])?;
    let evidence = member(ctx, &["session", "revocation"])?;
    let intent = p.get("intent").ok_or("an intent_session needs the envelope.intent binding")?;
    let root = bound_root(is, ctx, now)?;
    if !same(root.get("intent_ref"), intent.get("ref")) {
        return Err("intent.ref is not the session statement".into());
    }
    let rschema = root.get("schema");
    if !same(rschema.and_then(|x| x.get("digest")), is.get("schema")) {
        return Err("intent_session.schema is not the session schema".into());
    }
    if !same(rschema.and_then(|x| x.get("aud")), p.get("aud")) {
        return Err("the session schema is for another audience".into());
    }
    let seq = nonneg(is.get("seq")).ok_or("intent_session.seq is not a safe integer")?;
    let task_map = root.get("layers").and_then(|l| l.get("task")).and_then(|t| t.get("map_digest"));
    if seq == 0 && !same(intent.get("map_digest"), task_map) {
        return Err("a seq-0 action must use the session task map".into());
    }
    let gc = grant_session_caveat(grant);
    if let Some(e) = intent_session_caveat_error(gc) {
        return Err(format!("admitting root: {e}"));
    }
    let gc = gc.ok_or("admitting root: not an intent_session caveat")?;
    if !same(gc.get("session"), is.get("session")) || !same(gc.get("root"), is.get("root")) || !same(gc.get("seq"), is.get("seq")) {
        return Err("the admitting root is bound to another session, root or seq".into());
    }
    let principals: Vec<String> =
        root.get("principals").and_then(Value::as_array).into_iter().flatten().filter_map(|x| s(x.get("key")).map(String::from)).collect();
    let is_principal = |g: &Value| s(g.get("issuer")).is_some_and(|i| principals.iter().any(|k| k == i));
    if !is_principal(grant) {
        return Err("the admitting root is not signed by a session principal".into());
    }
    let seq = seq as usize;
    if prior.len() < seq {
        return Err(format!("the verifier does not hold the {seq} earlier grants of this session"));
    }
    for i in 0..seq {
        let g = &prior[i];
        if !g.as_object().is_some_and(|o| o.get("id").is_some_and(Value::is_string) && o.get("issuer").is_some_and(Value::is_string)) {
            return Err(format!("session grant {i} is not a capability"));
        }
        if let Err(e) = suite_of(g.get("alg")) {
            return Err(format!("session grant {i}: {e}"));
        }
        let c = grant_session_caveat(g);
        let ok = intent_session_caveat_error(c).is_none()
            && c.is_some_and(|c| same(c.get("session"), is.get("session")) && same(c.get("root"), is.get("root")) && sint(c.get("seq")) == Some(i as i64));
        if !ok {
            return Err(format!("session grant {i} does not belong to this session at seq {i}"));
        }
        if !is_principal(g) {
            return Err(format!("session grant {i} is not signed by a session principal"));
        }
        if i > 0 && !(b32(prior[i - 1].get("id")) && same(c.and_then(|c| c.get("prev")), prior[i - 1].get("id"))) {
            return Err(format!("session grant {i} does not chain to grant {}", i - 1));
        }
    }
    if seq > 0 && !(b32(prior[seq - 1].get("id")) && same(gc.get("prev"), prior[seq - 1].get("id"))) {
        return Err(format!("the admitting root does not chain to grant {}", seq - 1));
    }
    let rev = root.get("revocation");
    if rev.is_some() || max_age_s.is_some() {
        let ages = [rev.and_then(|r| nonneg(r.get("max_age_s"))), max_age_s];
        let max_age = ages.iter().flatten().min().copied().ok_or("revocation: no max age")?;
        let max_age_ms = (max_age as f64) * 1000.0;
        let rev = rev.ok_or("revocation: the policy requires a revocation epoch but the session root names no revocation authority")?;
        let authority = s(rev.get("key")).ok_or("revocation: the session root names no revocation authority")?;
        let session = s(is.get("session")).unwrap_or("");
        let id_of = |g: &Value| s(g.get("id")).map(String::from).ok_or("a session grant has no id (fail closed)".to_string());
        let mut ids = vec![session_revocation_id(session), map_revocation_id(s(intent.get("map_digest")).unwrap_or(""))];
        for g in &prior[..seq] {
            ids.push(delta_revocation_id(&id_of(g)?));
        }
        ids.push(delta_revocation_id(&id_of(grant)?));
        if let Some(std) = root.get("layers").and_then(|l| l.get("std")).filter(|x| x.is_object()) {
            let version = sint(std.get("version")).ok_or("layers.std.version is not a safe integer")?;
            ids.push(profile_revocation_id(s(std.get("profile")).unwrap_or(""), &version.to_string()));
        }
        // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
        let last = member(ctx, &["session", "revocation_last"])?;
        check_session_revocation(evidence, session, authority, &ids, now as f64, max_age_ms, None, rev.get("pq_pk"), last)
            .map_err(|e| format!("revocation: {e}"))?;
    }
    Ok(())
}

/// Rule 15 (`accumulators`); on success `env.acc` and `env.mon`.
fn acc_step(pv: &Value, p: &Map<String, Value>, ctx: Option<&IntentV2Context>, now: i64) -> Result<(Map<String, Value>, Map<String, Value>), String> {
    let is = p.get("intent_session").ok_or("no intent_session")?;
    let root = bound_root(is, ctx, now)?;
    acc_ctx_error(ctx)?;
    schema_ctx_error(ctx)?;
    let docs = member_list(ctx, &["schema", "docs"])?;
    let params = member_obj(ctx, &["params"])?;
    let state = member_obj(ctx, &["acc", "state"])?;
    let mons = member_obj(ctx, &["acc", "monitors"])?;
    let receipts = member_list(ctx, &["acc", "receipts"])?;
    let last_seq = member_obj(ctx, &["acc", "last_seq"])?;
    let key_sets = Value::Array(member_list(ctx, &["acc", "sequencer_keys"])?.to_vec());
    let verb = action_str(p, "verb");
    let empty: Vec<Value> = Vec::new();
    let claims: &[Value] = is.get("acc").and_then(Value::as_array).map_or(&empty, Vec::as_slice);
    let accs: &[Value] = root.get("accumulators").and_then(Value::as_array).map_or(&empty, Vec::as_slice);
    let holder_kind = |a: &Value| s(a.get("holder").and_then(|h| h.get("kind"))).map(String::from);
    for c in claims {
        let cid = s(c.get("id")).unwrap_or("");
        let a = accs.iter().find(|a| s(a.get("id")) == Some(cid)).ok_or_else(|| format!("claim '{cid}' names no accumulator of the session"))?;
        if holder_kind(a).as_deref() == Some("wallet") {
            return Err(format!("accumulator '{cid}' is wallet-held and cannot be claimed at a site"));
        }
    }
    let schema_doc = schema_by_digest(docs, s(is.get("schema")));
    let mut acc_env = Map::new();
    for a in accs {
        let ao = a.as_object().ok_or("accumulator is not an object")?;
        let id = s(ao.get("id")).unwrap_or("");
        let kind = holder_kind(a);
        if kind.as_deref() == Some("wallet") {
            continue;
        }
        let agg = s(ao.get("agg")).unwrap_or("");
        let sel_unit = ao.get("sel").and_then(|x| x.get("accumulates_into"));
        if sel_unit.is_some() && schema_doc.is_none() {
            return Err(format!("accumulator '{id}' selects by accumulates_into but the session schema is not available"));
        }
        let selected = acc_selects(ao, &verb, schema_doc)?;
        let claim = claims.iter().find(|c| s(c.get("id")) == Some(id));
        let pre = state.and_then(|st| st.get(id));
        if !selected {
            if claim.is_some() {
                return Err(format!("claim '{id}' for an accumulator this action does not feed"));
            }
            if kind.as_deref() == Some("site_local") {
                if let Some(pre) = pre {
                    if let Some(e) = pre_state_error(agg, pre) {
                        return Err(format!("accumulator '{id}': {e}"));
                    }
                    acc_env.insert(id.into(), serde_json::json!({ "post": pre_value(agg, pre) }));
                }
            }
            continue;
        }
        let claim = claim.ok_or_else(|| format!("no claim for accumulator '{id}' that this action feeds"))?;
        let params = params.ok_or("no plaintext params to compute accumulator values")?;
        if let Some(key) = s(ao.get("key")) {
            let name = key.strip_prefix("action.params.").unwrap_or(key);
            if !params.contains_key(name) {
                return Err(format!("accumulator '{id}': the key parameter {key} is missing"));
            }
            let kd = match schema_doc {
                Some(doc) => schema_verb(doc, &verb)?.and_then(|v| v.get("params")).and_then(|ps| ps.get(key)),
                None => None,
            };
            let identity = kd.and_then(|kd| s(kd.get("semantic"))).is_some_and(|sm| !sm.starts_with("text."));
            if !identity {
                return Err(format!("accumulator '{id}': the key must be a schema-declared identity (not free text)"));
            }
        }
        let v = acc_value_of(ao, &verb, params, schema_doc)?.map_err(|e| format!("accumulator '{id}': {e}"))?;
        let post: i64 = if kind.as_deref() == Some("site_local") {
            if claim.get("receipt").is_some() {
                return Err(format!("accumulator '{id}' is site-local: a receipt is not accepted"));
            }
            let pre = pre.ok_or_else(|| format!("no state for site-local accumulator '{id}'"))?;
            if let Some(e) = pre_state_error(agg, pre) {
                return Err(format!("accumulator '{id}': {e}"));
            }
            combine_acc(agg, pre, &v).ok_or_else(|| format!("accumulator '{id}' overflows 2^53-1"))?
        } else {
            let rid = claim.get("receipt").ok_or_else(|| format!("accumulator '{id}' is sequenced: the claim needs a reservation receipt"))?;
            let rc = receipts
                .iter()
                .find(|x| acc_receipt_digest(x).is_some_and(|d| Some(d.as_str()) == s(Some(rid))))
                .ok_or_else(|| format!("the reservation receipt for '{id}' was not presented"))?;
            let holder = obj(ao.get("holder")).ok_or("holder is not an object")?;
            let age_ms = |k: &str, default: i64| -> f64 {
                match member(ctx, &["policy", "acc", k]) {
                    Ok(Some(v)) => nonneg(Some(v)).map_or(f64::NAN, |x| x as f64 * 1000.0),
                    _ => default as f64,
                }
            };
            let fresh = ReceiptFreshness {
                max_receipt_age_ms: age_ms("max_receipt_age_s", DEFAULT_MAX_RECEIPT_AGE_MS),
                max_keyset_age_ms: age_ms("max_keyset_age_s", DEFAULT_MAX_KEYSET_AGE_MS),
                tracked: s(holder.get("root"))
                    .and_then(|root| member(ctx, &["acc", "keyset_versions"]).ok().flatten().and_then(|kv| kv.get(root)))
                    .and_then(|t| Some((sint(t.get("version"))?, s(t.get("digest"))?.to_string()))),
            };
            // the reference (verifyReceiptAgainstHolder is a boolean) gives ONE reason for every refusal of this step (shape,
            // clock, key set, signature); only a suite the dispatch refuses keeps its distinct unsupported_suite reason
            verify_receipt_against_holder(rc, holder, Some(&key_sets), now as f64, &fresh).map_err(|e| {
                if e.contains(super::intent_suite::UNSUPPORTED_SUITE) {
                    format!("the reservation receipt for '{id}': {e}")
                } else {
                    format!("the reservation receipt for '{id}' is not signed by a key the session sequencer's root-signed key set lists for its issue time")
                }
            })?;
            if !same(rc.get("session"), is.get("session")) || s(rc.get("acc")) != Some(id) || !same(rc.get("aud"), p.get("aud")) {
                return Err(format!("the reservation receipt for '{id}' is for another session, accumulator or audience"));
            }
            let rd = pcactn_reservation_digest(pv).ok_or("the PCActn has no reservation digest (fail closed)")?;
            if s(rc.get("pcactn_digest")) != Some(rd.as_str()) {
                return Err(format!("the reservation receipt for '{id}' is for another action"));
            }
            if !sint(rc.get("expires_at")).is_some_and(|e| now <= e) {
                return Err(format!("the reservation receipt for '{id}' has expired"));
            }
            let seq = sint(rc.get("seq")).ok_or("receipt seq is not a safe integer")?;
            if let Some(last) = last_seq.and_then(|ls| ls.get(id)) {
                let last = nonneg(Some(last)).ok_or_else(|| format!("context.intent_v2.acc.last_seq.{id} must be a non-negative safe integer"))?;
                if seq <= last {
                    return Err(format!("the reservation receipt for '{id}' replays seq {seq} (last accepted {last})"));
                }
            }
            if !receipt_arithmetic_ok(agg, rc, v.val) {
                return Err(format!("the reservation receipt for '{id}' does not add up"));
            }
            nonneg(rc.get("post")).ok_or("receipt post is not a safe integer")?
        };
        if let Some(dm) = nonneg(ao.get("domain_max")) {
            if post > dm {
                return Err(format!("accumulator '{id}' post {post} is outside its domain (max {dm})"));
            }
        }
        if nonneg(claim.get("post")) != Some(post) {
            return Err(format!("the claimed post for '{id}' differs from the verifier's {post}"));
        }
        acc_env.insert(id.into(), serde_json::json!({ "post": post }));
    }
    let mut mon_env = Map::new();
    for m in root.get("monitors").and_then(Value::as_array).map_or(&empty, |x| x) {
        let mid = s(m.get("id")).unwrap_or("");
        match mons.and_then(|ms| ms.get(mid)) {
            Some(Value::String(x)) if monitor_states(m).contains(x) => {
                mon_env.insert(mid.into(), serde_json::json!({ "state": x }));
            }
            _ => return Err(format!("no valid state for monitor '{mid}'")),
        }
    }
    Ok((acc_env, mon_env))
}

/// The `layers` check (`decideLayerCeilings`): org, then site, then std. An absent ceiling is the whole space; a
/// configured one (`{predicates: [...]}`, checked with the context) admits the action iff some predicate matches.
fn layers_step(layers: &Value, ctx_root: &Value) -> Step {
    let l = layers.as_object().ok_or("context.intent_v2.layers must be an object")?;
    for k in ["org", "site", "std"] {
        let preds: Vec<Value> = match l.get(k) {
            None => continue,
            Some(o) => o
                .as_object()
                .filter(|m| m.len() == 1)
                .and_then(|m| m.get("predicates"))
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| format!("layers: the {k} ceiling is malformed (null or not exactly {{predicates: [...]}})"))?,
        };
        if !evaluate_predicates(&preds, &Ctx::new(ctx_root)) {
            return Err(format!("layers: the action is outside the {k} ceiling (a ceiling is never a question)"));
        }
    }
    Ok(())
}

/// Rule 19 (`map`, V15 Z0): the PCActn's committed map opens at the action's cell, which is in the committed grant, and
/// the committed residual risk is within `policy.map.max_residual_risk_ppm` when set.
fn map_step(p: &Map<String, Value>, ctx: Option<&IntentV2Context>) -> Step {
    let is = p.get("intent_session");
    if is.and_then(|x| x.get("map_form")).and_then(Value::as_str) != Some(MAP_FORM_COMMIT) {
        return Err("this verifier requires a committed map (intent_session.map_form \"commit\")".into());
    }
    let intent = p.get("intent").ok_or("a committed map needs the envelope.intent binding")?;
    let disclosure = member(ctx, &["map", "disclosure"])?.ok_or("no disclosure of the committed map was presented")?;
    let eps = member(ctx, &["policy", "map", "max_residual_risk_ppm"])?.and_then(|v| nonneg(Some(v)));
    let action = p.get("action").cloned().unwrap_or_else(|| Value::Object(Map::new()));
    let d = decide_map_disclosure(intent.get("map_digest"), &action, member(ctx, &["params"])?, Some(disclosure), eps);
    if d.ok {
        Ok(())
    } else {
        Err(d.reason)
    }
}

fn run(out: &mut IntentV2Decision, name: &'static str, f: impl FnOnce() -> Step) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| Err(format!("{name} error (fail closed)")));
    let ok = r.is_ok();
    out.checks.push(IntentV2Check { name, ok, reason: r.err().unwrap_or_default() });
}

/// The W-B input (`IntentWBInput`) for this PCActn, or the malformed verifier-state member.
fn wb_input(p: &Map<String, Value>, ctx: Option<&IntentV2Context>, now: i64, action: Value) -> Result<Value, String> {
    member_obj(ctx, &["wb"])?;
    let mut wi = Map::new();
    let is = p.get("intent_session").cloned().unwrap_or(Value::Null);
    wi.insert("now".into(), Value::from(now));
    wi.insert("aud".into(), p.get("aud").cloned().unwrap_or(Value::Null));
    wi.insert("session".into(), is.get("session").cloned().unwrap_or(Value::Null));
    wi.insert("action".into(), action);
    wi.insert("intent_session".into(), is);
    if let Some(a) = member(ctx, &["wb", "artifacts"])? {
        wi.insert("artifacts".into(), a.clone());
    }
    let policy = member(ctx, &["wb", "policy"])?.cloned().unwrap_or_else(|| Value::Object(Map::new()));
    wi.insert("policy".into(), policy);
    Ok(Value::Object(wi))
}

/// Run the v2 checks on a wire-valid PCActn (`decideIntentV2`). Never panics: an internal error fails the check being
/// evaluated. A malformed verifier context ([`intent_v2_context_error`]) fails every v2 check that could be reported
/// (`schema`, `intent_session`, and `accumulators` when the PCActn carries `intent_session`); a clock that is not a safe
/// integer fails every reported check.
pub fn decide_intent_v2(pcactn: &Value, grant: &Value, ctx: Option<&IntentV2Context>, now: i64) -> IntentV2Decision {
    let mut out = IntentV2Decision::default();
    let p = match pcactn.as_object() {
        Some(p) => p,
        None => return out,
    };
    let present = p.contains_key("intent_session");
    let committed_map = p.get("intent_session").and_then(|is| is.get("map_form")).and_then(Value::as_str) == Some(MAP_FORM_COMMIT);
    if let Some(e) = ctx.and_then(|c| intent_v2_context_error(c.as_json())) {
        for name in ["schema", "intent_session", "accumulators", "map"] {
            if (name != "accumulators" || present) && (name != "map" || committed_map) {
                out.checks.push(IntentV2Check { name, ok: false, reason: format!("malformed v2 context: {e}") });
            }
        }
        return out;
    }
    let map_active = committed_map || flag_on(ctx, &["policy", "map", "require"]);
    let clock_ok = (-MAX_SAFE..=MAX_SAFE).contains(&now);
    let run = |out: &mut IntentV2Decision, name: &'static str, f: &mut dyn FnMut() -> Step| {
        run(out, name, || if clock_ok { f() } else { Err("the verifier clock is not a safe integer (fail closed)".into()) })
    };
    let mut canon: Option<Map<String, Value>> = None;
    if present || flag_on(ctx, &["policy", "schema", "closed_world"]) {
        run(&mut out, "schema", &mut || {
            canon = Some(schema_step(p, ctx)?.1);
            Ok(())
        });
    }
    if let Some(c) = &canon {
        out.env.insert("canon".into(), Value::Object(c.clone()));
    }
    if present || flag_on(ctx, &["policy", "session", "require"]) {
        run(&mut out, "intent_session", &mut || session_step(p, grant, ctx, now));
    }
    let params = match member(ctx, &["params"]) {
        Ok(Some(v @ Value::Object(_))) => v.clone(),
        _ => Value::Object(Map::new()),
    };
    let action = serde_json::json!({ "verb": action_str(p, "verb"), "resource": action_str(p, "resource"), "params": params });
    if present {
        let layers = member(ctx, &["layers"]);
        if !matches!(layers, Ok(None)) {
            let mut env = Map::new();
            if let Some(c) = &canon {
                env.insert("canon".into(), Value::Object(c.clone()));
            }
            let root = serde_json::json!({ "action": action.clone(), "env": Value::Object(env) });
            run(&mut out, "layers", &mut || match &layers {
                Ok(Some(l)) => layers_step(l, &root),
                Ok(None) => Ok(()),
                Err(e) => Err(e.clone()),
            });
        }
    }
    if !present {
        if map_active {
            run(&mut out, "map", &mut || map_step(p, ctx));
        }
        return out;
    }
    let mut acc_env = None;
    run(&mut out, "accumulators", &mut || {
        acc_env = Some(acc_step(pcactn, p, ctx, now)?);
        Ok(())
    });
    if let Some((acc, mon)) = acc_env {
        out.env.insert("acc".into(), Value::Object(acc));
        out.env.insert("mon".into(), Value::Object(mon));
    }
    if map_active {
        run(&mut out, "map", &mut || map_step(p, ctx));
    }
    let wi = match wb_input(p, ctx, now, action) {
        Ok(wi) => wi,
        Err(e) => {
            out.checks.push(IntentV2Check { name: "facts", ok: false, reason: format!("W-B: {e}") });
            return out;
        }
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decide_intent_wb(&wi))) {
        Err(_) => out.checks.push(IntentV2Check { name: "facts", ok: false, reason: "W-B error (fail closed)".into() }),
        Ok(wb) => {
            for (name, c) in &wb.checks {
                let (ok, reason) = match c {
                    WbCheck::Pass => (true, String::new()),
                    WbCheck::Question => (false, format!("intent_required: {}", if wb.reason.is_empty() { "a question is required" } else { &wb.reason })),
                    WbCheck::Fail => (false, if wb.reason.is_empty() { "rejected".to_string() } else { wb.reason.clone() }),
                };
                out.checks.push(IntentV2Check { name, ok, reason });
            }
            if wb.outcome != "deny" {
                for k in ["world", "prov", "class"] {
                    if let Some(v) = wb.env.get(k) {
                        out.env.insert(k.into(), v.clone());
                    }
                }
            }
        }
    }
    out
}

/// True iff any v2 check would be reported (the PCActn carries `intent_session`, a v2 policy flag is set, or the
/// context is malformed and the checks fail closed).
pub fn intent_v2_active(pcactn: &Value, ctx: Option<&IntentV2Context>) -> bool {
    pcactn.get("intent_session").is_some()
        || ctx.is_some_and(|c| intent_v2_context_error(c.as_json()).is_some())
        || flag_on(ctx, &["policy", "schema", "closed_world"])
        || flag_on(ctx, &["policy", "session", "require"])
        || flag_on(ctx, &["policy", "map", "require"])
}
