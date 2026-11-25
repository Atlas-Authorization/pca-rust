//! PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, Access Evaluations boxcar, the COAZ
//! MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over `{"path", "body"}` values and the three
//! Search APIs (subject / resource / action). JSON-valued: requests and responses are `serde_json::Value`, byte-identical to the
//! reference including its `undefined` / `null` / template-literal quirks. A reference throw is an `Err` (or a 500 / fail-closed deny
//! where the reference catches it).
//!
//! Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any raised error (or
//! panic of a host closure) is `decision: false`.
//!
//! shortcut: the Policy-VM (`decide` / `derive_decide_input`) is injected through [`PdpConfig`] (the crate has no TypeScript-shaped
//! one); a PDP without it fails closed on the path that needs it. `admits_concrete` defaults to the native analyzer. The
//! `enforce.taint` gate is evaluated after the core verdict (the crate's verifier has no taint option), so it never changes the
//! first failing reason. A reference `Promise` is a plain call here.
use crate::intent_v2::js_value_string;
use crate::oauth::truthy;
use crate::taint::{panic_message, taint_gate_check, TaintGate};
use crate::{FreshnessGate, VerifyOptions};
use serde_json::{json, Map, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

pub const PCA_APPROVAL_KEY: &str = "pca_approval";
pub const PCA_ACTION_KEY: &str = "pca_action";
pub const PCA_PROVENANCE_KEY: &str = "pca_provenance";
pub const DEFAULT_MAX_EVALUATIONS: f64 = 100.0;
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";
pub const COAZ_TOOL_PATH: &str = "/access/v1/mcp/tool/evaluation";
pub const SEARCH_SUBJECT_PATH: &str = "/access/v1/search/subject";
pub const SEARCH_RESOURCE_PATH: &str = "/access/v1/search/resource";
pub const SEARCH_ACTION_PATH: &str = "/access/v1/search/action";

static NULL: Value = Value::Null;

/// A host function over JSON: `Err` is a throw.
pub type JsonFn = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
/// `(pcactn, ctx) -> decide input`.
pub type DeriveFn = Arc<dyn Fn(&Value, &Value) -> Result<Value, String> + Send + Sync>;
pub type AdmitsFn = Arc<dyn Fn(&Value, &Value) -> Result<bool, String> + Send + Sync>;
pub type ResolveFn = Arc<dyn Fn(&Value) -> Result<Option<PdpContext>, String> + Send + Sync>;

/// The optional verifier gates of a resolved context.
#[derive(Clone, Default)]
pub struct Enforce {
    pub freshness: Option<FreshnessGate>,
    pub taint: Option<TaintGate>,
    /// Attestation is not supported by this verifier: `true` fails closed.
    pub attestation: bool,
}

/// What `resolve` returns for a request: the grant, its policy and the optional chain / plan / risk / budget.
#[derive(Clone, Default)]
pub struct PdpContext {
    pub grant: Value,
    pub chain: Option<Value>,
    pub policy: Value,
    pub plan: Option<Value>,
    pub risk: Option<Value>,
    pub budget: Option<Value>,
    pub enforce: Enforce,
    /// Overrides [`default_to_action`] for this request.
    pub to_action: Option<JsonFn>,
}

/// This PDP's own audience id, compared to a PCActn's signed `aud`.
#[derive(Clone, Debug, PartialEq)]
pub enum Audience {
    /// Omitted: the verifier gets no audience and refuses a PCActn that carries an `aud` (fail closed).
    Absent,
    /// `null`: accept any audience (the PCActn's own `aud` is taken).
    AcceptAny,
    Exact(String),
}

pub struct PdpConfig {
    pub resolve: ResolveFn,
    pub audience: Audience,
    pub authorized_plan_roots: Option<Vec<String>>,
    pub insecure_skip_plan_root_check: bool,
    /// Clock (epoch ms); default the system clock.
    pub now: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    pub tool_capability: Option<Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>>,
    /// Deny every request that does not carry a signed PCActn (default true).
    pub require_proof: bool,
    /// `input = {operation, pcactn, provenance?}`, returns `{allow, reason?}`.
    pub authorizer: Option<JsonFn>,
    /// Deny every PCActn request when no authorizer is configured (default true).
    pub require_authorizer: bool,
    /// Boxcar bound (default [`DEFAULT_MAX_EVALUATIONS`]; `f64::INFINITY` removes it).
    pub max_evaluations: Option<f64>,
    /// The Policy-VM: `decide(derive_decide_input(pcactn, ctx))` returns `{releaseGuardianShare, admit, r, requiredThreshold, reasons}`.
    pub decide: Option<JsonFn>,
    pub derive_decide_input: Option<DeriveFn>,
    pub admits_concrete: Option<AdmitsFn>,
}

impl PdpConfig {
    pub fn new(resolve: ResolveFn) -> PdpConfig {
        PdpConfig {
            resolve,
            audience: Audience::Absent,
            authorized_plan_roots: None,
            insecure_skip_plan_root_check: false,
            now: None,
            tool_capability: None,
            require_proof: true,
            authorizer: None,
            require_authorizer: true,
            max_evaluations: None,
            decide: None,
            derive_decide_input: None,
            admits_concrete: None,
        }
    }
}

// ---- JS helpers -------------------------------------------------------------------------------------------------------------

/// `x.k` in JavaScript: null throws, anything but an object has no such member.
fn prop<'a>(x: &'a Value, k: &str) -> Result<Option<&'a Value>, String> {
    match x {
        Value::Null => Err(format!("Cannot read properties of null (reading '{k}')")),
        Value::Object(m) => Ok(m.get(k)),
        _ => Ok(None),
    }
}

fn is_rec(x: &Value) -> bool {
    x.is_object()
}

fn is_str(x: Option<&Value>) -> bool {
    matches!(x, Some(Value::String(_)))
}

fn tpl(v: Option<&Value>) -> String {
    v.map_or("undefined".to_string(), js_value_string)
}

/// `a === b` for JSON values (objects and arrays are references, never equal).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Null), Some(Value::Null)) => true,
        (None, None) => true,
        _ => false,
    }
}

fn err_text(e: &str) -> String {
    if e.is_empty() {
        "unknown".into()
    } else {
        e.to_string()
    }
}

fn field_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    match prop(v, k)? {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("authzen: {k} must be a string")),
    }
}

// ---- guards -----------------------------------------------------------------------------------------------------------------

fn type_id(x: &Value) -> bool {
    is_rec(x) && is_str(x.get("type")) && is_str(x.get("id"))
}

pub fn is_authzen_subject(x: &Value) -> bool {
    type_id(x)
}

pub fn is_authzen_action(x: &Value) -> bool {
    is_rec(x) && is_str(x.get("name"))
}

pub fn is_authzen_resource(x: &Value) -> bool {
    type_id(x)
}

pub fn is_access_evaluation_request(x: &Value) -> bool {
    is_rec(x)
        && is_authzen_subject(&x["subject"])
        && is_authzen_action(&x["action"])
        && is_authzen_resource(&x["resource"])
        && x.get("context").map_or(true, is_rec)
}

pub fn is_access_evaluations_request(x: &Value) -> bool {
    is_rec(x) && x.get("evaluations").is_some_and(Value::is_array)
}

pub fn is_coaz_tool_authorization_request(x: &Value) -> bool {
    is_rec(x) && is_authzen_subject(&x["subject"]) && is_rec(&x["tool"]) && is_str(x["tool"].get("name"))
}

fn is_required_threshold(x: &Value) -> bool {
    is_rec(x)
        && x.get("t").and_then(Value::as_f64).is_some_and(|t| t == 1.0 || t == 2.0 || t == 3.0)
        && is_str(x.get("proof"))
        && x.get("optimisticAllowed").is_some_and(Value::is_boolean)
}

// ---- AARP -------------------------------------------------------------------------------------------------------------------

/// The AARP pending-approval reference of a decision, or `Value::Null`. `Err` is the reference's throw on a null decision / context.
pub fn approval_of(resp: &Value) -> Result<Value, String> {
    let ctx = match prop(resp, "context")? {
        None => return Ok(Value::Null),
        Some(c) => c,
    };
    let p = match prop(ctx, PCA_APPROVAL_KEY)? {
        Some(p) if is_rec(p) => p,
        _ => return Ok(Value::Null),
    };
    let id = match p.get("auth_req_id") {
        Some(Value::String(s)) if p.get("approval_required") == Some(&Value::Bool(true)) => s.clone(),
        _ => return Ok(Value::Null),
    };
    let tier: i64 = if p.get("tier").and_then(Value::as_f64) == Some(3.0) { 3 } else { 2 };
    let rt = match p.get("required_threshold") {
        Some(rt) if is_required_threshold(rt) => rt.clone(),
        _ => json!({ "t": tier, "proof": if tier == 3 { "strong" } else { "standard" }, "optimisticAllowed": false }),
    };
    let num_or = |k: &str, d: i64| match p.get(k) {
        Some(n) if n.is_number() => n.clone(),
        _ => json!(d),
    };
    let str_or = |k: &str, d: &str| match p.get(k) {
        Some(Value::String(s)) => s.clone(),
        _ => d.to_string(),
    };
    Ok(json!({
        "approval_required": true,
        "auth_req_id": id,
        "tier": tier,
        "required_threshold": rt,
        "goal_commit": str_or("goal_commit", ""),
        "risk": num_or("risk", 1),
        "reason": str_or("reason", "approval required"),
        "requested_at": num_or("requested_at", 0),
    }))
}

pub fn is_approval_required(resp: &Value) -> Result<bool, String> {
    Ok(!approval_of(resp)?.is_null())
}

// ---- mapping ----------------------------------------------------------------------------------------------------------------

fn deny(reason: &str, id: Option<&str>, status: Option<i64>) -> Value {
    let mut context = Map::new();
    context.insert("reason_admin".into(), json!({ "denied": true, "reason": reason }));
    context.insert("reason_user".into(), json!({ "message": reason }));
    if let Some(s) = status {
        context.insert("error".into(), json!({ "status": s, "message": reason }));
    }
    if let Some(i) = id {
        context.insert("id".into(), json!(i));
    }
    json!({ "decision": false, "context": Value::Object(context) })
}

fn permit(reason: &str) -> Value {
    json!({ "decision": true, "context": { "reason_admin": { "reason": reason } } })
}

fn pick_reversibility(req: &Value) -> Option<String> {
    if let Some(Value::String(s)) = req["action"].get("properties").and_then(|p| p.get("reversibility_class")) {
        return Some(s.clone());
    }
    if let Some(Value::String(s)) = req.get("context").and_then(|c| c.get("reversibility_class")) {
        return Some(s.clone());
    }
    None
}

fn env_from_context(context: Option<&Value>) -> Option<Value> {
    let m = context?.as_object()?;
    let out: Map<String, Value> =
        m.iter().filter(|(k, _)| k.as_str() != PCA_ACTION_KEY && k.as_str() != PCA_APPROVAL_KEY).map(|(k, v)| (k.clone(), v.clone())).collect();
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Default AuthZEN to PCA action mapping: verb = `action.name`; resource = `"type:id"` (just the type when the id is empty);
/// params = `resource.properties` overlaid by `action.properties`; subject = `subject.properties`; env = context minus the PCA keys.
pub fn default_to_action(req: &Value) -> Result<Value, String> {
    let rtype = field_str(&req["resource"], "type")?;
    let rid = field_str(&req["resource"], "id")?;
    let name = field_str(&req["action"], "name")?;
    let resource = if rid.is_empty() { rtype.to_string() } else { format!("{rtype}:{rid}") };
    let mut params = Map::new();
    for src in [&req["resource"]["properties"], &req["action"]["properties"]] {
        if let Some(o) = src.as_object() {
            for (k, v) in o {
                params.insert(k.clone(), v.clone());
            }
        }
    }
    let mut out = Map::new();
    out.insert("verb".into(), json!(name));
    out.insert("resource".into(), json!(resource));
    out.insert("params".into(), Value::Object(params));
    if let Some(rc) = pick_reversibility(req) {
        out.insert("reversibilityClass".into(), json!(rc));
    }
    if let Some(sp) = req["subject"].get("properties").filter(|p| is_rec(p)) {
        out.insert("subject".into(), sp.clone());
    }
    if let Some(env) = env_from_context(req.get("context")) {
        out.insert("env".into(), env);
    }
    Ok(Value::Object(out))
}

enum Carried {
    Absent,
    Malformed,
    Pcactn(Value),
}

fn pcactn_from_context(context: Option<&Value>) -> Carried {
    let raw = match context.and_then(|c| c.as_object()).and_then(|m| m.get(PCA_ACTION_KEY)) {
        None | Some(Value::Null) => return Carried::Absent,
        Some(r) => r,
    };
    let Value::String(s) = raw else { return Carried::Malformed };
    if s.len() > crate::MAX_ARTIFACT_BYTES {
        return Carried::Malformed;
    }
    match crate::strict_parse(s) {
        Ok(v) if v.is_object() => Carried::Pcactn(v),
        _ => Carried::Malformed,
    }
}

fn params_of(action: &Value) -> Value {
    match action.get("params") {
        Some(p) if is_rec(p) => p.clone(),
        _ => Value::Object(Map::new()),
    }
}

fn fresh_budget(grant: &Value, now: i64) -> Value {
    let b = crate::authorize::read_envelope(grant)
        .and_then(|e| e.get("risk_policy").and_then(|r| r.get("bMax")).cloned())
        .filter(Value::is_number)
        .unwrap_or(json!(0));
    json!({ "B": b, "tau": now, "asOf": now })
}

fn approval_required(p: &Value, decision: &Value, grant: &Value, now: i64) -> Result<Value, String> {
    let rt = &decision["requiredThreshold"];
    let tier: i64 = if prop(rt, "t")?.and_then(Value::as_f64).is_some_and(|t| t >= 3.0) { 3 } else { 2 };
    let reasons = decision.get("reasons").cloned();
    let first = reasons.as_ref().and_then(|r| r.as_array()).and_then(|a| a.first()).filter(|v| !v.is_null()).cloned();
    let reason = first.unwrap_or_else(|| json!(format!("requires tier-{tier} co-sign")));
    let act = &p["action"];
    let mut body = Map::new();
    body.insert("d".into(), json!("atlas-pca/authzen/aarp/v1"));
    for k in ["verb", "resource", "params_digest"] {
        if let Some(v) = act.get(k) {
            body.insert(k.into(), v.clone());
        }
    }
    if let Some(c) = p.get("counter") {
        body.insert("counter".into(), c.clone());
    }
    body.insert("at".into(), json!(now));
    let auth_req_id = crate::hash_canonical(&Value::Object(body));
    let goal_commit = crate::authorize::read_envelope(grant).and_then(|e| e.get("goal_commit").cloned()).unwrap_or(json!(""));
    let r = decision.get("r").cloned().unwrap_or(Value::Null);
    let mut admin = Map::new();
    admin.insert("stage".into(), json!("step_up"));
    admin.insert("risk".into(), r.clone());
    admin.insert("threshold".into(), rt.clone());
    if let Some(rs) = reasons {
        admin.insert("reasons".into(), rs);
    }
    let pending = json!({
        "approval_required": true,
        "auth_req_id": auth_req_id,
        "tier": tier,
        "required_threshold": rt,
        "goal_commit": goal_commit,
        "risk": r,
        "reason": reason,
        "requested_at": now,
    });
    let mut context = Map::new();
    context.insert("id".into(), json!(auth_req_id));
    context.insert("reason_admin".into(), Value::Object(admin));
    context.insert("reason_user".into(), json!({ "message": "approval required before this action can proceed" }));
    context.insert(PCA_APPROVAL_KEY.into(), pending);
    Ok(json!({ "decision": false, "context": Value::Object(context) }))
}

/// Merges boxcar defaults with one item; `None` when a required piece is still missing (fail closed). A null item throws.
fn merge_evaluation(defaults: &Value, item: &Value) -> Result<Option<Value>, String> {
    if item.is_null() {
        return Err("Cannot read properties of null (reading 'subject')".into());
    }
    let pick = |k: &str| match item.get(k) {
        Some(v) if !v.is_null() => Some(v.clone()),
        _ => defaults.get(k).cloned(),
    };
    let (subject, action, resource) = (pick("subject"), pick("action"), pick("resource"));
    let (Some(subject), Some(action), Some(resource)) = (subject, action, resource) else { return Ok(None) };
    if !is_authzen_subject(&subject) || !is_authzen_action(&action) || !is_authzen_resource(&resource) {
        return Ok(None);
    }
    let mut out = Map::new();
    out.insert("subject".into(), subject);
    out.insert("action".into(), action);
    out.insert("resource".into(), resource);
    match item.get("context") {
        Some(c) if !c.is_null() => {
            out.insert("context".into(), c.clone());
        }
        _ => {
            if let Some(c) = defaults.get("context") {
                out.insert("context".into(), c.clone());
            }
        }
    }
    Ok(Some(Value::Object(out)))
}

// ---- the PDP ----------------------------------------------------------------------------------------------------------------

pub struct AuthzenPdp {
    cfg: PdpConfig,
}

pub fn authzen_pdp(cfg: PdpConfig) -> AuthzenPdp {
    AuthzenPdp { cfg }
}

fn caught<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(p) => Err(panic_message(p.as_ref())),
    }
}

impl AuthzenPdp {
    fn now(&self) -> i64 {
        match &self.cfg.now {
            Some(f) => f(),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0),
        }
    }

    /// AuthZEN Access Evaluation: one `{subject, action, resource, context?}` to one decision. Never fails: any error is a deny.
    pub fn evaluate(&self, req: &Value) -> Value {
        let now = self.now();
        match caught(|| self.eval_inner(req, now)) {
            Ok(v) => v,
            Err(e) => deny(&format!("evaluation error (fail closed): {}", err_text(&e)), None, Some(500)),
        }
    }

    fn eval_inner(&self, req: &Value, now: i64) -> Result<Value, String> {
        let c = &self.cfg;
        let ctx = match (c.resolve)(req)? {
            None => return Ok(deny("no PCA authority resolved for this request", None, None)),
            Some(x) => x,
        };
        let mapped = match &ctx.to_action {
            Some(f) => f(req)?,
            None => default_to_action(req)?,
        };
        let p = match pcactn_from_context(req.get("context")) {
            Carried::Malformed => return Ok(deny("context carries a malformed PCActn", None, None)),
            Carried::Absent => {
                if c.require_proof {
                    return Ok(deny("a signed PCActn is required (requireProof)", None, None));
                }
                let admissible = match &c.admits_concrete {
                    Some(f) => f(&ctx.policy, &mapped)?,
                    None => crate::analyzer::admits_concrete(&ctx.policy, &mapped)?,
                };
                return Ok(if admissible {
                    permit("statically admissible under the declared authority")
                } else {
                    deny("action is not admissible under the declared authority", None, None)
                });
            }
            Carried::Pcactn(p) => p,
        };
        if c.require_authorizer && c.authorizer.is_none() {
            return Ok(deny("no replay/revocation authorizer is configured (requireAuthorizer)", None, None));
        }

        // the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
        let act = match p.get("action") {
            None => return Err("Cannot read properties of undefined (reading 'verb')".into()),
            Some(a) => a,
        };
        let act_prop = |k: &str| prop(act, k);
        let (verb, resource) = (act_prop("verb")?, act_prop("resource")?);
        if !strict_eq(verb, mapped.get("verb")) || !strict_eq(resource, mapped.get("resource")) {
            return Ok(deny(
                &format!(
                    "the PCActn authorizes {} on {}, not the requested {} on {}",
                    tpl(verb),
                    tpl(resource),
                    tpl(mapped.get("verb")),
                    tpl(mapped.get("resource"))
                ),
                None,
                None,
            ));
        }
        let req_params = params_of(&mapped);
        let digest = crate::params_digest(Some(&req_params));
        if !matches!(act_prop("params_digest")?, Some(Value::String(d)) if *d == digest) {
            return Ok(deny("the request attributes do not match the PCActn's signed params_digest", None, None));
        }

        let audience = match &c.audience {
            Audience::Exact(a) => a.clone(),
            Audience::AcceptAny => p.get("aud").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("").to_string(),
            Audience::Absent => String::new(),
        };
        if ctx.enforce.attestation {
            return Err("authzen: enforce.attestation is not supported by this verifier (fail closed)".into());
        }
        let opts = VerifyOptions {
            authorized_plan_roots: c.authorized_plan_roots.as_deref(),
            insecure_skip_plan_root_check: c.insecure_skip_plan_root_check,
            freshness_gate: ctx.enforce.freshness,
            ..VerifyOptions::default()
        };
        let verdict = crate::verify_pcactn_core_with(&p, &ctx.grant, now, &audience, &opts);
        let mut checks = Map::new();
        for (k, ok) in &verdict.checks {
            checks.insert(if k == "chain" { "cap_chain".to_string() } else { k.clone() }, json!(if *ok { "pass" } else { "fail" }));
        }
        let wire_failed = verdict.checks.get("wire") == Some(&false);
        if !wire_failed && c.authorized_plan_roots.is_none() && c.insecure_skip_plan_root_check {
            checks.insert("plan_root_authorized".into(), json!("not-enforced"));
        }
        let mut allow = verdict.allow;
        let mut reason = verdict.reason.clone();
        if let (Some(g), false) = (&ctx.enforce.taint, wire_failed) {
            let why = match caught(|| taint_gate_check(p.get("provenance").unwrap_or(&NULL), g)) {
                Ok(()) => None,
                Err(e) => Some(e),
            };
            checks.insert("taint_gate".into(), json!(if why.is_none() { "pass" } else { "fail" }));
            if let Some(w) = why {
                if allow {
                    reason = format!("taint_gate: {w}");
                }
                allow = false;
            }
        }
        if !allow {
            let reason = if reason.is_empty() { "PCActn verification failed".to_string() } else { reason };
            return Ok(json!({ "decision": false, "context": {
                "reason_admin": { "denied": true, "stage": "verify", "checks": Value::Object(checks), "reason": reason },
                "reason_user": { "message": "the proof-carrying action did not verify" } } }));
        }

        let budget = ctx.budget.clone().filter(|b| !b.is_null()).unwrap_or_else(|| fresh_budget(&ctx.grant, now));
        let mut dctx = Map::new();
        dctx.insert("grant".into(), ctx.grant.clone());
        if let Some(chain) = ctx.chain.clone().filter(|c| !c.is_null()).or_else(|| p.get("cap_chain").cloned()) {
            dctx.insert("chain".into(), chain);
        }
        if let Some(plan) = ctx.plan.clone().filter(|v| !v.is_null()) {
            dctx.insert("plan".into(), plan);
        }
        dctx.insert("params".into(), req_params.clone());
        dctx.insert("risk".into(), ctx.risk.clone().filter(|v| !v.is_null()).unwrap_or_else(|| json!({})));
        dctx.insert("budget".into(), budget);
        dctx.insert("now".into(), json!(now));
        for k in ["subject", "env"] {
            if let Some(v) = mapped.get(k).filter(|v| !v.is_null()) {
                dctx.insert(k.into(), v.clone());
            }
        }
        let (Some(derive), Some(decide)) = (&c.derive_decide_input, &c.decide) else {
            let name = if c.derive_decide_input.is_none() { "derive_decide_input" } else { "decide" };
            return Err(format!("authzen: config.{name} is not provided (fail closed)"));
        };
        let decision = decide(&derive(&p, &Value::Object(dctx))?)?;
        let dv = |k: &str| decision.get(k).cloned().unwrap_or(Value::Null);

        if !truthy(decision.get("releaseGuardianShare")) {
            let mut admin = Map::new();
            admin.insert("denied".into(), json!(true));
            admin.insert("stage".into(), json!("policy"));
            if let Some(r) = decision.get("reasons") {
                admin.insert("reasons".into(), r.clone());
            }
            admin.insert("risk".into(), dv("r"));
            return Ok(json!({ "decision": false, "context": {
                "reason_admin": Value::Object(admin),
                "reason_user": { "message": "the policy does not permit this action" } } }));
        }

        if truthy(decision.get("admit")) {
            if let Some(authorizer) = &c.authorizer {
                let mut ain = Map::new();
                ain.insert("operation".into(), json!({ "verb": mapped["verb"], "resource": mapped["resource"], "params": req_params }));
                ain.insert("pcactn".into(), p.clone());
                if let Some(pv) = req.get("context").and_then(|c| c.get(PCA_PROVENANCE_KEY)) {
                    ain.insert("provenance".into(), pv.clone());
                }
                let az = authorizer(&Value::Object(ain))?;
                if !truthy(prop(&az, "allow")?) {
                    let mut admin = Map::new();
                    admin.insert("denied".into(), json!(true));
                    admin.insert("stage".into(), json!("authorize"));
                    if let Some(r) = az.get("reason") {
                        admin.insert("reason".into(), r.clone());
                    }
                    return Ok(json!({ "decision": false, "context": {
                        "reason_admin": Value::Object(admin),
                        "reason_user": { "message": "the proof-carrying action was not authorized" } } }));
                }
            }
            return Ok(
                json!({ "decision": true, "context": { "reason_admin": { "stage": "policy", "risk": dv("r"), "threshold": dv("requiredThreshold") } } }),
            );
        }

        // admissible but needs a guardian / human co-sign: AARP approval-required (step-up)
        approval_required(&p, &decision, &ctx.grant, now)
    }

    /// AuthZEN Access Evaluations (boxcar). `Err` is the reference's throw on a null request or item.
    pub fn evaluations(&self, req: &Value) -> Result<Value, String> {
        let items = match prop(req, "evaluations")? {
            Some(Value::Array(a)) => a,
            _ => return Ok(json!({ "evaluations": [] })),
        };
        let semantic: Option<&Value> = match prop(req, "options")? {
            Some(o) => prop_opt(o, "evaluations_semantic").filter(|s| !s.is_null()),
            None => None,
        };
        let semantic = match semantic {
            None => "execute_all",
            Some(Value::String(s)) => s.as_str(),
            Some(_) => "",
        };
        let refuse = |reason: &str| Ok(json!({ "evaluations": items.iter().map(|_| deny(reason, None, Some(400))).collect::<Vec<_>>() }));
        if !matches!(semantic, "execute_all" | "deny_on_first_deny" | "permit_on_first_permit") {
            return refuse("unsupported evaluations_semantic");
        }
        let mx = self.cfg.max_evaluations.unwrap_or(DEFAULT_MAX_EVALUATIONS);
        if items.len() as f64 > mx {
            return refuse(&format!("too many evaluations (limit {})", crate::intent_v2::js_number_string(mx)));
        }
        let merged = items.iter().map(|it| merge_evaluation(req, it)).collect::<Result<Vec<_>, String>>()?;
        let mut out = vec![];
        for m in merged {
            let r = match m {
                None => deny("incomplete evaluation (missing subject/action/resource)", None, Some(400)),
                Some(m) => self.evaluate(&m),
            };
            let d = r["decision"].as_bool();
            out.push(r);
            if (semantic == "deny_on_first_deny" && d == Some(false)) || (semantic == "permit_on_first_permit" && d == Some(true)) {
                break;
            }
        }
        Ok(json!({ "evaluations": out }))
    }

    /// COAZ: authorize an MCP tool invocation (tool to required capability to decision).
    pub fn evaluate_tool(&self, req: &Value) -> Result<Value, String> {
        let tool = &req["tool"];
        let name = field_str(tool, "name")?;
        let capability = match &self.cfg.tool_capability {
            None => name.to_string(),
            Some(f) => match caught(|| f(name)) {
                Ok(c) => c,
                Err(e) => {
                    let r = deny(&format!("evaluation error (fail closed): {}", err_text(&e)), None, Some(500));
                    return Ok(json!({ "decision": false, "tool": name, "required_capability": "", "context": r["context"] }));
                }
            },
        };
        let mut action = Map::new();
        action.insert("name".into(), json!(capability));
        if let Some(a) = tool.get("arguments") {
            action.insert("properties".into(), a.clone());
        }
        let mut mapped = Map::new();
        mapped.insert("subject".into(), req["subject"].clone());
        mapped.insert("action".into(), Value::Object(action));
        mapped.insert("resource".into(), json!({ "type": "mcp_tool", "id": name }));
        if let Some(c) = req.get("context") {
            mapped.insert("context".into(), c.clone());
        }
        let resp = self.evaluate(&Value::Object(mapped));
        let mut out = Map::new();
        out.insert("decision".into(), resp["decision"].clone());
        out.insert("tool".into(), json!(name));
        out.insert("required_capability".into(), json!(capability));
        if let Some(c) = resp.get("context") {
            out.insert("context".into(), c.clone());
        }
        Ok(Value::Object(out))
    }
}

/// `x.k` for a non-null `x`.
fn prop_opt<'a>(x: &'a Value, k: &str) -> Option<&'a Value> {
    x.as_object().and_then(|m| m.get(k))
}

// ---- handler ----------------------------------------------------------------------------------------------------------------

fn status(s: i64, body: Value) -> Value {
    json!({ "status": s, "body": body })
}

fn err_body(m: &str) -> Value {
    json!({ "error": m })
}

fn route(pdp: &AuthzenPdp, req: &Value) -> Result<Value, String> {
    let body = req.get("body").unwrap_or(&NULL);
    match req.get("path").and_then(Value::as_str) {
        Some(EVALUATION_PATH) => {
            if !is_access_evaluation_request(body) {
                return Ok(status(400, err_body("invalid AuthZEN Access Evaluation request")));
            }
            Ok(status(200, pdp.evaluate(body)))
        }
        Some(EVALUATIONS_PATH) => {
            // an absent or empty `evaluations` array is a plain single Access Evaluation
            if is_rec(body) && body.get("evaluations").map_or(true, |e| e.as_array().is_some_and(|a| a.is_empty())) {
                if !is_access_evaluation_request(body) {
                    return Ok(status(400, err_body("invalid AuthZEN Access Evaluations request")));
                }
                return Ok(status(200, pdp.evaluate(body)));
            }
            if !is_access_evaluations_request(body) {
                return Ok(status(400, err_body("invalid AuthZEN Access Evaluations request")));
            }
            Ok(status(200, pdp.evaluations(body)?))
        }
        Some(COAZ_TOOL_PATH) => {
            if !is_coaz_tool_authorization_request(body) {
                return Ok(status(400, err_body("invalid COAZ MCP-tool authorization request")));
            }
            Ok(status(200, pdp.evaluate_tool(body)?))
        }
        _ => Ok(status(404, err_body(&format!("unknown AuthZEN path: {}", tpl(req.get("path")))))),
    }
}

/// `{path, body}` to `{status, body}`. A malformed body is a 400 (a PEP enforces it as a deny); any raised error is a 500 with no detail.
pub fn authzen_handler(pdp: &AuthzenPdp, req: &Value) -> Value {
    caught(|| route(pdp, req)).unwrap_or_else(|_| status(500, err_body("internal error")))
}

// ---- search -----------------------------------------------------------------------------------------------------------------

pub type SearchFn = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

/// The three searches; `None` means that search is unsupported. A function receives the request (the searched entity's `id` stripped for
/// subject / resource search) and returns `{results, page?, context?}`.
#[derive(Clone, Default)]
pub struct SearchProvider {
    pub search_subject: Option<SearchFn>,
    pub search_resource: Option<SearchFn>,
    pub search_action: Option<SearchFn>,
}

fn non_empty(x: Option<&Value>) -> bool {
    matches!(x, Some(Value::String(s)) if !s.is_empty())
}

fn props_ok(x: &Value) -> bool {
    x.get("properties").map_or(true, is_rec)
}

fn entity(x: &Value, need_id: bool) -> bool {
    is_rec(x) && non_empty(x.get("type")) && (!need_id || non_empty(x.get("id"))) && props_ok(x)
}

fn search_action_ok(x: &Value) -> bool {
    is_rec(x) && non_empty(x.get("name")) && props_ok(x)
}

fn safe_nonneg_int(v: &Value) -> bool {
    match v.as_f64() {
        Some(f) if v.is_number() => f.is_finite() && f == f.trunc() && !f.is_sign_negative() && f <= 9007199254740991.0,
        _ => false,
    }
}

fn page_ok(p: Option<&Value>) -> bool {
    let Some(p) = p else { return true };
    is_rec(p) && p.get("token").map_or(true, Value::is_string) && p.get("limit").map_or(true, safe_nonneg_int) && props_ok(p)
}

fn search_base(b: &Value) -> bool {
    b.get("context").map_or(true, is_rec) && page_ok(b.get("page"))
}

pub fn is_subject_search(b: &Value) -> bool {
    is_rec(b) && search_base(b) && entity(&b["subject"], false) && search_action_ok(&b["action"]) && entity(&b["resource"], true)
}

pub fn is_resource_search(b: &Value) -> bool {
    is_rec(b) && search_base(b) && entity(&b["subject"], true) && search_action_ok(&b["action"]) && entity(&b["resource"], false)
}

pub fn is_action_search(b: &Value) -> bool {
    is_rec(b) && search_base(b) && b.get("action").is_none() && entity(&b["subject"], true) && entity(&b["resource"], true)
}

/// The fragment for `/.well-known/authzen-configuration`; a missing endpoint means that search is unsupported.
pub fn search_metadata(base: &str, p: &SearchProvider) -> Value {
    let mut out = Map::new();
    for (has, key, path) in [
        (p.search_subject.is_some(), "search_subject_endpoint", SEARCH_SUBJECT_PATH),
        (p.search_resource.is_some(), "search_resource_endpoint", SEARCH_RESOURCE_PATH),
        (p.search_action.is_some(), "search_action_endpoint", SEARCH_ACTION_PATH),
    ] {
        if has {
            out.insert(key.into(), json!(format!("{base}{path}")));
        }
    }
    Value::Object(out)
}

fn strip_id(req: &Value, key: &str) -> Value {
    let mut e = req[key].clone();
    if let Some(m) = e.as_object_mut() {
        m.remove("id");
    }
    let mut out = req.clone();
    if let Some(m) = out.as_object_mut() {
        m.insert(key.to_string(), e);
    }
    out
}

fn shape(r: &Value, limit: Option<f64>, type_ok: &dyn Fn(&Value) -> Result<bool, String>) -> Result<Value, String> {
    let results_in = match prop(r, "results")? {
        Some(Value::Array(a)) => a,
        _ => return Err("results.filter is not a function".into()),
    };
    let mut seen = std::collections::HashSet::new();
    let mut results: Vec<Value> = vec![];
    for t in results_in {
        let k = crate::js_stringify(t);
        if !type_ok(t)? || !seen.insert(k) {
            continue;
        }
        results.push(t.clone());
    }
    let capped: Vec<Value> = match limit {
        Some(l) if l > 0.0 => results.iter().take(if l >= usize::MAX as f64 { usize::MAX } else { l as usize }).cloned().collect(),
        _ => results.clone(),
    };
    // a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
    if capped.len() < results.len() {
        return Err("provider returned more than the page limit".into());
    }
    let mut out = Map::new();
    if let Some(pg) = r.get("page").filter(|p| truthy(Some(*p))) {
        let mut page = Map::new();
        if let Some(nt) = prop_opt(pg, "next_token") {
            page.insert("next_token".into(), nt.clone());
        }
        page.insert("count".into(), json!(capped.len()));
        if let Some(t) = prop_opt(pg, "total") {
            page.insert("total".into(), t.clone());
        }
        if let Some(pr) = prop_opt(pg, "properties").filter(|p| truthy(Some(*p))) {
            page.insert("properties".into(), pr.clone());
        }
        out.insert("page".into(), Value::Object(page));
    }
    if let Some(c) = r.get("context").filter(|c| truthy(Some(*c))) {
        out.insert("context".into(), c.clone());
    }
    out.insert("results".into(), Value::Array(capped));
    Ok(Value::Object(out))
}

fn search_route(p: &SearchProvider, req: &Value) -> Result<Option<Value>, String> {
    let body = req.get("body").unwrap_or(&NULL);
    let limit = body.get("page").and_then(|pg| pg.get("limit")).and_then(Value::as_f64);
    let by_type = |tv: Value| move |e: &Value| -> Result<bool, String> { Ok(prop(e, "type")?.is_some_and(|t| *t == tv)) };
    let path = req.get("path").and_then(Value::as_str).unwrap_or("");
    let (f, what, valid, key): (&Option<SearchFn>, &str, fn(&Value) -> bool, Option<&str>) = match path {
        SEARCH_SUBJECT_PATH => (&p.search_subject, "subject", is_subject_search as fn(&Value) -> bool, Some("subject")),
        SEARCH_RESOURCE_PATH => (&p.search_resource, "resource", is_resource_search as fn(&Value) -> bool, Some("resource")),
        SEARCH_ACTION_PATH => (&p.search_action, "action", is_action_search as fn(&Value) -> bool, None),
        _ => return Ok(None),
    };
    let Some(f) = f else { return Ok(Some(status(404, err_body(&format!("{what} search is not supported"))))) };
    if !valid(body) {
        return Ok(Some(status(400, err_body(&format!("invalid AuthZEN {what} search request")))));
    }
    let out = match key {
        Some(k) => shape(&f(&strip_id(body, k))?, limit, &by_type(body[k]["type"].clone()))?,
        None => shape(&f(body)?, limit, &|_| Ok(true))?,
    };
    Ok(Some(status(200, out)))
}

/// `None` for a path that is not a search path, so it can be chained after [`authzen_handler`]'s result.
pub fn authzen_search_handler(p: &SearchProvider, req: &Value) -> Option<Value> {
    match caught(|| search_route(p, req)) {
        Ok(v) => v,
        Err(_) => Some(status(500, err_body("internal error"))),
    }
}
