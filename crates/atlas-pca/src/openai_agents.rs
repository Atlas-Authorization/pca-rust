//! OpenAI Agents SDK guard for Proof-Carrying Authority: the framework-agnostic logic of the reference's
//! `@atlasauth/pca-openai-agents`. A tool is a JSON-in / JSON-out [`AgentTool`] (a name, passthrough fields and an `execute(input,
//! run_context)` closure), a run context is a JSON value, so no vendor SDK is involved and any agent runtime adapts to it.
//!
//! * [`with_pca_tool`] / [`pca_tools`]: a tool call first REQUIRES a proof-carrying action (found in the run context per the
//!   PCA-Action convention), VERIFIES it (fail closed: [`PcaToolDenied`], which the runtime reports to the model as a tool error) and
//!   only then runs the original. Default mode `"full"`: [`FullPolicy`] runs the whole [`AuthorizeOptions`] pipeline (the call is
//!   bound to the operation it executes, the grant's limits, revocation and single use are enforced). `mode: "signature-only"` with
//!   `verify` checks only the signature, chain, audience and window, which does NOT prove the grant permits the call.
//! * [`pca_input_guardrail`] / [`pca_tool_guard`]: signature-only pre-filters that trip when the run or tool call carries no valid
//!   proof (`{tripwireTriggered, outputInfo}`).
//! * step-up: [`review_tool_call`], [`pending_step_ups`], [`pca_needs_approval`], [`with_approval`] map a risky tool to the
//!   runtime's `needsApproval` so the run interrupts for a guardian / human co-sign.
//!
//! shortcut: calls are synchronous (wrap a blocking tool in your runtime's executor); the grant-form `verify` needs a string
//! `audience` (the reference's "accept any audience" opt-out is only available through a custom [`VerifyFn`]); `review_tool_call`
//! takes the agent's `review` as a closure (the Rust agent has no built-in step-up review); a proof source that returns something
//! other than a string or an object is malformed (the reference passes any value through as a PCActn); `needsApproval` is a closure,
//! never a boolean.
use crate::intent_v2::js_value_string;
use crate::{decode_pca_header, strict_parse, verify_pcactn_core_with, AuthorizeOptions, Operation, VerifyOptions};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub type ResolveGrantFn = Arc<dyn Fn(&str) -> Result<Option<Value>, String> + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> i64 + Send + Sync>;

// ---- errors ------------------------------------------------------------------------------------------------------------------

/// A guarded tool refused to run. `kind`: `missing` | `malformed` | `verify` | `binding` | `policy` | `replay` | `revoked` |
/// `config`. `message` is the whole text, `PCA tool denied (<kind>) for <verb>: <why>`.
#[derive(Debug, Clone, PartialEq)]
pub struct PcaToolDenied {
    pub message: String,
    /// The verb the proof claimed (or the configured verb / `(tool)` when unknown).
    pub verb: String,
    pub kind: String,
    /// The per-check verdicts of the verifier, when the denial was a verification failure.
    pub checks: Option<Value>,
}

impl PcaToolDenied {
    fn new(why: &str, verb: &str, kind: &str, checks: Option<Value>) -> Self {
        PcaToolDenied { message: format!("PCA tool denied ({kind}) for {verb}: {why}"), verb: verb.into(), kind: kind.into(), checks }
    }
}

impl std::fmt::Display for PcaToolDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PcaToolDenied {}

/// Why a guarded call failed: the guard refused it, or the wrapped tool / verifier / recorder itself failed.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolError {
    Denied(PcaToolDenied),
    Tool(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::Denied(d) => std::fmt::Display::fmt(d, f),
            ToolError::Tool(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ToolError {}

impl From<String> for ToolError {
    fn from(m: String) -> Self {
        ToolError::Tool(m)
    }
}

// ---- tools -------------------------------------------------------------------------------------------------------------------

/// `execute(input, run_context)`.
pub type ExecuteFn = Arc<dyn Fn(&Value, Option<&Value>) -> Result<Value, ToolError> + Send + Sync>;
/// The runtime's `needsApproval(run_context, input, call_id)`.
pub type NeedsApprovalFn = Arc<dyn Fn(&Value, &Value, Option<&str>) -> Result<bool, String> + Send + Sync>;

/// A tool as the guard sees it: every field other than `execute` is preserved by the wrappers.
#[derive(Clone, Default)]
pub struct AgentTool {
    pub name: Option<String>,
    /// The tool's other fields (description, parameters, ...), kept as they are.
    pub fields: Map<String, Value>,
    pub execute: Option<ExecuteFn>,
    pub needs_approval: Option<NeedsApprovalFn>,
}

// ---- proof sources -----------------------------------------------------------------------------------------------------------

fn is_record(v: &Value) -> bool {
    matches!(v, Value::Object(_) | Value::Array(_))
}

/// A member under JavaScript `??` semantics: absent and null both read as `None`.
fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    match o {
        Value::Object(m) => m.get(k).filter(|v| !v.is_null()),
        _ => None,
    }
}

fn proof_from_bag(bag: &Value) -> Option<String> {
    if !is_record(bag) {
        return None;
    }
    match get(bag, "pca").or_else(|| get(bag, "pcaProof")) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The encoded PCActn from `run_context.context.{pca | pcaProof}`, then from `run_context.{pca | pcaProof}`.
pub fn proof_from_run_context(_input: &Value, run_context: &Value) -> Option<String> {
    get(run_context, "context").and_then(proof_from_bag).or_else(|| proof_from_bag(run_context))
}

/// The call's provenance bundle: `pcaProvenance` / `pca_provenance` / `PCA-Provenance` on `run_context.context`, then on the run
/// context itself; the first one that is neither absent nor null.
pub fn provenance_from_run_context(run_context: &Value) -> Option<Value> {
    for bag in [get(run_context, "context").unwrap_or(&Value::Null), run_context] {
        if !is_record(bag) {
            continue;
        }
        if let Some(v) = get(bag, "pcaProvenance").or_else(|| get(bag, "pca_provenance")).or_else(|| get(bag, "PCA-Provenance")) {
            return Some(v.clone());
        }
    }
    None
}

/// The proof source of the guardrails: the run context passed as `args.context`.
pub fn guardrail_proof_from_context(args: &Value) -> Option<String> {
    let outer = get(args, "context")?;
    get(outer, "context").and_then(proof_from_bag).or_else(|| proof_from_bag(outer))
}

/// `(input, run_context) -> proof` for a tool call.
pub type ProofSourceFn = Arc<dyn Fn(&Value, &Value) -> Option<Value> + Send + Sync>;
/// `(args) -> proof` for a guardrail.
pub type GuardrailSourceFn = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;
/// `(input, run_context) -> provenance bundle` for a tool call.
pub type ProvenanceSourceFn = Arc<dyn Fn(&Value, &Value) -> Option<Value> + Send + Sync>;

/// A proof source reading a `PCA-Action` header value from a headers-like object on the tool input (`field` default `headers`,
/// `header` default `PCA-Action`).
pub fn proof_from_input_headers(field: Option<&str>, header: Option<&str>) -> ProofSourceFn {
    let (field, header) = (field.unwrap_or("headers").to_string(), header.unwrap_or("PCA-Action").to_string());
    Arc::new(move |input: &Value, _rc: &Value| -> Option<Value> {
        let bag = input.as_object()?.get(&field)?;
        match bag.as_object().and_then(|m| m.get(&header)) {
            Some(Value::String(s)) => Some(Value::String(s.clone())),
            _ => None,
        }
    })
}

// ---- verification ------------------------------------------------------------------------------------------------------------

/// The result of a verification: `allow`, the per-check verdicts and, on a denial, why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerifyResult {
    pub allow: bool,
    pub checks: Option<Value>,
    pub reason: Option<String>,
}

/// A fully custom verifier: hand it the decoded PCActn.
pub type VerifyFn = Arc<dyn Fn(&Value) -> Result<VerifyResult, String> + Send + Sync>;

/// Core-verify config: the grant the proof must chain to.
#[derive(Clone)]
pub struct VerifyGrant {
    pub grant: Value,
    /// Verifier clock (epoch ms); default the system clock.
    pub now: Option<ClockFn>,
    /// The Merkle plan roots the principal authorized; required unless `insecure_skip_plan_root_check` is set.
    pub authorized_plan_roots: Option<Vec<String>>,
    pub insecure_skip_plan_root_check: bool,
}

#[derive(Clone)]
pub enum Verify {
    Func(VerifyFn),
    Grant(VerifyGrant),
}

/// The verifier's audience: unset (a PCActn that carries `aud` then fails closed), `Any` (the reference's `null`: accept any
/// audience, only through a custom [`VerifyFn`]) or a string that must equal the PCActn's signed `aud`.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Audience {
    #[default]
    Unset,
    Any,
    Is(String),
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `decodePCActn`: strict JSON, an object, within the artifact size cap.
fn decode_pcactn(text: &str) -> Result<Value, String> {
    if text.len() > crate::MAX_ARTIFACT_BYTES {
        return Err(crate::ARTIFACT_SIZE_REASON.to_string());
    }
    let v = strict_parse(text)?;
    if v.is_object() {
        Ok(v)
    } else {
        Err("decodePCActn: not an object".into())
    }
}

/// A proof as it arrives: the PCActn object, its encoded JSON, or a base64url `PCA-Action` value.
fn to_pcactn(raw: &Value) -> Result<Value, String> {
    match raw {
        Value::Object(_) => Ok(raw.clone()),
        Value::String(s) => decode_pcactn(s).or_else(|_| {
            let text = decode_pca_header(s).map_err(|_| "PCA-Action header does not decode to UTF-8 text".to_string())?;
            decode_pcactn(&text)
        }),
        _ => Err("the proof is neither a PCActn object nor encoded text".into()),
    }
}

fn run_verify(verify: Option<&Verify>, pcactn: &Value, audience: &Audience) -> Result<VerifyResult, String> {
    match verify {
        Some(Verify::Func(f)) => f(pcactn),
        Some(Verify::Grant(g)) => {
            let aud = match audience {
                Audience::Is(a) => a,
                _ => return Ok(VerifyResult { allow: false, checks: Some(json!({})), reason: Some("a string audience is required (fail closed)".into()) }),
            };
            let now = g.now.as_ref().map_or_else(system_now, |f| f());
            let vo = VerifyOptions {
                authorized_plan_roots: g.authorized_plan_roots.as_deref(),
                insecure_skip_plan_root_check: g.insecure_skip_plan_root_check,
                ..Default::default()
            };
            let v = verify_pcactn_core_with(pcactn, &g.grant, now, aud, &vo);
            let checks: Map<String, Value> = v.checks.iter().map(|(k, ok)| (k.clone(), json!(if *ok { "pass" } else { "fail" }))).collect();
            Ok(VerifyResult { allow: v.allow, checks: Some(Value::Object(checks)), reason: (!v.allow).then(|| v.reason.clone()) })
        }
        None => Ok(VerifyResult { allow: false, checks: Some(json!({})), reason: Some("no verifier configured".into()) }),
    }
}

struct Verified {
    pcactn: Value,
    result: VerifyResult,
}

/// The decision of the full-policy pipeline for one call.
struct FullDecision {
    allow: bool,
    kind: String,
    reason: String,
    checks: Option<Value>,
}

impl FullDecision {
    fn deny(kind: &str, reason: &str, checks: Option<Value>) -> Self {
        FullDecision { allow: false, kind: kind.into(), reason: reason.into(), checks }
    }
}

type FullCheck = Arc<dyn Fn(&Value, &Value, &Value) -> FullDecision + Send + Sync>;

fn verb_of(pcactn: &Value) -> Option<&Value> {
    pcactn.get("action").and_then(|a| a.get("verb"))
}

fn show(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

/// Decode, bind to `verb`, then verify (or run the full policy). The verified PCActn, or the refusal.
fn assert_proof(
    raw: Option<Value>,
    verify: Option<&Verify>,
    audience: &Audience,
    verb: Option<&str>,
    label: &str,
    full: Option<&dyn Fn(&Value) -> FullDecision>,
) -> Result<Verified, ToolError> {
    let deny = |why: &str, v: &str, kind: &str, checks: Option<Value>| ToolError::Denied(PcaToolDenied::new(why, v, kind, checks));
    let raw = match raw {
        Some(r) if !r.is_null() => r,
        _ => return Err(deny("no proof-carrying action present on the call", label, "missing", None)),
    };
    let pcactn = to_pcactn(&raw).map_err(|e| deny(&format!("proof could not be decoded: {e}"), label, "malformed", None))?;
    let got = verb_of(&pcactn).filter(|v| !v.is_null());
    let who = got.map_or_else(|| label.to_string(), js_value_string);
    if let Some(want) = verb {
        if got.and_then(Value::as_str) != Some(want) {
            return Err(deny(&format!("proof is for '{}', not this tool's '{want}'", show(got)), &who, "binding", None));
        }
    }
    if let Some(full) = full {
        let d = full(&pcactn);
        if !d.allow {
            return Err(deny(&d.reason, &who, if d.kind == "authn" { "verify" } else { d.kind.as_str() }, d.checks));
        }
        return Ok(Verified { pcactn, result: VerifyResult { allow: true, checks: d.checks, reason: None } });
    }
    let result = run_verify(verify, &pcactn, audience)?;
    if !result.allow {
        return Err(deny(result.reason.as_deref().unwrap_or("verification failed"), &who, "verify", result.checks));
    }
    Ok(Verified { pcactn, result })
}

// ---- full-policy mode --------------------------------------------------------------------------------------------------------

/// `(input, run_context) -> the operation this call executes`.
pub type ToolOperationFn = Arc<dyn Fn(&Value, &Value) -> Operation + Send + Sync>;

/// Full-policy mode: the [`AuthorizeOptions`] (replay store, revocation check, ...), the grant source and the operation. A guard
/// built without one of them is refused at build time (a configuration error, fail closed).
#[derive(Clone, Default)]
pub struct FullPolicy {
    pub options: Option<AuthorizeOptions>,
    pub resolve_grant: Option<ResolveGrantFn>,
    /// The operation a call executes. Default: the guard's `verb` and `resource` with the tool input as params.
    pub operation: Option<ToolOperationFn>,
    pub now: Option<ClockFn>,
}

/// A provenance bundle from an object, a JSON text or a base64url header value; `None` when it is neither.
pub fn provenance_from(v: &Value) -> Option<Value> {
    match v {
        Value::Object(_) | Value::Array(_) => Some(v.clone()),
        Value::String(s) if !s.is_empty() => strict_parse(s).ok().or_else(|| decode_pca_header(s).ok().and_then(|t| strict_parse(&t).ok())),
        _ => None,
    }
}

fn authorize_call(
    auth: &AuthorizeOptions,
    resolve: &ResolveGrantFn,
    audience: &str,
    pcactn: &Value,
    op: &Operation,
    bundle: Option<&Value>,
    now: i64,
) -> FullDecision {
    let (a_verb, a_res) = (pcactn.get("action").and_then(|a| a.get("verb")), pcactn.get("action").and_then(|a| a.get("resource")));
    if a_verb.and_then(Value::as_str) != Some(op.verb.as_str()) || (!op.resource.is_empty() && a_res.and_then(Value::as_str) != Some(op.resource.as_str())) {
        let want = if op.resource.is_empty() { op.verb.clone() } else { format!("{} on {}", op.verb, op.resource) };
        return FullDecision::deny("binding", &format!("the proof is for {} on {}, but this call is {want}", show(a_verb), show(a_res)), None);
    }
    let header = bundle.and_then(|b| crate::arg_provenance::encode_provenance_header(b).ok());
    let resolve = |r: &str| (**resolve)(r);
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        auth.run_full(Some(pcactn), Some(op), audience, &resolve, Some(now), None, None, None, None, None, header.as_deref(), None, None)
    }));
    let r = match run {
        Ok(r) => r,
        Err(_) => return FullDecision::deny("policy", "authorization error (fail closed)", None),
    };
    let checks: Map<String, Value> = r.checks.iter().map(|(k, s)| (k.clone(), json!(s.as_str()))).collect();
    let checks = Some(Value::Object(checks));
    if r.allow {
        return FullDecision { allow: true, kind: String::new(), reason: String::new(), checks };
    }
    let failed = |name: &str| r.checks.get(name).is_some_and(|s| s.as_str() == "fail");
    let kind = if r.missing.as_ref().is_some_and(|m| !m.is_empty()) {
        "config"
    } else if r.status == 401 {
        "authn"
    } else if failed("revocation") {
        "revoked"
    } else if failed("replay") {
        "replay"
    } else {
        "policy"
    };
    FullDecision::deny(kind, r.reason.as_deref().unwrap_or("denied"), checks)
}

/// Check the full-policy configuration once (an error names what is missing) and return the per-call check; `None` in
/// signature-only mode.
fn full_policy(o: &WithPcaToolOptions) -> Result<Option<FullCheck>, String> {
    let mode = o.mode.as_deref().unwrap_or("full");
    if mode != "full" && mode != "signature-only" {
        return Err(format!("with_pca_tool: unknown mode '{mode}'"));
    }
    if mode == "signature-only" {
        if o.authorize.is_some() {
            return Err("with_pca_tool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'".into());
        }
        if o.verify.is_none() {
            return Err("with_pca_tool: mode 'signature-only' needs `verify`".into());
        }
        return Ok(None);
    }
    let auth = o
        .authorize
        .clone()
        .ok_or("with_pca_tool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only")?;
    if o.verify.is_some() {
        return Err("with_pca_tool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`".into());
    }
    let audience = match &o.audience {
        Audience::Is(a) => Some(a.clone()),
        _ => None,
    };
    let mut missing: Vec<&str> = Vec::new();
    if audience.is_none() {
        missing.push("audience");
    }
    if auth.resolve_grant.is_none() {
        missing.push("grant or resolveGrant");
    }
    if auth.options.is_none() {
        missing.push("state, isRevoked");
    }
    if auth.operation.is_none() && (o.verb.is_none() || o.resource.is_none()) {
        missing.push("operation (or the guard's verb and resource)");
    }
    let (Some(audience), Some(resolve), Some(options)) = (audience, auth.resolve_grant.clone(), auth.options.clone()) else {
        return Err(format!("with_pca_tool: full policy mode is missing {}", missing.join(", ")));
    };
    if !missing.is_empty() {
        return Err(format!("with_pca_tool: full policy mode is missing {}", missing.join(", ")));
    }
    let (verb, resource) = (o.verb.clone().unwrap_or_default(), o.resource.clone().unwrap_or_default());
    let (operation, now) = (auth.operation.clone(), auth.now.clone());
    let prov = o.provenance.clone();
    Ok(Some(Arc::new(move |pcactn: &Value, input: &Value, ctx: &Value| {
        let op = match &operation {
            Some(f) => f(input, ctx),
            None => Operation::new(verb.clone(), resource.clone(), if input.is_object() { input.clone() } else { json!({}) }),
        };
        let bundle = match &prov {
            Some(f) => f(input, ctx),
            None => provenance_from_run_context(ctx),
        };
        let bundle = bundle.as_ref().and_then(provenance_from);
        authorize_call(&options, &resolve, &audience, pcactn, &op, bundle.as_ref(), now.as_ref().map_or_else(system_now, |f| f()))
    })))
}

// ---- the execution guard -----------------------------------------------------------------------------------------------------

pub type OnDenyFn = Arc<dyn Fn(&PcaToolDenied, &Value) + Send + Sync>;
pub type OnVerifiedFn = Arc<dyn Fn(&VerifyResult, &Value, &Value) + Send + Sync>;
/// Records a tool result as UNTRUSTED tool output (`(tool, output)`); wrap a [`crate::arg_provenance::ProvenanceRecorder`] in a mutex.
pub type RecorderFn = Arc<dyn Fn(&str, &Value) -> Result<(), String> + Send + Sync>;

/// Options of [`with_pca_tool`] (and, as per-tool overrides, of [`pca_tools`]).
#[derive(Clone, Default)]
pub struct WithPcaToolOptions {
    /// How to find the proof. Default: [`proof_from_run_context`].
    pub require: Option<ProofSourceFn>,
    /// `"full"` (the default): every call runs `authorize`. `"signature-only"`: only the proof's signature, chain, audience and
    /// window are checked (`verify`); the grant's limits are NOT evaluated and nothing stops a replay.
    pub mode: Option<String>,
    pub verify: Option<Verify>,
    pub authorize: Option<FullPolicy>,
    /// See [`Audience`].
    pub audience: Audience,
    /// Defense in depth: assert the proof's `action.verb` equals this (bind the proof to THIS tool).
    pub verb: Option<String>,
    /// The resource of the default operation in full mode (with `verb`).
    pub resource: Option<String>,
    /// Where the provenance bundle of a call is. Default: [`provenance_from_run_context`].
    pub provenance: Option<ProvenanceSourceFn>,
    /// When set, every result the tool returns is recorded as UNTRUSTED tool output.
    pub recorder: Option<RecorderFn>,
    pub on_deny: Option<OnDenyFn>,
    pub on_verified: Option<OnVerifiedFn>,
}

/// A copy of `tool` whose every call first requires and verifies a proof, then runs the original; every other field is kept.
/// A configuration error (an unknown mode, a missing component) is an `Err` here, never a silent pass at call time.
pub fn with_pca_tool(tool: &AgentTool, options: WithPcaToolOptions) -> Result<AgentTool, String> {
    let source: ProofSourceFn = options.require.clone().unwrap_or_else(|| Arc::new(|i: &Value, rc: &Value| proof_from_run_context(i, rc).map(Value::String)));
    let label = options.verb.clone().or_else(|| tool.name.clone()).unwrap_or_else(|| "(tool)".to_string());
    let full = full_policy(&options)?;
    let orig = tool.execute.clone();
    let exec: ExecuteFn = Arc::new(move |input: &Value, run_context: Option<&Value>| {
        let empty = json!({});
        let ctx = run_context.unwrap_or(&empty);
        let raw = source(input, ctx);
        let full_call = |p: &Value| match &full {
            Some(f) => f(p, input, ctx),
            None => FullDecision::deny("config", "no full policy", None),
        };
        let full_dyn: Option<&dyn Fn(&Value) -> FullDecision> = full.as_ref().map(|_| &full_call as &dyn Fn(&Value) -> FullDecision);
        let verified = match assert_proof(raw, options.verify.as_ref(), &options.audience, options.verb.as_deref(), &label, full_dyn) {
            Ok(v) => v,
            Err(ToolError::Denied(d)) => {
                if let Some(f) = &options.on_deny {
                    f(&d, input);
                }
                return Err(ToolError::Denied(d));
            }
            Err(e) => return Err(e),
        };
        if let Some(f) = &options.on_verified {
            f(&verified.result, &verified.pcactn, input);
        }
        let run = orig.as_ref().ok_or_else(|| ToolError::Tool("with_pca_tool: the wrapped tool has no execute()".into()))?;
        let out = run(input, run_context)?;
        if let Some(rec) = &options.recorder {
            let v = verb_of(&verified.pcactn).filter(|v| !v.is_null()).map_or_else(|| label.clone(), js_value_string);
            rec(&v, &out).map_err(ToolError::Tool)?;
        }
        Ok(out)
    });
    Ok(AgentTool { name: tool.name.clone(), fields: tool.fields.clone(), execute: Some(exec), needs_approval: tool.needs_approval.clone() })
}

/// [`pca_tools`] options: the shared options, per-tool overrides and the guarded subset.
#[derive(Clone, Default)]
pub struct PcaToolsOptions {
    pub shared: WithPcaToolOptions,
    /// Override shared options for specific tools (commonly `{refund: {verb: "stripe.refund"}}`).
    pub per: HashMap<String, WithPcaToolOptions>,
    /// Guard only these tools; every other entry passes through unchanged (the same `Arc`). `None`: guard all.
    pub only: Option<Vec<String>>,
}

/// A per-tool `authorize` or `verify` replaces the shared mode (the two are exclusive); `mode` follows the override, else the
/// shared one; `audience` is the override's when it set one (even `Any`), every other option the override's when set.
fn merge_options(base: &WithPcaToolOptions, over: Option<&WithPcaToolOptions>) -> WithPcaToolOptions {
    let Some(over) = over else { return base.clone() };
    let mode = over.mode.clone().or_else(|| if over.authorize.is_some() { None } else { base.mode.clone() });
    let (verify, authorize) = if over.authorize.is_some() {
        (None, over.authorize.clone())
    } else if over.verify.is_some() {
        (over.verify.clone(), None)
    } else {
        (base.verify.clone(), base.authorize.clone())
    };
    WithPcaToolOptions {
        require: over.require.clone().or_else(|| base.require.clone()),
        mode,
        verify,
        authorize,
        audience: if over.audience != Audience::Unset { over.audience.clone() } else { base.audience.clone() },
        verb: over.verb.clone().or_else(|| base.verb.clone()),
        resource: over.resource.clone().or_else(|| base.resource.clone()),
        provenance: over.provenance.clone().or_else(|| base.provenance.clone()),
        recorder: over.recorder.clone().or_else(|| base.recorder.clone()),
        on_deny: over.on_deny.clone().or_else(|| base.on_deny.clone()),
        on_verified: over.on_verified.clone().or_else(|| base.on_verified.clone()),
    }
}

/// Guard a whole `(name, tool)` list in one call: every tool with the shared options (override per tool via `per`, or limit the set
/// via `only`; untouched tools pass through as the same `Arc`). The first configuration error fails the whole call.
pub fn pca_tools(tools: &[(String, Arc<AgentTool>)], options: &PcaToolsOptions) -> Result<Vec<(String, Arc<AgentTool>)>, String> {
    let mut out = Vec::with_capacity(tools.len());
    for (name, tool) in tools {
        if options.only.as_ref().is_some_and(|only| !only.contains(name)) {
            out.push((name.clone(), tool.clone()));
            continue;
        }
        let merged = merge_options(&options.shared, options.per.get(name));
        out.push((name.clone(), Arc::new(with_pca_tool(tool, merged)?)));
    }
    Ok(out)
}

// ---- guardrails --------------------------------------------------------------------------------------------------------------

/// Options of [`pca_input_guardrail`] / [`pca_tool_guard`].
#[derive(Clone, Default)]
pub struct GuardrailOptions {
    /// How to find the proof. Default: [`guardrail_proof_from_context`].
    pub require: Option<GuardrailSourceFn>,
    /// Required: the grant the proof must satisfy, or a custom verifier.
    pub verify: Option<Verify>,
    pub audience: Audience,
    /// Bind the proof to a specific verb.
    pub verb: Option<String>,
    /// The guardrail's name (shown in traces).
    pub name: Option<String>,
}

/// A signature-only proof gate: `execute(args)` returns `{tripwireTriggered, outputInfo}`.
#[derive(Clone)]
pub struct Guardrail {
    pub name: String,
    source: GuardrailSourceFn,
    verify: Verify,
    audience: Audience,
    verb: Option<String>,
}

impl Guardrail {
    /// Trips (rejects the run / call) on any refusal of the proof pipeline; an `Err` is the verifier itself failing.
    pub fn execute(&self, args: &Value) -> Result<Value, String> {
        let label = self.verb.clone().unwrap_or_else(|| "(run)".to_string());
        match assert_proof((self.source)(args), Some(&self.verify), &self.audience, self.verb.as_deref(), &label, None) {
            Ok(v) => {
                let info = verb_of(&v.pcactn).map_or_else(|| json!({}), |verb| json!({ "verb": verb }));
                Ok(json!({ "tripwireTriggered": false, "outputInfo": info }))
            }
            Err(ToolError::Denied(d)) => {
                let mut info = json!({ "kind": d.kind, "verb": d.verb, "reason": d.message });
                if let Some(c) = d.checks {
                    info["checks"] = c;
                }
                Ok(json!({ "tripwireTriggered": true, "outputInfo": info }))
            }
            Err(ToolError::Tool(m)) => Err(m),
        }
    }
}

fn guardrail(default_name: &str, o: GuardrailOptions) -> Result<Guardrail, String> {
    let verify = o.verify.ok_or("a PCA guardrail needs `verify` (the grant the proof must satisfy, or a custom verifier)")?;
    let source: GuardrailSourceFn = o.require.unwrap_or_else(|| Arc::new(|a: &Value| guardrail_proof_from_context(a).map(Value::String)));
    Ok(Guardrail { name: o.name.unwrap_or_else(|| default_name.to_string()), source, verify, audience: o.audience, verb: o.verb })
}

/// An input guardrail: runs once at the top of a run and trips when the run context carries no valid proof.
pub fn pca_input_guardrail(options: GuardrailOptions) -> Result<Guardrail, String> {
    guardrail("pca-input-guardrail", options)
}

/// The same proof gate scoped to a tool call; prefer [`with_pca_tool`] with `authorize` for the real check.
pub fn pca_tool_guard(options: GuardrailOptions) -> Result<Guardrail, String> {
    guardrail("pca-tool-guard", options)
}

// ---- step-up -----------------------------------------------------------------------------------------------------------------

/// Map a tool name (and its input) to the PCA action to review: `{verb, resource, params?}`, or `None` for an unguarded tool (auto).
pub type IntentFn = Arc<dyn Fn(&str, Option<&Value>) -> Option<Value> + Send + Sync>;
/// The agent's review of an intended action: `(agent, verb, resource, params, opts)` -> `{kind: "auto"}`, `{kind: "deny", reason}`
/// or `{kind: "step_up", request}`.
pub type ReviewFn = Arc<dyn Fn(&Value, &str, &str, &Value, &Value) -> Result<Value, String> + Send + Sync>;

#[derive(Clone)]
pub struct StepUpOptions {
    pub intent: IntentFn,
    pub review: Option<ReviewFn>,
    /// Standing "approve this class for N hours" grants that downgrade a matching step-up to auto.
    pub standing: Option<Value>,
    /// Plaintext goal to carry on any step-up request.
    pub goal: Option<String>,
    /// Review clock (epoch ms).
    pub now: Option<i64>,
    pub renderer: Option<Value>,
    pub insecure_unbound_approval: Option<bool>,
}

/// Review one intended tool call: `auto` (no human needed: also every tool with no intent), `deny`, or `step_up` with a request
/// (tier 2 guardian co-sign, tier 3 human). Returns `{tool, review}`.
pub fn review_tool_call(agent: &Value, tool: &str, input: Option<&Value>, opts: &StepUpOptions) -> Result<Value, String> {
    let Some(mapped) = (opts.intent)(tool, input) else {
        return Ok(json!({ "tool": tool, "review": { "kind": "auto" } }));
    };
    let review = opts.review.as_ref().ok_or("review_tool_call: pass `review`, the agent's review of an intended action")?;
    let field = |k: &str| mapped.get(k).and_then(Value::as_str).ok_or(format!("review_tool_call: the intent for '{tool}' has no {k}"));
    let params = mapped.get("params").filter(|p| !p.is_null()).or(input).cloned().unwrap_or(Value::Null);
    let mut o = Map::new();
    if let Some(n) = opts.now {
        o.insert("now".into(), json!(n));
    }
    if let Some(g) = &opts.goal {
        o.insert("goal".into(), json!(g));
    }
    if let Some(s) = &opts.standing {
        o.insert("standing".into(), s.clone());
    }
    if let Some(r) = &opts.renderer {
        o.insert("renderer".into(), r.clone());
    }
    if let Some(b) = opts.insecure_unbound_approval {
        o.insert("insecureUnboundApproval".into(), json!(b));
    }
    let r = review(agent, field("verb")?, field("resource")?, &params, &Value::Object(o))?;
    Ok(json!({ "tool": tool, "review": r }))
}

/// The step-up requests among `review_tool_call` results (auto / deny filtered out): `[{tool, request}]`.
pub fn pending_step_ups(reviews: &Value) -> Value {
    let list = reviews.as_array().map(Vec::as_slice).unwrap_or(&[]);
    Value::Array(
        list.iter().filter(|r| r["review"]["kind"] == json!("step_up")).map(|r| json!({ "tool": r["tool"], "request": r["review"]["request"] })).collect(),
    )
}

/// Options of [`pca_needs_approval`] / [`with_approval`].
#[derive(Clone)]
pub struct NeedsApprovalOptions {
    pub step: StepUpOptions,
    /// The tool name to review (default: the wrapped tool's name in [`with_approval`], else `(tool)`).
    pub tool_name: Option<String>,
    /// True when a step-up request was already co-signed: it is then let through.
    pub approved: Option<Arc<dyn Fn(&Value) -> bool + Send + Sync>>,
    /// Receives each step-up this call raised (`{tool, request}`): push it to the approval inbox.
    pub on_step_up: Option<Arc<dyn Fn(&Value) + Send + Sync>>,
    /// Whether a policy `deny` also routes to approval (so the approver rejects it rather than the tool silently running).
    /// Default true, fail safe.
    pub deny_needs_approval: Option<bool>,
}

/// The runtime's `needsApproval` from risk review: `auto` -> false; a step-up not yet co-signed -> `on_step_up` and true (the run
/// interrupts); an already approved step-up -> false; `deny` -> true unless `deny_needs_approval` is false. A tool with no intent
/// mapping is `auto`. A review of an unknown kind is treated as a step-up (fail closed).
pub fn pca_needs_approval(agent: Value, opts: NeedsApprovalOptions) -> NeedsApprovalFn {
    let name = opts.tool_name.clone().unwrap_or_else(|| "(tool)".to_string());
    Arc::new(move |_rc: &Value, input: &Value, _call_id: Option<&str>| -> Result<bool, String> {
        let r = review_tool_call(&agent, &name, Some(input), &opts.step)?;
        let review = &r["review"];
        match review["kind"].as_str() {
            Some("auto") => Ok(false),
            Some("deny") => Ok(opts.deny_needs_approval.unwrap_or(true)),
            _ => {
                if opts.approved.as_ref().is_some_and(|f| f(&review["request"])) {
                    return Ok(false);
                }
                if let Some(f) = &opts.on_step_up {
                    f(&json!({ "tool": name, "request": review["request"] }));
                }
                Ok(true)
            }
        }
    })
}

/// A copy of `tool` with `needs_approval` from PCA risk review (the tool's name seeds the intent lookup unless `tool_name` is
/// given). Every other field is preserved.
pub fn with_approval(tool: &AgentTool, agent: Value, mut opts: NeedsApprovalOptions) -> AgentTool {
    let name = opts.tool_name.clone().or_else(|| tool.name.clone()).unwrap_or_else(|| "(tool)".to_string());
    opts.tool_name = Some(name);
    AgentTool { needs_approval: Some(pca_needs_approval(agent, opts)), ..tool.clone() }
}
