//! `authorize_execution`: the full-policy check for one local execution (an agent framework tool call, a gateway request), for
//! verifiers that have the PCActn in hand rather than an HTTP request.
//!
//! The core verifier alone checks that a proof is genuine; it does not read the grant's limits, so a validly signed $400 payment under
//! a $100 grant passes it. This runs, in order:
//!
//! 1. configuration: the audience, a grant source, the replay / budget store and the revocation check are REQUIRED; a missing one denies
//!    every call (fail closed, never a downgrade to signature-only);
//! 2. operation binding: the PCActn's signed verb (and resource, when the caller names one) must be the operation about to execute;
//! 3. the full server verifier, through [`AuthorizeOptions`] (the one pipeline): the grant from the caller's store, the operation's
//!    params against the signed params digest, the grant's predicates, limits and caveats, revocation, the replay counter and the trust
//!    budget, with risk priced from server-side inputs.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::intent_v2::js_value_string;
use crate::{
    read_envelope, AssuranceHooks, AssuranceRequirement, AuthorizeOptions, AuthorizeResult, CheckStatus, FreshnessGate, K1Input, Operation, StateStore,
    AttestationHookFn, ThresholdHookFn, ZkHookFn,
};

/// The operation that is about to execute: what the PCActn must have been signed for.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionOperation {
    /// The PCA verb of this operation. Must equal the signed `action.verb`.
    pub verb: String,
    /// The PCA resource. When given it must equal the signed `action.resource`.
    pub resource: Option<String>,
    /// The parameters the operation will execute with. They must hash to the signed `action.params_digest` (a JSON object).
    pub params: Value,
    /// The provenance bundle the agent presented with this call; absent = unlabelled.
    pub provenance: Option<Value>,
}

impl ExecutionOperation {
    pub fn new(verb: impl Into<String>, params: Value) -> Self {
        ExecutionOperation { verb: verb.into(), resource: None, params, provenance: None }
    }
}

/// `(grant_ref, pcactn) -> Ok(Some(grant))`; `Ok(None)` = unknown grant; an `Err` denies (fail closed).
pub type ExecutionGrantResolver = dyn Fn(&str, &Value) -> Result<Option<Value>, String> + Send + Sync;
/// `(grant, pcactn) -> Ok(revoked)`: only `Ok(false)` passes.
pub type ExecutionRevocationCheck = dyn Fn(&Value, &Value) -> Result<bool, String> + Send + Sync;
/// `(grant_ref, plan_root) -> authorized`.
pub type ExecutionPlanGate = dyn Fn(&str, &str) -> bool + Send + Sync;
/// `(grant, params, pcactn) -> server-side risk inputs` (camelCase names, e.g. `blastRadius`); `None` prices every input at the worst case.
pub type ExecutionRisk = dyn Fn(&Value, &Value, &Value) -> Option<Map<String, Value>> + Send + Sync;

/// The configuration of [`authorize_execution`]. `audience`, a grant source, `state` and `is_revoked` are required.
#[derive(Clone, Default)]
pub struct AuthorizeExecutionOptions {
    /// REQUIRED: this verifier's audience id.
    pub audience: String,
    /// The grant the PCActn must chain to. Give this or `resolve_grant`.
    pub grant: Option<Value>,
    /// Look the grant up in YOUR store by the PCActn's signed `grant_ref`. Never return a grant taken from the call.
    pub resolve_grant: Option<Arc<ExecutionGrantResolver>>,
    /// REQUIRED: replay counters and trust budgets per agent. Share one store across processes.
    pub state: Option<Arc<dyn StateStore>>,
    /// REQUIRED: is this grant revoked? A verifier that cannot answer this must not authorize.
    pub is_revoked: Option<Arc<ExecutionRevocationCheck>>,
    /// Has the principal authorized this plan root for this grant? Default: a one-step plan is authorized when it is exactly the step signed.
    pub is_plan_authorized: Option<Arc<ExecutionPlanGate>>,
    /// Server-side risk inputs. Default [`amount_risk`].
    pub risk: Option<Arc<ExecutionRisk>>,
    /// The threshold verifier hook (see [`ThresholdHookFn`]); revocation always comes from `is_revoked`.
    pub threshold: Option<Arc<ThresholdHookFn>>,
    /// The attestation verifier hook (see [`AttestationHookFn`]). Without one a grant that pins the agent fails `attestation`.
    pub attestation: Option<Arc<AttestationHookFn>>,
    /// The zero-knowledge compliance verifier hook (see [`ZkHookFn`]). Without one a PCActn carrying a `zk_compliance` proof fails `zk_compliance`.
    pub zk: Option<Arc<ZkHookFn>>,
    /// The labels of the verifier's own hooks (they decide what a passing check is reported to rest on).
    pub assurance_hooks: Option<AssuranceHooks>,
    /// Further checks that must report `pass`, on top of the full-mode defaults.
    pub require: Vec<String>,
    /// Caveat language v2 input. Absent: every K1 caveat in the chain refuses (fail closed).
    pub k1: Option<K1Input>,
    /// The consume-once store `max_uses` caveats spend from.
    pub uses_store: Option<Arc<dyn StateStore>>,
    /// Accepted signature suites. Default `["ed25519"]`.
    pub allowed_suites: Option<Vec<String>>,
    /// Server-side PQ pins `issuer -> pq_pk`, needed only if you accept a post-quantum suite.
    pub pq_pins: Option<Map<String, Value>>,
    /// Verifier clock (epoch ms). Default the system clock.
    pub now: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    /// High-assurance policy: weaker, missing, failed, unlabelled, awaiting-audit or unsupported evidence denies.
    pub require_assurance: Option<AssuranceRequirement>,
    /// The freshness-anchor gate; set = fails closed.
    pub freshness_gate: Option<FreshnessGate>,
    /// More than one process shares `state`: a process-scoped store is refused and every call is denied with the reason.
    pub multi_instance: Option<bool>,
    /// Re-verifications after an atomic claim's budget conflict before the call is denied (`claimRetries`; default 3).
    pub claim_retries: Option<usize>,
    /// The pinned mediator keys of the provenance gate (`{mediator, kid, pk, pq_pk?}`).
    pub provenance_mediators: Vec<Value>,
    /// The facts of the action about to run (the provenance gate; without it every action is unknown, so sensitive).
    pub provenance_actions: Option<Arc<dyn Fn(&Operation) -> Option<Value> + Send + Sync>>,
}

/// Why a full-policy check refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionDenialKind {
    Config,
    Binding,
    Authn,
    Policy,
    Replay,
    Revoked,
}

impl ExecutionDenialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Binding => "binding",
            Self::Authn => "authn",
            Self::Policy => "policy",
            Self::Replay => "replay",
            Self::Revoked => "revoked",
        }
    }
}

/// The outcome of [`authorize_execution`].
#[derive(Debug, Clone)]
pub enum ExecutionDecision {
    Allow {
        pcactn: Value,
        grant: Value,
        /// The full result of the pipeline (verdict checks, assurance report, obligations).
        result: AuthorizeResult,
    },
    Deny {
        kind: ExecutionDenialKind,
        status: u16,
        /// The decisive reason, in the verifier's words.
        reason: String,
        /// Every check of the verifier, when it ran.
        checks: Option<std::collections::BTreeMap<String, CheckStatus>>,
        result: Option<AuthorizeResult>,
    },
}

impl ExecutionDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, ExecutionDecision::Allow { .. })
    }
}

/// The required components that `opts` lacks (empty when the configuration is complete).
pub fn missing_execution_components(opts: &AuthorizeExecutionOptions) -> Vec<String> {
    let mut missing = Vec::new();
    if opts.audience.is_empty() {
        missing.push("audience".to_string());
    }
    if opts.grant.is_none() && opts.resolve_grant.is_none() {
        missing.push("grant or resolveGrant".to_string());
    }
    if opts.state.is_none() {
        missing.push("state".to_string());
    }
    if opts.is_revoked.is_none() {
        missing.push("isRevoked".to_string());
    }
    missing
}

/// The server's risk inputs for a money-moving operation: `blastRadius = amount / kappa` from the verified `params[amount_field]`
/// (default `amount`) and the grant's own risk policy. `None` when there is no numeric amount (the verifier then prices the missing
/// inputs at the worst case).
pub fn amount_risk(grant: &Value, params: &Value, amount_field: Option<&str>) -> Option<Map<String, Value>> {
    let amount = params.get(amount_field.unwrap_or("amount"))?.as_f64()?;
    let kappa = read_envelope(grant)?.get("risk_policy")?.get("kappa")?.as_f64()?;
    if !amount.is_finite() || !kappa.is_finite() || !(kappa > 0.0) {
        return None;
    }
    let mut m = Map::new();
    m.insert("blastRadius".into(), json!((amount / kappa).clamp(0.0, 1.0)));
    Some(m)
}

const RISK_NOISE: &str = "risk input(s) missing";

/// The verifier reports its core checks in this order; checks added after them (params_digest, policy, replay, ...) follow in the order
/// their reasons were reported. The reference walks `verdict.checks` in that insertion order, so the first failing one in it names the denial.
const CORE_CHECK_ORDER: [&str; 16] = [
    "wire",
    "version",
    "audience",
    "validity",
    "cap_chain",
    "grant_ref_bound",
    "plan_inclusion",
    "plan_root_authorized",
    "leaf_signature",
    "counter_format",
    "intent",
    "taint_gate",
    "freshness",
    "attestation",
    "threshold",
    "revocation",
];

/// The reason of the first failing check (the verifier also lists context such as worst-case risk inputs). The verb and resource are
/// bound before the verifier runs, so a failing `operation` check here is a params mismatch that `params_digest` already reports:
/// it is ranked last so the reason stays the established `params_digest` one.
fn decisive_reason(r: &AuthorizeResult) -> String {
    let reported = |n: &str| r.reasons.iter().position(|x| x.split_once(':').is_some_and(|(h, _)| h == n)).unwrap_or(usize::MAX);
    let mut failing: Vec<&String> = r.checks.iter().filter(|(_, s)| **s == CheckStatus::Fail).map(|(k, _)| k).collect();
    // core checks in their fixed order, then the rest by when they were reported; `operation` last (it duplicates `params_digest`)
    failing.sort_by_key(|n| (n.as_str() == "operation", CORE_CHECK_ORDER.iter().position(|c| c == n).unwrap_or(CORE_CHECK_ORDER.len()), reported(n)));
    for name in failing {
        if let Some(hit) = r.reasons.iter().find(|x| x.strip_prefix(name.as_str()).is_some_and(|t| t.starts_with(':')) && !x.contains(RISK_NOISE)) {
            return hit.clone();
        }
    }
    r.reasons.iter().find(|x| !x.contains(RISK_NOISE)).or_else(|| r.reasons.first()).cloned().unwrap_or_else(|| "denied".to_string())
}

fn deny(kind: ExecutionDenialKind, status: u16, reason: String) -> ExecutionDecision {
    ExecutionDecision::Deny { kind, status, reason, checks: None, result: None }
}

/// Authorize one execution completely: configuration, binding to the operation, and the full verifier. See the module doc.
pub fn authorize_execution(pcactn: &Value, operation: &ExecutionOperation, opts: &AuthorizeExecutionOptions) -> ExecutionDecision {
    let missing = missing_execution_components(opts);
    if !missing.is_empty() {
        return deny(ExecutionDenialKind::Config, 403, format!("full policy mode is missing {} (fail closed)", missing.join(", ")));
    }
    catch_unwind(AssertUnwindSafe(|| run(pcactn, operation, opts)))
        .unwrap_or_else(|_| deny(ExecutionDenialKind::Policy, 403, "authorization error (fail closed): unknown".to_string()))
}

fn run(p: &Value, operation: &ExecutionOperation, opts: &AuthorizeExecutionOptions) -> ExecutionDecision {
    let action = p.get("action");
    let signed_verb = action.and_then(|a| a.get("verb"));
    let signed_resource = action.and_then(|a| a.get("resource"));
    let verb_ok = signed_verb.and_then(Value::as_str) == Some(operation.verb.as_str());
    let resource_ok = operation.resource.as_deref().map_or(true, |r| signed_resource.and_then(Value::as_str) == Some(r));
    // binding: checked before any state is read or written, so a proof presented for another operation is not spent.
    if !verb_ok || !resource_ok {
        let want = match &operation.resource {
            Some(r) => format!("{} on {r}", operation.verb),
            None => operation.verb.clone(),
        };
        let show = |v: Option<&Value>| v.map_or("undefined".to_string(), js_value_string);
        return deny(
            ExecutionDenialKind::Binding,
            403,
            format!("the proof is for {} on {}, but this call is {want}", show(signed_verb), show(signed_resource)),
        );
    }
    let grant_ref = p.get("grant_ref").and_then(Value::as_str).unwrap_or("");
    let grant = match (&opts.grant, &opts.resolve_grant) {
        (Some(g), _) => g.clone(),
        (None, Some(f)) => match f(grant_ref, p) {
            Ok(Some(g)) if !g.is_null() => g,
            Ok(_) => return deny(ExecutionDenialKind::Authn, 401, "unknown grant_ref".to_string()),
            Err(e) => return deny(ExecutionDenialKind::Policy, 403, format!("authorization error (fail closed): {e}")),
        },
        (None, None) => return deny(ExecutionDenialKind::Config, 403, "full policy mode is missing grant or resolveGrant (fail closed)".to_string()),
    };
    let now = opts
        .now
        .as_ref()
        .map_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0), |f| f());
    let params = operation.params.clone();
    let state = opts.state.clone().expect("checked by missing_execution_components");
    let revoked = opts.is_revoked.clone().expect("checked by missing_execution_components");

    // the one pipeline: `AuthorizeOptions` (every component required, the proof bound to the operation, the atomic claim path when
    // the store has one). This wrapper only maps option names, adds the principal's plan gate and the amount-priced risk.
    let mut ao = AuthorizeOptions::new(state, move |pc: &Value, g: &Value| revoked(g, pc));
    ao.allowed_suites = Some(opts.allowed_suites.clone().unwrap_or_else(|| vec!["ed25519".to_string()]));
    ao = ao.with_require(opts.require.iter().cloned());
    let plan_gate = opts.is_plan_authorized.clone();
    let ctx_params = params.clone();
    ao = ao.with_context(move |pc: &Value| {
        let node = json!({
            "id": pc.get("plan").and_then(|pl| pl.get("node_id")).cloned().unwrap_or(Value::Null),
            "verb": pc.get("action").and_then(|a| a.get("verb")).cloned().unwrap_or(Value::Null),
            "resource": pc.get("action").and_then(|a| a.get("resource")).cloned().unwrap_or(Value::Null),
            "params_digest": pc.get("action").and_then(|a| a.get("params_digest")).cloned().unwrap_or(Value::Null),
            "reversibility_class": pc.get("action").and_then(|a| a.get("reversibility_class")).cloned().unwrap_or(Value::Null),
        });
        // the plan root's consistency with the signed root is checked by the verifier itself (a mismatch is reported first)
        let approved = match &plan_gate {
            Some(f) => {
                f(pc.get("grant_ref").and_then(Value::as_str).unwrap_or(""), pc.get("plan").and_then(|pl| pl.get("root")).and_then(Value::as_str).unwrap_or(""))
            }
            None => true,
        };
        Ok(Some(json!({"params": ctx_params, "plan": [node], "plan_authorized": approved})))
    });
    let risk = opts.risk.clone();
    ao = ao.with_risk(move |op: &Operation, g: &Value, pc: &Value| {
        let inputs = match &risk {
            Some(f) => f(g, &op.params, pc),
            None => amount_risk(g, &op.params, None),
        };
        Ok(inputs.unwrap_or_default())
    });
    if let Some(m) = opts.multi_instance {
        ao = ao.with_multi_instance(m);
    }
    if let Some(n) = opts.claim_retries {
        ao = ao.with_claim_retries(n);
    }
    if let Some(k) = &opts.k1 {
        ao = ao.with_k1(k.clone());
    }
    if let Some(u) = &opts.uses_store {
        ao = ao.with_uses_store(u.clone());
    }
    if let Some(pins) = &opts.pq_pins {
        ao = ao.with_pq_pins(pins.clone());
    }
    if let Some(a) = &opts.require_assurance {
        ao = ao.with_require_assurance(a.clone());
    }
    if let Some(h) = &opts.assurance_hooks {
        ao = ao.with_assurance_hooks(h.clone());
    }
    if let Some(g) = opts.freshness_gate {
        ao = ao.with_freshness_gate(g);
    }
    if let Some(t) = opts.threshold.clone() {
        ao = ao.with_threshold(move |a: &Value, b: &Value, c: i64| t(a, b, c));
    }
    if let Some(t) = opts.attestation.clone() {
        ao = ao.with_attestation(move |a: &Value, b: &Value, c: i64| t(a, b, c));
    }
    if let Some(t) = opts.zk.clone() {
        ao = ao.with_zk(move |a: &Value, b: &Value, c: i64| t(a, b, c));
    }
    if !opts.provenance_mediators.is_empty() {
        ao = ao.with_provenance_mediators(opts.provenance_mediators.clone());
    }
    if let Some(f) = opts.provenance_actions.clone() {
        ao = ao.with_provenance_actions(move |op: &Operation| f(op));
    }
    if let Some(b) = operation.provenance.clone() {
        ao = ao.with_provenance_bundle(move |_op: &Operation| Ok(Some(b.clone())));
    }
    let op = Operation::new(
        operation.verb.clone(),
        operation.resource.clone().or_else(|| signed_resource.and_then(Value::as_str).map(str::to_string)).unwrap_or_default(),
        params,
    );
    let g2 = grant.clone();
    let resolve = move |_: &str| Ok::<Option<Value>, String>(Some(g2.clone()));
    let r = ao.run(Some(p), Some(&op), &opts.audience, &resolve, Some(now), None, None);
    if r.allow {
        return ExecutionDecision::Allow { pcactn: r.pcactn.clone().unwrap_or_else(|| p.clone()), grant, result: r };
    }
    let kind = if r.status == 401 {
        ExecutionDenialKind::Authn
    } else if r.check("revocation") == Some(CheckStatus::Fail) {
        ExecutionDenialKind::Revoked
    } else if r.check("replay") == Some(CheckStatus::Fail) {
        ExecutionDenialKind::Replay
    } else {
        ExecutionDenialKind::Policy
    };
    ExecutionDecision::Deny { kind, status: r.status, reason: decisive_reason(&r), checks: Some(r.checks.clone()), result: Some(r) }
}
