//! The undo-window coordinator: admission, the durable ledger, the human surface and the real rollback (the reference
//! `createUndoCoordinator`). The pure record, token, receipts and state machine are in [`crate::undo`]; the stores in [`crate::undo_store`].
//!
//! - admit: ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, the signed reversibility class is
//!   `reversible`, the `engine` (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is
//!   AUTHORIZED under the original grant (predicates, envelope, root and delegated caveats over the original PCActn's verified chain).
//! - open: writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened` receipt,
//!   mints the one-click undo token and notifies the principal. A window nobody was told about is no window: a failed notification
//!   aborts the record and raises an alert.
//! - veto: a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves `open -> vetoed` exactly once and
//!   starts the compensation.
//! - compensate: re-decides the compensating action under the grant as it stood at admission, then runs it at most once per attempt
//!   through the `operations` store and the `compensate` executor. Success: `compensated`, budget released. Anything else:
//!   `compensation_failed`, the reservation kept and an alert raised (never silent).
//! - finalize_due: closes the windows whose time is up and commits their budget reservations.
//!
//! The API is synchronous (the injected store, engine, notifier and compensator are blocking).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::agent::KeyPair;
use crate::approval_channels::{ApprovalDispatcher, NotifyContext};
use crate::authorize::Operation;
use crate::intent_v2::js_value_string;
use crate::operations::{CreateOutcome, OperationRecord, OperationState, OperationStore};
use crate::staleness::Reversibility;
use crate::undo::{
    compensation_digest, decode_undo_token, encode_undo_token, resolve_undo_window, sign_undo_token, undo_token_check, undo_token_digest, undo_transition,
    UndoTransition, UndoWindowPolicy,
};
use crate::undo_store::{with_receipt, UndoCreate, UndoError, UndoErrorCode, UndoQuery, UndoStore};
use crate::{hash_canonical, is_k1_caveat, policy_decision, verify_chain_policy};

const MAX_CAS: usize = 64;
/// With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands).
pub const UNDO_RELAY_GRACE_MS: i64 = 60_000;

/// What the verifier's action definitions say about undoing an operation.
#[derive(Debug, Clone, PartialEq)]
pub struct UndoPlan {
    /// Digest of the CONFIRMED definition of the original action.
    pub def_digest: String,
    pub compensation_verb: String,
    pub compensation_params: Value,
    pub compensation_def_digest: String,
    /// The compensating definition's resource-id parameter, filled at execution from the original's result.
    pub target_param: Option<String>,
    /// K7: the canonical render of the original action and H(R): what the principal is shown.
    pub render: Option<Value>,
    pub render_digest: Option<String>,
}

/// The source of confirmed reversibility. It must answer from SIGNED, reviewer-confirmed definitions only.
pub trait UndoEngine: Send + Sync {
    /// `None`: not undoable = irreversible.
    fn plan(&self, op: &Operation, operation_id: &str) -> Option<UndoPlan>;
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct UndoPolicy {
    /// `always` (default): every eligible action gets a window. `escalations`: only an action that would have asked first. `off`.
    pub mode: Option<String>,
    /// The veto window (clamped into the coordinator's bounds; never below 30 s).
    pub window_ms: Option<f64>,
    /// When the grant is revoked while windows are open: `keep` (default) or `veto`.
    pub on_revocation: Option<String>,
}

/// An admitted but not yet opened window.
#[derive(Debug, Clone)]
pub struct UndoAdmissionDraft {
    pub id: String,
    pub opened_at: i64,
    pub window_end: i64,
    pub converted: bool,
    pub plan: UndoPlan,
    pub compensation: Value,
    pub pcactn: Value,
    pub grant: Value,
    pub operation: Operation,
}

/// What an allowed `authorize` result carries when the action got a veto window.
#[derive(Debug, Clone, PartialEq)]
pub struct UndoWindowInfo {
    pub id: String,
    pub window_end: i64,
    pub converted: bool,
    pub compensation_verb: String,
    pub compensation_resource: String,
    /// The encoded one-click undo token (also delivered to the principal).
    pub token: String,
    /// `{kind: "undo_window", params: {id, window_end}, due: window_end}`.
    pub obligation: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UndoNotice {
    /// `opened`, `vetoed`, `compensated`, `compensation_failed`, `finalized` or `revoked`.
    pub kind: &'static str,
    /// The record without `pcactn` and `receipts`.
    pub record: Value,
    /// `opened` only: the encoded token for the one-click undo link.
    pub token: Option<String>,
    pub render: Option<Value>,
}

pub struct UndoNotifyResult {
    pub delivered: bool,
    pub reason: Option<String>,
}

pub trait UndoNotifier: Send + Sync {
    /// Whether at least one of the principal's channels accepted the notice.
    fn notify(&self, n: &UndoNotice) -> UndoNotifyResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoAlert {
    /// `critical` or `warning`.
    pub level: &'static str,
    /// `compensation_failed`, `notify_failed`, `effect_unknown`, `slash_after_window`, `budget_settle_failed`, `revoked_open_window`,
    /// `compensation_denied` or `veto_relay_failed`.
    pub code: &'static str,
    pub record: String,
    pub reason: String,
}

/// What the compensating-action executor receives.
#[derive(Debug, Clone)]
pub struct UndoCompensationCall {
    /// The compensating operation with its target filled in (when the definition names one).
    pub operation: Operation,
    /// The idempotency key of this attempt (pass it to the downstream call).
    pub idempotency_key: String,
    /// The original operation id (`undo_of`) and its reported result.
    pub undo_of: String,
    pub original_result: Option<Value>,
    /// The record without `pcactn`.
    pub record: Value,
}

/// A veto taken by a relay: the principal's token and the time the relay received it.
#[derive(Debug, Clone, PartialEq)]
pub struct UndoRelayedVeto {
    pub id: String,
    pub token: Value,
    pub at: i64,
}

/// Vetoes received somewhere else (the hosted veto endpoint). A relay that cannot be read finalizes NOTHING (a veto may be waiting).
pub trait UndoVetoRelay: Send + Sync {
    fn pending(&self) -> Result<Vec<UndoRelayedVeto>, UndoError>;
}

/// The aggregate budget reservations held during a window (committed on finalize, released on compensation or abort).
/// [`crate::budget_ledger::KvBudgetLedger`] implements it (a release carries evidence only when you give
/// `budget_evidence`); adapt another ledger to this seam. Outcomes `settled` and `replayed` are success.
pub trait UndoBudgetLedger: Send + Sync {
    fn commit(&self, key: &str, id: &str) -> Result<String, String>;
    fn release(&self, key: &str, id: &str, evidence: Option<Value>) -> Result<String, String>;
}

/// Slashes a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window). Returns the settlement record.
pub trait UndoBondSlasher: Send + Sync {
    fn slash_bond(&self, params: &Value) -> Result<Value, String>;
}

pub type UndoGrantResolver = dyn Fn(&str, &Value) -> Option<Value> + Send + Sync;
pub type UndoCompensator = dyn Fn(&UndoCompensationCall) -> Result<Value, String> + Send + Sync;
pub type UndoAlertSink = dyn Fn(&UndoAlert) + Send + Sync;
pub type UndoPolicyFn = dyn Fn(&Operation, &Value) -> Option<UndoPolicy> + Send + Sync;
pub type UndoTargetResolver = dyn Fn(&Value) -> Option<String> + Send + Sync;
pub type UndoBudgetEvidence = dyn Fn(&Value, &str) -> Option<Value> + Send + Sync;

/// The configuration of [`create_undo_coordinator`]. `store`, `engine`, `signer_secret`, `audience`, `resolve_grant`, `compensate`,
/// `operations`, `notifier` and `alert` are REQUIRED.
#[derive(Clone, Default)]
pub struct UndoCoordinatorOptions {
    /// The durable undo ledger (`durable() == true`).
    pub store: Option<Arc<dyn UndoStore>>,
    pub engine: Option<Arc<dyn UndoEngine>>,
    /// The undo service key (32-byte Ed25519 seed): signs tokens and receipts.
    pub signer_secret: Option<Vec<u8>>,
    /// This resource server's audience (bound into the token).
    pub audience: String,
    /// The grant by reference, from YOUR store (the same function `authorize` uses).
    pub resolve_grant: Option<Arc<UndoGrantResolver>>,
    /// Runs a compensating action (your connector). Return `Err` on failure.
    pub compensate: Option<Arc<UndoCompensator>>,
    /// At-most-once records for compensation attempts (shared and durable in production).
    pub operations: Option<Arc<dyn OperationStore>>,
    pub notifier: Option<Arc<dyn UndoNotifier>>,
    /// Where a failure that needs a human goes (pager, SIEM). Never silent.
    pub alert: Option<Arc<UndoAlertSink>>,
    pub policy: Option<Arc<UndoPolicyFn>>,
    pub window: UndoWindowPolicy,
    /// The value of the compensating action's target parameter. Default: `effect.result.id` when it is a non-empty string.
    pub resolve_target: Option<Arc<UndoTargetResolver>>,
    pub budget: Option<Arc<dyn UndoBudgetLedger>>,
    pub budget_evidence: Option<Arc<UndoBudgetEvidence>>,
    /// Verifier-side PQ pins forwarded to the compensation decision.
    pub pq_pins: Option<std::collections::HashMap<String, String>>,
    /// A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes.
    pub effect_timeout_ms: Option<i64>,
    pub now: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    pub relay: Option<Arc<dyn UndoVetoRelay>>,
    /// TESTS ONLY: accept a store whose `durable()` is false (every open window is lost on restart).
    pub insecure_volatile_store: bool,
}

/// The required components that are absent (empty = complete).
pub fn missing_undo_components(o: &UndoCoordinatorOptions) -> Vec<String> {
    let mut m = Vec::new();
    if o.store.is_none() {
        m.push("store");
    }
    if o.engine.is_none() {
        m.push("engine");
    }
    if o.signer_secret.as_ref().map_or(true, |s| s.len() != 32) {
        m.push("signerSecret");
    }
    if o.audience.is_empty() {
        m.push("audience");
    }
    if o.resolve_grant.is_none() {
        m.push("resolveGrant");
    }
    if o.compensate.is_none() {
        m.push("compensate");
    }
    if o.operations.is_none() {
        m.push("operations");
    }
    if o.notifier.is_none() {
        m.push("notifier");
    }
    if o.alert.is_none() {
        m.push("alert");
    }
    m.into_iter().map(String::from).collect()
}

/// The undo service key's public half, for verifying tokens and receipts elsewhere (e.g. the hosted veto route).
pub fn undo_signer_public(secret: &[u8; 32]) -> String {
    KeyPair::from_seed(secret).public
}

/// Null when `a` is a usable admission `{id, window_end, compensation: {verb}}`, else the reason.
pub fn undo_admission_error(a: &Value) -> Option<String> {
    let Some(m) = a.as_object() else { return Some("an admission must be an object".into()) };
    match m.get("id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() && id.encode_utf16().count() <= 128 => {}
        _ => return Some("admission id must be a non-empty string of at most 128 characters".into()),
    }
    let we = m.get("window_end").and_then(|v| crate::safe_int(v));
    if !we.is_some_and(|w| w >= 0) || m.get("window_end").and_then(Value::as_f64).is_some_and(|f| f == 0.0 && f.is_sign_negative()) {
        return Some("admission window_end must be a non-negative safe integer".into());
    }
    match m.get("compensation").and_then(Value::as_object).and_then(|c| c.get("verb")).and_then(Value::as_str) {
        Some(v) if !v.is_empty() => None,
        _ => Some("admission compensation.verb must be a non-empty string".into()),
    }
}

/// The result of a veto.
#[derive(Debug, Clone, PartialEq)]
pub enum VetoResult {
    Ok {
        record: Value,
        replayed: bool,
    },
    /// `code`: a token check (`malformed`, `signer`, `signature`, `record`, `binding`, `expired`), a transition code (`window_closed`,
    /// `finalized`, ...) or `unknown`.
    Refused {
        code: String,
        reason: String,
    },
}

/// How a veto is made: the principal's one-click token (with the relay's time), an authenticated operator of this server, or a
/// policy-made veto (`revocation`, `fraud_proof`).
pub enum VetoBy {
    Token { token: Value, at: Option<i64> },
    Operator(String),
    Veto(Value),
}

/// The coordinator. Build it with [`create_undo_coordinator`].
pub struct UndoCoordinator {
    o: UndoCoordinatorOptions,
    store: Arc<dyn UndoStore>,
    engine: Arc<dyn UndoEngine>,
    operations: Arc<dyn OperationStore>,
    notifier: Arc<dyn UndoNotifier>,
    key: KeyPair,
    signer_public: String,
    effect_timeout_ms: i64,
}

/// Build the coordinator. Fails with `config` for a missing component and `not_durable` for a volatile store (fail closed).
pub fn create_undo_coordinator(opts: UndoCoordinatorOptions) -> Result<UndoCoordinator, UndoError> {
    let missing = missing_undo_components(&opts);
    if !missing.is_empty() {
        return Err(UndoError::new(UndoErrorCode::Config, format!("undo coordinator: missing required component(s): {}", missing.join(", "))));
    }
    if opts.effect_timeout_ms.is_some_and(|t| t < 0) {
        return Err(UndoError::new(UndoErrorCode::Config, "undo coordinator: effectTimeoutMs must be a non-negative number"));
    }
    let store = opts.store.clone().expect("checked");
    if !store.durable() && !opts.insecure_volatile_store {
        return Err(UndoError::new(UndoErrorCode::NotDurable, "an undo ledger must be durable: a restart would lose every open window and its compensation"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(opts.signer_secret.as_ref().expect("checked"));
    let key = KeyPair::from_seed(&seed);
    Ok(UndoCoordinator {
        signer_public: key.public.clone(),
        key,
        store,
        engine: opts.engine.clone().expect("checked"),
        operations: opts.operations.clone().expect("checked"),
        notifier: opts.notifier.clone().expect("checked"),
        effect_timeout_ms: opts.effect_timeout_ms.unwrap_or(5 * 60_000),
        o: opts,
    })
}

enum Applied {
    Done { record: Value, applied: bool },
    Refused { code: String, reason: String },
}

fn strip(r: &Value) -> Value {
    let mut r = r.clone();
    if let Some(m) = r.as_object_mut() {
        m.remove("pcactn");
        m.remove("receipts");
    }
    r
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_f64).map_or(0, |f| f as i64)
}

fn state_of(v: &Value) -> &str {
    s(v, "state")
}

fn invalid(m: impl AsRef<str>) -> UndoError {
    UndoError::new(UndoErrorCode::Invalid, m)
}

impl UndoCoordinator {
    /// The undo service key's public half.
    pub fn signer_public(&self) -> &str {
        &self.signer_public
    }

    fn now(&self) -> Result<i64, UndoError> {
        let t = match &self.o.now {
            Some(f) => f(),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0),
        };
        Ok(t)
    }

    fn alert(&self, level: &'static str, code: &'static str, record: &str, reason: String) {
        let a = UndoAlert { level, code, record: record.to_string(), reason: reason.clone() };
        if let Some(f) = &self.o.alert {
            // an alert sink that panics is itself a failure the operator must see: write it where a host always looks
            if catch_unwind(AssertUnwindSafe(|| f(&a))).is_err() {
                eprintln!("pca undo alert ({code}) for {record}: {reason}");
            }
        }
    }

    fn notify(&self, n: UndoNotice) -> UndoNotifyResult {
        match catch_unwind(AssertUnwindSafe(|| self.notifier.notify(&n))) {
            Ok(r) if r.delivered => UndoNotifyResult { delivered: true, reason: None },
            Ok(r) => UndoNotifyResult { delivered: false, reason: Some(r.reason.unwrap_or_else(|| "no channel delivered the notice".into())) },
            Err(_) => UndoNotifyResult { delivered: false, reason: Some("notifier error".into()) },
        }
    }

    fn notice(&self, kind: &'static str, rec: &Value) -> UndoNotifyResult {
        self.notify(UndoNotice { kind, record: strip(rec), token: None, render: None })
    }

    /// Apply one event with compare-and-swap retries; returns the stored record and whether this call applied it.
    fn apply(&self, id: &str, ev: &Value, check_at: Option<i64>) -> Result<Applied, UndoError> {
        for _ in 0..MAX_CAS {
            let Some(cur) = self.store.get(id)? else { return Ok(Applied::Refused { code: "unknown".into(), reason: format!("no undo record {id}") }) };
            let t = self.now()?;
            // a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
            match undo_transition(&cur, ev, check_at.unwrap_or(t) as f64) {
                UndoTransition::Refused { code, reason } => return Ok(Applied::Refused { code: code.into(), reason }),
                UndoTransition::Replayed => return Ok(Applied::Done { record: cur, applied: false }),
                UndoTransition::Applied { record, event, note } => {
                    let next = with_receipt(&record, event, &note, t, &self.key).map_err(invalid)?;
                    if self.store.replace(id, i(&cur, "ver"), &next)? {
                        return Ok(Applied::Done { record: next, applied: true });
                    }
                }
            }
        }
        Err(UndoError::new(UndoErrorCode::ConflictExhausted, format!("undo record {id} kept changing")))
    }

    fn must(&self, id: &str, ev: &Value) -> Result<(Value, bool), UndoError> {
        match self.apply(id, ev, None)? {
            Applied::Refused { code, reason } => Err(invalid(format!("{code}: {reason}"))),
            Applied::Done { record, applied } => Ok((record, applied)),
        }
    }

    fn settle_budget(&self, rec: &Value, how: &str) {
        let Some(ledger) = &self.o.budget else { return };
        let Some(list) = rec.get("budget").and_then(Value::as_array).filter(|l| !l.is_empty()) else { return };
        for r in list {
            let (key, id) = (s(r, "key"), s(r, "id"));
            let out = if how == "commit" { ledger.commit(key, id) } else { ledger.release(key, id, self.o.budget_evidence.as_ref().and_then(|f| f(r, how))) };
            match out {
                Ok(o) if o == "settled" || o == "replayed" => {}
                Ok(o) => self.alert("warning", "budget_settle_failed", s(rec, "id"), format!("{how} of {key}/{id}: {o}")),
                Err(e) => self.alert("warning", "budget_settle_failed", s(rec, "id"), format!("{how} of {key}/{id}: {e}")),
            }
        }
    }

    fn policy_of(&self, op: &Operation, grant: &Value) -> UndoPolicy {
        self.o.policy.as_ref().and_then(|f| f(op, grant)).unwrap_or_default()
    }

    /// The policy decision on the compensating action under the original chain: the chain verifies from the grant, the envelope
    /// predicates and every caveat group pass. Risk and budget never gate a release (the human/step-up path stays available).
    fn compensation_allowed(&self, pc: &Value, grant: &Value, op: &Operation, at: i64) -> (bool, String) {
        let deny = |why: String| (false, why);
        let Some(chain) = pc.get("cap_chain").and_then(Value::as_array).filter(|c| !c.is_empty()) else {
            return deny("capability chain unverified: empty chain".into());
        };
        if let Err(e) = verify_chain_policy(chain, grant.get("issuer").and_then(Value::as_str), None, self.o.pq_pins.as_ref(), Some(grant)) {
            return deny(format!("capability chain unverified: {e}"));
        }
        let k1 = |c: &Value| c.get("caveats").and_then(Value::as_array).is_some_and(|l| l.iter().any(is_k1_caveat));
        if chain.last().is_some_and(k1) || k1(grant) {
            return deny("caveat language: a K1 caveat needs an input this decision does not carry (fail closed)".into());
        }
        let d = policy_decision(
            grant,
            &Value::Array(chain.clone()),
            &json!({"action": {"verb": op.verb, "resource": op.resource, "params": op.params}, "now": at}),
        );
        if d["allow"] == json!(true) {
            return (true, String::new());
        }
        let list = |k: &str| d["failed"][k].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        let why = match d["reasons"].as_array().and_then(|r| r.first()).and_then(Value::as_str) {
            Some("envelope_missing") => "grant carries no valid envelope".to_string(),
            // the evaluator's own reason (`no predicate permits ..`, `<limit> not satisfied for ..`), as the reference reports it
            Some("predicates_unsatisfied") => {
                let preds = crate::read_envelope(grant).and_then(|e| e.get("predicates").and_then(Value::as_array).cloned()).unwrap_or_default();
                crate::authorize::envelope_predicates_denial(&preds, &json!({"action": {"verb": op.verb, "resource": op.resource, "params": op.params}}))
                    .unwrap_or_else(|| "action not permitted by envelope predicates".to_string())
            }
            Some("chain_malformed") => "delegation chain is empty or malformed".to_string(),
            Some("envelope_caveats_unsatisfied") => format!("caveat(s) not satisfied: {}", list("envelope")),
            Some("root_caveats_unsatisfied") => format!("root caveat(s) not satisfied: {}", list("root")),
            Some("delegated_caveats_unsatisfied") => format!("delegated caveat(s) not satisfied: {}", list("delegated")),
            _ => "the grant does not authorize the compensating action".to_string(),
        };
        (false, why)
    }

    /// ELIGIBILITY: `Ok(draft)` only when every condition holds, else `Err(reason)` (the action stays irreversible).
    pub fn admit(&self, pcactn: &Value, grant: Option<&Value>, operation: &Operation, converted: bool) -> Result<UndoAdmissionDraft, String> {
        catch_unwind(AssertUnwindSafe(|| self.admit_inner(pcactn, grant, operation, converted)))
            .unwrap_or_else(|_| Err("undo admission error (fail closed): unknown".into()))
    }

    fn admit_inner(&self, pc: &Value, grant: Option<&Value>, op: &Operation, converted: bool) -> Result<UndoAdmissionDraft, String> {
        let grant = match grant {
            Some(g) => g.clone(),
            None => (self.o.resolve_grant.as_ref().expect("checked"))(s(pc, "grant_ref"), pc).ok_or("unknown grant")?,
        };
        let pol = self.policy_of(op, &grant);
        let mode = pol.mode.as_deref().unwrap_or("always");
        if mode == "off" {
            return Err("policy: undo windows are off".into());
        }
        if mode == "escalations" && !converted {
            return Err("policy: windows only replace approvals".into());
        }
        // the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
        let class = pc.get("action").and_then(|a| a.get("reversibility_class"));
        if class.and_then(Value::as_str) != Some("reversible") {
            return Err(format!("the signed class is {}", class.map_or("undefined".to_string(), js_value_string)));
        }
        let id = hash_canonical(pc);
        let plan = self.engine.plan(op, &id).ok_or("not confirmed reversible, or no confirmed compensating action")?;
        let mut comp = json!({"verb": plan.compensation_verb, "resource": op.resource, "params": plan.compensation_params, "undo_of": id, "def_digest": plan.compensation_def_digest});
        if let Some(tp) = &plan.target_param {
            comp["target_param"] = json!(tp);
        }
        let t = self.now().map_err(|e| e.message)?;
        let comp_op = Operation::new(plan.compensation_verb.clone(), op.resource.clone(), plan.compensation_params.clone());
        let (ok, why) = self.compensation_allowed(pc, &grant, &comp_op, t);
        if !ok {
            return Err(format!("the compensating action is not authorized under the grant: {why}"));
        }
        let window_ms = resolve_undo_window(pol.window_ms, &self.o.window);
        Ok(UndoAdmissionDraft {
            id,
            opened_at: t,
            window_end: t + window_ms,
            converted,
            plan,
            compensation: comp,
            pcactn: pc.clone(),
            grant,
            operation: op.clone(),
        })
    }

    fn info_of(&self, rec: &Value) -> Result<UndoWindowInfo, UndoError> {
        let tok = sign_undo_token(rec, &self.key).and_then(|t| encode_undo_token(&t)).map_err(invalid)?;
        Ok(UndoWindowInfo {
            id: s(rec, "id").to_string(),
            window_end: i(rec, "window_end"),
            converted: rec.get("converted") == Some(&json!(true)),
            compensation_verb: s(&rec["compensation"], "verb").to_string(),
            compensation_resource: s(&rec["compensation"], "resource").to_string(),
            token: tok,
            obligation: json!({"kind": "undo_window", "params": {"id": s(rec, "id"), "window_end": i(rec, "window_end")}, "due": i(rec, "window_end")}),
        })
    }

    /// Open the window: the record is written DURABLY before the effect may run, then the principal is told. A window nobody was told
    /// about is no window: a failed notification aborts the record and raises an alert. `bond`: `(bond ref, challenge end)`.
    pub fn open(&self, adm: &UndoAdmissionDraft, bond: Option<(&str, i64)>) -> Result<UndoWindowInfo, UndoError> {
        let chain = adm.pcactn.get("cap_chain").and_then(Value::as_array).cloned().unwrap_or_default();
        let window_end = bond.map_or(adm.window_end, |(_, ends)| adm.window_end.max(ends));
        let cdig = compensation_digest(&adm.compensation).ok_or_else(|| invalid("the compensation is outside the strict JSON profile"))?;
        let mut base = json!({
            "v": 1, "id": adm.id, "aud": self.o.audience, "grant_ref": s(&adm.pcactn, "grant_ref"),
            "holder": chain.last().map(|h| s(h, "holder")).unwrap_or(""), "principal": s(&adm.grant, "issuer"),
            "action": {"verb": adm.operation.verb, "resource": adm.operation.resource, "params_digest": s(&adm.pcactn["action"], "params_digest"), "def_digest": adm.plan.def_digest},
            "compensation": adm.compensation, "compensation_digest": cdig,
            "opened_at": adm.opened_at, "window_end": window_end, "converted": adm.converted, "state": "open", "ver": 0,
            "pcactn": String::from_utf8_lossy(&crate::hash::canonical_bytes_lenient(&adm.pcactn)),
            "attempt": 0, "receipts": []
        });
        if let Some(rd) = &adm.plan.render_digest {
            base["render_digest"] = json!(rd);
        }
        if let Some((r, _)) = bond {
            base["bond_ref"] = json!(r);
        }
        let rec = with_receipt(&base, "opened", if adm.converted { "converted" } else { "" }, adm.opened_at, &self.key).map_err(invalid)?;
        match self.store.create(&rec)? {
            UndoCreate::Exists(cur) => {
                // a retry of the same admission returns the same window; anything else is a different action under the same id
                if s(&cur, "compensation_digest") != cdig || state_of(&cur) != "open" {
                    return Err(invalid(format!("undo record {} already exists with other terms or state {}", adm.id, state_of(&cur))));
                }
                self.info_of(&cur)
            }
            UndoCreate::Created => {
                let info = self.info_of(&rec)?;
                let n = self.notify(UndoNotice { kind: "opened", record: strip(&rec), token: Some(info.token.clone()), render: adm.plan.render.clone() });
                if !n.delivered {
                    self.apply(s(&rec, "id"), &json!({"kind": "abort", "reason": "notify_failed"}), None)?;
                    let why = n.reason.unwrap_or_else(|| "not delivered".into());
                    self.alert("critical", "notify_failed", s(&rec, "id"), format!("the principal could not be told about the undo window: {why}"));
                    return Err(invalid(format!("notify_failed: the undo window could not be announced ({why})")));
                }
                Ok(info)
            }
        }
    }

    pub fn get(&self, id: &str) -> Result<Option<Value>, UndoError> {
        self.store.get(id)
    }

    /// Hold aggregate budget reservations (`[{key, id}]`) until the window closes.
    pub fn hold_budget(&self, id: &str, reservations: &[(String, String)]) -> Result<Value, UndoError> {
        for _ in 0..MAX_CAS {
            let cur = self.store.get(id)?.ok_or_else(|| invalid(format!("no undo record {id}")))?;
            if state_of(&cur) != "open" && state_of(&cur) != "vetoed" {
                return Err(invalid(format!("a {} record holds no budget", state_of(&cur))));
            }
            let mut next = cur.clone();
            let mut b = cur.get("budget").and_then(Value::as_array).cloned().unwrap_or_default();
            b.extend(reservations.iter().map(|(k, i)| json!({"key": k, "id": i})));
            next["budget"] = Value::Array(b);
            next["ver"] = json!(i(&cur, "ver") + 1);
            if self.store.replace(id, i(&cur, "ver"), &next)? {
                return Ok(next);
            }
        }
        Err(UndoError::new(UndoErrorCode::ConflictExhausted, format!("undo record {id} kept changing")))
    }

    /// The original effect ran: record its result (it names the compensation target). A veto that arrived while the effect was running is acted on now.
    pub fn record_effect(&self, id: &str, result: Option<&Value>) -> Result<Value, UndoError> {
        let mut ev = json!({"kind": "effect"});
        if let Some(r) = result {
            ev["result"] = r.clone();
        }
        let (rec, _) = self.must(id, &ev)?;
        if state_of(&rec) == "vetoed" {
            self.run_compensation(rec)
        } else {
            Ok(rec)
        }
    }

    /// The effect never ran: close the window (held budget released).
    pub fn abort(&self, id: &str, reason: &str) -> Result<Value, UndoError> {
        let (rec, applied) = self.must(id, &json!({"kind": "abort", "reason": reason}))?;
        if applied {
            self.settle_budget(&rec, "effect_not_run");
        }
        Ok(rec)
    }

    /// Veto with the one-click token (the principal), as an authenticated operator, or by policy.
    pub fn veto(&self, id: &str, by: &VetoBy) -> VetoResult {
        match self.veto_inner(id, by) {
            Ok(r) => r,
            Err(e) => VetoResult::Refused { code: "malformed".into(), reason: format!("veto error (fail closed): {}", e.message) },
        }
    }

    fn veto_inner(&self, id: &str, by: &VetoBy) -> Result<VetoResult, UndoError> {
        let refuse = |code: &str, reason: String| -> Result<VetoResult, UndoError> { Ok(VetoResult::Refused { code: code.into(), reason }) };
        let Some(cur) = self.store.get(id)? else { return refuse("unknown", format!("no undo record {id}")) };
        let mut t = self.now()?;
        let mut check_at: Option<i64> = None;
        let v = match by {
            VetoBy::Token { token, at } => {
                if let Some(at) = at {
                    if *at > t || *at < i(&cur, "opened_at") {
                        return refuse("malformed", "a relayed veto time must lie between the opening of the window and now".into());
                    }
                    t = *at;
                    check_at = Some(*at);
                }
                let tok = match token.as_str() {
                    Some(text) => decode_undo_token(text).unwrap_or(Value::Null),
                    None => token.clone(),
                };
                let chk = undo_token_check(&tok, &self.signer_public, &cur, t as f64);
                if chk != "ok" {
                    return refuse(chk, format!("the undo token was refused ({chk})"));
                }
                json!({"at": t, "via": "token", "by": s(&cur, "principal"), "evidence": undo_token_digest(&tok)})
            }
            VetoBy::Operator(op) => {
                if op.is_empty() {
                    return refuse("malformed", "an operator veto names the operator".into());
                }
                json!({"at": t, "via": "operator", "by": op})
            }
            VetoBy::Veto(v) => {
                let mut v = v.clone();
                v["at"] = json!(t);
                v
            }
        };
        let (record, applied) = match self.apply(id, &json!({"kind": "veto", "veto": v}), check_at)? {
            Applied::Refused { code, reason } => return refuse(&code, reason),
            Applied::Done { record, applied } => (record, applied),
        };
        if applied {
            self.notice("vetoed", &record);
        }
        let done = self.run_compensation(record)?;
        Ok(VetoResult::Ok { record: done, replayed: !applied })
    }

    /// Apply the relay's pending vetoes now (also done by every `finalize_due`). Fails when the relay cannot be read.
    pub fn sync_relay(&self) -> Result<Vec<VetoResult>, UndoError> {
        let Some(relay) = &self.o.relay else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for x in relay.pending()? {
            // a forged or late relay entry is refused by the same checks as any veto
            out.push(self.veto(&x.id, &VetoBy::Token { token: x.token, at: Some(x.at) }));
        }
        Ok(out)
    }

    fn fail_compensation(&self, rec: &Value, reason: String, code: &'static str) -> Result<Value, UndoError> {
        let out = match self.apply(s(rec, "id"), &json!({"kind": "compensation_failed", "reason": reason}), None)? {
            Applied::Refused { .. } => self.store.get(s(rec, "id"))?.unwrap_or_else(|| rec.clone()),
            Applied::Done { record, applied } => {
                if applied {
                    self.alert("critical", code, s(rec, "id"), reason);
                    self.notice("compensation_failed", &record);
                }
                record
            }
        };
        Ok(out)
    }

    fn run_compensation(&self, rec0: Value) -> Result<Value, UndoError> {
        let mut rec = rec0;
        if state_of(&rec) != "vetoed" {
            return Ok(rec);
        }
        let t = self.now()?;
        let veto_at = rec.get("veto").and_then(|v| v.get("at")).and_then(Value::as_f64).map_or(t, |f| f as i64);
        if rec.get("effect").is_none() && t - veto_at < self.effect_timeout_ms {
            return Ok(rec); // wait for the effect report (record_effect resumes)
        }
        let pc = crate::strict_parse(rec.get("pcactn").and_then(Value::as_str).unwrap_or(""))
            .map_err(|e| invalid(format!("the stored PCActn is unreadable: {e}")))?;
        let resolve = self.o.resolve_grant.as_ref().expect("checked");
        let Some(grant) = resolve(s(&rec, "grant_ref"), &pc) else {
            return self.fail_compensation(&rec, "the grant is no longer known: the compensation cannot be authorized".into(), "compensation_denied");
        };
        let mut params = rec["compensation"]["params"].as_object().cloned().unwrap_or_default();
        if let Some(tp) = rec["compensation"].get("target_param").and_then(Value::as_str) {
            let target = match &self.o.resolve_target {
                Some(f) => f(&rec),
                None => rec
                    .get("effect")
                    .and_then(|e| e.get("result"))
                    .and_then(|r| r.get("id"))
                    .and_then(Value::as_str)
                    .filter(|x| !x.is_empty())
                    .map(String::from),
            };
            let Some(target) = target else {
                return self.fail_compensation(
                    &rec,
                    format!("the target '{tp}' of the compensation is unknown (no effect result names it)"),
                    "compensation_failed",
                );
            };
            params.insert(tp.to_string(), json!(target));
        }
        let op = Operation::new(s(&rec["compensation"], "verb"), s(&rec["compensation"], "resource"), Value::Object(params.clone()));
        let (ok, why) = self.compensation_allowed(&pc, &grant, &op, i(&rec, "opened_at"));
        if !ok {
            return self.fail_compensation(&rec, format!("the compensating action is not authorized under the grant: {why}"), "compensation_denied");
        }
        // at most once per attempt: the operation record is created before the compensator runs
        let op_id = hash_canonical(&json!({"d": "atlas-pca/undo-compensation-op/v1", "record": s(&rec, "id"), "attempt": i(&rec, "attempt")}));
        let orec = OperationRecord {
            id: op_id.clone(),
            state: OperationState::Pending,
            verb: op.verb.clone(),
            resource: op.resource.clone(),
            params_digest: hash_canonical(&Value::Object(params.clone())),
            reversibility: Reversibility::Irreversible,
            started_at: t,
            executing_at: None,
            finished_at: None,
            result: None,
            error: None,
        };
        let store_err = |e: crate::StoreError| UndoError::new(UndoErrorCode::StoreCorrupt, e.0);
        if let CreateOutcome::Exists(prev) = self.operations.create(orec.clone()).map_err(store_err)? {
            match prev.state {
                OperationState::Committed => {
                    let mut ev = json!({"kind": "compensated"});
                    if let Some(r) = &prev.result {
                        ev["result"] = r.clone();
                    }
                    if let Applied::Done { record, .. } = self.apply(s(&rec, "id"), &ev, None)? {
                        rec = record;
                    }
                    return self.finish_compensated(rec);
                }
                OperationState::Failed | OperationState::Uncertain => {
                    return self.fail_compensation(
                        &rec,
                        format!("compensation attempt {} {}: {}", i(&rec, "attempt"), prev.state.as_str(), prev.error.clone().unwrap_or_default()),
                        "compensation_failed",
                    );
                }
                OperationState::Aborted => {
                    let Applied::Done { record, .. } =
                        self.apply(s(&rec, "id"), &json!({"kind": "compensation_failed", "reason": "attempt never started"}), None)?
                    else {
                        return Ok(rec);
                    };
                    return match self.apply(s(&rec, "id"), &json!({"kind": "retry"}), None)? {
                        Applied::Done { record: again, .. } => self.run_compensation(again),
                        Applied::Refused { .. } => Ok(record),
                    };
                }
                OperationState::Pending | OperationState::Executing => {
                    // another worker holds it, or a crash; stale ones are settled here
                    if t - prev.executing_at.unwrap_or(prev.started_at) > self.effect_timeout_ms {
                        let settled = if prev.state == OperationState::Pending {
                            OperationRecord { state: OperationState::Aborted, error: Some("never started".into()), finished_at: Some(t), ..prev.clone() }
                        } else {
                            OperationRecord {
                                state: OperationState::Uncertain,
                                error: Some("no outcome recorded: the compensation may or may not have run".into()),
                                finished_at: Some(t),
                                ..prev.clone()
                            }
                        };
                        self.operations.transition(&prev.id, prev.state, settled).map_err(store_err)?;
                        let again = self.store.get(s(&rec, "id"))?.unwrap_or_else(|| rec.clone());
                        return self.run_compensation(again);
                    }
                    return Ok(rec);
                }
            }
        }
        // re-read under the record: a concurrent retry or resolution wins
        let cur = self.store.get(s(&rec, "id"))?;
        let cur = match cur {
            Some(c) if state_of(&c) == "vetoed" && i(&c, "attempt") == i(&rec, "attempt") => c,
            other => {
                self.operations
                    .transition(
                        &op_id,
                        OperationState::Pending,
                        OperationRecord {
                            state: OperationState::Aborted,
                            error: Some("the undo record moved on".into()),
                            finished_at: Some(self.now()?),
                            ..orec
                        },
                    )
                    .map_err(store_err)?;
                return Ok(other.unwrap_or(rec));
            }
        };
        let running = OperationRecord { state: OperationState::Executing, executing_at: Some(self.now()?), ..orec.clone() };
        if !self.operations.transition(&op_id, OperationState::Pending, running.clone()).map_err(store_err)? {
            return Ok(self.store.get(s(&rec, "id"))?.unwrap_or(rec));
        }
        let call = UndoCompensationCall {
            operation: op,
            idempotency_key: op_id.clone(),
            undo_of: s(&rec, "id").to_string(),
            original_result: rec.get("effect").and_then(|e| e.get("result")).cloned(),
            record: {
                let mut c = cur.clone();
                if let Some(m) = c.as_object_mut() {
                    m.remove("pcactn");
                }
                c
            },
        };
        let comp = self.o.compensate.as_ref().expect("checked");
        let result = match catch_unwind(AssertUnwindSafe(|| comp(&call))) {
            Ok(Ok(r)) => r,
            Ok(Err(error)) => return self.compensator_failed(&rec, &op_id, &running, error),
            Err(_) => return self.compensator_failed(&rec, &op_id, &running, "the compensator panicked".into()),
        };
        let _ = self.operations.transition(
            &op_id,
            OperationState::Executing,
            OperationRecord { state: OperationState::Committed, result: Some(result.clone()), finished_at: Some(self.now()?), ..running },
        );
        let mut ev = json!({"kind": "compensated"});
        if !result.is_null() {
            ev["result"] = result;
        }
        match self.apply(s(&rec, "id"), &ev, None)? {
            Applied::Refused { .. } => Ok(self.store.get(s(&rec, "id"))?.unwrap_or(rec)),
            Applied::Done { record, .. } => self.finish_compensated(record),
        }
    }

    fn compensator_failed(&self, rec: &Value, op_id: &str, running: &OperationRecord, error: String) -> Result<Value, UndoError> {
        let failed = OperationRecord { state: OperationState::Failed, error: Some(error.clone()), finished_at: Some(self.now()?), ..running.clone() };
        let _ = self.operations.transition(op_id, OperationState::Executing, failed);
        self.fail_compensation(rec, format!("the compensating action failed: {error}"), "compensation_failed")
    }

    fn finish_compensated(&self, rec: Value) -> Result<Value, UndoError> {
        if state_of(&rec) == "compensated" {
            self.settle_budget(&rec, "rollback");
            self.notice("compensated", &rec);
        }
        Ok(rec)
    }

    /// Run the compensation of a vetoed record now (a recovery or an operator action).
    pub fn compensate(&self, id: &str) -> Result<Value, UndoError> {
        let cur = self.store.get(id)?.ok_or_else(|| invalid(format!("no undo record {id}")))?;
        self.run_compensation(cur)
    }

    /// `compensation_failed -> vetoed` under the next attempt number, then compensate again.
    pub fn retry(&self, id: &str) -> Result<Value, UndoError> {
        let (rec, _) = self.must(id, &json!({"kind": "retry"}))?;
        self.run_compensation(rec)
    }

    /// Close the windows whose time is up and commit their budget reservations; returns the ids finalized. The relay's pending vetoes
    /// are applied first; a relay that cannot be read finalizes NOTHING.
    pub fn finalize_due(&self) -> Result<Vec<String>, UndoError> {
        let mut out = Vec::new();
        if let Err(e) = self.sync_relay() {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            self.alert("critical", "veto_relay_failed", "*", format!("the veto relay could not be read; no window was finalized: {}", e.message));
            return Ok(out);
        }
        // with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
        let by = self.now()? - 1 - if self.o.relay.is_some() { UNDO_RELAY_GRACE_MS } else { 0 };
        for rec in self.store.list(&UndoQuery { state: "open".into(), window_ended_by: Some(by), ..Default::default() })? {
            let Applied::Done { record, applied: true } = self.apply(s(&rec, "id"), &json!({"kind": "finalize"}), None)? else { continue };
            out.push(s(&rec, "id").to_string());
            if record.get("effect").is_none() {
                self.alert("warning", "effect_unknown", s(&rec, "id"), "the window closed without an effect report: reconcile the original operation".into());
            }
            self.settle_budget(&record, "commit");
            self.notice("finalized", &record);
        }
        Ok(out)
    }

    /// After a restart: finish the compensation of every vetoed record, then close the windows that are due.
    pub fn recover(&self) -> Result<Vec<String>, UndoError> {
        let mut out = Vec::new();
        for rec in self.store.list(&UndoQuery { state: "vetoed".into(), ..Default::default() })? {
            let r = self.run_compensation(rec.clone())?;
            if state_of(&r) != "vetoed" {
                out.push(s(&rec, "id").to_string());
            }
        }
        out.extend(self.finalize_due()?);
        Ok(out)
    }

    /// A grant was revoked: its open windows are vetoed (`onRevocation: veto`) or the principal is told and can still undo them.
    pub fn on_revocation(&self, grant_ref: &str) -> Result<Vec<String>, UndoError> {
        let mut out = Vec::new();
        for rec in self.store.list(&UndoQuery { state: "open".into(), grant_ref: Some(grant_ref.to_string()), ..Default::default() })? {
            let pc = crate::strict_parse(rec.get("pcactn").and_then(Value::as_str).unwrap_or(""))
                .map_err(|e| invalid(format!("the stored PCActn is unreadable: {e}")))?;
            let resolve = self.o.resolve_grant.as_ref().expect("checked");
            let pol = match resolve(s(&rec, "grant_ref"), &pc) {
                Some(g) => self.policy_of(&Operation::new(s(&rec["action"], "verb"), s(&rec["action"], "resource"), json!({})), &g),
                None => UndoPolicy::default(),
            };
            if pol.on_revocation.as_deref().unwrap_or("keep") == "veto" {
                if let VetoResult::Ok { .. } = self.veto(s(&rec, "id"), &VetoBy::Veto(json!({"at": 0, "via": "revocation", "by": grant_ref}))) {
                    out.push(s(&rec, "id").to_string());
                }
            } else {
                self.alert(
                    "warning",
                    "revoked_open_window",
                    s(&rec, "id"),
                    format!("grant {grant_ref} was revoked while this window is open; the principal can still undo it"),
                );
                self.notice("revoked", &rec);
            }
        }
        Ok(out)
    }

    /// Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), and only then roll the
    /// effect back. `params` carries `claimId`. Returns the settlement record and the veto result.
    pub fn rollback_on_slash(&self, bonds: &dyn UndoBondSlasher, params: &Value) -> Result<(Value, VetoResult), String> {
        let settlement = bonds.slash_bond(params)?;
        let evidence = hash_canonical(&json!({"d": "atlas-pca/undo-slash-ref/v1", "settlement": settlement}));
        let claim = s(params, "claimId").to_string();
        let target = match self
            .store
            .list(&UndoQuery { state: "open".into(), bond_ref: Some(claim.clone()), ..Default::default() })
            .map_err(|e| e.message)?
            .into_iter()
            .next()
        {
            Some(t) => Some(t),
            None => self.store.get(&claim).map_err(|e| e.message)?,
        };
        let Some(target) = target else {
            return Ok((settlement, VetoResult::Refused { code: "unknown".into(), reason: format!("no undo record for bond {claim}") }));
        };
        let v = self.veto(s(&target, "id"), &VetoBy::Veto(json!({"at": 0, "via": "fraud_proof", "by": claim, "evidence": evidence})));
        if let VetoResult::Refused { reason, .. } = &v {
            self.alert("critical", "slash_after_window", s(&target, "id"), format!("the bond was slashed but the effect could not be rolled back: {reason}"));
        }
        Ok((settlement, v))
    }
}

/// Report the outcome of the original effect to the ledger: a committed effect is recorded (its result names the compensation target),
/// an effect that failed or never started aborts the window (nothing to undo; held budget released); an unknown outcome leaves the window
/// running (`finalize_due` alerts if it closes without a report).
pub fn report_undo_effect(undo: &UndoCoordinator, id: &str, status: &str, result: Option<&Value>) -> Result<Value, UndoError> {
    match status {
        "committed" => undo.record_effect(id, result),
        "failed" | "aborted" | "refused" => undo.abort(id, &format!("effect_{status}")),
        _ => undo.get(id)?.ok_or_else(|| invalid(format!("no undo record {id}"))),
    }
}

/// An [`UndoNotifier`] over the existing approval channels (Slack, webhook, email, SMS, push). The notice becomes a step-up-shaped
/// message whose link is the one-click undo URL and whose render is the WYSIWYS render of the action.
pub struct DispatcherUndoNotifier {
    dispatcher: Arc<ApprovalDispatcher>,
    undo_url: Arc<dyn Fn(&str, &str) -> String + Send + Sync>,
    inbox_url: Option<String>,
}

/// The reference `undoNotifierFromDispatcher`; `undo_url(token, record id)` builds the one-click link.
pub fn undo_notifier_from_dispatcher(
    dispatcher: Arc<ApprovalDispatcher>,
    undo_url: Arc<dyn Fn(&str, &str) -> String + Send + Sync>,
    inbox_url: Option<String>,
) -> DispatcherUndoNotifier {
    DispatcherUndoNotifier { dispatcher, undo_url, inbox_url }
}

fn iso(ms: i64) -> String {
    // civil-from-days (Howard Hinnant), UTC, millisecond precision: the reference's `new Date(ms).toISOString()`
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
}

impl UndoNotifier for DispatcherUndoNotifier {
    fn notify(&self, n: &UndoNotice) -> UndoNotifyResult {
        let r = &n.record;
        let (verb, resource) = (s(&r["action"], "verb"), s(&r["action"], "resource"));
        let until = iso(i(r, "window_end"));
        let reason = match n.kind {
            "opened" => format!("Already done: {verb} on {resource}. You can undo it until {until}."),
            "vetoed" => format!("Undo started for {verb} on {resource}."),
            "compensated" => format!("Undone: {verb} on {resource}."),
            "compensation_failed" => format!(
                "UNDO FAILED for {verb} on {resource}: {}. An operator has been alerted.",
                r.get("outcome").and_then(|o| o.get("reason")).and_then(Value::as_str).unwrap_or("unknown")
            ),
            "revoked" => format!("The agent's grant was revoked. {verb} on {resource} can still be undone until {until}."),
            _ => format!("Final: {verb} on {resource} can no longer be undone."),
        };
        let mut req = json!({
            "id": format!("undo:{}:{}", s(r, "id"), n.kind), "verb": verb, "resource": resource, "tier": 3, "reason": reason, "goalCommit": "",
            "lineage": {"goalCommit": "", "goalVerified": false, "chain": [{"kind": "action", "label": format!("{verb} {resource}"), "detail": format!("undo: {}", s(&r["compensation"], "verb"))}], "because": reason},
            "r": 0, "requestedAt": i(r, "opened_at")
        });
        if let (Some(render), Some(rd)) = (&n.render, r.get("render_digest")) {
            req["render"] = render.clone();
            req["renderDigest"] = rd.clone();
        }
        let link = match (&n.token, n.kind) {
            (Some(t), "opened") => Some((self.undo_url)(t, s(r, "id"))),
            _ => self.inbox_url.clone(),
        };
        let out = self.dispatcher.notify_all(&req, &NotifyContext { inbox_url: link, now: None });
        if out.iter().any(|d| d.get("delivered") == Some(&json!(true))) {
            return UndoNotifyResult { delivered: true, reason: None };
        }
        let why = out
            .iter()
            .map(|d| format!("{}: {}", s(d, "kind"), d.get("reason").and_then(Value::as_str).unwrap_or("not delivered")))
            .collect::<Vec<_>>()
            .join("; ");
        UndoNotifyResult { delivered: false, reason: Some(if why.is_empty() { "no enabled channel".into() } else { why }) }
    }
}

/// The HTTP transport of [`hosted_undo_veto_relay`]: `(url, method, headers) -> (ok, status, json body)`; an `Err` is a transport failure.
pub type UndoRelayFetch = dyn Fn(&str, &str, &[(String, String)]) -> Result<(bool, u16, Value), String> + Send + Sync;

pub struct HostedUndoVetoRelay {
    base: String,
    secret_key: String,
    fetch: Arc<UndoRelayFetch>,
    limit: i64,
}

/// The relay over a hosted undo ledger: `GET {base_url}/v1/pca/undo/vetoes` with the instance secret key. Pass it as
/// `UndoCoordinatorOptions::relay`. A non-2xx answer or a malformed body is an error (and so finalizes nothing).
pub fn hosted_undo_veto_relay(base_url: &str, secret_key: &str, fetch: Arc<UndoRelayFetch>, limit: Option<i64>) -> HostedUndoVetoRelay {
    HostedUndoVetoRelay {
        base: base_url.trim_end_matches('/').to_string(),
        secret_key: secret_key.to_string(),
        fetch,
        limit: limit.unwrap_or(200).clamp(1, 200),
    }
}

impl UndoVetoRelay for HostedUndoVetoRelay {
    fn pending(&self) -> Result<Vec<UndoRelayedVeto>, UndoError> {
        let url = format!("{}/v1/pca/undo/vetoes?limit={}", self.base, self.limit);
        let headers = vec![("authorization".to_string(), format!("Bearer {}", self.secret_key)), ("accept".to_string(), "application/json".to_string())];
        let (ok, status, body) = (self.fetch)(&url, "GET", &headers).map_err(|e| invalid(format!("the veto relay failed: {e}")))?;
        if !ok {
            return Err(invalid(format!("the veto relay answered {status}")));
        }
        let data = body.get("data").and_then(Value::as_array).ok_or_else(|| invalid("the veto relay answered without a data list"))?;
        let mut out = Vec::new();
        for row in data {
            let (id, token, at) = (
                row.get("record_id").and_then(Value::as_str),
                row.get("veto").and_then(|v| v.get("token")).and_then(Value::as_str),
                row.get("veto").and_then(|v| v.get("at")).and_then(Value::as_f64),
            );
            match (id, token, at) {
                (Some(id), Some(token), Some(at)) => out.push(UndoRelayedVeto { id: id.to_string(), token: json!(token), at: at as i64 }),
                _ => return Err(invalid("the veto relay answered a malformed entry")),
            }
        }
        Ok(out)
    }
}
