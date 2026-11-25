//! [`verify_pcactn_verdict`]: the stateless resource-server verifier that answers with the FULL verdict (the reference's `verifyPCActn`).
//!
//! One call returns `allow`, the recomputed risk `r`, the `requiredThreshold`, every check with its status (`pass` / `fail` /
//! `not-enforced` / `unsupported`), the reasons in order, the budget after the decision (when it allows or escalates) and, when asked, the
//! per-check assurance report. Unlike [`crate::authorize`] it holds no state: no state store, no grant resolver, and the operation is
//! optional (without it there is no `operation` check; with it, its params replace `context.params`). It never panics and never throws:
//! an internal error is a fail-closed verdict (`malformed: fail`, `r` 1, the worst threshold).
//!
//! It is a thin layer over the pieces [`crate::authorize`] already composes: the signature / chain / plan / counter / intent checks are the
//! core verifier's, the release decision is [`crate::policy_vm::decide_with_k1`], the assurance report and requirement are
//! [`crate::assurance`], the revocation epoch is [`crate::staleness::check_revocation_epoch`] and the beacon is [`crate::beacon`]. Only the
//! fold of those results into one verdict lives here.
//!
//! The options are JSON with the reference's member names (every one optional except `grant`): `grant` (the verifier's OWN stored grant),
//! `now`, `audience` (a string; an explicit `null` accepts any audience; absent fails closed), `insecureSkipPlanRootCheck`, `context`
//! (`params`, `subject`, `env`, `plan`, `planAuthorized`, `reversibilityClass`, `risk`, `budget`, `recentActionTimes`, `revocationEpoch`,
//! `beacon`), `require`, `allowedSuites`, `pqPins`, `operation`, `requireRiskInputs`, `assurance`, `requireAssurance`, `allowUnsupported`,
//! `intent`, `intentV2`, `freshAt`, `k1` and `enforce.freshness`. The callbacks (`hooks.attestation` / `threshold` / `revocation` / `zk`,
//! `enforce.attestation`, `enforce.taint`) are in [`VerdictHooks`]. There is NO `allowUnboundPq`: a PQ key is never read from the artifact.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Map, Value};

use crate::assurance::{assurance_report, refresh_assurance, unmet_assurance, AssuranceHooks, AssuranceRequirement, AssuranceSources, HookDecl};
use crate::authorize::{class_rank, known_plan_root, needs_model_rules, requires_attestation, v2_env, CheckStatus};
use crate::caveat_lang::{discharge_action_digest, evaluate_k1, is_k1_caveat, DischargePin, K1Ctx, K1Input};
use crate::fresh_at::FreshAtPolicy;
use crate::intent_v2::{js_number_string, js_value_string};
use crate::policy_vm::{decide_with_k1, resolve_reversibility_class, tool_call_of};
use crate::staleness::{check_revocation_epoch, EpochCheckOptions};
use crate::taint::TaintGate;
use crate::{
    core_verdict, decide_intent_v2, evaluate_agent_caveats, freshness_gate_check, hash_canonical_strict, read_envelope, strict_parse, FreshnessGate, IntentPolicy,
    IntentV2Context, VerifyOptions, MAX_ARTIFACT_BYTES, PCACTN_WIRE_VERSION,
};

/// The minimum enforcement profile of a stateless resource server.
pub const DEFAULT_REQUIRED_CHECKS: [&str; 6] = ["counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"];

/// A verifier hook (the reference's `hooks.attestation` / `threshold` / `revocation` / `zk`): it receives the PCActn, the grant and the
/// verifier clock and answers `{enforced, ok?, reason?, t?}`. An `Err` is a hook that threw; a JSON `null` answer is the reference's
/// `malformed` (a hook that answers nothing); any other non-object answer is "not enforced".
pub type VerdictHook<'a> = &'a dyn Fn(&Value, &Value, i64) -> Result<Value, String>;

/// `enforce.attestation`: the attestation verifier that takes the `attestation` slot, and whether a not-enforced answer fails (default true).
#[derive(Clone, Copy, Default)]
pub struct AttestationGate<'a> {
    pub verifier: Option<VerdictHook<'a>>,
    pub required: Option<bool>,
}

/// The callbacks of [`verify_pcactn_verdict`].
#[derive(Clone, Copy, Default)]
pub struct VerdictHooks<'a> {
    pub attestation: Option<VerdictHook<'a>>,
    pub threshold: Option<VerdictHook<'a>>,
    pub revocation: Option<VerdictHook<'a>>,
    pub zk: Option<VerdictHook<'a>>,
    /// `enforce.attestation` (its verifier takes the place of `attestation`).
    pub attestation_gate: Option<AttestationGate<'a>>,
    /// `enforce.taint`.
    pub taint: Option<&'a TaintGate>,
    /// What each configured hook declares about its own evidence (an unlabelled hook is reported `unknown` in the assurance report).
    pub labels: Option<&'a AssuranceHooks>,
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
/// The order in which the reference's core can fail (its single reason is the first failure in this order).
const RANK: [(&str, u8); 19] = [
    ("wire", 0),
    ("version", 1),
    ("audience", 2),
    ("validity", 3),
    ("cap_chain", 4),
    ("grant_ref_bound", 5),
    ("plan_inclusion", 6),
    ("plan_root_authorized", 7),
    ("leaf_signature", 8),
    ("counter_format", 9),
    ("intent", 10),
    ("fresh_at", 12),
    ("taint_gate", 13),
    ("freshness", 14),
    ("attestation", 15),
    ("threshold", 16),
    ("revocation", 17),
    ("zk_compliance", 18),
    ("malformed", 19),
];
const CORE_ORDER: [&str; 19] = [
    "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "intent", "schema",
    "intent_session", "layers", "accumulators", "map", "facts", "provenance", "classes", "fresh_at",
];

type Ck = BTreeMap<String, CheckStatus>;

fn worst() -> Value {
    json!({"t": 3, "proof": "strong", "optimisticAllowed": false})
}

fn checks_json(ck: &Ck) -> Value {
    Value::Object(ck.iter().map(|(n, s)| (n.clone(), json!(s.as_str()))).collect())
}

fn statuses(ck: &Ck) -> Vec<(String, CheckStatus)> {
    ck.iter().map(|(n, s)| (n.clone(), *s)).collect()
}

fn fail_closed(reason: String, checks: &[(&str, CheckStatus)]) -> Value {
    let mut ck: Ck = checks.iter().map(|(n, s)| (n.to_string(), *s)).collect();
    ck.insert("malformed".into(), CheckStatus::Fail);
    json!({"allow": false, "r": 1, "requiredThreshold": worst(), "checks": checks_json(&ck), "reasons": [reason]})
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

fn nn<'a>(v: Option<&'a Value>) -> Option<&'a Value> {
    v.filter(|x| !x.is_null())
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

/// `String(v)` where an absent member is `undefined`.
fn js_u(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

fn rank(reason: &str) -> u8 {
    match reason.find(':') {
        None => 99,
        Some(c) => RANK.iter().find(|(n, _)| *n == &reason[..c]).map_or(11, |(_, r)| *r), // the Intent v2 checks sit between intent and fresh_at
    }
}

fn hash_of(v: &Value) -> Option<String> {
    hash_canonical_strict(v)
}

/// The reference's text for a reason of this crate's core (its check names and a few texts differ).
fn text(r: &str, p: &Value, allowed: Option<&[String]>) -> String {
    if r == "version: unsupported ver" {
        return format!("version: unsupported ver {} (this verifier requires {PCACTN_WIRE_VERSION})", js_u(p.get("ver")));
    }
    if let Some(rest) = r.strip_prefix("chain: ") {
        return format!("cap_chain: {rest}");
    }
    if r == "leaf_signature: signature does not verify under the leaf holder key" {
        let alg = p.get("alg").map_or_else(|| "ed25519".to_string(), js_value_string);
        if allowed.is_some_and(|a| !a.iter().any(|x| *x == alg)) {
            return format!("leaf_signature: signature suite '{alg}' is not allowed by this verifier's suite policy");
        }
        return format!("{r} / suite");
    }
    r.to_string()
}

enum Stage {
    NotEnforced,
    Pass(Option<Value>),
    Fail(String, Option<Value>),
    Thrown(String),
}

/// Runs one hook the way the reference's core does: a throw or a null answer ends the stages, anything else is read as
/// `{enforced, ok, reason, t}`.
fn run_stage(h: Option<VerdictHook<'_>>, p: &Value, grant: &Value, now: i64) -> Stage {
    let Some(h) = h else { return Stage::NotEnforced };
    let r = match catch_unwind(AssertUnwindSafe(|| h(p, grant, now))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Stage::Thrown(e),
        Err(e) => return Stage::Thrown(crate::taint::panic_message(e.as_ref())),
    };
    let Value::Object(m) = &r else {
        return if r.is_null() { Stage::Thrown("Cannot read properties of null (reading 'enforced')".into()) } else { Stage::NotEnforced };
    };
    if !m.get("enforced").is_some_and(truthy) {
        return Stage::NotEnforced;
    }
    let t = m.get("t").cloned();
    if m.get("ok").is_some_and(truthy) {
        Stage::Pass(t)
    } else {
        let why = match m.get("reason") {
            None | Some(Value::Null) => "rejected".to_string(),
            Some(x) => js_value_string(x),
        };
        Stage::Fail(why, t)
    }
}

/// Records one completed hook stage; returns the `t` an enforced hook reported.
fn apply(name: &str, s: Stage, ck: &mut Ck, cand: &mut Vec<String>, thrown: &mut Option<String>) -> Option<Value> {
    match s {
        Stage::NotEnforced => {
            ck.insert(name.into(), CheckStatus::NotEnforced);
            None
        }
        Stage::Pass(t) => {
            ck.insert(name.into(), CheckStatus::Pass);
            t
        }
        Stage::Fail(why, t) => {
            ck.insert(name.into(), CheckStatus::Fail);
            cand.push(format!("{name}: {why}"));
            t
        }
        Stage::Thrown(msg) => {
            *thrown = Some(msg);
            None
        }
    }
}

fn parse_k1(v: &Value) -> K1Input {
    let list = |k: &str| v.get(k).and_then(Value::as_array);
    K1Input {
        pins: list("pins").map(|a| a.iter().filter_map(DischargePin::from_json).collect()).unwrap_or_default(),
        discharges: list("discharges").cloned().unwrap_or_default(),
        narrow: v.get("narrow").cloned(),
        action_digest: None,
        revoked_discharges: list("revoked_discharges")
            .or_else(|| list("revokedDischarges"))
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
        spiffe_id: v.get("spiffe_id").or_else(|| v.get("spiffeId")).and_then(Value::as_str).map(String::from),
        history: list("history").cloned(),
    }
}

fn wants_assurance(opts: &Value) -> bool {
    opts.get("assurance") == Some(&Value::Bool(true)) || nn(opts.get("requireAssurance")).is_some()
}

fn system_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// The full verdict of the reference's `verifyPCActn` over a PCActn (a JSON object, or its wire text as a JSON string). See the module doc.
pub fn verify_pcactn_verdict(pcactn: &Value, opts: &Value, hooks: &VerdictHooks<'_>) -> Value {
    let mut v = match catch_unwind(AssertUnwindSafe(|| run(pcactn, opts, hooks))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => fail_closed(format!("verifier error (fail closed): {e}"), &[]),
        Err(e) => fail_closed(format!("verifier error (fail closed): {}", crate::taint::panic_message(e.as_ref())), &[]),
    };
    // a verdict that stopped before the checks ran (undecodable, wire, verifier error) still reports its outcomes when asked
    if wants_assurance(opts) && v.get("assurance").is_none() {
        let ck: Vec<(String, CheckStatus)> = v["checks"]
            .as_object()
            .map(|m| m.iter().filter_map(|(n, s)| Some((n.clone(), CheckStatus::parse(s.as_str()?)?))).collect())
            .unwrap_or_default();
        v["assurance"] = assurance_report(&AssuranceSources { checks: &ck, pcactn: None, hooks: None, attestation_hook: None, threshold_t: None, allow_unbound_pq: false, degraded: &[] }).to_json();
    }
    v
}

/// Default-deny: every required check must be `pass`; one that is not turns the verdict to a deny and (unless already `fail`) is recorded as
/// `fail` with its reason. `counter` is the old name of `replay` (with a store) or `counter_format`.
fn enforce(allow: &mut bool, ck: &mut Ck, reasons: &mut Vec<String>, required: &[String]) {
    for name in required {
        let name = if name == "counter" && !ck.contains_key("counter") {
            if ck.contains_key("replay") { "replay" } else { "counter_format" }
        } else {
            name.as_str()
        };
        let st = ck.get(name).copied();
        if st == Some(CheckStatus::Pass) {
            continue;
        }
        *allow = false;
        if st == Some(CheckStatus::Fail) {
            continue;
        }
        let shown = st.map_or("absent", |s| s.as_str());
        reasons.push(format!("{name}: required check is {shown} (default-deny: not enforced by this resource server)"));
        ck.insert(name.to_string(), CheckStatus::Fail);
    }
}

fn run(pcactn: &Value, opts: &Value, hooks: &VerdictHooks<'_>) -> Result<Value, String> {
    // ---- decode
    let p: Value = match pcactn {
        Value::String(t) => {
            let parsed = if t.len() > MAX_ARTIFACT_BYTES { Err("artifact too large".to_string()) } else { strict_parse(t) };
            match parsed {
                Ok(v) if v.is_object() => v,
                Ok(_) => return Ok(fail_closed("undecodable PCActn: decodePCActn: not an object".into(), &[])),
                Err(e) => return Ok(fail_closed(format!("undecodable PCActn: {e}"), &[])),
            }
        }
        v => v.clone(),
    };
    if matches!(p, Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) {
        return Ok(fail_closed("PCActn is not an object".into(), &[]));
    }
    // `Number.isFinite(opts.now ?? Date.now())` does not coerce: a string, a marker for NaN or an infinity, any non-number is refused
    // before anything else is read
    if nn(opts.get("now")).is_some_and(|n| !(n.is_number() && n.as_f64().is_some_and(f64::is_finite))) {
        return Ok(fail_closed("the verifier clock is not a finite time".into(), &[]));
    }

    // ---- the options
    let o = |k: &str| nn(opts.get(k));
    let grant = match o("grant") {
        Some(g) if g.is_object() && g.get("caveats").is_some_and(Value::is_array) => g,
        _ => return Err("the grant is not a capability".into()),
    };
    let now_raw: Value = o("now").cloned().unwrap_or_else(|| json!(system_now()));
    let now_f = num(Some(&now_raw));
    let now_ok = now_f.is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE);
    let now_int: i64 = if now_ok { now_f.unwrap_or(0.0) as i64 } else { 0 };
    let now_float = now_f.unwrap_or(f64::NAN);
    let now_cav: Value = match now_f {
        Some(f) if f.fract() == 0.0 && f.abs() < 9.0e15 => json!(f as i64),
        _ => now_raw.clone(),
    };
    let empty = Map::new();
    let ctx_orig = o("context").and_then(Value::as_object).unwrap_or(&empty);
    let op = o("operation").filter(|v| truthy(v));
    let op_o = op.and_then(Value::as_object).unwrap_or(&empty);
    let mut ctx = ctx_orig.clone();
    if let Some(prm) = nn(op_o.get("params")) {
        ctx.insert("params".into(), prm.clone());
    }
    let enf = o("enforce");
    let att_gate = hooks.attestation_gate;
    let att_hook = att_gate.and_then(|g| g.verifier).or(hooks.attestation);

    // ---- the Intent v2 context (the grant's model rules need the plaintext params and the host env even without a v2 policy)
    let env = read_envelope(grant);
    let needs = needs_model_rules(grant);
    let v2_in = o("intentV2");
    let v2: Option<IntentV2Context> = if v2_in.is_some_and(truthy) || needs {
        let mut m = v2_in.and_then(Value::as_object).cloned().unwrap_or_default();
        for k in ["params", "env"] {
            if nn(m.get(k)).is_none() {
                if let Some(x) = nn(ctx.get(k)) {
                    m.insert(k.into(), x.clone());
                }
            }
        }
        IntentV2Context::from_json(&Value::Object(m))
    } else {
        None
    };
    let v2d = (p.get("intent_session").is_some() || needs).then(|| decide_intent_v2(&p, grant, v2.as_ref(), now_int));

    // ---- the core checks. The audience is decided here (a string, an explicit null that accepts any, or absent); the core is handed an
    // audience that cannot disagree unless a string was supplied.
    let p_aud = p.get("aud").and_then(Value::as_str);
    let has_aud = p_aud.is_some_and(|a| !a.is_empty());
    let aud_arg: String = match opts.get("audience") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => p_aud.unwrap_or("").to_string(),
        Some(_) => "\u{0}not-a-string-audience".to_string(),
    };
    let allowed: Option<Vec<String>> = o("allowedSuites").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
    let intent_policy = o("intent").and_then(IntentPolicy::from_json);
    let fresh_at = o("freshAt").and_then(FreshAtPolicy::from_json);
    let vo = VerifyOptions {
        allowed: allowed.as_deref(),
        intent: intent_policy.as_ref(),
        intent_v2: v2.as_ref(),
        authorized_plan_roots: None,
        insecure_skip_plan_root_check: true,
        freshness_gate: None,
        pq_pins: None,
    };
    let core = core_verdict(&p, grant, now_int, &aud_arg, &vo, fresh_at.as_ref(), false);
    if core.checks.get("wire") == Some(&false) {
        let r = if core.reason.is_empty() { "wire: malformed PCActn".to_string() } else { core.reason.clone() };
        return Ok(fail_closed(r, &[("wire", CheckStatus::Fail)]));
    }

    // ---- the core's verdict in the reference's vocabulary
    let st = |ok: bool| if ok { CheckStatus::Pass } else { CheckStatus::Fail };
    let mut ck: Ck = Ck::new();
    for name in CORE_ORDER {
        if let Some(ok) = core.checks.get(name) {
            ck.insert((if name == "chain" { "cap_chain" } else { name }).to_string(), st(*ok));
            if name == "plan_inclusion" {
                ck.insert("plan_root_authorized".into(), CheckStatus::NotEnforced);
            }
        }
    }
    for (name, ok) in &core.checks {
        if !CORE_ORDER.contains(&name.as_str()) {
            ck.insert(name.clone(), st(*ok));
        }
    }
    let mut cand: Vec<String> = Vec::new();
    if !core.allow && !core.reason.is_empty() {
        cand.push(text(&core.reason, &p, allowed.as_deref()));
    }
    match opts.get("audience") {
        Some(Value::Null) => {
            ck.insert("audience".into(), CheckStatus::NotEnforced);
        }
        None => {
            if has_aud {
                ck.insert("audience".into(), CheckStatus::Fail);
                cand.push("audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)".into());
            } else {
                ck.insert("audience".into(), CheckStatus::NotEnforced);
            }
        }
        Some(_) => {}
    }
    if !now_ok {
        ck.insert("validity".into(), CheckStatus::Fail);
        cand.retain(|r| !r.starts_with("validity: "));
        cand.push("validity: the verifier clock is not a safe integer epoch-ms".into());
    }

    // the opt-in taint gate (M1)
    match hooks.taint {
        None => {
            ck.insert("taint_gate".into(), CheckStatus::NotEnforced);
        }
        Some(g) => match catch_unwind(AssertUnwindSafe(|| crate::taint::taint_gate_check(p.get("provenance").unwrap_or(&Value::Null), g))) {
            Ok(Ok(())) => {
                ck.insert("taint_gate".into(), CheckStatus::Pass);
            }
            Ok(Err(why)) => {
                ck.insert("taint_gate".into(), CheckStatus::Fail);
                cand.push(format!("taint_gate: {why}"));
            }
            Err(e) => {
                ck.insert("taint_gate".into(), CheckStatus::Fail);
                cand.push(format!("taint_gate: taint gate error (fail closed): {}", crate::taint::panic_message(e.as_ref())));
            }
        },
    }
    // the freshness gate (M3)
    if let Some(fr) = nn(enf.and_then(|e| e.get("freshness"))) {
        let g = FreshnessGate {
            max_age_ms: num(fr.get("maxAgeMs")).unwrap_or(f64::NAN),
            epoch_ms: num(fr.get("epochMs")),
            now: num(fr.get("now")),
            clock_skew_ms: num(fr.get("clockSkewMs")),
        };
        match freshness_gate_check(p.as_object().unwrap_or(&empty), &g, now_int) {
            Ok(()) => {
                ck.insert("freshness".into(), CheckStatus::Pass);
            }
            Err(why) => {
                ck.insert("freshness".into(), CheckStatus::Fail);
                cand.push(format!("freshness: {why}"));
            }
        }
    }

    // ---- the hook stages, in the reference's order; a hook that throws (or answers null) ends the stages after it with `malformed`
    let mut thrown: Option<String> = None;
    let mut hook_t: Option<Value> = None;
    apply("attestation", run_stage(att_hook, &p, grant, now_int), &mut ck, &mut cand, &mut thrown);
    if thrown.is_none() {
        if let Some(g) = att_gate {
            if matches!(ck.get("attestation"), None | Some(CheckStatus::NotEnforced)) && g.required != Some(false) {
                ck.insert("attestation".into(), CheckStatus::Fail);
                cand.push("attestation: attestation required but the verifier reported not-enforced / no document (fail closed)".into());
            }
        }
        hook_t = apply("threshold", run_stage(hooks.threshold, &p, grant, now_int), &mut ck, &mut cand, &mut thrown);
    }
    if thrown.is_none() {
        apply("revocation", run_stage(hooks.revocation, &p, grant, now_int), &mut ck, &mut cand, &mut thrown);
    }
    if thrown.is_none() && p.get("zk_compliance").is_some() {
        match run_stage(hooks.zk, &p, grant, now_int) {
            Stage::Pass(_) => {
                ck.insert("zk_compliance".into(), CheckStatus::Pass);
            }
            Stage::Fail(why, _) => {
                ck.insert("zk_compliance".into(), CheckStatus::Fail);
                cand.push(format!("zk_compliance: {why}"));
            }
            Stage::NotEnforced => {
                ck.insert("zk_compliance".into(), CheckStatus::Fail);
                cand.push(format!("zk_compliance: {}", crate::ZK_UNVERIFIED));
            }
            Stage::Thrown(msg) => thrown = Some(msg),
        }
    }
    if let Some(msg) = &thrown {
        // the stage that threw and every stage after it are not reported: they are never run or marked above
        ck.insert("malformed".into(), CheckStatus::Fail);
        cand.push(format!("malformed: PCActn: {msg}"));
    }
    let mut unsupported: Vec<&str> = Vec::new();
    if p.get("bond_ref").is_some() && thrown.is_none() {
        ck.insert("bond".into(), CheckStatus::NotEnforced); // reported `unsupported` in the final verdict only (the reference's proved fold)
        unsupported.push("bond");
    }

    // the core's single reason: its first failure in the reference's own order
    let mut first: Option<&String> = None;
    for c in &cand {
        if first.is_none_or(|f| rank(c) < rank(f)) {
            first = Some(c);
        }
    }
    let first = first.map(|f| match f.strip_prefix("malformed: PCActn: ") {
        Some(rest) => format!("malformed PCActn: {rest}"),
        None => f.clone(),
    });
    let core_allow = !ck.values().any(|s| *s == CheckStatus::Fail);
    let mut reasons: Vec<String> = if !core_allow { first.into_iter().collect() } else { Vec::new() };
    if let Some(d) = &v2d {
        let v2r: Vec<crate::decision::V2CheckResult> = d
            .checks
            .iter()
            .map(|c| crate::decision::V2CheckResult { name: c.name.to_string(), ok: c.ok, reason: if c.ok { None } else { Some(c.reason.clone()) } })
            .collect();
        reasons = crate::decision::fold_v2_reasons(&reasons, &v2r);
    }
    macro_rules! fail {
        ($name:expr, $why:expr) => {{
            let why: String = $why;
            ck.insert($name.to_string(), CheckStatus::Fail);
            reasons.push(format!("{}: {}", $name, why));
        }};
    }

    // ---- the server-side PQ pin
    let pq_pins = o("pqPins");
    if let Some(pins) = pq_pins {
        let alg = grant.get("alg").map_or_else(|| "ed25519".to_string(), js_value_string);
        let issuer = grant.get("issuer").and_then(Value::as_str);
        let pin = issuer.and_then(|i| pins.get(i));
        let has = issuer.is_some_and(|i| pins.get(i).is_some());
        if alg == "ed25519" {
            if has {
                fail!("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused".to_string());
            } else {
                ck.insert("pq_pin".into(), CheckStatus::Pass);
            }
        } else if pin.and_then(Value::as_str).zip(grant.get("pq_pk").and_then(Value::as_str)).is_some_and(|(a, b)| a == b) {
            ck.insert("pq_pin".into(), CheckStatus::Pass);
        } else {
            let why = if pin.is_none() {
                format!("no server-side PQ pin for the grant issuer (suite {alg})")
            } else {
                "the grant pq_pk does not match the server-side pin".to_string()
            };
            fail!("pq_pin", why);
        }
    }

    // ---- grant_ref and the operation
    if p.get("grant_ref") == grant.get("id") {
        ck.insert("grant_ref".into(), CheckStatus::Pass);
    } else {
        fail!("grant_ref", "does not reference the supplied grant".to_string());
    }
    let action = p.get("action").and_then(Value::as_object).unwrap_or(&empty);
    let digest = action.get("params_digest").and_then(Value::as_str);
    if op.is_some() {
        let (op_verb, op_res) = (op_o.get("verb").and_then(Value::as_str), op_o.get("resource").and_then(Value::as_str));
        let op_params = nn(op_o.get("params"));
        let signed = format!("{} on {}", js_u(action.get("verb")), js_u(action.get("resource")));
        match (op_verb, op_res) {
            (Some(v), Some(r)) => {
                if action.get("verb").and_then(Value::as_str) != Some(v) || action.get("resource").and_then(Value::as_str) != Some(r) {
                    fail!("operation", format!("the proof is for {signed}, but this operation is {v} on {r}"));
                } else if op_params.is_some_and(|x| hash_of(x).as_deref() != digest) {
                    fail!("operation", format!("the proof's params_digest does not match the params of this {v} operation"));
                } else if op_params.is_some_and(|x| ctx_orig.contains_key("params") && ctx_orig.get("params").and_then(hash_of) != hash_of(x)) {
                    fail!("operation", "context.params differ from the operation params".to_string());
                } else {
                    ck.insert("operation".into(), CheckStatus::Pass);
                }
            }
            _ => fail!("operation", "the server operation has no verb / resource (fail closed)".to_string()),
        }
    }
    if let Some(prm) = ctx.get("params") {
        if hash_of(prm).as_deref() == digest {
            ck.insert("params_digest".into(), CheckStatus::Pass);
        } else {
            fail!("params_digest", "supplied params do not hash to action.params_digest".to_string());
        }
    } else {
        ck.insert("params_digest".into(), CheckStatus::NotEnforced);
    }

    // ---- the server's own copy of the plan
    let plan_v = ctx.get("plan");
    let plan_supplied = plan_v.is_some_and(truthy);
    let mut plan_nodes: Option<Value> = None;
    let mut root_matches = false;
    if plan_supplied {
        let nodes = plan_v.cloned().unwrap_or(Value::Null);
        let arr = nodes.as_array().ok_or("ctx.plan.map is not a function")?;
        if arr.iter().any(|n| !n.is_object()) {
            return Err("plan node is not an object".into());
        }
        root_matches = known_plan_root(&nodes).is_some_and(|r| p.get("plan").and_then(|pl| pl.get("root")).and_then(Value::as_str) == Some(r.as_str()));
        plan_nodes = Some(nodes);
    }
    let authorized = ctx.get("planAuthorized").and_then(Value::as_bool);
    let pd = if !plan_supplied {
        "not-enforced"
    } else if !root_matches {
        "mismatch"
    } else {
        match authorized {
            Some(true) => "pass",
            Some(false) => "unauthorized",
            None => "not-enforced",
        }
    };
    match pd {
        "mismatch" => fail!("plan_root_authorized", "known plan does not match plan.root".to_string()),
        "unauthorized" => fail!("plan_root_authorized", "the plan root has not been authorized by the principal".to_string()),
        "pass" => {
            ck.insert("plan_root_authorized".into(), CheckStatus::Pass);
        }
        _ if opts.get("insecureSkipPlanRootCheck") == Some(&Value::Bool(true)) => {
            ck.insert("plan_root_authorized".into(), CheckStatus::NotEnforced);
        }
        _ => fail!(
            "plan_root_authorized",
            "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)".to_string()
        ),
    }

    // ---- the guardian-signed revocation epoch
    if let Some(re) = ctx.get("revocationEpoch").filter(|v| truthy(v)) {
        let epoch = re.get("epoch").unwrap_or(&Value::Null);
        let r = match re.get("guardianPublic").and_then(Value::as_str) {
            None => Err("revocation epoch not signed by the pinned guardian".to_string()),
            Some(g) => check_revocation_epoch(
                epoch,
                &EpochCheckOptions {
                    guardian_public: g,
                    now: now_float,
                    grant_ref: grant.get("id").and_then(Value::as_str),
                    last_accepted_epoch: num(re.get("lastAcceptedEpoch")),
                    pcactn_epoch: num(p.get("freshness").and_then(|f| f.get("epoch"))),
                    max_age_ms: num(re.get("maxAgeMs")),
                    pq_pin: None,
                },
            ),
        };
        match r {
            Ok(()) => {
                if ck.get("freshness") != Some(&CheckStatus::Fail) {
                    ck.insert("freshness".into(), CheckStatus::Pass);
                }
            }
            Err(why) => fail!("freshness", why),
        }
    } else {
        ck.entry("freshness".into()).or_insert(CheckStatus::NotEnforced);
    }

    // ---- the dead-man liveness beacon
    let bc = ctx.get("beacon").filter(|v| truthy(v));
    let (mut br, mut replayed, mut ref_binds): (Result<(), String>, bool, bool) = (Ok(()), false, false);
    if let Some(bc) = bc {
        let b_obj = bc.get("beacon").unwrap_or(&Value::Null);
        let issuers: Vec<String> = bc.get("issuers").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let pins = bc.get("pqPins").and_then(Value::as_object);
        br = crate::beacon::verify_liveness_beacon(b_obj, &issuers, now_int, bc.get("instance").and_then(Value::as_str).unwrap_or(""), grant.get("id").and_then(Value::as_str), pins);
        let (last, seq) = (num(bc.get("lastAcceptedSeq")), num(b_obj.get("seq")));
        replayed = br.is_ok() && matches!((last, seq), (Some(l), Some(s)) if s < l);
        ref_binds = br.is_ok()
            && !replayed
            && p.get("freshness").and_then(|f| f.get("beacon_ref")).and_then(Value::as_str).is_some_and(|r| Some(r) == crate::beacon::beacon_ref(b_obj).as_deref());
    }
    match crate::beacon::beacon_decision(bc.is_some(), br.is_ok(), replayed, ref_binds) {
        "rejected" => fail!("beacon", br.clone().err().unwrap_or_else(|| "beacon rejected".into())),
        "replayed" => {
            let seq = num(bc.and_then(|b| b.get("beacon")).and_then(|b| b.get("seq"))).unwrap_or(f64::NAN);
            let last = num(bc.and_then(|b| b.get("lastAcceptedSeq"))).unwrap_or(f64::NAN);
            fail!("beacon", format!("beacon seq {} is older than the last accepted {} (replay)", js_number_string(seq), js_number_string(last)));
        }
        "unbound" => fail!("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon".to_string()),
        "pass" => {
            ck.insert("beacon".into(), CheckStatus::Pass);
        }
        _ => {
            ck.insert("beacon".into(), CheckStatus::NotEnforced);
        }
    }

    // ---- require-when-bound: a grant that binds the agent REQUIRES a passing attestation
    if requires_attestation(env.as_ref().and_then(|e| e.get("agent_binding"))) && ck.get("attestation") != Some(&CheckStatus::Pass) {
        fail!("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED".to_string());
    }

    // ---- budget (an absent one fails closed to B = 0) and the risk inputs
    let has_budget = ctx.contains_key("budget");
    let ctx_budget = ctx.get("budget").cloned().unwrap_or(Value::Null);
    ck.insert("budget".into(), if truthy(&ctx_budget) { CheckStatus::Pass } else { CheckStatus::NotEnforced });
    if !has_budget {
        reasons.push("budget: no budget supplied \u{2014} fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge".into());
    }
    let budget_in = if ctx_budget.is_null() { json!({"B": 0, "tau": now_raw, "asOf": now_raw}) } else { ctx_budget.clone() };
    let risk: Map<String, Value> = ctx.get("risk").and_then(Value::as_object).cloned().unwrap_or_default();
    if let Some(req) = o("requireRiskInputs").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        let supplied = |k: &str| num(risk.get(k)).is_some_and(f64::is_finite) || (k == "semanticDistance" && ctx.contains_key("plan"));
        let missing: Vec<String> = req.iter().map(js_value_string).filter(|k| !supplied(k.as_str())).collect();
        if missing.is_empty() {
            ck.insert("risk_inputs".into(), CheckStatus::Pass);
        } else {
            fail!("risk_inputs", format!("required risk input(s) not supplied by the server: {}", missing.join(", ")));
        }
    }

    // ---- reversibility: the server's class wins; the agent may only be stricter
    let declared = action.get("reversibility_class");
    let mut reversibility: Option<Value> = declared.cloned();
    if let Some(sc) = ctx.get("reversibilityClass") {
        let (dr, sr) = (class_rank(declared), class_rank(Some(sc)));
        if dr < sr {
            fail!("reversibility", format!("declared class '{}' is less restrictive than the authoritative '{}'", js_u(declared), js_value_string(sc)));
        } else {
            ck.insert("reversibility".into(), CheckStatus::Pass);
        }
        reversibility = if dr > sr { declared.cloned() } else { Some(sc.clone()) };
    }

    // ---- the Policy VM
    let mut inner = Map::new();
    inner.insert("verb".into(), action.get("verb").cloned().unwrap_or(Value::Null));
    inner.insert("resource".into(), action.get("resource").cloned().unwrap_or(Value::Null));
    if let Some(prm) = nn(ctx.get("params")) {
        inner.insert("params".into(), prm.clone());
    }
    if let Some(r) = nn(reversibility.as_ref()) {
        inner.insert("reversibility_class".into(), r.clone());
    }
    let inner = Value::Object(inner);
    let mut actx = Map::new();
    actx.insert("action".into(), inner.clone());
    if let Some(s) = nn(ctx.get("subject")) {
        actx.insert("subject".into(), s.clone());
    }
    if let Some(e) = v2_env(&p, grant, v2.as_ref(), now_int, ctx.get("env")) {
        actx.insert("env".into(), e);
    }
    if let Some(Value::String(b)) = p.get("tool_binding") {
        actx.insert("toolBinding".into(), Value::String(b.clone()));
    }
    let action_ctx = Value::Object(actx);
    let chain: &[Value] = p.get("cap_chain").and_then(Value::as_array).map_or(&[], Vec::as_slice);
    let depth = chain.len().saturating_sub(1);
    let recent = nn(ctx.get("recentActionTimes"));
    let mut cav_ctx = Map::new();
    cav_ctx.insert("delegationDepth".into(), json!(depth));
    if let Some(r) = recent {
        cav_ctx.insert("recentActionTimes".into(), r.clone());
    }
    let plan_o = p.get("plan").and_then(Value::as_object).unwrap_or(&empty);
    let k1_in = o("k1");
    let digest_p = discharge_action_digest(&p);
    let k1_full: Option<K1Input> = k1_in.map(|k| K1Input { action_digest: digest_p.clone(), ..parse_k1(k) });
    let k1_decide: Option<K1Input> = k1_full.clone().map(|k| K1Input { narrow: None, ..k });
    let mut din = Map::new();
    din.insert("grant".into(), grant.clone());
    din.insert("trustedRoot".into(), grant.clone());
    if let Some(pins) = pq_pins {
        din.insert("pqPins".into(), if pins.is_object() { pins.clone() } else { json!({}) });
    }
    din.insert("action".into(), action_ctx.clone());
    if let Some(n) = &plan_nodes {
        din.insert("plan".into(), n.clone());
    }
    if let Some(n) = plan_o.get("node_id") {
        din.insert("nodeId".into(), n.clone());
    }
    din.insert("risk".into(), Value::Object(risk.clone()));
    let mut budget_decide = budget_in.clone();
    if !has_budget {
        if let Some(m) = budget_decide.as_object_mut() {
            m.insert("B".into(), json!(0));
        }
    }
    din.insert("budget".into(), budget_decide);
    din.insert("now".into(), now_raw.clone());
    din.insert("caveatContext".into(), Value::Object(cav_ctx));
    if let Some(c) = p.get("caution").filter(|c| c.is_number()) {
        din.insert("rFloor".into(), c.clone());
    }
    let d = decide_with_k1(&Value::Object(din), k1_decide.as_ref());

    // caveats added by delegation hops are conjunctive too
    if let Some(leaf) = chain.last() {
        let leaf_cavs = leaf.get("caveats").and_then(Value::as_array).ok_or("leaf.caveats.slice is not a function")?;
        let gcs = grant.get("caveats").and_then(Value::as_array).map_or(0, Vec::len);
        let extra: Vec<Value> = leaf_cavs.get(gcs..).unwrap_or(&[]).to_vec();
        let use_k1 = k1_full.as_ref().is_some_and(|k| k.narrow.is_some()) || leaf_cavs.iter().any(is_k1_caveat);
        let k1r = use_k1.then(|| evaluate_k1(grant, p.get("cap_chain").unwrap_or(&Value::Null), k1_full.as_ref(), &K1Ctx { now: now_int, action: Some(&inner) }));
        let mut cctx = Map::new();
        cctx.insert("now".into(), now_cav.clone());
        cctx.insert("action".into(), inner.clone());
        cctx.insert("delegation_depth".into(), json!(depth));
        if let Some(b) = nn(risk.get("blastRadius")) {
            cctx.insert("blast_radius".into(), b.clone());
        }
        if let Some(rc) = resolve_reversibility_class(&action_ctx, plan_nodes.as_ref(), plan_o.get("node_id")) {
            cctx.insert("reversibility_class".into(), rc);
        }
        if let Some(r) = recent {
            cctx.insert("recent_action_times".into(), r.clone());
        }
        let mut list: Vec<Value> = extra.into_iter().filter(|c| !is_k1_caveat(c)).collect();
        if let Some(k) = &k1r {
            list.extend(k.plain.iter().cloned());
        }
        let (cv_ok, cv_failed) = evaluate_agent_caveats(&Value::Array(list), &Value::Object(cctx), Some(&action_ctx), Some(&tool_call_of(&action_ctx)));
        let k1_ok = k1r.as_ref().is_none_or(|k| k.ok);
        if cv_ok && k1_ok {
            ck.insert("delegated_caveats".into(), CheckStatus::Pass);
        } else {
            let mut failed = cv_failed;
            let mut why = String::new();
            if let Some(k) = k1r.as_ref() {
                failed.extend(k.failed.iter().cloned());
                if !k.ok {
                    why = format!(" ({})", k.reasons.join("; "));
                }
            }
            fail!("delegated_caveats", format!("delegation caveat(s) not satisfied: {}{why}", failed.join(", ")));
        }
    }

    // ---- policy and threshold
    let release = d["releaseGuardianShare"] == Value::Bool(true);
    ck.insert("policy".into(), if release { CheckStatus::Pass } else { CheckStatus::Fail });
    for x in d["reasons"].as_array().into_iter().flatten() {
        reasons.push(format!("policy: {}", js_value_string(x)));
    }
    let t_req = d["requiredThreshold"]["t"].as_f64().unwrap_or(3.0);
    let t_show = js_number_string(t_req);
    let proof = d["requiredThreshold"]["proof"].as_str().unwrap_or("strong").to_string();
    let th = ck.get("threshold").copied();
    let hf = num(hook_t.as_ref());
    let hook_ti = hf.filter(|f| !f.is_nan()).map(|f| f.clamp(-MAX_SAFE, MAX_SAFE).floor());
    if t_req > 1.0 && release && th == Some(CheckStatus::Pass) && !hook_ti.is_some_and(|h| h >= t_req) {
        let said = hook_t.as_ref().map_or_else(|| "unreported".to_string(), js_value_string);
        fail!(
            "threshold",
            format!("threshold hook enforced t={said} but the server requires t={t_show} (below the server-derived threshold; derive t from server-held data)")
        );
    } else if t_req > 1.0 && release && th != Some(CheckStatus::Pass) {
        let why = if th == Some(CheckStatus::Fail) {
            format!("t={t_show} required and the threshold proof was rejected")
        } else {
            format!("t={t_show} ({proof}) required but no threshold verifier is enforced")
        };
        fail!("threshold", why);
    }

    // ---- assurance
    let required: Vec<String> = match o("require") {
        None => DEFAULT_REQUIRED_CHECKS.iter().map(|s| s.to_string()).collect(),
        Some(Value::Array(a)) => a.iter().map(js_value_string).collect(),
        Some(_) => return Err("required.map is not a function".into()),
    };
    let req_a = o("requireAssurance");
    let want_assurance = wants_assurance(opts);
    let labels = hooks.labels.cloned().unwrap_or_default();
    let decl = |present: bool, label: &Option<HookDecl>| present.then(|| label.clone().unwrap_or(HookDecl::Unlabelled));
    let ah = AssuranceHooks {
        attestation: decl(hooks.attestation.is_some(), &labels.attestation),
        zk: decl(hooks.zk.is_some(), &labels.zk),
        threshold: decl(hooks.threshold.is_some(), &labels.threshold),
        revocation: decl(hooks.revocation.is_some(), &labels.revocation),
    };
    let att_decl = decl(att_hook.is_some(), &labels.attestation);
    let degraded: Vec<(String, String)> = if v2d.as_ref().is_some_and(|d| d.legacy_model_polarity) {
        vec![("tighten".to_string(), "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)".to_string())]
    } else {
        Vec::new()
    };
    let report = |cs: &Ck| {
        let list = statuses(cs);
        assurance_report(&AssuranceSources { checks: &list, pcactn: Some(&p), hooks: Some(&ah), attestation_hook: att_decl.as_ref(), threshold_t: hf, allow_unbound_pq: false, degraded: &degraded })
    };
    if let Some(ra) = req_a.filter(|v| truthy(v)) {
        // an unknown key or value (a `threshold` that is not a list included) is refused by `unmet_assurance`, fail closed
        let unmet = unmet_assurance(&report(&ck), &AssuranceRequirement::from_json(ra));
        match unmet {
            None => {
                ck.insert("assurance".into(), CheckStatus::Pass);
            }
            Some(u) => {
                ck.insert("assurance".into(), CheckStatus::Fail);
                reasons.push(u); // the requirement's own text, already prefixed
            }
        }
    }

    let mut allow = !ck.values().any(|s| *s == CheckStatus::Fail) && release && core_allow;
    let mut fin = ck.clone();
    for n in &unsupported {
        if fin.get(*n) == Some(&CheckStatus::NotEnforced) {
            fin.insert(n.to_string(), CheckStatus::Unsupported);
        }
    }
    let fin0 = fin.clone();
    let budget_out = truthy(&ctx_budget).then(|| json!({"B": d["budget"]["B"], "tau": d["budget"]["tau"], "asOf": d["budget"].get("asOf").cloned().unwrap_or(Value::Null)}));
    let allow_unsupported: Vec<&str> = o("allowUnsupported").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let refused: Vec<&str> = unsupported.iter().copied().filter(|n| !allow_unsupported.contains(n)).collect();
    let mut out = json!({"allow": false, "r": d["r"], "requiredThreshold": d["requiredThreshold"]});
    if !refused.is_empty() {
        let mut rs = reasons;
        rs.extend(refused.iter().map(|n| format!("{n}: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)")));
        enforce(&mut allow, &mut fin, &mut rs, &required);
        out["allow"] = json!(false);
        out["checks"] = checks_json(&fin);
        out["reasons"] = json!(rs);
        if want_assurance {
            let mut a = report(&fin0);
            refresh_assurance(&mut a, &statuses(&fin));
            out["assurance"] = a.to_json();
        }
        return Ok(out);
    }
    // the post-decision budget rides on a core-allowed verdict BEFORE the required-check enforcement can flip it to a denial (the
    // reference builds the verdict first and enforces afterwards), so a verdict refused only for a required check still reports it
    let core_allowed = allow;
    enforce(&mut allow, &mut fin, &mut reasons, &required);
    out["allow"] = json!(allow);
    if core_allowed {
        if let Some(b) = &budget_out {
            out["budget"] = b.clone();
        }
    }
    out["checks"] = checks_json(&fin);
    // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
    if !allow && truthy(&ctx_budget) {
        out["reasons"] = json!(reasons);
        if crate::decision::decision_of(&out) == "escalate" {
            out["budget"] = json!({"B": d["budget"]["B"], "tau": d["budget"]["tau"], "asOf": d["budget"].get("asOf").cloned().unwrap_or(Value::Null)});
        }
    }
    if !allow && reasons.is_empty() {
        reasons = vec!["denied".to_string()];
    }
    out["reasons"] = json!(reasons);
    if want_assurance {
        let mut a = report(&fin0);
        refresh_assurance(&mut a, &statuses(&fin));
        out["assurance"] = a.to_json();
    }
    Ok(out)
}
