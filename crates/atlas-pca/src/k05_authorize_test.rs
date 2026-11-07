//! k05 differential oracle for the authorize pipeline's 0.5 additions: tests/data/k05-authorize.json.gz, written by the
//! TypeScript reference (tools/pca-audit/k05-oracles/authorize-oracle.mts; every native replays the same file): tool_schema
//! validation and evaluation, the risk policy, the envelope reader and whole `authorize` scenarios (provenance by default,
//! fresh_at escalation, escalation answers, undo admission). A scenario is {grant, config, steps}: a fresh memory store per
//! scenario, single-step plans, a revocation hook per step, and per step the reference's projection (allow, decision, status,
//! the checks it names, the failing ones, the provenance_flow / undo_window / escalation / fresh_at reasons, the escalation
//! request or answer, the undo admission).
use super::*;
use crate::escalation::PinnedSigner;
use crate::k042_support::{k05_run, K05};
use crate::undo::UndoCompensationRef;

const KEY: [&str; 22] = [
    "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature", "counter_format", "fresh_at",
    "attestation", "revocation", "grant_ref", "operation", "params_digest", "delegated_caveats", "policy", "replay", "provenance_flow", "undo_window", "escalation",
];
const OWN: [&str; 4] = ["provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: "];

fn admission(v: &Value) -> Option<UndoAdmission> {
    let c = v.get("compensation")?;
    Some(UndoAdmission {
        id: v.get("id")?.as_str()?.to_string(),
        window_end: v.get("window_end")?.as_i64()?,
        compensation: UndoCompensationRef { verb: c.get("verb")?.as_str()?.to_string(), resource: c.get("resource")?.as_str()?.to_string() },
    })
}

fn scenario(sc: &Value) -> Value {
    let grant = sc["grant"].clone();
    let cfg = &sc["config"];
    let store = MemoryStateStore::new();
    let gid = grant["id"].as_str().unwrap_or("").to_string();
    let g2 = grant.clone();
    let resolve = move |r: &str| Ok::<_, String>((r == gid).then(|| g2.clone()));
    let pins: Vec<Value> = cfg["mediators"].as_array().cloned().unwrap_or_default();
    let facts = cfg.get("actions").cloned();
    let actions = move |op: &Operation| facts.as_ref().and_then(|f| f.get(&op.verb)).cloned();
    let observed = cfg.get("observed").cloned();
    let seen = move |_: &Value, _: &Operation, _: Option<&str>| observed.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
    let fresh = cfg.get("freshAt").map(|f| FreshAtPolicy::from_json(f).expect("freshAt"));
    let undo_cfg = cfg.get("undo").cloned();
    let admit = move |_: &Value, _: &Value, op: &Operation| Ok::<_, String>(undo_cfg.as_ref().and_then(|u| u.get(&op.verb)).and_then(admission));
    let esc = cfg.get("escalation");
    let principals: Vec<PinnedSigner> =
        esc.and_then(|e| e["principals"].as_array()).map(|a| a.iter().filter_map(Value::as_str).map(PinnedSigner::ed25519).collect()).unwrap_or_default();
    let render_digest = esc.and_then(|e| e.get("render_digest")).and_then(Value::as_str).map(String::from);
    let render = move |_: &Value| render_digest.clone();
    let has_render = esc.is_some_and(|e| e.get("render_digest").is_some());
    let insecure = esc.is_some_and(|e| e.get("insecureUnboundApproval") == Some(&Value::Bool(true)));
    let mut out = Vec::new();
    for s in sc["steps"].as_array().cloned().unwrap_or_default() {
        let revoked = s.get("revoked") == Some(&Value::Bool(true));
        let is_revoked = move |_: &Value, _: &Value| Ok::<_, String>(revoked);
        let op = Operation::from_json(&s["operation"]).expect("operation");
        let input = AuthorizeInput {
            operation: Some(&op),
            audience: cfg["audience"].as_str().unwrap_or(""),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&is_revoked),
            now: cfg["now"].as_i64(),
            plan: Some("single-step"),
            fresh_at: fresh.as_ref(),
            escalation_principals: &principals,
            escalation_answer: s.get("escalationAnswer"),
            escalation_render: has_render.then_some(&render as &EscalationRenderFn),
            insecure_unbound_approval: insecure,
            provenance_mediators: &pins,
            provenance_actions: cfg.get("actions").is_some().then_some(&actions as &ProvActionsFn<'_>),
            provenance_observed: cfg.get("observed").is_some().then_some(&seen as &ProvObservedFn<'_>),
            provenance: s.get("provenance").filter(|p| !p.is_null()),
            undo: cfg.get("undo").is_some().then_some(&admit as &UndoAdmitFn<'_>),
            ..Default::default()
        };
        let r = authorize(Some(&s["pcactn"]), &input);
        let mut checks = Map::new();
        // the reference's cap_chain is `chain` here; the reference reports attestation `not-enforced` after counter_format when
        // no verifier is configured, where this crate (no attestation verifier) records the check only when it fails
        let get = |k: &str| match k {
            "cap_chain" => r.checks.get("chain").copied(),
            "attestation" if r.checks.contains_key("counter_format") => Some(r.checks.get(k).copied().unwrap_or(CheckStatus::NotEnforced)),
            _ => r.checks.get(k).copied(),
        };
        for k in KEY {
            if let Some(c) = get(k) {
                checks.insert(k.into(), json!(c.as_str()));
            }
        }
        let failed: Vec<&str> = KEY.iter().copied().filter(|k| get(k) == Some(CheckStatus::Fail)).collect();
        // the K7 reason names this crate's option names; the reference names its own
        let reasons: Vec<String> = r
            .reasons
            .iter()
            .filter(|x| OWN.iter().any(|o| x.starts_with(o)))
            .map(|x| x.replace("(set escalation_render, or insecure_unbound_approval)", "(set escalation.render, or insecureUnboundApproval)"))
            .collect();
        let escalation = match &r.escalation {
            None => Value::Null,
            Some(e) if r.allow => e.clone(),
            Some(_) => json!({"request": true}),
        };
        let undo = r.undo.as_ref().map_or(Value::Null, |u| {
            json!({"id": u.id, "window_end": u.window_end, "compensation": {"verb": u.compensation.verb, "resource": u.compensation.resource}})
        });
        out.push(json!({"allow": r.allow, "decision": r.decision, "status": r.status, "checks": checks, "failed": failed, "reasons": reasons,
            "escalation": escalation, "undo": undo}));
    }
    Value::Array(out)
}

#[test]
fn k05_authorize_matches_the_reference() {
    k05_run("authorize", 12800, |_, f, a| match f {
        "validateArgSchema" => K05::Val(json!(validate_arg_schema(&a[0]))),
        "evaluateToolSchema" => {
            // the reference's camelCase ToolCall members are snake_case here
            let mut call = a[1].clone();
            if let Some(o) = call.as_object_mut() {
                for (js, rs) in [("toolSignature", "tool_signature"), ("toolSignatureDigest", "tool_signature_digest")] {
                    if let Some(v) = o.remove(js) {
                        o.insert(rs.into(), v);
                    }
                }
            }
            let (ok, reason) = evaluate_tool_schema(&a[0], &call);
            let mut o = json!({"ok": ok});
            if let Some(r) = reason {
                o["reason"] = json!(r);
            }
            K05::Val(o)
        }
        "validateRiskPolicy" => K05::Val(json!(risk_policy_error(Some(&a[0])))),
        "readEnvelope" => K05::Val(read_envelope(&a[0]).map_or(Value::Null, Value::Object)),
        "requiresAttestation" => K05::Val(json!(requires_attestation(a.first().filter(|v| !v.is_null())))),
        "authorize" => K05::Val(scenario(&a[0])),
        _ => K05::Skip("fn not in this module"),
    });
}

#[test]
fn arg_schema_refuses_negative_zero() {
    // strict profile: -0 is never a wire integer (a bound, an integer const / enum member)
    let v = |s: &str| validate_arg_schema(&serde_json::from_str(s).unwrap());
    assert_eq!(v(r#"{"props": {"a": {"type": "string", "maxLength": -0}}}"#).as_deref(), Some("a: bad maxLength"));
    assert_eq!(v(r#"{"props": {"a": {"type": "array", "items": {"type": "string"}, "minItems": -0}}}"#).as_deref(), Some("a: bad minItems"));
    assert_eq!(v(r#"{"props": {"a": {"type": "integer", "enum": [-0]}}}"#).as_deref(), Some("a: bad enum"));
    assert_eq!(v(r#"{"props": {"a": {"type": "integer", "const": -0}}}"#).as_deref(), Some("a: bad const"));
    assert_eq!(v(r#"{"props": {"a": {"type": "integer", "enum": [0]}}}"#), None);
}

// ---- direct: small helpers, per server/verify.ts, server/authorize.ts, agent-native.ts, reversibility.ts ----

use crate::agent::{default_risk_policy, max_uses_caveat, mint_grant, Agent, KeyPair, Suite};
use crate::arg_provenance::{principal_direct_provenance, ProvenanceRecorder};
use crate::params_digest;

struct Fixed(bool);
impl StateStore for Fixed {
    fn claim(&self, _: &str, _: u64) -> Result<ClaimResult, StoreError> {
        Ok(if self.0 { ClaimResult::claimed() } else { ClaimResult::replay(None) })
    }
    fn last(&self, _: &str) -> Option<Option<u64>> {
        None
    }
}

#[test]
fn small_formats_and_the_default_consume_once() {
    assert_eq!(StoreError("down".into()).to_string(), "replay store: down");
    assert_eq!(CheckStatus::Pass.to_string(), CheckStatus::Pass.as_str());
    assert_eq!(state_key("g", "h"), "g:h");
    assert_eq!(Fixed(true).consume_once("k", 5, 1), Ok(true));
    assert_eq!(Fixed(false).consume_once("k", 5, 1), Ok(false));
    assert!(system_now() > 1_600_000_000_000);
}

#[test]
fn root_caveats_drops_only_the_first_envelope_object() {
    let g = json!({"caveats": ["x", {"type": "envelope"}, {"type": "rate"}, {"type": "envelope"}]});
    assert_eq!(root_caveats(&g), json!(["x", {"type": "rate"}, {"type": "envelope"}]));
    assert_eq!(root_caveats(&json!({"caveats": ["x"]})), json!(["x"]));
    // an earlier object caveat of another type stays: only the envelope one goes
    assert_eq!(root_caveats(&json!({"caveats": [{"type": "rate"}, {"type": "envelope"}]})), json!([{"type": "rate"}]));
}

#[test]
fn schema_scalars_compare_like_javascript_triple_equals() {
    assert!(js_eq(&json!(1), &json!(1.0)));
    assert!(!js_eq(&json!(1), &json!(2)));
    assert!(!js_eq(&json!(1), &json!("1")));
    assert!(!js_eq(&json!("1"), &json!(1)));
    assert!(!js_eq(&json!(true), &json!(1)));
    assert!(js_eq(&json!(true), &json!(true)));
    assert!(js_eq(&json!("a"), &json!("a")));
}

#[test]
fn a_bad_bound_is_refused_for_number_and_integer_alike() {
    for t in ["number", "integer"] {
        let s = json!({"props": {"a": {"type": t, "min": "x"}}});
        assert_eq!(validate_arg_schema(&s).as_deref(), Some("a: bad min"), "{t}");
    }
}

#[test]
fn schema_node_budget_is_256() {
    let empty = json!({});
    let mut at_limit = MAX_SCHEMA_NODES - 1;
    assert_eq!(object_schema_error(Some(&empty), None, 1, &mut at_limit), None);
    let mut over = MAX_SCHEMA_NODES;
    assert_eq!(object_schema_error(Some(&empty), None, 1, &mut over).as_deref(), Some("schema too large"));
}

fn string_spec() -> Value {
    json!({"type": "string"})
}

fn spec_map(v: &Value) -> &Map<String, Value> {
    v.as_object().unwrap()
}

#[test]
fn value_budgets_stop_at_the_reference_limits() {
    // agent-native.ts: depth > MAX_SCHEMA_DEPTH + 1, ++n > MAX_VALUE_NODES
    let (spec, v) = (string_spec(), json!("x"));
    let check = |depth: usize, start: usize| {
        let mut n = start;
        check_value(spec_map(&spec), &v, "a", depth, &mut n)
    };
    assert_eq!(check(MAX_SCHEMA_DEPTH + 1, 0), None);
    assert_eq!(check(MAX_SCHEMA_DEPTH + 2, 0).as_deref(), Some("a: too deep"));
    assert_eq!(check(1, MAX_VALUE_NODES - 1), None);
    assert_eq!(check(1, MAX_VALUE_NODES).as_deref(), Some("a: too many values"));
    assert_eq!(MAX_VALUE_NODES, 10_000);
}

#[test]
fn nesting_counts_towards_the_depth_limit() {
    let run = |spec: &Value, v: &Value| {
        let mut n = 0;
        check_value(spec_map(spec), v, "a", 1, &mut n)
    };
    let list_spec = |d: usize| (0..d).fold(string_spec(), |s, _| json!({"type": "array", "items": s}));
    let list_val = |d: usize| (0..d).fold(json!("x"), |v, _| json!([v]));
    assert_eq!(run(&list_spec(8), &list_val(8)), None);
    assert_eq!(run(&list_spec(9), &list_val(9)), Some(format!("a{}: too deep", "[0]".repeat(9))));
    let obj_spec = |d: usize| (0..d).fold(string_spec(), |s, _| json!({"type": "object", "props": {"k": s}}));
    let obj_val = |d: usize| (0..d).fold(json!("x"), |v, _| json!({ "k": v }));
    assert_eq!(run(&obj_spec(8), &obj_val(8)), None);
    assert_eq!(run(&obj_spec(9), &obj_val(9)), Some(format!("a{}: too deep", ".k".repeat(9))));
}

#[test]
fn an_agent_caveat_needs_an_object_context_and_an_empty_list_needs_nothing() {
    let cv = json!({"type": "predicates", "allow": [{"verb": "v"}]});
    let action = json!({"action": {"verb": "v", "resource": "r"}});
    assert!(agent_caveat_satisfied(&cv, &json!({}), &action, &json!({})));
    assert!(!agent_caveat_satisfied(&cv, &Value::Null, &action, &json!({})));
    assert_eq!(evaluate_agent_caveats(&json!([]), &Value::Null, None, None), (true, vec![]));
    assert_eq!(evaluate_agent_caveats(&json!([cv]), &Value::Null, Some(&action), None), (false, vec!["<evaluation error>".to_string()]));
}

#[test]
fn an_operation_needs_a_verb_a_resource_and_object_params() {
    assert!(Operation::new("v", "r", json!({})).is_valid());
    assert!(!Operation::new("", "r", json!({})).is_valid());
    assert!(!Operation::new("v", "", json!({})).is_valid());
    assert!(!Operation::new("v", "r", json!([])).is_valid());
}

#[test]
fn the_decisive_reason_is_operation_then_plan_state_then_list_order() {
    let checks = |list: &[(&str, CheckStatus)], reasons: &[&str]| Checks {
        list: list.iter().map(|(n, s)| (n.to_string(), *s)).collect(),
        reasons: reasons.iter().map(|r| r.to_string()).collect(),
        unsupported_refused: false,
    };
    use CheckStatus::{Fail, Pass};
    let all = ["zeta: z", "plan_state: p", "operation: o", "fine: f"];
    let c = checks(&[("zeta", Fail), ("plan_state", Fail), ("operation", Fail), ("fine", Pass)], &all);
    assert_eq!(c.decisive(), "operation: o");
    let c = checks(&[("zeta", Fail), ("plan_state", Fail), ("operation", Pass), ("fine", Pass)], &all);
    assert_eq!(c.decisive(), "plan_state: p");
    let c = checks(&[("zeta", Pass), ("plan_state", Pass), ("operation", Pass), ("fine", Fail)], &all);
    assert_eq!(c.decisive(), "fine: f");
    // a failing check with no reason of its own falls through; none at all is the first reason
    let c = checks(&[("zeta", Fail)], &["other: x"]);
    assert_eq!(c.decisive(), "other: x");
    assert_eq!(checks(&[], &[]).decisive(), "denied");
}

#[test]
fn class_ranks_are_the_reference_table() {
    for (c, want) in [(json!("reversible"), 0), (json!("rate_limited"), 1), (json!("costly"), 1), (json!("irreversible"), 2), (json!("other"), 2), (json!(5), 2)] {
        assert_eq!(class_rank(Some(&c)), want, "{c}");
    }
    assert_eq!(class_rank(None), 2);
}

#[test]
fn a_plan_node_needs_a_verb_and_a_resource() {
    assert!(known_plan_root(&json!([{"id": "a", "verb": "v", "resource": "r"}])).is_some());
    assert!(known_plan_root(&json!([{"id": "a", "verb": "v"}])).is_none());
    assert!(known_plan_root(&json!([{"id": "a", "resource": "r"}])).is_none());
}

#[test]
fn only_a_set_member_of_the_v2_env_is_taken() {
    let mut rest = Map::new();
    rest.insert("host".into(), json!(1));
    let env = json!({"acc": {"a": 1}, "world": null});
    insert_set_members(&mut rest, env.as_object().unwrap().clone());
    assert_eq!(Value::Object(rest), json!({"host": 1, "acc": {"a": 1}}));
}

#[test]
fn root_k1_caveats_leave_the_stock_evaluator_only_when_k1_runs() {
    let env = json!({"predicates": [{"verb": "v"}], "caveats": []});
    let action = json!({"action": {"verb": "v", "resource": "r"}});
    let cctx = json!({"now": 1, "action": {"verb": "v", "resource": "r"}});
    let step = |grant: Value, k1: bool| policy_step(env.as_object(), &grant, &cctx, &action, &json!({}), k1);
    let sealed = json!({"caveats": [{"type": "envelope"}, {"type": "sealed"}]});
    assert_eq!(step(sealed.clone(), true), Vec::<String>::new());
    assert_eq!(step(sealed, false), vec!["root caveat(s) not satisfied: sealed".to_string()]);
    let bogus = json!({"caveats": [{"type": "envelope"}, {"type": "bogus"}]});
    assert_eq!(step(bogus, true), vec!["root caveat(s) not satisfied: bogus".to_string()]);
}

#[test]
fn the_options_expose_their_plans_and_revocation_hook() {
    let opts = |revoked: bool| AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), move |_: &Value, _: &Value| Ok::<_, String>(revoked));
    assert_eq!(opts(true).revoked(&json!({}), &json!({})), Ok(true));
    assert_eq!(opts(false).revoked(&json!({}), &json!({})), Ok(false));
    assert!(opts(false).plans().is_none());
    let reg = Arc::new(PlanRegistry::new());
    let o = opts(false).with_plans(reg.clone());
    assert!(std::ptr::eq(o.plans().unwrap(), &*reg));
}

// ---- before the core checks: what is refused, and with which reason ----

fn early(presented: Result<Option<&Value>, &str>, resolved: Result<Option<Value>, String>, context: Result<Option<Value>, String>) -> AuthorizeResult {
    let op = Operation::new("v", "r", json!({}));
    let resolve = |_: &str| resolved.clone();
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let provider = |_: &Value| context.clone();
    let store = MemoryStateStore::new();
    let input = AuthorizeInput { operation: Some(&op), audience: "aud", resolve_grant: Some(&resolve), state_store: Some(&store), is_revoked: Some(&revoked), context: Some(&provider), ..Default::default() };
    match presented {
        Ok(p) => authorize(p, &input),
        Err(text) => authorize_json(text, &input),
    }
}

#[test]
fn an_artifact_is_read_only_within_the_size_cap_and_only_as_an_object() {
    const UNDECODABLE: &str = "undecodable PCActn: could not be decoded";
    const NO_REF: &str = "malformed: grant_ref is not a string";
    let text = |t: &str| early(Err(t), Ok(None), Ok(None));
    let padded = |n: usize| format!("{{{}}}", " ".repeat(n - 2));
    assert_eq!(text("{}").reason.as_deref(), Some(NO_REF));
    assert_eq!(text(&padded(MAX_ARTIFACT_BYTES)).reason.as_deref(), Some(NO_REF));
    assert_eq!(text(&padded(MAX_ARTIFACT_BYTES + 1)).reason.as_deref(), Some(UNDECODABLE));
    assert_eq!(text("5").reason.as_deref(), Some(UNDECODABLE));
    assert_eq!(text("{").reason.as_deref(), Some(UNDECODABLE));
    let none = early(Ok(None), Ok(None), Ok(None));
    assert_eq!((none.status, none.reason.as_deref()), (401, Some("wire: no PCActn presented")));
    assert_eq!(early(Ok(Some(&json!(5))), Ok(None), Ok(None)).reason.as_deref(), Some(UNDECODABLE));
}

#[test]
fn an_unknown_grant_and_a_failing_resolver_are_told_apart() {
    let p = json!({"grant_ref": "g"});
    const UNKNOWN: &str = "grant_ref: does not resolve to a known grant";
    for resolved in [Ok(None), Ok(Some(json!(5)))] {
        let r = early(Ok(Some(&p)), resolved, Ok(None));
        assert_eq!((r.status, r.reason.as_deref()), (401, Some(UNKNOWN)));
    }
    let r = early(Ok(Some(&p)), Err("down".into()), Ok(None));
    assert_eq!((r.status, r.reason.as_deref()), (403, Some("resolve_grant: grant resolution failed (fail closed)")));
}

#[test]
fn a_context_that_is_not_an_object_and_a_failing_one_are_told_apart() {
    let p = json!({"grant_ref": "g"});
    let run = |context| early(Ok(Some(&p)), Ok(Some(json!({}))), context);
    assert_eq!(run(Ok(Some(json!(5)))).reason.as_deref(), Some("context: the context callback must return a dict (fail closed)"));
    assert_eq!(run(Err("down".into())).reason.as_deref(), Some("context: the context callback failed (fail closed)"));
}

// ---- the whole pipeline over a real signed action ----

const NOW: i64 = 1_700_000_000_000;

fn fixed_now() -> i64 {
    NOW
}

#[derive(Default)]
struct Scene<'a> {
    envelope: Option<Value>,
    context: Option<Value>,
    /// the class the agent declares (default `reversible`)
    declared: Option<&'a str>,
    /// caveats of one delegation hop
    hop: Option<Value>,
    k1: Option<&'a K1Input>,
    uses: Option<&'a dyn StateStore>,
    /// the K1 caveat added to the resolved grant, and an empty presented chain
    no_chain: bool,
}

fn run_scene(s: Scene<'_>) -> AuthorizeResult {
    let d = Suite::default();
    let (principal, holder) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let mut envelope = json!({"predicates": [{"verb": "v", "resource": "r"}], "caveats": [], "risk_policy": default_risk_policy()});
    if let Some(patch) = &s.envelope {
        for (k, x) in patch.as_object().unwrap() {
            envelope[k.as_str()] = x.clone();
        }
    }
    let params = json!({});
    let grant = mint_grant(&principal, &holder.public, &envelope, "goal", None, None, &d).unwrap().grant;
    let mut agent = Agent::new(holder, grant.clone(), "aud", 0);
    agent.clock = fixed_now;
    if let Some(c) = s.declared {
        agent.use_plan(vec![json!({"id": "n1", "verb": "v", "resource": "r", "params_digest": params_digest(Some(&params)), "reversibility_class": c})]);
    }
    let action = match &s.hop {
        Some(cs) => agent.delegate(KeyPair::from_seed(&[3u8; 32]), cs, &d).unwrap().act("v", "r", Some(&params), Map::new(), &d),
        None => agent.act("v", "r", Some(&params), Map::new(), &d),
    }
    .unwrap();
    let mut pcactn = action.pcactn;
    let mut resolved = grant;
    if s.no_chain {
        pcactn["cap_chain"] = json!([]);
        resolved["caveats"].as_array_mut().unwrap().push(json!({"type": "sealed"}));
    }
    let op = Operation::new("v", "r", params);
    let mut rec = ProvenanceRecorder::new("conformance-harness", "k1", Some([1u8; 32])).unwrap();
    let bundle = principal_direct_provenance(&mut rec, &op).unwrap();
    let pins = vec![rec.pin()];
    let resolve = |_: &str| Ok::<_, String>(Some(resolved.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let context = |_: &Value| Ok::<_, String>(s.context.clone());
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: "aud",
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&revoked),
        now: Some(NOW),
        plan: Some(SINGLE_STEP),
        context: Some(&context),
        k1: s.k1,
        uses_store: s.uses,
        provenance_mediators: &pins,
        provenance: Some(&bundle),
        ..Default::default()
    };
    authorize(Some(&pcactn), &input)
}

fn reads(field: &str, value: Value) -> Value {
    json!({"predicates": [{"verb": "v", "resource": "r", "where": [{"field": field, "op": "eq", "value": value}]}]})
}

#[test]
fn a_plain_action_is_allowed_and_bound_to_its_operation() {
    let mut r = run_scene(Scene::default());
    assert!(r.allow, "{r:?}");
    let good = Operation::new("v", "r", json!({}));
    assert!(is_authorized_for(&r, &good));
    assert!(!is_authorized_for(&r, &Operation::new("x", "r", json!({}))));
    assert!(!is_authorized_for(&r, &Operation::new("v", "x", json!({}))));
    assert!(!is_authorized_for(&r, &Operation::new("v", "r", json!({"a": 1}))));
    assert!(!is_authorized_for(&r, &Operation::new("", "", json!({}))));
    r.allow = false;
    assert!(!is_authorized_for(&r, &good));
}

#[test]
fn the_authoritative_class_can_only_be_tightened() {
    // reversibility.ts ranks; verify.ts: declared below the server's fails, the higher rank is effective, a tie is the server's
    for (declared, server, effective) in [
        ("reversible", "reversible", "reversible"),
        ("irreversible", "reversible", "irreversible"),
        ("costly", "rate_limited", "rate_limited"),
        ("rate_limited", "costly", "costly"),
        ("irreversible", "irreversible", "irreversible"),
    ] {
        let r = run_scene(Scene { envelope: Some(reads("action.reversibility_class", json!(effective))), context: Some(json!({ "reversibility_class": server })), declared: Some(declared), ..Default::default() });
        assert!(r.allow, "{declared} {server}: {r:?}");
        assert_eq!(r.check("reversibility"), Some(CheckStatus::Pass));
    }
    for (declared, server) in [("reversible", "costly"), ("reversible", "rate_limited"), ("costly", "irreversible"), ("reversible", "other")] {
        let r = run_scene(Scene { context: Some(json!({ "reversibility_class": server })), declared: Some(declared), ..Default::default() });
        assert!(!r.allow, "{declared} {server}");
        assert_eq!(r.check("reversibility"), Some(CheckStatus::Fail));
    }
}

#[test]
fn with_no_server_class_the_declared_one_is_effective_and_a_null_one_is_unknown() {
    let r = run_scene(Scene { envelope: Some(reads("action.reversibility_class", json!("costly"))), declared: Some("costly"), ..Default::default() });
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("reversibility"), None);
    let r = run_scene(Scene { context: Some(json!({"reversibility_class": null})), ..Default::default() });
    assert_eq!(r.check("reversibility"), Some(CheckStatus::Fail));
    assert!(r.reasons.iter().any(|x| x.contains("declared class 'reversible' is less restrictive than the authoritative 'null'")), "{r:?}");
}

#[test]
fn the_context_feeds_the_predicates_and_the_caveats() {
    let r = run_scene(Scene { envelope: Some(reads("subject.a", json!(1))), context: Some(json!({"subject": {"a": 1}})), ..Default::default() });
    assert!(r.allow, "{r:?}");
    let caveat = |c: Value| Some(json!({ "caveats": [c] }));
    let r = run_scene(Scene { envelope: caveat(json!({"type": "max_blast_radius", "max": 10})), context: Some(json!({"blast_radius": 5})), ..Default::default() });
    assert!(r.allow, "{r:?}");
    let r = run_scene(Scene { envelope: caveat(json!({"type": "rate", "max": 1, "per_secs": 60})), context: Some(json!({"recent_action_times": []})), ..Default::default() });
    assert!(r.allow, "{r:?}");
}

#[test]
fn a_k1_caveat_without_k1_input_is_refused_by_the_caveat_language() {
    let r = run_scene(Scene { hop: Some(json!([max_uses_caveat("m", 1, NOW + 1000)])), ..Default::default() });
    assert_eq!(r.check("delegated_caveats"), Some(CheckStatus::Fail));
    assert!(r.reasons.iter().any(|x| x.contains("the caveat language is not configured")), "{r:?}");
}

#[test]
fn a_max_uses_hop_is_admitted_by_k1_and_needs_a_uses_store() {
    let (k1, uses) = (K1Input::default(), MemoryStateStore::new());
    let hop = || Some(json!([max_uses_caveat("m", 1, NOW + 1000)]));
    let r = run_scene(Scene { hop: hop(), k1: Some(&k1), uses: Some(&uses), ..Default::default() });
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("delegated_caveats"), Some(CheckStatus::Pass));
    let r = run_scene(Scene { hop: hop(), k1: Some(&k1), ..Default::default() });
    assert!(!r.allow);
    assert_eq!(r.check("max_uses"), Some(CheckStatus::Fail));
}

#[test]
fn a_grant_level_k1_failure_counts_when_no_hop_is_presented() {
    let r = run_scene(Scene { no_chain: true, ..Default::default() });
    assert_eq!(r.check("delegated_caveats"), Some(CheckStatus::Fail));
}

#[test]
fn a_legacy_polarity_pass_is_reported_as_degraded() {
    let mut envelope = reads("env.judge.x", json!(1));
    envelope["model_polarity"] = json!("legacy");
    let r = run_scene(Scene { envelope: Some(envelope), context: Some(json!({"env": {"judge": {"x": 1}}})), ..Default::default() });
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("tighten"), Some(CheckStatus::Pass));
    assert_eq!(r.degraded.get("tighten").map(String::as_str), Some(LEGACY_POLARITY_DEGRADED));
    assert!(r.assurance.get("tighten").is_some_and(|e| e.degraded), "{r:?}");
    // tighten passes with no legacy polarity: nothing is degraded
    let r = run_scene(Scene { envelope: Some(json!({"tighten": []})), ..Default::default() });
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("tighten"), Some(CheckStatus::Pass));
    assert!(r.degraded.is_empty());
    assert!(!r.assurance.get("tighten").is_some_and(|e| e.degraded), "{r:?}");
}
