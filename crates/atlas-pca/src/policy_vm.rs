//! The Policy VM entry point: [`decide`] turns one action, the grant and its delegation chain, the risk inputs and the trust budget
//! into a release decision, and [`derive_decide_input`] assembles its input from a PCActn plus the resource server's context.
//! [`crate::authorize`] runs the same steps inside its pipeline; this is the standalone function for hosts that decide outside it
//! (the fraud-proof and dispute adjudication, bond settlement, the AuthZEN PDP and an MPC party's local evaluation take it as
//! their injected `decide`).
//!
//! The input is a JSON object with the reference's member names: `grant`, `action` (`{action: {verb, resource, params?,
//! reversibility_class?}, subject?, env?, toolBinding?}`), `chain`?, `plan`?, `nodeId`?, `goalNodeId`?, `risk`, `budget`, `now`,
//! `caveatContext`?, `ageHorizonMs`?, `rFloor`?, `trustedRoot`?, `pqPins`? and `chainVerified`?. The decision is
//! `{releaseGuardianShare, requiredThreshold: {t, proof, optimisticAllowed}, r, admit, needStepUp, reasons, budget, k1Bound?}`.
//! FAILS CLOSED: an unverified chain, a missing envelope or any error is a denial. Total: never panics.

use crate::authorize::envelope_predicates_denial;
use crate::bond_store::num;
use crate::caveat_lang::{evaluate_k1, is_k1_caveat, K1Ctx, K1Input};
use crate::risk::{decide_risk, RiskPolicy, RiskStep, TrustBudget};
use crate::{evaluate_agent_caveats, read_envelope, root_caveats, verify_chain_policy};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The message of the error [`derive_decide_input`] returns without `ctx.grant` (the reference's `DecideInputGrantRequired`,
/// code `grant_required`).
pub const DECIDE_INPUT_GRANT_REQUIRED: &str =
    "deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant";

fn denied(reason: String, budget: Option<Value>) -> Value {
    let mut d = json!({
        "releaseGuardianShare": false,
        "requiredThreshold": {"t": 3, "proof": "strong", "optimisticAllowed": false},
        "r": 1, "admit": false, "needStepUp": true, "reasons": [reason],
    });
    if let Some(b) = budget {
        d["budget"] = b;
    }
    d
}

fn parse_budget(v: &Value) -> Option<TrustBudget> {
    let n = |k: &str| v.get(k).filter(|x| x.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite());
    let as_of = match v.get("asOf") {
        None | Some(Value::Null) => None,
        Some(x) => Some(x.as_f64().filter(|f| f.is_finite() && x.is_number())?),
    };
    Some(TrustBudget { b: n("B")?, tau: n("tau")?, as_of })
}

/// The reversibility class of an action: its own class, else the class of the plan node it is bound to (`node_id`), else none
/// (which no `reversibility_max` caveat accepts and which is not fast-path eligible). With no node named there is never a guess.
pub fn resolve_reversibility_class(action: &Value, plan: Option<&Value>, node_id: Option<&Value>) -> Option<Value> {
    let own = action.get("action").and_then(|a| a.get("reversibility_class")).filter(|v| !v.is_null());
    if let Some(o) = own {
        return Some(o.clone());
    }
    let id = node_id.filter(|n| n.is_string())?;
    plan?.as_array()?.iter().find(|n| n.get("id") == Some(id))?.get("reversibility_class").filter(|v| !v.is_null()).cloned()
}

/// The tool call an action denotes, for `tool_schema` caveats: `{tool, args, toolSignatureDigest?}`.
pub fn tool_call_of(action: &Value) -> Value {
    let a = action.get("action");
    let mut tc = Map::new();
    tc.insert("tool".into(), json!(a.and_then(|a| a.get("verb")).and_then(Value::as_str).unwrap_or("")));
    tc.insert("args".into(), a.and_then(|a| a.get("params")).filter(|p| p.is_object()).cloned().unwrap_or_else(|| json!({})));
    if let Some(Value::String(b)) = action.get("toolBinding") {
        tc.insert("toolSignatureDigest".into(), json!(b));
    }
    Value::Object(tc)
}

/// Decide one action (see the module doc). A chain that carries caveat-language (K1) caveats is refused: use [`decide_with_k1`].
pub fn decide(input: &Value) -> Value {
    decide_with_k1(input, None)
}

/// [`decide`] with the verifier's caveat-language input (pins, discharges, narrow block, SPIFFE ID, history). `max_uses` is spent
/// afterwards by the caller from the decision's `k1Bound`, once everything else allowed.
pub fn decide_with_k1(input: &Value, k1: Option<&K1Input>) -> Value {
    let fallback = input.get("budget").filter(|b| !b.is_null()).cloned().unwrap_or_else(|| json!({"B": 0, "tau": 0}));
    // one regex work budget for the whole decision (envelope predicates and every caveat of every hop)
    match catch_unwind(AssertUnwindSafe(|| crate::safe_regex::with_regex_budget(|| decide_inner(input, k1)))) {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => denied(format!("policy evaluation error (fail closed): {e}"), Some(fallback)),
        Err(_) => denied("policy evaluation error (fail closed): unknown".into(), Some(fallback)),
    }
}

fn decide_inner(input: &Value, k1: Option<&K1Input>) -> Result<Value, String> {
    let inp = input.as_object().ok_or("the decide input is not an object")?;
    let null = Value::Null;
    let grant = inp.get("grant").unwrap_or(&null);
    let action = inp.get("action").unwrap_or(&null);
    let budget_in = inp.get("budget").cloned();
    let env = match read_envelope(grant) {
        Some(e) => e,
        None => return Ok(denied("grant carries no valid envelope".into(), budget_in)),
    };
    let now = match inp.get("now").filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite()) {
        Some(n) => n,
        None => return Ok(denied("invalid decision time".into(), budget_in)),
    };
    let chain = inp.get("chain");
    let hops = chain.and_then(Value::as_array).filter(|c| !c.is_empty());

    // fail closed on an UNVERIFIED capability chain: unless the caller passed the already-verified marker, the chain (or the
    // grant alone) is verified here, rooted at the grant's issuer
    if inp.get("chainVerified") != Some(&Value::Bool(true)) {
        let single = [grant.clone()];
        let to_verify: &[Value] = hops.map_or(&single[..], Vec::as_slice);
        let pins: Option<HashMap<String, String>> = inp
            .get("pqPins")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect());
        if let Err(reason) = verify_chain_policy(to_verify, grant.get("issuer").and_then(Value::as_str), None, pins.as_ref(), inp.get("trustedRoot")) {
            return Ok(denied(format!("capability chain unverified: {reason}"), budget_in));
        }
    }

    let pol = RiskPolicy::from_value(env.get("risk_policy").unwrap_or(&null))?;
    let mut reasons: Vec<String> = Vec::new();

    // 1. semantic predicates (default deny)
    let preds = env.get("predicates").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let pr_ok = match envelope_predicates_denial(preds, action) {
        Some(why) => {
            reasons.push(why);
            false
        }
        None => true,
    };

    // 2. caveats: the envelope's, the root grant's own, and the ones the hops appended
    let risk = inp.get("risk").and_then(Value::as_object).cloned().unwrap_or_default();
    let inner = action.get("action").cloned().unwrap_or(Value::Null);
    let mut c = Map::new();
    c.insert("now".into(), num(now));
    c.insert("action".into(), inner.clone());
    if let Some(b) = risk.get("blastRadius").filter(|v| !v.is_null()) {
        c.insert("blast_radius".into(), b.clone());
    }
    if let Some(r) = resolve_reversibility_class(action, inp.get("plan"), inp.get("nodeId")) {
        c.insert("reversibility_class".into(), r);
    }
    // the caller's caveat context overrides what was derived (a null member is an absent one)
    for (k, v) in inp.get("caveatContext").and_then(Value::as_object).into_iter().flatten() {
        let key = match k.as_str() {
            "blastRadius" => "blast_radius",
            "reversibilityClass" => "reversibility_class",
            "recentActionTimes" => "recent_action_times",
            "delegationDepth" => "delegation_depth",
            other => other,
        };
        if v.is_null() {
            c.remove(key);
        } else {
            c.insert(key.into(), v.clone());
        }
    }
    let own = grant.get("caveats").and_then(Value::as_array).map_or(0, Vec::len);
    let mut chain_ok = true;
    let mut extra: Vec<Value> = Vec::new();
    if chain.is_some() {
        match hops {
            None => {
                chain_ok = false;
                reasons.push("delegation chain is empty or malformed".into());
            }
            Some(h) => {
                c.insert("delegation_depth".into(), json!(h.len() - 1));
                let leaf = h[h.len() - 1].get("caveats").and_then(Value::as_array).ok_or("the leaf capability carries no caveat list")?;
                extra = leaf.iter().skip(own).cloned().collect();
            }
        }
    }
    let rev_class = c.get("reversibility_class").and_then(Value::as_str).map(str::to_string);
    let cctx = Value::Object(c);
    let call = tool_call_of(action);
    let eval = |list: &Value| evaluate_agent_caveats(list, &cctx, Some(action), Some(&call));

    let (ecv_ok, failed) = eval(env.get("caveats").unwrap_or(&null));
    if !ecv_ok {
        reasons.push(format!("caveat(s) not satisfied: {}", failed.join(", ")));
    }
    // the caveat-language types need the chain position, the discharges or a store: they are taken out of the lists the stock
    // evaluator sees and evaluated over the chain (with no K1 input every one of them is unsatisfied)
    let leaf_caveats = hops.map_or(grant, |h| &h[h.len() - 1]).get("caveats").and_then(Value::as_array);
    let use_k1 = leaf_caveats.is_some_and(|cs| cs.iter().any(is_k1_caveat)) || k1.is_some_and(|k| k.narrow.is_some());
    let k1r = use_k1.then(|| evaluate_k1(grant, chain.unwrap_or(&null), k1, &K1Ctx { now: now as i64, action: Some(&inner) }));
    let no_k1 = |v: Value| match v {
        Value::Array(l) => Value::Array(l.into_iter().filter(|c| !is_k1_caveat(c)).collect()),
        o => o,
    };
    let (rcv_ok, failed) = eval(&no_k1(root_caveats(grant)));
    if !rcv_ok {
        reasons.push(format!("root caveat(s) not satisfied: {}", failed.join(", ")));
    }
    let mut delegated: Vec<Value> = extra.into_iter().filter(|c| !is_k1_caveat(c)).collect();
    if let Some(k) = &k1r {
        delegated.extend(k.plain.iter().cloned());
    }
    let (mut dcv_ok, failed) = eval(&Value::Array(delegated));
    if !dcv_ok {
        reasons.push(format!("delegated caveat(s) not satisfied: {}", failed.join(", ")));
    }
    if let Some(k) = k1r.as_ref().filter(|k| !k.ok) {
        dcv_ok = false;
        for (i, r) in k.reasons.iter().enumerate() {
            reasons.push(format!("caveat language: {}: {r}", k.failed.get(i).map_or("<malformed>", String::as_str)));
        }
    }

    // 3-5. risk, the threshold band, the budget admission and the release / admit / debit decision
    let budget = budget_in.as_ref().and_then(parse_budget).ok_or("the trust budget is missing or malformed")?;
    let plan = inp.get("plan").and_then(Value::as_array).map(Vec::as_slice);
    let dec = decide_risk(&RiskStep {
        policy: &pol,
        risk: &risk,
        plan,
        node_id: inp.get("nodeId").and_then(Value::as_str),
        goal_node_id: inp.get("goalNodeId").and_then(Value::as_str),
        budget,
        now,
        // `?? default`: absent or null is the default; any other non-number is NaN (the age term then saturates)
        age_horizon_ms: inp.get("ageHorizonMs").filter(|v| !v.is_null()).map(|v| v.as_f64().unwrap_or(f64::NAN)),
        r_floor: inp.get("rFloor").filter(|v| v.is_number()).and_then(Value::as_f64),
        reversibility_class: rev_class.as_deref(),
        pr_ok,
        cv_ok: ecv_ok && rcv_ok,
        dcv_ok,
        chain_ok,
    });
    reasons.extend(dec.reasons.iter().cloned());
    let rt = dec.required_threshold;
    let b = &dec.budget;
    let mut out = json!({
        "releaseGuardianShare": dec.release_guardian_share,
        "requiredThreshold": {"t": rt.t, "proof": rt.proof_name(), "optimisticAllowed": rt.optimistic_allowed},
        "r": num(dec.r), "admit": dec.admit, "needStepUp": dec.need_step_up, "reasons": reasons,
        "budget": {"B": num(b.b), "tau": num(b.tau), "asOf": num(b.as_of.unwrap_or(b.tau))},
    });
    if let Some(k) = k1r {
        out["k1Bound"] = Value::Array(k.bound.iter().map(|x| json!({"caveat": x.caveat, "hop": x.hop, "capHash": x.cap_hash})).collect());
    }
    Ok(out)
}

fn truthy(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null) | Some(Value::Bool(false))) && v.and_then(Value::as_str) != Some("") && v.and_then(Value::as_f64) != Some(0.0)
}

/// Assemble a decide input from a PCActn plus the resource server's context `ctx` (`{grant, risk, budget, now, plan?, params?,
/// chain?, pqPins?, goalNodeId?, subject?, env?, caveatContext?, ageHorizonMs?}`), so the caller and the verifier derive the
/// action, node and chain identically. `ctx.grant` is REQUIRED: the grant from the verifier's OWN store (also the chain's trusted
/// root); it is never defaulted from the presented chain (`Err(`[`DECIDE_INPUT_GRANT_REQUIRED`]`)`). `ctx.params` must already
/// be checked against `action.params_digest`.
pub fn derive_decide_input(p: &Value, ctx: &Value) -> Result<Value, String> {
    if ctx.is_null() {
        return Err("Cannot read properties of null (reading 'grant')".into());
    }
    let grant = ctx.get("grant").filter(|g| g.is_object() || g.is_array()).ok_or(DECIDE_INPUT_GRANT_REQUIRED)?;
    if p.is_null() && ctx.get("chain").is_none_or(Value::is_null) {
        return Err("Cannot read properties of null (reading 'cap_chain')".into());
    }
    let present = |v: Option<&Value>| v.filter(|x| !x.is_null()).cloned();
    let mut out = Map::new();
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v {
            out.insert(k.into(), v);
        }
    };
    put("grant", Some(grant.clone()));
    // the stored grant authorises a pure-PQ / hybrid root on its own pq_pk, exactly as the core verifier does
    put("trustedRoot", Some(grant.clone()));
    put("pqPins", ctx.get("pqPins").cloned());
    put("chain", present(ctx.get("chain")).or_else(|| p.get("cap_chain").cloned()));
    let a = p.get("action");
    let mut inner = Map::new();
    for k in ["verb", "resource"] {
        if let Some(v) = a.and_then(|a| a.get(k)) {
            inner.insert(k.into(), v.clone());
        }
    }
    inner.insert("params".into(), present(ctx.get("params")).unwrap_or_else(|| json!({})));
    if let Some(v) = a.and_then(|a| a.get("reversibility_class")) {
        inner.insert("reversibility_class".into(), v.clone());
    }
    let mut action = Map::new();
    action.insert("action".into(), Value::Object(inner));
    for k in ["subject", "env"] {
        if truthy(ctx.get(k)) {
            action.insert(k.into(), ctx[k].clone());
        }
    }
    put("action", Some(Value::Object(action)));
    put("plan", ctx.get("plan").cloned());
    put("nodeId", p.get("plan").and_then(|pl| pl.get("node_id")).cloned());
    for (k, from) in [("goalNodeId", "goalNodeId"), ("risk", "risk"), ("budget", "budget"), ("now", "now"), ("caveatContext", "caveatContext"), ("ageHorizonMs", "ageHorizonMs")] {
        put(k, ctx.get(from).cloned());
    }
    Ok(Value::Object(out))
}

/// A party's local Policy-VM evaluation distilled to its decision vector (the only thing that enters a multi-party composition):
/// `allow` = the party releases, `t` = the threshold it demands, `r_quant` = its risk quantized to `{0..q}` (default
/// [`crate::mpc::DEFAULT_Q`]). The party's decide input (its envelope, risk inputs, budget) never leaves its process. Total.
pub fn evaluate_party(decide_input: &Value, q: Option<i64>) -> crate::mpc::DecisionVector {
    let d = decide(decide_input);
    crate::mpc::DecisionVector {
        allow: i64::from(d["releaseGuardianShare"] == Value::Bool(true)),
        t: d["requiredThreshold"]["t"].as_i64().unwrap_or(3),
        r_quant: crate::mpc::quantize_r(d["r"].as_f64().unwrap_or(f64::NAN), q.unwrap_or(crate::mpc::DEFAULT_Q)),
    }
}
