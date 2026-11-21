//! Fraud proofs and one-shot dispute adjudication for bonded optimistic claims. [`verify_fraud_proof`] RE-RUNS the Policy VM on the
//! server-held frozen open-time snapshot under the grant the verifier trusts, and [`adjudicate_dispute`] re-adjudicates with an objective
//! oracle's authoritative value substituted for the single disputed input; [`adjudicate_dispute_game`] narrows two committed traces by
//! refereed bisection to one contested step and rules on that step alone. A slash is never authorized by a challenger's assertion.
//!
//! The Policy VM is supplied by the caller as a [`DecideFn`] (`decide(input) -> {releaseGuardianShare, r, requiredThreshold:
//! {optimisticAllowed, t}, reasons}`); with none supplied every function fails CLOSED. All functions are total (they never panic).

use crate::immune::to_fixed;
use crate::intent_v2::js_number_string;
use serde_json::{json, Map, Value};

pub const DEFAULT_R_MARGIN: f64 = 1e-9;
const INPUTS: [&str; 4] = ["reversibility_class", "reversibility", "blastRadius", "semanticDistance"];
const IRREVERSIBLE_CLASS: &str = "irreversible";

/// The Policy VM: `decide(input)` for a decide input (the frozen snapshot plus the trusted grant).
pub type DecideFn<'a> = &'a dyn Fn(&Value) -> Result<Value, String>;
/// The objective oracle: `resolve(input, snapshot)` returns `{input, value?, class?, valid, reason?}`.
pub type OracleFn<'a> = &'a dyn Fn(&str, &Value) -> Result<Value, String>;

fn fin(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}

fn margin_of(r_margin: Option<f64>) -> f64 {
    r_margin.filter(|m| m.is_finite()).map_or(DEFAULT_R_MARGIN, |m| m.max(0.0))
}

fn with_grant(snap: &Value, grant: &Value) -> Value {
    let mut m = snap.as_object().cloned().unwrap_or_default();
    m.insert("grant".into(), grant.clone());
    Value::Object(m)
}

fn run_decide(decide: Option<DecideFn>, input: &Value) -> Result<Value, String> {
    (decide.ok_or("no Policy VM supplied (fail closed)")?)(input)
}

fn summarize(d: &Value) -> Result<Value, String> {
    let rel = d.get("releaseGuardianShare").ok_or("decision has no releaseGuardianShare")?;
    let r = fin(d.get("r")).ok_or("decision has no finite r")?;
    let opt = d.get("requiredThreshold").and_then(|t| t.get("optimisticAllowed")).ok_or("decision has no requiredThreshold")?;
    Ok(json!({"releaseGuardianShare": rel, "r": r, "optimisticAllowed": opt}))
}

fn truthy(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

fn claimed_r(claim: &Value) -> Result<f64, String> {
    fin(claim.get("claimed_r")).ok_or_else(|| "claim has no finite claimed_r".to_string())
}

fn num_s(v: Option<&Value>) -> String {
    match v.and_then(Value::as_f64) {
        Some(f) => js_number_string(f),
        None => "undefined".into(),
    }
}

fn snap_class(snap: &Value) -> Option<&str> {
    snap.get("action").and_then(|a| a.get("action")).and_then(|a| a.get("reversibility_class")).and_then(Value::as_str)
}

/// Independently verify a fraud proof against a bonded claim: `{fraudulent, slashBondRef?, reason}`. Total; fails closed.
pub fn verify_fraud_proof(claim: &Value, proof: &Value, grant: &Value, open_snapshot: &Value, decide: Option<DecideFn>) -> Value {
    let no = |reason: &str| json!({"fraudulent": false, "reason": reason});
    let run = || -> Result<Value, String> {
        // `typeof x === 'object'`: an array passes these shape tests and fails on its (absent) members instead
        if !(proof.is_object() || proof.is_array()) {
            return Ok(no("malformed fraud proof"));
        }
        if proof.get("pcactn_digest") != claim.get("pcactn_digest") {
            return Ok(no("fraud proof targets a different PCActn than the claim"));
        }
        if proof.get("bond_ref") != claim.get("bond_ref") {
            return Ok(no("fraud proof names a different bond than the claim"));
        }
        if !(open_snapshot.is_object() || open_snapshot.is_array()) {
            return Ok(no("no frozen open-time snapshot supplied; cannot judge the claim"));
        }
        let rec = run_decide(decide, &with_grant(open_snapshot, grant))?;
        let s = summarize(&rec)?;
        // the reference reads `proof.decision.releaseGuardianShare`: a missing or null decision is a TypeError there
        match proof.get("decision") {
            None => return Err("Cannot read properties of undefined (reading 'releaseGuardianShare')".into()),
            Some(Value::Null) => return Err("Cannot read properties of null (reading 'releaseGuardianShare')".into()),
            _ => {}
        }
        let d = proof.get("decision").filter(|d| d.is_object());
        let dr = d.and_then(|d| fin(d.get("r")));
        let s_r = s["r"].as_f64().unwrap_or(f64::NAN);
        if Some(&s["releaseGuardianShare"]) != d.and_then(|d| d.get("releaseGuardianShare"))
            || Some(&s["optimisticAllowed"]) != d.and_then(|d| d.get("optimisticAllowed"))
            || !dr.is_some_and(|dr| (s_r - dr).abs() <= 1e-9)
        {
            return Ok(no("proof decision does not match an independent recomputation"));
        }
        let margin = margin_of(fin(proof.get("r_margin")));
        let irreversible =
            claim.get("reversibility_class").and_then(Value::as_str) == Some(IRREVERSIBLE_CLASS) || snap_class(open_snapshot) == Some(IRREVERSIBLE_CLASS);
        let slash = |reason: String| json!({"fraudulent": true, "slashBondRef": claim.get("bond_ref").cloned().unwrap_or(Value::Null), "reason": reason});
        if irreversible {
            return Ok(slash("irreversible action is ineligible for the optimistic path".into()));
        }
        if !truthy(Some(&s["releaseGuardianShare"])) {
            let why: Vec<&str> = rec.get("reasons").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let why = if why.is_empty() { "not compliant".to_string() } else { why.join("; ") };
            return Ok(slash(format!("Policy VM denies the action: {why}")));
        }
        if !truthy(Some(&s["optimisticAllowed"])) {
            return Ok(slash(format!("optimistic path not allowed at real r={}", to_fixed(s_r, 3))));
        }
        let cr = claimed_r(claim)?;
        if s_r > cr + margin {
            return Ok(slash(format!("risk understated: claimed {}, real {}", js_number_string(cr), to_fixed(s_r, 3))));
        }
        Ok(no("claim is compliant under independent recomputation; bond stands"))
    };
    run().unwrap_or_else(|e| no(&format!("fraud-proof verification error: {e}")))
}

/// File a fraud proof against `claim` for `pcactn`: the Policy VM is re-run on the frozen open-time snapshot under `grant` (a caller
/// decision is never trusted). `Ok(None)` for a compliant claim, a claim for another action, or a missing snapshot.
pub fn file_fraud_proof(
    claim: &Value,
    pcactn: &Value,
    grant: &Value,
    open_snapshot: &Value,
    r_margin: Option<f64>,
    decide: Option<DecideFn>,
) -> Result<Option<Value>, String> {
    if !open_snapshot.is_object() {
        return Ok(None);
    }
    let actual = run_decide(decide, &with_grant(open_snapshot, grant))?;
    let s = summarize(&actual)?;
    if claim.get("pcactn_digest").and_then(Value::as_str) != crate::hash_canonical_strict(pcactn).as_deref() {
        return Ok(None);
    }
    let margin = margin_of(r_margin);
    let optimistic = truthy(Some(&s["optimisticAllowed"]));
    let r = s["r"].as_f64().unwrap_or(f64::NAN);
    let mut evidence = open_snapshot.as_object().cloned().unwrap_or_default();
    evidence.remove("grant");
    let rc = pcactn.get("action").and_then(|a| a.get("reversibility_class")).and_then(Value::as_str);
    let (kind, reason) = if claim.get("reversibility_class").and_then(Value::as_str) == Some(IRREVERSIBLE_CLASS) || rc == Some(IRREVERSIBLE_CLASS) {
        ("irreversible", "irreversible action took the optimistic path".to_string())
    } else if !truthy(Some(&s["releaseGuardianShare"])) {
        let why: Vec<&str> = actual.get("reasons").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        ("policy-denied", format!("Policy VM denied the action: {}", if why.is_empty() { "not compliant".to_string() } else { why.join("; ") }))
    } else if !optimistic {
        (
            "optimistic-not-allowed",
            format!("optimistic path not allowed at real r={} (t={})", to_fixed(r, 3), num_s(actual.get("requiredThreshold").and_then(|t| t.get("t")))),
        )
    } else if r > claimed_r(claim)? + margin {
        ("risk-understated", format!("claimed r={} but real r={}", num_s(claim.get("claimed_r")), to_fixed(r, 3)))
    } else {
        return Ok(None);
    };
    Ok(Some(json!({
        "pcactn_digest": claim["pcactn_digest"], "bond_ref": claim["bond_ref"], "claimed_r": claim["claimed_r"],
        "decision": {"releaseGuardianShare": s["releaseGuardianShare"], "r": r, "optimisticAllowed": optimistic},
        "evidence": Value::Object(evidence), "r_margin": margin, "kind": kind, "reason": reason,
    })))
}

/// A JSON-normalized copy of a decide input captured at claim open (store it with the claim, grant stripped).
pub fn freeze_open_snapshot(input: &Value) -> Result<Value, String> {
    serde_json::from_str(&serde_json::to_string(input).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

// ---- one-shot dispute ---------------------------------------------------------------------------------------------------------

fn fast_path_admits(s: &Value, claimed_r: f64, margin: f64) -> bool {
    truthy(Some(&s["releaseGuardianShare"])) && truthy(Some(&s["optimisticAllowed"])) && s["r"].as_f64().is_some_and(|r| r <= claimed_r + margin)
}

fn snapshot_value(snap: &Value, input: &str) -> Option<Value> {
    if input == "reversibility_class" {
        let v = snap.get("caveatContext").and_then(|c| c.get("reversibilityClass")).filter(|v| !v.is_null());
        return v.cloned().or_else(|| snap_class(snap).map(|c| json!(c)));
    }
    snap.get("risk").and_then(|r| r.get(input)).filter(|v| !v.is_null()).cloned()
}

/// Fold an oracle resolution `{input, value?, class?}` into a COPY of `snap` for its single disputed input.
pub fn substitute_disputed_input(snap: &Value, res: &Value) -> Result<Value, String> {
    let input = res.get("input").and_then(Value::as_str).ok_or("resolution has no input")?;
    let mut out = snap.as_object().cloned().unwrap_or_default();
    let ctx = snap.get("caveatContext").and_then(Value::as_object);
    if input == "reversibility_class" {
        let class = res.get("class").and_then(Value::as_str).filter(|c| !c.is_empty()).ok_or("oracle reversibility_class resolution carries no class")?;
        let mut act = snap.get("action").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut inner = act.get("action").and_then(Value::as_object).cloned().unwrap_or_default();
        inner.insert("reversibility_class".into(), json!(class));
        act.insert("action".into(), Value::Object(inner));
        out.insert("action".into(), Value::Object(act));
        if let Some(c) = ctx.filter(|c| c.get("reversibilityClass").is_some_and(|v| !v.is_null())) {
            let mut c = c.clone();
            c.insert("reversibilityClass".into(), json!(class));
            out.insert("caveatContext".into(), Value::Object(c));
        }
        return Ok(Value::Object(out));
    }
    let value = fin(res.get("value")).ok_or_else(|| format!("oracle {input} resolution carries no finite value"))?;
    let mut risk = snap.get("risk").and_then(Value::as_object).cloned().unwrap_or_default();
    risk.insert(input.into(), json!(value));
    out.insert("risk".into(), Value::Object(risk));
    if input == "blastRadius" {
        if let Some(c) = ctx.filter(|c| c.get("blastRadius").is_some_and(|v| !v.is_null())) {
            let mut c = c.clone();
            c.insert("blastRadius".into(), json!(value));
            out.insert("caveatContext".into(), Value::Object(c));
        }
    }
    Ok(Value::Object(out))
}

fn js_json(v: &Option<Value>) -> String {
    v.as_ref().map_or("undefined".to_string(), crate::js_stringify)
}

fn worst() -> Value {
    json!({"releaseGuardianShare": false, "r": 1, "optimisticAllowed": false})
}

fn indeterminate(input: &str, reason: String, baseline: Option<Value>, agent_value: Option<Value>) -> Value {
    // `agentValue` / `oracleValue` are `undefined` (no key) when the dispute never got as far as reading them
    let mut v = json!({
        "outcome": "indeterminate", "fraudulent": false, "slashCounterBond": false, "input": input,
        "baseline": baseline.unwrap_or_else(worst), "adjudicated": worst(), "reason": reason,
    });
    if let Some(a) = agent_value {
        v["agentValue"] = a;
    }
    v
}

/// Adjudicate a contestable dispute: RE-RUN the Policy VM on the frozen open-time snapshot with the ORACLE's authoritative value
/// substituted for the single disputed input. `outcome`: `agent-fraud` (slash the agent's bond), `claim-upheld` (slash the challenger's
/// counter-bond) or `indeterminate` (slash neither). The challenger's asserted value is never read for the verdict. Total; fails closed.
pub fn adjudicate_dispute(
    claim: &Value,
    dispute: &Value,
    grant: &Value,
    open_snapshot: &Value,
    oracle: Option<OracleFn>,
    r_margin: Option<f64>,
    decide: Option<DecideFn>,
) -> Value {
    let margin = margin_of(r_margin);
    let input_name = dispute.get("input").and_then(Value::as_str).filter(|i| INPUTS.contains(i)).unwrap_or("reversibility_class");
    let run = || -> Result<Value, String> {
        if !dispute.is_object() {
            return Ok(indeterminate("reversibility_class", "malformed dispute".into(), None, None));
        }
        let input = match dispute.get("input").and_then(Value::as_str).filter(|i| INPUTS.contains(i)) {
            Some(i) => i,
            None => {
                let shown = dispute.get("input").map_or("undefined".to_string(), crate::intent_v2::js_value_string);
                return Ok(indeterminate("reversibility_class", format!("unknown disputed input: {shown}"), None, None));
            }
        };
        if dispute.get("pcactn_digest") != claim.get("pcactn_digest") {
            return Ok(indeterminate(input, "dispute targets a different PCActn than the claim".into(), None, None));
        }
        if dispute.get("bond_ref") != claim.get("bond_ref") {
            return Ok(indeterminate(input, "dispute names a different bond than the claim".into(), None, None));
        }
        if !open_snapshot.is_object() {
            return Ok(indeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate".into(), None, None));
        }
        let oracle = match oracle {
            Some(o) => o,
            None => return Ok(indeterminate(input, "no objective oracle supplied".into(), None, None)),
        };
        let snap = with_grant(open_snapshot, grant);
        let baseline = summarize(&run_decide(decide, &snap)?)?;
        let agent_value = snapshot_value(&snap, input);
        let res = oracle(input, &snap)?;
        if res.get("input").and_then(Value::as_str) != Some(input) || !truthy(res.get("valid")) {
            let why = res.get("reason").and_then(Value::as_str).filter(|r| !r.is_empty()).map(|r| format!(": {r}")).unwrap_or_default();
            return Ok(indeterminate(input, format!("objective oracle could not authoritatively resolve {input}{why}"), Some(baseline), agent_value));
        }
        let oracle_value = res.get("class").filter(|c| !c.is_null()).or_else(|| res.get("value")).cloned();
        let adjudicated = summarize(&run_decide(decide, &substitute_disputed_input(&snap, &res)?)?)?;
        let cr = claimed_r(claim)?;
        let ar = adjudicated["r"].as_f64().unwrap_or(f64::NAN);
        if !fast_path_admits(&adjudicated, cr, margin) {
            let why = if !truthy(Some(&adjudicated["releaseGuardianShare"])) {
                "the Policy VM denies the action".to_string()
            } else if !truthy(Some(&adjudicated["optimisticAllowed"])) {
                format!("the optimistic path is not allowed (higher threshold) at r={}", to_fixed(ar, 3))
            } else {
                format!("the real r={} exceeds the claimed r={}", to_fixed(ar, 3), js_number_string(cr))
            };
            return Ok(json!({
                "outcome": "agent-fraud", "fraudulent": true, "slashBondRef": claim.get("bond_ref").cloned().unwrap_or(Value::Null), "slashCounterBond": false,
                "input": input, "agentValue": agent_value.clone().unwrap_or(Value::Null), "oracleValue": oracle_value.clone().unwrap_or(Value::Null),
                "baseline": baseline, "adjudicated": adjudicated,
                "reason": format!("understated {input}: agent relied on {}, oracle says {} \u{2014} {why}", js_json(&agent_value), js_json(&oracle_value)),
            }));
        }
        Ok(json!({
            "outcome": "claim-upheld", "fraudulent": false, "slashCounterBond": true, "input": input,
            "agentValue": agent_value.clone().unwrap_or(Value::Null), "oracleValue": oracle_value.clone().unwrap_or(Value::Null),
            "baseline": baseline, "adjudicated": adjudicated,
            "reason": format!("the objective oracle upholds the agent's {input} ({}); fast-path admission survives \u{2014} the dispute is frivolous", js_json(&oracle_value)),
        }))
    };
    run().unwrap_or_else(|e| indeterminate(input_name, format!("dispute adjudication error (fail closed): {e}"), None, None))
}

// ---- interactive dispute game -------------------------------------------------------------------------------------------------

fn assertion_equals(a: &Value, b: &Value) -> bool {
    let (av, bv) = (a.get("value"), b.get("value"));
    let value_eq = match (av, bv) {
        (None, None) => true,
        (Some(x), Some(y)) if x.is_number() && y.is_number() => x.as_f64().map(f64::to_bits) == y.as_f64().map(f64::to_bits),
        _ => false,
    };
    value_eq && a.get("class") == b.get("class")
}

fn apply_assertion(snap: &Value, input: &str, a: &Value) -> Result<Value, String> {
    let mut res = Map::new();
    res.insert("input".into(), json!(input));
    res.insert("valid".into(), json!(true));
    for k in ["value", "class"] {
        if let Some(v) = a.get(k) {
            res.insert(k.into(), v.clone());
        }
    }
    substitute_disputed_input(snap, &Value::Object(res))
}

fn state_after(snap: &Value, steps: &[&str], assertions: &[Value], j: usize, decide: Option<DecideFn>) -> Result<Value, String> {
    let mut s = snap.clone();
    for i in 0..j {
        let a = assertions.get(i).ok_or("dispute game trace is shorter than its step list")?;
        s = apply_assertion(&s, steps[i], a)?;
    }
    summarize(&run_decide(decide, &s)?)
}

/// Adjudicate an INTERACTIVE multi-round dispute game by refereed bisection. Returns `{verdict, converged, contestedStep,
/// contestedInput?, transcript, rounds}`; fails CLOSED to an `indeterminate` verdict on any malformed input, binding mismatch, missing
/// snapshot or oracle, absence of a genuine admission dispute, non-convergence, or error.
pub fn adjudicate_dispute_game(
    claim: &Value,
    game: &Value,
    grant: &Value,
    open_snapshot: &Value,
    oracle: Option<OracleFn>,
    r_margin: Option<f64>,
    decide: Option<DecideFn>,
) -> Value {
    let margin = margin_of(r_margin);
    let first_step = game
        .get("steps")
        .and_then(Value::as_array)
        .and_then(|s| s.first())
        .and_then(Value::as_str)
        .filter(|i| INPUTS.contains(i))
        .unwrap_or("reversibility_class");
    let fail = |reason: String, input: Option<&str>| json!({"verdict": indeterminate(input.unwrap_or(first_step), reason, None, None), "converged": false, "contestedStep": -1, "transcript": [], "rounds": 0});
    let run = || -> Result<Value, String> {
        if !game.is_object() {
            return Ok(fail("malformed dispute game".into(), None));
        }
        if game.get("pcactn_digest") != claim.get("pcactn_digest") {
            return Ok(fail("dispute game targets a different PCActn than the claim".into(), None));
        }
        if game.get("bond_ref") != claim.get("bond_ref") {
            return Ok(fail("dispute game names a different bond than the claim".into(), None));
        }
        let raw_steps = match game.get("steps").and_then(Value::as_array).filter(|s| !s.is_empty()) {
            Some(s) => s,
            None => return Ok(fail("dispute game has no steps".into(), None)),
        };
        let mut steps: Vec<&str> = Vec::new();
        for s in raw_steps {
            match s.as_str().filter(|i| INPUTS.contains(i)) {
                Some(i) => steps.push(i),
                None => return Ok(fail(format!("unknown disputed input: {}", crate::intent_v2::js_value_string(s)), None)),
            }
        }
        let n = steps.len();
        let (defender, challenger) = match (game.get("defender").and_then(Value::as_array), game.get("challenger").and_then(Value::as_array)) {
            (Some(d), Some(c)) if d.len() == n && c.len() == n => (d, c),
            _ => return Ok(fail("party assertions do not cover every step".into(), None)),
        };
        if !open_snapshot.is_object() {
            return Ok(fail("no frozen open-time snapshot supplied; cannot adjudicate".into(), None));
        }
        let oracle = match oracle {
            Some(o) => o,
            None => return Ok(fail("no objective oracle supplied".into(), None)),
        };
        let snap = with_grant(open_snapshot, grant);
        let cr = claimed_r(claim)?;
        // genuine-dispute gate: the defender's full trace must still admit the fast path and the challenger's must not
        if !fast_path_admits(&state_after(&snap, &steps, defender, n, decide)?, cr, margin) {
            return Ok(fail("defender does not defend the fast-path admission; nothing to adjudicate".into(), None));
        }
        if fast_path_admits(&state_after(&snap, &steps, challenger, n, decide)?, cr, margin) {
            return Ok(fail("the parties do not disagree on admission; no genuine dispute to bisect".into(), None));
        }
        let prefix_agrees = |m: usize| (0..m).all(|i| assertion_equals(&defender[i], &challenger[i]));
        if prefix_agrees(n) {
            return Ok(fail("the parties committed identical traces; no contested step to bisect".into(), None));
        }
        let (mut lo, mut hi) = (0usize, n);
        let mut transcript = Vec::new();
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            let agreed = prefix_agrees(mid);
            transcript.push(json!({"lo": lo, "hi": hi, "mid": mid, "agreedAtMid": agreed}));
            if agreed {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let contested = lo;
        let contested_input = steps[contested];
        let mut pre = snap.clone();
        for i in 0..contested {
            if !assertion_equals(&defender[i], &challenger[i]) {
                return Ok(fail("agreed prefix is not actually agreed; cannot reconstruct the pre-state".into(), Some(contested_input)));
            }
            pre = apply_assertion(&pre, steps[i], &defender[i])?;
        }
        let chal = &challenger[contested];
        let mut dispute = json!({"pcactn_digest": claim.get("pcactn_digest").cloned().unwrap_or(Value::Null), "bond_ref": claim.get("bond_ref").cloned().unwrap_or(Value::Null), "input": contested_input});
        if let Some(v) = chal.get("value") {
            dispute["asserted_value"] = v.clone();
        }
        if let Some(c) = chal.get("class") {
            dispute["asserted_class"] = c.clone();
        }
        let verdict = adjudicate_dispute(claim, &dispute, grant, &pre, Some(oracle), Some(margin), decide);
        let rounds = transcript.len();
        Ok(
            json!({"verdict": verdict, "converged": true, "contestedStep": contested, "contestedInput": contested_input, "transcript": transcript, "rounds": rounds}),
        )
    };
    run().unwrap_or_else(|e| fail(format!("dispute game adjudication error (fail closed): {e}"), None))
}

// ---- claim verification ---------------------------------------------------------------------------------------------------------

/// Verify a bonded claim: the signature verifies under `signer_public`, the claim covers THIS PCActn, the action is not irreversible
/// and the challenge window is acceptable at `server_now` under `policy` (default [`crate::optimistic::DEFAULT_WINDOW_POLICY`]).
/// `{ok: true}` or `{ok: false, reason}`. It does NOT judge policy compliance: that is a fraud proof's job. Total.
pub fn verify_claim(claim: &Value, pcactn: &Value, signer_public: &str, server_now: f64, policy: Option<&crate::optimistic::WindowPolicy>) -> Value {
    use crate::optimistic::{claim_check, validate_window, DEFAULT_WINDOW_POLICY};
    let policy = policy.unwrap_or(&DEFAULT_WINDOW_POLICY);
    let no = |reason: &str| json!({"ok": false, "reason": reason});
    let digest = crate::hash_canonical_strict(pcactn);
    // a PCActn outside the strict profile has no digest: only the checks that come before the digest comparison can still answer
    let check = claim_check(claim, digest.as_deref().unwrap_or(""), signer_public, server_now, policy);
    match check {
        "ok" if digest.is_some() => json!({"ok": true}),
        "malformed" => no("malformed claim"),
        "irreversible" => no("irreversible action is ineligible for the optimistic path"),
        _ if digest.is_none() => no("claim verification error: the PCActn is not canonicalizable"),
        "digest" => no("claim does not cover this PCActn"),
        "claimed_r" => no("claimed_r is not finite"),
        "window" => no(validate_window(fin(claim.get("issued_at")).unwrap_or(f64::NAN), fin(claim.get("challenge_window_ms")).unwrap_or(f64::NAN), server_now, policy)
            .unwrap_or("malformed challenge window")),
        _ => no("claim signature does not verify"),
    }
}
