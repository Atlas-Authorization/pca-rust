//! Runtime routing and conformance (`runtime.ts`): routing an admitted action by the map's posterior and the verb's reversibility,
//! the judge input, the intent-conformance attestation (IC-Att) and just-in-time consent.
use super::semantic::{bond_amount, default_bond_policy, verify_semantic_threshold};
use super::{dbl, R};
use crate::intent_kit::{hash_strict, jn, js_max, js_min, js_round, opt, truthy};
use crate::intent_kit2::learner::Learner;
use crate::intent_kit2::mapkit::apply_divergence;
use crate::intent_kit2::omega::{harm_max, harm_of, Vs};
use crate::intent_kit2::util::num;
use crate::intent_kit3::render::{outcome_to_action, render_action};
use serde_json::{json, Map, Value};

pub const IC_ATT_DOMAIN: &str = "atlas-pca/intent-ic-att/v1";

fn with(base: &Map<String, Value>, extra: Vec<(&str, Value)>) -> Value {
    let mut m = base.clone();
    for (k, v) in extra {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// deny / allow / optimistic / jit-consent for an action the grant already admits. `opts`: theta2, hMax, bondPolicy.
pub fn route_action(l: &mut Learner, o: &Value, opts: &Value) -> R<Value> {
    let vs: Option<Vs> = o.get("verb").and_then(Value::as_str).and_then(|v| l.omega_t.vs_of(v)).cloned();
    let rev = |v: &Vs| v.reversibility.clone().map(Value::String).unwrap_or(Value::Null);
    let vs = match vs {
        Some(v) if v.cell_of(o).is_some() => v,
        other => {
            let r = other.and_then(|v| v.reversibility).map_or_else(|| json!("unknown"), Value::String);
            return Ok(json!({"route": "deny", "p": 0, "inGrant": false, "vetoed": false, "reversibility": r, "harm": 0, "risk": 1, "judges": false,
                "reason": "outside the Intent Map's outcome space"}));
        }
    };
    let p = l.acceptance(o);
    let in_grant = l.admits_outcome(o);
    let vetoed = l.is_vetoed(o);
    let harm = harm_of(&vs, o);
    let h_max = match opt(opts, "hMax") {
        Some(h) => dbl(Some(h)),
        None => harm_max(&l.omega_t)?,
    };
    let risk = js_min(1.0, js_max(0.0, ((1.0 - p) * harm) / if h_max > 0.0 { h_max } else { 1.0 }));
    let theta2 = opt(opts, "theta2").map_or(0.5, |t| dbl(Some(t)));
    let mut base = Map::new();
    base.insert("p".into(), num(p));
    base.insert("inGrant".into(), json!(in_grant));
    base.insert("vetoed".into(), json!(vetoed));
    base.insert("reversibility".into(), rev(&vs));
    base.insert("harm".into(), num(harm));
    base.insert("risk".into(), num(risk));
    if !in_grant {
        let why = if vetoed { "the cell was vetoed by a runtime divergence" } else { "outside the conservative grant (p_n < τ)" };
        return Ok(with(&base, vec![("route", json!("deny")), ("judges", json!(false)), ("reason", json!(why))]));
    }
    let irreversible = vs.reversibility.as_deref() == Some("irreversible");
    let judges = irreversible || p < 1.0 - 1e-12 || risk >= theta2;
    if irreversible {
        return Ok(with(
            &base,
            vec![("route", json!("jit-consent")), ("judges", json!(judges)), ("reason", json!("irreversible: just-in-time consent on the rendered action"))],
        ));
    }
    if judges {
        let policy = opt(opts, "bondPolicy").cloned().unwrap_or_else(default_bond_policy);
        let bond = bond_amount(&policy, harm)?;
        let why = if p < 1.0 - 1e-12 { "unconfirmed region (p_n < 1): bonded claim + judges" } else { "risk ≥ θ₂: bonded claim + judges" };
        return Ok(with(&base, vec![("route", json!("optimistic")), ("judges", json!(judges)), ("bond", num(bond)), ("reason", json!(why))]));
    }
    Ok(with(&base, vec![("route", json!("allow")), ("judges", json!(false)), ("reason", json!("confirmed region, reversible, low risk"))]))
}

// ---- L3: the judge input and the IC-Att --------------------------------------------------------------------------------------

/// The PCActn action shape of an outcome (`params_digest` by the canonical rule).
pub fn pcactn_action_of(vs: &Value, o: &Value) -> R<Value> {
    let a = outcome_to_action(vs, o);
    let mut m = Map::new();
    m.insert("verb".into(), a["verb"].clone());
    m.insert("resource".into(), a["resource"].clone());
    m.insert("params_digest".into(), json!(crate::params_digest(a.get("params"))));
    if let Some(r) = vs.get("reversibility") {
        m.insert("reversibility_class".into(), r.clone());
    }
    Ok(Value::Object(m))
}

/// `actionDigest`: the digest every verdict must bind to.
pub fn action_digest(action: &Value) -> R<String> {
    hash_strict(action)
}

/// The judge input for an outcome of verb space `vs` whose posterior is `p`; `ctx`: intentRef, mapDigest, statementText, slots, goalCommitment.
pub fn judge_input_of(vs: &Value, o: &Value, p: f64, ctx: &Value) -> R<Value> {
    let mut m = ctx.as_object().cloned().unwrap_or_default();
    m.insert("renderedAction".into(), json!(render_action(vs, &o["values"])?));
    m.insert("p".into(), num(p));
    m.insert("reversibility".into(), vs.get("reversibility").cloned().unwrap_or(Value::Null));
    m.insert("actionDigest".into(), json!(action_digest(&pcactn_action_of(vs, o)?)?));
    Ok(Value::Object(m))
}

fn verb_space_of(l: &Learner, verb: &Value) -> Option<Value> {
    l.omega["verbs"].as_array()?.iter().find(|v| &v["verb"] == verb).cloned()
}

/// [`judge_input_of`] over a learner (its Omega and posterior).
pub fn judge_input_of_learner(l: &mut Learner, o: &Value, ctx: &Value) -> R<Value> {
    let vs = verb_space_of(l, &o["verb"]).ok_or_else(|| format!("judgeInputOf: no verb {} in Ω", crate::intent_kit3::js_str(o.get("verb"))))?;
    let p = l.acceptance(o);
    judge_input_of(&vs, o, p, ctx)
}

/// The digest of a calibration set (what the IC-Att commits to).
pub fn calibration_digest(c: &Value) -> R<String> {
    let samples = c.get("samples").and_then(Value::as_array).ok_or("c.samples.map is not a function")?;
    let mut ss = vec![];
    for s in samples {
        if s.is_null() {
            return Err("Cannot read properties of null (reading 'score')".into());
        }
        let mut m = Map::new();
        for k in ["score", "faithful"] {
            if let Some(x) = s.get(k) {
                m.insert(k.into(), x.clone());
            }
        }
        ss.push(Value::Object(m));
    }
    let mut body = Map::new();
    body.insert("d".into(), json!("atlas-pca/intent-calibration/v1"));
    if let Some(a) = c.get("alpha") {
        body.insert("alpha".into(), a.clone());
    }
    body.insert("samples".into(), Value::Array(ss));
    hash_strict(&Value::Object(body))
}

fn to_ppm(x: f64) -> Value {
    if x.is_finite() {
        jn(js_round(x * 1_000_000.0))
    } else {
        Value::Null
    }
}

/// Verify a panel's verdicts for one action and produce the IC-Att. `opts`: judgeKeys, k, calibration?.
pub fn intent_conformance_attestation(input: &Value, verdicts: &Value, opts: &Value) -> R<Value> {
    let mut vo = Map::new();
    for (to, v) in [
        ("judgeKeys", opts.get("judgeKeys")),
        ("k", opts.get("k")),
        ("goalCommitment", input.get("goalCommitment")),
        ("actionDigest", input.get("actionDigest")),
    ] {
        if let Some(x) = v {
            vo.insert(to.into(), x.clone());
        }
    }
    if truthy(opts.get("calibration")) {
        vo.insert("calibration".into(), opts["calibration"].clone());
    }
    let r = verify_semantic_threshold(verdicts, &Value::Object(vo));
    let mut digests: Vec<String> = vec![];
    for v in verdicts.as_array().ok_or("verdicts.map is not a function")? {
        digests.push(hash_strict(v)?);
    }
    digests.sort_by(|a, b| crate::intent_kit::u16cmp(a, b));
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("kind".into(), json!("pca-ic-att"));
    for (to, from) in [("intent_ref", "intentRef"), ("map_digest", "mapDigest"), ("action_digest", "actionDigest"), ("goal_commitment", "goalCommitment")] {
        if let Some(x) = input.get(from) {
            m.insert(to.into(), x.clone());
        }
    }
    m.insert("verdict_digests".into(), json!(digests));
    m.insert("calibration_digest".into(), if truthy(opts.get("calibration")) { json!(calibration_digest(&opts["calibration"])?) } else { Value::Null });
    if let Some(k) = opts.get("k") {
        m.insert("k".into(), k.clone());
    }
    m.insert("ok".into(), json!(r.ok));
    m.insert("agree_count".into(), json!(r.agree_count));
    let score = to_ppm(r.aggregate_score);
    m.insert("aggregate_score_ppm".into(), if score.is_null() { json!(0) } else { score });
    m.insert("cutoff_ppm".into(), r.cutoff.map_or(Value::Null, to_ppm));
    if let Some(reason) = r.reason.as_deref().filter(|s| !s.is_empty()) {
        m.insert("reason".into(), json!(reason));
    }
    Ok(Value::Object(m))
}

/// Ask the panel (a synchronous callback returning the verdicts) and attest: `{att, verdicts}`.
pub fn check_intent_conformance(panel: &dyn Fn(&Value) -> R<Value>, input: &Value, opts: &Value) -> R<Value> {
    let verdicts = panel(input)?;
    Ok(json!({"att": intent_conformance_attestation(input, &verdicts, opts)?, "verdicts": verdicts}))
}

/// The content address of an IC-Att (the value a v1 PCActn carries as `ic_att_digest`).
pub fn ic_att_digest(a: &Value) -> R<String> {
    hash_strict(&json!({"d": IC_ATT_DOMAIN, "a": a}))
}

/// Re-verify an IC-Att from the verdicts it names (a relying party never trusts the `ok` bit): `{ok, problems}`.
pub fn verify_ic_att(att: &Value, input: &Value, verdicts: &Value, opts: &Value) -> R<Value> {
    let again = intent_conformance_attestation(input, verdicts, opts)?;
    let mut problems: Vec<String> = vec![];
    if ic_att_digest(&again)? != ic_att_digest(att)? {
        problems.push("IC-Att does not match the recomputation from its verdicts".into());
    }
    if again["ok"] != json!(true) {
        let why = again.get("reason").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("unknown");
        problems.push(format!("panel does not pass: {why}"));
    }
    Ok(json!({"ok": problems.is_empty(), "problems": problems}))
}

/// `semanticRiskContribution`: `1 - score` clamped to [0, 1]; a non-finite score is full risk.
pub fn semantic_risk_contribution(score: f64) -> f64 {
    if !score.is_finite() {
        return 1.0;
    }
    let r = 1.0 - score;
    if r < 0.0 {
        0.0
    } else if r > 1.0 {
        1.0
    } else {
        r
    }
}

/// The monotone risk fold `r := max(r, 1 - aggregateScore)`: never lowers r.
pub fn fold_semantic_risk(r: f64, att: &Value) -> f64 {
    js_max(r, semantic_risk_contribution(dbl(att.get("aggregate_score_ppm")) / 1_000_000.0))
}

// ---- L4: just-in-time consent ------------------------------------------------------------------------------------------------

/// The consent prompt for an action; `ctx`: intentRef, mapDigest.
pub fn jit_consent_request(vs: &Value, o: &Value, p: f64, ctx: &Value) -> R<Value> {
    let text = format!("{} This cannot be undone. Approve?", render_action(vs, &o["values"])?);
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("kind".into(), json!("pca-intent-jit"));
    for (to, from) in [("intent_ref", "intentRef"), ("map_digest", "mapDigest")] {
        if let Some(x) = ctx.get(from) {
            m.insert(to.into(), x.clone());
        }
    }
    if let Some(v) = o.get("verb") {
        m.insert("verb".into(), v.clone());
    }
    m.insert("values".into(), Value::Object(o["values"].as_object().cloned().unwrap_or_default()));
    m.insert("reversibility".into(), vs.get("reversibility").cloned().unwrap_or(Value::Null));
    m.insert("p_ppm".into(), jn(js_round(p * 1_000_000.0)));
    m.insert("text".into(), json!(text));
    Ok(Value::Object(m))
}

/// [`jit_consent_request`] over a learner.
pub fn jit_consent_request_learner(l: &mut Learner, o: &Value, ctx: &Value) -> R<Value> {
    let vs = verb_space_of(l, &o["verb"]).ok_or_else(|| format!("jitConsentRequest: no verb {} in Ω", crate::intent_kit3::js_str(o.get("verb"))))?;
    let p = l.acceptance(o);
    jit_consent_request(&vs, o, p, ctx)
}

pub fn jit_consent_digest(r: &Value) -> R<String> {
    hash_strict(&json!({"d": "atlas-pca/intent-jit/v1", "r": r}))
}

/// Record the principal's JIT decision as a runtime observation: approve -> y = 1, deny -> y = 0 (the cell is vetoed).
pub fn record_jit_decision(l: &mut Learner, req: &Value, decision: &str) -> R<Value> {
    apply_divergence(l, &json!({"verb": req["verb"], "values": req["values"]}), if decision == "approve" { 1.0 } else { 0.0 })
}
