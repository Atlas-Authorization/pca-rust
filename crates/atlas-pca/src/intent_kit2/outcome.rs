//! Outcome verification (postconditions on observed effects, evaluated by the one predicate evaluator; three-valued: ok, violated,
//! pending) and the Monte Carlo residual-risk estimate of a learner. Plain JSON in and out.
use super::learner::*;
use super::mapkit::apply_divergence;
use super::omega::*;
use super::util::*;
use crate::predicates::{evaluate_predicates, is_group_condition, Ctx};
use serde_json::{json, Map, Value};

fn amt() -> Vec<Value> {
    vec![json!({"field": "env.effect.amount", "op": "lte", "ref": "action.params.amount"}), json!({"field": "env.effect.amount", "op": "gte", "value": 0})]
}

fn pc(id: &str, verb: &str, description: &str, wh: Vec<Value>) -> Value {
    json!({"id": id, "verb": verb, "description": description, "where": wh})
}

fn eq_ref(field: &str, r: &str) -> Vec<Value> {
    vec![json!({"field": format!("env.effect.{field}"), "op": "eq", "ref": r})]
}

/// The built-in postconditions (`DEFAULT_POSTCONDITIONS`).
pub fn default_postconditions() -> Vec<Value> {
    vec![
        pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", amt()),
        pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", eq_ref("recipient", "action.params.recipient")),
        pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", amt()),
        pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", amt()),
        pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", eq_ref("recipient", "action.params.recipient")),
        pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", eq_ref("to", "action.params.to")),
        pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", eq_ref("channel", "action.params.channel")),
        pc("files.write.path", "files.write", "the written path is the requested resource", eq_ref("path", "action.resource")),
        pc("files.delete.path", "files.delete", "the deleted path is the requested resource", eq_ref("path", "action.resource")),
        pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", eq_ref("repo", "action.resource")),
        pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", eq_ref("hour", "env.hour")),
    ]
}

/// (field, ref?) of every leaf condition.
fn leaves(c: &Value, out: &mut Vec<(String, Option<String>)>) {
    if !c.is_object() {
        return;
    }
    if is_group_condition(c) {
        if let Some(a) = c["all_of"].as_array() {
            for x in a {
                leaves(x, out);
            }
        } else if let Some(a) = c["any_of"].as_array() {
            for x in a {
                leaves(x, out);
            }
        } else if c.get("not").is_some() {
            leaves(&c["not"], out);
        }
        return;
    }
    if let Some(f) = c["field"].as_str() {
        out.push((f.to_string(), c["ref"].as_str().map(String::from)));
    }
}

/// A dotted-path lookup: object members and canonical array indices; `None` is "undefined" (JSON null is present).
fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for k in path.split('.') {
        match cur {
            Value::Object(m) if m.contains_key(k) => cur = &m[k],
            Value::Array(a) => {
                let ok = !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) && (k == "0" || !k.starts_with('0'));
                let i: usize = if ok { k.parse().ok()? } else { return None };
                cur = a.get(i)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

/// The evaluator's context for an action plus its observed effect.
pub fn effect_context(rev: Option<&str>, o: &Value, effect: &Value) -> R<Value> {
    let a = outcome_to_action(rev, o)?;
    let mut action = Map::new();
    action.insert("verb".into(), a["verb"].clone());
    action.insert("resource".into(), a["resource"].clone());
    action.insert("params".into(), a["params"].clone());
    if let Some(r) = rev {
        action.insert("reversibility_class".into(), json!(r));
    }
    let mut ctx = Map::new();
    ctx.insert("action".into(), Value::Object(action));
    if let Some(s) = member(&a, "subject").filter(|x| truthy(x)) {
        ctx.insert("subject".into(), s.clone());
    }
    let mut env = a["env"].as_object().cloned().unwrap_or_default();
    env.insert("effect".into(), effect.clone());
    ctx.insert("env".into(), Value::Object(env));
    Ok(Value::Object(ctx))
}

pub fn check_postconditions(vs: &Vs, o: &Value, effect: &Value, pcs: Option<&Value>) -> R<Value> {
    let defaults = Value::Array(default_postconditions());
    let pcs = pcs.unwrap_or(&defaults);
    let ctx = effect_context(vs.reversibility.as_deref(), o, effect)?;
    let (mut violated, mut missing, mut checked, mut not_applicable): (Vec<String>, Vec<String>, Vec<String>, Vec<String>) = (vec![], vec![], vec![], vec![]);
    for p in arr(pcs, "postconditions")? {
        if p["verb"] != o["verb"] {
            continue;
        }
        let id = js_str(&p["id"]);
        let mut ls: Vec<(String, Option<String>)> = vec![];
        for c in arr(&p["where"], "postcondition where")? {
            leaves(c, &mut ls);
        }
        if ls.iter().any(|(_, r)| r.as_ref().is_some_and(|r| !r.starts_with("env.effect.") && get_path(&ctx, r).is_none())) {
            not_applicable.push(id);
            continue;
        }
        let mut need: Vec<String> = vec![];
        for (f, r) in &ls {
            for x in std::iter::once(f).chain(r.iter()) {
                if x.starts_with("env.effect.") && !need.contains(x) {
                    need.push(x.clone());
                }
            }
        }
        let lacking: Vec<String> = need.into_iter().filter(|f| get_path(&ctx, f).is_none()).collect();
        if !lacking.is_empty() {
            missing.extend(lacking);
            continue;
        }
        checked.push(id.clone());
        let pred = json!({"verb": o["verb"], "resource": "*", "where": p["where"]});
        if !evaluate_predicates(&[pred], &Ctx::new(&ctx)) {
            violated.push(id);
        }
    }
    missing.sort_by(|a, b| u16cmp(a, b));
    missing.dedup();
    let status = if !violated.is_empty() {
        "violated"
    } else if !missing.is_empty() {
        "pending"
    } else {
        "ok"
    };
    Ok(json!({"status": status, "violated": violated, "missing": missing, "checked": checked, "notApplicable": not_applicable}))
}

/// Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the action's
/// cell. `ok` and `pending` change nothing. `pcs` absent = the default postconditions.
pub fn verify_outcome(l: &mut Learner, o: &Value, effect: &Value, pcs: Option<&Value>) -> R<Value> {
    let verb = js_str(&o["verb"]);
    let vs = l.omega_t.vs_of(&verb).cloned().ok_or_else(|| format!("verifyOutcome: no verb {verb} in \u{3a9}"))?;
    let report = check_postconditions(&vs, o, effect, pcs)?;
    if report["status"].as_str() != Some("violated") {
        return Ok(json!({"report": report}));
    }
    let div = apply_divergence(l, o, 0.0)?;
    Ok(json!({"report": report, "divergence": div}))
}

/// The Monte Carlo form of the learner's residual-risk estimate, for the cross-check (a double, NaN when `samples` is 0).
pub fn estimate_residual_risk_mc(l: &mut Learner, samples: f64, seed: f64) -> R<f64> {
    let mut rng = Rng::new(seed);
    let g = Admitter::new(&l.synthesize()?)?;
    let omega = l.omega_t.clone();
    let mut r = 0.0;
    let n = samples.max(0.0) as usize;
    for _ in 0..n {
        let (vi, o) = sample_outcome(&omega, &mut rng)?;
        let vs = &omega.verbs[vi];
        if g.admits(vs.reversibility.as_deref(), &o)? {
            r += (1.0 - l.acceptance(&o)) * harm_of(vs, &o);
        }
    }
    Ok(r / samples)
}
