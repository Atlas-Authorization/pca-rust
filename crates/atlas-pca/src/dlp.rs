//! Data-flow governance, DLP for agents: declare data classes (a resource matcher and the maximum taint that may reach them without a
//! human) and evaluate an action's provenance taint against them. ADVISORY: taint levels are labels something upstream attached; this
//! checks them against ceilings and never tracks data through a program, so it is never the only control over an exfiltration path.
//! Taint 0 is clean; higher is more untrusted or sensitive. JSON-valued: the policy is
//! `{classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}`, a context is `{verb, resource,
//! taint}`, a result is `{outcome: allow | step_up | deny, class?, reason?}`. Fails closed: a malformed policy or ceiling is a deny and a
//! taint that is not a finite number is maximally tainted. Where the reference would throw (a class that is not an object, a resource
//! that is not a string) this returns an error.
use crate::intent_v2::js_number_string;
use crate::oauth::{js_str, truthy};
use serde_json::{json, Map, Value};

fn matches(pattern: Option<&Value>, resource: Option<&Value>) -> Result<bool, String> {
    if pattern.and_then(Value::as_str) == Some("*") {
        return Ok(true);
    }
    let Some(p) = pattern.and_then(Value::as_str) else { return Err("pattern.endsWith is not a function".into()) };
    if let Some(prefix) = p.strip_suffix('*') {
        let Some(r) = resource.and_then(Value::as_str) else { return Err("resource.startsWith is not a function".into()) };
        return Ok(r.starts_with(prefix));
    }
    Ok(resource.and_then(Value::as_str) == Some(p))
}

/// Length in UTF-16 code units, as JS `String.length`.
fn u16len(s: &str) -> f64 {
    s.encode_utf16().count() as f64
}

fn specificity(pattern: &str) -> f64 {
    if pattern == "*" {
        0.0
    } else if let Some(p) = pattern.strip_suffix('*') {
        u16len(p)
    } else {
        u16len(pattern) + 1000.0 // exact beats any prefix
    }
}

fn num_of(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
}

/// A malformed ceiling sorts first (so the policy then denies instead of picking a lenient sibling); an absent ceiling is the most lenient.
fn strictness(c: &Map<String, Value>) -> f64 {
    match c.get("maxTaintForAuto") {
        None => f64::INFINITY,
        Some(v) => v.as_f64().filter(|n| !n.is_nan()).unwrap_or(f64::NEG_INFINITY),
    }
}

fn same_value_zero(a: &Value, b: Option<&Value>) -> bool {
    match (a, b) {
        (Value::Number(x), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (x, Some(y)) => x == y,
        _ => false,
    }
}

fn verb_matches(c: &Map<String, Value>, verb: Option<&Value>) -> Result<bool, String> {
    let vs = c.get("verbs");
    if !truthy(vs) {
        return Ok(true);
    }
    match vs {
        Some(Value::Array(list)) => Ok(list.iter().any(|x| same_value_zero(x, verb))),
        Some(Value::String(s)) => Ok(s.contains(&verb.map_or_else(|| "undefined".to_string(), js_str))),
        _ => Err("c.verbs.includes is not a function".into()),
    }
}

/// The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equally specific ones the strictest wins,
/// then the first listed.
fn class_for<'a>(classes: &'a [Value], verb: Option<&Value>, resource: Option<&Value>) -> Result<Option<&'a Map<String, Value>>, String> {
    let mut best: Option<&Map<String, Value>> = None;
    for cv in classes {
        let Some(c) = cv.as_object() else { return Err("Cannot read properties of a non-object class".into()) };
        if !matches(c.get("resource"), resource)? || !verb_matches(c, verb)? {
            continue;
        }
        let Some(b) = best else {
            best = Some(c);
            continue;
        };
        // the comparator `specificity(b) - specificity(a) || strictness(a) - strictness(b)`, a NaN reading as equal
        let spec = |m: &Map<String, Value>| m.get("resource").and_then(Value::as_str).map_or(0.0, specificity);
        let mut order = spec(b) - spec(c);
        if order == 0.0 || order.is_nan() {
            order = strictness(c) - strictness(b);
        }
        if order < 0.0 {
            best = Some(c);
        }
    }
    Ok(best)
}

fn is_num(v: Option<&Value>) -> bool {
    num_of(v).is_some_and(|n| !n.is_nan())
}

/// A ceiling that is present but not a number would make every `>` false and allow everything.
fn malformed(policy: &Map<String, Value>, cls: Option<&Map<String, Value>>) -> bool {
    match cls {
        Some(c) => {
            (c.contains_key("maxTaintForAuto") && !is_num(c.get("maxTaintForAuto"))) || (c.contains_key("hardDenyAbove") && !is_num(c.get("hardDenyAbove")))
        }
        None => policy.contains_key("defaultMaxTaintForAuto") && !is_num(policy.get("defaultMaxTaintForAuto")),
    }
}

fn result(outcome: &str, cls: Option<&Map<String, Value>>, reason: Option<String>) -> Value {
    let mut r = Map::new();
    r.insert("outcome".into(), json!(outcome));
    if let Some(name) = cls.and_then(|c| c.get("name")) {
        r.insert("class".into(), name.clone());
    }
    if let Some(reason) = reason {
        r.insert("reason".into(), Value::String(reason));
    }
    Value::Object(r)
}

/// Evaluate an action's data flow against the DLP policy. `ctx` is `{verb, resource, taint}`; a `taint` that is not a finite number is
/// treated as maximally tainted.
pub fn evaluate_dlp(policy: &Value, ctx: &Value) -> Result<Value, String> {
    let Some(p) = policy.as_object() else { return Ok(result("deny", None, Some("malformed DLP policy".into()))) };
    let Some(classes) = p.get("classes").and_then(Value::as_array) else { return Ok(result("deny", None, Some("malformed DLP policy".into()))) };
    let Some(cx) = ctx.as_object() else { return Err("Cannot read properties of a non-object context".into()) };
    let cls = class_for(classes, cx.get("verb"), cx.get("resource"))?;
    if malformed(p, cls) {
        return Ok(result("deny", cls, Some("malformed DLP policy: ceilings must be numbers".into())));
    }
    let max = match cls {
        Some(c) => c.get("maxTaintForAuto"),
        None => p.get("defaultMaxTaintForAuto"),
    };
    let finite_taint = num_of(cx.get("taint")).filter(|t| t.is_finite());
    let bad = finite_taint.is_none();
    let taint = finite_taint.unwrap_or(f64::INFINITY);
    // no ceiling at all: nothing to compare against, so even an unknown taint is unconstrained here
    let Some(max) = num_of(max) else { return Ok(result("allow", cls, None)) };
    let label = cls.and_then(|c| c.get("name")).filter(|n| !n.is_null()).map_or_else(|| "<default>".to_string(), js_str);
    if let Some(hard) = cls.and_then(|c| num_of(c.get("hardDenyAbove"))) {
        if bad || taint > hard {
            let why = format!("taint {} exceeds hard ceiling {} for '{}'", js_number_string(taint), js_number_string(hard), label);
            return Ok(result("deny", cls, Some(why)));
        }
    }
    if bad || taint > max {
        let why = format!("taint {} > {} for '{}' \u{2014} needs human review", js_number_string(taint), js_number_string(max), label);
        return Ok(result("step_up", cls, Some(why)));
    }
    Ok(result("allow", cls, None))
}

/// Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. `opts` is `{piiResource?, secretsResource?}`
/// (null is refused as in the reference).
pub fn default_dlp_policy(opts: &Value) -> Result<Value, String> {
    if opts.is_null() {
        return Err("Cannot read properties of null (reading 'piiResource')".into());
    }
    let mut classes = Vec::new();
    if let Some(r) = opts.get("piiResource").filter(|r| truthy(Some(r))) {
        classes.push(json!({ "name": "pii", "resource": r, "maxTaintForAuto": 0, "hardDenyAbove": 2 }));
    }
    if let Some(r) = opts.get("secretsResource").filter(|r| truthy(Some(r))) {
        classes.push(json!({ "name": "secrets", "resource": r, "maxTaintForAuto": 0, "hardDenyAbove": 0 }));
    }
    Ok(json!({ "classes": classes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(p: &Value, verb: &str, res: &str, taint: Value) -> Value {
        evaluate_dlp(p, &json!({ "verb": verb, "resource": res, "taint": taint })).unwrap()
    }

    #[test]
    fn example_policy_decisions() {
        let p = crate::control_evals::example_dlp_policy();
        assert_eq!(ev(&p, "gmail.send", "external:a@b", json!(0))["outcome"], "allow");
        let s = ev(&p, "gmail.send", "external:a@b", json!(2));
        assert_eq!(s["outcome"], "step_up");
        assert_eq!(s["reason"], "taint 2 > 0 for 'external-send' \u{2014} needs human review");
        let d = ev(&p, "gmail.send", "external:a@b", json!(5));
        assert_eq!(d["outcome"], "deny");
        assert_eq!(d["reason"], "taint 5 exceeds hard ceiling 3 for 'external-send'");
        assert_eq!(ev(&p, "gmail.draft", "draft:x", json!(9))["outcome"], "allow"); // no class matches, no default ceiling
        assert_eq!(ev(&p, "files.read", "secret:k", json!(1))["outcome"], "deny");
        // a non-finite or non-numeric taint is maximally tainted
        assert_eq!(ev(&p, "gmail.send", "external:a@b", Value::Null)["outcome"], "deny");
        assert_eq!(ev(&p, "gmail.send", "external:a@b", json!("0"))["outcome"], "deny");
    }

    #[test]
    fn malformed_and_specificity() {
        let ctx = json!({ "verb": "v", "resource": "r", "taint": 0 });
        assert_eq!(evaluate_dlp(&Value::Null, &ctx).unwrap()["reason"], "malformed DLP policy");
        let bad = json!({ "classes": [{ "name": "c", "resource": "*", "maxTaintForAuto": "0" }] });
        assert_eq!(evaluate_dlp(&bad, &ctx).unwrap()["reason"], "malformed DLP policy: ceilings must be numbers");
        let two = json!({ "classes": [
            { "name": "any", "resource": "*", "maxTaintForAuto": 9 },
            { "name": "db", "resource": "db:*", "maxTaintForAuto": 1 },
            { "name": "db-strict", "resource": "db:*", "maxTaintForAuto": 0 },
        ] });
        assert_eq!(ev(&two, "v", "db:x", json!(1))["class"], "db-strict");
    }

    #[test]
    fn preset() {
        let p = default_dlp_policy(&json!({ "piiResource": "customer:*", "secretsResource": "secret:*" })).unwrap();
        assert_eq!(p["classes"].as_array().unwrap().len(), 2);
        assert_eq!(default_dlp_policy(&json!({})).unwrap(), json!({ "classes": [] }));
        assert!(default_dlp_policy(&Value::Null).is_err());
    }
}
