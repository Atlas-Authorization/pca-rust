//! The grounding half of NL to policy (packages/pca/src/nl.ts): the prompt that confines a model to the catalog's verbs
//! (`nl_prompt`), the strict parse that GROUNDS its answer against the catalog (`parse_nl_policy`: it never fails on model garbage;
//! hallucinated verbs and unusable limits are dropped and reported), and the NL-facade compiler of the intent panel
//! (`compile_nl_facade`). The model itself is injected by the caller as the raw string it answered; nothing here trusts it.
use crate::facade::{builtin_catalog, compile_policy, parse_limit, ActionSpec, CompileOptions};
use serde_json::{json, Map, Value};

/// The catalogued spec of `connector.action`: the exact verb (a later entry overrides an earlier one), else an alias that names exactly one
/// action of this connector. `None` for a verb the catalog does not define.
pub fn catalog_lookup<'a>(catalog: &'a [ActionSpec], connector: &str, action: &str) -> Option<&'a ActionSpec> {
    let verb = format!("{connector}.{action}");
    if let Some(s) = catalog.iter().rev().find(|s| s.verb == verb) {
        return Some(s);
    }
    let mut by_verb: Vec<&ActionSpec> = vec![];
    for s in catalog {
        match by_verb.iter().position(|x| x.verb == s.verb) {
            Some(i) => by_verb[i] = s,
            None => by_verb.push(s),
        }
    }
    let hits: Vec<&&ActionSpec> = by_verb.iter().filter(|s| s.connector == connector && s.aliases.iter().any(|a| a == action)).collect();
    (hits.len() == 1).then(|| *hits[0])
}

/// `nlPrompt`: the grounding prompt: the model may only use verbs the catalog actually defines.
pub fn nl_prompt(instruction: &str, catalog: &[ActionSpec]) -> String {
    let verbs: Vec<String> = catalog
        .iter()
        .map(|s| {
            let amount = s.amount_field.as_ref().map(|a| format!(", amount field \"{a}\"")).unwrap_or_default();
            let also = if s.aliases.is_empty() { String::new() } else { format!(", also called: {}", s.aliases.join(", ")) };
            format!("  - {} ({}{amount}{also}): {}", s.verb, s.reversibility, s.description)
        })
        .collect();
    [
        "You translate an instruction into a strict JSON agent policy. Output ONLY JSON, no prose, no code fence.".to_string(),
        "Shape: {\"permissions\":{\"<connector>\":[\"<action>\",...]},\"limits\":{\"<action-or-verb>\":\"$<amount>/<period>\"|\"<count>/<period>\"}}"
            .to_string(),
        "Rules: use ONLY the verbs below (connector.action). A limit key is a bare action (e.g. \"refund\") or a full verb (e.g. \"stripe.refund\")."
            .to_string(),
        "Monetary limits start with \"$\"; plain numbers are counts. Periods: hour, day, week, month. Omit limits you are unsure about.".to_string(),
        String::new(),
        "Available verbs:".to_string(),
        verbs.join("\n"),
        String::new(),
        format!("Instruction: {instruction}"),
        "JSON:".to_string(),
    ]
    .join("\n")
}

/// The outermost brace span (drops a code fence and any prose on either side).
fn strip_fence(raw: &str) -> &str {
    let t = raw.trim_matches(|c: char| crate::action_schema::is_js_ws(c));
    match (t.find('{'), t.rfind('}')) {
        (Some(i), Some(j)) if j >= i => &t[i..=j],
        _ => t,
    }
}

/// `parseNLPolicy`: `{permissions, limits, unknownVerbs, droppedLimits}`. Strictly parses the model's JSON and GROUNDS it against the
/// catalog; never fails on garbage (it returns the empty result).
pub fn parse_nl_policy(raw: &str, catalog: &[ActionSpec]) -> Value {
    let (mut permissions, mut limits) = (Map::new(), Map::new());
    let (mut unknown, mut dropped): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    let result = |p: Map<String, Value>, l: Map<String, Value>, u: Vec<Value>, d: Vec<Value>| json!({"permissions": p, "limits": l, "unknownVerbs": u, "droppedLimits": d});
    let Ok(obj) = serde_json::from_str::<Value>(strip_fence(raw)) else { return result(permissions, limits, unknown, dropped) };
    if !(obj.is_object() || obj.is_array()) {
        return result(permissions, limits, unknown, dropped);
    }
    // Object.entries: an array's elements by index
    let entries = |v: &Value| -> Vec<(String, Value)> {
        match v {
            Value::Object(m) => m.iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
            Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
            _ => vec![],
        }
    };
    if let Some(perms) = obj.get("permissions").filter(|p| p.is_object() || p.is_array()) {
        for (connector, actions) in &entries(perms) {
            let Some(actions) = actions.as_array() else { continue };
            for action in actions.iter().filter_map(Value::as_str) {
                let verb = format!("{connector}.{action}");
                match catalog_lookup(catalog, connector, action) {
                    Some(spec) => {
                        let stored = if spec.connector == *connector { spec.action.clone() } else { action.to_string() };
                        let list = permissions.entry(connector.clone()).or_insert_with(|| json!([]));
                        list.as_array_mut().map(|l| l.push(json!(stored)));
                    }
                    None => unknown.push(json!(verb)),
                }
            }
        }
    }
    // dedupe actions per connector, keeping first-seen order
    for list in permissions.values_mut() {
        let mut seen: Vec<Value> = vec![];
        for a in list.as_array().into_iter().flatten() {
            if !seen.contains(a) {
                seen.push(a.clone());
            }
        }
        *list = Value::Array(seen);
    }
    let mut granted: Vec<String> = vec![];
    for (c, acts) in &permissions {
        for a in acts.as_array().into_iter().flatten().filter_map(Value::as_str) {
            granted.push(format!("{c}.{a}"));
            granted.push(a.to_string());
            if let Some(spec) = catalog.iter().rev().find(|s| s.verb == format!("{c}.{a}")) {
                granted.extend(spec.aliases.iter().cloned());
            }
        }
    }
    if let Some(lims) = obj.get("limits").filter(|l| l.is_object() || l.is_array()) {
        for (key, spec) in &entries(lims) {
            match spec.as_str() {
                Some(s) if parse_limit(s).is_ok() && granted.contains(key) => {
                    limits.insert(key.clone(), json!(s));
                }
                _ => dropped.push(json!(key)),
            }
        }
    }
    result(permissions, limits, unknown, dropped)
}

/// The kept caveats of a compiled policy: only `reversibility_max` is part of the outcome space.
fn measurable(c: &[Value]) -> Vec<Value> {
    c.iter().filter(|x| x.get("type").and_then(Value::as_str) == Some("reversibility_max")).cloned().collect()
}

/// `nlFacadeCompiler`'s `compile` over the model's answer `raw`: ground it against `catalog` (the built-in one by default), compile it through the facade
/// path the verifier enforces, and keep what the outcome space measures. `{compiler, family, policy, notes, raw}`.
pub fn compile_nl_facade(id: &str, family: &str, raw: &str, catalog: &[ActionSpec]) -> Result<Value, String> {
    let parsed = parse_nl_policy(raw, catalog);
    let strs = |k: &str, fmt: &str| -> Vec<Value> {
        parsed[k].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| json!(format!("{fmt}{s}"))).collect()
    };
    let mut notes = strs("unknownVerbs", "unknown verb dropped: ");
    notes.extend(strs("droppedLimits", "limit dropped: "));
    if parsed["permissions"].as_object().is_none_or(Map::is_empty) {
        notes.push(json!("no grantable permission"));
        return Ok(json!({"compiler": id, "family": family, "policy": {"predicates": [], "caveats": []}, "notes": notes, "raw": raw}));
    }
    let cp = compile_policy(&CompileOptions {
        permissions: &parsed["permissions"],
        limits: Some(&parsed["limits"]),
        catalog: Some(&catalog),
        budget_model: None,
        risk_policy: None,
        now: 0,
    })?;
    for c in cp.caveats.iter().filter(|c| c.get("type").and_then(Value::as_str) != Some("reversibility_max")) {
        notes.push(json!(format!(
            "caveat outside \u{3a9} not measured: {}",
            c.get("type").map(crate::intent_v2::js_value_string).unwrap_or_else(|| "undefined".into())
        )));
    }
    Ok(json!({"compiler": id, "family": family, "policy": {"predicates": cp.predicates, "caveats": measurable(&cp.caveats)}, "notes": notes, "raw": raw}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_lists_the_catalog_and_the_parse_grounds_the_answer() {
        let cat = builtin_catalog();
        let p = nl_prompt("refund up to $200/day", &cat);
        assert!(p.contains("Available verbs:\n  - ") && p.ends_with("Instruction: refund up to $200/day\nJSON:"));
        let raw = "```json\n{\"permissions\":{\"stripe\":[\"refund\",\"refund\",\"nuke\"],\"zzz\":[\"x\"]},\"limits\":{\"refund\":\"$200/day\",\"nuke\":\"5/day\",\"refund2\":3}}\n```";
        let r = parse_nl_policy(raw, &cat);
        assert_eq!(r["permissions"], json!({"stripe": ["refund"]}));
        assert_eq!(r["limits"], json!({"refund": "$200/day"}));
        assert_eq!(r["unknownVerbs"], json!(["stripe.nuke", "zzz.x"]));
        assert_eq!(r["droppedLimits"], json!(["nuke", "refund2"]));
        for garbage in ["", "not json", "5", "null", "[1]", "{\"permissions\": 7}"] {
            assert_eq!(parse_nl_policy(garbage, &cat)["permissions"], json!({}), "{garbage}");
        }
    }

    #[test]
    fn the_facade_compiler_grants_only_what_grounds() {
        let ok = compile_nl_facade("m", "f", r#"{"permissions":{"stripe":["refund"]},"limits":{"refund":"$200/day"}}"#, &builtin_catalog()).unwrap();
        assert_eq!(ok["compiler"], "m");
        assert!(ok["policy"]["predicates"].as_array().is_some_and(|p| !p.is_empty()));
        let none = compile_nl_facade("m", "f", r#"{"permissions":{"zzz":["x"]}}"#, &builtin_catalog()).unwrap();
        assert_eq!(none["policy"], json!({"predicates": [], "caveats": []}));
        assert_eq!(none["notes"], json!(["unknown verb dropped: zzz.x", "no grantable permission"]));
    }
}
