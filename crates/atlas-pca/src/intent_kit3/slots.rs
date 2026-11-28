//! Structured intent slots compiled into the policy they literally describe (`slots.ts`).
use serde_json::{json, Map, Value};

fn present<'a>(sc: &'a Value, k: &str) -> Option<&'a Value> {
    sc.get(k)
}

fn truthy_list(sc: &Value, k: &str) -> Option<Value> {
    match sc.get(k) {
        Some(Value::Array(a)) if !a.is_empty() => Some(Value::Array(a.clone())),
        Some(v) if !v.is_null() && !v.is_array() && crate::wallet_omega::truthy(v) => Some(v.clone()),
        _ => None,
    }
}

fn slot_conds(sc: &Value) -> Result<Vec<Value>, String> {
    let p = sc.get("path").cloned().ok_or("slots: constraint without a path")?;
    let mut out = vec![];
    if let Some(m) = present(sc, "min") {
        out.push(json!({ "field": p, "op": "gte", "value": m }));
    }
    if let Some(m) = present(sc, "max") {
        out.push(json!({ "field": p, "op": "lte", "value": m }));
    }
    let mut any_of = vec![];
    if let Some(v) = truthy_list(sc, "oneOf") {
        any_of.push(json!({ "field": p, "op": "in", "value": v }));
    }
    match sc.get("prefixOneOf") {
        Some(Value::Array(a)) => {
            for x in a {
                any_of.push(json!({ "field": p, "op": "prefix", "value": x }));
            }
        }
        Some(Value::Null) | None => {}
        Some(_) => return Err("slots: prefixOneOf must be a list".into()),
    }
    match any_of.len() {
        0 => {}
        1 => out.push(any_of.remove(0)),
        _ => out.push(json!({ "any_of": any_of })),
    }
    if let Some(v) = truthy_list(sc, "noneOf") {
        out.push(json!({ "field": p, "op": "nin", "value": v }));
    }
    Ok(out)
}

/// One predicate per slot verb: `{predicates, caveats: []}`.
pub fn slots_to_policy(slots: &Value) -> Result<Value, String> {
    let verbs = slots.get("verbs").and_then(Value::as_array).ok_or("slots: verbs must be a list")?;
    let cons = slots.get("constraints").and_then(Value::as_array).ok_or("slots: constraints must be a list")?;
    let mut preds = vec![];
    for verb in verbs {
        let mut where_ = vec![];
        for c in cons {
            if present(c, "verb").is_none() || c.get("verb") == Some(verb) {
                where_.extend(slot_conds(c)?);
            }
        }
        let mut pr = Map::new();
        pr.insert("verb".into(), verb.clone());
        pr.insert("resource".into(), json!("*"));
        if !where_.is_empty() {
            pr.insert("where".into(), Value::Array(where_));
        }
        preds.push(Value::Object(pr));
    }
    Ok(json!({ "predicates": preds, "caveats": [] }))
}
