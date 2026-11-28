//! `lift_legacy`: the total, conservative lift of the facade's `{permissions, limits}` input to a Goal + IR Ontology (`legacy.ts`).
//! The corrected semantics of the four facade bugs: `$200/day` is a SLIDING 86 400 000 ms sum bound (explicit window), not a
//! per-call ceiling plus a one-day grant lifetime; a `$` limit on a verb with no amount field is an error; every limit is its own
//! bound, so adding a limit only narrows (co-sign tiers are not part of the goal). Money parameters are integers in MINOR units
//! of USD (cents), the explicit unit the old facade left implicit.
use super::js::u16cmp;
use crate::facade::{compile_policy, parse_limit, ActionSpec, CompileOptions};
use serde_json::{json, Value};

const MAX_SAFE: i64 = 9007199254740991;

/// Inputs of [`lift_legacy`]; `None` members take the reference's defaults (no expiry, `notBefore` 0, empty request digest).
pub struct LiftOptions<'a> {
    pub permissions: &'a Value,
    pub limits: Option<&'a Value>,
    pub catalog: Option<&'a [ActionSpec]>,
    pub principal: &'a str,
    pub not_after: Option<i64>,
    pub not_before: Option<i64>,
    pub nl_digest: Option<&'a str>,
}

/// `Math.round`: ties toward +Infinity.
fn js_round(x: f64) -> f64 {
    let r = x.floor();
    if x - r >= 0.5 {
        r + 1.0
    } else {
        r
    }
}
fn is_safe(x: f64) -> bool {
    x.fract() == 0.0 && x.abs() <= MAX_SAFE as f64
}

/// `{goal, ontology}`; a refusal wherever the reference throws.
pub fn lift_legacy(o: &LiftOptions) -> Result<Value, String> {
    let usd = json!({"k": "money", "ccy": "USD"});
    let empty = serde_json::Map::new();
    let raw = match o.limits {
        None | Some(Value::Null) => &empty,
        Some(l) => l.as_object().ok_or("limits must be an object")?,
    };
    // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
    let specs =
        compile_policy(&CompileOptions { permissions: o.permissions, limits: None, catalog: o.catalog, budget_model: None, risk_policy: None, now: 0 })?
            .actions;
    let mut grants: Vec<Value> = Vec::new();
    let mut bounds: Vec<Value> = Vec::new();
    let mut verbs: Vec<(String, Value)> = Vec::new();
    for s in &specs {
        let gid = format!("g:{}", s.verb);
        let amount_path = s.amount_field.clone();
        let params = match &amount_path {
            Some(p) => json!([{"path": p, "ty": {"k": "q", "u": usd}}]),
            None => json!([]),
        };
        verbs.push((s.verb.clone(), json!({"verb": s.verb, "cls": s.reversibility, "params": params})));
        let resource = s.resource.clone().unwrap_or_else(|| "*".to_string());
        if (resource.contains('*') || resource.contains('?') || resource.starts_with("re:")) && resource != "*" {
            return Err(format!("liftLegacy: resource pattern '{resource}' of {} is not expressible; name exact resources or acknowledge a wildcard", s.verb));
        }
        // `own(verb) ?? own(action)`: an own member, a JSON null counts as absent unless it is the last name tried
        let raw_limit = match raw.get(&s.verb) {
            None | Some(Value::Null) => raw.get(&s.action),
            some => some,
        };
        let mut cond = json!({"k": "true"});
        if let Some(rl) = raw_limit {
            let lim = parse_limit(rl.as_str().ok_or("parseLimit: limit must be a string")?)?;
            if lim.unit == "usd" {
                let path = amount_path.clone().ok_or_else(|| {
                    format!("liftLegacy: '$' limit on '{}' but the catalog gives that verb no amount field, so the limit could not be enforced", s.verb)
                })?;
                let minor = js_round(lim.amount * 100.0);
                if !is_safe(minor) {
                    return Err(format!("liftLegacy: limit for {} is out of range", s.verb));
                }
                let minor = minor as i64;
                let amt = json!({"k": "param", "path": path, "ty": {"k": "q", "u": usd}});
                cond = json!({"k": "and",
                    "a": {"k": "cmp", "op": "gte", "l": amt, "r": {"k": "lit", "v": {"k": "q", "q": {"u": usd, "n": 0}}}},
                    "b": {"k": "cmp", "op": "lte", "l": amt, "r": {"k": "lit", "v": {"k": "q", "q": {"u": usd, "n": minor}}}}});
                if let Some(ms) = lim.period_ms {
                    bounds.push(json!({"bid": format!("b:{}", s.verb), "sel": {"k": "gids", "gids": [gid]}, "agg": "sum", "value": amt, "key": "",
                        "window": {"k": "sliding", "ms": ms}, "scope": {"k": "session"}, "cap": {"u": usd, "n": minor}, "onExceed": "deny"}));
                }
            } else {
                if !is_safe(lim.amount) {
                    return Err(format!("liftLegacy: count limit for {} must be a whole number", s.verb));
                }
                let window = match lim.period_ms {
                    Some(ms) => json!({"k": "sliding", "ms": ms}),
                    None => json!({"k": "lifetime"}),
                };
                bounds.push(json!({"bid": format!("b:{}", s.verb), "sel": {"k": "gids", "gids": [gid]}, "agg": "count",
                    "value": {"k": "lit", "v": {"k": "q", "q": {"u": {"k": "count"}, "n": 1}}}, "key": "", "window": window,
                    "scope": {"k": "session"}, "cap": {"u": {"k": "count"}, "n": lim.amount as i64}, "onExceed": "deny"}));
            }
        }
        let res =
            if resource == "*" { json!({"k": "any", "reason": "legacy default: no resource scope given"}) } else { json!({"k": "exact", "id": resource}) };
        grants.push(json!({"gid": gid, "verb": s.verb, "res": res, "cond": cond}));
    }
    let key = |v: &Value, f: &str| v[f].as_str().unwrap_or("").to_string();
    grants.sort_by(|a, b| u16cmp(&key(a, "gid"), &key(b, "gid")));
    bounds.sort_by(|a, b| u16cmp(&key(a, "bid"), &key(b, "bid")));
    for i in 1..grants.len() {
        if grants[i]["gid"] == grants[i - 1]["gid"] {
            return Err(format!("liftLegacy: duplicate grant {}", key(&grants[i], "gid")));
        }
    }
    let gids: Vec<Value> = grants.iter().map(|g| g["gid"].clone()).collect();
    let wildcard: Vec<Value> = grants.iter().filter(|g| g["res"]["k"] == "any").map(|g| g["gid"].clone()).collect();
    let goal = json!({
        "v": 1, "principal": o.principal, "ontDigest": "legacy-catalog", "nlDigest": o.nl_digest.unwrap_or(""), "sources": [],
        "grants": grants, "prohibits": [], "bounds": bounds,
        "validity": {"notBefore": o.not_before.unwrap_or(0), "notAfter": o.not_after.unwrap_or(MAX_SAFE), "maxIdle": 0},
        "deleg": {"maxDepth": 16, "narrowOnly": true, "mayTouch": gids},
        "escalateOn": [], "wildcardAck": wildcard, "holes": []});
    verbs.sort_by(|a, b| u16cmp(&a.0, &b.0));
    let mut deduped: Vec<Value> = Vec::new();
    for (i, (name, v)) in verbs.iter().enumerate() {
        if i == 0 || verbs[i - 1].0 != *name {
            deduped.push(v.clone());
        }
    }
    Ok(json!({"goal": goal, "ontology": {"verbs": deduped, "rels": []}}))
}
