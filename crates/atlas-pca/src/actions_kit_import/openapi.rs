//! OpenAPI 3.x and Swagger 2 to drafts: one def per operation, parameters from path / query / body (nested bodies flattened to dotted
//! names), the method giving the initial effects. `x-` extensions are ignored unless allow-listed. Every draft is `unreviewed`.

use super::common::*;
use crate::action_schema::is_js_ws;
use crate::actions::utf16_len;
use serde_json::{Map, Value};

const METHODS: [&str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
const BODY_TYPES: [&str; 3] = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"];

fn effect_of(m: &str) -> &'static [&'static str] {
    match m {
        "get" | "head" | "options" | "trace" => &["read"],
        "post" => &["create"],
        "put" | "patch" => &["update"],
        _ => &["delete"],
    }
}
fn natural(m: &str) -> bool {
    matches!(m, "get" | "head" | "options" | "trace" | "put" | "delete")
}

/// `(v[0-9]+(\.[0-9]+)?|api|rest|public|latest)` fullmatch, ASCII case-insensitive.
fn versionish(sg: &str) -> bool {
    let l = sg.to_ascii_lowercase();
    if matches!(l.as_str(), "api" | "rest" | "public" | "latest") {
        return true;
    }
    let Some(r) = l.strip_prefix('v') else { return false };
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    match r.split_once('.') {
        Some((a, b)) => digits(a) && digits(b),
        None => digits(r),
    }
}

/// `\{[^\n\r  ]+\}` fullmatch.
fn param_seg_shape(sg: &str) -> bool {
    sg.len() >= 3 && sg.starts_with('{') && sg.ends_with('}') && !sg[1..sg.len() - 1].contains(['\n', '\r', '\u{2028}', '\u{2029}'])
}

fn path_facts(path: &str) -> (Vec<String>, bool) {
    let segs: Vec<&str> = path.split('/').filter(|x| !x.is_empty()).collect();
    let ends = segs.last().is_some_and(|l| param_seg_shape(l));
    let nouns = segs.iter().filter(|sg| !sg.contains('{') && !sg.contains('}') && !versionish(sg)).flat_map(|sg| tokens_of(sg)).collect();
    (nouns, ends)
}

/// The object a `$ref` chain ends at (an array is possible: callers read members through `g`); None when it does not resolve.
fn deref(c: &mut Ctx, x: &Value, where_: &str) -> Option<Value> {
    if !is_obj(x) {
        return None;
    }
    if !g(x, "$ref").is_some_and(is_str) {
        return Some(x.clone());
    }
    let mut seen: Vec<String> = vec![];
    let mut cur = x.clone();
    while let Some(r) = g(&cur, "$ref").and_then(Value::as_str).map(String::from) {
        if seen.contains(&r) || (seen.len() as i64) > c.lim.max_ref_depth {
            add_todo(c, where_, "cyclic_ref", "a reference chain is cyclic or too deep");
            return None;
        }
        seen.push(r.clone());
        let Some(t) = pointer(&c.root, &Value::String(r.clone())).cloned() else {
            add_todo(c, where_, "unresolved_ref", &format!("reference '{}' does not resolve locally", clip(&r, 120)));
            return None;
        };
        cur = t;
    }
    Some(cur)
}

fn swagger2_param(p: &Map<String, Value>) -> Map<String, Value> {
    if p.contains_key("schema") || p.get("in").and_then(Value::as_str) == Some("body") {
        return p.clone();
    }
    let skip = ["name", "in", "required", "description"];
    let mut out: Map<String, Value> = skip.iter().filter_map(|k| p.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
    let rest: Map<String, Value> = p.iter().filter(|(k, _)| !skip.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    out.insert("schema".into(), Value::Object(rest));
    out
}

fn json_plus(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    l.strip_prefix("application/").is_some_and(|rest| rest.split(';').next().unwrap_or("").ends_with("+json"))
}

/// The request body schema (`Some(Null)` is a declared null schema; `None` is undefined).
fn body_schema(c: &mut Ctx, op: &Value, params: &[Map<String, Value>], swagger: bool, where_: &str) -> Option<Value> {
    if swagger {
        for q in params {
            if q.get("in").and_then(Value::as_str) == Some("body") {
                return q.get("schema").cloned();
            }
        }
        return None;
    }
    let rb = g(op, "requestBody").and_then(|x| deref(c, x, where_));
    let content = go(rb.as_ref(), "content")?;
    let cm = content.as_object()?;
    let keys = sorted_keys(cm);
    let mut pick: Option<&String> = None;
    for t in BODY_TYPES {
        pick = keys.iter().find(|k| k.to_lowercase().split(';').next().unwrap_or("").trim_matches(is_js_ws) == t);
        if pick.is_some() {
            break;
        }
    }
    if pick.is_none() {
        pick = keys.iter().find(|k| json_plus(k));
    }
    let Some(pick) = pick else {
        if !keys.is_empty() {
            let shown: Vec<String> = keys.iter().take(3).map(|k| clip(k, 40)).collect();
            add_todo(c, where_, "body_type", &format!("request body media types ({}) are not form or JSON; the body is not declared", shown.join(", ")));
        }
        return None;
    };
    g(&cm[pick], "schema").cloned()
}

fn pkey(q: &Map<String, Value>) -> String {
    format!("{}:{}", q["in"].as_str().unwrap_or(""), q["name"].as_str().unwrap_or(""))
}

pub fn import_openapi(source: &Value, opts: &Value) -> R<Value> {
    let mut c = new_ctx("openapi", Source::Json(source), opts)?;
    if !is_obj(source) {
        return Err(kerr("bad_source", "an OpenAPI document must be an object"));
    }
    let swagger = gstr(source, "swagger").is_some_and(|t| t.starts_with('2'));
    let v3 = gstr(source, "openapi").is_some_and(|t| t.starts_with("3."));
    if !swagger && !v3 {
        return Err(kerr("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')"));
    }
    let empty = Map::new();
    let paths = match g(source, "paths") {
        Some(Value::Object(p)) => p,
        _ => &empty,
    };
    let global_security: Option<&Vec<Value>> = g(source, "security").and_then(Value::as_array);
    for path in sorted_keys(paths) {
        let Some(item0) = deref(&mut c, &paths[&path], &path) else { continue };
        let shared: Vec<Value> = g(&item0, "parameters").and_then(Value::as_array).cloned().unwrap_or_default();
        for method in METHODS {
            let Some(op) = g(&item0, method).filter(|o| is_obj(o)).cloned() else { continue };
            let where_ = format!("{} {}", method.to_uppercase(), clip(&path, 120));
            let operation_id: Option<String> = gstr(&op, "operationId").filter(|t| utf16_len(t) > 0 && utf16_len(t) <= 200).map(String::from);
            let (nouns, ends) = path_facts(&path);
            let name_raw: Option<&str> = if c.ext.contains("x-pca-verb") { gstr(&op, "x-pca-verb") } else { None };
            let verb: String = match (name_raw, &operation_id) {
                (Some(n), _) if is_verb(n) && n.starts_with(&format!("{}.", c.ns)) => n.to_string(),
                (_, Some(id)) => verb_of_str(&c.ns, id),
                _ => {
                    let tail = if method == "get" && !ends { "list" } else { method };
                    let mut words: Vec<&str> = nouns.iter().rev().take(2).rev().map(String::as_str).collect();
                    words.push(tail);
                    verb_of_str(&c.ns, &words.join(" "))
                }
            };
            let mut bud = new_budget(&c);
            let mut merged: Map<String, Value> = Map::new();
            let own_params: Vec<Value> = g(&op, "parameters").and_then(Value::as_array).cloned().unwrap_or_default();
            for raw in shared.iter().chain(own_params.iter()) {
                let Some(q0) = deref(&mut c, raw, &where_) else { continue };
                let Some(q0m) = q0.as_object() else { continue };
                if !q0m.get("name").is_some_and(is_str) || !q0m.get("in").is_some_and(is_str) {
                    continue;
                }
                let q = if swagger { swagger2_param(q0m) } else { q0m.clone() };
                merged.insert(pkey(&q), Value::Object(q));
            }
            let allp: Vec<Map<String, Value>> = merged.values().filter_map(|v| v.as_object().cloned()).collect();
            let mut params: Map<String, Value> = Map::new();
            let mut idem_param: Option<String> = None;
            if let Some(body) = body_schema(&mut c, &op, &allp, swagger, &where_) {
                let b = resolve(&body, &mut c, &mut bud, &format!("{where_}: request body"))?;
                if b.get("type").and_then(Value::as_str) == Some("object") || matches!(b.get("properties"), Some(Value::Object(_))) {
                    flatten_object(&b, &mut c, &mut bud, &where_, &mut params, &[], true)?;
                } else {
                    add_todo(&mut c, &where_, "body_shape", "the request body is not an object schema; it is not declared");
                }
            }
            let mut sorted_p = allp.clone();
            sorted_p.sort_by(|a, b| pkey(a).as_bytes().cmp(pkey(b).as_bytes()));
            for q in &sorted_p {
                let name = q["name"].as_str().unwrap_or("").to_string();
                let loc = q["in"].as_str().unwrap_or("").to_string();
                if loc == "header" && name.to_ascii_lowercase() == "idempotency-key" {
                    idem_param = Some("idempotency_key".into());
                    continue;
                }
                if loc == "body" {
                    continue;
                }
                if !matches!(loc.as_str(), "path" | "query" | "formData") {
                    add_todo(
                        &mut c,
                        &where_,
                        "param_location",
                        &format!("{} parameter '{}' is not an action parameter (path, query and body only)", clip(&loc, 12), clip(&name, 60)),
                    );
                    continue;
                }
                let sname = param_seg(&name);
                if sname != name {
                    add_todo(&mut c, &format!("{where_}: {name}"), "renamed_param", &format!("parameter '{}' is declared as '{sname}'", clip(&name, 80)));
                }
                if params.contains_key(&sname) || params.keys().any(|k| k.starts_with(&format!("{sname}."))) {
                    add_todo(
                        &mut c,
                        &format!("{where_}: {name}"),
                        "skipped_param",
                        &format!("'{sname}' is declared by the body and by a {loc} parameter; kept the body's"),
                    );
                    continue;
                }
                if params.len() >= 64 {
                    add_todo(&mut c, &where_, "too_many_params", "more than 64 parameters; the rest are dropped");
                    break;
                }
                let sq: Value = match q.get("schema") {
                    None | Some(Value::Null) => Value::Object(Map::new()),
                    Some(x) => x.clone(),
                };
                let qd = q.get("description");
                let mut spread = spread_obj(Some(&sq));
                if jtruthy(qd) && !jtruthy(g(&sq, "description")) {
                    spread.insert("description".into(), qd.cloned().unwrap_or(Value::Null));
                }
                let sch = resolve(&Value::Object(spread), &mut c, &mut bud, &format!("{where_}: {name}"))?;
                let required = loc == "path" || is_true(q.get("required"));
                let p = leaf_param(&sch, required, &mut c, &mut bud, &format!("{where_}: {name}"))?;
                params.insert(sname, Value::Object(p));
            }
            match &idem_param {
                Some(ip) if !params.contains_key(ip) => {
                    params.insert(ip.clone(), serde_json::json!({"type": "string", "required": false, "max_len": 255}));
                }
                _ => idem_param = None,
            }
            let scope = if ends || method == "post" { "one" } else { "set" };
            let sec: Option<Vec<Value>> = match g(&op, "security") {
                Some(Value::Array(a)) => Some(a.clone()),
                _ => global_security.cloned(),
            };
            let mut scope_set: Vec<String> = vec![];
            for r in sec.iter().flatten() {
                if let Value::Object(rm) = r {
                    for v in rm.values() {
                        if let Value::Array(xs) = v {
                            scope_set.extend(xs.iter().filter_map(|x| x.as_str().map(String::from)));
                        }
                    }
                }
            }
            scope_set.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            scope_set.dedup();
            if !scope_set.is_empty() {
                let shown: Vec<String> = scope_set.iter().take(12).map(|x| clip(x, 60)).collect();
                add_todo(&mut c, &where_, "required_scope", &format!("requires scope: {}", shown.join(", ")));
            }
            if is_true(g(&op, "deprecated")) {
                add_todo(&mut c, &where_, "deprecated", "the operation is marked deprecated");
            }
            if let Some(opm) = op.as_object() {
                let hit = opm.keys().find(|k| k.starts_with("x-") && !c.ext.contains(k.as_str())).cloned();
                if let Some(k) = hit {
                    add_todo(&mut c, &where_, "extension_ignored", &format!("extension '{}' is ignored (not allow-listed)", clip(&k, 60)));
                }
            }
            let summary = g(&op, "summary");
            let desc = g(&op, "description");
            let name = operation_id.clone().unwrap_or_else(|| where_.clone());
            let binding_id = operation_id.clone().unwrap_or_else(|| clip(&format!("{method}_{path}"), 200));
            let bindings = serde_json::json!({"openapi": {"operationId": binding_id, "method": method.to_uppercase(), "path": clip(&path, 240)}});
            let title_v: Option<Value> = match summary {
                Some(Value::String(t)) if !t.is_empty() => Some(Value::String(t.clone())),
                _ => operation_id.clone().map(Value::String),
            };
            let desc_v: Option<&Value> = match (desc, summary) {
                (Some(d), _) if d.is_string() => Some(d),
                (_, Some(sm)) if sm.is_string() => Some(sm),
                _ => None,
            };
            let idempotency = match &idem_param {
                Some(ip) => Some(serde_json::json!({"mode": "key_param", "param": ip})),
                None if natural(method) => Some(serde_json::json!({"mode": "natural"})),
                None => None,
            };
            let eo = EmitOpts { verb: Some(verb), title: title_v.as_ref(), description: desc_v, idempotency, traits: None, no_alias: operation_id.is_none() };
            emit_def(&mut c, &name, effect_of(method), scope, params, bindings, eo)?;
        }
    }
    Ok(finish(c))
}
