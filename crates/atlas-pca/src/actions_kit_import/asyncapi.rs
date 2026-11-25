//! AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect `send`, receiving is `read`; the message payload becomes the params. A
//! broker publish leaves the trust domain, so it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`.

use super::common::*;
use serde_json::{Map, Value};

fn deref(c: &mut Ctx, x: Option<&Value>, where_: &str, depth: i64) -> Option<Value> {
    let x = x?;
    if !is_obj(x) {
        return None;
    }
    let Some(r) = gstr(x, "$ref") else { return Some(x.clone()) };
    if depth > c.lim.max_ref_depth {
        add_todo(c, where_, "ref_depth", "a reference chain is too deep");
        return None;
    }
    let Some(t) = pointer(&c.root, &Value::String(r.to_string())).cloned() else {
        add_todo(c, where_, "unresolved_ref", &format!("reference '{}' does not resolve locally", clip(r, 120)));
        return None;
    };
    deref(c, Some(&t), where_, depth + 1)
}

fn payload_params(c: &mut Ctx, msgs: &[Value], where_: &str, params: &mut Map<String, Value>, bud: &mut Budget) -> R<()> {
    let mut resolved: Vec<Value> = vec![];
    for m in msgs {
        if let Some(r) = deref(c, Some(m), where_, 0) {
            resolved.push(r);
        }
    }
    if resolved.is_empty() {
        return Ok(());
    }
    if resolved.len() > 1 {
        add_todo(c, where_, "message_variants", &format!("{} message variants: only the first is declared", resolved.len()));
    }
    let Some(payload) = g(&resolved[0], "payload") else { return Ok(()) };
    let sch = resolve(payload, c, bud, &format!("{where_}: payload"))?;
    if sch.get("type").and_then(Value::as_str) == Some("object") || matches!(sch.get("properties"), Some(Value::Object(_))) {
        flatten_object(&sch, c, bud, where_, params, &[], true)?;
    } else {
        add_todo(c, where_, "payload_shape", "the message payload is not an object schema; it is not declared");
    }
    Ok(())
}

fn channel_params(c: &mut Ctx, ch: &Value, where_: &str, params: &mut Map<String, Value>) {
    let Some(ps) = deref(c, g(ch, "parameters"), where_, 0) else { return };
    let Some(pm) = ps.as_object() else { return };
    for name in sorted_keys(pm) {
        let sg = param_seg(&name);
        if params.contains_key(&sg) {
            continue;
        }
        params.insert(sg, serde_json::json!({"type": "string", "max_len": 256}));
    }
}

fn internal(c: &Ctx, ch: &Value) -> bool {
    c.ext.contains("x-pca-internal") && is_true(g(ch, "x-pca-internal"))
}

fn emit(c: &mut Ctx, op_name: Option<&str>, ch_name: &str, ch: &Value, action: &str, op: &Value, msgs: &[Value]) -> R<()> {
    let where_ = format!("{action} {}", clip(ch_name, 100));
    let mut bud = new_budget(c);
    let mut params: Map<String, Value> = Map::new();
    channel_params(c, ch, &where_, &mut params);
    payload_params(c, msgs, &where_, &mut params, &mut bud)?;
    let effects: &[&str] = if action == "receive" {
        &["read"]
    } else if internal(c, ch) {
        &["create"]
    } else {
        &["send"]
    };
    let eo = EmitOpts {
        verb: if op_name.is_none() { Some(verb_of_str(&c.ns, &format!("{ch_name} {action}"))) } else { None },
        title: g(op, "summary").filter(|v| v.is_string()),
        description: g(op, "description").filter(|v| v.is_string()),
        idempotency: None,
        traits: None,
        no_alias: op_name.is_none(),
    };
    let name = op_name.map(String::from).unwrap_or_else(|| where_.clone());
    emit_def(c, &name, effects, "one", params, serde_json::json!({"asyncapi": {"channel": clip(ch_name, 250), "op": action}}), eo)?;
    Ok(())
}

pub fn import_asyncapi(source: &Value, opts: &Value) -> R<Value> {
    let mut c = new_ctx("asyncapi", Source::Json(source), opts)?;
    let ver = gstr(source, "asyncapi").filter(|t| t.starts_with("2.") || t.starts_with("3."));
    let Some(ver) = ver else {
        return Err(kerr("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')"));
    };
    let v3 = ver.starts_with('3');
    let empty = Map::new();
    if v3 {
        let ops = match g(source, "operations") {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        for oid in sorted_keys(ops) {
            let op = deref(&mut c, Some(&ops[&oid]), &oid, 0);
            let action = op.as_ref().and_then(|o| gstr(o, "action")).filter(|a| *a == "send" || *a == "receive").map(String::from);
            let (Some(op), Some(action)) = (op, action) else {
                add_todo(&mut c, &oid, "skipped_op", "an operation without action send|receive is skipped");
                continue;
            };
            let chan = g(&op, "channel").cloned();
            let Some(ch_ref) = deref(&mut c, chan.as_ref(), &oid, 0) else { continue };
            let ch_name: String = match gstr(&ch_ref, "address") {
                Some(a) => a.to_string(),
                None => match chan.as_ref().and_then(|ch| gstr(ch, "$ref")) {
                    Some(r) => r.rsplit('/').next().unwrap_or("").to_string(),
                    None => oid.clone(),
                },
            };
            let msgs: Vec<Value> = match (g(&op, "messages"), g(&ch_ref, "messages")) {
                (Some(Value::Array(a)), _) if !a.is_empty() => a.clone(),
                (_, Some(Value::Object(m))) => sorted_keys(m).iter().map(|k| m[k].clone()).collect(),
                _ => vec![],
            };
            emit(&mut c, Some(&oid), &ch_name, &ch_ref, &action, &op, &msgs)?;
        }
    } else {
        let channels = match g(source, "channels") {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        for ch_name in sorted_keys(channels) {
            let Some(ch) = deref(&mut c, Some(&channels[&ch_name]), &ch_name, 0) else { continue };
            for (key, action) in [("publish", "send"), ("subscribe", "receive")] {
                let Some(op) = deref(&mut c, g(&ch, key), &ch_name, 0) else { continue };
                let m = deref(&mut c, g(&op, "message"), &ch_name, 0);
                let msgs: Vec<Value> = match &m {
                    Some(mv) => match g(mv, "oneOf") {
                        Some(Value::Array(a)) => a.clone(),
                        _ => vec![mv.clone()],
                    },
                    None => vec![],
                };
                let oid = gstr(&op, "operationId").filter(|t| !t.is_empty());
                emit(&mut c, oid, &ch_name, &ch, action, &op, &msgs)?;
            }
        }
    }
    Ok(finish(c))
}
