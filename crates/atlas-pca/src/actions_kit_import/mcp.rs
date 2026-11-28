//! MCP `tools/list` to drafts. The annotations are HINTS from the tool's own server and are untrusted: they can only add restriction
//! (destructive, network egress); every output is `unreviewed`.

use super::common::*;
use crate::actions::utf16_len;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// `source` is a `tools/list` result {"tools": [...]} or the tool array itself.
pub fn import_mcp(source: &Value, opts: &Value) -> R<Value> {
    let mut c = new_ctx("mcp", Source::Json(source), opts)?;
    let tools: &Vec<Value> = match source {
        Value::Array(a) => a,
        Value::Object(m) => match m.get("tools") {
            Some(Value::Array(a)) => a,
            _ => return Err(bad_src()),
        },
        _ => return Err(bad_src()),
    };
    let mut seen: HashSet<String> = HashSet::new();
    for t in tools {
        let name = match gstr(t, "name") {
            Some(n) if is_obj(t) && utf16_len(n) > 0 && utf16_len(n) <= 256 => n.to_string(),
            _ => {
                add_todo(&mut c, "(tool)", "skipped_op", "an entry without a usable name is skipped");
                continue;
            }
        };
        if seen.contains(&name) {
            add_todo(&mut c, &name, "duplicate_tool", "a tool name listed twice; the first is kept");
            continue;
        }
        seen.insert(name.clone());
        let input = g(t, "inputSchema").cloned().unwrap_or(Value::Null);
        c.root = input.clone();
        let mut bud = new_budget(&c);
        let inp = resolve(&input, &mut c, &mut bud, &format!("{name}: inputSchema"))?;
        let mut params: Map<String, Value> = Map::new();
        flatten_object(&inp, &mut c, &mut bud, &name, &mut params, &[], true)?;
        let empty = Value::Object(Map::new());
        let a: &Value = match g(t, "annotations") {
            Some(x) if x.is_object() => x,
            _ => &empty,
        };
        let destructive = is_true(g(a, "destructiveHint"));
        let read = is_true(g(a, "readOnlyHint")) && !destructive;
        let effects: &[&str] = if read {
            &["read"]
        } else if destructive {
            &["update", "delete"]
        } else {
            &["update"]
        };
        let title: Option<&Value> = match g(a, "title") {
            Some(x) if x.as_str().is_some_and(|z| !z.is_empty()) => Some(x),
            _ => g(t, "title"),
        };
        let eo = EmitOpts {
            verb: None,
            title,
            description: g(t, "description"),
            idempotency: if is_true(g(a, "idempotentHint")) { Some(serde_json::json!({"mode": "natural"})) } else { None },
            traits: if is_true(g(a, "openWorldHint")) { Some(with_trait(None, "pca.network_egress")) } else { None },
            no_alias: false,
        };
        emit_def(&mut c, &name, effects, "one", params, serde_json::json!({"mcp": {"tool": clip(&name, 256)}}), eo)?;
    }
    Ok(finish(c))
}

fn bad_src() -> ActionKitError {
    kerr("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}")
}
