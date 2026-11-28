//! One JSON Schema plus a caller-given verb to one def.

use super::common::*;
use serde_json::{Map, Value};

/// `opts`: the common import options plus `verb` (required, `<ns>.<noun>.<action>`), `title`, `description`, `effects` (default ["update"]).
pub fn import_json_schema(schema: &Value, opts: &Value) -> R<Value> {
    let mut c = new_ctx("jsonschema", Source::Json(schema), opts)?;
    let ns = c.ns.clone();
    let verb = match gstr(opts, "verb") {
        Some(v) if is_verb(v) && v.starts_with(&format!("{ns}.")) => v.to_string(),
        _ => return Err(kerr("bad_verb", format!("verb must be a valid verb in namespace '{ns}'"))),
    };
    let effects: Vec<String> = match g(opts, "effects").filter(|v| !v.is_null()) {
        None => vec!["update".into()],
        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|e| e.as_str().is_some_and(|x| EFFECTS.contains(&x))) => {
            a.iter().filter_map(|e| e.as_str().map(String::from)).collect()
        }
        Some(_) => return Err(kerr("bad_effects", "effects must be 1+ known effects")),
    };
    if !is_obj(schema) {
        return Err(kerr("bad_source", "a JSON Schema must be an object"));
    }
    let mut bud = new_budget(&c);
    let root = resolve(schema, &mut c, &mut bud, &verb)?;
    let mut params: Map<String, Value> = Map::new();
    if root.get("type").and_then(Value::as_str) == Some("object") || matches!(root.get("properties"), Some(Value::Object(_))) {
        flatten_object(&root, &mut c, &mut bud, &verb, &mut params, &[], true)?;
    } else {
        add_todo(&mut c, &verb, "not_object", "the schema is not an object schema: the def has no parameters");
    }
    // title: opts.title (when not null/undefined) else root.title when a string
    let title: Option<Value> = match g(opts, "title").filter(|v| !v.is_null()) {
        Some(t) => Some(t.clone()),
        None => root.get("title").filter(|t| t.is_string()).cloned(),
    };
    let description: Value = match g(opts, "description").filter(|v| !v.is_null()) {
        Some(d) => d.clone(),
        None => Value::String(clipv(root.get("description"), 600)),
    };
    let name = verb.split('.').skip(1).collect::<Vec<_>>().join("_");
    let eff: Vec<&str> = effects.iter().map(String::as_str).collect();
    let eo = EmitOpts { verb: Some(verb.clone()), title: title.as_ref(), description: Some(&description), idempotency: None, traits: None, no_alias: false };
    emit_def(&mut c, &name, &eff, "one", params, Value::Object(Map::new()), eo)?;
    Ok(finish(c))
}
