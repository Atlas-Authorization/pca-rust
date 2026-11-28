//! `import -> suggest` as one call, the text forms the CLI prints and reads (JSON Lines of defs), and the importer registry (import/pipeline.ts
//! and import/registry.ts). Pure: no file system, no network. `defsToYaml` needs a YAML emitter and is not part of this module.

use super::common::{js_str, jtruthy, kerr, s, Source, IMPORT_KINDS, R};
use super::model::{suggest_with_models, ModelAdapter};
use super::suggest::{apply_suggestion, default_rules, rules_digest, suggest_with_rules};
use super::{asyncapi, graphql, grpc, jsonschema, mcp, openapi};
use crate::action_schema::is_js_ws;
use crate::actions::{core_registry, validate_def, Registry};
use serde_json::{Map, Value};

pub const MAX_IMPORT_OPS: usize = 20_000;

fn u16cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Import one source of the given kind (`kind` is any value: only a known kind name imports). Every def is `unreviewed`.
pub fn import_actions(kind: &Value, source: &Value, opts: &Value) -> R<Value> {
    match kind.as_str() {
        Some("openapi") => openapi::import_openapi(source, opts),
        Some("mcp") => mcp::import_mcp(source, opts),
        Some("graphql") => graphql::import_graphql(source, opts),
        Some("grpc") => grpc::import_grpc(Source::Json(source), opts),
        Some("asyncapi") => asyncapi::import_asyncapi(source, opts),
        Some("jsonschema") => jsonschema::import_json_schema(source, opts),
        _ => Err(kerr("bad_kind", format!("unknown import kind '{}' (one of {})", js_str(kind), IMPORT_KINDS.join(", ")))),
    }
}

/// What `suggest_defs` reads: `mode` ("rules" default, "model", "none"), `rules`, `registry` (core by default) and the model adapters.
#[derive(Clone, Default)]
pub struct SuggestOpts<'a> {
    pub mode: Option<&'a str>,
    pub rules: Option<&'a Value>,
    pub registry: Option<&'a Registry>,
    pub models: &'a [&'a dyn ModelAdapter],
}

/// Suggest for already imported defs: `{defs (state `suggested`), errors (model errors, if any)}`.
pub fn suggest_defs(defs: &[Value], o: &SuggestOpts) -> R<Value> {
    let mode = o.mode.filter(|m| !m.is_empty()).unwrap_or("rules");
    let mut out_m = Map::new();
    if mode == "none" {
        out_m.insert("defs".into(), Value::Array(defs.to_vec()));
        out_m.insert("errors".into(), Value::Array(vec![]));
        return Ok(Value::Object(out_m));
    }
    let core_holder;
    let registry: &Registry = match o.registry {
        Some(r) => r,
        None => {
            core_holder = core_registry();
            &core_holder
        }
    };
    let default_holder;
    let rules: &Value = match o.rules.filter(|r| !r.is_null()) {
        Some(r) => r,
        None => {
            default_holder = default_rules();
            &default_holder
        }
    };
    let digest = rules_digest(rules)?;
    let mut out: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();
    for d in defs {
        let mut sg = suggest_with_rules(d, rules, Some(registry))?;
        let mut models: Option<Value> = None;
        if mode == "model" {
            let run = suggest_with_models(d, o.models, registry)?;
            for e in run["errors"].as_array().cloned().unwrap_or_default() {
                let mut m = Map::new();
                m.insert("verb".into(), d["verb"].clone());
                if let Some(eo) = e.as_object() {
                    for (k, v) in eo {
                        m.insert(k.clone(), v.clone());
                    }
                }
                errors.push(Value::Object(m));
            }
            let mut traits: Vec<String> = Vec::new();
            for t in sg["traits"].as_array().into_iter().flatten().chain(run["suggestion"]["traits"].as_array().into_iter().flatten()) {
                if let Some(t) = t.as_str() {
                    if !traits.iter().any(|x| x == t) {
                        traits.push(t.to_string());
                    }
                }
            }
            traits.sort_by(|a, b| u16cmp(a, b));
            let mut m = Map::new();
            m.insert("traits".into(), Value::Array(traits.iter().map(|t| s(t)).collect()));
            m.insert("roles".into(), sg["roles"].clone());
            m.insert("tags".into(), sg["tags"].clone());
            m.insert("fired".into(), sg["fired"].clone());
            sg = Value::Object(m);
            models = Some(run["models"].clone());
        }
        let mut rules_by = Map::new();
        rules_by.insert("version".into(), rules["version"].clone());
        rules_by.insert("digest".into(), s(&digest));
        rules_by.insert("fired".into(), sg["fired"].clone());
        let mut by = Map::new();
        by.insert("rules".into(), Value::Object(rules_by));
        if let Some(ms) = models.filter(|m| m.as_array().is_some_and(|a| !a.is_empty())) {
            by.insert("models".into(), ms);
        }
        out.push(apply_suggestion(d, &sg, &Value::Object(by))?);
    }
    out_m.insert("defs".into(), Value::Array(out));
    out_m.insert("errors".into(), Value::Array(errors));
    Ok(Value::Object(out_m))
}

/// Import, then suggest: the import result with `defs` replaced by the suggested defs and `suggestErrors` added.
pub fn import_and_suggest(kind: &Value, source: &Value, opts: &Value, suggest: &SuggestOpts) -> R<Value> {
    let r = import_actions(kind, source, opts)?;
    let defs: Vec<Value> = r["defs"].as_array().cloned().unwrap_or_default();
    let sd = suggest_defs(&defs, suggest)?;
    let mut m = r.as_object().cloned().unwrap_or_default();
    m.insert("defs".into(), sd["defs"].clone());
    m.insert("suggestErrors".into(), sd["errors"].clone());
    Ok(Value::Object(m))
}

// ---- JSON Lines -----------------------------------------------------------------------------------------------------------

/// One def per line, strict canonical JSON, sorted by verb (UTF-16 order): byte-reproducible.
pub fn defs_to_jsonl(defs: &[Value]) -> R<String> {
    let mut sorted: Vec<&Value> = defs.iter().collect();
    for d in &sorted {
        if !d["verb"].is_string() {
            return Err(super::common::type_err("a def needs a verb"));
        }
    }
    sorted.sort_by(|a, b| u16cmp(a["verb"].as_str().unwrap_or(""), b["verb"].as_str().unwrap_or("")));
    let mut lines: Vec<String> = Vec::new();
    for d in sorted {
        lines.push(crate::canonicalize_strict(d).map_err(|e| kerr("bad_defs", e))?);
    }
    Ok(lines.join("\n") + if defs.is_empty() { "" } else { "\n" })
}

/// Parse and validate a JSONL file of defs. `bad_defs` names the first bad line.
pub fn jsonl_to_defs(text: &str) -> R<Vec<Value>> {
    let mut out = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let l = line.trim_matches(is_js_ws);
        if l.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(l).map_err(|_| kerr("bad_defs", format!("line {}: not JSON", i + 1)))?;
        if let Some(bad) = validate_def(&v) {
            return Err(kerr("bad_defs", format!("line {}: {bad}", i + 1)));
        }
        out.push(v);
    }
    Ok(out)
}

// ---- importer registry (the shape the CLI reads) ---------------------------------------------------------------------------

/// `IMPORTERS[kind](document, {ns, uri?, licence?, verb?})` -> `{defs, todo: ["<where>: <message>"]}`. An unknown kind is `key_error`; a
/// JSON Schema import without `verb` is `bad_opts`.
pub fn run_importer(kind: &str, doc: &Value, opts: &Value) -> R<Value> {
    if !IMPORT_KINDS.contains(&kind) {
        return Err(kerr("key_error", format!("no importer '{kind}'")));
    }
    if kind == "jsonschema" && !opts.get("verb").is_some_and(|v| jtruthy(Some(v))) {
        return Err(kerr("bad_opts", "a JSON Schema import needs --verb <ns.noun.action>"));
    }
    let r = import_actions(&s(kind), doc, opts)?;
    let todo: Vec<Value> = r["todo"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|t| Value::String(format!("{}: {}", js_str(&t["where"]), js_str(&t["message"]))))
        .collect();
    let mut m = Map::new();
    m.insert("defs".into(), r["defs"].clone());
    m.insert("todo".into(), Value::Array(todo));
    Ok(Value::Object(m))
}
