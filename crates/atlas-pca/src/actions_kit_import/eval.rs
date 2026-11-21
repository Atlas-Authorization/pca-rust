//! Measure the suggestion rules against a labeled corpus (import/eval.ts). Every corpus entry is turned into a source document of its own
//! kind, run through the real importer and the real suggestion engine, and the traits the system flags are compared with the labels:
//! precision and recall per trait, with an exact Clopper-Pearson bound on each. Heuristic numbers on a reviewed corpus, never a safety
//! guarantee. Pure: no file system (the corpus text is handed in).

use super::common::{js_str, js_str_opt, kerr, s, type_err, R};
use super::pipeline::import_actions;
use super::suggest::{apply_suggestion, default_rules, suggest_with_rules};
use crate::action_schema::is_js_ws;
use crate::actions::{closure, core_registry, hint_traits, Registry};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

const LABEL_SHORT: [(&str, &str); 20] = [
    ("money", "money_moving"),
    ("destr", "destructive"),
    ("comm", "external_communication"),
    ("priv", "privilege_change"),
    ("exp", "data_export"),
    ("exec", "code_execution"),
    ("cred", "credential_access"),
    ("bulk", "bulk"),
    ("pii", "pii_access"),
    ("pub", "public_exposure"),
    ("pers", "persistence"),
    ("infra", "infra_mutation"),
    ("cost", "cost_incurring"),
    ("legal", "legal_binding"),
    ("imp", "impersonation"),
    ("egress", "network_egress"),
    ("fin", "financial_data_read"),
    ("reg", "regulated_data"),
    ("sched", "scheduled"),
    ("spawn", "agent_spawning"),
];

const READ_FIRST: [&str; 25] = [
    "get",
    "list",
    "find",
    "search",
    "count",
    "describe",
    "show",
    "lookup",
    "check",
    "validate",
    "preview",
    "calculate",
    "estimate",
    "convert",
    "format",
    "compare",
    "summarize",
    "sort",
    "filter",
    "read",
    "fetch",
    "query",
    "view",
    "browse",
    "open",
];

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}
static SPEC_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[^:]+:([a-z]+)(?::([^\n\r\x{2028}\x{2029}]+))?$"));
static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[^:]+:([a-z]+)"));
static PATH_PARAM_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\{([^}]+)\}"));
static FIRST_WORD_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z][a-z0-9]*"));
static PLAIN_NAME_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z]+s?$"));

fn u16cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn is_blank(t: &str) -> bool {
    t.trim_matches(is_js_ws).is_empty()
}

// ---- parsing ----------------------------------------------------------------------------------------------------------------

/// `parseHandTsv(text)`: the hand corpus (`kind  name  loc  params  labels  description`, tab separated, `#` comments).
pub fn parse_hand_tsv(text: &str) -> R<Vec<Value>> {
    let mut out = Vec::new();
    let mut n = 0;
    for line in text.split('\n') {
        if is_blank(line) || line.starts_with('#') {
            continue;
        }
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 6 {
            return Err(kerr("bad_corpus", format!("hand corpus line needs 6 columns: {}", line.chars().take(80).collect::<String>())));
        }
        let (kind, name, loc, params, labels, description) = (c[0], c[1], c[2], c[3], c[4], c[5]);
        n += 1;
        let params_v: Vec<Value> = if params == "-" { vec![] } else { params.split(',').map(s).collect() };
        let labels_v: Vec<String> = if labels == "-" {
            vec![]
        } else {
            labels.split(',').map(|x| LABEL_SHORT.iter().find(|(k, _)| *k == x).map_or(x, |(_, v)| *v).to_string()).collect()
        };
        let mut e = Map::new();
        e.insert("id".into(), Value::String(format!("hand-{n:04}")));
        e.insert("src".into(), s("hand"));
        e.insert("kind".into(), s(kind));
        e.insert("name".into(), s(name));
        e.insert("params".into(), Value::Array(params_v));
        e.insert("labels".into(), Value::Array(labels_v.iter().map(|x| s(x)).collect()));
        e.insert("description".into(), s(description));
        if kind == "openapi" {
            let parts: Vec<&str> = loc.split(' ').collect();
            e.insert("method".into(), s(parts[0]));
            e.insert("path".into(), Value::String(parts[1..].join(" ")));
        }
        for x in &labels_v {
            if !LABEL_SHORT.iter().any(|(_, v)| *v == x.as_str()) {
                return Err(kerr("bad_corpus", format!("unknown label '{x}' in {name}")));
            }
        }
        out.push(Value::Object(e));
    }
    Ok(out)
}

/// `parseCorpusJsonl(text)`: one JSON value per non-blank line.
pub fn parse_corpus_jsonl(text: &str) -> R<Vec<Value>> {
    let mut out = Vec::new();
    for l in text.split('\n') {
        if is_blank(l) {
            continue;
        }
        out.push(serde_json::from_str::<Value>(l).map_err(|e| kerr("bad_corpus", format!("not JSON: {e}")))?);
    }
    Ok(out)
}

// ---- entries -> source documents ------------------------------------------------------------------------------------------

fn schema_of(spec: &str) -> Value {
    let (typ, fmt) = match SPEC_RE.captures(spec) {
        Some(m) => (m.get(1).map(|x| x.as_str().to_string()), m.get(2).map(|x| x.as_str().to_string())),
        None => (None, None),
    };
    if typ.as_deref() == Some("array") {
        return json!({"type": "array", "items": {"type": "string"}});
    }
    let t = match typ.as_deref() {
        Some("number") => "number".to_string(),
        Some(x) => x.to_string(),
        None => "string".to_string(),
    };
    let mut m = Map::new();
    m.insert("type".into(), Value::String(t));
    if let Some(f) = fmt.filter(|f| !f.is_empty()) {
        m.insert("format".into(), Value::String(f));
    }
    Value::Object(m)
}

/// `slice(0, indexOf(':'))`; with no colon the slice drops the last character.
fn pname(spec: &str) -> String {
    match spec.find(':') {
        Some(i) => spec[..i].to_string(),
        None => {
            let mut c = spec.chars();
            c.next_back();
            c.as_str().to_string()
        }
    }
}

fn first_word(n: &str) -> String {
    FIRST_WORD_RE.find(n).map_or(n, |m| m.as_str()).to_lowercase()
}

fn type_word(spec: &str) -> String {
    TYPE_RE.captures(spec).map_or_else(|| "string".to_string(), |m| m[1].to_string())
}

fn str_field(e: &Value, k: &str) -> R<String> {
    match e.get(k) {
        Some(Value::String(t)) => Ok(t.clone()),
        Some(v) if !v.is_null() => Ok(js_str(v)),
        _ => Err(type_err(format!("entry has no {k}"))),
    }
}

fn params_of(e: &Value) -> R<Vec<String>> {
    match e.get("params") {
        Some(Value::Array(a)) => Ok(a.iter().map(js_str).collect()),
        _ => Err(type_err("entry params must be a list")),
    }
}

fn opt_str(e: &Value, k: &str) -> Option<String> {
    e.get(k).filter(|v| !v.is_null()).map(js_str)
}

fn truthy_str(e: &Value, k: &str) -> bool {
    e.get(k).is_some_and(|v| v.as_str().map_or(!v.is_null() && v != &Value::Bool(false), |t| !t.is_empty()))
}

fn openapi_doc(es: &[&Value]) -> R<Value> {
    let mut paths = Map::new();
    for e in es {
        let method = opt_str(e, "method").unwrap_or_else(|| "get".into()).to_lowercase();
        let body = matches!(method.as_str(), "post" | "put" | "patch");
        let params = params_of(e)?;
        let mut props = Map::new();
        for p in &params {
            props.insert(pname(p), schema_of(p));
        }
        let path_src = opt_str(e, "path").filter(|p| !p.is_empty()).unwrap_or_default();
        let path_params: Vec<String> = PATH_PARAM_RE.captures_iter(&path_src).map(|m| m[1].to_string()).collect();
        let mut op = Map::new();
        if truthy_str(e, "name") {
            op.insert("operationId".into(), e["name"].clone());
        }
        if truthy_str(e, "description") {
            op.insert("summary".into(), e["description"].clone());
        }
        let mut parameters: Vec<Value> = path_params.iter().map(|n| json!({"name": n, "in": "path", "required": true, "schema": {"type": "string"}})).collect();
        if !body {
            for p in &params {
                if !path_params.iter().any(|q| *q == pname(p)) {
                    parameters.push(json!({"name": pname(p), "in": "query", "schema": schema_of(p)}));
                }
            }
        }
        op.insert("parameters".into(), Value::Array(parameters));
        if body && !params.is_empty() {
            op.insert(
                "requestBody".into(),
                json!({"content": {"application/json": {"schema": {"type": "object", "properties": Value::Object(props), "required": []}}}}),
            );
        }
        let key = opt_str(e, "path").unwrap_or_else(|| "undefined".into());
        let slot = paths.entry(key).or_insert_with(|| Value::Object(Map::new()));
        if let Some(m) = slot.as_object_mut() {
            m.insert(method, Value::Object(op));
        }
    }
    Ok(json!({"openapi": "3.0.3", "info": {"title": "corpus", "version": "1"}, "paths": Value::Object(paths)}))
}

fn gql_type(t: &str) -> &'static str {
    match t {
        "integer" => "Int",
        "boolean" => "Boolean",
        "array" => "[String]",
        _ => "String",
    }
}

fn proto_type(t: &str) -> &'static str {
    match t {
        "integer" => "int64",
        "boolean" => "bool",
        "array" => "repeated string",
        _ => "string",
    }
}

fn graphql_sdl(es: &[&Value]) -> R<String> {
    let (mut q, mut m): (Vec<String>, Vec<String>) = (vec![], vec![]);
    for e in es {
        let params = params_of(e)?;
        let name = str_field(e, "name")?;
        let desc = str_field(e, "description")?;
        let args = if params.is_empty() {
            String::new()
        } else {
            format!("({})", params.iter().map(|p| format!("{}: {}", pname(p), gql_type(&type_word(p)))).collect::<Vec<_>>().join(", "))
        };
        let target = if READ_FIRST.contains(&first_word(&name).as_str()) || PLAIN_NAME_RE.is_match(&name) { &mut q } else { &mut m };
        target.push(format!("  \"{}\"\n  {}{}: String", desc.replace('"', "'"), name, args));
    }
    let mut out = String::new();
    if !q.is_empty() {
        out += &format!("type Query {{\n{}\n}}\n", q.join("\n"));
    }
    if !m.is_empty() {
        out += &format!("type Mutation {{\n{}\n}}\n", m.join("\n"));
    }
    Ok(out)
}

fn proto_text(es: &[&Value]) -> R<String> {
    let mut order: Vec<String> = vec![];
    let mut svcs: HashMap<String, Vec<&Value>> = HashMap::new();
    for e in es {
        let svc = str_field(e, "name")?.split('/').next().unwrap_or("").to_string();
        if !svcs.contains_key(&svc) {
            order.push(svc.clone());
        }
        svcs.entry(svc).or_default().push(e);
    }
    let mut msgs = vec!["message Empty {}".to_string()];
    let mut out: Vec<String> = vec![];
    for sv in &order {
        let mut rpcs = vec![];
        for e in &svcs[sv] {
            let name = str_field(e, "name")?;
            let mname = name.split('/').nth(1).ok_or_else(|| type_err("a gRPC corpus name is Service/Method"))?.to_string();
            let fields: Vec<String> =
                params_of(e)?.iter().enumerate().map(|(i, p)| format!("  {} {} = {};", proto_type(&type_word(p)), pname(p), i + 1)).collect();
            msgs.push(format!("message {mname}Request {{\n{}\n}}", fields.join("\n")));
            rpcs.push(format!("  rpc {mname}({mname}Request) returns (Empty);"));
        }
        out.push(format!("service {sv} {{\n{}\n}}", rpcs.join("\n")));
    }
    Ok(format!("syntax = \"proto3\";\npackage corpus;\n{}\n{}\n", msgs.join("\n"), out.join("\n")))
}

fn async_doc(es: &[&Value]) -> R<Value> {
    let mut channels = Map::new();
    for e in es {
        let mut props = Map::new();
        for p in params_of(e)? {
            props.insert(pname(&p), schema_of(&p));
        }
        channels.insert(
            str_field(e, "name")?,
            json!({"publish": {"summary": str_field(e, "description")?, "message": {"payload": {"type": "object", "properties": Value::Object(props)}}}}),
        );
    }
    Ok(json!({"asyncapi": "2.6.0", "info": {"title": "corpus", "version": "1"}, "channels": Value::Object(channels)}))
}

fn mcp_doc(es: &[&Value]) -> R<Value> {
    let mut out = vec![];
    for e in es {
        let mut props = Map::new();
        for p in params_of(e)? {
            props.insert(pname(&p), schema_of(&p));
        }
        out.push(json!({"name": str_field(e, "name")?, "description": str_field(e, "description")?, "inputSchema": {"type": "object", "properties": Value::Object(props)}}));
    }
    Ok(Value::Array(out))
}

fn key_of(e: &Value) -> R<String> {
    if e.get("kind").and_then(Value::as_str) == Some("openapi") {
        Ok(format!("{} {}", opt_str(e, "method").unwrap_or_else(|| "GET".into()).to_uppercase(), js_str_opt(e.get("path").filter(|v| !v.is_null()))))
    } else {
        str_field(e, "name")
    }
}

fn cand(v: Option<&Value>) -> Option<String> {
    v.filter(|x| !x.is_null()).map(js_str)
}

fn def_key(d: &Value) -> String {
    let b = d.get("bindings").filter(|x| x.is_object());
    let at = |k: &str| b.and_then(|b| b.get(k)).filter(|x| x.as_object().is_some_and(|m| !m.is_empty()));
    let (oa, gq, gr, aa, mc) = (at("openapi"), at("graphql"), at("grpc"), at("asyncapi"), at("mcp"));
    let c1 = oa.filter(|o| super::common::jtruthy(o.get("path"))).map(|o| format!("{} {}", js_str_opt(o.get("method")), js_str_opt(o.get("path"))));
    let c2 = oa.and_then(|o| cand(o.get("operationId")));
    let c3 = mc.and_then(|o| cand(o.get("tool")));
    let c4 = gq.and_then(|o| cand(o.get("field")));
    let c5 = gr.map(|o| format!("{}/{}", js_str_opt(o.get("service")).rsplit('.').next().unwrap_or(""), js_str_opt(o.get("method"))));
    let c6 = aa.and_then(|o| cand(o.get("channel")));
    [c1, c2, c3, c4, c5, c6].into_iter().flatten().next().unwrap_or_default()
}

/// Import every entry with the real importer of its kind: `{defs: {entry id: draft def}, todo: count}` (an entry whose def was not emitted is absent).
pub fn import_corpus(entries: &[Value]) -> R<Value> {
    let mut defs = Map::new();
    let mut todo = 0usize;
    let mut order: Vec<(String, String)> = vec![];
    let mut groups: HashMap<(String, String), Vec<&Value>> = HashMap::new();
    for e in entries {
        let kind = str_field(e, "kind")?;
        let spec = opt_str(e, "spec").unwrap_or_default();
        let k = (kind, spec);
        if !groups.contains_key(&k) {
            order.push(k.clone());
        }
        groups.entry(k).or_default().push(e);
    }
    for g in &order {
        let es = &groups[g];
        let kind = g.0.as_str();
        let src = match kind {
            "openapi" => openapi_doc(es)?,
            "mcp" => mcp_doc(es)?,
            "graphql" => Value::String(graphql_sdl(es)?),
            "grpc" => Value::String(proto_text(es)?),
            _ => async_doc(es)?,
        };
        let opts = json!({"ns": "corpus", "limits": {"max_ops": 50_000, "max_nodes": 20_000_000, "max_bytes": 200_000_000}});
        let r = import_actions(&s(kind), &src, &opts)?;
        todo += r["todo"].as_array().map_or(0, Vec::len);
        let mut by_key: HashMap<String, &Value> = HashMap::new();
        for d in r["defs"].as_array().into_iter().flatten() {
            by_key.insert(def_key(d), d);
        }
        for e in es {
            if let Some(d) = by_key.get(&key_of(e)?).filter(|d| d.as_object().is_some_and(|m| !m.is_empty())) {
                defs.insert(str_field(e, "id")?, (*d).clone());
            }
        }
    }
    Ok(json!({"defs": Value::Object(defs), "todo": todo}))
}

// ---- scoring ----------------------------------------------------------------------------------------------------------------

/// Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at.
pub fn real_split(spec: Option<&str>) -> &'static str {
    let mut h: u32 = 2_166_136_261;
    for ch in spec.unwrap_or("").chars() {
        let o = ch as u32;
        let unit = if o <= 0xFFFF { o } else { 0xD800 + ((o - 0x10000) >> 10) }; // charCodeAt(0) of a code point
        h = (h ^ unit).wrapping_mul(16_777_619);
    }
    if (h >> 7) % 2 == 0 {
        "tune"
    } else {
        "holdout"
    }
}

fn source_of(e: &Value) -> String {
    if e["src"].as_str() == Some("real") {
        format!("real/{}", real_split(e.get("spec").and_then(Value::as_str)))
    } else {
        js_str(&e["src"])
    }
}

fn strip_pca(t: &str) -> String {
    t.strip_prefix("pca.").unwrap_or(t).to_string()
}

fn num(v: f64) -> Value {
    Value::from(v)
}

fn stat(trait_name: &str, rows: &[(bool, bool)], alpha: f64) -> R<Value> {
    let (mut tp, mut fp, mut fnn) = (0usize, 0usize, 0usize);
    for (actual, predicted) in rows {
        if *actual && *predicted {
            tp += 1;
        } else if *predicted {
            fp += 1;
        } else if *actual {
            fnn += 1;
        }
    }
    let (pos, pred) = (tp + fnn, tp + fp);
    let upper = |k: usize, n: usize| -> R<f64> { crate::wallet_omega::clopper_pearson_upper(k as f64, n as f64, alpha).map_err(|e| kerr("bad_alpha", e)) };
    let mut m = Map::new();
    m.insert("trait".into(), s(trait_name));
    m.insert("positives".into(), Value::from(pos));
    m.insert("predicted".into(), Value::from(pred));
    m.insert("tp".into(), Value::from(tp));
    m.insert("fp".into(), Value::from(fp));
    m.insert("fn".into(), Value::from(fnn));
    m.insert("precision".into(), if pred == 0 { Value::Null } else { num(tp as f64 / pred as f64) });
    m.insert("recall".into(), if pos == 0 { Value::Null } else { num(tp as f64 / pos as f64) });
    m.insert("recall_lower".into(), if pos == 0 { Value::Null } else { num(1.0 - upper(fnn, pos)?) });
    // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
    m.insert("precision_lower".into(), if pred == 0 || pred > 600 { Value::Null } else { num(1.0 - upper(fp, pred)?) });
    Ok(Value::Object(m))
}

/// Score `entries` against their labels. `rules` default to the shipped rules, `registry` to the core registry, `alpha` to 0.05.
pub fn eval_suggest(entries: &[Value], rules: Option<&Value>, registry: Option<&Registry>, alpha: Option<f64>) -> R<Value> {
    let default_holder;
    let rules: &Value = match rules.filter(|r| !r.is_null()) {
        Some(r) => r,
        None => {
            default_holder = default_rules();
            &default_holder
        }
    };
    let core_holder;
    let registry: &Registry = match registry {
        Some(r) => r,
        None => {
            core_holder = core_registry();
            &core_holder
        }
    };
    let alpha = alpha.unwrap_or(0.05);
    let imported = import_corpus(entries)?;
    let defs = imported["defs"].as_object().cloned().unwrap_or_default();
    let mut trait_names: Vec<String> = registry.traits.keys().filter(|t| *t != "pca.unreviewed" && *t != "pca.irreversible").map(|t| strip_pca(t)).collect();
    trait_names.sort_by(|a, b| u16cmp(a, b));
    let mut flagged: HashMap<String, HashSet<String>> = HashMap::new();
    let mut added: HashMap<String, HashSet<String>> = HashMap::new();
    for e in entries {
        let id = str_field(e, "id")?;
        let Some(d) = defs.get(&id).filter(|d| d.as_object().is_some_and(|m| !m.is_empty())) else { continue };
        let sg = suggest_with_rules(d, rules, Some(registry))?;
        let by = json!({"rules": {"version": rules["version"].clone(), "digest": "", "fired": sg["fired"].clone()}});
        let sd = apply_suggestion(d, &sg, &by)?;
        let cl = closure(registry, &hint_traits(&sd))?;
        flagged.insert(id.clone(), cl.iter().filter(|t| *t != "pca.unreviewed").map(|t| strip_pca(t)).collect());
        added.insert(id, sg["traits"].as_array().into_iter().flatten().map(|t| strip_pca(&js_str(t))).collect());
    }
    let score = |es: &[&Value], pred: &HashMap<String, HashSet<String>>| -> R<Vec<Value>> {
        let mut out = vec![];
        for t in &trait_names {
            let mut rows = vec![];
            for e in es {
                let labeled = e["labels"].as_array().is_some_and(|l| l.iter().any(|x| x.as_str() == Some(t)));
                let predicted = pred.get(e["id"].as_str().unwrap_or("")).is_some_and(|p| p.contains(t));
                rows.push((labeled, predicted));
            }
            let st = stat(t, &rows, alpha)?;
            if st["positives"].as_u64().unwrap_or(0) > 0 || st["predicted"].as_u64().unwrap_or(0) > 0 {
                out.push(st);
            }
        }
        Ok(out)
    };
    let all: Vec<&Value> = entries.iter().collect();
    let mut sources: Vec<String> = entries.iter().map(source_of).collect();
    if entries.iter().any(|e| e["src"].as_str() == Some("real")) {
        sources.push("real".into());
    }
    sources.sort_by(|a, b| u16cmp(a, b));
    sources.dedup();
    let mut by_source = Map::new();
    for sname in &sources {
        let es: Vec<&Value> = entries.iter().filter(|e| if sname == "real" { e["src"].as_str() == Some("real") } else { source_of(e) == *sname }).collect();
        by_source.insert(sname.clone(), json!({"entries": es.len(), "flagged": score(&es, &flagged)?}));
    }
    Ok(json!({
        "alpha": num(alpha), "entries": entries.len(), "mapped": defs.len(), "rules_version": rules["version"].clone(), "flagged": score(&all, &flagged)?,
        "suggested": score(&all, &added)?, "by_source": Value::Object(by_source),
    }))
}

// ---- report -----------------------------------------------------------------------------------------------------------------

/// `Number.prototype.toFixed(1)` of `x * 100` with a `-` for an absent value (ties go up, as the reference does).
fn pct(x: Option<&Value>) -> String {
    let Some(f) = x.and_then(Value::as_f64) else { return "-".into() };
    let v = f * 100.0;
    let q = v * 4.0;
    // an exact tie at one decimal is a quarter (m/4, m odd): round it up
    if v >= 0.0 && q.fract() == 0.0 && q < 9e15 && (q as i64) % 2 != 0 {
        let n = (v * 10.0).floor() as i64 + 1;
        return format!("{}.{}%", n / 10, n % 10);
    }
    format!("{v:.1}%")
}

fn int_text(v: &Value) -> String {
    match v.as_i64() {
        Some(i) => i.to_string(),
        None => (v.as_f64().unwrap_or(0.0) as i64).to_string(),
    }
}

pub fn render_eval_markdown(r: &Value) -> R<String> {
    let table = |stats: &Value| -> String {
        let mut rows = vec![
            "| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |".to_string(),
            "|---|---:|---:|---:|---:|---:|---:|---:|".to_string(),
        ];
        for st in stats.as_array().into_iter().flatten() {
            rows.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                js_str(&st["trait"]),
                int_text(&st["positives"]),
                int_text(&st["predicted"]),
                pct(st.get("recall")),
                pct(st.get("recall_lower")),
                pct(st.get("precision")),
                int_text(&st["fn"]),
                int_text(&st["fp"])
            ));
        }
        rows.join("\n")
    };
    let alpha = r["alpha"].as_f64().ok_or_else(|| type_err("the report needs an alpha"))?;
    let mut lines: Vec<String> = vec![
        format!("# Suggestion rules {}: measured on a labeled corpus", js_str(&r["rules_version"])),
        String::new(),
        format!(
            "{} labeled operations ({} imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = {}.",
            int_text(&r["entries"]),
            int_text(&r["mapped"]),
            crate::intent_v2::js_number_string(alpha)
        ),
        "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor."
            .to_string(),
        String::new(),
        "## What a reviewer is shown (importer facts plus suggestions)".to_string(),
        String::new(),
        table(&r["flagged"]),
        String::new(),
        "## What the suggestion rules added".to_string(),
        String::new(),
        table(&r["suggested"]),
        String::new(),
    ];
    for (name, v) in r["by_source"].as_object().into_iter().flatten() {
        lines.push(format!("## Source: {} ({} operations)", name, int_text(&v["entries"])));
        lines.push(String::new());
        lines.push(table(&v["flagged"]));
        lines.push(String::new());
    }
    Ok(lines.join("\n"))
}

fn cmp_lt(a: Option<&Value>, b: &Value) -> bool {
    a.and_then(Value::as_f64).is_some_and(|x| x < b.as_f64().unwrap_or(f64::NAN))
}

/// Empty when the report meets the floors; else one line per failure.
pub fn floor_failures(r: &Value, f: &Value) -> R<Vec<String>> {
    let mut out: Vec<String> = vec![];
    let real = r["by_source"].get("real/holdout").filter(|v| v.is_object());
    let min_entries = &f["real"]["min_entries"];
    if real.map_or(true, |x| cmp_lt(x.get("entries"), min_entries)) {
        out.push(format!(
            "the real-spec hold-out has {} operations, fewer than the required {}",
            real.map_or("0".to_string(), |x| int_text(&x["entries"])),
            int_text(min_entries)
        ));
    }
    if cmp_lt(r.get("mapped"), &r["entries"]) {
        out.push(format!("{} corpus operations were not imported", (r["entries"].as_i64().unwrap_or(0)) - r["mapped"].as_i64().unwrap_or(0)));
    }
    let find = |side: Option<&Value>, t: &str| -> Option<Value> {
        side.and_then(|x| x["flagged"].as_array()).and_then(|a| a.iter().find(|x| x["trait"].as_str() == Some(t))).cloned()
    };
    for (t, floor) in f["real"]["recall_lower"].as_object().into_iter().flatten() {
        let st = find(real, t);
        let need = f["real"]["min_positives"].get(t).cloned().unwrap_or_else(|| json!(0));
        match &st {
            Some(x) if !cmp_lt(x.get("positives"), &need) => {
                if x["recall_lower"].is_null() || cmp_lt(x.get("recall_lower"), floor) {
                    out.push(format!("{t}: hold-out recall lower bound {} is below the recorded floor {}", pct(x.get("recall_lower")), pct(Some(floor))));
                }
            }
            _ => out.push(format!(
                "{t}: {} real labeled positives, fewer than the {} the floor needs",
                st.as_ref().map_or("0".to_string(), |x| int_text(&x["positives"])),
                int_text(&need)
            )),
        }
    }
    let syn = r["by_source"].get("syn").filter(|v| v.is_object());
    for (t, floor) in f["regression"]["recall_lower"].as_object().into_iter().flatten() {
        let st = find(syn, t);
        if st.as_ref().map_or(true, |x| x["recall_lower"].is_null() || cmp_lt(x.get("recall_lower"), floor)) {
            out.push(format!("{t}: regression-set recall lower bound {} is below {}", pct(st.as_ref().and_then(|x| x.get("recall_lower"))), pct(Some(floor))));
        }
    }
    Ok(out)
}
