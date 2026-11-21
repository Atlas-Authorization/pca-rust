//! The rest of `action-schema.ts` over JSON: the exported vocabulary constants, the value-dependent reversibility, the wallet floor test,
//! schema lookup, signing and the discovery key entry, and the DRAFTING importers that turn an MCP `tools/list` or an OpenAPI document
//! into a draft schema with a todo list (`draftSchemaFromMcpTools`, `draftSchemaFromOpenApi`). The shape check, verification, digest and
//! conformance are in [`crate::action_schema`].
//!
//! The importers flatten what a parameter declaration cannot carry (local `$ref`s, `allOf`, an `anyOf` / `oneOf` with one live variant
//! or only string constants) and flag everything else in the todo list as a `string` placeholder, which rejects every non-string value:
//! a draft fails closed until the developer refines it. Every write verb is drafted `irreversible` and every sensitivity `material`.
use serde_json::{json, Map, Value};

use crate::agent::{sign_with_suite, KeyPair, Suite};

pub const ACTION_SCHEMA_DOMAIN: &str = "atlas-pca/action-schema/v1\0";
pub const ACTION_SCHEMA_REF_DOMAIN: &str = "atlas-pca/action-schema-ref/v1";
pub const ACTION_SCHEMA_KIND: &str = "pca-action-schema";
pub const WELL_KNOWN_PCA_ACTIONS_PATH: &str = "/.well-known/pca-actions.json";
pub const SENSITIVITIES: [&str; 3] = ["free", "material", "critical"];
pub const SCHEMA_REVERSIBILITY: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
pub const PARAM_TYPES: [&str; 6] = ["string", "integer", "boolean", "date", "set", "array"];
pub const PARAM_TYPES_V2: [&str; 9] = ["string", "integer", "boolean", "date", "set", "array", "datetime", "duration", "object_ref"];
pub const SCHEMA_V2_EFFECTS: [&str; 12] =
    ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
pub const SCHEMA_V2_CAVEATS: [&str; 8] =
    ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"];
pub const SCHEMA_V2_PRULES: [&str; 8] = [
    "array_bounded",
    "export_bounded",
    "id_not_wildcard",
    "money_amount_bounded",
    "money_has_currency",
    "pay_has_idempotency",
    "recipient_param_declared",
    "secret_not_logged",
];
pub const SCHEMA_V2_CONTEXT: [&str; 6] =
    ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"];
pub const SCHEMA_V2_TAGS: [&str; 9] = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"];
pub const SCHEMA_V2_PROVENANCE: [&str; 3] = ["first_party", "tool", "agent"];
pub const MAX_SCHEMA_VERBS: usize = 256;
pub const MAX_SCHEMA_PARAMS: usize = 64;
pub const MAX_SCHEMA_VALUES: usize = 256;
pub const DEFAULT_MAX_LEN: usize = 1024;
pub const DEFAULT_MAX_ITEMS: usize = 64;
/// The source of `PARAM_PATH_RE`.
pub const PARAM_PATH_RE: &str = r"^action\.params\.[A-Za-z0-9_]{1,64}$";
/// The source of `PARAM_PATH_RE_V2`.
pub const PARAM_PATH_RE_V2: &str = r"^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$";
/// The source of `UNIT_ID_RE`.
pub const UNIT_ID_RE: &str = r"^[a-z0-9_]+(?:\.[a-z0-9_]+)*$";
/// Semantic types that are ALWAYS at least material, whatever the site says (a prefix match on `x.`, or exact).
pub const WALLET_FLOOR_PREFIXES: [&str; 5] = ["money.", "party.", "contact.", "person.", "credential."];
pub const WALLET_FLOOR_EXACT: [&str; 1] = ["text.message"];

const MAX_REF_DEPTH: usize = 8;
const MAX_REF_NODES: i64 = 20_000;

// ---- JavaScript value semantics ---------------------------------------------------------------------------------------------------

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

/// `Number.isSafeInteger(v)`.
fn safe_integer(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    v.as_f64().filter(|f| v.is_number() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0)
}

fn jnum(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object()?.get(k)
}

/// `a ?? b`: absent and `null` fall through.
fn present<'a>(v: Option<&'a Value>) -> Option<&'a Value> {
    v.filter(|x| !x.is_null())
}

fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => crate::intent_v2::js_value_string(x),
    }
}

/// The first `n` UTF-16 code units of a string (`s.slice(0, n)`); a pair straddling the cut is dropped whole.
fn slice_units(s: &str, n: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in s.chars() {
        units += c.len_utf16();
        if units > n {
            break;
        }
        out.push(c);
    }
    out
}

fn description_of(v: Option<&Value>) -> Result<Option<String>, String> {
    match v {
        _ if !truthy(v) => Ok(None),
        Some(Value::String(s)) => Ok(Some(slice_units(s, 1024))),
        _ => Err("description.slice is not a function".into()),
    }
}

/// `{...a, ...b}` over object members (a non-object contributes nothing).
fn spread(a: Option<&Value>, b: Option<&Value>) -> Map<String, Value> {
    let mut m = a.and_then(Value::as_object).cloned().unwrap_or_default();
    for (k, v) in b.and_then(Value::as_object).into_iter().flatten() {
        m.insert(k.clone(), v.clone());
    }
    m
}

// ---- reversibility, the wallet floor, lookup ----------------------------------------------------------------------------------------

/// `rev_S(w)`: the value-dependent reversibility class of a verb for these params: a `reversibility_by` map keyed by the value of its
/// param (a string, a boolean or a safe integer), an unmapped or absent value taking its `default` (else `irreversible`, fail closed); else
/// the verb's own `reversibility`, else `reversible` for a read and `irreversible` for anything else. Own-property lookups only.
pub fn reversibility_of(v: &Value, params: &Value) -> Result<Value, String> {
    if let Some(by) = get(v, "reversibility_by").filter(|b| truthy(Some(*b))) {
        let param = by.get("param").and_then(Value::as_str).ok_or("Cannot read properties of undefined (reading 'slice')")?;
        let name: String = param.chars().skip("action.params.".len()).collect();
        let key = get(params, &name).and_then(|x| match x {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(_) => safe_integer(Some(x)).filter(|f| !(*f == 0.0 && f.is_sign_negative())).map(|f| (f as i64).to_string()),
            _ => None,
        });
        if let Some(mapped) = key.and_then(|k| by.get("map").and_then(|m| m.get(&k))) {
            return Ok(mapped.clone());
        }
        return Ok(present(by.get("default")).cloned().unwrap_or_else(|| json!("irreversible")));
    }
    Ok(present(v.get("reversibility"))
        .cloned()
        .unwrap_or_else(|| json!(if v.get("kind").and_then(Value::as_str) == Some("read") { "reversible" } else { "irreversible" })))
}

/// Does the wallet floor cover this semantic type? `floor` is `{prefixes?, exact?}` (absent members take the defaults).
pub fn floor_applies(semantic: &str, floor: Option<&Value>) -> bool {
    let list = |k: &str, default: &[&str]| -> Vec<String> {
        match floor.and_then(|f| present(f.get(k))).and_then(Value::as_array) {
            Some(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            None => default.iter().map(|s| s.to_string()).collect(),
        }
    };
    list("exact", &WALLET_FLOOR_EXACT).iter().any(|e| e == semantic)
        || list("prefixes", &WALLET_FLOOR_PREFIXES).iter().any(|p| semantic.starts_with(p.as_str()))
}

/// The first verb declaration whose `verb` equals `verb` (`null` when none). Own members only.
pub fn schema_verb_decl(doc: &Value, verb: &str) -> Result<Value, String> {
    Ok(crate::action_schema::schema_verb(doc, verb)?.map_or(Value::Null, |o| Value::Object(o.clone())))
}

// ---- signing and the discovery key entry ----------------------------------------------------------------------------------------------

/// Sign a schema as the site: `{...doc, sig: {alg, kid, value, pq_value?}}` over `ACTION_SCHEMA_DOMAIN || strictCanonical(doc)`; `kid` names
/// the site's discovery key entry and is not validated. `Err` for an unsigned document that is not well formed or an unknown suite.
pub fn sign_action_schema_value(doc: &Value, kid: &str, site: &KeyPair, suite: &Suite) -> Result<Value, String> {
    if let Some(bad) = crate::action_schema_shape_error_unsigned(doc) {
        return Err(format!("signActionSchema: {bad}"));
    }
    if !crate::action_schema::is_str(Some(&json!(kid)), 128) {
        return Err("signActionSchema: sig.kid must be a non-empty string".into());
    }
    let mut msg = ACTION_SCHEMA_DOMAIN.as_bytes().to_vec();
    msg.extend_from_slice(crate::canonicalize_strict(doc)?.as_bytes());
    let (sig, pq_sig) = sign_with_suite(suite, Some(site), &msg)?;
    let alg = suite.alg.unwrap_or("ed25519");
    let mut s = json!({"alg": alg, "kid": kid, "value": sig});
    if let Some(p) = pq_sig {
        s["pq_value"] = json!(p);
    }
    let mut out = doc.clone();
    out["sig"] = s;
    Ok(out)
}

/// The discovery key entry for a signer: `{kid, alg, pk, pq_pk?}`. `Err` for an unknown suite.
pub fn action_schema_key_of(kid: &str, site: &KeyPair, suite: &Suite) -> Result<Value, String> {
    if !crate::action_schema::is_str(Some(&json!(kid)), 128) {
        return Err("actionSchemaKeyOf: kid must be a non-empty string".into());
    }
    let alg = suite.alg.unwrap_or("ed25519");
    let resolved =
        crate::intent_suite::suite_of(Some(&json!(alg))).map_err(|_| "Cannot read properties of null (reading 'alg')".to_string())?;
    let mut o = json!({"kid": kid, "alg": resolved.alg, "pk": site.public});
    if resolved.needs_pq_pk {
        if let Some(p) = suite.pq {
            o["pq_pk"] = json!(p.public);
        }
    }
    Ok(o)
}

// ---- drafting: MCP tools and OpenAPI operations -> a DRAFT schema -----------------------------------------------------------------------

/// MCP annotations give a LOWER bound on reversibility (hints never lower a classification): `{kind, atLeast}`.
pub fn reversibility_from_mcp_hints(annotations: &Value) -> Value {
    if get(annotations, "readOnlyHint") == Some(&json!(true)) {
        json!({"kind": "read", "atLeast": "reversible"})
    } else if get(annotations, "destructiveHint") == Some(&json!(true)) {
        json!({"kind": "write", "atLeast": "rate_limited"})
    } else {
        json!({"kind": "write", "atLeast": "reversible"})
    }
}

struct Ctx<'a> {
    root: &'a Value,
    todo: Vec<String>,
    left: Option<i64>,
}

/// Follow a local `#/a/b` JSON pointer in `root`: the object it names, else `None` (absent, not local, or not an object).
fn pointer<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let path = reference.strip_prefix("#/")?;
    let mut cur = root;
    for raw in path.split('/') {
        let seg = raw.replace("~1", "/").replace("~0", "~");
        cur = cur.as_object()?.get(&seg)?;
    }
    (cur.is_object() || cur.is_array()).then_some(cur)
}

fn null_only(m: &Value) -> bool {
    match get(m, "type") {
        Some(Value::String(t)) => t == "null",
        Some(Value::Array(a)) => a.iter().all(|x| x.as_str() == Some("null")),
        _ => false,
    }
}

/// Flatten what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single
/// non-null variant (or the union of string constants); whatever remains is flagged in `todo` and left as an empty schema.
fn flatten(s: Option<&Value>, c: &mut Ctx<'_>, place: &str, depth: usize) -> Value {
    let Some(s) = s.filter(|s| s.is_object() || s.is_array()) else { return json!({}) };
    let left = c.left.unwrap_or(MAX_REF_NODES) - 1;
    c.left = Some(left);
    if left < 0 {
        if left == -1 {
            c.todo.push(format!("{place}: schema expansion stopped after {MAX_REF_NODES} nodes (declared string; refine or drop)"));
        }
        return json!({});
    }
    if depth > MAX_REF_DEPTH {
        c.todo.push(format!("{place}: schema nesting or reference chain deeper than {MAX_REF_DEPTH} (declared string; refine or drop)"));
        return json!({});
    }
    let mut cur = s.clone();
    if let Some(r) = get(s, "$ref").and_then(Value::as_str) {
        let Some(target) = pointer(c.root, r) else {
            let shown: String = slice_units(r, 120);
            c.todo.push(format!("{place}: reference '{shown}' is not a local reference that resolves (declared string; refine or drop)"));
            return json!({});
        };
        let target = target.clone();
        let mut siblings = s.as_object().cloned().unwrap_or_default();
        siblings.remove("$ref");
        let mut m = spread(Some(&flatten(Some(&target), c, place, depth + 1)), None);
        for (k, v) in siblings {
            m.insert(k, v);
        }
        cur = Value::Object(m);
    }
    if let Some(all) = get(&cur, "allOf").and_then(Value::as_array).cloned() {
        let mut rest = cur.as_object().cloned().unwrap_or_default();
        rest.remove("allOf");
        let mut acc = json!({});
        for m in &all {
            let fm = flatten(Some(m), c, place, depth + 1);
            let mut merged = spread(Some(&acc), Some(&fm));
            merged.insert("properties".into(), Value::Object(spread(get(&acc, "properties"), get(&fm, "properties"))));
            let mut required: Vec<Value> = get(&acc, "required").and_then(Value::as_array).cloned().unwrap_or_default();
            required.extend(get(&fm, "required").and_then(Value::as_array).cloned().unwrap_or_default());
            merged.insert("required".into(), Value::Array(required));
            acc = Value::Object(merged);
        }
        cur = Value::Object(spread(Some(&acc), Some(&Value::Object(rest))));
    }
    let alts = present(get(&cur, "anyOf")).or_else(|| get(&cur, "oneOf")).and_then(Value::as_array).cloned();
    if let Some(alts) = alts {
        let mut rest = cur.as_object().cloned().unwrap_or_default();
        rest.remove("anyOf");
        rest.remove("oneOf");
        let flat: Vec<Value> = alts.iter().map(|m| flatten(Some(m), c, place, depth + 1)).collect();
        let live: Vec<Value> = flat.into_iter().filter(|m| !null_only(m)).collect();
        if live.len() == 1 {
            return Value::Object(spread(Some(&live[0]), Some(&Value::Object(rest))));
        }
        let consts: Vec<Option<Vec<Value>>> = live
            .iter()
            .map(|m| match (get(m, "const"), get(m, "enum").and_then(Value::as_array)) {
                (Some(k @ Value::String(_)), _) => Some(vec![k.clone()]),
                (_, Some(e)) if e.iter().all(Value::is_string) => Some(e.clone()),
                _ => None,
            })
            .collect();
        if live.len() > 1 && consts.iter().all(Option::is_some) {
            let mut seen: Vec<Value> = Vec::new();
            for v in consts.into_iter().flatten().flatten() {
                if !seen.contains(&v) {
                    seen.push(v);
                }
            }
            let mut out = rest;
            out.insert("type".into(), json!("string"));
            out.insert("enum".into(), Value::Array(seen));
            return Value::Object(out);
        }
        c.todo.push(format!("{place}: a union of {} schemas has no schema representation (declared string; refine or drop)", live.len()));
        return Value::Object(rest);
    }
    if get(&cur, "enum").is_none() {
        if let Some(k @ Value::String(_)) = get(&cur, "const") {
            let k = k.clone();
            if let Some(m) = cur.as_object_mut() {
                m.insert("enum".into(), json!([k]));
            }
        }
    }
    cur
}

fn string_enum(v: Option<&Value>) -> Option<Vec<Value>> {
    v.and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string)).cloned()
}

/// JSON Schema property -> parameter declaration. Sensitivity defaults to `material` (the importer never marks anything `free`);
/// unrepresentable shapes become `string` placeholders flagged in `todo`.
fn decl_of_json_schema(name: &str, schema: Option<&Value>, required: bool, c: &mut Ctx<'_>) -> Result<Value, String> {
    let s = flatten(schema, c, &format!("action.params.{name}"), 0);
    let t = match get(&s, "type") {
        Some(Value::Array(a)) => a.iter().find(|x| x.as_str() != Some("null")).cloned(),
        other => other.cloned(),
    };
    let mut base = Map::new();
    base.insert("semantic".into(), present(get(&s, "x-pca-semantic")).cloned().unwrap_or_else(|| json!("unknown")));
    base.insert("sensitivity".into(), present(get(&s, "x-pca-sensitivity")).cloned().unwrap_or_else(|| json!("material")));
    if !required {
        base.insert("required".into(), json!(false));
    }
    if let Some(d) = description_of(get(&s, "description"))? {
        base.insert("description".into(), json!(d));
    }
    if !truthy(get(&s, "x-pca-semantic")) {
        c.todo.push(format!("action.params.{name}: semantic type"));
    }
    let with = |ty: &str, extra: Vec<(&str, Value)>| {
        let mut m = Map::new();
        m.insert("type".into(), json!(ty));
        for (k, v) in &base {
            m.insert(k.clone(), v.clone());
        }
        for (k, v) in extra {
            m.insert(k.into(), v);
        }
        Value::Object(m)
    };
    let int = |k: &str| safe_integer(get(&s, k));
    let t_str = t.as_ref().and_then(Value::as_str);
    if t_str == Some("integer") {
        let mut extra: Vec<(&str, Value)> = Vec::new();
        if int("minimum").is_some() {
            extra.push(("min", get(&s, "minimum").cloned().unwrap_or(Value::Null)));
        } else if let Some(e) = int("exclusiveMinimum") {
            extra.push(("min", jnum(e + 1.0)));
        }
        if int("maximum").is_some() {
            extra.push(("max", get(&s, "maximum").cloned().unwrap_or(Value::Null)));
        } else if let Some(e) = int("exclusiveMaximum") {
            extra.push(("max", jnum(e - 1.0)));
        }
        if let Some(u) = get(&s, "x-pca-unit").filter(|u| truthy(Some(*u))) {
            extra.push(("unit", u.clone()));
        }
        if let Some(a) = get(&s, "x-pca-accumulates-into").filter(|a| truthy(Some(*a))) {
            extra.push(("accumulates_into", a.clone()));
        }
        return Ok(with("integer", extra));
    }
    if t_str == Some("boolean") {
        return Ok(with("boolean", vec![]));
    }
    if t_str == Some("string") && get(&s, "format").and_then(Value::as_str) == Some("date") {
        return Ok(with("date", vec![]));
    }
    if t_str == Some("string") {
        let mut extra: Vec<(&str, Value)> = Vec::new();
        if let Some(e) = string_enum(get(&s, "enum")) {
            extra.push(("values", Value::Array(e)));
        }
        if int("maxLength").is_some_and(|m| m > 0.0) {
            extra.push(("max_len", get(&s, "maxLength").cloned().unwrap_or(Value::Null)));
        }
        return Ok(with("string", extra));
    }
    if t_str == Some("array") {
        let it = flatten(get(&s, "items"), c, &format!("action.params.{name}[]"), 0);
        let it_enum = string_enum(get(&it, "enum"));
        if truthy(get(&s, "uniqueItems")) {
            if let Some(values) = it_enum {
                let mut extra: Vec<(&str, Value)> = vec![("values", Value::Array(values))];
                if int("minItems").is_some() {
                    extra.push(("min_items", get(&s, "minItems").cloned().unwrap_or(Value::Null)));
                }
                if int("maxItems").is_some() {
                    extra.push(("max_items", get(&s, "maxItems").cloned().unwrap_or(Value::Null)));
                }
                return Ok(with("set", extra));
            }
        }
        let it_t = match get(&it, "type") {
            Some(Value::Array(a)) => a.first().cloned(),
            other => other.cloned(),
        };
        let mut extra: Vec<(&str, Value)> = Vec::new();
        if it_t.as_ref().and_then(Value::as_str) == Some("integer") {
            extra.push(("items", json!("integer")));
        }
        if int("maxItems").is_some() {
            extra.push(("max_items", get(&s, "maxItems").cloned().unwrap_or(Value::Null)));
        }
        if int("minItems").is_some() {
            extra.push(("min_items", get(&s, "minItems").cloned().unwrap_or(Value::Null)));
        }
        return Ok(with("array", extra));
    }
    c.todo.push(format!(
        "action.params.{name}: type '{}' has no schema representation (declared string; refine or drop)",
        js_string(t.as_ref())
    ));
    Ok(with("string", vec![]))
}

/// `[A-Za-z0-9_]{1,64}`.
fn schema_name(n: &str) -> bool {
    (1..=64).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn sorted_keys(v: Option<&Value>) -> Vec<String> {
    let mut k: Vec<String> = v.and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default();
    k.sort();
    k
}

fn draft(verbs: Vec<Value>, site: &Value, todo: Vec<String>) -> Value {
    let mut verbs = verbs;
    verbs.sort_by(|a, b| js_string(a.get("verb")).cmp(&js_string(b.get("verb"))));
    json!({
        "schema": {"v": 1, "kind": ACTION_SCHEMA_KIND, "site": site.get("site"), "aud": site.get("aud"), "version": site.get("version"), "verbs": verbs},
        "todo": todo,
    })
}

/// A draft schema from an MCP `tools/list` and the site `{site, aud, version, verbPrefix?}`: `{schema, todo}`. A verb is `prefix + tool.name`;
/// every write verb is drafted `irreversible` (a destructive hint keeps it at least `rate_limited`). `Err` where the reference throws.
pub fn draft_schema_from_mcp_tools(tools: &Value, site: &Value) -> Result<Value, String> {
    let mut todo: Vec<String> = Vec::new();
    let mut verbs: Vec<Value> = Vec::new();
    for t in tools.as_array().ok_or("tools is not iterable")? {
        if t.is_null() {
            return Err("Cannot read properties of null (reading 'inputSchema')".into());
        }
        let tool_name = js_string(get(t, "name"));
        let input_schema = get(t, "inputSchema").unwrap_or(&Value::Null);
        let mut c = Ctx { root: input_schema, todo: std::mem::take(&mut todo), left: None };
        let input = flatten(get(t, "inputSchema"), &mut c, &format!("{tool_name}: inputSchema"), 0);
        let props = get(&input, "properties").cloned().unwrap_or_else(|| json!({}));
        let req: Vec<Value> = get(&input, "required").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut params = Map::new();
        for name in sorted_keys(Some(&props)) {
            if !schema_name(&name) {
                c.todo.push(format!("{tool_name}: parameter '{name}' is not a schema name ([A-Za-z0-9_]{{1,64}}); rename it"));
                continue;
            }
            let decl = decl_of_json_schema(&name, props.get(&name), req.iter().any(|r| r.as_str() == Some(name.as_str())), &mut c)?;
            params.insert(format!("action.params.{name}"), decl);
        }
        todo = c.todo;
        let h = reversibility_from_mcp_hints(get(t, "annotations").unwrap_or(&Value::Null));
        let verb = format!("{}{tool_name}", present(site.get("verbPrefix")).map_or(String::new(), |p| js_string(Some(p))));
        let write = h["kind"] == json!("write");
        if write {
            todo.push(format!("{verb}: reversibility (drafted irreversible)"));
        }
        let mut v = json!({
            "verb": verb,
            "kind": h["kind"],
            "params": Value::Object(params),
            "reversibility": if write { "irreversible" } else { "reversible" },
            "mcp": {"tool": get(t, "name")},
        });
        if let Some(d) = description_of(get(t, "description"))? {
            v["description"] = json!(d);
        }
        verbs.push(v);
    }
    Ok(draft(verbs, site, todo))
}

/// The JSON media type of a request body: `application/json` first, else any `application/*+json`.
fn json_body_schema(b: Option<&Value>) -> Option<Value> {
    let content = b.and_then(|b| get(b, "content")).filter(|c| c.is_object())?;
    let keys = sorted_keys(Some(content));
    let key = keys.iter().find(|k| k.to_lowercase() == "application/json").or_else(|| {
        keys.iter().find(|k| {
            let l = k.to_lowercase();
            l.strip_prefix("application/").is_some_and(|rest| {
                let head = rest.split(';').next().unwrap_or("");
                !rest.is_empty() && (head.ends_with("+json")) && !head.contains(';')
            })
        })
    })?;
    content.get(key.as_str()).and_then(|c| get(c, "schema")).cloned()
}

/// A draft schema from an OpenAPI document and the site `{site, aud, version}`: `{schema, todo}`. One verb per operation with an
/// `operationId` (`x-pca-verb` names it, else the id). The parameters are the operation's path and query parameters (the path item's
/// included, the operation's own winning) plus the properties of its JSON request body (which wins a name clash); local `$ref`s are
/// followed; header and cookie parameters and shared names are flagged in `todo`. `Err` where the reference throws.
pub fn draft_schema_from_open_api(doc: &Value, site: &Value) -> Result<Value, String> {
    let mut c = Ctx { root: doc, todo: Vec::new(), left: None };
    let mut verbs: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    // dereference a local `$ref` of the document; `None` for a non-object, or a reference that does not resolve (flagged)
    fn deref(doc: &Value, x: Option<&Value>, todo: &mut Vec<String>) -> Option<Value> {
        let x = x.filter(|x| x.is_object() || x.is_array())?;
        match get(x, "$ref").and_then(Value::as_str) {
            None => Some(x.clone()),
            Some(r) => {
                let t = pointer(doc, r).cloned();
                if t.is_none() {
                    todo.push(format!("reference '{}' is not a local reference that resolves", slice_units(r, 120)));
                }
                t
            }
        }
    }
    let paths = get(doc, "paths").cloned().unwrap_or_else(|| json!({}));
    for path in sorted_keys(Some(&paths)) {
        let ops = &paths[path.as_str()];
        if ops.is_null() {
            return Err("Cannot read properties of null (reading 'parameters')".into());
        }
        let shared: Vec<Value> = get(ops, "parameters").and_then(Value::as_array).cloned().unwrap_or_default();
        for method in sorted_keys(Some(ops)) {
            let op = &ops[method.as_str()];
            if !op.is_object() || !truthy(get(op, "operationId")) {
                continue;
            }
            c.left = Some(MAX_REF_NODES);
            let op_id = js_string(get(op, "operationId"));
            let lower = method.to_lowercase();
            let read = match present(get(op, "x-pca-kind")).filter(|k| truthy(Some(*k))) {
                Some(k) => k.as_str() == Some("read"),
                None => lower == "get" || lower == "head",
            };
            let verb = present(get(op, "x-pca-verb")).or_else(|| get(op, "operationId")).cloned().unwrap_or(Value::Null);
            let verb_s = js_string(Some(&verb));
            if seen.contains(&verb_s) {
                c.todo.push(format!("{verb_s}: declared by more than one operation; give each a distinct x-pca-verb"));
            }
            seen.push(verb_s.clone());
            let mut params = Map::new();
            // request body first (it wins a name clash), then the operation's own parameters over the path item's
            let body_ref = deref(doc, get(op, "requestBody"), &mut c.todo);
            let body_schema = json_body_schema(body_ref.as_ref());
            let body = flatten(body_schema.as_ref(), &mut c, &format!("{op_id}: request body"), 0);
            let bprops = get(&body, "properties").cloned().unwrap_or_else(|| json!({}));
            let breq: Vec<Value> = get(&body, "required").and_then(Value::as_array).cloned().unwrap_or_default();
            let mut add_name = |name: &str,
                                sch: Option<&Value>,
                                required: bool,
                                source: &str,
                                c: &mut Ctx<'_>,
                                params: &mut Map<String, Value>|
             -> Result<(), String> {
                if !schema_name(name) {
                    c.todo.push(format!("{op_id}: parameter '{name}' is not a schema name; rename it"));
                    return Ok(());
                }
                let key = format!("action.params.{name}");
                if params.contains_key(&key) {
                    c.todo.push(format!("{op_id}: '{name}' is declared by both the {source} and another source; kept the first"));
                    return Ok(());
                }
                let decl = decl_of_json_schema(name, sch, required, c)?;
                params.insert(key, decl);
                Ok(())
            };
            for name in sorted_keys(Some(&bprops)) {
                add_name(
                    &name,
                    bprops.get(&name),
                    breq.iter().any(|r| r.as_str() == Some(name.as_str())),
                    "request body",
                    &mut c,
                    &mut params,
                )?;
            }
            let mut merged: Vec<(String, Value)> = Vec::new();
            let own: Vec<Value> = get(op, "parameters").and_then(Value::as_array).cloned().unwrap_or_default();
            for raw in shared.iter().chain(own.iter()) {
                let Some(q) = deref(doc, Some(raw), &mut c.todo) else { continue };
                let (Some(n), Some(i)) = (get(&q, "name").and_then(Value::as_str), get(&q, "in").and_then(Value::as_str)) else { continue };
                let key = format!("{i}:{n}");
                match merged.iter_mut().find(|(k, _)| *k == key) {
                    Some(slot) => slot.1 = q,
                    None => merged.push((key, q)),
                }
            }
            merged.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, q) in merged {
                let (name, place) =
                    (get(&q, "name").and_then(Value::as_str).unwrap_or(""), get(&q, "in").and_then(Value::as_str).unwrap_or(""));
                if place != "path" && place != "query" {
                    c.todo.push(format!("{op_id}: {place} parameter '{name}' is not an action parameter (the schema sees path, query and body parameters only)"));
                    continue;
                }
                let mut sch = get(&q, "schema").cloned().filter(Value::is_object).unwrap_or_else(|| json!({}));
                if truthy(get(&q, "description")) && !truthy(get(&sch, "description")) {
                    sch["description"] = get(&q, "description").cloned().unwrap_or(Value::Null);
                }
                add_name(
                    name,
                    Some(&sch),
                    place == "path" || get(&q, "required") == Some(&json!(true)),
                    &format!("{place} parameters"),
                    &mut c,
                    &mut params,
                )?;
            }
            let declared_rev = present(get(op, "x-pca-reversibility")).filter(|r| truthy(Some(*r))).cloned();
            let rev = declared_rev.clone().unwrap_or_else(|| json!(if read { "reversible" } else { "irreversible" }));
            if !read && declared_rev.is_none() {
                c.todo.push(format!("{verb_s}: reversibility (drafted irreversible)"));
            }
            let mut v = json!({
                "verb": verb,
                "kind": if read { "read" } else { "write" },
                "params": Value::Object(params),
                "reversibility": rev,
                "openapi": {"operationId": get(op, "operationId")},
            });
            if let Some(d) = description_of(get(op, "description"))? {
                v["description"] = json!(d);
            }
            verbs.push(v);
        }
    }
    Ok(draft(verbs, site, c.todo))
}
