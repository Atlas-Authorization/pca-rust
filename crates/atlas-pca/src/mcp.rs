//! MCP adapter, the pure surface: the client half of MCP authorization step-up (a `WWW-Authenticate` parser, the step-up
//! planner with the PCA `pca_need` extension, the RFC 9207 `iss` table and the client conformance matrix), the tool-result
//! proof meta and `PCA-Action` header, and the v1 action-schema draft from an MCP tool list with its decisions and the
//! closed-world tool-call check.
//!
//! Values are the reference's JSON shapes; inputs follow JavaScript semantics where the reference does (absent members,
//! truthiness, object spread), so a hostile tool list is drafted, or refused, as the reference does. A JavaScript runtime
//! TypeError is an `Err`. The live wrapper `pcaFetch` is [`pca_fetch`] (transport-neutral: the caller sends the request). Not here:
//! `importActionDefsFromMcp` (it delegates to the optional action-kit importer).
use crate::action_schema::{conform_action, is_js_ws, schema_verb};
use crate::oauth::{js_str, truthy};
use serde_json::{json, Map, Value};

pub const MCP_CLIENT_REVISIONS: [&str; 5] = ["2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft"];
const MAX_REF_DEPTH: usize = 8;
const MAX_REF_NODES: i64 = 20_000;
const ACTION_SCHEMA_KIND: &str = "pca-action-schema";

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

/// The client-side MCP authorization conformance matrix (revision -> level per requirement).
pub fn mcp_auth_client_rows() -> Value {
    let l = |a: &str, b: &str, c: &str, d: &str, e: &str| json!({ "2025-03-26": a, "2025-06-18": b, "2025-11-25": c, "2026-07-28": d, "draft": e });
    json!([
        { "id": "parse-www-authenticate", "requirement": "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "levels": l("n/a", "MUST", "MUST", "MUST", "MUST"), "section": "Protected Resource Metadata Discovery Requirements" },
        { "id": "step-up-on-insufficient-scope", "requirement": "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "levels": l("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow" },
        { "id": "scope-union", "requirement": "The new scope set is the union of the previously requested set and the challenge scopes.", "levels": l("n/a", "n/a", "n/a", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow, step 2" },
        { "id": "retry-limit", "requirement": "Retry no more than a few times and track upgrade attempts per resource and operation.", "levels": l("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow, step 4" },
        { "id": "iss-validation-table", "requirement": "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "levels": l("n/a", "n/a", "n/a", "MUST", "MUST"), "section": "Authorization Response Validation" },
        { "id": "pca-need-ignored-by-stock-client", "requirement": "A client that does not know pca_need behaves exactly as without it.", "levels": l("EXT", "EXT", "EXT", "EXT", "EXT"), "section": "RFC 9110 section 11.2 (unknown auth-params are ignored)" },
    ])
}

// ---- WWW-Authenticate ----------------------------------------------------------------------------------------------

/// Parse a `WWW-Authenticate` value into `[{scheme, params}]` (scheme and parameter names lower-cased, quoted values
/// unescaped, a repeated parameter keeps its first value). Never fails: anything but a string is no challenge.
pub fn parse_challenges(header: &Value) -> Value {
    let Some(h) = header.as_str() else { return json!([]) };
    let c: Vec<char> = h.chars().collect();
    let n = c.len();
    let mut i = 0;
    let mut out: Vec<(String, Map<String, Value>)> = Vec::new();
    let ws = |i: &mut usize| {
        while *i < n && matches!(c[*i], ' ' | '\t' | ',') {
            *i += 1;
        }
    };
    let token = |i: &mut usize| -> String {
        let s = *i;
        while *i < n && !" \t,=\"".contains(c[*i]) {
            *i += 1;
        }
        c[s..*i].iter().collect()
    };
    ws(&mut i);
    while i < n {
        let name = token(&mut i);
        if name.is_empty() {
            i += 1; // a stray quote or equals sign
            continue;
        }
        while i < n && matches!(c[i], ' ' | '\t') {
            i += 1;
        }
        if i < n && c[i] == '=' {
            i += 1;
            while i < n && matches!(c[i], ' ' | '\t') {
                i += 1;
            }
            let mut val = String::new();
            if i < n && c[i] == '"' {
                i += 1;
                while i < n && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < n {
                        i += 1;
                    }
                    val.push(c[i]);
                    i += 1;
                }
                i += 1;
            } else {
                val = token(&mut i);
            }
            let key = name.to_lowercase();
            // the reference's params is a plain object: an inherited name ('constructor', '__proto__') is "in" it already
            if let Some((_, p)) = out.last_mut() {
                if key != "constructor" && key != "__proto__" && !p.contains_key(&key) {
                    p.insert(key, json!(val));
                }
            }
        } else {
            out.push((name.to_lowercase(), Map::new()));
        }
        ws(&mut i);
    }
    Value::Array(out.into_iter().map(|(s, p)| json!({ "scheme": s, "params": p })).collect())
}

/// `pcaNeedFromChallenge`: the first `pca_need="..."` (at the start or after whitespace or a comma) decoded, or `None`.
fn pca_need_from_challenge(header: &Value) -> Option<Result<Value, &'static str>> {
    let h = header.as_str()?;
    const P: &str = "pca_need=\"";
    let mut from = 0;
    while let Some(off) = h[from..].find(P) {
        let at = from + off;
        from = at + 1;
        if at > 0 && !h[..at].chars().next_back().is_some_and(|ch| ch == ',' || is_js_ws(ch)) {
            continue;
        }
        let rest = &h[at + P.len()..];
        match rest.find(['"', '\\']) {
            Some(e) if rest.as_bytes()[e] == b'"' => return Some(crate::a2a::decode_need(&json!(&rest[..e]))),
            _ => continue,
        }
    }
    None
}

/// The refusal code of a present but unusable `pca_need`, or `None`.
pub fn pca_need_problem(header: &Value) -> Option<&'static str> {
    match pca_need_from_challenge(header) {
        Some(Err(code)) => Some(code),
        _ => None,
    }
}

/// The next step for a response: only `403` with `error="insufficient_scope"` on a Bearer challenge is a step-up; the
/// scope set is the sorted union of what was requested and what the challenge names; an unchanged union without a usable
/// `pca_need` gives up. `state`: `{requested, attempts, maxAttempts?, pcaAware?}`.
pub fn plan_step_up(status: &Value, header: &Value, state: &Value) -> Result<Value, String> {
    let max = state.get("maxAttempts").filter(|m| !m.is_null()).and_then(Value::as_f64).unwrap_or(3.0);
    let give_up = |r: &str| json!({ "action": "give_up", "reason": r });
    let bearer =
        if status.as_f64() == Some(403.0) { parse_challenges(header).as_array().unwrap().iter().find(|c| c["scheme"] == "bearer").cloned() } else { None };
    let Some(bearer) = bearer.filter(|b| b["params"].get("error").and_then(Value::as_str) == Some("insufficient_scope")) else {
        return Ok(give_up("not_insufficient_scope"));
    };
    let attempts = state.get("attempts").and_then(Value::as_f64).ok_or("state.attempts must be a number")?;
    if !(attempts.is_finite() && attempts < max) {
        return Ok(give_up("retry_limit"));
    }
    let requested = crate::oauth::spread(state.get("requested").unwrap_or(&Value::Null), "state.requested")?;
    let mut union: Vec<Value> = Vec::new();
    let scopes = bearer["params"].get("scope").and_then(Value::as_str).unwrap_or("");
    for s in requested.iter().cloned().chain(scopes.split(' ').filter(|x| !x.is_empty()).map(|x| json!(x))) {
        if !union.contains(&s) {
            union.push(s);
        }
    }
    // Array.prototype.sort: String() of each item, UTF-16 code unit order
    union.sort_by(|a, b| js_str(a).encode_utf16().cmp(js_str(b).encode_utf16()));
    let next = num(attempts + 1.0);
    if state.get("pcaAware") == Some(&Value::Bool(true)) {
        if let Some(Ok(need)) = pca_need_from_challenge(header) {
            return Ok(json!({ "action": "pca", "need": need, "fallbackScopes": union, "attempts": next }));
        }
    }
    if union.iter().all(|s| requested.contains(s)) {
        return Ok(give_up("no_new_scope"));
    }
    Ok(json!({ "action": "scope", "scopes": union, "attempts": next }))
}

/// RFC 9207 section 2.4 as tabulated by the MCP specification: `{recordedIssuer, issParameterSupported, iss}` (an absent
/// `iss` differs from a null one). Simple string comparison, no normalization.
pub fn check_authorization_response_iss(a: &Value) -> Result<Value, String> {
    if a.is_null() {
        return Err("Cannot read properties of null (reading 'recordedIssuer')".into());
    }
    let Some(rec) = a.get("recordedIssuer").and_then(Value::as_str).filter(|r| !r.is_empty()) else {
        return Ok(json!({ "proceed": false, "reason": "no_recorded_issuer" }));
    };
    Ok(match a.get("iss") {
        None => {
            if a.get("issParameterSupported") == Some(&Value::Bool(true)) {
                json!({ "proceed": false, "reason": "iss_missing" })
            } else {
                json!({ "proceed": true })
            }
        }
        Some(Value::String(s)) if s == rec => json!({ "proceed": true }),
        Some(_) => json!({ "proceed": false, "reason": "iss_mismatch" }),
    })
}

// ---- tool results ----------------------------------------------------------------------------------------------------

/// `{...x}` of a JSON value: object members, or array / string items keyed by index; primitives spread nothing.
fn spread_obj(v: Option<&Value>) -> Map<String, Value> {
    match v {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Some(Value::String(s)) => {
            s.encode_utf16().collect::<Vec<u16>>().iter().enumerate().map(|(i, u)| (i.to_string(), json!(String::from_utf16_lossy(&[*u])))).collect()
        }
        _ => Map::new(),
    }
}

/// Attach the encoded PCActn to a tool result's `_meta` (`x-pca-action`), keeping every other member.
pub fn guard_tool_result(pca: &Value, result: &Value) -> Result<Value, String> {
    if result.is_null() {
        return Err("Cannot read properties of null (reading '_meta')".into());
    }
    let meta = result.get("_meta");
    let mut m = if truthy(meta) && matches!(meta, Some(Value::Object(_) | Value::Array(_))) { spread_obj(meta) } else { Map::new() };
    if pca.is_null() {
        return Err("Cannot read properties of null (reading 'encoded')".into());
    }
    m.remove("x-pca-action");
    if let Some(e) = pca.get("encoded") {
        m.insert("x-pca-action".into(), e.clone());
    }
    let mut out = spread_obj(Some(result));
    out.insert("_meta".into(), Value::Object(m));
    Ok(Value::Object(out))
}

/// The `PCA-Action` header carrying an encoded PCActn: base64url of its UTF-8 text.
pub fn pca_headers(encoded: &str) -> Value {
    json!({ "PCA-Action": crate::b64_encode(encoded.as_bytes()) })
}

// ---- action schema draft -------------------------------------------------------------------------------------------

struct Ctx<'a> {
    root: Option<&'a Value>,
    todo: Vec<String>,
    left: i64,
}

fn slice_u16(s: &str, n: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().collect();
    if u.len() <= n {
        s.to_string()
    } else {
        String::from_utf16_lossy(&u[..n])
    }
}

/// `x.slice(0, 1024)` of a truthy value: strings by UTF-16 units, arrays by items, anything else is a TypeError.
fn slice1024(x: &Value, what: &str) -> Result<Value, String> {
    match x {
        Value::String(s) => Ok(json!(slice_u16(s, 1024))),
        Value::Array(a) => Ok(Value::Array(a.iter().take(1024).cloned().collect())),
        _ => Err(format!("{what}.slice is not a function")),
    }
}

fn safe_int(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0)
}

fn pointer<'a>(root: Option<&'a Value>, r: &str) -> Option<&'a Value> {
    let path = r.strip_prefix("#/")?;
    let mut cur = root?;
    for raw in path.split('/') {
        let seg = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(m) => m.get(&seg)?,
            Value::Array(a) => {
                let ok = seg == "0" || (!seg.is_empty() && !seg.starts_with('0') && seg.bytes().all(|b| b.is_ascii_digit()));
                a.get(if ok { seg.parse::<usize>().ok()? } else { return None })?
            }
            _ => return None,
        };
    }
    matches!(cur, Value::Object(_) | Value::Array(_)).then_some(cur)
}

fn nullish(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// `[...x]` for the `required` merge: arrays and strings iterate, anything else is a TypeError.
fn iter_items(v: Option<&Value>) -> Result<Vec<Value>, String> {
    if nullish(v) {
        return Ok(Vec::new());
    }
    crate::oauth::spread(v.unwrap(), "required")
}

fn is_null_type(m: &Map<String, Value>) -> bool {
    match m.get("type") {
        Some(Value::String(t)) => t == "null",
        Some(Value::Array(a)) => a.iter().all(|x| x == "null"),
        _ => false,
    }
}

fn enum_strings(v: Option<&Value>) -> Option<Vec<Value>> {
    v.and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string)).cloned()
}

/// Follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single non-null variant (or a union of string
/// constants); what cannot be represented is flagged in `todo` and left empty (the caller declares it `string`).
fn flatten(s: Option<&Value>, c: &mut Ctx, at: &str, depth: usize) -> Result<Map<String, Value>, String> {
    let s = match s {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::Array(_)) => Map::new(), // an array has no schema members
        _ => return Ok(Map::new()),
    };
    c.left -= 1;
    if c.left < 0 {
        if c.left == -1 {
            c.todo.push(format!("{at}: schema expansion stopped after {MAX_REF_NODES} nodes (declared string; refine or drop)"));
        }
        return Ok(Map::new());
    }
    if depth > MAX_REF_DEPTH {
        c.todo.push(format!("{at}: schema nesting or reference chain deeper than {MAX_REF_DEPTH} (declared string; refine or drop)"));
        return Ok(Map::new());
    }
    let mut cur = s.clone();
    if let Some(Value::String(r)) = s.get("$ref") {
        let Some(target) = pointer(c.root, r) else {
            c.todo.push(format!("{at}: reference '{}' is not a local reference that resolves (declared string; refine or drop)", slice_u16(r, 120)));
            return Ok(Map::new());
        };
        let mut merged = flatten(Some(target), c, at, depth + 1)?;
        for (k, v) in s.iter().filter(|(k, _)| k.as_str() != "$ref") {
            merged.insert(k.clone(), v.clone());
        }
        cur = merged;
    }
    if let Some(Value::Array(all)) = cur.get("allOf").cloned() {
        let mut acc = Map::new();
        for x in &all {
            let m = flatten(Some(x), c, at, depth + 1)?;
            let mut props = spread_obj(acc.get("properties"));
            props.extend(spread_obj(m.get("properties")));
            let mut req = iter_items(acc.get("required"))?;
            req.extend(iter_items(m.get("required"))?);
            let mut next = acc.clone();
            next.extend(m);
            next.insert("properties".into(), Value::Object(props));
            next.insert("required".into(), Value::Array(req));
            acc = next;
        }
        for (k, v) in cur.iter().filter(|(k, _)| k.as_str() != "allOf") {
            acc.insert(k.clone(), v.clone());
        }
        cur = acc;
    }
    let alts = if nullish(cur.get("anyOf")) { cur.get("oneOf") } else { cur.get("anyOf") }.cloned();
    if let Some(Value::Array(alts)) = alts {
        let rest: Map<String, Value> =
            cur.iter().filter(|(k, _)| k.as_str() != "anyOf" && k.as_str() != "oneOf").map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut live = Vec::new();
        for x in &alts {
            let m = flatten(Some(x), c, at, depth + 1)?;
            if !is_null_type(&m) {
                live.push(m);
            }
        }
        if live.len() == 1 {
            let mut out = live.remove(0);
            out.extend(rest);
            return Ok(out);
        }
        let consts: Vec<Option<Vec<Value>>> = live
            .iter()
            .map(|m| match m.get("const") {
                Some(k @ Value::String(_)) => Some(vec![k.clone()]),
                _ => enum_strings(m.get("enum")),
            })
            .collect();
        if live.len() > 1 && consts.iter().all(Option::is_some) {
            let mut vals: Vec<Value> = Vec::new();
            for v in consts.into_iter().flatten().flatten() {
                if !vals.contains(&v) {
                    vals.push(v);
                }
            }
            let mut out = rest;
            out.insert("type".into(), json!("string"));
            out.insert("enum".into(), Value::Array(vals));
            return Ok(out);
        }
        c.todo.push(format!("{at}: a union of {} schemas has no schema representation (declared string; refine or drop)", live.len()));
        return Ok(rest);
    }
    if cur.get("enum").is_none() {
        if let Some(k @ Value::String(_)) = cur.get("const").cloned() {
            cur.insert("enum".into(), json!([k]));
        }
    }
    Ok(cur)
}

fn decl_of(name: &str, schema: Option<&Value>, required: bool, c: &mut Ctx) -> Result<Value, String> {
    let s = flatten(schema, c, &format!("action.params.{name}"), 0)?;
    let t = match s.get("type") {
        Some(Value::Array(a)) => a.iter().find(|x| *x != "null").cloned(),
        t => t.cloned(),
    };
    let ts = t.as_ref().and_then(Value::as_str);
    let mut base = Map::new();
    let sem = s.get("x-pca-semantic").filter(|v| !v.is_null());
    base.insert("semantic".into(), sem.cloned().unwrap_or(json!("unknown")));
    base.insert("sensitivity".into(), s.get("x-pca-sensitivity").filter(|v| !v.is_null()).cloned().unwrap_or(json!("material")));
    if !required {
        base.insert("required".into(), json!(false));
    }
    if truthy(s.get("description")) {
        base.insert("description".into(), slice1024(&s["description"], "s.description")?);
    }
    if !truthy(sem) {
        c.todo.push(format!("action.params.{name}: semantic type"));
    }
    let typed = |ty: &str, base: &Map<String, Value>| {
        let mut m = Map::new();
        m.insert("type".into(), json!(ty));
        m.extend(base.clone());
        m
    };
    match ts {
        Some("integer") => {
            let mut m = typed("integer", &base);
            if let Some(v) = safe_int(s.get("minimum")) {
                m.insert("min".into(), num(v));
            } else if let Some(v) = safe_int(s.get("exclusiveMinimum")) {
                m.insert("min".into(), num(v + 1.0));
            }
            if let Some(v) = safe_int(s.get("maximum")) {
                m.insert("max".into(), num(v));
            } else if let Some(v) = safe_int(s.get("exclusiveMaximum")) {
                m.insert("max".into(), num(v - 1.0));
            }
            if truthy(s.get("x-pca-unit")) {
                m.insert("unit".into(), s["x-pca-unit"].clone());
            }
            if truthy(s.get("x-pca-accumulates-into")) {
                m.insert("accumulates_into".into(), s["x-pca-accumulates-into"].clone());
            }
            Ok(Value::Object(m))
        }
        Some("boolean") => Ok(Value::Object(typed("boolean", &base))),
        Some("string") if s.get("format").and_then(Value::as_str) == Some("date") => Ok(Value::Object(typed("date", &base))),
        Some("string") => {
            let mut m = typed("string", &base);
            if let Some(e) = enum_strings(s.get("enum")) {
                m.insert("values".into(), Value::Array(e));
            }
            if let Some(v) = safe_int(s.get("maxLength")).filter(|v| *v > 0.0) {
                m.insert("max_len".into(), num(v));
            }
            Ok(Value::Object(m))
        }
        Some("array") => {
            let it = flatten(s.get("items"), c, &format!("action.params.{name}[]"), 0)?;
            let it_enum = enum_strings(it.get("enum"));
            if truthy(s.get("uniqueItems")) && it_enum.is_some() {
                let mut m = typed("set", &base);
                m.insert("values".into(), Value::Array(it_enum.unwrap()));
                if let Some(v) = safe_int(s.get("minItems")) {
                    m.insert("min_items".into(), num(v));
                }
                if let Some(v) = safe_int(s.get("maxItems")) {
                    m.insert("max_items".into(), num(v));
                }
                return Ok(Value::Object(m));
            }
            let it_t = match it.get("type") {
                Some(Value::Array(a)) => a.first().cloned(),
                t => t.cloned(),
            };
            let mut m = typed("array", &base);
            if it_t.as_ref().and_then(Value::as_str) == Some("integer") {
                m.insert("items".into(), json!("integer"));
            }
            if let Some(v) = safe_int(s.get("maxItems")) {
                m.insert("max_items".into(), num(v));
            }
            if let Some(v) = safe_int(s.get("minItems")) {
                m.insert("min_items".into(), num(v));
            }
            Ok(Value::Object(m))
        }
        _ => {
            let tn = t.as_ref().map_or_else(|| "undefined".to_string(), js_str);
            c.todo.push(format!("action.params.{name}: type '{tn}' has no schema representation (declared string; refine or drop)"));
            Ok(Value::Object(typed("string", &base)))
        }
    }
}

/// `t[k]` for a tool value: own members of an object; a primitive or array has none of the tool members.
fn own<'a>(t: &'a Value, k: &str) -> Option<&'a Value> {
    t.as_object().and_then(|m| m.get(k))
}

/// MCP annotations give a LOWER bound on reversibility only (hints never lower a classification).
pub fn reversibility_from_mcp_hints(a: Option<&Value>) -> Value {
    let hint = |k: &str| a.and_then(|a| own(a, k)) == Some(&Value::Bool(true));
    if hint("readOnlyHint") {
        json!({ "kind": "read", "atLeast": "reversible" })
    } else if hint("destructiveHint") {
        json!({ "kind": "write", "atLeast": "rate_limited" })
    } else {
        json!({ "kind": "write", "atLeast": "reversible" })
    }
}

fn is_schema_name(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Draft a v1 action schema from an MCP `tools/list` (`{schema, todo}`): verb = `<verbPrefix><tool.name>`, every write
/// verb drafted `irreversible` (the fail-closed default). `site`: `{site, aud, version, verbPrefix?}`.
pub fn draft_action_schema_from_mcp(tools: &Value, site: &Value) -> Result<Value, String> {
    let Some(tools) = tools.as_array() else { return Err("source.listTools is not a function".into()) };
    if site.is_null() {
        return Err("Cannot read properties of null (reading 'verbPrefix')".into());
    }
    let mut todo: Vec<String> = Vec::new();
    let mut verbs: Vec<Value> = Vec::new();
    for t in tools {
        if t.is_null() {
            return Err("Cannot read properties of null (reading 'inputSchema')".into());
        }
        let name_s = own(t, "name").map_or_else(|| "undefined".to_string(), js_str);
        let mut c = Ctx { root: own(t, "inputSchema"), todo: std::mem::take(&mut todo), left: MAX_REF_NODES };
        let input = flatten(own(t, "inputSchema"), &mut c, &format!("{name_s}: inputSchema"), 0)?;
        let props = input.get("properties").filter(|p| !p.is_null()).cloned().unwrap_or(json!({}));
        let req = iter_items(input.get("required"))?;
        let mut keys: Vec<(String, Value)> = match &props {
            Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
            Value::String(s) => {
                s.encode_utf16().collect::<Vec<u16>>().iter().enumerate().map(|(i, u)| (i.to_string(), json!(String::from_utf16_lossy(&[*u])))).collect()
            }
            _ => Vec::new(),
        };
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let mut params = Map::new();
        for (pname, pv) in &keys {
            if !is_schema_name(pname) {
                c.todo.push(format!("{name_s}: parameter '{pname}' is not a schema name ([A-Za-z0-9_]{{1,64}}); rename it"));
                continue;
            }
            let required = req.iter().any(|r| r.as_str() == Some(pname));
            params.insert(format!("action.params.{pname}"), decl_of(pname, Some(pv), required, &mut c)?);
        }
        todo = c.todo;
        let h = reversibility_from_mcp_hints(own(t, "annotations"));
        let prefix = site.get("verbPrefix").filter(|p| !p.is_null()).map_or_else(String::new, js_str);
        let verb = format!("{prefix}{name_s}");
        let read = h["kind"] == "read";
        if !read {
            todo.push(format!("{verb}: reversibility (drafted irreversible)"));
        }
        let mut e = Map::new();
        e.insert("verb".into(), json!(verb));
        e.insert("kind".into(), h["kind"].clone());
        e.insert("params".into(), Value::Object(params));
        e.insert("reversibility".into(), json!(if read { "reversible" } else { "irreversible" }));
        e.insert("mcp".into(), own(t, "name").map_or_else(|| json!({}), |n| json!({ "tool": n })));
        if truthy(own(t, "description")) {
            e.insert("description".into(), slice1024(&t["description"], "t.description")?);
        }
        verbs.push(Value::Object(e));
    }
    verbs.sort_by(|a, b| a["verb"].as_str().unwrap_or("").cmp(b["verb"].as_str().unwrap_or("")));
    let mut schema = Map::new();
    schema.insert("v".into(), json!(1));
    schema.insert("kind".into(), json!(ACTION_SCHEMA_KIND));
    for k in ["site", "aud", "version"] {
        if let Some(v) = site.get(k) {
            schema.insert(k.into(), v.clone());
        }
    }
    schema.insert("verbs".into(), Value::Array(verbs));
    Ok(json!({ "schema": schema, "todo": todo }))
}

/// `Object.entries(x)`: null is a TypeError; arrays and strings list their items by index.
fn entries(v: Option<&Value>) -> Result<Vec<(String, Value)>, String> {
    match v {
        None | Some(Value::Null) => Err("Cannot convert undefined or null to object".into()),
        Some(x) => Ok(spread_obj(Some(x)).into_iter().collect()),
    }
}

/// Record the developer's decisions on a draft (a new object). A decision about a verb or parameter the draft does not
/// have is refused: the schema is closed, so a typo must not silently publish a looser schema.
pub fn apply_schema_decisions(draft: &Value, d: &Value) -> Result<Value, String> {
    let mut out = draft.clone();
    if d.is_null() {
        return Err("Cannot read properties of null (reading 'units')".into());
    }
    if truthy(d.get("units")) {
        let mut u = spread_obj(out.get("units").filter(|x| !x.is_null()));
        u.extend(spread_obj(d.get("units")));
        match out.as_object_mut() {
            Some(o) => {
                o.insert("units".into(), Value::Object(u));
            }
            None => return Err("Cannot create property 'units' on a non-object draft".into()),
        }
    }
    for (verb, dv) in entries(d.get("verbs"))? {
        let Some(vs) = out.get_mut("verbs").and_then(Value::as_array_mut) else { return Err("out.verbs.find is not a function".into()) };
        let mut found = None;
        for (i, x) in vs.iter().enumerate() {
            if x.is_null() {
                return Err("Cannot read properties of null (reading 'verb')".into());
            }
            if x.get("verb").and_then(Value::as_str) == Some(verb.as_str()) {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else { return Err(format!("applySchemaDecisions: the draft has no verb '{verb}'")) };
        let v = &mut vs[i];
        if dv.is_null() {
            return Err("Cannot read properties of null (reading 'reversibility')".into());
        }
        if truthy(own(&dv, "reversibility")) {
            v["reversibility"] = dv["reversibility"].clone();
        }
        let dp_all = own(&dv, "params").filter(|p| !p.is_null()).cloned().unwrap_or(json!({}));
        for (path, dp) in entries(Some(&dp_all))? {
            let vp = v.get_mut("params").filter(|p| !p.is_null()).ok_or("Cannot read properties of undefined (reading 'params')")?;
            let p = vp.as_object_mut().and_then(|m| m.get_mut(&path));
            if !truthy(p.as_deref()) {
                return Err(format!("applySchemaDecisions: verb '{verb}' has no parameter '{path}'"));
            }
            // Object.assign on a non-object declaration changes only a throwaway wrapper
            if let Some(Value::Object(pm)) = p {
                pm.extend(spread_obj(Some(&dp)));
            }
        }
    }
    Ok(out)
}

/// JavaScript `===` of two JSON values from separate parses: primitives by value, objects and arrays never equal.
fn strict_eq(a: Option<&Value>, b: &Value) -> bool {
    match (a, b) {
        (None, _) => false, // the tool name argument is never undefined here
        (Some(x), y) => !matches!(x, Value::Object(_) | Value::Array(_)) && x == y,
    }
}

fn verb_of(schema: &Value, tool: &Value) -> Result<Option<Value>, String> {
    if schema.is_null() {
        return Err("Cannot read properties of null (reading 'verbs')".into());
    }
    let Some(verbs) = schema.get("verbs").and_then(Value::as_array) else { return Err("schema.verbs.find is not a function".into()) };
    for v in verbs {
        if v.is_null() {
            return Err("Cannot read properties of null (reading 'mcp')".into());
        }
        let t = v.get("mcp").filter(|m| !m.is_null()).and_then(|m| own(m, "tool"));
        if strict_eq(t, tool) {
            return Ok(v.get("verb").cloned());
        }
    }
    Ok(None)
}

/// The schema verb an MCP tool maps to (by `mcp.tool`), or `null`.
pub fn verb_of_tool(schema: &Value, tool: &Value) -> Result<Value, String> {
    Ok(verb_of(schema, tool)?.unwrap_or(Value::Null))
}

/// Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb): `{ok, verb?}` or
/// `{ok: false, code, path?, reason}`.
pub fn conform_tool_call(schema: &Value, tool: &Value, args: &Value) -> Result<Value, String> {
    let Some(verb) = verb_of(schema, tool)? else {
        return Ok(json!({ "ok": false, "code": "unknown_verb", "reason": format!("MCP tool '{}' is not declared by the site schema", js_str(tool)) }));
    };
    let vs = js_str(&verb);
    let r = conform_action(schema, &vs, args);
    if r.ok {
        let decl = schema_verb(schema, &vs).ok().flatten().map(|m| Value::Object(m.clone())).unwrap_or(Value::Null);
        return Ok(json!({ "ok": true, "verb": decl }));
    }
    let mut m = Map::new();
    m.insert("ok".into(), json!(false));
    m.insert("code".into(), json!(r.code));
    if let Some(p) = r.path {
        m.insert("path".into(), json!(p));
    }
    m.insert("reason".into(), json!(r.reason));
    Ok(Value::Object(m))
}

/// `{MCP_CLIENT_REVISIONS, MCP_AUTH_CLIENT_ROWS}`.
pub fn constants() -> Value {
    json!({ "MCP_CLIENT_REVISIONS": MCP_CLIENT_REVISIONS, "MCP_AUTH_CLIENT_ROWS": mcp_auth_client_rows() })
}

// ---------------------------------------------------------------------------------------------------- pcaFetch (agent side)
/// An outbound MCP HTTP request, transport-neutral: the caller's HTTP client sends it.
#[derive(Debug, Clone, Default)]
pub struct McpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// What the transport answered. `body` is `None` when the body could not be read.
#[derive(Debug, Clone, Default)]
pub struct McpResponse {
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// A failure of [`pca_fetch`]: the proof could not be built (nothing was sent), or the transport failed.
#[derive(Debug)]
pub enum PcaFetchError<E> {
    Pca(String),
    Transport(E),
}

/// The `tools/call` of a JSON-RPC body: the tool name and its arguments (`{}` unless an object).
fn tool_call_of(body: &str) -> Option<(String, Value)> {
    let msg: Value = serde_json::from_str(body).ok()?;
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let name = msg.pointer("/params/name")?.as_str()?.to_string();
    let args = msg.pointer("/params/arguments").filter(|a| a.is_object()).cloned().unwrap_or_else(|| json!({}));
    Some((name, args))
}

/// The agent side of an MCP server that requires a PCActn per tool call (the reference's `pcaFetch`). For a JSON-RPC `tools/call`
/// request it builds a fresh PCActn for that call (verb and resource from `tool_action`, the arguments committed by digest, a new
/// counter), sets it as the `PCA-Action` header (plus the provenance bundle when `session` is given), sends the request through
/// `send` and records the response as UNTRUSTED tool output before returning it. Every other request, and a tool `tool_action` maps
/// to `None`, passes through unchanged. It decides nothing: the server's verifier does. `aud` must equal the agent's own audience (a
/// different one is refused: the audience is the agent's).
pub fn pca_fetch<E>(
    agent: &crate::agent::Agent,
    mut session: Option<&mut crate::adapters::AdapterSession>,
    tool_action: &dyn Fn(&str, &Value) -> Option<(String, String)>,
    aud: Option<&str>,
    suite: &crate::agent::Suite,
    mut req: McpRequest,
    send: impl FnOnce(McpRequest) -> Result<McpResponse, E>,
) -> Result<McpResponse, PcaFetchError<E>> {
    let call = req.body.as_deref().and_then(tool_call_of);
    let Some((name, args)) = call else { return send(req).map_err(PcaFetchError::Transport) };
    let Some((verb, resource)) = tool_action(&name, &args) else { return send(req).map_err(PcaFetchError::Transport) };
    if aud.is_some_and(|a| a != agent.aud) {
        return Err(PcaFetchError::Pca("pca_fetch: the audience override differs from the agent's audience".into()));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(s) = session.as_deref_mut() {
        let b = s.recorder.for_action(&crate::Operation::new(verb.clone(), resource.clone(), args.clone())).map_err(PcaFetchError::Pca)?;
        headers.extend(crate::adapters::provenance_headers(Some(&b)).map_err(PcaFetchError::Pca)?);
    }
    let act = agent.act(&verb, &resource, Some(&args), Map::new(), suite).map_err(PcaFetchError::Pca)?;
    headers.extend(act.headers);
    for (k, v) in headers {
        req.headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&k));
        req.headers.push((k, v));
    }
    let url = req.url.clone();
    let res = send(req).map_err(PcaFetchError::Transport)?;
    if let Some(s) = session {
        let stream = res.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("event-stream"));
        let content = match (&res.body, stream) {
            (Some(b), false) => Value::String(b.clone()),
            _ => json!({"tool": name, "stream": url}),
        };
        s.record_tool_result(&name, &content).map_err(PcaFetchError::Pca)?;
    }
    Ok(res)
}

#[cfg(test)]
mod pca_fetch_tests {
    use super::*;

    #[test]
    fn only_a_tools_call_with_a_string_name_is_a_tool_call() {
        let c = tool_call_of(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":[1]}}"#).expect("call");
        assert_eq!(c, ("t".to_string(), json!({})));
        assert!(tool_call_of(r#"{"method":"tools/list"}"#).is_none());
        assert!(tool_call_of(r#"{"method":"tools/call","params":{"name":3}}"#).is_none());
        assert!(tool_call_of("not json").is_none());
    }
}
