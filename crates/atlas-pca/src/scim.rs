//! SCIM 2.0 provisioning of agent passports (RFC 7643 / 7644): the passport <-> SCIM `Agent` mapping, the `attr eq "value"`
//! filter subset, PATCH, a framework-agnostic `/Agents` handler over an in-memory store, and the Microsoft Entra Agent ID /
//! Okta push adapters. Requests, responses and resources are JSON values in the reference's shapes, byte-identical to it
//! (resource `meta.version` = `W/"<strict canonical hash of the resource without meta>"`).
use crate::action_schema::is_js_ws;
use crate::actions::js_to_number;
use crate::agent::issue_passport;
use crate::oauth::{js_str, spread};
use crate::revoke::member;
use serde_json::{json, Map, Value};
use std::sync::Mutex;

pub const AGENT_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:atlas:2.0:Agent";
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const AGENT_RESOURCE_TYPE: &str = "Agent";
pub const ENTRA_AGENT_EXTENSION_URN: &str = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent";
pub const OKTA_AGENT_EXTENSION_URN: &str = "urn:okta:scim:schemas:custom:1.0:Agent";
const SCIM_CONTENT_TYPE: &str = "application/scim+json";
const FILTERABLE: [&str; 6] = ["userName", "displayName", "externalId", "id", "active", "owner"];
const MUTABLE_PATHS: [&str; 6] = ["active", "displayName", "externalId", "owner", "capabilities", "holder"];

pub use crate::agent::passport_fingerprint;

/// A SCIM value error: `(scimType, detail)`, answered as a 400 by the handler.
#[derive(Debug, Clone, PartialEq)]
pub struct ScimValueError {
    pub scim_type: &'static str,
    pub detail: String,
}

fn verr<T>(scim_type: &'static str, detail: impl Into<String>) -> Result<T, ScimValueError> {
    Err(ScimValueError { scim_type, detail: detail.into() })
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

/// `new Date(ms).toISOString()`; `Err` past the ECMAScript time range (RangeError there).
pub fn iso_at(ms: f64) -> Result<String, String> {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        return Err("Invalid time value".into());
    }
    let t = ms.trunc() as i64;
    let (days, rem) = (t.div_euclid(86_400_000), t.rem_euclid(86_400_000));
    // civil-from-days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let year = if (0..=9999).contains(&y) { format!("{y:04}") } else { format!("{}{:06}", if y < 0 { '-' } else { '+' }, y.abs()) };
    let (h, mi, s, frac) = (rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000);
    Ok(format!("{year}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{frac:03}Z"))
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn nn<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    member(v, k).filter(|x| !x.is_null())
}

/// Project a passport into a SCIM Agent resource. `proj` = `{owner, displayName?, externalId?, active?, capabilities?,
/// holder?}`; `meta` = `{baseUrl?, created?, lastModified?, now?}` (`now` in ms; default the clock). `Err` when the resource
/// is outside the strict canonical profile (e.g. no `owner`), as the reference's hash refuses it.
pub fn passport_to_scim(passport: &Value, proj: &Value, meta: &Value) -> Result<Value, String> {
    let clock = nn(meta, "now").and_then(Value::as_f64);
    passport_to_scim_with(passport, proj, meta, &|| clock.unwrap_or_else(now_ms))
}

fn passport_to_scim_with(passport: &Value, proj: &Value, meta: &Value, now: &dyn Fn() -> f64) -> Result<Value, String> {
    let id = member(passport, "id").cloned();
    let label = |k: &str| member(passport, k).map_or_else(|| "undefined".into(), js_str);
    let mut base = Map::new();
    base.insert("schemas".into(), json!([AGENT_SCHEMA_URN]));
    if let Some(i) = &id {
        base.insert("id".into(), i.clone());
    }
    base.insert("displayName".into(), nn(proj, "displayName").cloned().unwrap_or_else(|| json!(format!("{} ({})", label("model_id"), label("operator")))));
    base.insert("active".into(), nn(proj, "active").cloned().unwrap_or(json!(true)));
    let owner = member(proj, "owner").ok_or("passportToScim: owner is undefined (outside the canonical JSON profile)")?;
    base.insert("owner".into(), owner.clone());
    let caps = match member(proj, "capabilities") {
        Some(c) if crate::oauth::truthy(Some(c)) => spread(c, "capabilities")?,
        _ => Vec::new(),
    };
    base.insert("capabilities".into(), Value::Array(caps));
    if let Some(i) = &id {
        base.insert("passportRef".into(), i.clone());
    }
    base.insert("passport".into(), passport.clone());
    for k in ["externalId", "holder"] {
        if let Some(v) = member(proj, k) {
            base.insert(k.into(), v.clone());
        }
    }
    if id.is_none() {
        return Err("passportToScim: passport.id is undefined (outside the canonical JSON profile)".into());
    }
    let digest = crate::hash_canonical_strict(&Value::Object(base.clone())).ok_or("passportToScim: the resource is outside the canonical JSON profile")?;
    let prefix = match member(meta, "baseUrl") {
        Some(b) => js_str(b).trim_end_matches('/').to_string(),
        None => String::new(),
    };
    let created = match nn(meta, "created") {
        Some(c) => c.clone(),
        None => json!(iso_at(now())?),
    };
    let last = match nn(meta, "lastModified") {
        Some(c) => c.clone(),
        None => json!(iso_at(now())?),
    };
    let location = format!("{prefix}/Agents/{}", encode_uri_component(&js_str(id.as_ref().unwrap_or(&Value::Null))));
    base.insert(
        "meta".into(),
        json!({ "resourceType": AGENT_RESOURCE_TYPE, "created": created, "lastModified": last, "location": location, "version": format!("W/\"{digest}\"") }),
    );
    Ok(Value::Object(base))
}

fn as_bool(v: Option<&Value>) -> Option<bool> {
    match v {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) if s == "true" => Some(true),
        Some(Value::String(s)) if s == "false" => Some(false),
        _ => None,
    }
}

fn as_string(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| x.is_string())
}

fn as_string_array(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| x.as_array().is_some_and(|a| a.iter().all(Value::is_string)))
}

fn read_identity(body: &Map<String, Value>) -> Result<Value, ScimValueError> {
    if let Some(Value::Object(n)) = body.get("passport") {
        let (Some(model), Some(op)) = (as_string(n.get("model_id")), as_string(n.get("operator"))) else {
            return verr("invalidValue", "passport.model_id and passport.operator are required");
        };
        let mut id = Map::new();
        id.insert("model_id".into(), model.clone());
        id.insert("operator".into(), op.clone());
        id.insert("hardware_rooted".into(), json!(as_bool(n.get("hardware_rooted")).unwrap_or(false)));
        id.insert("issued_at".into(), n.get("issued_at").filter(|x| x.is_number()).cloned().unwrap_or(json!(0)));
        for k in ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"] {
            if let Some(v) = as_string(n.get(k)) {
                id.insert(k.into(), v.clone());
            }
        }
        if let Some(m) = as_bool(n.get("weights_measured")) {
            id.insert("weights_measured".into(), json!(m));
        }
        return Ok(Value::Object(id));
    }
    let (Some(model), Some(op)) = (as_string(body.get("model")).or_else(|| as_string(body.get("model_id"))), as_string(body.get("operator"))) else {
        return verr("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`");
    };
    Ok(json!({ "model_id": model, "operator": op, "hardware_rooted": as_bool(body.get("hardwareRooted")).unwrap_or(false), "issued_at": 0 }))
}

fn read_projection(body: &Map<String, Value>) -> Value {
    let nested_op = body.get("passport").filter(|p| p.is_object()).and_then(|p| as_string(p.get("operator")));
    let owner = as_string(body.get("owner")).or_else(|| as_string(body.get("operator"))).or(nested_op).cloned().unwrap_or(json!(""));
    let mut p = Map::new();
    p.insert("owner".into(), owner);
    for k in ["displayName", "externalId"] {
        if let Some(v) = as_string(body.get(k)) {
            p.insert(k.into(), v.clone());
        }
    }
    if let Some(a) = as_bool(body.get("active")) {
        p.insert("active".into(), json!(a));
    }
    if let Some(c) = as_string_array(body.get("capabilities")) {
        p.insert("capabilities".into(), c.clone());
    }
    if let Some(h) = as_string(body.get("holder")) {
        p.insert("holder".into(), h.clone());
    }
    Value::Object(p)
}

/// Read an untrusted SCIM Agent body (nested `passport` object, or the flat IdP form `model` + `operator`) into
/// `{identity, projection}`.
pub fn scim_to_provisioning_request(value: &Value) -> Result<Value, ScimValueError> {
    let Value::Object(body) = value else { return verr("invalidSyntax", "request body must be a JSON object") };
    if let Some(s) = body.get("schemas") {
        if !s.as_array().is_some_and(|a| a.contains(&json!(AGENT_SCHEMA_URN))) {
            return verr("invalidValue", format!("schemas must include {AGENT_SCHEMA_URN}"));
        }
    }
    Ok(json!({ "identity": read_identity(body)?, "projection": read_projection(body) }))
}

/// A SCIM error envelope.
pub fn scim_error(status: u16, detail: &str, scim_type: Option<Value>) -> Value {
    let mut b = json!({ "schemas": [ERROR_SCHEMA], "status": status.to_string(), "detail": detail });
    if let Some(t) = scim_type {
        b["scimType"] = t;
    }
    b
}

/// A SCIM ListResponse envelope.
pub fn scim_list_response(resources: Vec<Value>, total: Value, start_index: Value) -> Value {
    json!({ "schemas": [LIST_RESPONSE_SCHEMA], "totalResults": total, "startIndex": start_index, "itemsPerPage": resources.len(), "Resources": resources })
}

/// Parse the supported filter subset `attr eq "value"` / `attr eq true|false` into `{attr, value}`.
pub fn parse_filter(filter: &Value) -> Result<Value, ScimValueError> {
    let Some(f) = filter.as_str() else { return verr("invalidFilter", "filter must be a string") };
    let unsupported = || verr("invalidFilter", format!("unsupported filter (only `attr eq \"value\"` is supported): {f}"));
    let cs: Vec<char> = f.chars().collect();
    let mut i = 0;
    let ws = |i: &mut usize| {
        let s = *i;
        while *i < cs.len() && is_js_ws(cs[*i]) {
            *i += 1;
        }
        *i > s
    };
    ws(&mut i);
    let a0 = i;
    while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '_') {
        i += 1;
    }
    if i == a0 || !ws(&mut i) {
        return unsupported();
    }
    let attr: String = cs[a0..i].iter().collect::<String>().trim_end_matches(is_js_ws).to_string();
    if !(cs.len() >= i + 2 && cs[i].eq_ignore_ascii_case(&'e') && cs[i + 1].eq_ignore_ascii_case(&'q')) {
        return unsupported();
    }
    i += 2;
    if !ws(&mut i) {
        return unsupported();
    }
    let value = if cs.get(i) == Some(&'"') {
        i += 1;
        let mut raw = String::new();
        loop {
            match cs.get(i) {
                None => return unsupported(),
                Some('"') => break,
                Some('\\') => match cs.get(i + 1) {
                    Some(&c) if !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}') => {
                        raw.push(c);
                        i += 2;
                    }
                    _ => return unsupported(),
                },
                Some(&c) => {
                    raw.push(c);
                    i += 1;
                }
            }
        }
        i += 1;
        json!(raw)
    } else {
        let rest: String = cs[i..].iter().collect();
        let word = rest.get(..4).filter(|w| w.eq_ignore_ascii_case("true")).or_else(|| rest.get(..5).filter(|w| w.eq_ignore_ascii_case("false")));
        let Some(w) = word else { return unsupported() };
        i += w.chars().count();
        json!(w.eq_ignore_ascii_case("true"))
    };
    ws(&mut i);
    if i != cs.len() {
        return unsupported();
    }
    if !FILTERABLE.contains(&attr.as_str()) {
        return verr("invalidFilter", format!("filter attribute not supported: {attr}"));
    }
    Ok(json!({ "attr": attr, "value": value }))
}

fn matches_filter(agent: &Value, f: &Value) -> bool {
    let attr = match f["attr"].as_str() {
        Some("userName") => "displayName",
        Some(a) => a,
        None => return false,
    };
    member(agent, attr) == Some(&f["value"])
}

/// Object keys in JavaScript property order (array-index keys ascending, then insertion order).
fn js_keys(m: &Map<String, Value>) -> Vec<&String> {
    let idx = |k: &str| k.parse::<u32>().ok().filter(|n| *n != u32::MAX && n.to_string() == k);
    let mut ix: Vec<&String> = m.keys().filter(|k| idx(k).is_some()).collect();
    ix.sort_by_key(|k| idx(k));
    ix.extend(m.keys().filter(|k| idx(k).is_none()));
    ix
}

fn read_patch_ops(value: &Value) -> Result<Vec<(String, Option<String>, Option<Value>)>, ScimValueError> {
    let Value::Object(body) = value else { return verr("invalidSyntax", "PATCH body must be a JSON object") };
    let ops = match body.get("Operations") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => return verr("invalidValue", "PATCH requires a non-empty Operations array"),
    };
    ops.iter()
        .map(|raw| {
            let o = raw.as_object();
            let op = o.and_then(|o| o.get("op")).and_then(Value::as_str).map(str::to_lowercase);
            let Some(op) = op.filter(|x| matches!(x.as_str(), "add" | "replace" | "remove")) else {
                return verr("invalidValue", format!("unsupported PATCH op: {}", o.and_then(|o| o.get("op")).map_or_else(|| "undefined".into(), js_str)));
            };
            let path = o.and_then(|o| o.get("path")).and_then(Value::as_str).map(String::from);
            Ok((op, path, o.and_then(|o| o.get("value")).cloned()))
        })
        .collect()
}

fn projection_of(r: &Value) -> Value {
    let mut p = Map::new();
    for k in ["owner", "active", "capabilities", "displayName", "externalId", "holder"] {
        if let Some(v) = member(r, k) {
            p.insert(k.into(), v.clone());
        }
    }
    Value::Object(p)
}

fn apply_scalar(p: &mut Map<String, Value>, path: &str, op: &str, value: Option<&Value>) -> Result<(), ScimValueError> {
    match path {
        "active" => {
            let b = if op == "remove" {
                true
            } else {
                as_bool(value).ok_or(ScimValueError { scim_type: "invalidValue", detail: "`active` must be a boolean".into() })?
            };
            p.insert("active".into(), json!(b));
        }
        "capabilities" => {
            let v = if op == "remove" {
                json!([])
            } else {
                let arr = as_string_array(value).ok_or(ScimValueError { scim_type: "invalidValue", detail: "`capabilities` must be a string array".into() })?;
                if op == "add" {
                    let mut all = p.get("capabilities").and_then(Value::as_array).cloned().unwrap_or_default();
                    all.extend(arr.as_array().into_iter().flatten().cloned());
                    Value::Array(all)
                } else {
                    arr.clone()
                }
            };
            p.insert("capabilities".into(), v);
        }
        _ if op == "remove" => {
            if path == "displayName" || path == "owner" {
                return verr("mutability", format!("`{path}` cannot be removed"));
            }
            p.remove(path);
        }
        _ => {
            let Some(s) = as_string(value) else { return verr("invalidValue", format!("`{path}` must be a string")) };
            p.insert(path.into(), s.clone());
        }
    }
    Ok(())
}

fn apply_patch_op(p: &mut Map<String, Value>, (op, path, value): &(String, Option<String>, Option<Value>)) -> Result<(), ScimValueError> {
    let Some(path) = path else {
        if op == "remove" {
            return verr("noTarget", "a `remove` op requires a `path`");
        }
        let Some(Value::Object(obj)) = value else { return verr("invalidValue", "a pathless PATCH value must be an object") };
        for k in js_keys(obj) {
            if !MUTABLE_PATHS.contains(&k.as_str()) {
                return verr("mutability", format!("attribute is immutable or unknown: {k}"));
            }
            apply_scalar(p, k, "replace", obj.get(k))?;
        }
        return Ok(());
    };
    if !MUTABLE_PATHS.contains(&path.as_str()) {
        return verr("mutability", format!("attribute is immutable or unknown: {path}"));
    }
    apply_scalar(p, path, op, value.as_ref())
}

/// Options of [`ScimHandler`]. `authenticate` is required unless `allow_unauthenticated` (a request is served only when it
/// returns `true`); `now` is the clock in ms for `meta` timestamps.
#[derive(Default)]
pub struct ScimHandlerOptions {
    pub base_url: Option<String>,
    pub now: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    pub authenticate: Option<Box<dyn Fn(&Value) -> bool + Send + Sync>>,
    pub allow_unauthenticated: bool,
}

/// The `/Agents` endpoint over an in-memory store (insertion-ordered by resource id; each entry `(resource, passport)`).
pub struct ScimHandler {
    store: Mutex<Vec<(String, Value, Value)>>,
    opts: ScimHandlerOptions,
}

fn response(status: u16, body: Value, extra: &[(&str, &Value)]) -> Value {
    let mut h = Map::new();
    h.insert("content-type".into(), json!(SCIM_CONTENT_TYPE));
    for (k, v) in extra {
        h.insert((*k).into(), (*v).clone());
    }
    json!({ "status": status, "body": body, "headers": h })
}

fn error_response(status: u16, detail: &str, scim_type: Option<&str>) -> Value {
    response(status, scim_error(status, detail, scim_type.map(|t| json!(t))), &[])
}

fn value_error(e: ScimValueError) -> Value {
    error_response(400, &e.detail, Some(e.scim_type))
}

fn resource_response(status: u16, r: &Value) -> Value {
    response(status, r.clone(), &[("location", &r["meta"]["location"]), ("etag", &r["meta"]["version"])])
}

/// `Number(v)` when it is an integer, else the fallback (absent: the fallback).
fn int_param(v: Option<&Value>, fallback: f64) -> f64 {
    if v.is_none() {
        return fallback;
    }
    let n = js_to_number(v);
    if n.is_finite() && n.trunc() == n {
        n
    } else {
        fallback
    }
}

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

impl ScimHandler {
    pub fn new(opts: ScimHandlerOptions) -> Result<Self, String> {
        if opts.authenticate.is_none() && !opts.allow_unauthenticated {
            return Err("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)".into());
        }
        Ok(Self { store: Mutex::new(Vec::new()), opts })
    }

    fn materialize(&self, passport: &Value, proj: &Value, created: Option<&Value>) -> Result<Value, String> {
        let mut meta = Map::new();
        if let Some(b) = &self.opts.base_url {
            meta.insert("baseUrl".into(), json!(b));
        }
        if let Some(c) = created {
            meta.insert("created".into(), c.clone());
        }
        let now = || self.opts.now.as_ref().map_or_else(now_ms, |f| f());
        passport_to_scim_with(passport, proj, &Value::Object(meta), &now)
    }

    fn get(&self, id: &Value) -> Option<(Value, Value)> {
        let s = id.as_str()?;
        self.store.lock().ok()?.iter().find(|(k, _, _)| k == s).map(|(_, r, p)| (r.clone(), p.clone()))
    }

    fn put(&self, resource: Value, passport: Value) {
        let id = js_str(&resource["id"]);
        if let Ok(mut st) = self.store.lock() {
            match st.iter_mut().find(|(k, _, _)| *k == id) {
                Some(slot) => *slot = (id, resource, passport),
                None => st.push((id, resource, passport)),
            }
        }
    }

    /// The passports in the store, in store order.
    pub fn passports(&self) -> Vec<Value> {
        self.store.lock().map(|st| st.iter().map(|(_, _, p)| p.clone()).collect()).unwrap_or_default()
    }

    /// Serve one request `{method, id?, query?, body?}` -> `{status, body?, headers}`. `Err` only when a resource falls
    /// outside the canonical JSON profile (the reference throws there).
    pub fn handle(&self, req: &Value) -> Result<Value, String> {
        if let Some(auth) = &self.opts.authenticate {
            if !auth(req) {
                let mut r = error_response(401, "authentication required", None);
                r["headers"]["www-authenticate"] = json!("Bearer");
                return Ok(r);
            }
        }
        let id = member(req, "id");
        let not_found = |id: &Value| error_response(404, &format!("Agent {} not found", js_str(id)), None);
        match member(req, "method").and_then(Value::as_str) {
            Some("GET") => match id {
                None => Ok(self.list(member(req, "query"))),
                Some(id) => Ok(self.get(id).map_or_else(|| not_found(id), |(r, _)| resource_response(200, &r))),
            },
            Some("POST") if id.is_some() => Ok(error_response(405, "POST is not allowed on an individual Agent", None)),
            Some("POST") => self.create(member(req, "body").unwrap_or(&Value::Null)),
            Some(m @ ("PUT" | "PATCH" | "DELETE")) if id.is_none() => Ok(error_response(405, &format!("{m} requires an Agent id"), None)),
            Some(m @ ("PUT" | "PATCH")) => {
                let id = id.unwrap_or(&Value::Null);
                let Some((existing, passport)) = self.get(id) else { return Ok(not_found(id)) };
                let body = member(req, "body").unwrap_or(&Value::Null);
                let proj = if m == "PUT" {
                    let Value::Object(b) = body else { return Ok(error_response(400, "request body must be a JSON object", Some("invalidSyntax"))) };
                    let mut p = read_projection(b);
                    if p["owner"] == json!("") {
                        p["owner"] = existing["owner"].clone();
                    }
                    p
                } else {
                    let mut p = projection_of(&existing);
                    let applied = read_patch_ops(body).and_then(|ops| ops.iter().try_for_each(|op| apply_patch_op(p.as_object_mut().expect("object"), op)));
                    if let Err(e) = applied {
                        return Ok(value_error(e));
                    }
                    p
                };
                let resource = self.materialize(&passport, &proj, Some(&existing["meta"]["created"]))?;
                self.put(resource.clone(), passport);
                Ok(resource_response(200, &resource))
            }
            Some("DELETE") => {
                let id = id.unwrap_or(&Value::Null);
                let removed = match (id.as_str(), self.store.lock()) {
                    (Some(s), Ok(mut st)) => {
                        let before = st.len();
                        st.retain(|(k, _, _)| k != s);
                        st.len() != before
                    }
                    _ => false,
                };
                Ok(if removed { json!({ "status": 204, "headers": {} }) } else { not_found(id) })
            }
            _ => Ok(error_response(405, &format!("method not allowed: {}", member(req, "method").map_or_else(|| "undefined".into(), js_str)), None)),
        }
    }

    fn list(&self, query: Option<&Value>) -> Value {
        let q = query.unwrap_or(&Value::Null);
        let mut items: Vec<Value> = self.store.lock().map(|st| st.iter().map(|(_, r, _)| r.clone()).collect()).unwrap_or_default();
        if let Some(f) = member(q, "filter").filter(|f| *f != &json!("")) {
            match parse_filter(f) {
                Ok(parsed) => items.retain(|a| matches_filter(a, &parsed)),
                Err(e) => return value_error(e),
            }
        }
        let total = items.len() as f64;
        let start = int_param(member(q, "startIndex"), 1.0).max(1.0);
        let count = member(q, "count").map(|c| int_param(Some(c), total).max(0.0));
        let from = ((start - 1.0).min(total)) as usize;
        let to = count.map_or(items.len(), |c| (start - 1.0 + c).min(total).max(from as f64) as usize);
        let page = items[from..to].to_vec();
        response(200, scim_list_response(page, num(total), num(start)), &[])
    }

    fn create(&self, body: &Value) -> Result<Value, String> {
        let req = match scim_to_provisioning_request(body) {
            Ok(r) => r,
            Err(e) => return Ok(value_error(e)),
        };
        let passport = issue_passport(&req["identity"])?;
        if self.get(&passport["id"]).is_some() {
            return Ok(error_response(
                409,
                &format!("an agent with this attested identity already exists (id {})", js_str(&passport["id"])),
                Some("uniqueness"),
            ));
        }
        let resource = self.materialize(&passport, &req["projection"], None)?;
        self.put(resource.clone(), passport);
        Ok(resource_response(201, &resource))
    }
}

/// `buildRegistry(passports).all()`: one passport per id (a later one replaces an earlier one in place).
pub fn passport_registry(passports: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for p in passports {
        match out.iter_mut().find(|x| x.get("id") == p.get("id")) {
            Some(slot) => *slot = p.clone(),
            None => out.push(p.clone()),
        }
    }
    out
}

fn extension_attributes(a: &Value) -> Value {
    let mut m = Map::new();
    m.insert("owner".into(), a["owner"].clone());
    m.insert("model".into(), a["passport"]["model_id"].clone());
    m.insert("operator".into(), a["passport"]["operator"].clone());
    m.insert("hardwareRooted".into(), a["passport"]["hardware_rooted"].clone());
    m.insert("capabilities".into(), a["capabilities"].clone());
    m.insert("passportRef".into(), a["passportRef"].clone());
    if let Some(h) = member(a, "holder") {
        m.insert("holder".into(), h.clone());
    }
    Value::Object(m)
}

fn push_payload(a: &Value, ext: &str, user_name: bool) -> Value {
    let mut m = Map::new();
    m.insert("schemas".into(), json!([AGENT_SCHEMA_URN, ext]));
    if user_name {
        m.insert("userName".into(), a["passportRef"].clone());
    }
    m.insert("externalId".into(), nn(a, "externalId").unwrap_or(&a["passportRef"]).clone());
    m.insert("displayName".into(), a["displayName"].clone());
    m.insert("active".into(), a["active"].clone());
    m.insert(ext.into(), extension_attributes(a));
    Value::Object(m)
}

/// The Microsoft Entra Agent ID payload of a SCIM Agent.
pub fn to_entra_agent_payload(agent: &Value) -> Value {
    push_payload(agent, ENTRA_AGENT_EXTENSION_URN, false)
}

/// The Okta SCIM payload of a SCIM Agent.
pub fn to_okta_scim_payload(agent: &Value) -> Value {
    push_payload(agent, OKTA_AGENT_EXTENSION_URN, true)
}

/// What a push transport answered: `ok`, `status`, and the parsed JSON body (`Err` when it had none / did not parse).
pub struct PushReply {
    pub ok: bool,
    pub status: u16,
    pub json: Result<Value, String>,
}

/// POST a payload to a directory's SCIM endpoint with a bearer token through `fetch(url, init)` (`init` = `{method, headers,
/// body}`, body = the payload's JSON text). Returns `{ok, status, body}` (body null when the reply was not JSON).
pub fn push_provision(payload: &Value, endpoint: &str, token: &str, fetch: &mut dyn FnMut(&str, &Value) -> Result<PushReply, String>) -> Result<Value, String> {
    let init = json!({ "method": "POST", "headers": { "authorization": format!("Bearer {token}"), "content-type": SCIM_CONTENT_TYPE }, "body": crate::js_stringify(payload) });
    let r = fetch(endpoint, &init)?;
    Ok(json!({ "ok": r.ok, "status": r.status, "body": r.json.unwrap_or(Value::Null) }))
}

pub fn push_to_entra(agent: &Value, endpoint: &str, token: &str, fetch: &mut dyn FnMut(&str, &Value) -> Result<PushReply, String>) -> Result<Value, String> {
    push_provision(&to_entra_agent_payload(agent), endpoint, token, fetch)
}

pub fn push_to_okta(agent: &Value, endpoint: &str, token: &str, fetch: &mut dyn FnMut(&str, &Value) -> Result<PushReply, String>) -> Result<Value, String> {
    push_provision(&to_okta_scim_payload(agent), endpoint, token, fetch)
}
