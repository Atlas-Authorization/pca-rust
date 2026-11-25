//! OAuth 2.1 / MCP-authorization interop: the discovery and challenge envelope around the PCActn (the proof stays the PCActn).
//! RFC 9728 Protected Resource Metadata, RFC 8707 resource indicators and token-audience binding, RFC 6750 / RFC 7235
//! `WWW-Authenticate` challenges (MCP authorization: `Bearer resource_metadata="<PRM URL>"`), the `pca_grant` authorization
//! detail helpers and the OAuth scope derived from a confirmed action. Pure, I/O-free.
//!
//! Options and documents are JSON values with the reference's member names (`resource`, `authorizationServers`,
//! `bearerMethodsSupported`, ...); errors are the reference's messages.
use crate::{a2a, js_stringify, pca_grant};
use serde_json::{json, Map, Value};

/// RFC 9728 section 3: the well-known path component of the Protected Resource Metadata.
pub const WELL_KNOWN_OAUTH_PRM: &str = "/.well-known/oauth-protected-resource";
/// The sibling PCA discovery document's well-known path.
pub const WELL_KNOWN_PCA_PATH: &str = "/.well-known/pca-configuration";
const DEFAULT_SUITES: [&str; 3] = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"];
const DEFAULT_REQUIRED: [&str; 7] = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"];
const DEFAULT_PCA_HINT: &str = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}";

// ---- JavaScript value semantics the reference relies on ------------------------------------------------------------

pub(crate) fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `x ?? default`: absent or null is nullish.
fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

/// `String(x)` for a JSON value.
pub(crate) fn js_str(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => crate::intent_v2::js_number_string(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { js_str(x) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `[...x]` (array spread): an array is copied, a string splits into code points, anything else is not iterable.
pub(crate) fn spread(v: &Value, what: &str) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        _ => Err(format!("{what} is not iterable")),
    }
}

/// `{...x}` (object spread) members.
fn spread_obj(v: &Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m.clone(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            units.iter().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[*u])))).collect()
        }
        _ => Map::new(),
    }
}

/// The options object of a call: `{}` when absent; reading a member of `null` is a TypeError in the reference.
fn opts_of<'a>(v: Option<&'a Value>, fname: &str) -> Result<Option<&'a Map<String, Value>>, String> {
    match v {
        None => Ok(None),
        Some(Value::Null) => Err(format!("{fname}: options must not be null")),
        Some(x) => Ok(x.as_object()),
    }
}

fn get<'a>(o: Option<&'a Map<String, Value>>, k: &str) -> Option<&'a Value> {
    o.and_then(|m| m.get(k))
}

// ---- RFC 9728 ------------------------------------------------------------------------------------------------------

/// RFC 9728 section 1.2: why `resource` is not a resource identifier (an `https` URL without a fragment), or `None`.
pub fn resource_identifier_problem(resource: &Value) -> Option<&'static str> {
    let Some(r) = resource.as_str().filter(|s| !s.is_empty()) else { return Some("resource identifier must be a non-empty string") };
    let Ok(u) = url::Url::parse(r) else { return Some("resource identifier is not an absolute URL") };
    if u.scheme() != "https" {
        return Some("resource identifier must use the https scheme");
    }
    if r.contains('#') {
        return Some("resource identifier must not contain a fragment");
    }
    None
}

/// `pathname` + `search` of a parsed URL as WHATWG serializes them (`search` is empty for an absent or empty query).
fn path_and_search(u: &url::Url) -> (String, String) {
    let search = match u.query() {
        Some(q) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    };
    (u.path().to_string(), search)
}

/// RFC 9728 section 3.1: the well-known path for a resource identifier (`https://h/r` -> `/.well-known/oauth-protected-resource/r`).
pub fn prm_path_for_resource(resource: &str) -> Result<String, String> {
    if let Some(p) = resource_identifier_problem(&Value::String(resource.into())) {
        return Err(format!("prmPathForResource: {p}"));
    }
    let u = url::Url::parse(resource).map_err(|_| "Invalid URL".to_string())?;
    let (path, search) = path_and_search(&u);
    Ok(format!("{WELL_KNOWN_OAUTH_PRM}{}{search}", if path == "/" { "" } else { &path }))
}

/// RFC 9728 section 3.1: the absolute metadata URL (the `resource_metadata` value).
pub fn prm_url_for_resource(resource: &str) -> Result<String, String> {
    let u = url::Url::parse(resource).map_err(|_| "Invalid URL".to_string())?;
    Ok(format!("{}{}", u.origin().ascii_serialization(), prm_path_for_resource(resource)?))
}

/// The PCA discovery document (`buildDiscoveryDocument`) for the members this bridge forwards.
fn discovery(audience: &Value, o: Option<&Map<String, Value>>) -> Value {
    let mut d = Map::new();
    d.insert("audience".into(), audience.clone());
    d.insert("pca_versions".into(), present(get(o, "pcaVersions")).cloned().unwrap_or(json!([2])));
    d.insert("signature_suites".into(), present(get(o, "signatureSuites")).cloned().unwrap_or(json!(DEFAULT_SUITES)));
    d.insert("action_header".into(), present(get(o, "actionHeader")).cloned().unwrap_or(json!("PCA-Action")));
    d.insert("required_checks".into(), present(get(o, "requiredChecks")).cloned().unwrap_or(json!(DEFAULT_REQUIRED)));
    for (opt, key) in [("endpoints", "endpoints"), ("trustedRoots", "trusted_roots"), ("metadata", "metadata")] {
        if truthy(get(o, opt)) {
            d.insert(key.into(), o.unwrap()[opt].clone());
        }
    }
    Value::Object(d)
}

/// RFC 9728: the Protected Resource Metadata document. `resource` is this RS's identifier, the exact value a PCActn's signed
/// `aud` must equal; the embedded `pca` block is the PCA discovery document. Errs on an empty or (strict, the default)
/// invalid `resource`.
pub fn protected_resource_metadata(opts: &Value) -> Result<Value, String> {
    let o = opts_of(Some(opts), "protectedResourceMetadata")?;
    let resource = match get(o, "resource") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required".into()),
    };
    let rv = Value::String(resource.clone());
    if get(o, "strict") != Some(&Value::Bool(false)) {
        if let Some(p) = resource_identifier_problem(&rv) {
            return Err(format!("protectedResourceMetadata: {p}"));
        }
    }
    let disc = discovery(&rv, o);
    let pca_conf = match present(get(o, "pcaConfigurationEndpoint")) {
        Some(v) => v.clone(),
        None => Value::String(format!("{}{WELL_KNOWN_PCA_PATH}", resource.split('?').next().unwrap_or("").trim_end_matches('/'))),
    };
    let mut doc = Map::new();
    doc.insert("resource".into(), rv);
    doc.insert("bearer_methods_supported".into(), present(get(o, "bearerMethodsSupported")).cloned().unwrap_or(json!(["header"])));
    doc.insert("pca_action_header".into(), disc["action_header"].clone());
    doc.insert("pca_signature_suites".into(), Value::Array(spread(&disc["signature_suites"], "discovery.signature_suites")?));
    doc.insert("pca_versions".into(), Value::Array(spread(&disc["pca_versions"], "discovery.pca_versions")?));
    doc.insert("pca_configuration_endpoint".into(), pca_conf);
    doc.insert("pca".into(), disc);
    for (opt, key, is_list) in [
        ("authorizationServers", "authorization_servers", true),
        ("resourceDocumentation", "resource_documentation", false),
        ("scopesSupported", "scopes_supported", true),
        ("resourceName", "resource_name", false),
        ("resourceSigningAlgValuesSupported", "resource_signing_alg_values_supported", true),
        ("authorizationDetailsTypesSupported", "authorization_details_types_supported", true),
    ] {
        if truthy(get(o, opt)) {
            let v = &o.unwrap()[opt];
            doc.insert(key.into(), if is_list { Value::Array(spread(v, &format!("opts.{opt}"))?) } else { v.clone() });
        }
    }
    Ok(Value::Object(doc))
}

fn str_list(v: Option<&Value>) -> bool {
    v.and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string))
}

/// Validate an untrusted PRM document. RFC 9728 section 3.3: `resource` (and the embedded `pca.audience`) must equal
/// `parseOpts.expectedResource`, which strict mode (the default) requires.
pub fn parse_protected_resource_metadata(value: &Value, parse_opts: Option<&Value>) -> Result<Value, String> {
    const F: &str = "parseProtectedResourceMetadata";
    // arrays are objects to the reference: their named members are all absent
    let empty = Map::new();
    let v = match value {
        Value::Object(m) => m,
        Value::Array(_) => &empty,
        _ => return Err(format!("{F}: not an object")),
    };
    let Some(resource) = v.get("resource").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Err(format!("{F}: missing `resource`"));
    };
    if !str_list(v.get("bearer_methods_supported")) {
        return Err(format!("{F}: bearer_methods_supported must be a string[]"));
    }
    if !v.get("pca_action_header").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err(format!("{F}: missing pca_action_header"));
    }
    if !str_list(v.get("pca_signature_suites")) {
        return Err(format!("{F}: pca_signature_suites must be a string[]"));
    }
    if !v.get("pca_versions").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_number)) {
        return Err(format!("{F}: pca_versions must be a number[]"));
    }
    let pca = match v.get("pca") {
        Some(p @ (Value::Object(_) | Value::Array(_))) => p,
        _ => return Err(format!("{F}: missing embedded `pca` discovery document")),
    };
    let audience = pca.get("audience").and_then(Value::as_str).filter(|s| !s.is_empty());
    if audience.is_none() {
        return Err(format!("{F}: embedded pca.audience is required"));
    }
    let po = opts_of(parse_opts, F)?;
    let expected = get(po, "expectedResource");
    if let Some(e) = expected {
        if e.as_str() != Some(resource) {
            return Err(format!("{F}: `resource` does not match the expected resource identifier"));
        }
        if e.as_str() != audience {
            return Err(format!("{F}: embedded pca.audience does not match the expected resource identifier"));
        }
    }
    if get(po, "strict") != Some(&Value::Bool(false)) {
        if expected.is_none() {
            return Err(format!("{F}: expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip"));
        }
        if let Some(p) = resource_identifier_problem(&v["resource"]) {
            return Err(format!("{F}: {p}"));
        }
        if !v["bearer_methods_supported"].as_array().unwrap().iter().all(|m| matches!(m.as_str(), Some("header" | "body" | "query"))) {
            return Err(format!("{F}: bearer_methods_supported has a value outside header/body/query"));
        }
    }
    let mut doc = Map::new();
    for k in ["resource", "bearer_methods_supported", "pca_action_header", "pca_signature_suites", "pca_versions", "pca"] {
        doc.insert(k.into(), v[k].clone());
    }
    for k in ["pca_configuration_endpoint", "resource_documentation", "resource_name"] {
        if v.get(k).is_some_and(Value::is_string) {
            doc.insert(k.into(), v[k].clone());
        }
    }
    for k in ["authorization_servers", "scopes_supported", "resource_signing_alg_values_supported"] {
        if str_list(v.get(k)) {
            doc.insert(k.into(), v[k].clone());
        }
    }
    Ok(Value::Object(doc))
}

// ---- challenges ----------------------------------------------------------------------------------------------------

/// A quoted auth-param value (RFC 7235): a quote, backslash or control character is refused (header injection).
fn quoted(v: &Value) -> Result<String, String> {
    let s = js_str(v);
    if s.chars().any(|c| c == '"' || c == '\\' || (c as u32) < 0x20 || c == '\u{7f}') {
        return Err("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline".into());
    }
    Ok(s)
}

/// The base64url `pca_need` header value (`encodePcaNeed`): a malformed or oversized need is refused.
pub fn encode_pca_need(need: &Value) -> Result<String, String> {
    if let Some(code) = a2a::need_error(need) {
        return Err(format!("encodePcaNeed: malformed need ({code})"));
    }
    let text = crate::canonicalize_strict(need)?;
    let enc = crate::b64_encode(text.as_bytes());
    if enc.len() > 2048 {
        return Err("encodePcaNeed: the need is too large for a header".into());
    }
    Ok(enc)
}

/// MCP + RFC 6750: the `WWW-Authenticate` value of a 401: `Bearer resource_metadata="<prmUrl>"` (plus `error`,
/// `error_description`, `scope`, `pca_need`), then (default) the PCA challenge, or `pcaChallenge` verbatim.
pub fn www_authenticate(prm_url: &Value, opts: Option<&Value>) -> Result<String, String> {
    if !prm_url.as_str().is_some_and(|s| !s.is_empty()) {
        return Err("wwwAuthenticate: prmUrl is required".into());
    }
    let mut bearer = vec![format!("resource_metadata=\"{}\"", quoted(prm_url)?)];
    let o = opts_of(opts, "wwwAuthenticate")?;
    for (opt, name) in [("error", "error"), ("errorDescription", "error_description"), ("scope", "scope")] {
        if truthy(get(o, opt)) {
            bearer.push(format!("{name}=\"{}\"", quoted(&o.unwrap()[opt])?));
        }
    }
    if truthy(get(o, "pcaNeed")) {
        bearer.push(format!("pca_need=\"{}\"", quoted(&Value::String(encode_pca_need(&o.unwrap()["pcaNeed"])?))?));
    }
    let mut challenges = vec![format!("Bearer {}", bearer.join(", "))];
    let include_pca = present(get(o, "includePca")).map_or(true, |v| truthy(Some(v)));
    if truthy(get(o, "pcaChallenge")) {
        let c = js_str(&o.unwrap()["pcaChallenge"]);
        if c.chars().any(|ch| ((ch as u32) < 0x20 && ch != '\t') || ch == '\u{7f}') {
            return Err("pca-oauth: pcaChallenge may not contain control characters or newlines".into());
        }
        challenges.push(c);
    } else if include_pca {
        let realm = present(get(o, "realm")).cloned().unwrap_or(json!("pca"));
        let hint = present(get(o, "hint")).cloned().unwrap_or(json!(DEFAULT_PCA_HINT));
        let mut pca = format!("PCA realm=\"{}\"", quoted(&realm)?);
        if truthy(Some(&hint)) {
            pca.push_str(&format!(", hint=\"{}\"", quoted(&hint)?));
        }
        challenges.push(pca);
    }
    Ok(challenges.join(", "))
}

/// RFC 8707: does an incoming `resource` indicator (one value or the array form) name this RS? The OAuth-layer echo only:
/// the PCActn's signed `aud` is the security boundary. `{ok, matched?}` / `{ok: false, reason}`.
pub fn check_resource_indicator(resource_param: &Value, expected_audience: &Value) -> Result<Value, String> {
    let Some(exp) = expected_audience.as_str().filter(|s| !s.is_empty()) else {
        return Err("checkResourceIndicator: expectedAudience is required".into());
    };
    if resource_param.is_null() {
        return Ok(json!({ "ok": false, "reason": "no resource indicator presented" }));
    }
    let values = match resource_param {
        Value::Array(a) => a.clone(),
        x => vec![x.clone()],
    };
    if values.is_empty() {
        return Ok(json!({ "ok": false, "reason": "empty resource indicator" }));
    }
    if values.iter().any(|r| r.as_str() == Some(exp)) {
        return Ok(json!({ "ok": true, "matched": exp }));
    }
    Ok(json!({ "ok": false, "reason": format!("resource indicator {} does not match audience {}", js_stringify(&Value::Array(values)), js_stringify(expected_audience)) }))
}

/// Token-audience binding (RFC 8707 / RFC 7519 section 4.1.3): the verified token's `aud` is, or contains, exactly this
/// resource. Missing, empty or different is refused.
pub fn check_token_audience(aud: &Value, expected_resource: &Value) -> Result<Value, String> {
    let Some(exp) = expected_resource.as_str().filter(|s| !s.is_empty()) else {
        return Err("checkTokenAudience: expectedResource is required".into());
    };
    if aud.is_null() {
        return Ok(json!({ "ok": false, "reason": "token has no audience" }));
    }
    let values = match aud {
        Value::Array(a) => a.clone(),
        x => vec![x.clone()],
    };
    if values.is_empty() {
        return Ok(json!({ "ok": false, "reason": "token has an empty audience" }));
    }
    if values.iter().any(|a| a.as_str() == Some(exp)) {
        return Ok(json!({ "ok": true, "matched": exp }));
    }
    Ok(json!({ "ok": false, "reason": format!("token audience {} does not include resource {}", js_stringify(aud), js_stringify(expected_resource)) }))
}

/// The path and body to serve the PRM document at: `{path, body, rfcPath}` (`path` is the RFC 9728 section 3.1 path; only a
/// non-strict invalid identifier falls back to the bare well-known path).
pub fn oauth_discovery_handler(opts: &Value) -> Result<Value, String> {
    let body = protected_resource_metadata(opts)?;
    let r = &opts["resource"];
    let path = match (resource_identifier_problem(r), r.as_str()) {
        (None, Some(s)) => prm_path_for_resource(s)?,
        _ => WELL_KNOWN_OAUTH_PRM.to_string(),
    };
    Ok(json!({ "path": path, "body": body, "rfcPath": path }))
}

/// The complete MCP/OAuth 401: `{status: 401, headers: {"WWW-Authenticate"}, body: {error, error_description?, resource_metadata}}`.
pub fn mcp_unauthorized(prm_url: &Value, opts: Option<&Value>) -> Result<Value, String> {
    let o = opts_of(opts, "mcpUnauthorized")?;
    let mut body = Map::new();
    body.insert("error".into(), present(get(o, "error")).cloned().unwrap_or(json!("invalid_request")));
    body.insert("resource_metadata".into(), prm_url.clone());
    if truthy(get(o, "errorDescription")) {
        body.insert("error_description".into(), o.unwrap()["errorDescription"].clone());
    }
    let header = www_authenticate(prm_url, opts)?;
    Ok(json!({ "status": 401, "headers": { "WWW-Authenticate": header }, "body": body }))
}

/// Upgrade a guard's deny result: its `wwwAuthenticate` PCA challenge is kept verbatim and the MCP `Bearer resource_metadata`
/// challenge is prepended; every other member is preserved.
pub fn upgrade_unauthorized_challenge(result: &Value, prm_url: &Value, opts: Option<&Value>) -> Result<Value, String> {
    if result.is_null() {
        return Err("upgradeUnauthorizedChallenge: result must not be null".into());
    }
    let existing = result.as_object().and_then(|m| m.get("wwwAuthenticate"));
    let mut merged = opts.map(spread_obj).unwrap_or_default();
    if truthy(existing) {
        merged.insert("pcaChallenge".into(), existing.unwrap().clone());
    }
    let header = www_authenticate(prm_url, Some(&Value::Object(merged)))?;
    let mut out = spread_obj(result);
    out.insert("wwwAuthenticate".into(), Value::String(header));
    Ok(Value::Object(out))
}

// ---- pca_grant authorization details ---------------------------------------------------------------------------------

/// A validated `pca_grant` detail for the presented chain: `{chainIds, chainRef?, bundleRevision?, locations?}`.
pub fn build_pca_grant_detail(chain_ids: &[&str], chain_ref: Option<&Value>, bundle_revision: Option<&Value>, locations: Option<&[Value]>) -> Result<Value, String> {
    let mut d = Map::new();
    d.insert("type".into(), json!(pca_grant::PCA_GRANT_TYPE));
    d.insert("chain_digest".into(), json!(pca_grant::chain_digest(chain_ids)));
    d.insert("chain_len".into(), json!(chain_ids.len()));
    if let Some(r) = chain_ref {
        d.insert("chain_ref".into(), r.clone());
    }
    if let Some(b) = bundle_revision {
        d.insert("bundle_revision".into(), b.clone());
    }
    if let Some(l) = locations {
        d.insert("locations".into(), Value::Array(l.to_vec()));
    }
    let d = Value::Object(d);
    pca_grant::validate_detail(&d).map_err(|c| format!("buildPcaGrantDetail: refused ({c})"))?;
    Ok(d)
}

/// The `authorization_details` request parameter: `encodeURIComponent(JSON.stringify(details))`.
pub fn pca_grant_request_param(details: &[Value]) -> String {
    let text = js_stringify(&Value::Array(details.to_vec()));
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Resource-server check of an access token's `authorization_details`: `{allow: true, detail}` or
/// `{allow: false, status: 401 | 403, error: "invalid_token" | "insufficient_scope", code}`.
pub fn authorize_pca_grant_token(authorization_details: &Value, resource: &str, chain_ids: &[&str], proof_verified: bool) -> Value {
    let details = match pca_grant::parse_details(authorization_details) {
        Ok(d) => d,
        Err(code) => return json!({ "allow": false, "status": 401, "error": "invalid_token", "code": code }),
    };
    match pca_grant::check_presentation(&details, resource, chain_ids, proof_verified) {
        Ok(i) => json!({ "allow": true, "detail": details[i] }),
        Err(code) => {
            let (status, error) = if code == "wrong_location" { (403, "insufficient_scope") } else { (401, "invalid_token") };
            json!({ "allow": false, "status": status, "error": error, "code": code })
        }
    }
}

/// RFC 6749 section 3.3 scope-token: printable ASCII without space, `"` or `\`.
fn scope_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

/// The OAuth scopes a CONFIRMED action needs (`deriveActionScopes`): its upstream `scopes_min`, deduplicated and sorted,
/// optionally bound to a provider and capped by a granted set. `{ok: true, scopes, provider, def_digest}` or `{ok: false, code}`.
pub fn derive_action_scopes(action: &Value, provider: Option<&Value>, granted: Option<&[Value]>) -> Value {
    let fail = |code: &str| json!({ "ok": false, "code": code });
    let Some(a) = action.as_object() else {
        // an array is an object to the reference, with no `confirmed` member
        return fail(if action.is_array() { "unconfirmed" } else { "unknown_action" });
    };
    if a.get("confirmed") != Some(&Value::Bool(true)) {
        return fail("unconfirmed");
    }
    let up = a.get("upstream").filter(|u| !u.is_null());
    let up_provider = up.and_then(|u| u.get("provider"));
    if let Some(p) = provider {
        if up_provider != Some(p) {
            return fail("provider_mismatch");
        }
    }
    let Some(min) = up.and_then(|u| u.get("scopes_min")).and_then(Value::as_array).filter(|m| !m.is_empty()) else {
        return fail("no_scopes");
    };
    if !min.iter().all(|s| s.as_str().is_some_and(|t| t.encode_utf16().count() <= 256 && scope_token(t))) {
        return fail("bad_scope");
    }
    let mut scopes: Vec<&str> = min.iter().filter_map(Value::as_str).collect();
    scopes.sort_by(|x, y| x.encode_utf16().cmp(y.encode_utf16()));
    scopes.dedup();
    if let Some(g) = granted {
        if !scopes.iter().all(|s| g.iter().any(|x| x.as_str() == Some(s))) {
            return fail("exceeds_grant");
        }
    }
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("scopes".into(), json!(scopes));
    if let Some(p) = up_provider {
        out.insert("provider".into(), p.clone());
    }
    if let Some(d) = a.get("def_digest") {
        out.insert("def_digest".into(), d.clone());
    }
    Value::Object(out)
}

/// The OAuth scope request for a confirmed action: `{ok: true, scope, scopes, resource?}` or `{ok: false, code}`.
pub fn oauth_scope_for_action(action: &Value, provider: Option<&Value>, granted: Option<&[Value]>, resource: Option<&Value>) -> Value {
    let d = derive_action_scopes(action, provider, granted);
    if d["ok"] != json!(true) {
        return json!({ "ok": false, "code": d["code"] });
    }
    let scopes: Vec<&str> = d["scopes"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    let mut out = json!({ "ok": true, "scope": scopes.join(" "), "scopes": scopes });
    if let Some(r) = resource {
        out["resource"] = r.clone();
    }
    out
}
