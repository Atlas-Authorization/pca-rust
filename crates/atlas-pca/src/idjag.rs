//! Identity Assertion JWT Authorization Grants (ID-JAG, the cross-app access flow), a native port of the reference bridge:
//! verify an ID-JAG on top of the OIDC verifier (single audience, `act` agent, scopes, and in the strict draft profile the
//! `typ`, `client_id` and single-use `jti`), project it onto a PCA principal or a root capability, and build the RFC 8693
//! token-exchange and RFC 7523 jwt-bearer requests. Errors are [`OidcError`]s; the ID-JAG codes add `actor`, `scope`, `grant`.
use crate::agent::{mint_root, KeyPair, Suite};
use crate::oauth::js_str;
use crate::oidc::{oidc_principal, verify_id_token, HttpFetch, OidcError, OidcKey};
use serde_json::{json, Map, Value};

pub const MAX_ID_JAG_CHARS: usize = 16384;
pub const IDJAG_AUTHORITY_CAVEAT: &str = "idjag_authority";
pub const IDJAG_PROVENANCE_CAVEAT: &str = "idjag_provenance";
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The single-use `jti` store: `Ok(true)` only when this is the first use of `jti` (an `Err` counts as already used).
pub type ConsumeJti<'a> = &'a dyn Fn(&str, f64) -> Result<bool, String>;

fn err(code: &str, m: impl Into<String>) -> OidcError {
    OidcError { code: code.into(), message: m.into() }
}
fn type_err(m: impl Into<String>) -> OidcError {
    err("type_error", m)
}

fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// `s.split(/\s+/)` with the empty pieces dropped.
fn split_ws(s: &str) -> Vec<Value> {
    s.split(crate::action_schema::is_js_ws).filter(|p| !p.is_empty()).map(|p| json!(p)).collect()
}

fn strings_only(a: &[Value]) -> Vec<Value> {
    a.iter().filter(|s| s.as_str().is_some_and(|s| !s.is_empty())).cloned().collect()
}

fn parse_scopes(scope: Option<&Value>, scopes: Option<&Value>) -> Option<Vec<Value>> {
    match (scope, scopes) {
        (Some(Value::String(s)), _) => Some(split_ws(s)),
        (Some(Value::Array(a)), _) => Some(strings_only(a)),
        (_, Some(Value::Array(a))) => Some(strings_only(a)),
        _ => None,
    }
}

/// `verifyIdJag(jwt, opts)`. `opts` (JSON): `issuer`, `audience` (one string) required; `nonce`, `requiredScopes`,
/// `clockToleranceSec`, `maxTokenAgeSec`, `algorithms`, `jwksUri`, `discover`, `strictDraft` (default true), `clientId`
/// (required when strict). `consume_jti` is required when strict. `key` / `fetch` as for [`verify_id_token`].
pub fn verify_id_jag(
    jwt: &Value,
    opts: &Value,
    key: Option<&OidcKey>,
    fetch: Option<&dyn HttpFetch>,
    consume_jti: Option<ConsumeJti>,
) -> Result<Value, OidcError> {
    let Some(t) = non_empty_str(Some(jwt)) else { return Err(err("invalid_token", "verifyIdJag: jwt must be a non-empty string")) };
    if t.encode_utf16().count() > MAX_ID_JAG_CHARS {
        return Err(err("invalid_token", "verifyIdJag: jwt exceeds the size limit"));
    }
    if !opts.is_object() && !opts.is_array() {
        return Err(err("config", "verifyIdJag: opts is required"));
    }
    let Some(issuer) = non_empty_str(get(opts, "issuer")) else { return Err(err("config", "verifyIdJag: opts.issuer is required")) };
    let Some(audience) = non_empty_str(get(opts, "audience")) else {
        return Err(err("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)"));
    };
    let strict = get(opts, "strictDraft") != Some(&Value::Bool(false));
    let consume = match consume_jti {
        Some(c) => Some(c),
        None if strict => return Err(err("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)")),
        None => None,
    };
    let client_id = non_empty_str(get(opts, "clientId"));
    if strict && client_id.is_none() {
        return Err(err("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)"));
    }
    let mut o = Map::new();
    o.insert("issuer".into(), json!(issuer));
    o.insert("audience".into(), json!(audience));
    for k in ["nonce", "clockToleranceSec", "maxTokenAgeSec", "algorithms", "jwksUri", "discover"] {
        if let Some(v) = get(opts, k) {
            o.insert(k.into(), v.clone());
        }
    }
    let base = verify_id_token(jwt, &Value::Object(o), key, fetch).map_err(|e| match e.code.as_str() {
        "type_error" | "discovery" | "ERR_INVALID_ARG_TYPE" => err("invalid_token", "ID-JAG verification failed"),
        _ => e,
    })?;
    let one = match &base["aud"] {
        Value::Array(l) => l.len() == 1 && l[0] == audience,
        a => a == audience,
    };
    if !one {
        return Err(err("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)"));
    }
    // the signature is verified, so the payload is authentic: read the non-OIDC claims from it
    let jws = crate::jose::assert_canonical_compact_jws(jwt, 3, crate::jose::DEFAULT_MAX_JWS_BYTES, true).map_err(|e| err("invalid_token", e))?;
    let raw = Value::Object(jws.payload.unwrap_or_default());
    let actor = match raw.get("act") {
        Some(Value::Object(m)) if non_empty_str(m.get("sub")).is_some() => m.clone(),
        _ => return Err(err("actor", "ID-JAG is missing a well-formed \"act\" (agent) claim with a string \"sub\"")),
    };
    let sub = actor["sub"].clone();
    let scopes = parse_scopes(raw.get("scope"), raw.get("scopes")).ok_or_else(|| err("scope", "ID-JAG is missing the \"scope\" (or \"scopes\") claim"))?;
    if let Some(Value::Array(req)) = get(opts, "requiredScopes") {
        for r in req {
            if !scopes.contains(r) {
                return Err(err("scope", format!("ID-JAG does not grant the required scope \"{}\"", js_str(r))));
            }
        }
    }
    let jti = non_empty_str(raw.get("jti"));
    if let Some(consume) = consume.filter(|_| strict) {
        if jws.header.get("typ") != Some(&json!("oauth-id-jag+jwt")) {
            return Err(err("grant", "ID-JAG header typ must be \"oauth-id-jag+jwt\""));
        }
        let Some(cid) = non_empty_str(raw.get("client_id")) else { return Err(err("grant", "ID-JAG is missing \"client_id\"")) };
        if Some(cid) != client_id {
            return Err(err("grant", "ID-JAG client_id does not match the expected client"));
        }
        let Some(j) = jti else { return Err(err("grant", "ID-JAG is missing \"jti\"")) };
        if consume(j, base["exp"].as_f64().unwrap_or(f64::NAN)) != Ok(true) {
            return Err(err("grant", "ID-JAG jti was already used or the single-use store failed"));
        }
    }
    let mut g = Map::new();
    g.insert("iss".into(), base["iss"].clone());
    g.insert("sub".into(), base["sub"].clone());
    g.insert("actor".into(), Value::Object(actor));
    g.insert("agent".into(), sub);
    g.insert("audience".into(), json!(audience));
    g.insert("scopes".into(), Value::Array(scopes));
    g.insert("iat".into(), base["iat"].clone());
    g.insert("exp".into(), base["exp"].clone());
    if let Some(j) = jti {
        g.insert("jti".into(), json!(j));
    }
    for k in ["nonce", "cnf"] {
        if let Some(v) = base.get(k) {
            g.insert(k.into(), v.clone());
        }
    }
    g.insert("oidcClaims".into(), base);
    Ok(Value::Object(g))
}

/// `idJagToPcaPrincipal(grant, opts)`: the OIDC principal of the grant's verified claims.
pub fn id_jag_to_pca_principal(grant: &Value, opts: Option<&Value>) -> Result<Value, OidcError> {
    if !grant.is_object() && !grant.is_array() {
        return Err(type_err("idJagToPcaPrincipal: grant is required"));
    }
    oidc_principal(get(grant, "oidcClaims").unwrap_or(&Value::Null), opts)
}

/// `idJagToCapability(grant, opts)`: a root capability from the principal to `opts.holder` carrying the `idjag_authority`,
/// `idjag_provenance` and `oidc_subject` caveats (then `opts.extraCaveats`). `principal_secret` is the principal's 32-byte
/// Ed25519 seed; its public key must be `opts.principalPublic`.
pub fn id_jag_to_capability(grant: &Value, opts: &Value, principal_secret: Option<&[u8]>, suite: &Suite) -> Result<Value, OidcError> {
    if !grant.is_object() && !grant.is_array() {
        return Err(type_err("idJagToCapability: grant is required"));
    }
    if !opts.is_object() && !opts.is_array() {
        return Err(type_err("idJagToCapability: opts is required"));
    }
    let Some(secret) = principal_secret else { return Err(type_err("idJagToCapability: opts.principalSecret must be a Uint8Array")) };
    let Some(pp) = non_empty_str(get(opts, "principalPublic")) else { return Err(type_err("idJagToCapability: opts.principalPublic is required")) };
    let Some(holder) = non_empty_str(get(opts, "holder")) else { return Err(type_err("idJagToCapability: opts.holder (the agent key) is required")) };
    let principal = id_jag_to_pca_principal(grant, Some(&json!({ "principalPublic": pp })))?;
    let scopes = match get(grant, "scopes") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        _ => return Err(type_err("grant.scopes is not iterable")),
    };
    let g = |k: &str| get(grant, k).cloned().unwrap_or(Value::Null);
    let mut prov = Map::new();
    for (k, src) in [
        ("type", json!(IDJAG_PROVENANCE_CAVEAT)),
        ("iss", g("iss")),
        ("sub", g("sub")),
        ("agent", g("agent")),
        ("aud", g("audience")),
        ("iat", g("iat")),
        ("exp", g("exp")),
    ] {
        prov.insert(k.into(), src);
    }
    if let Some(j) = get(grant, "jti") {
        prov.insert("jti".into(), j.clone());
    }
    let mut caveats = vec![
        json!({ "type": IDJAG_AUTHORITY_CAVEAT, "scopes": scopes.clone(), "aud": g("audience") }),
        Value::Object(prov),
        principal["subjectCaveat"].clone(),
    ];
    match get(opts, "extraCaveats") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => caveats.extend(a.iter().cloned()),
        Some(_) => return Err(type_err("opts.extraCaveats is not iterable")),
    }
    let seed: &[u8; 32] = secret.try_into().map_err(|_| type_err("principalSecret must be a 32-byte Ed25519 seed"))?;
    let kp = KeyPair::from_seed(seed);
    if kp.public != pp {
        // the reference signs with the secret and names principalPublic as the issuer; a mismatch would be a broken root
        return Err(type_err("idJagToCapability: opts.principalSecret does not belong to opts.principalPublic"));
    }
    let capability = mint_root(&kp, holder, &Value::Array(caveats), None, suite).map_err(type_err)?;
    Ok(json!({ "capability": capability, "principal": principal, "scopes": scopes }))
}

/// `isIdJagAuthorityCaveat(cv)`.
pub fn is_id_jag_authority_caveat(cv: &Value) -> bool {
    get(cv, "type") == Some(&json!(IDJAG_AUTHORITY_CAVEAT))
        && get(cv, "scopes").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string))
        && non_empty_str(get(cv, "aud")).is_some()
}

/// `isIdJagProvenanceCaveat(cv)`.
pub fn is_id_jag_provenance_caveat(cv: &Value) -> bool {
    get(cv, "type") == Some(&json!(IDJAG_PROVENANCE_CAVEAT))
        && ["iss", "sub", "agent", "aud"].iter().all(|k| get(cv, k).is_some_and(Value::is_string))
        && ["iat", "exp"].iter().all(|k| get(cv, k).is_some_and(Value::is_number))
}

fn read_caveat(cap: &Value, ty: &str, guard: fn(&Value) -> bool) -> Result<Value, OidcError> {
    let found = match get(cap, "caveats") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => a.iter().find(|c| get(c, "type").and_then(Value::as_str) == Some(ty)),
        Some(_) => return Err(type_err("cap.caveats.find is not a function")),
    };
    Ok(found.filter(|c| guard(c)).cloned().unwrap_or(Value::Null))
}

/// `readIdJagAuthority(cap)`: the first `idjag_authority` caveat when it is well formed, else null.
pub fn read_id_jag_authority(cap: &Value) -> Result<Value, OidcError> {
    read_caveat(cap, IDJAG_AUTHORITY_CAVEAT, is_id_jag_authority_caveat)
}

/// `readIdJagProvenance(cap)`: the first `idjag_provenance` caveat when it is well formed, else null.
pub fn read_id_jag_provenance(cap: &Value) -> Result<Value, OidcError> {
    read_caveat(cap, IDJAG_PROVENANCE_CAVEAT, is_id_jag_provenance_caveat)
}

// ---- XAA request shapes ---------------------------------------------------------------------------------------------------

/// A JavaScript object literal built by spreads: a key keeps its first position when overwritten, and integer-index keys
/// enumerate first, ascending.
#[derive(Default)]
struct JsObj(Vec<(String, Value)>);

impl JsObj {
    fn set(&mut self, k: &str, v: Value) {
        match self.0.iter_mut().find(|(x, _)| x == k) {
            Some(e) => e.1 = v,
            None => self.0.push((k.to_string(), v)),
        }
    }
    /// `...x` of a JSON value: an object's members, an array's or a string's indices; anything else adds nothing.
    fn spread(&mut self, v: Option<&Value>) {
        match v {
            Some(Value::Object(m)) => m.iter().for_each(|(k, x)| self.set(k, x.clone())),
            Some(Value::Array(a)) => a.iter().enumerate().for_each(|(i, x)| self.set(&i.to_string(), x.clone())),
            Some(Value::String(s)) => s.encode_utf16().enumerate().for_each(|(i, u)| self.set(&i.to_string(), json!(String::from_utf16_lossy(&[u])))),
            _ => {}
        }
    }
    fn ordered(self) -> Vec<(String, Value)> {
        let index = |k: &str| k.parse::<u32>().ok().filter(|n| *n != u32::MAX && n.to_string() == k);
        let (mut ints, rest): (Vec<_>, Vec<_>) = self.0.into_iter().partition(|(k, _)| index(k).is_some());
        ints.sort_by_key(|(k, _)| index(k));
        ints.into_iter().chain(rest).collect()
    }
}

/// `application/x-www-form-urlencoded` byte serializer (URLSearchParams): space is `+`, `*-._` and alphanumerics stay.
fn form_encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b' ' => o.push('+'),
            b'*' | b'-' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn form_request(url: &str, params: JsObj) -> Value {
    let clean: Vec<(String, String)> =
        params.ordered().into_iter().filter_map(|(k, v)| v.as_str().filter(|s| !s.is_empty()).map(|s| (k, s.to_string()))).collect();
    let body = clean.iter().map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v))).collect::<Vec<_>>().join("&");
    let p: Map<String, Value> = clean.into_iter().map(|(k, v)| (k, json!(v))).collect();
    json!({
        "url": url,
        "method": "POST",
        "headers": { "content-type": "application/x-www-form-urlencoded", "accept": "application/json" },
        "params": p,
        "body": body,
    })
}

fn scope_param(scope: Option<&Value>) -> Result<Option<String>, OidcError> {
    let parts = match scope {
        None => return Ok(None),
        Some(Value::Array(a)) => strings_only(a),
        Some(Value::String(s)) => split_ws(s),
        Some(_) => return Err(type_err("scope.split is not a function")),
    };
    Ok((!parts.is_empty()).then(|| parts.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")))
}

fn or_default(v: Option<&Value>, d: &str) -> Value {
    v.filter(|x| !x.is_null()).cloned().unwrap_or(json!(d))
}

/// `tokenExchangeRequest(opts)`: the RFC 8693 request that exchanges the user's ID token for an ID-JAG.
pub fn token_exchange_request(opts: &Value) -> Result<Value, OidcError> {
    if !opts.is_object() && !opts.is_array() {
        return Err(type_err("tokenExchangeRequest: opts is required"));
    }
    let Some(te) = non_empty_str(get(opts, "tokenEndpoint")) else { return Err(type_err("tokenExchangeRequest: opts.tokenEndpoint is required")) };
    if non_empty_str(get(opts, "subjectToken")).is_none() {
        return Err(type_err("tokenExchangeRequest: opts.subjectToken is required"));
    }
    let has_actor = non_empty_str(get(opts, "actorToken")).is_some();
    let scope = scope_param(get(opts, "scope"))?;
    let mut p = JsObj::default();
    p.set("grant_type", json!(GRANT_TYPE_TOKEN_EXCHANGE));
    p.set("subject_token", get(opts, "subjectToken").cloned().unwrap_or_default());
    p.set("subject_token_type", or_default(get(opts, "subjectTokenType"), TOKEN_TYPE_ID_TOKEN));
    p.set("requested_token_type", or_default(get(opts, "requestedTokenType"), TOKEN_TYPE_ID_JAG));
    for (k, src) in [("audience", "audience"), ("resource", "resource")] {
        if let Some(v) = get(opts, src) {
            p.set(k, v.clone());
        }
    }
    if let Some(s) = scope {
        p.set("scope", json!(s));
    }
    if has_actor {
        p.set("actor_token", get(opts, "actorToken").cloned().unwrap_or_default());
        p.set("actor_token_type", or_default(get(opts, "actorTokenType"), TOKEN_TYPE_JWT));
    }
    if let Some(v) = get(opts, "clientId") {
        p.set("client_id", v.clone());
    }
    p.spread(get(opts, "extra"));
    Ok(form_request(te, p))
}

/// `jwtBearerAssertion(opts)`: the RFC 7523 request that presents the ID-JAG to the resource app's token endpoint.
pub fn jwt_bearer_assertion(opts: &Value) -> Result<Value, OidcError> {
    if !opts.is_object() && !opts.is_array() {
        return Err(type_err("jwtBearerAssertion: opts is required"));
    }
    let Some(te) = non_empty_str(get(opts, "tokenEndpoint")) else { return Err(type_err("jwtBearerAssertion: opts.tokenEndpoint is required")) };
    let Some(assertion) = non_empty_str(get(opts, "assertion")) else { return Err(type_err("jwtBearerAssertion: opts.assertion is required")) };
    let scope = scope_param(get(opts, "scope"))?;
    let mut p = JsObj::default();
    p.set("grant_type", json!(GRANT_TYPE_JWT_BEARER));
    p.set("assertion", json!(assertion));
    if let Some(s) = &scope {
        p.set("scope", json!(s));
    }
    if let Some(v) = get(opts, "clientId") {
        p.set("client_id", v.clone());
    }
    if let Some(ca) = non_empty_str(get(opts, "clientAssertion")) {
        p.set("client_assertion_type", json!(CLIENT_ASSERTION_TYPE_JWT_BEARER));
        p.set("client_assertion", json!(ca));
    }
    p.spread(get(opts, "extra"));
    let mut out = Map::new();
    out.insert("grantType".into(), json!(GRANT_TYPE_JWT_BEARER));
    out.insert("assertion".into(), json!(assertion));
    if let Some(s) = scope {
        out.insert("scope".into(), json!(s));
    }
    out.insert("request".into(), form_request(te, p));
    Ok(Value::Object(out))
}
