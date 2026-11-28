//! GNAP (RFC 9635) bridge, the Agent-GNAP profile: GNAP access rights map onto policy-envelope predicates, a grant request
//! becomes an attenuated, key-bound capability (a root grant or a delegated hop that records its clamped rights), actions are
//! authorized against the intersection of the root envelope and every hop's rights, a capability chain travels as a bound
//! access token, requests are proven with `jwsd` detached JWS, a continuation resolves through a threshold co-signature folded
//! into the action's PCActn, and the interaction modes (redirect / app / user code, finish hash, the AS state machine).
//!
//! JSON-valued API: options and requests are `serde_json::Value`s with the reference's member names; errors carry the
//! reference's messages. Every verification path fails closed.
use crate::agent::{build_pcactn, delegate, mint_grant, rand_bytes, KeyPair, PcactnInput, Suite};
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, hash_canonical_strict, js_stringify, sha, strict_parse, threshold_message};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub const GNAP_GRANT_CAVEAT: &str = "gnap_grant";
pub const GNAP_ACCESS_CAVEAT: &str = "gnap_access";
/// Upper bound on an accepted detached JWS string (UTF-16 code units, as the reference counts).
pub const MAX_DETACHED_JWS_CHARS: usize = 8192;
pub const START_MODES: [&str; 4] = ["redirect", "app", "user_code", "user_code_uri"];
pub const FINISH_METHODS: [&str; 2] = ["redirect", "push"];
pub const HASH_METHODS: [&str; 5] = ["sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512"];
const JWSD_TYP: &str = "gnap-binding-jwsd";

fn is_record(v: &Value) -> bool {
    v.is_object()
}

fn js(v: &Value) -> String {
    crate::intent_v2::js_value_string(v)
}

fn js_opt(v: Option<&Value>) -> String {
    v.map(js).unwrap_or_else(|| "undefined".into())
}

/// A JS number as JSON: integral values in the safe range print without a fraction (as `JSON.stringify` does).
fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

fn str_arr(u: Option<&Value>) -> Option<Vec<Value>> {
    u.and_then(Value::as_array).map(|a| a.iter().filter(|s| s.is_string()).cloned().collect())
}

/// A canonical, unpadded base64url Ed25519 public key (exactly 32 bytes).
fn as_ed25519(x: Option<&Value>) -> Option<String> {
    let s = x?.as_str()?;
    decode_b64u_strict(s, Some(32)).map(|_| s.to_string())
}

/// The resource string for a GNAP (type, location) pair: `gnap:<type>:<location>`.
pub fn gnap_action_resource(typ: &str, location: &str) -> String {
    format!("gnap:{typ}:{location}")
}

// ---- access rights ---------------------------------------------------------------------------------------------------

fn try_normalize_access_item(item: &Value) -> Option<Value> {
    if let Some(s) = item.as_str() {
        return if s.is_empty() { None } else { Some(json!({ "type": s })) };
    }
    let o = item.as_object()?;
    let t = o.get("type")?.as_str().filter(|t| !t.is_empty())?;
    let mut out = Map::new();
    out.insert("type".into(), json!(t));
    for k in ["actions", "locations", "datatypes"] {
        if let Some(a) = str_arr(o.get(k)).filter(|a| !a.is_empty()) {
            out.insert(k.into(), Value::Array(a));
        }
    }
    if let Some(id) = o.get("identifier").filter(|v| v.is_string()) {
        out.insert("identifier".into(), id.clone());
    }
    if let Some(a) = str_arr(o.get("privileges")).filter(|a| !a.is_empty()) {
        out.insert("privileges".into(), Value::Array(a));
    }
    Some(Value::Object(out))
}

/// Normalize an access array for issuance: every entry must be a non-empty string or an object with a non-empty `type`.
pub fn normalize_access(items: &Value) -> Result<Vec<Value>, String> {
    let a = items.as_array().ok_or("access must be an array")?;
    a.iter().map(|i| try_normalize_access_item(i).ok_or_else(|| "malformed access item (needs a non-empty string `type`)".to_string())).collect()
}

fn read_access_array(u: Option<&Value>) -> Vec<Value> {
    u.and_then(Value::as_array).map(|a| a.iter().filter_map(try_normalize_access_item).collect()).unwrap_or_default()
}

fn non_empty_list<'a>(o: &'a Value, k: &str) -> Option<&'a Vec<Value>> {
    o.get(k).and_then(Value::as_array).filter(|a| !a.is_empty())
}

/// One predicate per location: `type` namespaces the resource, `actions` are the verbs (`*` when absent), `datatypes` /
/// `identifier` become `where` conditions on the action params.
pub fn access_to_predicates(access: &Value) -> Vec<Value> {
    let verb = non_empty_list(access, "actions").map(|a| Value::Array(a.clone())).unwrap_or(json!("*"));
    let star = vec![json!("*")];
    let locations = non_empty_list(access, "locations").unwrap_or(&star);
    let mut wh: Vec<Value> = Vec::new();
    if let Some(d) = non_empty_list(access, "datatypes") {
        wh.push(json!({ "field": "action.params.datatype", "op": "in", "value": d }));
    }
    if let Some(id) = access.get("identifier").filter(|v| v.is_string()) {
        wh.push(json!({ "field": "action.params.identifier", "op": "eq", "value": id }));
    }
    let t = js_opt(access.get("type"));
    locations
        .iter()
        .map(|loc| {
            let mut p = Map::new();
            p.insert("verb".into(), verb.clone());
            p.insert("resource".into(), json!(gnap_action_resource(&t, &js(loc))));
            if !wh.is_empty() {
                p.insert("where".into(), Value::Array(wh.clone()));
            }
            Value::Object(p)
        })
        .collect()
}

fn access_array_to_predicates(access: &[Value]) -> Vec<Value> {
    access.iter().flat_map(access_to_predicates).collect()
}

fn covers_strings(sup: Option<&Value>, sub: Option<&Value>) -> bool {
    let Some(sup) = sup else { return true };
    let Some(sub) = sub else { return false };
    let sup = sup.as_array().map(Vec::as_slice).unwrap_or(&[]);
    sub.as_array().is_some_and(|s| s.iter().all(|x| sup.contains(x)))
}

fn covers_locations(sup: Option<&Value>, sub: Option<&Value>) -> bool {
    let Some(sup) = sup else { return true };
    let sup = sup.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let Some(sub) = sub else { return sup.contains(&json!("*")) };
    sub.as_array().is_some_and(|s| {
        s.iter().all(|x| {
            sup.iter().any(|g| {
                g == x || g == "*" || matches!((g.as_str(), x.as_str()), (Some(gs), Some(xs)) if gs.ends_with('*') && xs.starts_with(&gs[..gs.len() - 1]))
            })
        })
    })
}

/// Does the granted right `g` fully contain the requested right `r`?
pub fn access_contains(g: &Value, r: &Value) -> bool {
    if g.get("type") != r.get("type") {
        return false;
    }
    if !covers_strings(g.get("actions"), r.get("actions")) || !covers_locations(g.get("locations"), r.get("locations")) {
        return false;
    }
    if !covers_strings(g.get("datatypes"), r.get("datatypes")) {
        return false;
    }
    !matches!((g.get("identifier"), r.get("identifier")), (Some(a), Some(b)) if a != b)
}

/// Is `r` covered by at least one right of `granted`?
pub fn access_within(granted: &[Value], r: &Value) -> bool {
    granted.iter().any(|g| access_contains(g, r))
}

/// Split a requested access array into `{granted, dropped}` against the issuer's rights.
pub fn clamp_access(issuer_granted: &[Value], requested: &[Value]) -> Value {
    let (granted, dropped): (Vec<Value>, Vec<Value>) = requested.iter().cloned().partition(|r| access_within(issuer_granted, r));
    json!({ "granted": granted, "dropped": dropped })
}

// ---- provenance caveats ----------------------------------------------------------------------------------------------

fn read_gnap_grant(root: &Value) -> Option<Vec<Value>> {
    let env = crate::authorize::read_envelope(root)?;
    let cv = env.get("caveats")?.as_array()?.iter().find(|c| c.get("type").and_then(Value::as_str) == Some(GNAP_GRANT_CAVEAT))?;
    if !cv.get("client_id").is_some_and(Value::is_string) || !cv.get("request_digest").is_some_and(Value::is_string) {
        return None;
    }
    Some(read_access_array(cv.get("granted_access")))
}

/// The effective granted access of a chain: the leaf's last `gnap_access` caveat, else the root grant's recorded rights.
/// Refused (as the reference's runtime error) when the leaf is JSON null.
pub fn granted_access_of(chain: &Value) -> Result<Vec<Value>, String> {
    let Some(c) = chain.as_array().filter(|c| !c.is_empty()) else { return Ok(vec![]) };
    let leaf = &c[c.len() - 1];
    if leaf.is_null() {
        return Err("Cannot read properties of null (reading 'caveats')".into());
    }
    if let Some(cvs) = leaf.get("caveats").and_then(Value::as_array) {
        if let Some(cv) = cvs.iter().rev().find(|cv| cv.get("type").and_then(Value::as_str) == Some(GNAP_ACCESS_CAVEAT)) {
            return Ok(read_access_array(cv.get("access")));
        }
    }
    Ok(read_gnap_grant(&c[0]).unwrap_or_default())
}

// ---- holders ---------------------------------------------------------------------------------------------------------

/// The holder key of a request: the client key's OKP/Ed25519 JWK, or `holder_override` when given (`Some(Value::Null)` is
/// an override and is refused). The client key proof method must be `jwsd`.
pub fn resolve_holder(req: &Value, holder_override: Option<&Value>) -> Result<String, String> {
    if req.is_null() {
        return Err("Cannot read properties of null (reading 'client')".into());
    }
    let client = req.get("client").filter(|c| c.is_object() || c.is_array());
    let declared = client.and_then(|c| c.get("key"));
    if let Some(d) = declared.filter(|d| d.is_object() || d.is_array()) {
        let method = match d.get("proof") {
            Some(Value::String(s)) => Some(s.as_str()),
            Some(p @ Value::Object(_)) => p.get("method").and_then(Value::as_str),
            _ => None,
        };
        if method != Some("jwsd") {
            return Err(format!("unsupported client key proof method: {} (only jwsd is supported)", method.unwrap_or("none")));
        }
    }
    if let Some(h) = holder_override {
        return as_ed25519(Some(h)).ok_or_else(|| "holder override is not a canonical base64url Ed25519 public key".to_string());
    }
    if let Some(jwk) = declared.and_then(|k| k.get("jwk")) {
        if jwk.get("kty") == Some(&json!("OKP")) && jwk.get("crv") == Some(&json!("Ed25519")) {
            if let Some(x) = as_ed25519(jwk.get("x")) {
                return Ok(x);
            }
        }
    }
    Err("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override".into())
}

/// The holder key as a GNAP JWK (a bound access-token response).
pub fn holder_jwk(holder: &Value) -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": holder, "use": "sig", "alg": "EdDSA" })
}

fn access_of(req: &Value) -> Result<&Value, String> {
    if req.is_null() {
        return Err("Cannot read properties of null (reading 'access_token')".into());
    }
    match req.get("access_token") {
        Some(at) if is_record(at) && at.get("access").is_some_and(Value::is_array) => Ok(&at["access"]),
        _ => Err("grant request must carry access_token.access (single-token request)".into()),
    }
}

// ---- grant request -> capability -------------------------------------------------------------------------------------

/// Convert a grant request into a capability bound to the client key, attenuated to never exceed the issuer.
/// `opts`: `issuerPublic`, `parent` (truthy: delegate a hop), `issuerChain`, `clampToIssuer`, `holder`, `interacted`, `now`
/// (epoch ms), and for a root grant `goal`, `riskPolicy`, `agentBinding`, `salt`. `issuer` signs the hop (the principal for a
/// root grant, the parent holder for a delegation). Returns `{grant, chain, holder, grantedAccess, droppedAccess, provenance}`.
pub fn grant_request_to_capability(req: &Value, opts: &Value, issuer: Option<&KeyPair>) -> Result<Value, String> {
    let holder = resolve_holder(req, opts.get("holder"))?;
    let requested = normalize_access(access_of(req)?)?;
    let now = match opts.get("now").filter(|v| !v.is_null()) {
        Some(v) => v.as_f64().ok_or("now must be a number")?.floor(),
        None => now_ms().floor(),
    };
    let interacted = opts.get("interacted") == Some(&Value::Bool(true));
    let parent = opts.get("parent").filter(|p| crate::oauth::truthy(Some(p)));
    let issuer_chain: Vec<Value> = match (parent, opts.get("issuerChain").filter(|c| !c.is_null())) {
        (Some(_), Some(c)) => c.as_array().cloned().ok_or("issuerChain must be an array")?,
        (Some(p), None) => vec![p.clone()],
        _ => vec![],
    };
    let (mut granted, mut dropped) = (requested.clone(), Vec::new());
    if parent.is_some() && opts.get("clampToIssuer") != Some(&Value::Bool(false)) {
        let g = granted_access_of(&Value::Array(issuer_chain.clone()))?;
        (granted, dropped) = requested.into_iter().partition(|r| access_within(&g, r));
    }
    let interact = req.get("interact").cloned().unwrap_or(Value::Null);
    let request_digest = hash_canonical_strict(&json!({ "d": "atlas-pca/gnap/request/v1", "client_id": holder, "access": granted, "interact": interact }))
        .ok_or("canonicalize: the request is outside the canonical profile")?;
    let signer = issuer.ok_or("signWithSuite: 'ed25519' requires edSecret")?;
    if let Some(p) = parent {
        let provenance = json!({ "type": GNAP_ACCESS_CAVEAT, "access": granted, "predicates": access_array_to_predicates(&granted),
            "request_digest": request_digest, "client_id": holder, "ts": num(now) });
        let child = delegate(p, signer, Some(&holder), &json!([provenance]), None, &Suite::default())?;
        let mut chain = issuer_chain;
        chain.push(child.clone());
        return Ok(json!({ "grant": child, "chain": chain, "holder": holder, "grantedAccess": granted, "droppedAccess": dropped, "provenance": provenance }));
    }
    if let Some(pk) = opts.get("issuerPublic") {
        // stricter than the reference: an issuer public key that is not the signing key's is refused (never a grant whose
        // issuer cannot have signed it)
        if pk.as_str() != Some(signer.public.as_str()) {
            return Err("issuerPublic is not the public key of the issuer secret".into());
        }
    }
    let provenance = json!({ "type": GNAP_GRANT_CAVEAT, "client_id": holder, "granted_access": granted, "request_digest": request_digest,
        "interacted": interacted, "ts": num(now) });
    let nn = |k: &str| opts.get(k).filter(|v| !v.is_null()).cloned();
    let envelope = json!({ "predicates": access_array_to_predicates(&granted), "caveats": [provenance.clone()],
        "agent_binding": nn("agentBinding").unwrap_or(json!({})), "risk_policy": nn("riskPolicy").unwrap_or_else(crate::agent::default_risk_policy) });
    let goal = match nn("goal") {
        Some(g) => g.as_str().ok_or("goal must be a string")?.to_string(),
        None => format!("gnap:grant:{holder}"),
    };
    let salt = match opts.get("salt") {
        None => None,
        Some(s) => Some(s.as_str().ok_or("salt must be a string")?),
    };
    let grant = mint_grant(signer, &holder, &envelope, &goal, salt, None, &Suite::default())?.grant;
    Ok(json!({ "grant": grant, "chain": [grant], "holder": holder, "grantedAccess": granted, "droppedAccess": dropped, "provenance": provenance }))
}

// ---- action authorization --------------------------------------------------------------------------------------------

fn chain_opts(opts: &Value) -> (Option<String>, Option<HashMap<String, String>>) {
    // an explicit null (or any non-string) expected issuer never matches a root issuer
    let exp = opts.get("expectedRootIssuer").map(|v| v.as_str().map(String::from).unwrap_or_else(|| "\u{0}".into()));
    let pins = opts.get("pqPins").and_then(Value::as_object).map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect());
    (exp, pins)
}

fn verify_chain_with(chain: &[Value], opts: &Value) -> Result<(), String> {
    let (exp, pins) = chain_opts(opts);
    crate::verify_chain_policy(chain, exp.as_deref(), None, pins.as_ref(), None)
}

/// Is `action` (`{verb, resource, params?, reversibility_class?}`) authorized by a GNAP-issued chain? The chain must verify,
/// the root envelope must permit the action and so must every delegated hop's recorded rights. `opts`: `expectedRootIssuer`,
/// `pqPins`. Returns `{allowed, reason?}`.
pub fn authorize_gnap_action(chain: &Value, action: &Value, opts: &Value) -> Value {
    let deny = |r: String| json!({ "allowed": false, "reason": r });
    let Some(c) = chain.as_array().filter(|c| !c.is_empty()) else { return deny("empty chain".into()) };
    if let Err(r) = verify_chain_with(c, opts) {
        return deny(format!("capability chain invalid: {r}"));
    }
    let Some(env) = crate::authorize::read_envelope(&c[0]) else { return deny("root grant carries no policy envelope".into()) };
    let mut a = Map::new();
    for k in ["verb", "resource", "params", "reversibility_class"] {
        if let Some(v) = action.get(k) {
            a.insert(k.into(), v.clone());
        }
    }
    let ctx = json!({ "action": a });
    let preds = env.get("predicates").and_then(Value::as_array).cloned().unwrap_or_default();
    if let Some(r) = crate::authorize::envelope_predicates_denial(&preds, &ctx) {
        return deny(format!("root authority denies: {r}"));
    }
    if let Some(cvs) = c[c.len() - 1].get("caveats").and_then(Value::as_array) {
        for cv in cvs.iter().filter(|cv| cv.get("type").and_then(Value::as_str) == Some(GNAP_ACCESS_CAVEAT)) {
            let hop = access_array_to_predicates(&read_access_array(cv.get("access")));
            if let Some(r) = crate::authorize::envelope_predicates_denial(&hop, &ctx) {
                return deny(format!("delegated hop denies: {r}"));
            }
        }
    }
    json!({ "allowed": true })
}

// ---- bound tokens ----------------------------------------------------------------------------------------------------

/// A capability chain as a GNAP access-token value: base64url of its JSON text (member order kept).
pub fn encode_bound_token(chain: &Value) -> String {
    b64_encode(js_stringify(chain).as_bytes())
}

fn is_capability_shape(x: &Value) -> bool {
    let Some(o) = x.as_object() else { return false };
    ["id", "issuer", "holder", "body_digest", "sig"].iter().all(|k| o.get(*k).is_some_and(Value::is_string))
        && o.get("caveats").is_some_and(Value::is_array)
        && ["parent", "alg", "pq_pk", "pq_sig"].iter().all(|k| o.get(*k).is_none_or(Value::is_string))
}

fn decode_bound_token(value: &str) -> Option<Vec<Value>> {
    let bytes = decode_b64u_strict(value, None)?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf][..]).unwrap_or(&bytes); // a fatal UTF-8 decoder still drops one BOM
    let parsed = strict_parse(std::str::from_utf8(bytes).ok()?).ok()?;
    let a = parsed.as_array()?;
    a.iter().all(is_capability_shape).then(|| a.clone())
}

/// Render a chain as a GNAP grant response with a bound access token. `opts`: `expiresIn`, `bearer`, `instanceId`,
/// `manageUri`, `continue`.
pub fn capability_to_grant_response(chain: &Value, opts: &Value) -> Result<Value, String> {
    let Some(c) = chain.as_array().filter(|c| !c.is_empty()) else { return Err("capabilityToGrantResponse: empty chain".into()) };
    let leaf = &c[c.len() - 1];
    let mut token = Map::new();
    token.insert("value".into(), json!(encode_bound_token(chain)));
    token.insert("access".into(), Value::Array(granted_access_of(chain)?));
    let key = if opts.get("bearer") == Some(&Value::Bool(true)) { json!(false) } else { holder_jwk(leaf.get("holder").unwrap_or(&Value::Null)) };
    token.insert("key".into(), key);
    if let Some(e) = opts.get("expiresIn") {
        token.insert("expires_in".into(), e.clone());
    }
    if let Some(m) = opts.get("manageUri") {
        token.insert("manage".into(), json!({ "uri": m }));
    }
    let mut res = Map::new();
    res.insert("access_token".into(), Value::Object(token));
    if let Some(cn) = opts.get("continue") {
        res.insert("continue".into(), cn.clone());
    }
    if let Some(i) = opts.get("instanceId") {
        res.insert("instance_id".into(), i.clone());
    }
    Ok(Value::Object(res))
}

/// Verify an incoming bound token: `{ok:true, principal, capability, chain, access}` or `{ok:false, reason}`.
pub fn verify_gnap_token(value: &Value, opts: &Value) -> Value {
    let fail = |r: &str| json!({ "ok": false, "reason": r });
    let Some(v) = value.as_str().filter(|v| !v.is_empty()) else { return fail("token value is empty") };
    let Some(chain) = decode_bound_token(v).filter(|c| !c.is_empty()) else { return fail("token is not a decodable PCA capability chain") };
    if let Err(r) = verify_chain_with(&chain, opts) {
        return fail(&format!("capability chain invalid: {r}"));
    }
    let cv = Value::Array(chain.clone());
    let access = granted_access_of(&cv).unwrap_or_default();
    json!({ "ok": true, "principal": chain[0]["issuer"], "capability": chain[chain.len() - 1], "chain": cv, "access": access })
}

// ---- jwsd detached-JWS proofs ----------------------------------------------------------------------------------------

/// The content a `jwsd` proof covers.
#[derive(Debug, Clone)]
pub enum GnapBody {
    /// No request content (the payload is empty).
    Absent,
    /// The exact content bytes.
    Bytes(Vec<u8>),
    /// A string is the exact content (UTF-8); any other value is hashed as its strict canonical JSON.
    Json(Value),
}

fn to_plain(v: &Value) -> Value {
    match v {
        Value::Number(n) if n.as_f64() == Some(0.0) && n.as_f64().is_some_and(f64::is_sign_negative) => json!(0),
        Value::Array(a) => Value::Array(a.iter().map(to_plain).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), to_plain(x))).collect()),
        x => x.clone(),
    }
}

/// The JWS payload of a `jwsd` proof (RFC 9635 7.3.3): SHA-256 of the request content, or nothing for no content.
pub fn gnap_content_digest(body: &GnapBody) -> Result<Vec<u8>, String> {
    Ok(match body {
        GnapBody::Absent => vec![],
        GnapBody::Bytes(b) => sha(b),
        GnapBody::Json(Value::String(s)) => sha(s.as_bytes()),
        GnapBody::Json(v) => sha(canonicalize_strict(&to_plain(v))?.as_bytes()),
    })
}

fn ath_of(v: &str) -> String {
    b64_encode(&sha(v.as_bytes()))
}

/// A `jwsd` detached-JWS proof over `body` signed by `key` (whose public half is the holder). `args`: `htm`, `uri`,
/// `created` (epoch seconds, default now), `kid`, `accessTokenValue` (bound through `ath`). Returns `{detachedJws, header, holder}`.
pub fn sign_gnap_request(args: &Value, body: &GnapBody, key: &KeyPair) -> Result<Value, String> {
    let created = match args.get("created").filter(|v| !v.is_null()) {
        Some(c) => c.clone(),
        None => num((now_ms() / 1000.0).floor()),
    };
    let htm = args.get("htm").and_then(Value::as_str).ok_or("Cannot read properties of undefined (reading 'toUpperCase')")?;
    let mut h = Map::new();
    h.insert("alg".into(), json!("EdDSA"));
    h.insert("typ".into(), json!(JWSD_TYP));
    h.insert("htm".into(), json!(htm.to_uppercase()));
    if let Some(u) = args.get("uri") {
        h.insert("uri".into(), u.clone());
    }
    h.insert("created".into(), created);
    if let Some(k) = args.get("kid") {
        h.insert("kid".into(), k.clone());
    }
    if let Some(t) = args.get("accessTokenValue") {
        h.insert("ath".into(), json!(ath_of(t.as_str().ok_or("accessTokenValue must be a string")?)));
    }
    let payload = gnap_content_digest(body)?;
    let header = Value::Object(h);
    let prot = b64_encode(js_stringify(&header).as_bytes());
    let sig = key.sign(format!("{prot}.{}", b64_encode(&payload)).as_bytes());
    Ok(json!({ "detachedJws": format!("{prot}..{}", b64_encode(&sig)), "header": header, "holder": key.public }))
}

/// A replay store: called with `(proofId, expiresSec)` once per otherwise-valid proof; `Ok(true)` = already seen (refused).
/// An `Err` counts as replayed.
pub type SeenProof<'a> = &'a mut dyn FnMut(&str, f64) -> Result<bool, String>;

/// `assertCanonicalJwsSegments`: both segments canonical base64url, the header a strict-JSON object.
fn canonical_segments(prot: &str, sig: &str) -> Result<Map<String, Value>, String> {
    if prot.len() + sig.len() > crate::jose::DEFAULT_MAX_JWS_BYTES {
        return Err("non-canonical compact JWS: too-long".into());
    }
    if prot.is_empty() || sig.is_empty() {
        return Err("non-canonical compact JWS: empty-segment".into());
    }
    let hb = crate::attest::jws::decode_canonical_b64url(prot)?;
    let header = match crate::jose::parse_json_bytes(&hb)? {
        Value::Object(m) => m,
        _ => return Err("non-canonical compact JWS: not-an-object".into()),
    };
    crate::attest::jws::decode_canonical_b64url(sig)?;
    Ok(header)
}

/// Verify a `jwsd` proof and bind the request to `holder`. `args`: `detachedJws`, `holder`, `htm`, `uri`, `maxAgeSec`
/// (default 300), `now` (epoch ms), `accessTokenValue`, `replayCheck` (`"unchecked"` opts out of the replay store).
/// Without `seen_proof` and without the opt-out the call is refused. Returns `{ok:true, holder, header}` or `{ok:false, reason}`.
pub fn verify_gnap_request(args: &Value, body: &GnapBody, seen_proof: Option<SeenProof>) -> Result<Value, String> {
    if seen_proof.is_none() && args.get("replayCheck").and_then(Value::as_str) != Some("unchecked") {
        return Err("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'".into());
    }
    let fail = |r: &str| Ok(json!({ "ok": false, "reason": r }));
    const MALFORMED: &str = "malformed jwsd request";
    let Some(jws) = args.get("detachedJws").and_then(Value::as_str) else { return fail(MALFORMED) };
    if jws.encode_utf16().count() > MAX_DETACHED_JWS_CHARS {
        return fail("detached JWS exceeds the size limit");
    }
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return fail("not a compact JWS (expected three dot-separated parts)");
    }
    let (prot, mid, sig) = (parts[0], parts[1], parts[2]);
    let Some(holder) = as_ed25519(args.get("holder")) else { return fail("holder is not a canonical base64url Ed25519 public key") };
    let Ok(digest) = gnap_content_digest(body) else { return fail(MALFORMED) };
    let payload = b64_encode(&digest);
    if !mid.is_empty() && mid != payload {
        return fail("not a DETACHED compact JWS");
    }
    let header = match canonical_segments(prot, sig) {
        Ok(h) => h,
        Err(e) => return fail(&format!("non-canonical detached JWS: {e}")),
    };
    // the JOSE verify: EdDSA under the holder key, `crit` only for b64 (the signing input is the same either way: the
    // payload segment is the base64url text)
    let sig_ok = header.get("alg").and_then(Value::as_str) == Some("EdDSA")
        && crate::jose::check_crit_b64(&header).is_ok()
        && crate::jose::import_public_jwk(&json!({ "kty": "OKP", "crv": "Ed25519", "x": holder }), "EdDSA").is_ok_and(|k| {
            crate::jose::verify_jws_signature("EdDSA", &k, format!("{prot}.{payload}").as_bytes(), &decode_b64u_strict(sig, None).unwrap_or_default())
        });
    if !sig_ok {
        return fail("jwsd signature does not verify under the holder key (or body was tampered)");
    }
    if header.get("typ").and_then(Value::as_str) != Some(JWSD_TYP) {
        return fail("unexpected typ (not gnap-binding-jwsd)");
    }
    let htm = match header.get("htm").and_then(Value::as_str) {
        None => return fail("htm does not match the request method"),
        Some(h) => match args.get("htm").and_then(Value::as_str) {
            None => return fail(MALFORMED),
            Some(a) if h.to_uppercase() == a.to_uppercase() => h.to_string(),
            Some(_) => return fail("htm does not match the request method"),
        },
    };
    let uri = match header.get("uri").and_then(Value::as_str) {
        Some(u) if args.get("uri").and_then(Value::as_str) == Some(u) => u.to_string(),
        _ => return fail("uri does not match the request target"),
    };
    let Some(created) = header.get("created").and_then(Value::as_f64) else { return fail("missing or malformed created") };
    let now = match args.get("now").filter(|v| !v.is_null()) {
        Some(n) => match n.as_f64() {
            Some(n) => n,
            None => return fail(MALFORMED),
        },
        None => now_ms(),
    };
    let now_sec = (now / 1000.0).floor();
    let max_age = match args.get("maxAgeSec").filter(|v| !v.is_null()) {
        Some(m) => match m.as_f64() {
            Some(m) => m,
            None => return fail(MALFORMED),
        },
        None => 300.0,
    };
    if !(now_sec.is_finite() && created <= now_sec + 60.0) {
        return fail("created is in the future");
    }
    if !(max_age.is_finite() && now_sec - created <= max_age) {
        return fail("jwsd proof is stale");
    }
    let ath = header.get("ath").and_then(Value::as_str);
    if let Some(want) = args.get("accessTokenValue") {
        if want.as_str().is_none() || ath != want.as_str().map(ath_of).as_deref() {
            return fail("ath does not bind the named access token");
        }
    }
    if let Some(store) = seen_proof {
        if store(&ath_of(jws), created + max_age).unwrap_or(true) {
            return fail("jwsd proof replayed (or the replay store failed)");
        }
    }
    let mut out = Map::new();
    out.insert("alg".into(), json!("EdDSA"));
    out.insert("typ".into(), json!(JWSD_TYP));
    out.insert("htm".into(), json!(htm));
    out.insert("uri".into(), json!(uri));
    out.insert("created".into(), header["created"].clone());
    if let Some(k) = header.get("kid").filter(|k| k.is_string()) {
        out.insert("kid".into(), k.clone());
    }
    if let Some(a) = ath {
        out.insert("ath".into(), json!(a));
    }
    Ok(json!({ "ok": true, "holder": holder, "header": out }))
}

// ---- continuation / step-up ------------------------------------------------------------------------------------------

/// Does a grant request need a continuation (interaction requested, an explicit tier above 1, or rights beyond the issuer
/// chain's)? `opts`: `issuerChain`, `tier`. Returns `{required, reason, beyond, tier}`.
pub fn gnap_request_requires_step_up(req: &Value, opts: &Value) -> Result<Value, String> {
    let mut beyond = Vec::new();
    if let Some(chain) = opts.get("issuerChain").filter(|c| crate::oauth::truthy(Some(c))) {
        let g = granted_access_of(chain)?;
        beyond = normalize_access(access_of(req)?)?.into_iter().filter(|r| !access_within(&g, r)).collect();
    }
    if req.is_null() {
        return Err("Cannot read properties of null (reading 'interact')".into());
    }
    let interact = match req.get("interact") {
        None => false,
        Some(Value::Null) => return Err("Cannot read properties of null (reading 'start')".into()),
        Some(i) => i.get("start").and_then(Value::as_array).is_some_and(|s| !s.is_empty()),
    };
    let tier = opts.get("tier").filter(|t| !t.is_null());
    let required = interact || !beyond.is_empty() || tier.and_then(Value::as_f64).is_some_and(|t| t > 1.0);
    let tier = tier.cloned().unwrap_or(json!(if beyond.is_empty() { 2 } else { 3 }));
    let reason = if !required {
        "no step-up required".to_string()
    } else if !beyond.is_empty() {
        format!("requested rights exceed the issuer's authority ({} right(s) beyond)", beyond.len())
    } else if interact {
        "GNAP interaction requested".to_string()
    } else {
        format!("tier {} step-up required", js(&tier))
    };
    Ok(json!({ "required": required, "reason": reason, "beyond": beyond, "tier": tier }))
}

/// Begin a continuation: the `continue` handle and the step-up it resolves through. `args`: `signerSet`, `t`, `tier`,
/// `continueUri`, `continueToken`, `wait`, `reason`. Returns `{response, stepUp}`.
pub fn begin_gnap_continuation(args: &Value) -> Value {
    let mut cont = Map::new();
    if let Some(u) = args.get("continueUri") {
        cont.insert("uri".into(), u.clone());
    }
    let mut at = Map::new();
    if let Some(t) = args.get("continueToken") {
        at.insert("value".into(), t.clone());
    }
    at.insert("bound".into(), json!(true));
    cont.insert("access_token".into(), Value::Object(at));
    if let Some(w) = args.get("wait") {
        cont.insert("wait".into(), w.clone());
    }
    let mut su = Map::new();
    for (k, src) in [("tier", "tier"), ("t", "t"), ("signerSet", "signerSet")] {
        if let Some(v) = args.get(src) {
            su.insert(k.into(), v.clone());
        }
    }
    let reason = match args.get("reason").filter(|r| !r.is_null()) {
        Some(r) => r.clone(),
        None => json!(format!("tier {} co-signature required to continue", js_opt(args.get("tier")))),
    };
    su.insert("reason".into(), reason);
    if let Some(t) = args.get("continueToken") {
        su.insert("continueToken".into(), t.clone());
    }
    json!({ "response": { "continue": cont }, "stepUp": su })
}

fn threshold_t(t: &Value) -> Option<u8> {
    match t.as_f64() {
        Some(x) if x == 1.0 || x == 2.0 || x == 3.0 => Some(x as u8),
        _ => None,
    }
}

fn set_of(signer_set: &Value) -> &[Value] {
    signer_set.as_array().map(Vec::as_slice).unwrap_or(&[])
}

/// `shareMessage(role, message, signerSet, t)` for an Ed25519 share.
fn share_message(role: &str, message: &[u8], signer_set: &Value, t: &Value) -> Result<Vec<u8>, String> {
    let t = threshold_t(t).ok_or("shareMessage: t must be 1, 2 or 3")?;
    // shortcut: a signer-set entry with a non-string role / publicKey is refused (the reference hashes String(value)); such a
    // set never verifies anyway
    let ssh = crate::signer_set_hash(set_of(signer_set)).ok_or("malformed signer set")?;
    let mut m = format!("atlas-pca/share/{role}\0").into_bytes();
    m.extend(sha(message));
    m.extend(ssh);
    m.push(t);
    Ok(m)
}

fn sign_share(role: &str, key: &KeyPair, message: &[u8], signer_set: &Value, t: &Value) -> Result<Value, String> {
    let m = share_message(role, message, signer_set, t)?;
    Ok(json!({ "role": role, "publicKey": key.public, "sig": b64_encode(&key.sign(&m)) }))
}

/// One role's step-up co-signature share over a PCActn body, bound to the signer set and `t` (1, 2 or 3).
pub fn gnap_step_up_share(body: &Value, role: &str, key: &KeyPair, signer_set: &Value, t: &Value) -> Result<Value, String> {
    let msg = threshold_message(body.as_object().ok_or("thresholdMessage: the PCActn body must be an object")?)?;
    sign_share(role, key, &msg, signer_set, t)
}

const ROLES: [&str; 3] = ["agent", "guardian", "principal"];
const PQ_PK_LENGTHS: [usize; 7] = [1952, 2592, 32, 64, 897, 1793, 97484];

fn show(v: Option<&Value>) -> String {
    match v {
        Some(Value::Array(_)) => "<array>".into(),
        Some(Value::Object(_)) => "<object>".into(),
        v => js_opt(v),
    }
}

/// `verifyThreshold` without a leaf baseline: the signer set is validated first (known roles, a canonical key per entry, a
/// well-formed `pq_pk`, one key per role, one role per key), then the distinct registered keys with a valid role / set /
/// t-bound share are counted. `{ok, count, roles, reason?}`; total.
fn verify_threshold(shares: &[Value], message: &[u8], signer_set: &Value, t: &Value) -> Value {
    let verdict = |ok: bool, roles: Vec<String>, reason: String| {
        let mut v = json!({ "ok": ok, "count": roles.len(), "roles": roles });
        if !ok {
            v["reason"] = json!(reason);
        }
        v
    };
    if threshold_t(t).is_none() {
        return verdict(false, vec![], format!("invalid threshold t={} (must be 1, 2 or 3)", show(Some(t))));
    }
    let set = set_of(signer_set);
    let mut reg: Vec<(&str, &str)> = Vec::new();
    let mut seen: Vec<(&str, &str, Option<&str>)> = Vec::new();
    for e in set {
        let role = e.get("role").and_then(Value::as_str).filter(|r| ROLES.contains(r));
        let pk = e.get("publicKey").and_then(Value::as_str).filter(|p| decode_b64u_strict(p, Some(32)).is_some());
        let (Some(role), Some(pk)) = (role, pk) else { return verdict(false, vec![], "malformed signer set".into()) };
        let pq = e.get("pq_pk").map(|v| v.as_str().filter(|s| decode_b64u_strict(s, None).is_some_and(|b| PQ_PK_LENGTHS.contains(&b.len()))));
        let pq_ok = !matches!(pq, Some(None));
        let pq = pq.flatten();
        if !pq_ok || seen.iter().any(|s| s.0 == role && s.1 == pk && s.2 != pq) {
            return verdict(false, vec![], "malformed signer set (pq_pk)".into());
        }
        seen.push((role, pk, pq));
        if reg.iter().any(|r| r.0 == role && r.1 != pk) {
            return verdict(false, vec![], format!("signer set registers more than one key for role {}", show(e.get("role"))));
        }
        if reg.iter().any(|r| r.1 == pk && r.0 != role) {
            return verdict(false, vec![], "signer set registers one key under two roles".into());
        }
        if !reg.iter().any(|r| r.0 == role) {
            reg.push((role, pk));
        }
    }
    let tm = b64_encode(message);
    let (mut keys, mut roles, mut reason): (Vec<String>, Vec<String>, Option<String>) = (vec![], vec![], None);
    for share in shares {
        let (Some(role), Some(pk)) = (share.get("role").and_then(Value::as_str), share.get("publicKey").and_then(Value::as_str)) else {
            reason.get_or_insert("malformed share".into());
            continue;
        };
        if keys.iter().any(|k| k == pk) {
            continue;
        }
        let Some(want) = reg.iter().find(|r| r.0 == role).map(|r| r.1) else {
            reason.get_or_insert(format!("role {role} is not in the signer set"));
            continue;
        };
        if want != pk {
            reason.get_or_insert(format!("share for role {role} uses a key not registered for that role"));
            continue;
        }
        // the share signature, the suite and pq_pk rules: the core's single-share verifier over the same bound message
        let entry = json!({ "role": role, "t": t, "signer_set": set, "threshold_message": tm, "share": share });
        if !crate::verify_threshold_share(&entry) {
            reason.get_or_insert(format!("invalid signature for role {role}"));
            continue;
        }
        keys.push(pk.to_string());
        roles.push(role.to_string());
    }
    let need = threshold_t(t).unwrap_or(4) as usize;
    if roles.len() >= need {
        return verdict(true, roles, String::new());
    }
    let r = reason.unwrap_or_else(|| format!("only {} distinct valid key(s), need {}", roles.len(), show(Some(t))));
    verdict(false, roles, r)
}

/// Resolve a continuation: build the action's PCActn (signed by `agent_leaf`), fold the agent share and the step-up
/// co-signatures (`cosigns`: role + key) into its `threshold`, and verify `t` is reached. `args`: `grant`, `chain`, `plan`,
/// `nodeId`, `params`, `counter`, `aud`, `now` (epoch ms), `ttlMs`, `signerSet`, `t`. Returns `{pcactn, threshold, verdict}`.
pub fn complete_gnap_continuation(args: &Value, agent_leaf: &KeyPair, cosigns: Option<&[(String, KeyPair)]>) -> Result<Value, String> {
    let chain = args.get("chain").and_then(Value::as_array).filter(|c| !c.is_empty()).ok_or("completeGnapContinuation: empty chain")?;
    let plan = args.get("plan").and_then(Value::as_array).ok_or("completeGnapContinuation: plan must be an array")?;
    let node_id = args.get("nodeId").and_then(Value::as_str).ok_or("completeGnapContinuation: nodeId must be a string")?;
    let int = |k: &str| args.get(k).filter(|v| !v.is_null()).map(|v| v.as_f64().map(|f| f as i64).ok_or(format!("{k} must be a number"))).transpose();
    let iat = int("now")?.unwrap_or_else(|| now_ms() as i64);
    let counter = int("counter")?.ok_or("completeGnapContinuation: counter must be a number")?;
    let p = build_pcactn(&PcactnInput {
        grant: args.get("grant").unwrap_or(&Value::Null),
        chain,
        plan,
        node_id,
        params: args.get("params"),
        counter,
        signer: agent_leaf,
        aud: args.get("aud").and_then(Value::as_str).ok_or("completeGnapContinuation: aud must be a string")?,
        iat,
        exp: int("ttlMs")?.map(|t| iat + t),
        extra: Map::new(),
        suite: Suite::default(),
    })?;
    let msg = threshold_message(p.as_object().ok_or("PCActn")?)?;
    let set = args.get("signerSet").unwrap_or(&Value::Null);
    let t = args.get("t").unwrap_or(&Value::Null);
    let cosigns = cosigns.ok_or("Cannot read properties of undefined (reading 'map')")?;
    let mut shares = vec![sign_share("agent", agent_leaf, &msg, set, t)?];
    for (role, key) in cosigns {
        shares.push(sign_share(role, key, &msg, set, t)?);
    }
    let verdict = verify_threshold(&shares, &msg, set, t);
    let threshold = json!({ "shares": shares });
    let mut pcactn = p;
    pcactn["threshold"] = threshold.clone();
    Ok(json!({ "pcactn": pcactn, "threshold": threshold, "verdict": verdict }))
}

// ---- the profile -----------------------------------------------------------------------------------------------------

/// The package constants.
pub fn constants() -> Value {
    json!({ "GNAP_GRANT_CAVEAT": GNAP_GRANT_CAVEAT, "GNAP_ACCESS_CAVEAT": GNAP_ACCESS_CAVEAT, "MAX_DETACHED_JWS_CHARS": MAX_DETACHED_JWS_CHARS,
        "START_MODES": START_MODES, "FINISH_METHODS": FINISH_METHODS, "HASH_METHODS": HASH_METHODS })
}

/// The machine-readable Agent-GNAP profile.
pub fn agent_gnap_profile() -> Value {
    let m = |g: &str, p: &str, n: &str| json!({ "gnap": g, "pca": p, "note": n });
    json!({
        "name": "agent-gnap",
        "version": "1.0",
        "rfc": "RFC 9635",
        "summary": "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
        "mapping": [
            m("access[].type", "predicate resource namespace gnap:<type>:<location>", "the resource family the rights live in"),
            m("access[].actions", "predicate.verb (list, or * for any)", "the operations permitted"),
            m("access[].locations", "predicate.resource (exact or trailing-* prefix)", "the resource targets"),
            m("access[].datatypes / identifier", "predicate.where on action.params.*", "value-level constraints"),
            m("client.key.jwk (OKP/Ed25519)", "capability.holder (cnf-bound key)", "the proof-of-possession key"),
            m("grant request (no prior grant)", "mintGrant \u{2192} root capability", "envelope predicates = requested access"),
            m("grant request (delegated hop)", "delegate \u{2192} child capability + gnap_access caveat", "append-only attenuation"),
            m("access_token (\u{a7}3.2)", "a verifiable PCA capability chain (encodeBoundToken)", "bound, self-verifying token"),
            m("continue (\u{a7}3.1) + interact (\u{a7}3.3)", "PCA step-up: FROST/threshold co-signature folded into a PCActn", "tier-2/3 escalation"),
            m("jwsd detached JWS (\u{a7}7.3.4)", "request proof binding the body to capability.holder", "verified with jose"),
        ],
        "proofMethods": ["jwsd"],
        "multiHop": "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA caveats are conjunctive and append-only, so no hop can widen \u{2014} \"never wider than the issuer\" holds across any depth.",
        "stepUp": "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or multi-signature) before the action is admitted.",
        "security": [
            "Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
            "Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
            "All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
            "Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
            "Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.",
        ],
    })
}

// ---- interaction (RFC 9635 sections 2.5, 3.3, 4) ---------------------------------------------------------------------

/// An interaction failure with the reference's stable code (`invalid_interaction`, `unknown_interaction`, `too_many_attempts`,
/// `invalid_request`, `expired`, `wrong_state`, `unsupported_hash`), or `type_error` for a value the reference rejects with a
/// runtime type error.
#[derive(Debug, Clone, PartialEq)]
pub struct InteractionError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for InteractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn ierr(code: &'static str, message: impl Into<String>) -> InteractionError {
    InteractionError { code, message: message.into() }
}

fn start_name(e: &Value) -> Option<&str> {
    match e {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("mode").and_then(Value::as_str),
        _ => None,
    }
}

/// Is `uri` an acceptable finish callback: absolute, at most 2048 characters, no fragment; https, loopback http, or an app
/// scheme (never javascript / data / file / blob)?
pub fn callback_uri_ok(uri: &Value) -> bool {
    let Some(s) = uri.as_str() else { return false };
    if s.encode_utf16().count() > 2048 || s.contains('#') {
        return false;
    }
    let Ok(u) = url::Url::parse(s) else { return false };
    if u.fragment().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => true,
        "http" => matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "javascript" | "data" | "file" | "blob" => false,
        _ => true,
    }
}

/// The names a JavaScript `in` test on the reference's method table also finds (inherited from `Object.prototype`): the
/// reference's validation admits them, and its hash step then refuses them with a type error.
const OBJECT_PROTO: [&str; 12] = [
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "__proto__",
    "toLocaleString",
];

fn hash_key_in(v: &Value) -> bool {
    let k = js(v);
    HASH_METHODS.contains(&k.as_str()) || OBJECT_PROTO.contains(&k.as_str())
}

fn printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Validation problems of an interaction request (empty when valid).
pub fn validate_interact_request(r: &Value) -> Vec<String> {
    let Some(o) = r.as_object() else { return vec!["interact must be an object".into()] };
    let mut e: Vec<String> = Vec::new();
    match o.get("start").and_then(Value::as_array) {
        Some(s) if !s.is_empty() && s.len() <= 16 => {
            for x in s {
                if start_name(x).is_none() {
                    e.push("each start entry is a mode name or an object with a mode".into());
                }
            }
        }
        _ => e.push("start must be a non-empty array of modes".into()),
    }
    if let Some(f) = o.get("finish") {
        if !f.is_object() && !f.is_array() {
            e.push("finish must be an object".into());
        } else {
            if !f.get("method").and_then(Value::as_str).is_some_and(|m| FINISH_METHODS.contains(&m)) {
                e.push("finish.method must be redirect or push".into());
            }
            if !callback_uri_ok(f.get("uri").unwrap_or(&Value::Null)) {
                e.push("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment".into());
            }
            let nonce_ok = f.get("nonce").and_then(Value::as_str).is_some_and(|n| (8..=256).contains(&n.encode_utf16().count()) && printable_ascii(n));
            if !nonce_ok {
                e.push("finish.nonce must be 8..256 printable ASCII characters".into());
            }
            if let Some(h) = f.get("hash_method") {
                if !hash_key_in(h) {
                    e.push("finish.hash_method is not a supported Named Information hash".into());
                }
            }
        }
    }
    e
}

/// The interaction finish hash (RFC 9635 4.2.3): base64url(hash(clientNonce \n asNonce \n interactRef \n grantEndpoint)) with
/// `hashMethod` (default `sha-256`). `a` members: `clientNonce`, `asNonce`, `interactRef`, `grantEndpoint`, `hashMethod`.
pub fn interaction_hash(a: &Value) -> Result<String, InteractionError> {
    use sha2::Digest;
    let m = a.get("hashMethod").filter(|v| !v.is_null()).cloned().unwrap_or(json!("sha-256"));
    let k = js(&m);
    if !hash_key_in(&m) {
        return Err(ierr("unsupported_hash", format!("hash_method {k} is not supported")));
    }
    let text = format!("{}\n{}\n{}\n{}", js_opt(a.get("clientNonce")), js_opt(a.get("asNonce")), js_opt(a.get("interactRef")), js_opt(a.get("grantEndpoint")));
    // the reference hashes the text in Node's 'ascii' encoding: the low byte of every UTF-16 code unit
    let bytes: Vec<u8> = text.encode_utf16().map(|u| u as u8).collect();
    let d: Vec<u8> = match k.as_str() {
        "sha-256" => sha2::Sha256::digest(&bytes).to_vec(),
        "sha-384" => sha2::Sha384::digest(&bytes).to_vec(),
        "sha-512" => sha2::Sha512::digest(&bytes).to_vec(),
        "sha3-256" => sha3::Sha3_256::digest(&bytes).to_vec(),
        "sha3-512" => sha3::Sha3_512::digest(&bytes).to_vec(),
        // a key that resolves on Object.prototype: Node refuses it as a non-string algorithm, naming what it received
        _ => {
            let received = match k.as_str() {
                "__proto__" => "an instance of Object".to_string(),
                "constructor" => "function Object".to_string(),
                other => format!("function {other}"),
            };
            return Err(ierr("ERR_INVALID_ARG_TYPE", format!("The \"algorithm\" argument must be of type string. Received {received}")));
        }
    };
    Ok(b64_encode(&d))
}

/// Constant-time comparison of a received finish hash with the expected one.
pub fn verify_interaction_hash(received: &Value, a: &Value) -> Result<bool, InteractionError> {
    let Some(got) = received.as_str() else { return Ok(false) };
    let want = interaction_hash(a)?;
    let (w, g) = (want.as_bytes(), got.as_bytes());
    Ok(w.len() == g.len() && w.iter().zip(g).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0)
}

/// A client's finish callback: `{hash, interact_ref}` checked against `ctx` (`clientNonce`, `asNonce`, `grantEndpoint`,
/// `hashMethod`). Returns the interaction reference.
pub fn accept_finish(cb: &Value, ctx: &Value) -> Result<String, InteractionError> {
    let r = cb.get("interact_ref").and_then(Value::as_str).filter(|r| !r.is_empty());
    let (Some(r), Some(h)) = (r, cb.get("hash").filter(|h| h.is_string())) else {
        return Err(ierr("unknown_interaction", "hash and interact_ref are required"));
    };
    let mut a = ctx.as_object().cloned().unwrap_or_default();
    a.insert("interactRef".into(), json!(r));
    if !verify_interaction_hash(h, &Value::Object(a))? {
        return Err(ierr("unknown_interaction", "the callback hash does not validate"));
    }
    Ok(r.to_string())
}

const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A random user code of `len` (6..12) characters from an unambiguous alphabet.
pub fn new_user_code(len: i64) -> Result<String, String> {
    if !(6..=12).contains(&len) {
        return Err("user code length 6..12".into());
    }
    let b = rand_bytes::<12>()?;
    Ok(b[..len as usize].iter().map(|x| CODE_ALPHABET[(x % 32) as usize] as char).collect())
}

fn norm_code(c: &str) -> String {
    c.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '\u{feff}').collect::<String>().to_uppercase()
}

/// GNAP access rights as `{verb, resource}` needs: every right needs explicit actions and locations.
pub fn access_to_needs(access: &Value) -> Result<Vec<Value>, InteractionError> {
    let mut out = Vec::new();
    for a in access.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        if a.is_null() {
            return Err(ierr("type_error", "Cannot read properties of null (reading 'actions')"));
        }
        let (Some(acts), Some(locs)) = (non_empty_list(a, "actions"), non_empty_list(a, "locations")) else {
            return Err(ierr("invalid_request", format!("access \"{}\" needs explicit actions and locations to become a need", js_opt(a.get("type")))));
        };
        let t = js_opt(a.get("type"));
        for verb in acts {
            for loc in locs {
                out.push(json!({ "verb": verb, "resource": gnap_action_resource(&t, &js(loc)) }));
            }
        }
    }
    Ok(out)
}

/// One pending / approved / finalized interaction.
#[derive(Debug, Clone)]
pub struct Interaction {
    pub id: String,
    pub state: &'static str,
    pub grant_endpoint: String,
    pub modes: Vec<String>,
    /// `{method, uri, clientNonce, asNonce, hashMethod}` when the client asked for a finish.
    pub finish: Option<Value>,
    pub user_code: Option<String>,
    pub interact_ref: Option<String>,
    pub ref_used: bool,
    pub expires_at: f64,
}

impl Interaction {
    /// The reference's JSON shape (camelCase members, absent ones omitted).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("state".into(), json!(self.state));
        m.insert("grantEndpoint".into(), json!(self.grant_endpoint));
        m.insert("modes".into(), json!(self.modes));
        m.insert("refUsed".into(), json!(self.ref_used));
        m.insert("expiresAt".into(), num(self.expires_at));
        if let Some(c) = &self.user_code {
            m.insert("userCode".into(), json!(c));
        }
        if let Some(f) = &self.finish {
            m.insert("finish".into(), f.clone());
        }
        if let Some(r) = &self.interact_ref {
            m.insert("interactRef".into(), json!(r));
        }
        Value::Object(m)
    }
}

/// Options of an [`InteractionServer`].
pub struct InteractionServerOptions {
    pub grant_endpoint: String,
    pub supports: Vec<String>,
    pub redirect_uri: Box<dyn Fn(&str) -> String>,
    pub app_uri: Option<Box<dyn Fn(&str) -> String>>,
    pub user_code_uri: Option<String>,
    /// Interaction lifetime in seconds (default 600).
    pub ttl_sec: Option<f64>,
    /// The clock (seconds).
    pub now: Box<dyn Fn() -> f64>,
}

/// The authorization server's interaction state machine (in memory).
pub struct InteractionServer {
    o: InteractionServerOptions,
    by_id: HashMap<String, Interaction>,
    by_code: HashMap<String, String>,
    by_ref: HashMap<String, String>,
}

fn rand_b64u<const N: usize>() -> Result<String, InteractionError> {
    rand_bytes::<N>().map(|b| b64_encode(&b)).map_err(|e| ierr("type_error", e))
}

/// `u = new URL(uri); u.searchParams.set('hash', h); u.searchParams.set('interact_ref', r); u.toString()`.
fn redirect_url(uri: &str, hash: &str, r: &str) -> Result<String, InteractionError> {
    let mut u = url::Url::parse(uri).map_err(|_| ierr("type_error", "Invalid URL"))?;
    let mut pairs: Vec<(String, String)> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    for (name, value) in [("hash", hash), ("interact_ref", r)] {
        match pairs.iter().position(|p| p.0 == name) {
            Some(i) => {
                pairs[i].1 = value.to_string();
                let mut n = 0;
                pairs.retain(|p| {
                    p.0 != name || {
                        n += 1;
                        n == 1
                    }
                });
            }
            None => pairs.push((name.to_string(), value.to_string())),
        }
    }
    u.query_pairs_mut().clear().extend_pairs(pairs);
    Ok(u.to_string())
}

impl InteractionServer {
    pub fn new(o: InteractionServerOptions) -> Self {
        InteractionServer { o, by_id: HashMap::new(), by_code: HashMap::new(), by_ref: HashMap::new() }
    }

    /// Start an interaction for a validated request: `(interaction, response)`.
    pub fn start(&mut self, req: &Value) -> Result<(Interaction, Value), InteractionError> {
        let problems = validate_interact_request(req);
        if !problems.is_empty() {
            return Err(ierr("invalid_request", problems.join("; ")));
        }
        let asked: Vec<&str> = req["start"].as_array().map(|s| s.iter().filter_map(start_name).collect()).unwrap_or_default();
        let ucu = self.o.user_code_uri.clone().filter(|u| !u.is_empty());
        let modes: Vec<String> = self
            .o
            .supports
            .iter()
            .filter(|m| asked.contains(&m.as_str()) && (m.as_str() != "app" || self.o.app_uri.is_some()) && (m.as_str() != "user_code_uri" || ucu.is_some()))
            .cloned()
            .collect();
        let finish = req.get("finish").filter(|f| !f.is_null());
        if modes.is_empty() && finish.is_none() {
            return Err(ierr("invalid_interaction", "no requested interaction mode is supported"));
        }
        let id = rand_b64u::<16>()?;
        let ttl = self.o.ttl_sec.unwrap_or(600.0);
        let mut it = Interaction {
            id: id.clone(),
            state: "pending",
            grant_endpoint: self.o.grant_endpoint.clone(),
            modes: modes.clone(),
            finish: None,
            user_code: None,
            interact_ref: None,
            ref_used: false,
            expires_at: (self.o.now)() + ttl,
        };
        let mut res = Map::new();
        res.insert("expires_in".into(), num(ttl));
        let has = |m: &str| modes.iter().any(|x| x == m);
        if has("redirect") {
            res.insert("redirect".into(), json!((self.o.redirect_uri)(&id)));
        }
        if has("app") {
            if let Some(f) = &self.o.app_uri {
                res.insert("app".into(), json!(f(&id)));
            }
        }
        if has("user_code") || has("user_code_uri") {
            let code = new_user_code(8).map_err(|e| ierr("type_error", e))?;
            self.by_code.insert(code.clone(), id.clone());
            if has("user_code") {
                res.insert("user_code".into(), json!(code));
            }
            if has("user_code_uri") {
                res.insert("user_code_uri".into(), json!({ "code": code, "uri": ucu }));
            }
            it.user_code = Some(code);
        }
        if let Some(f) = finish {
            let as_nonce = rand_b64u::<24>()?;
            let hm = f.get("hash_method").filter(|v| !v.is_null()).cloned().unwrap_or(json!("sha-256"));
            it.finish = Some(json!({ "method": f["method"], "uri": f["uri"], "clientNonce": f["nonce"], "asNonce": as_nonce, "hashMethod": hm }));
            res.insert("finish".into(), json!(as_nonce));
        }
        self.by_id.insert(id, it.clone());
        Ok((it, Value::Object(res)))
    }

    /// The pending, unexpired interaction a user code names (spaces / dashes ignored, case-insensitive).
    pub fn lookup_user_code(&self, code: &str) -> Option<Interaction> {
        let it = self.by_id.get(self.by_code.get(&norm_code(code))?)?;
        (it.state == "pending" && { let n = (self.o.now)(); n.is_finite() && it.expires_at.is_finite() && n <= it.expires_at }).then(|| it.clone())
    }

    pub fn get(&self, id: &str) -> Option<Interaction> {
        self.by_id.get(id).cloned()
    }

    /// Approve a pending interaction: `{interactRef, finish?}` (a push body or a redirect URL carrying the finish hash).
    pub fn approve(&mut self, id: &str) -> Result<Value, InteractionError> {
        let now = (self.o.now)();
        let it = self.by_id.get_mut(id).ok_or_else(|| ierr("unknown_interaction", "no such interaction"))?;
        if !(now.is_finite() && it.expires_at.is_finite() && now <= it.expires_at) {
            return Err(ierr("expired", "the interaction expired"));
        }
        if it.state != "pending" {
            return Err(ierr("wrong_state", format!("interaction is {}", it.state)));
        }
        it.state = "approved";
        let r = rand_b64u::<18>()?;
        it.interact_ref = Some(r.clone());
        self.by_ref.insert(r.clone(), id.to_string());
        if let Some(c) = &it.user_code {
            self.by_code.remove(c);
        }
        let Some(f) = it.finish.clone() else { return Ok(json!({ "interactRef": r })) };
        let hash = interaction_hash(&json!({ "clientNonce": f["clientNonce"], "asNonce": f["asNonce"], "interactRef": r,
            "grantEndpoint": it.grant_endpoint, "hashMethod": f["hashMethod"] }))?;
        if f["method"] == "push" {
            return Ok(json!({ "interactRef": r, "finish": { "method": "push", "uri": f["uri"], "body": { "hash": hash, "interact_ref": r } } }));
        }
        let url = redirect_url(f["uri"].as_str().unwrap_or(""), &hash, &r)?;
        Ok(json!({ "interactRef": r, "finish": { "method": "redirect", "url": url } }))
    }

    /// Consume an interaction reference exactly once (a second use finalizes the interaction and is refused).
    pub fn consume(&mut self, interact_ref: &str) -> Result<Interaction, InteractionError> {
        let now = (self.o.now)();
        let it =
            self.by_ref.get(interact_ref).and_then(|id| self.by_id.get_mut(id)).ok_or_else(|| ierr("unknown_interaction", "no such interaction reference"))?;
        if it.ref_used || it.state == "finalized" {
            it.state = "finalized";
            return Err(ierr("too_many_attempts", "the interaction reference was already used"));
        }
        if !(now.is_finite() && it.expires_at.is_finite() && now <= it.expires_at) {
            return Err(ierr("expired", "the interaction expired"));
        }
        if it.state != "approved" {
            return Err(ierr("wrong_state", format!("interaction is {}", it.state)));
        }
        it.ref_used = true;
        Ok(it.clone())
    }

    pub fn finalize(&mut self, id: &str) {
        if let Some(it) = self.by_id.get_mut(id) {
            it.state = "finalized";
        }
    }
}
