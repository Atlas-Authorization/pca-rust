//! OpenID Connect rooting for Proof-Carrying Authority, a native port of the reference OIDC bridge.
//!
//! - [`discover_oidc`]: the issuer's `.well-known/openid-configuration` (provider metadata: `jwks_uri`, endpoints).
//! - [`verify_id_token`]: the verified ID-token claims (signature, `iss` / `aud` / `exp` / `nbf` / token age, `nonce`, `azp`,
//!   `at_hash`, `c_hash`), every failure an [`OidcError`] with the reference's stable `code`.
//! - [`oidc_principal`]: a PCA principal descriptor (a subject caveat plus the Ed25519 key a chain roots at).
//! - [`OidcJwks`]: a caching JWKS key resolver that fails closed on stale or unreachable keys; [`LocalJwkSet`]: a fixed set.
//!
//! The network is injected: an [`HttpFetch`] (any `Fn(&str, Option<f64>) -> Result<HttpResponse, String>` is one) does the
//! GET. Options are JSON objects with the reference's camelCase member names (`clockToleranceSec`, `maxTokenAgeSec`,
//! `requireHttps` ...); key material is passed as an [`OidcKey`].
use crate::jose;
use crate::oauth::{js_str, spread, truthy};
use crate::{b64_encode, decode_b64u_strict};
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::collections::HashSet;
use std::sync::Mutex;

pub const OIDC_SUBJECT_CAVEAT: &str = "oidc_subject";
pub const DEFAULT_MAX_DISCOVERY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_JWKS_TIMEOUT_MS: f64 = 5000.0;
/// The asymmetric OIDC signing algorithms allowed by default (never symmetric: a public JWKS is not an HMAC secret).
pub const DEFAULT_ID_TOKEN_ALGS: [&str; 10] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];
const WELL_KNOWN: &str = "/.well-known/openid-configuration";

/// Any OIDC failure. `code` is the reference's classification for ID-token verification (`config`, `invalid_token`,
/// `signature`, `issuer`, `audience`, `expired`, `issued_at`, `not_before`, `nonce`, `azp`, `at_hash`, `c_hash`, `keys`,
/// `claims`), `discovery` for a discovery failure, `type_error` for an argument of the wrong type and `ERR_INVALID_ARG_TYPE`
/// for a non-string `accessToken` / `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcError {
    pub code: String,
    pub message: String,
}

impl OidcError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        OidcError { code: code.into(), message: message.into() }
    }
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for OidcError {}

fn inv(m: impl Into<String>) -> OidcError {
    OidcError::new("invalid_token", m)
}
fn disc(m: impl Into<String>) -> OidcError {
    OidcError::new("discovery", m)
}
fn type_err(m: impl Into<String>) -> OidcError {
    OidcError::new("type_error", m)
}

/// One HTTP response: the status, the headers (any case) and the body text.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// The injected HTTP GET (`accept: application/json`). `timeout_ms` is the deadline the caller asked for; an `Err` is a
/// failed request.
pub trait HttpFetch {
    fn get(&self, url: &str, timeout_ms: Option<f64>) -> Result<HttpResponse, String>;
}

impl<F: Fn(&str, Option<f64>) -> Result<HttpResponse, String>> HttpFetch for F {
    fn get(&self, url: &str, timeout_ms: Option<f64>) -> Result<HttpResponse, String> {
        self(url, timeout_ms)
    }
}

/// A key resolver: the JWK to verify a token with, chosen from its protected header.
pub trait KeyResolver {
    fn resolve(&self, header: &Map<String, Value>) -> Result<Value, OidcError>;
}

/// The key material [`verify_id_token`] checks the signature with.
pub enum OidcKey<'a> {
    /// A JWK (any JSON value: anything but a usable public JWK, or an `oct` JWK for HS*, is refused).
    Jwk(Value),
    /// An HMAC secret (HS256 / HS384 / HS512 only, and only when `algorithms` allows them).
    Secret(Vec<u8>),
    /// A dynamic resolver ([`LocalJwkSet`], [`OidcJwks`] or your own).
    Resolver(&'a dyn KeyResolver),
}

fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn finite(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}

// ---- discovery ----------------------------------------------------------------------------------------------------------

fn is_https(u: &str) -> bool {
    url::Url::parse(u).is_ok_and(|p| p.scheme() == "https")
}

/// `discoveryUrl(issuer)`: `/.well-known/openid-configuration` appended, one trailing slash of the issuer not doubled.
pub fn discovery_url(issuer: &Value) -> Result<String, OidcError> {
    let Some(i) = issuer.as_str() else { return Err(type_err("issuer.endsWith is not a function")) };
    Ok(format!("{}{WELL_KNOWN}", i.strip_suffix('/').unwrap_or(i)))
}

/// `discoverOidc(issuer, opts)`: fetch and check the provider metadata. `opts`: `maxBytes` (default 1 MiB), `requireHttps`
/// (default true: only `false` turns it off). The document's `issuer` must equal `issuer` exactly (OIDC Discovery 4.3).
pub fn discover_oidc(issuer: &Value, opts: &Value, fetch: Option<&dyn HttpFetch>) -> Result<Value, OidcError> {
    let Some(issuer) = non_empty_str(Some(issuer)) else { return Err(disc("discoverOidc: issuer must be a non-empty string")) };
    if opts.is_null() {
        return Err(type_err("Cannot read properties of null (reading 'requireHttps')"));
    }
    let require_https = get(opts, "requireHttps") != Some(&Value::Bool(false));
    if require_https && !is_https(issuer) {
        return Err(disc(format!("discoverOidc: issuer '{issuer}' is not an https URL")));
    }
    let Some(fetch) = fetch else { return Err(disc("discoverOidc: no fetch implementation available (pass opts.fetch)")) };
    let url = format!("{}{WELL_KNOWN}", issuer.strip_suffix('/').unwrap_or(issuer));
    let res = fetch.get(&url, None).map_err(|_| disc(format!("discoverOidc: fetch of {url} failed")))?;
    if !(200..=299).contains(&res.status) {
        return Err(disc(format!("discoverOidc: {url} returned HTTP {}", res.status)));
    }
    let max = get(opts, "maxBytes").filter(|v| !v.is_null()).cloned().unwrap_or(json!(DEFAULT_MAX_DISCOVERY_BYTES));
    let cap = crate::actions::js_to_number(Some(&max));
    let too_big = || disc(format!("discoverOidc: {url} response exceeds {} bytes", js_str(&max)));
    // `Number(headers.get('content-length'))`: an absent header is Number(null) = 0
    let declared = res.header("content-length").map_or(0.0, crate::actions::js_str_to_number);
    if declared.is_finite() && declared > cap {
        return Err(too_big());
    }
    if res.body.len() as f64 > cap {
        return Err(too_big());
    }
    let body: Value = serde_json::from_str(&res.body).map_err(|_| disc(format!("discoverOidc: {url} did not return valid JSON")))?;
    let Value::Object(rec) = body else { return Err(disc("discoverOidc: metadata is not a JSON object")) };
    let Some(doc_issuer) = non_empty_str(rec.get("issuer")).map(String::from) else {
        return Err(disc("discoverOidc: metadata is missing a string \"issuer\""));
    };
    let Some(jwks_uri) = non_empty_str(rec.get("jwks_uri")).map(String::from) else {
        return Err(disc("discoverOidc: metadata is missing a string \"jwks_uri\""));
    };
    if doc_issuer != issuer {
        return Err(disc(format!("discoverOidc: metadata issuer '{doc_issuer}' does not match requested '{issuer}'")));
    }
    if require_https && !is_https(&jwks_uri) {
        return Err(disc(format!("discoverOidc: jwks_uri '{jwks_uri}' is not an https URL")));
    }
    let mut meta = Map::new();
    meta.insert("issuer".into(), json!(doc_issuer));
    meta.insert("jwks_uri".into(), json!(jwks_uri));
    for (k, v) in rec {
        if k != "issuer" && k != "jwks_uri" {
            meta.insert(k, v);
        }
    }
    Ok(Value::Object(meta))
}

// ---- JWK handling (the JOSE library's rules) ----------------------------------------------------------------------------

/// The key is usable for `alg`: a valid public key of the right type. Without the `ed448` feature an Ed448 key passes with a
/// 57-byte `x` (it imports, then never verifies: Ed448 signatures are refused natively).
fn usable_public(jwk: &Value, alg: &str) -> bool {
    #[cfg(not(feature = "ed448"))]
    if get(jwk, "kty") == Some(&json!("OKP")) && get(jwk, "crv") == Some(&json!("Ed448")) {
        return get(jwk, "x").and_then(Value::as_str).and_then(|x| decode_b64u_strict(x, None)).is_some_and(|b| b.len() == 57);
    }
    jose::import_public_jwk(jwk, alg).is_ok()
}

/// A JWK Set with the JOSE library's selection rules: the `kty` the `alg` needs, then `kid` (when the header has a string
/// one), member `alg`, `use`, `key_ops` and curve. Exactly one candidate must match and it must be a valid public key.
#[derive(Debug, Clone)]
pub struct LocalJwkSet {
    keys: Vec<Value>,
}

impl LocalJwkSet {
    /// `{keys: [<JWK object>...]}`; anything else is refused.
    pub fn new(jwks: &Value) -> Result<Self, String> {
        match get(jwks, "keys").and_then(Value::as_array) {
            Some(keys) if keys.iter().all(Value::is_object) => Ok(LocalJwkSet { keys: keys.clone() }),
            _ => Err("JSON Web Key Set malformed".into()),
        }
    }

    fn kids(&self) -> HashSet<String> {
        self.keys.iter().filter_map(|k| get(k, "kid").and_then(Value::as_str).map(String::from)).collect()
    }
}

impl KeyResolver for LocalJwkSet {
    fn resolve(&self, header: &Map<String, Value>) -> Result<Value, OidcError> {
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let kty = match alg.get(..2) {
            Some("RS" | "PS") => "RSA",
            Some("ES") => "EC",
            Some("Ed") => "OKP",
            _ => return Err(inv("Unsupported \"alg\" value for a JSON Web Key Set")),
        };
        let kid = header.get("kid").and_then(Value::as_str);
        let want_crv = match alg {
            "ES256" => Some("P-256"),
            "ES256K" => Some("secp256k1"),
            "ES384" => Some("P-384"),
            "ES512" => Some("P-521"),
            _ => None,
        };
        let s = |k: &Value, m: &str| get(k, m).and_then(Value::as_str).map(String::from);
        let found: Vec<&Value> = self
            .keys
            .iter()
            .filter(|k| {
                s(k, "kty").as_deref() == Some(kty)
                    && kid.is_none_or(|w| s(k, "kid").as_deref() == Some(w))
                    && s(k, "alg").is_none_or(|a| a == alg)
                    && s(k, "use").is_none_or(|u| u == "sig")
                    && get(k, "key_ops").and_then(Value::as_array).is_none_or(|ops| ops.iter().any(|o| o == "verify"))
                    && (alg != "EdDSA" || matches!(s(k, "crv").as_deref(), Some("Ed25519" | "Ed448")))
                    && want_crv.is_none_or(|c| s(k, "crv").as_deref() == Some(c))
            })
            .collect();
        let jwk = match found.as_slice() {
            [] => return Err(inv("no applicable key found in the JSON Web Key Set")),
            [one] => *one,
            _ => return Err(inv("multiple matching keys found in the JSON Web Key Set")),
        };
        if truthy(get(jwk, "d")) {
            return Err(inv("JSON Web Key Set members must be public keys"));
        }
        if !usable_public(jwk, alg) {
            return Err(inv("invalid JWK in the JSON Web Key Set"));
        }
        Ok(jwk.clone())
    }
}

// ---- the caching remote JWK Set -------------------------------------------------------------------------------------------

struct JwksConfig {
    uri: String,
    max_age_ms: f64,
    cooldown_ms: f64,
    max_bytes: f64,
    timeout_ms: f64,
}

/// `createOidcJwks`'s option checks (messages are the reference's).
fn jwks_config(opts: &Value) -> Result<JwksConfig, OidcError> {
    let Some(uri) = non_empty_str(get(opts, "jwksUri")) else { return Err(type_err("createOidcJwks: jwksUri is required")) };
    let require_https = get(opts, "requireHttps").filter(|v| !v.is_null()).is_none_or(|v| truthy(Some(v)));
    if require_https && !uri.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://")) {
        return Err(type_err("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)"));
    }
    let mut vals = [600.0, 30.0, 1024.0 * 1024.0, DEFAULT_JWKS_TIMEOUT_MS];
    for (i, name) in ["cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs"].iter().enumerate() {
        if let Some(v) = get(opts, name) {
            match v.as_f64() {
                Some(f) if f.is_finite() && f >= 0.0 => vals[i] = f,
                _ => return Err(type_err(format!("createOidcJwks: {name} must be a finite number >= 0"))),
            }
        }
    }
    Ok(JwksConfig { uri: uri.to_string(), max_age_ms: vals[0] * 1000.0, cooldown_ms: vals[1] * 1000.0, max_bytes: vals[2], timeout_ms: vals[3] })
}

fn keys_error(uri: &str) -> OidcError {
    OidcError::new("keys", format!("could not fetch the issuer signing keys from {uri}"))
}

/// One fetch of the key set: 2xx, at most `max_bytes` of UTF-8, a JSON object with a `keys` array of objects.
fn fetch_jwk_set(c: &JwksConfig, fetch: Option<&dyn HttpFetch>) -> Result<LocalJwkSet, OidcError> {
    let fetch = fetch.ok_or_else(|| keys_error(&c.uri))?;
    // AbortSignal.timeout refuses a fractional deadline before any request goes out
    if c.timeout_ms.fract() != 0.0 {
        return Err(keys_error(&c.uri));
    }
    let res = fetch.get(&c.uri, Some(c.timeout_ms)).map_err(|_| keys_error(&c.uri))?;
    if !(200..=299).contains(&res.status) || res.body.len() as f64 > c.max_bytes {
        return Err(keys_error(&c.uri));
    }
    let v: Value = serde_json::from_str(&res.body).map_err(|_| keys_error(&c.uri))?;
    LocalJwkSet::new(&v).map_err(|_| keys_error(&c.uri))
}

struct JwksState {
    cache: Option<(f64, LocalJwkSet, HashSet<String>)>,
    last_fetch: f64,
}

type BoxFetch = Box<dyn HttpFetch + Send + Sync>;
type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

/// `createOidcJwks`: keys are cached `cacheMaxAgeSec` (600); a stale set is refetched and, if that fails, verification is
/// refused (code `keys`): a stale set is never served. A `kid` not in the cached set refetches at most once per
/// `cooldownSec` (30). The clock is epoch milliseconds.
pub struct OidcJwks {
    config: JwksConfig,
    fetch: Option<BoxFetch>,
    now: Clock,
    // shortcut: concurrent callers refetch one after another under the lock instead of sharing one in-flight request
    state: Mutex<JwksState>,
}

/// `createOidcJwks(opts)`: `jwksUri` (https unless `requireHttps` is falsy), `cacheMaxAgeSec`, `cooldownSec`, `maxBytes`,
/// `timeoutMs`; `now` defaults to the wall clock (ms).
pub fn create_oidc_jwks(opts: &Value, fetch: Option<BoxFetch>, now: Option<Clock>) -> Result<OidcJwks, OidcError> {
    let config = jwks_config(opts)?;
    let now = now.unwrap_or_else(|| Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)));
    Ok(OidcJwks { config, fetch, now, state: Mutex::new(JwksState { cache: None, last_fetch: f64::NEG_INFINITY }) })
}

/// `createOidcJwksFromIssuer`: discover the `jwks_uri` (with `requireHttps` from `opts`), then [`create_oidc_jwks`].
pub fn create_oidc_jwks_from_issuer(issuer: &Value, opts: &Value, fetch: Option<BoxFetch>, now: Option<Clock>) -> Result<OidcJwks, OidcError> {
    let mut d = Map::new();
    if let Some(r) = get(opts, "requireHttps") {
        d.insert("requireHttps".into(), r.clone());
    }
    let meta = discover_oidc(issuer, &Value::Object(d), fetch.as_deref().map(|f| f as &dyn HttpFetch))?;
    let mut o = opts.as_object().cloned().unwrap_or_default();
    o.insert("jwksUri".into(), meta["jwks_uri"].clone());
    create_oidc_jwks(&Value::Object(o), fetch, now)
}

impl OidcJwks {
    fn refetch(&self, st: &mut JwksState) -> Result<(), OidcError> {
        st.last_fetch = (self.now)();
        let set = fetch_jwk_set(&self.config, self.fetch.as_deref().map(|f| f as &dyn HttpFetch))?;
        let kids = set.kids();
        let at = (self.now)();
        if !at.is_finite() {
            return Err(OidcError::new("keys", "the clock returned a non-finite time"));
        }
        st.cache = Some((at, set, kids));
        Ok(())
    }
}

impl KeyResolver for OidcJwks {
    fn resolve(&self, header: &Map<String, Value>) -> Result<Value, OidcError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let t = (self.now)();
        if !t.is_finite() {
            return Err(OidcError::new("keys", "the clock returned a non-finite time"));
        }
        let stale = st.cache.as_ref().is_none_or(|(at, _, _)| !(t - at < self.config.max_age_ms));
        if stale {
            st.cache = None; // never serve a stale set, even if the refetch below fails
            self.refetch(&mut st)?;
        } else if let Some(kid) = header.get("kid").and_then(Value::as_str) {
            let known = st.cache.as_ref().is_some_and(|(_, _, kids)| kids.contains(kid));
            if !known && !(t - st.last_fetch < self.config.cooldown_ms) {
                self.refetch(&mut st)?;
            }
        }
        match &st.cache {
            Some((_, set, _)) => set.resolve(header),
            None => Err(keys_error(&self.config.uri)),
        }
    }
}

/// The per-call resolver of `verifyIdToken({jwksUri})`: one fetch, no cache outlives the call.
struct OneShot<'a> {
    config: JwksConfig,
    fetch: Option<&'a dyn HttpFetch>,
}

impl KeyResolver for OneShot<'_> {
    fn resolve(&self, header: &Map<String, Value>) -> Result<Value, OidcError> {
        fetch_jwk_set(&self.config, self.fetch)?.resolve(header)
    }
}

// ---- ID-token verification ------------------------------------------------------------------------------------------------

enum Material {
    Jwk(Value),
    Secret(Vec<u8>),
}

/// The JOSE library's key-type gate for verification: HS* takes a secret or an `oct` JWK, everything else a public non-`oct`
/// JWK; a JWK's `use`, `key_ops` and `alg` must allow this use when present.
fn check_key_type(alg: &str, key: &Material) -> Result<(), OidcError> {
    let ops_ok = |k: &Value| -> Result<(), OidcError> {
        if get(k, "use").is_some_and(|u| u != "sig") {
            return Err(inv("Invalid key for this operation, when present its use must be sig"));
        }
        if get(k, "key_ops").is_some_and(|o| !o.as_array().is_some_and(|a| a.iter().any(|x| x == "verify"))) {
            return Err(inv("Invalid key for this operation, when present its key_ops must include verify"));
        }
        if get(k, "alg").is_some_and(|a| a != alg) {
            return Err(inv(format!("Invalid key for this operation, when present its alg must be {alg}")));
        }
        Ok(())
    };
    let kty = |k: &Value| get(k, "kty").and_then(Value::as_str).map(String::from);
    match key {
        Material::Secret(_) if alg.starts_with("HS") => Ok(()),
        Material::Jwk(k) if alg.starts_with("HS") && kty(k).as_deref() == Some("oct") && get(k, "k").is_some_and(Value::is_string) => ops_ok(k),
        _ if alg.starts_with("HS") => Err(inv("Invalid key for a symmetric algorithm")),
        Material::Jwk(k) if kty(k).is_some_and(|t| t != "oct") && get(k, "d").is_none() => ops_ok(k),
        _ => Err(inv("Invalid key for this operation: a public JWK is required")),
    }
}

/// The signature check: a key unfit for the alg is `invalid_token`; unusable key material or a bad signature is `false`.
fn verify_sig(alg: &str, key: &Material, sig: &[u8], data: &[u8]) -> Result<bool, OidcError> {
    if alg.starts_with("HS") {
        if !matches!(alg, "HS256" | "HS384" | "HS512") {
            return Err(inv(format!("alg {alg} is not supported")));
        }
        let secret = match key {
            Material::Secret(b) => b.clone(),
            Material::Jwk(k) => match get(k, "k").and_then(Value::as_str).and_then(|s| decode_b64u_strict(s, None)) {
                Some(b) => b,
                None => return Ok(false),
            },
        };
        return Ok(jose::verify_hmac(alg, &secret, data, sig));
    }
    let Material::Jwk(jwk) = key else { return Err(inv("Invalid key for this operation: a public JWK is required")) };
    let crv = get(jwk, "crv").and_then(Value::as_str);
    let t = match get(jwk, "kty").and_then(Value::as_str) {
        Some("RSA") => "rsa",
        Some("EC") => "ec",
        Some("OKP") if crv == Some("Ed25519") => "ed25519",
        Some("OKP") if crv == Some("Ed448") => "ed448",
        Some("OKP") => return Err(inv("Invalid key for this operation, its crv must be Ed25519 or Ed448")),
        _ => return Err(inv("Invalid key for this operation, its kty must be RSA, OKP, or EC")),
    };
    let ec_crv = match alg {
        "ES256" => Some("P-256"),
        "ES384" => Some("P-384"),
        "ES512" => Some("P-521"),
        _ => None,
    };
    if alg == "EdDSA" {
        if t != "ed25519" && t != "ed448" {
            return Err(inv("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448"));
        }
    } else if matches!(alg, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512") {
        if t != "rsa" {
            return Err(inv("Invalid key for this operation, its asymmetricKeyType must be rsa"));
        }
        let n_len = get(jwk, "n").and_then(Value::as_str).and_then(|n| decode_b64u_strict(n, None)).map_or(0, |b| b.len());
        if n_len * 8 < 2048 {
            return Err(inv(format!("{alg} requires key modulusLength to be 2048 bits or larger")));
        }
    } else if let Some(c) = ec_crv {
        if t != "ec" {
            return Err(inv("Invalid key for this operation, its asymmetricKeyType must be ec"));
        }
        if crv != Some(c) {
            return Err(inv("Invalid key curve for the algorithm"));
        }
    } else {
        return Err(inv(format!("alg {alg} is not supported either by JOSE or your javascript runtime")));
    }
    // shortcut: without the `ed448` feature Ed448 is never verified (fail closed)
    #[cfg(not(feature = "ed448"))]
    if t == "ed448" {
        return Ok(false);
    }
    Ok(match jose::import_public_jwk(jwk, alg) {
        Ok(k) => jose::verify_jws_signature(alg, &k, data, sig),
        Err(_) => false,
    })
}

/// The JOSE library's JWT claims-set checks, in its order, mapped onto the reference's codes.
fn check_claims(payload: &Map<String, Value>, opts: &Value, issuer: &str, audience: &Value) -> Result<(), OidcError> {
    let max_age = get(opts, "maxTokenAgeSec");
    let mut presence = vec![("iss", "issuer"), ("aud", "audience")];
    if max_age.is_some() {
        presence.push(("iat", "issued_at"));
    }
    for (claim, code) in presence {
        if !payload.contains_key(claim) {
            return Err(OidcError::new(code, format!("missing required \"{claim}\" claim")));
        }
    }
    if payload.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(OidcError::new("issuer", "unexpected \"iss\" claim value"));
    }
    if truthy(Some(audience)) {
        let want: Vec<Value> = match audience {
            Value::Array(a) => a.clone(),
            v => vec![v.clone()],
        };
        let ok = match payload.get("aud") {
            Some(a @ Value::String(_)) => want.contains(a),
            Some(Value::Array(l)) => want.iter().any(|w| l.contains(w)),
            _ => false,
        };
        if !ok {
            return Err(OidcError::new("audience", "unexpected \"aud\" claim value"));
        }
    }
    let tol = match get(opts, "clockToleranceSec") {
        None => 0.0,
        Some(v) => v.as_f64().ok_or_else(|| inv("Invalid clockTolerance option type"))?, // shortcut: "5s"-style strings refused
    };
    if !(tol.is_finite() && tol >= 0.0) {
        return Err(inv("verifyIdToken: clockToleranceSec must be a finite number >= 0"));
    }
    let now = jose::now_unix_sec();
    if (payload.contains_key("iat") || truthy(max_age)) && !payload.get("iat").is_some_and(Value::is_number) {
        return Err(OidcError::new("issued_at", "\"iat\" claim must be a number"));
    }
    if let Some(nbf) = payload.get("nbf") {
        let nbf = nbf.as_f64().ok_or_else(|| OidcError::new("not_before", "\"nbf\" claim must be a number"))?;
        if !(nbf <= now + tol) {
            return Err(OidcError::new("not_before", "\"nbf\" claim timestamp check failed"));
        }
    }
    if let Some(exp) = payload.get("exp") {
        let exp = exp.as_f64().ok_or_else(|| OidcError::new("claims", "\"exp\" claim must be a number"))?;
        if !(exp > now - tol) {
            return Err(OidcError::new("expired", "id token has expired"));
        }
    }
    if truthy(max_age) {
        let max = max_age.and_then(Value::as_f64).ok_or_else(|| inv("invalid time period format"))?; // shortcut: "1h" strings refused
        let age = now - payload.get("iat").and_then(Value::as_f64).unwrap_or(f64::NAN);
        if !(age - tol <= max) {
            return Err(OidcError::new("issued_at", "id token is older than the maximum accepted age"));
        }
        if age < -tol {
            return Err(OidcError::new("issued_at", "\"iat\" claim timestamp check failed (it should be in the past)"));
        }
    }
    Ok(())
}

/// OIDC Core 3.1.3.6: base64url(left half of H(value)), H by the token's alg (EdDSA = SHA-512). `value` is hashed as Node's
/// `ascii` encoding writes it: the low byte of each UTF-16 code unit.
fn check_half_hash(name: &str, actual: Option<&str>, value: &Value, alg: &str) -> Result<(), OidcError> {
    let Some(actual) = actual else { return Err(OidcError::new(name, format!("id token is missing the expected {name}"))) };
    let bits = if alg == "EdDSA" { Some("512") } else { ["256", "384", "512"].into_iter().find(|b| alg.ends_with(b)) };
    let Some(bits) = bits else { return Err(OidcError::new(name, format!("cannot compute {name} for alg {alg}"))) };
    let Some(v) = value.as_str() else {
        return Err(OidcError::new("ERR_INVALID_ARG_TYPE", "The \"data\" argument must be of type string or an instance of Buffer, TypedArray, or DataView."));
    };
    let bytes: Vec<u8> = v.encode_utf16().map(|u| u as u8).collect();
    let d = match bits {
        "256" => sha2::Sha256::digest(&bytes).to_vec(),
        "384" => sha2::Sha384::digest(&bytes).to_vec(),
        _ => sha2::Sha512::digest(&bytes).to_vec(),
    };
    if actual != b64_encode(&d[..d.len() / 2]) {
        return Err(OidcError::new(name, format!("id token {name} does not match the supplied value")));
    }
    Ok(())
}

fn project_claims(p: &Map<String, Value>, opts: &Value, audience: &Value) -> Result<Value, OidcError> {
    let iss = non_empty_str(p.get("iss")).ok_or_else(|| OidcError::new("issuer", "id token is missing the \"iss\" claim"))?;
    let sub = non_empty_str(p.get("sub")).ok_or_else(|| OidcError::new("claims", "id token is missing the \"sub\" claim"))?;
    let aud = p.get("aud").ok_or_else(|| OidcError::new("audience", "id token is missing the \"aud\" claim"))?;
    finite(p.get("iat")).ok_or_else(|| OidcError::new("issued_at", "id token is missing a numeric \"iat\" claim"))?;
    finite(p.get("exp")).ok_or_else(|| OidcError::new("expired", "id token is missing a numeric \"exp\" claim"))?;
    let nonce = non_empty_str(p.get("nonce"));
    let azp = non_empty_str(p.get("azp"));
    if let Some(want) = get(opts, "nonce") {
        if nonce.map(|n| json!(n)).as_ref() != Some(want) {
            let m = if nonce.is_none() { "id token is missing the expected nonce" } else { "id token nonce does not match the expected value" };
            return Err(OidcError::new("nonce", m));
        }
    }
    let aud_count = aud.as_array().map_or(1, Vec::len);
    let expected_azp = get(opts, "authorizedParty").filter(|v| !v.is_null()).or(audience.is_string().then_some(audience));
    if aud_count > 1 && azp.is_none() {
        return Err(OidcError::new("azp", "id token has multiple audiences but no azp (authorized party)"));
    }
    if let (Some(a), Some(e)) = (azp, expected_azp) {
        if e.as_str() != Some(a) {
            return Err(OidcError::new("azp", "id token azp does not match the authorized party"));
        }
    }
    let mut out = Map::new();
    out.insert("iss".into(), json!(iss));
    out.insert("sub".into(), json!(sub));
    out.insert("aud".into(), aud.clone());
    out.insert("iat".into(), p["iat"].clone());
    out.insert("exp".into(), p["exp"].clone());
    for k in ["nonce", "azp", "at_hash", "c_hash"] {
        if let Some(v) = non_empty_str(p.get(k)) {
            out.insert(k.into(), json!(v));
        }
    }
    if finite(p.get("auth_time")).is_some() {
        out.insert("auth_time".into(), p["auth_time"].clone());
    }
    if let Some(v) = non_empty_str(p.get("email")) {
        out.insert("email".into(), json!(v));
    }
    if let Some(b) = p.get("email_verified").and_then(Value::as_bool) {
        out.insert("email_verified".into(), json!(b));
    }
    for k in ["name", "preferred_username", "given_name", "family_name", "picture"] {
        if let Some(v) = non_empty_str(p.get(k)) {
            out.insert(k.into(), json!(v));
        }
    }
    if let Some(c @ Value::Object(_)) = p.get("cnf") {
        out.insert("cnf".into(), c.clone());
    }
    Ok(Value::Object(out))
}

/// `verifyIdToken(idToken, opts)`: verify an ID token and return its verified claims.
///
/// `opts` (JSON): `issuer` and `audience` (string or array) required; `nonce`, `authorizedParty`, `accessToken`, `code`,
/// `clockToleranceSec`, `maxTokenAgeSec`, `algorithms` (default [`DEFAULT_ID_TOKEN_ALGS`]), `jwksUri`, `discover`,
/// `requireHttps`. `key` wins over `jwksUri`, which wins over `discover: true`; `fetch` serves discovery and the JWKS GET of
/// the per-call `jwksUri` resolver (build an [`OidcJwks`] once and pass it as the key to cache keys across calls).
pub fn verify_id_token(id_token: &Value, opts: &Value, key: Option<&OidcKey>, fetch: Option<&dyn HttpFetch>) -> Result<Value, OidcError> {
    let Some(token) = non_empty_str(Some(id_token)) else { return Err(inv("verifyIdToken: idToken must be a non-empty string")) };
    if !opts.is_object() && !opts.is_array() {
        return Err(OidcError::new("config", "verifyIdToken: opts is required"));
    }
    let Some(issuer) = non_empty_str(get(opts, "issuer")) else { return Err(OidcError::new("config", "verifyIdToken: opts.issuer is required")) };
    let audience = match get(opts, "audience") {
        Some(a @ (Value::String(_) | Value::Array(_))) => a,
        _ => return Err(OidcError::new("config", "verifyIdToken: opts.audience is required")),
    };
    let jws = jose::assert_canonical_compact_jws(&json!(token), 3, jose::DEFAULT_MAX_JWS_BYTES, true).map_err(inv)?;
    let payload = jws.payload.clone().unwrap_or_default();

    // key wins, then jwksUri, then discover
    let one_shot;
    let resolver: Option<&dyn KeyResolver> = match key {
        Some(OidcKey::Resolver(r)) => Some(*r),
        Some(_) => None,
        None => {
            let mut uri = get(opts, "jwksUri").cloned();
            if uri.is_none() && get(opts, "discover") == Some(&json!(true)) {
                let mut d = Map::new();
                if let Some(r) = get(opts, "requireHttps") {
                    d.insert("requireHttps".into(), r.clone());
                }
                uri = Some(discover_oidc(&json!(issuer), &Value::Object(d), fetch)?["jwks_uri"].clone());
            }
            let Some(uri) = uri else {
                return Err(OidcError::new("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)"));
            };
            let mut c = Map::new();
            c.insert("jwksUri".into(), uri);
            if let Some(r) = get(opts, "requireHttps") {
                c.insert("requireHttps".into(), r.clone());
            }
            let config = jwks_config(&Value::Object(c)).map_err(|e| OidcError::new("config", format!("verifyIdToken: {}", e.message)))?;
            one_shot = OneShot { config, fetch };
            Some(&one_shot)
        }
    };
    let algs = match get(opts, "algorithms").filter(|v| !v.is_null()) {
        None => DEFAULT_ID_TOKEN_ALGS.iter().map(|a| json!(a)).collect(),
        Some(v) => spread(v, "(opts.algorithms ?? DEFAULT_ID_TOKEN_ALGS)").map_err(type_err)?,
    };

    // the JOSE library's jwtVerify, in its order
    let b64 = jose::check_crit_b64(&jws.header).map_err(inv)?;
    let alg = non_empty_str(jws.header.get("alg")).ok_or_else(|| inv("JWS \"alg\" (Algorithm) Header Parameter missing or invalid"))?;
    if !algs.iter().all(Value::is_string) {
        return Err(inv("\"algorithms\" option must be an array of strings"));
    }
    if !algs.iter().any(|a| a == alg) {
        return Err(inv("\"alg\" (Algorithm) Header Parameter value not allowed"));
    }
    let material = match (key, resolver) {
        (_, Some(r)) => Material::Jwk(r.resolve(&jws.header)?),
        (Some(OidcKey::Jwk(v)), None) => Material::Jwk(v.clone()),
        (Some(OidcKey::Secret(b)), None) => Material::Secret(b.clone()),
        _ => return Err(inv("id token verification failed")),
    };
    check_key_type(alg, &material)?;
    if let (Some(_), Material::Jwk(k)) = (resolver, &material) {
        if !alg.starts_with("HS") && !usable_public(k, alg) {
            return Err(inv("invalid JWK"));
        }
    }
    let data = format!("{}.{}", jws.segments[0], jws.segments[1]);
    if !verify_sig(alg, &material, &jws.bytes[2], data.as_bytes())? {
        return Err(OidcError::new("signature", "id token signature verification failed"));
    }
    if !b64 {
        return Err(inv("JWTs MUST NOT use unencoded payload"));
    }
    check_claims(&payload, opts, issuer, audience)?;

    let claims = project_claims(&payload, opts, audience)?;
    if let Some(v) = get(opts, "accessToken") {
        check_half_hash("at_hash", claims.get("at_hash").and_then(Value::as_str), v, alg)?;
    }
    if let Some(v) = get(opts, "code") {
        check_half_hash("c_hash", claims.get("c_hash").and_then(Value::as_str), v, alg)?;
    }
    Ok(claims)
}

// ---- principal --------------------------------------------------------------------------------------------------------------

/// `s` iff it is the canonical unpadded base64url of exactly 32 bytes.
fn canonical_ed25519(v: &Value) -> Option<String> {
    let s = non_empty_str(Some(v))?;
    decode_b64u_strict(s, Some(32)).map(|_| s.to_string())
}

/// `oidcPrincipal(claims, opts)`: `principalId` (`<iss>#<sub>`), the `oidc_subject` caveat, and `principalPublic` when the
/// token's `cnf` binds an OKP Ed25519 key or `opts.principalPublic` supplies one (both present: they must be equal).
pub fn oidc_principal(claims: &Value, opts: Option<&Value>) -> Result<Value, OidcError> {
    if claims.is_null() {
        return Err(type_err("Cannot read properties of null (reading 'iss')"));
    }
    let Some(iss) = non_empty_str(get(claims, "iss")) else { return Err(type_err("oidcPrincipal: claims.iss is required")) };
    let Some(sub) = non_empty_str(get(claims, "sub")) else { return Err(type_err("oidcPrincipal: claims.sub is required")) };
    let from_token = match get(claims, "cnf") {
        None => None,
        Some(Value::Null) => return Err(type_err("Cannot read properties of null (reading 'jwk')")),
        Some(cnf) => get(cnf, "jwk")
            .filter(|j| j.is_object() && get(j, "kty") == Some(&json!("OKP")) && get(j, "crv") == Some(&json!("Ed25519")))
            .and_then(|j| get(j, "x"))
            .and_then(canonical_ed25519),
    };
    let mut principal_public = from_token.clone();
    if let Some(o) = opts {
        if o.is_null() {
            return Err(type_err("Cannot read properties of null (reading 'principalPublic')"));
        }
        if let Some(pp) = get(o, "principalPublic") {
            let provided =
                canonical_ed25519(pp).ok_or_else(|| type_err("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key"))?;
            if from_token.as_ref().is_some_and(|t| *t != provided) {
                return Err(OidcError::new("mismatch", "oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token"));
            }
            principal_public = Some(provided);
        }
    }
    let mut out = Map::new();
    out.insert("iss".into(), json!(iss));
    out.insert("sub".into(), json!(sub));
    out.insert("principalId".into(), json!(format!("{iss}#{sub}")));
    out.insert("subjectCaveat".into(), json!({ "type": OIDC_SUBJECT_CAVEAT, "iss": iss, "sub": sub }));
    out.insert("claims".into(), claims.clone());
    if let Some(p) = principal_public {
        out.insert("principalPublic".into(), json!(p));
    }
    for (src, dst) in
        [("email", "email"), ("email_verified", "emailVerified"), ("name", "name"), ("preferred_username", "preferredUsername"), ("auth_time", "authTime")]
    {
        if let Some(v) = get(claims, src) {
            out.insert(dst.into(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// `isOidcSubjectCaveat(cv)`.
pub fn is_oidc_subject_caveat(cv: &Value) -> bool {
    get(cv, "type") == Some(&json!(OIDC_SUBJECT_CAVEAT)) && non_empty_str(get(cv, "iss")).is_some() && non_empty_str(get(cv, "sub")).is_some()
}
