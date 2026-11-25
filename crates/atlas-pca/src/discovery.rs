//! Resource-server discovery, `.well-known/pca-configuration` (`discovery.ts`): the document a server publishes (audience, accepted
//! suites, the action header, freshness and step-up endpoints, the intent block) and the pure build, parse and fetch of it. The document
//! is PUBLIC configuration; never put secrets in it. [`fetch_discovery`] takes the transport as an injected closure (no default client).
use crate::oauth::WELL_KNOWN_PCA_PATH;
use serde_json::{json, Map, Value};

fn err<T>(m: &str) -> Result<T, String> {
    Err(format!("parseDiscoveryDocument: {m}"))
}

/// Validate an `intent` discovery block. Anything malformed is an `Err` (fail closed).
pub fn parse_discovery_intent(v: &Value) -> Result<Value, String> {
    let Some(o) = v.as_object() else { return err("intent must be an object") };
    for k in o.keys() {
        if !["versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri"].contains(&k.as_str()) {
            return err(&format!("intent has unknown member '{k}'"));
        }
    }
    let versions = o.get("versions").and_then(Value::as_array).filter(|a| !a.is_empty() && a.iter().all(|n| n == &json!(1) || n == &json!(2)));
    let Some(versions) = versions else { return err("intent.versions must list 1 and/or 2") };
    let mut out = Map::new();
    out.insert("versions".into(), Value::Array(versions.clone()));
    for k in ["actions_uri", "evidence_uri"] {
        if let Some(x) = o.get(k) {
            if !x.as_str().is_some_and(|s| !s.is_empty()) {
                return err(&format!("intent.{k} must be a non-empty string"));
            }
            out.insert(k.into(), x.clone());
        }
    }
    if let Some(sk) = o.get("schema_keys") {
        let Some(list) = sk.as_array() else { return err("intent.schema_keys must be an array") };
        let mut keys = Vec::new();
        for x in list {
            let ok = x
                .as_object()
                .is_some_and(|e| ["kid", "alg", "pk"].iter().all(|k| e.get(*k).is_some_and(Value::is_string)) && e.get("pq_pk").is_none_or(Value::is_string));
            if !ok {
                return err("intent.schema_keys entries are {kid, alg, pk, pq_pk?}");
            }
            let mut e = Map::new();
            for k in ["kid", "alg", "pk", "pq_pk"] {
                if let Some(v) = x.get(k) {
                    e.insert(k.into(), v.clone());
                }
            }
            keys.push(Value::Object(e));
        }
        out.insert("schema_keys".into(), Value::Array(keys));
    }
    if let Some(q) = o.get("question_relay") {
        if !q.is_boolean() {
            return err("intent.question_relay must be a boolean");
        }
        out.insert("question_relay".into(), q.clone());
    }
    if let Some(t) = o.get("tiers") {
        let Some(m) = t.as_object() else { return err("intent.tiers must be an object") };
        if !m.values().all(|n| crate::safe_int(n).is_some_and(|n| (0..=4).contains(&n))) {
            return err("intent.tiers values must be integers 0..4");
        }
        out.insert("tiers".into(), t.clone());
    }
    Ok(Value::Object(out))
}

/// Everything [`build_discovery_document`] takes besides the audience; `None` members take the reference defaults.
#[derive(Default)]
pub struct BuildDiscoveryOptions {
    pub signature_suites: Option<Vec<String>>,
    pub pca_versions: Option<Vec<i64>>,
    pub action_header: Option<String>,
    pub required_checks: Option<Vec<String>>,
    pub endpoints: Option<Value>,
    pub trusted_roots: Option<Vec<String>>,
    pub metadata: Option<Value>,
    pub intent: Option<Value>,
    pub obligations_supported: Option<Vec<String>>,
}

/// Build a well-formed discovery document. `Err` on an empty audience or a malformed intent block.
pub fn build_discovery_document(audience: &str, o: &BuildDiscoveryOptions) -> Result<Value, String> {
    if audience.is_empty() {
        return Err("buildDiscoveryDocument: audience is required".into());
    }
    let default_suites = || vec!["ed25519".to_string(), "ml-dsa-65".to_string(), "hybrid-ed25519-ml-dsa-65".to_string()];
    let default_required =
        || ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"].map(String::from).to_vec();
    let mut d = Map::new();
    d.insert("audience".into(), json!(audience));
    d.insert("pca_versions".into(), json!(o.pca_versions.clone().unwrap_or_else(|| vec![2])));
    d.insert("signature_suites".into(), json!(o.signature_suites.clone().unwrap_or_else(default_suites)));
    d.insert("action_header".into(), json!(o.action_header.clone().unwrap_or_else(|| "PCA-Action".into())));
    d.insert("required_checks".into(), json!(o.required_checks.clone().unwrap_or_else(default_required)));
    if let Some(e) = &o.endpoints {
        d.insert("endpoints".into(), e.clone());
    }
    if let Some(t) = &o.trusted_roots {
        d.insert("trusted_roots".into(), json!(t));
    }
    if let Some(m) = &o.metadata {
        d.insert("metadata".into(), m.clone());
    }
    if let Some(i) = &o.intent {
        d.insert("intent".into(), parse_discovery_intent(i)?);
    }
    if let Some(s) = &o.obligations_supported {
        d.insert("obligations_supported".into(), json!(s));
    }
    Ok(Value::Object(d))
}

fn strings(v: &Value) -> Option<&Vec<Value>> {
    v.as_array().filter(|a| a.iter().all(Value::is_string))
}

/// Validate and narrow an untrusted value into a discovery document. Anything malformed is an `Err`.
pub fn parse_discovery_document(value: &Value) -> Result<Value, String> {
    let Some(v) = value.as_object() else { return err("not an object") };
    let Some(audience) = v.get("audience").filter(|a| a.as_str().is_some_and(|s| !s.is_empty())) else { return err("missing audience") };
    let Some(versions) = v.get("pca_versions").and_then(Value::as_array).filter(|a| a.iter().all(Value::is_number)) else {
        return err("pca_versions must be a number[]");
    };
    let Some(suites) = v.get("signature_suites").and_then(strings) else { return err("signature_suites must be a string[]") };
    let Some(header) = v.get("action_header").filter(|a| a.as_str().is_some_and(|s| !s.is_empty())) else { return err("missing action_header") };
    let mut doc = Map::new();
    doc.insert("audience".into(), audience.clone());
    doc.insert("pca_versions".into(), Value::Array(versions.clone()));
    doc.insert("signature_suites".into(), Value::Array(suites.clone()));
    doc.insert("action_header".into(), header.clone());
    if let Some(r) = v.get("required_checks").and_then(strings) {
        doc.insert("required_checks".into(), Value::Array(r.clone()));
    }
    if let Some(e) = v.get("endpoints").filter(|e| e.is_object() || e.is_array()) {
        doc.insert("endpoints".into(), e.clone());
    }
    if let Some(t) = v.get("trusted_roots").and_then(strings) {
        doc.insert("trusted_roots".into(), Value::Array(t.clone()));
    }
    if let Some(m) = v.get("metadata").filter(|m| m.is_object() || m.is_array()) {
        doc.insert("metadata".into(), m.clone());
    }
    if let Some(i) = v.get("intent") {
        doc.insert("intent".into(), parse_discovery_intent(i)?);
    }
    if let Some(o) = v.get("obligations_supported") {
        let Some(list) = strings(o) else { return err("obligations_supported must be a string[]") };
        doc.insert("obligations_supported".into(), Value::Array(list.clone()));
    }
    Ok(Value::Object(doc))
}

/// A GET transport: `(url, accept header) -> (status, parsed JSON body)`. `Err` is a transport failure.
pub type JsonGet = dyn Fn(&str, &str) -> Result<(u16, Value), String>;

/// Fetch and parse a resource server's discovery document. `base_url` is the server origin; the well-known path is appended.
/// `Err` on a transport failure, a non-2xx response or a malformed document.
pub fn fetch_discovery(base_url: &str, get: &dyn Fn(&str, &str) -> Result<(u16, Value), String>) -> Result<Value, String> {
    let url = format!("{}{WELL_KNOWN_PCA_PATH}", base_url.trim_end_matches('/'));
    let (status, body) = get(&url, "application/json")?;
    if !(200..300).contains(&status) {
        return Err(format!("fetchDiscovery: {url} returned {status}"));
    }
    parse_discovery_document(&body)
}

/// `true` iff this server (per its discovery doc) accepts a given signature suite.
pub fn accepts_suite(doc: &Value, suite: &str) -> bool {
    doc.get("signature_suites").and_then(Value::as_array).is_some_and(|a| a.iter().any(|s| s.as_str() == Some(suite)))
}
