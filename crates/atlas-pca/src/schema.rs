//! JSON Schema (draft 2020-12) documents for the PCA wire types (PCActn, Capability, the discovery document) and a small
//! dependency-free STRUCTURAL validator, mirroring the reference's `@atlasauth/pca-schema`.
//!
//! The schemas describe structure only (fields, JSON types, required); they cannot express security invariants (signature,
//! attenuation, plan membership, iat < exp). Passing means "well-formed", never "authorized". Every object is open
//! (`additionalProperties` true) so an unknown future field never fails structural validation.
//!
//! The validator implements only the keywords these schemas use: `type` (incl. unions), `enum`, `required`, `properties`,
//! `additionalProperties:false`, `items`, and local `#/...` `$ref`. No pattern / format / oneOf / anyOf / bounds (`minItems` is
//! published for external validators but, as in the reference, not enforced here).
use crate::missing_context::js_keys;
use serde_json::{json, Map, Value};

pub const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

fn alg() -> Value {
    json!({ "type": "string", "enum": ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"] })
}

fn capability_def() -> Value {
    let s = json!({ "type": "string" });
    json!({
        "type": "object",
        "required": ["id", "issuer", "holder", "caveats", "body_digest", "sig"],
        "properties": { "id": s, "issuer": s, "holder": s, "caveats": { "type": "array", "items": { "$ref": "#/$defs/caveat" } },
            "parent": s, "body_digest": s, "sig": s, "alg": alg(), "pq_pk": s, "pq_sig": s },
        "additionalProperties": true,
    })
}

fn caveat_def() -> Value {
    json!({ "type": "object", "required": ["type"], "properties": { "type": { "type": "string" } }, "additionalProperties": true })
}

/// The PCActn wire schema.
pub fn pcactn_schema() -> Value {
    let s = json!({ "type": "string" });
    json!({
        "$schema": DRAFT,
        "$id": "https://atlasauth.net/schemas/pca/pcactn.schema.json",
        "title": "PCActn",
        "description": "Proof-Carrying Authority action object (spec §7, wire format v2).",
        "type": "object",
        "required": ["ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig"],
        "properties": {
            "ver": { "type": "integer" },
            "action": { "$ref": "#/$defs/action" },
            "grant_ref": s,
            "cap_chain": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/capability" } },
            "plan": { "$ref": "#/$defs/plan" },
            "attestation": { "$ref": "#/$defs/attestation" },
            "provenance": { "$ref": "#/$defs/provenance" },
            "freshness": { "$ref": "#/$defs/freshness" },
            "counter": { "type": "integer" },
            "risk_claim": { "$ref": "#/$defs/riskClaim" },
            "aud": s,
            "iat": { "type": "integer" },
            "exp": { "type": "integer" },
            "nonce": s,
            "caution": { "type": "number" },
            "rationale_commitment": s,
            "progress_step": { "type": "object", "additionalProperties": true },
            "prohibition_evidence": { "type": ["object", "array"] },
            "tool_binding": s,
            "alg": alg(),
            "pq_pk": s,
            "sig": s,
            "pq_sig": s,
            "threshold": { "type": "object", "additionalProperties": true },
            "zk_compliance": { "description": "Opaque zk-compliance proof; shape is verifier-defined." },
            "bond_ref": s,
        },
        "additionalProperties": true,
        "$defs": {
            "caveat": caveat_def(),
            "capability": capability_def(),
            "action": { "type": "object", "required": ["verb", "resource", "params_digest", "reversibility_class"],
                "properties": { "verb": s, "resource": s, "params_digest": s, "reversibility_class": s }, "additionalProperties": true },
            "inclusionProof": { "type": "object", "required": ["index", "size", "path"],
                "properties": { "index": { "type": "integer" }, "size": { "type": "integer" },
                    "path": { "type": "array", "items": { "type": "object", "additionalProperties": true } } }, "additionalProperties": true },
            "plan": { "type": "object", "required": ["root", "inclusion_proof", "node_id"],
                "properties": { "root": s, "inclusion_proof": { "$ref": "#/$defs/inclusionProof" }, "node_id": s, "conditions_digest": s }, "additionalProperties": true },
            "riskClaim": { "type": "object", "required": ["r", "inputs"],
                "properties": { "r": { "type": "number" }, "inputs": { "type": "object", "additionalProperties": true } }, "additionalProperties": true },
            "attestation": { "type": "object", "required": ["quote_digest", "epoch", "model_id", "measurement", "operator"],
                "properties": { "quote_digest": s, "epoch": { "type": "integer" }, "model_id": s, "measurement": s, "operator": s }, "additionalProperties": true },
            "provenance": { "type": "object", "required": ["causal_hash", "taint_level", "trusted_refs"],
                "properties": { "causal_hash": s, "taint_level": { "type": "number" }, "trusted_refs": { "type": "array", "items": s } }, "additionalProperties": true },
            "freshness": { "type": "object", "required": ["beacon_ref", "epoch", "accumulator_witness"],
                "properties": { "beacon_ref": s, "epoch": { "type": "integer" }, "accumulator_witness": s }, "additionalProperties": true },
        },
    })
}

/// The Capability (chain hop) wire schema.
pub fn capability_schema() -> Value {
    let mut m = Map::new();
    m.insert("$schema".into(), json!(DRAFT));
    m.insert("$id".into(), json!("https://atlasauth.net/schemas/pca/capability.schema.json"));
    m.insert("title".into(), json!("Capability"));
    m.insert("description".into(), json!("An attenuable capability chain hop (spec §5.2)."));
    if let Value::Object(d) = capability_def() {
        m.extend(d);
    }
    m.insert("$defs".into(), json!({ "caveat": caveat_def() }));
    Value::Object(m)
}

/// The `.well-known/pca-configuration` discovery document schema.
pub fn discovery_schema() -> Value {
    let s = json!({ "type": "string" });
    json!({
        "$schema": DRAFT,
        "$id": "https://atlasauth.net/schemas/pca/discovery.schema.json",
        "title": "PcaDiscoveryDocument",
        "description": "The .well-known/pca-configuration discovery document (internet-wide integration).",
        "type": "object",
        "required": ["audience", "pca_versions", "signature_suites", "action_header"],
        "properties": {
            "audience": s,
            "pca_versions": { "type": "array", "items": { "type": "integer" } },
            "signature_suites": { "type": "array", "items": s },
            "action_header": s,
            "required_checks": { "type": "array", "items": s },
            "endpoints": { "$ref": "#/$defs/endpoints" },
            "trusted_roots": { "type": "array", "items": s },
            "metadata": { "type": "object", "additionalProperties": true },
        },
        "additionalProperties": true,
        "$defs": { "endpoints": { "type": "object",
            "properties": { "attestation_challenge": s, "revocation_epoch": s, "liveness_beacon": s, "stepup": s, "grant": s }, "additionalProperties": true } },
    })
}

/// All published schemas by name.
pub fn all_schemas() -> Value {
    json!({ "PCActn": pcactn_schema(), "Capability": capability_schema(), "PcaDiscoveryDocument": discovery_schema() })
}

/// A published schema by name (`PCActn`, `Capability`, `PcaDiscoveryDocument`).
pub fn named_schema(name: &str) -> Option<Value> {
    match name {
        "PCActn" => Some(pcactn_schema()),
        "Capability" => Some(capability_schema()),
        "PcaDiscoveryDocument" => Some(discovery_schema()),
        _ => None,
    }
}

fn js(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        v => crate::intent_v2::js_value_string(v),
    }
}

fn is_integer(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0 && f.is_finite()),
        _ => false,
    }
}

/// The JSON type name of a value (`integer` for an integral number).
pub fn json_type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Array(_) => "array",
        Value::Bool(_) => "boolean",
        Value::Number(_) if is_integer(v) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Object(_) => "object",
    }
}

fn matches_type(expected: &Value, v: &Value) -> bool {
    match expected.as_str() {
        Some("object") => v.is_object(),
        Some("array") => v.is_array(),
        Some("string") => v.is_string(),
        Some("number") => v.as_f64().is_some_and(f64::is_finite),
        // the validator rejects -0 for `integer` (Object.is), though the type NAME it reports for -0 is still "integer"
        Some("integer") => is_integer(v) && !v.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative()),
        Some("boolean") => v.is_boolean(),
        Some("null") => v.is_null(),
        _ => false,
    }
}

fn resolve_ref<'a>(root: &'a Value, r: &str) -> Option<&'a Value> {
    let mut cur = root;
    for token in r.strip_prefix("#/")?.split('/') {
        cur = cur.as_object()?.get(token)?;
    }
    cur.is_object().then_some(cur)
}

fn label(path: &str) -> &str {
    if path.is_empty() {
        "(root)"
    } else {
        path
    }
}

/// JS `===` over decoded JSON: objects and arrays never match.
fn strict_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::String(x), Value::String(y)) => x == y,
        _ => false,
    }
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false)) && v.as_f64() != Some(0.0) && v.as_str() != Some("")
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn check_node(schema: &Value, value: &Value, path: &str, root: &Value, errors: &mut Vec<String>) -> Result<(), String> {
    if schema.is_null() {
        return Err("Cannot read properties of null (reading '$ref')".into());
    }
    let Some(s) = schema.as_object() else { return Ok(()) };
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        return match resolve_ref(root, r) {
            Some(resolved) => check_node(resolved, value, path, root, errors),
            None => {
                errors.push(format!("{}: unresolved $ref '{r}'", label(path)));
                Ok(())
            }
        };
    }
    if let Some(t) = s.get("type") {
        let types: Vec<&Value> = match t {
            Value::Array(a) => a.iter().collect(),
            x => vec![x],
        };
        if !types.iter().any(|x| matches_type(x, value)) {
            let names: Vec<String> = types.iter().map(|x| js(x)).collect();
            errors.push(format!("{}: expected type {}, got {}", label(path), names.join("|"), json_type_of(value)));
            return Ok(());
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.iter().any(|x| strict_equal(x, value)) {
            let items: Vec<String> = e.iter().map(crate::js_stringify).collect();
            errors.push(format!("{}: value is not one of [{}]", label(path), items.join(", ")));
        }
    }
    if let Some(o) = value.as_object() {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for k in req {
                let key = js(k);
                if !o.contains_key(&key) {
                    errors.push(format!("{}: missing required property '{key}'", join(path, &key)));
                }
            }
        }
        let props = s.get("properties").filter(|p| truthy(p)).and_then(Value::as_object);
        if let Some(props) = props {
            for k in js_keys(props) {
                if let Some(v) = o.get(&k) {
                    check_node(&props[&k], v, &join(path, &k), root, errors)?;
                }
            }
            if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                for k in js_keys(o) {
                    if !props.contains_key(&k) {
                        errors.push(format!("{}: additional property not allowed", join(path, &k)));
                    }
                }
            }
        }
    }
    if let (Some(a), Some(items)) = (value.as_array(), s.get("items").filter(|i| truthy(i))) {
        for (i, el) in a.iter().enumerate() {
            check_node(items, el, &format!("{path}[{i}]"), root, errors)?;
        }
    }
    Ok(())
}

/// Structural validation: `{"valid": bool, "errors": [str]}` (errors empty when valid). A null schema is refused.
pub fn validate(schema: &Value, value: &Value) -> Result<Value, String> {
    let mut errors = Vec::new();
    check_node(schema, value, "", schema, &mut errors)?;
    Ok(json!({ "valid": errors.is_empty(), "errors": errors }))
}
