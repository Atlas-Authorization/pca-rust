//! Signed action schemas and closed-world conformance (Intent Layer v2 rule 14). Mirrors
//! `packages/pca/src/action-schema.ts` (`actionSchemaShapeError`, `verifyActionSchema`, `actionSchemaDigest`,
//! `conformAction`, `paramValueViolation`, `accumulationParams`) exactly; the `schema14-*` primitives and the `schema-*`
//! vectors pin it.

use serde_json::{Map, Value};

use super::{canonicalize_strict, decode_b64u_strict};
use super::intent_strict::*;
use super::intent_suite::{suite_of, verify_pinned_suite};

pub(crate) const ACTION_SCHEMA_DOMAIN: &str = "atlas-pca/action-schema/v1\0";
pub(crate) const ACTION_SCHEMA_REF_DOMAIN: &str = "atlas-pca/action-schema-ref/v1";
const KIND: &str = "pca-action-schema";
const SENSITIVITIES: [&str; 3] = ["free", "material", "critical"];
const REVERSIBILITY: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const PARAM_TYPES: [&str; 6] = ["string", "integer", "boolean", "date", "set", "array"];
const PARAM_TYPES_V2: [&str; 9] = ["string", "integer", "boolean", "date", "set", "array", "datetime", "duration", "object_ref"];
const V2_EFFECTS: [&str; 12] = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
const V2_CAVEATS: [&str; 8] = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"];
const V2_PRULES: [&str; 8] = [
    "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared",
    "secret_not_logged",
];
const V2_CONTEXT: [&str; 6] = ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"];
const V2_TAGS: [&str; 9] = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"];
const V2_PROVENANCE: [&str; 3] = ["first_party", "tool", "agent"];
const DOC_KEYS_V2: [&str; 12] = ["v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig", "traits_digest", "trait_defs", "pack"];
const VERB_KEYS_V2: [&str; 16] = [
    "verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description", "traits", "def", "floors",
    "confirmation",
];
const PARAM_KEYS_V2: [&str; 21] = [
    "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items", "max_items", "default",
    "principal_neutral_default", "accumulates_into", "issued_by_site", "description", "role", "format", "tags", "provenance_min",
];
const MAX_VERBS: usize = 256;
const MAX_PARAMS: usize = 64;
const MAX_VALUES: usize = 256;
const DEFAULT_MAX_LEN: f64 = 1024.0;
const DEFAULT_MAX_ITEMS: f64 = 64.0;
const DOC_KEYS: [&str; 9] = ["v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig"];
const VERB_KEYS: [&str; 12] =
    ["verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description"];
const PARAM_KEYS: [&str; 17] = [
    "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items", "max_items", "default",
    "principal_neutral_default", "accumulates_into", "issued_by_site", "description",
];
const SIG_KEYS: [&str; 4] = ["alg", "kid", "value", "pq_value"];

/// `isStr(v, max)` of action-schema.ts: a non-empty string of at most `max` UTF-8 bytes.
fn is_str(v: Option<&Value>, max: usize) -> bool {
    bstr(v, max)
}

fn is_one_of(v: Option<&Value>, set: &[&str]) -> bool {
    matches!(v, Some(Value::String(x)) if set.contains(&x.as_str()))
}

/// `^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$`
fn is_param_path_v2(x: &str) -> bool {
    x.strip_prefix("action.params.").is_some_and(|n| n.split('.').count() <= 3 && n.split('.').all(is_ident))
}

fn param_decl_error(path: &str, d: &Value, units: Option<&Value>, v2: bool) -> Option<String> {
    if !(if v2 { is_param_path_v2(path) } else { is_top_param_path(path) }) {
        return Some(format!("parameter path '{path}' is not action.params.<name>"));
    }
    if path.strip_prefix("action.params.").unwrap_or("").split('.').any(|g| RESERVED_NAMES.contains(&g)) {
        return Some(format!("parameter name '{path}' is reserved (__proto__ / constructor / prototype)"));
    }
    let d = match d.as_object() {
        Some(d) => d,
        None => return Some(format!("{path}: declaration must be an object")),
    };
    if let Some(k) = d.keys().find(|k| !(if v2 { PARAM_KEYS_V2.as_slice() } else { PARAM_KEYS.as_slice() }).contains(&k.as_str())) {
        return Some(format!("{path}: unknown member '{k}'"));
    }
    let ty = s(d.get("type"));
    if !is_one_of(d.get("type"), if v2 { &PARAM_TYPES_V2 } else { &PARAM_TYPES }) {
        return Some(format!("{path}: unknown type"));
    }
    if !is_str(d.get("semantic"), 128) {
        return Some(format!("{path}: semantic must be a non-empty string"));
    }
    if !is_one_of(d.get("sensitivity"), &SENSITIVITIES) {
        return Some(format!("{path}: unknown sensitivity"));
    }
    if d.get("required").is_some_and(|r| !r.is_boolean()) {
        return Some(format!("{path}: required must be a boolean"));
    }
    if let Some(vs) = d.get("values") {
        let ok = vs.as_array().is_some_and(|a| !a.is_empty() && a.len() <= MAX_VALUES && a.iter().all(|x| is_str(Some(x), 256)));
        if !ok {
            return Some(format!("{path}: values must be 1..{MAX_VALUES} strings"));
        }
        let a = vs.as_array().map(Vec::as_slice).unwrap_or(&[]);
        let distinct: std::collections::BTreeSet<&str> = a.iter().filter_map(Value::as_str).collect();
        if distinct.len() != a.len() {
            return Some(format!("{path}: values must be distinct"));
        }
        if ty != Some("string") && ty != Some("set") {
            return Some(format!("{path}: values apply to string and set only"));
        }
    }
    if ty == Some("set") && d.get("values").is_none() {
        return Some(format!("{path}: a set needs values"));
    }
    let int_like = ty == Some("integer") || (v2 && ty == Some("duration")) || (ty == Some("array") && s(d.get("items")) == Some("integer"));
    for k in ["min", "max"] {
        if d.get(k).is_some() && (sint(d.get(k)).is_none() || !int_like) {
            return Some(format!("{path}: {k} must be a safe integer on an integer parameter"));
        }
    }
    if let (Some(lo), Some(hi)) = (sint(d.get("min")), sint(d.get("max"))) {
        if lo > hi {
            return Some(format!("{path}: min > max"));
        }
    }
    if let Some(u) = d.get("unit") {
        let declared = match (u.as_str(), units.and_then(Value::as_object)) {
            (Some(u), Some(us)) => us.contains_key(u),
            _ => false,
        };
        if ty != Some("integer") || !declared {
            return Some(format!("{path}: unit must name a declared unit of an integer parameter"));
        }
    }
    if d.get("max_len").is_some() && !sint(d.get("max_len")).is_some_and(|m| m >= 1) {
        return Some(format!("{path}: max_len must be a positive safe integer"));
    }
    if d.get("items").is_some() && (ty != Some("array") || !is_str(d.get("items"), 64)) {
        return Some(format!("{path}: items applies to array only"));
    }
    for k in ["min_items", "max_items"] {
        if d.get(k).is_some() && (nonneg(d.get(k)).is_none() || (ty != Some("set") && ty != Some("array"))) {
            return Some(format!("{path}: {k} must be a non-negative safe integer on a set or array"));
        }
    }
    if let (Some(lo), Some(hi)) = (sint(d.get("min_items")), sint(d.get("max_items"))) {
        if lo > hi {
            return Some(format!("{path}: min_items > max_items"));
        }
    }
    if d.get("default") == Some(&Value::Null) {
        return Some(format!("{path}: default must not be null (absent = no default)"));
    }
    if d.get("principal_neutral_default").is_some_and(|x| !x.is_boolean()) {
        return Some(format!("{path}: principal_neutral_default must be a boolean"));
    }
    if d.get("principal_neutral_default") == Some(&Value::Bool(true)) && d.get("default").is_none() {
        return Some(format!("{path}: principal_neutral_default needs a default"));
    }
    if let Some(ai) = d.get("accumulates_into") {
        if ty != Some("integer") {
            return Some(format!("{path}: accumulates_into applies to integer parameters only"));
        }
        let a = match ai.as_array() {
            Some(a) if !a.is_empty() && a.len() <= 8 => a,
            _ => return Some(format!("{path}: accumulates_into must be 1..8 unit ids")),
        };
        if !a.iter().all(|u| u.as_str().is_some_and(|u| u.len() <= 64 && is_unit_id(u))) {
            return Some(format!("{path}: accumulates_into entries must be unit ids"));
        }
        let distinct: std::collections::BTreeSet<&str> = a.iter().filter_map(Value::as_str).collect();
        if distinct.len() != a.len() {
            return Some(format!("{path}: accumulates_into must be distinct"));
        }
    }
    if d.get("issued_by_site").is_some_and(|x| !x.is_boolean()) {
        return Some(format!("{path}: issued_by_site must be a boolean"));
    }
    if d.get("description").is_some() && !is_str(d.get("description"), 1024) {
        return Some(format!("{path}: description must be a string"));
    }
    if v2 {
        if d.get("role").is_some() && !is_str(d.get("role"), 128) {
            return Some(format!("{path}: role must be a non-empty string"));
        }
        if let Some(f) = d.get("format") {
            if !f.as_str().is_some_and(|f| format_check(f, "").is_some()) || (ty != Some("string") && ty != Some("object_ref")) {
                return Some(format!("{path}: format must be a known format on a string parameter"));
            }
        }
        if let Some(tg) = d.get("tags") {
            let ok = tg.as_array().is_some_and(|a| {
                a.len() <= V2_TAGS.len() && a.iter().filter_map(Value::as_str).collect::<std::collections::BTreeSet<_>>().len() == a.len() && a.iter().all(|t| is_one_of(Some(t), &V2_TAGS))
            });
            if !ok {
                return Some(format!("{path}: tags must be distinct known tags"));
            }
        }
        if d.get("provenance_min").is_some() && !is_one_of(d.get("provenance_min"), &V2_PROVENANCE) {
            return Some(format!("{path}: unknown provenance_min"));
        }
    }
    None
}

/// `schemaFloorsError(f)`: a well-formed materialized profile (shape only; the semantic check is rule 22).
pub(crate) fn schema_floors_error(f: Option<&Value>) -> Option<String> {
    let f = match f.and_then(Value::as_object) {
        Some(f) => f,
        None => return Some("floors must be an object".into()),
    };
    if let Some(k) = f.keys().find(|k| !["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"].contains(&k.as_str())) {
        return Some(format!("floors: unknown member '{k}'"));
    }
    let rng = |k: &str, lo: i64, hi: i64| sint(f.get(k)).is_some_and(|x| (lo..=hi).contains(&x));
    if !rng("risk", 0, 3) || !rng("esc", 0, 3) {
        return Some("floors.risk and floors.esc must be integers in 0..3".into());
    }
    if !is_one_of(f.get("rev"), &REVERSIBILITY) {
        return Some("floors.rev is not a reversibility class".into());
    }
    if !rng("blast_ppm", 0, 1_000_000) {
        return Some("floors.blast_ppm must be an integer in 0..1000000".into());
    }
    for name in ["caveats", "context", "prules"] {
        let ok = |x: &str| match name {
            "caveats" => V2_CAVEATS.contains(&x),
            "context" => V2_CONTEXT.contains(&x) || x.strip_prefix("session_taint_max:").is_some_and(|t| (1..=16).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')),
            _ => V2_PRULES.contains(&x),
        };
        let a = match f.get(name).and_then(Value::as_array) {
            Some(a) if a.len() <= 64 && a.iter().all(|x| x.as_str().is_some_and(ok)) => a,
            _ => return Some(format!("floors.{name} must be an array of known entries")),
        };
        if a.windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
            return Some(format!("floors.{name} must be sorted and distinct"));
        }
    }
    None
}

/// `^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$`
fn is_trait_id_shape(x: &str) -> bool {
    let ok = |g: &str, max: usize| !g.is_empty() && g.len() <= max && g.as_bytes()[0].is_ascii_lowercase() && g.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    x.split_once('.').is_some_and(|(a, b)| ok(a, 32) && ok(b, 64))
}

/// `confirmationShapeError(c)`: a well-formed `confirmation` (shape only; the signature check is rule 22).
fn confirmation_shape_error(c: &Value) -> Option<String> {
    let c = match c.as_object() {
        Some(c) => c,
        None => return Some("confirmation must be an object".into()),
    };
    if let Some(k) = c.keys().find(|k| !["def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"].contains(&k.as_str())) {
        return Some(format!("confirmation: unknown member '{k}'"));
    }
    if !b32(c.get("def_digest")) || !b32(c.get("traits_digest")) || !b32(c.get("facts_digest")) {
        return Some("confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests".into());
    }
    if !matches!(c.get("sig"), Some(Value::String(x)) if decode_b64u_strict(x, Some(64)).is_some()) {
        return Some("confirmation: sig must be a canonical base64url 64-byte signature".into());
    }
    let ft = c.get("final_traits").and_then(Value::as_array);
    if !ft.is_some_and(|t| t.len() <= 64 && t.iter().all(|x| x.as_str().is_some_and(is_trait_id_shape))) {
        return Some("confirmation: final_traits must be trait ids".into());
    }
    if ft.unwrap().windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
        return Some("confirmation: final_traits must be sorted and distinct".into());
    }
    let dm = match c.get("dismissed").and_then(Value::as_array) {
        Some(d) if d.len() <= 64 => d,
        _ => return Some("confirmation: dismissed must be an array".into()),
    };
    for d in dm {
        let ok = d.as_object().is_some_and(|d| d.len() == 2 && s(d.get("trait")).is_some_and(is_trait_id_shape) && is_str(d.get("reason"), 256));
        if !ok {
            return Some("confirmation: dismissed entries must be {trait, reason}".into());
        }
    }
    if !is_str(c.get("reviewer_kid"), 128) {
        return Some("confirmation: reviewer_kid must be a non-empty string".into());
    }
    if nonneg(c.get("ts")).is_none() {
        return Some("confirmation: ts must be a non-negative safe integer".into());
    }
    None
}

fn verb_decl_error(v: &Value, units: Option<&Value>, v2: bool) -> Option<String> {
    let v = match v.as_object() {
        Some(v) => v,
        None => return Some("verb entry must be an object".into()),
    };
    if let Some(k) = v.keys().find(|k| !(if v2 { VERB_KEYS_V2.as_slice() } else { VERB_KEYS.as_slice() }).contains(&k.as_str())) {
        return Some(format!("verb entry: unknown member '{k}'"));
    }
    if !is_str(v.get("verb"), 128) {
        return Some("verb entry: verb must be a non-empty string".into());
    }
    let at = format!("verb '{}'", s(v.get("verb")).unwrap_or(""));
    if !is_one_of(v.get("kind"), &["read", "write"]) {
        return Some(format!("{at}: kind must be read or write"));
    }
    let params = match obj(v.get("params")) {
        Some(p) => p,
        None => return Some(format!("{at}: params must be an object")),
    };
    if params.len() > MAX_PARAMS {
        return Some(format!("{at}: more than {MAX_PARAMS} parameters"));
    }
    for (p, d) in params {
        if let Some(e) = param_decl_error(p, d, units, v2) {
            return Some(format!("{at}: {e}"));
        }
    }
    if v2 {
        for p in params.keys() {
            if let Some(q) = params.keys().find(|q| *q != p && q.starts_with(&format!("{p}."))) {
                return Some(format!("{at}: parameter '{p}' is both a value and the parent of '{q}'"));
            }
        }
    }
    if v.get("reversibility").is_some() && !is_one_of(v.get("reversibility"), &REVERSIBILITY) {
        return Some(format!("{at}: unknown reversibility"));
    }
    if let Some(r) = v.get("reversibility_by") {
        let r = match r.as_object() {
            Some(r) if r.keys().all(|k| ["param", "map", "default"].contains(&k.as_str())) => r,
            _ => return Some(format!("{at}: reversibility_by must be {{param, map, default?}}")),
        };
        if !s(r.get("param")).is_some_and(|p| params.contains_key(p)) {
            return Some(format!("{at}: reversibility_by.param must be a declared parameter"));
        }
        let map_ok = obj(r.get("map")).is_some_and(|m| !m.is_empty() && m.values().all(|x| is_one_of(Some(x), &REVERSIBILITY)));
        if !map_ok {
            return Some(format!("{at}: reversibility_by.map must map values to reversibility classes"));
        }
        if r.get("default").is_some() && !is_one_of(r.get("default"), &REVERSIBILITY) {
            return Some(format!("{at}: reversibility_by.default is not a reversibility class"));
        }
    }
    if let Some(m) = v.get("mcp") {
        let ok = m.as_object().is_some_and(|m| m.len() == 1 && m.contains_key("tool") && is_str(m.get("tool"), 128));
        if !ok {
            return Some(format!("{at}: mcp must be {{tool}}"));
        }
    }
    if let Some(o) = v.get("openapi") {
        let ok = o.as_object().is_some_and(|o| o.len() == 1 && o.contains_key("operationId") && is_str(o.get("operationId"), 128));
        if !ok {
            return Some(format!("{at}: openapi must be {{operationId}}"));
        }
    }
    for k in if v2 { ["harm", "returns"].as_slice() } else { ["harm", "effects", "returns"].as_slice() } {
        if v.get(*k).is_some_and(|x| !x.is_object()) {
            return Some(format!("{at}: {k} must be an object"));
        }
    }
    if v2 {
        let ef = v.get("effects").and_then(Value::as_array);
        match ef {
            Some(e) if !e.is_empty() && e.len() <= V2_EFFECTS.len() && e.iter().all(|x| is_one_of(Some(x), &V2_EFFECTS)) => {}
            _ => return Some(format!("{at}: effects must be 1..{} known effects", V2_EFFECTS.len())),
        }
        let ef = ef.unwrap();
        if ef.windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
            return Some(format!("{at}: effects must be sorted and distinct"));
        }
        if (s(v.get("kind")) == Some("read")) != ef.iter().all(|x| x.as_str() == Some("read")) {
            return Some(format!("{at}: kind read must hold exactly when every effect is read"));
        }
        let tr = v.get("traits").and_then(Value::as_array);
        if !tr.is_some_and(|t| t.len() <= 64 && t.iter().all(|x| x.as_str().is_some_and(is_trait_id_shape))) {
            return Some(format!("{at}: traits must be trait ids"));
        }
        if tr.unwrap().windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
            return Some(format!("{at}: traits must be sorted and distinct"));
        }
        if !b32(v.get("def")) {
            return Some(format!("{at}: def must be a canonical base64url SHA-256 digest"));
        }
        if let Some(fe) = schema_floors_error(v.get("floors")) {
            return Some(format!("{at}: {fe}"));
        }
        if let Some(c) = v.get("confirmation") {
            if let Some(ce) = confirmation_shape_error(c) {
                return Some(format!("{at}: {ce}"));
            }
        }
    }
    if v.get("world").is_some_and(|x| !x.is_array()) {
        return Some(format!("{at}: world must be an array"));
    }
    if v.get("description").is_some() && !is_str(v.get("description"), 1024) {
        return Some(format!("{at}: description must be a string"));
    }
    None
}

/// `actionSchemaShapeError(doc)` of a SIGNED document. `None` = well-formed.
pub fn action_schema_shape_error(doc: &Value) -> Option<String> {
    shape_error(doc, true)
}

/// `actionSchemaShapeError(doc, {signed: false})`: the same rules for an unsigned document, which must not carry `sig`.
pub fn action_schema_shape_error_unsigned(doc: &Value) -> Option<String> {
    shape_error(doc, false)
}

fn shape_error(doc: &Value, signed: bool) -> Option<String> {
    let d = match doc.as_object() {
        Some(d) => d,
        None => return Some("schema is not an object".into()),
    };
    let v2 = same(d.get("v"), Some(&Value::from(2)));
    if let Some(k) = d.keys().find(|k| !(if v2 { DOC_KEYS_V2.as_slice() } else { DOC_KEYS.as_slice() }).contains(&k.as_str())) {
        return Some(format!("unknown member '{k}'"));
    }
    if !v2 && !same(d.get("v"), Some(&Value::from(1))) {
        return Some("unsupported schema version".into());
    }
    if s(d.get("kind")) != Some(KIND) {
        return Some(format!("kind must be '{KIND}'"));
    }
    if !is_str(d.get("site"), 2048) || !is_str(d.get("aud"), 256) || !is_str(d.get("version"), 128) {
        return Some("site, aud and version must be non-empty strings".into());
    }
    if let Some(units) = d.get("units") {
        let us = match units.as_object() {
            Some(u) => u,
            None => return Some("units must be an object".into()),
        };
        for (id, u) in us {
            if !is_unit_id(id) || id.encode_utf16().count() > 64 {
                return Some(format!("unit id '{id}' is malformed"));
            }
            let u = match u.as_object() {
                Some(u) if is_str(u.get("kind"), 64) => u,
                _ => return Some(format!("unit '{id}' must be an object with a kind")),
            };
            if u.keys().any(|k| !["kind", "currency", "exponent"].contains(&k.as_str())) {
                return Some(format!("unit '{id}': unknown member"));
            }
            if u.get("currency").is_some() && !is_str(u.get("currency"), 16) {
                return Some(format!("unit '{id}': currency must be a string"));
            }
            if u.get("exponent").is_some() && !nonneg(u.get("exponent")).is_some_and(|e| e <= 18) {
                return Some(format!("unit '{id}': exponent must be an integer in [0, 18]"));
            }
        }
    }
    if d.get("state").is_some_and(|x| !x.is_array()) {
        return Some("state must be an array".into());
    }
    if v2 {
        if d.get("traits_digest").is_some() && !b32(d.get("traits_digest")) {
            return Some("traits_digest must be a canonical base64url SHA-256 digest".into());
        }
        if d.get("trait_defs").is_some_and(|t| !t.as_array().is_some_and(|a| a.len() <= 64 && a.iter().all(Value::is_object))) {
            return Some("trait_defs must be an array of up to 64 objects".into());
        }
        if let Some(pk) = d.get("pack") {
            let ok = pk.as_object().is_some_and(|o| o.len() == 3 && is_str(o.get("ns"), 64) && is_str(o.get("version"), 128) && b32(o.get("root")));
            if !ok {
                return Some("pack must be {ns, version, root}".into());
            }
        }
    }
    let verbs = match d.get("verbs").and_then(Value::as_array) {
        Some(v) if !v.is_empty() && v.len() <= MAX_VERBS => v,
        _ => return Some(format!("verbs must be 1..{MAX_VERBS} entries")),
    };
    let mut seen = std::collections::BTreeSet::new();
    for v in verbs {
        if let Some(e) = verb_decl_error(v, d.get("units"), v2) {
            return Some(e);
        }
        let name = s(v.get("verb")).unwrap_or("");
        if !seen.insert(name) {
            return Some(format!("verb '{name}' is declared twice"));
        }
    }
    if signed {
        let sig = match obj(d.get("sig")) {
            Some(x) => x,
            None => return Some("sig must be an object".into()),
        };
        if let Some(k) = sig.keys().find(|k| !SIG_KEYS.contains(&k.as_str())) {
            return Some(format!("sig: unknown member '{k}'"));
        }
        if let Err(e) = suite_of(sig.get("alg")) {
            return Some(format!("sig.alg: {e}"));
        }
        if !is_str(sig.get("kid"), 128) {
            return Some("sig.kid must be a non-empty string".into());
        }
        if !b64any(sig.get("value")) {
            return Some("sig.value is not canonical base64url".into());
        }
        if sig.get("pq_value").is_some() && !b64any(sig.get("pq_value")) {
            return Some("sig.pq_value is not canonical base64url".into());
        }
    } else if d.contains_key("sig") {
        return Some("an unsigned schema must not carry sig".into());
    }
    let mut body = d.clone();
    body.remove("sig");
    if let Err(e) = canonicalize_strict(&Value::Object(body)) {
        return Some(format!("malformed schema: {e}"));
    }
    None
}

fn schema_message(d: &Map<String, Value>) -> Option<Vec<u8>> {
    let mut body = d.clone();
    body.remove("sig");
    let c = canonicalize_strict(&Value::Object(body)).ok()?;
    let mut m = ACTION_SCHEMA_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(c.as_bytes());
    Some(m)
}

/// `verifyActionSchema(doc, keys)`: shape, `sig.kid` names a listed discovery key, `sig.alg` equals THAT KEY's suite,
/// and the signature verifies (a PQ key only as pinned by the key entry). Never panics.
pub fn verify_action_schema(doc: &Value, keys: &Value) -> Result<(), String> {
    if let Some(e) = action_schema_shape_error(doc) {
        return Err(e);
    }
    let d = doc.as_object().ok_or("schema is not an object")?;
    let sig = obj(d.get("sig")).ok_or("sig must be an object")?;
    let kid = sig.get("kid");
    let ks = keys.as_array().ok_or("the schema keys must be an array")?;
    let key = ks.iter().filter_map(Value::as_object).find(|k| same(k.get("kid"), kid));
    let key = key.ok_or_else(|| format!("no schema key with kid '{}'", s(kid).unwrap_or("")))?;
    if key.get("pq_pk").is_some_and(|p| !p.is_string()) {
        return Err("the schema key pq_pk must be a string".into());
    }
    if !b32(key.get("pk")) {
        return Err("schema key pk is not canonical base64url (32 bytes)".into());
    }
    let ka = suite_of(key.get("alg")).map_err(|e| format!("schema key: {e}"))?;
    if suite_of(sig.get("alg"))?.alg != ka.alg {
        return Err("sig.alg does not match the pinned key suite".into());
    }
    let pk = s(key.get("pk")).unwrap_or("");
    let pin = key.get("pq_pk").map(|p| (pk, p));
    let msg = schema_message(d).ok_or("schema is not strictly canonical")?;
    let alg = Value::String(ka.alg.into());
    if !verify_pinned_suite(Some(&alg), pk, key.get("pq_pk"), &msg, sig.get("value"), sig.get("pq_value"), pin)? {
        return Err("schema signature invalid".into());
    }
    Ok(())
}

/// `actionSchemaDigest(doc)` = b64u(sha256(strictCanonical({d: "atlas-pca/action-schema-ref/v1", s: doc}))); `None`
/// where the reference throws (an out-of-profile document).
pub fn action_schema_digest(doc: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(ACTION_SCHEMA_REF_DOMAIN.into()));
    m.insert("s".into(), doc.clone());
    digest_of(&Value::Object(m))
}

/// `schemaVerb(doc, verb)`. `Err` where the reference throws (a `null` entry before the match).
pub(crate) fn schema_verb<'a>(doc: &'a Value, verb: &str) -> Result<Option<&'a Map<String, Value>>, String> {
    let verbs = match doc.get("verbs").and_then(Value::as_array) {
        Some(v) => v,
        None => return Ok(None),
    };
    for v in verbs {
        match v {
            Value::Null => return Err("verb entry is null".into()),
            Value::Object(o) if s(o.get("verb")) == Some(verb) => return Ok(Some(o)),
            _ => {}
        }
    }
    Ok(None)
}

/// `accumulationParams(v, unit)`: the integer parameters of a verb whose `accumulates_into` lists `unit`, sorted by
/// UTF-8 bytes. `Err` where the reference throws.
pub(crate) fn accumulation_params(v: &Map<String, Value>, unit: &str) -> Result<Vec<String>, String> {
    let params = match v.get("params") {
        Some(Value::Object(p)) => p,
        None | Some(Value::Null) => return Err("verb params missing".into()),
        Some(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (p, d) in params {
        let d = match d {
            Value::Null => return Err("parameter declaration is null".into()),
            Value::Object(d) => d,
            _ => continue,
        };
        if s(d.get("type")) != Some("integer") {
            continue;
        }
        let listed = match d.get("accumulates_into") {
            None | Some(Value::Null) => false,
            Some(Value::Array(a)) => a.iter().any(|u| u.as_str() == Some(unit)),
            Some(Value::String(st)) => st.contains(unit),
            Some(_) => return Err("accumulates_into is not a list".into()),
        };
        if listed {
            out.push(p.clone());
        }
    }
    sort_utf8(&mut out);
    Ok(out)
}

/// The rule-14 conformance result (`conformAction`): `ok`, else the violation `code` and, for a parameter, its `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformResult {
    pub ok: bool,
    pub code: Option<String>,
    pub path: Option<String>,
    pub reason: String,
}

impl ConformResult {
    fn ok() -> Self {
        ConformResult { ok: true, code: None, path: None, reason: String::new() }
    }
    fn bad(code: &str, path: Option<String>, reason: impl Into<String>) -> Self {
        ConformResult { ok: false, code: Some(code.into()), path, reason: reason.into() }
    }
}

fn is_calendar_date(x: &str) -> bool {
    let b = x.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r.clone()].iter().all(u8::is_ascii_digit).then(|| x[r].parse::<u32>().unwrap_or(0));
    let (y, m, d) = match (digits(0..4), digits(5..7), digits(8..10)) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return false,
    };
    if y < 1 || !(1..=12).contains(&m) || d < 1 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(m - 1) as usize];
    d <= dim
}

/// A numeric declaration member, `fallback` when absent. A present member that is not a number is NaN, which every
/// bound test below treats as a violation (fail closed; a signed schema's shape check already refuses it).
fn num_or(d: &Map<String, Value>, k: &str, fallback: f64) -> f64 {
    match d.get(k) {
        None => fallback,
        Some(v) => num(Some(v)).unwrap_or(f64::NAN),
    }
}

/// An optional inclusive bound (`None` = unbounded; a non-number is NaN: see [`num_or`]).
fn bound(d: &Map<String, Value>, k: &str) -> Option<f64> {
    d.get(k).map(|v| num(Some(v)).unwrap_or(f64::NAN))
}

fn in_values(d: &Map<String, Value>, x: &str) -> bool {
    d.get("values").and_then(Value::as_array).is_some_and(|vs| vs.iter().any(|v| v.as_str() == Some(x)))
}

// ---- v2 string formats (syntactic checks, identical in every language; none consults a registry or the network) ----

/// ECMAScript `\s`.
fn is_js_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn iban_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if !(15..=34).contains(&b.len()) || !b[..2].iter().all(u8::is_ascii_uppercase) || !b[2..4].iter().all(u8::is_ascii_digit) || !b[4..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    let mut rem: u64 = 0;
    for &ch in b[4..].iter().chain(&b[..4]) {
        let v = if ch >= b'A' { (ch - 55) as u64 } else { (ch - 48) as u64 };
        rem = (if v > 9 { rem * 100 + v } else { rem * 10 + v }) % 97;
    }
    rem == 1
}

fn canon_dec(n: &str) -> Option<u32> {
    (!n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) && (n == "0" || !n.starts_with('0'))).then(|| n.parse().ok()).flatten()
}

fn cidr_ok(s: &str) -> bool {
    let (addr, pre) = match s.split_once('/') {
        Some(x) => x,
        None => return false,
    };
    let digits = |x: &str, max: usize| !x.is_empty() && x.len() <= max && x.bytes().all(|c| c.is_ascii_digit());
    let oct: Vec<&str> = addr.split('.').collect();
    if oct.len() == 4 && oct.iter().all(|o| digits(o, 3)) && digits(pre, 2) {
        return oct.iter().all(|o| canon_dec(o).is_some_and(|n| n <= 255)) && canon_dec(pre).is_some_and(|n| n <= 32);
    }
    (2..=39).contains(&addr.len())
        && addr.bytes().all(|c| c.is_ascii_hexdigit() || c == b':')
        && addr.matches(':').count() >= 2
        && !addr.contains(":::")
        && digits(pre, 3)
        && canon_dec(pre).is_some_and(|n| n <= 128)
}

fn semver_ok(s: &str) -> bool {
    let idents = |x: &str| x.split('.').all(|g| !g.is_empty() && g.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    let (rest, build) = match s.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (s, None),
    };
    if build.is_some_and(|b| !idents(b)) {
        return false;
    }
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    if pre.is_some_and(|p| !idents(p)) {
        return false;
    }
    let nums: Vec<&str> = core.split('.').collect();
    nums.len() == 3 && nums.iter().all(|n| canon_dec_big(n))
}

fn canon_dec_big(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) && (n == "0" || !n.starts_with('0'))
}

fn email_ok(s: &str) -> bool {
    if s.chars().count() > 254 {
        return false;
    }
    let (local, dom) = match s.split_once('@') {
        Some(x) => x,
        None => return false,
    };
    let labels: Vec<&str> = dom.split('.').collect();
    (1..=64).contains(&local.len())
        && local.bytes().all(|c| c.is_ascii_alphanumeric() || b"._%+-".contains(&c))
        && labels.len() >= 2
        && labels.iter().all(|l| (1..=63).contains(&l.len()) && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// `^<scheme>://[^\s/?#]+[^\s]*$` after the scheme prefix has been matched.
fn authority_ok(rest: &str) -> bool {
    !rest.is_empty() && !rest.chars().any(is_js_ws) && !rest.starts_with(['/', '?', '#'])
}

fn url_ok(s: &str) -> bool {
    match s.split_once("://") {
        Some((sch, rest)) => {
            let b = sch.as_bytes();
            !b.is_empty() && b.len() <= 32 && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric() || b"+.-".contains(c)) && authority_ok(rest)
        }
        None => false,
    }
}

fn lower_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn uuid_ok(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && p.iter().zip([8, 4, 4, 4, 12]).all(|(g, n)| g.len() == n && lower_hex(g))
}

/// The checker of a v2 `format`, or `None` when the format is unknown. `id:<type>` accepts a 1..128 character safe id.
fn format_check(f: &str, x: &str) -> Option<bool> {
    Some(match f {
        "email" => email_ok(x),
        "url" => url_ok(x),
        "uri_https" => x.strip_prefix("https://").is_some_and(authority_ok),
        "uuid" => uuid_ok(x),
        "iban" => iban_ok(x),
        "phone_e164" => x.strip_prefix('+').is_some_and(|d| (7..=15).contains(&d.len()) && d.bytes().all(|c| c.is_ascii_digit()) && !d.starts_with('0')),
        "cidr" => cidr_ok(x),
        "iso_country" => x.len() == 2 && x.bytes().all(|c| c.is_ascii_uppercase()),
        "iso_currency" => x.len() == 3 && x.bytes().all(|c| c.is_ascii_uppercase()),
        "semver" => semver_ok(x),
        "sha256" => x.len() == 64 && lower_hex(x),
        _ => {
            let id = f.strip_prefix("id:").is_some_and(|t| {
                let p: Vec<&str> = t.split('.').collect();
                (1..=4).contains(&p.len()) && p.iter().all(|g| !g.is_empty() && g.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'))
            });
            if !id {
                return None;
            }
            (1..=128).contains(&x.len()) && x.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        }
    })
}

fn format_violation(d: &Map<String, Value>, x: &str) -> Option<(&'static str, String)> {
    let f = d.get("format")?;
    let fs = f.as_str().unwrap_or("");
    (format_check(fs, x) != Some(true)).then(|| ("out_of_domain", format!("not a valid {}", f.as_str().map(String::from).unwrap_or_else(|| f.to_string()))))
}

/// `^YYYY-MM-DDTHH:MM:SS(.f{1,3})?Z$` (a real calendar date, hour 00-23).
fn datetime_ok(x: &str) -> bool {
    let b = x.as_bytes();
    if b.len() < 20 || b[10] != b'T' || *b.last().unwrap() != b'Z' || !x.is_char_boundary(10) || !is_calendar_date(&x[..10]) {
        return false;
    }
    let t = &b[11..b.len() - 1];
    let d = |i: usize| t[i].is_ascii_digit();
    if t.len() < 8 || !(d(0) && d(1) && d(3) && d(4) && d(6) && d(7)) || t[2] != b':' || t[5] != b':' {
        return false;
    }
    let (h, m, sec) = ((t[0] - b'0') * 10 + (t[1] - b'0'), (t[3] - b'0') * 10 + (t[4] - b'0'), (t[6] - b'0') * 10 + (t[7] - b'0'));
    if h > 23 || m > 59 || sec > 59 {
        return false;
    }
    let frac = &t[8..];
    frac.is_empty() || (frac[0] == b'.' && (2..=4).contains(&frac.len()) && frac[1..].iter().all(u8::is_ascii_digit))
}

/// `paramValueViolation(d, x)`: `None` = in the declared domain, else (`bad_type` | `out_of_domain`, reason).
pub(crate) fn param_value_violation(d: &Map<String, Value>, x: &Value) -> Option<(&'static str, String)> {
    let max_len = num_or(d, "max_len", DEFAULT_MAX_LEN);
    match s(d.get("type")) {
        Some("string") => {
            let st = match x.as_str() {
                Some(st) => st,
                None => return Some(("bad_type", "expected a string".into())),
            };
            if !((st.len() as f64) <= max_len) {
                return Some(("out_of_domain", format!("longer than {max_len} UTF-8 bytes")));
            }
            if d.get("values").is_some() && !in_values(d, st) {
                return Some(("out_of_domain", "not one of the declared values".into()));
            }
            format_violation(d, st)
        }
        Some("object_ref") => {
            let st = match x.as_str() {
                Some(st) if !st.is_empty() => st,
                _ => return Some(("bad_type", "expected a non-empty id string".into())),
            };
            if !((st.len() as f64) <= max_len) {
                return Some(("out_of_domain", format!("longer than {max_len} UTF-8 bytes")));
            }
            format_violation(d, st)
        }
        Some("datetime") => {
            let st = match x.as_str() {
                Some(st) => st,
                None => return Some(("bad_type", "expected an RFC 3339 UTC string".into())),
            };
            (!datetime_ok(st)).then(|| ("out_of_domain", "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z".into()))
        }
        Some("duration") => {
            let i = match safe_int_val(x) {
                Some(i) => i as f64,
                None => return Some(("bad_type", "expected a safe integer (milliseconds)".into())),
            };
            if i < 0.0 {
                return Some(("out_of_domain", "a duration is not negative".into()));
            }
            if let Some(lo) = bound(d, "min") {
                if !(i >= lo) {
                    return Some(("out_of_domain", format!("below min {lo}")));
                }
            }
            if let Some(hi) = bound(d, "max") {
                if !(i <= hi) {
                    return Some(("out_of_domain", format!("above max {hi}")));
                }
            }
            None
        }
        Some("integer") => {
            let i = match safe_int_val(x) {
                Some(i) => i as f64,
                None => return Some(("bad_type", "expected a safe integer".into())),
            };
            if let Some(lo) = bound(d, "min") {
                if !(i >= lo) {
                    return Some(("out_of_domain", format!("below min {lo}")));
                }
            }
            if let Some(hi) = bound(d, "max") {
                if !(i <= hi) {
                    return Some(("out_of_domain", format!("above max {hi}")));
                }
            }
            None
        }
        Some("boolean") => (!x.is_boolean()).then(|| ("bad_type", "expected a boolean".into())),
        Some("date") => match x.as_str() {
            None => Some(("bad_type", "expected a YYYY-MM-DD string".into())),
            Some(st) => (!is_calendar_date(st)).then(|| ("out_of_domain", "not a calendar date YYYY-MM-DD".into())),
        },
        Some("set") => {
            let a = match x.as_array() {
                Some(a) if a.iter().all(Value::is_string) => a,
                _ => return Some(("bad_type", "expected an array of strings".into())),
            };
            let distinct: std::collections::BTreeSet<&str> = a.iter().filter_map(Value::as_str).collect();
            if distinct.len() != a.len() {
                return Some(("out_of_domain", "set members must be distinct".into()));
            }
            if !a.iter().all(|e| in_values(d, e.as_str().unwrap_or(""))) {
                return Some(("out_of_domain", "set member not among the declared values".into()));
            }
            let nvalues = d.get("values").and_then(Value::as_array).map_or(0, Vec::len) as f64;
            let n = a.len() as f64;
            if !(n >= num_or(d, "min_items", 0.0) && n <= num_or(d, "max_items", nvalues)) {
                return Some(("out_of_domain", "set size outside the declared bounds".into()));
            }
            None
        }
        Some("array") => {
            let a = match x.as_array() {
                Some(a) => a,
                None => return Some(("bad_type", "expected an array".into())),
            };
            let ints = s(d.get("items")) == Some("integer");
            for e in a {
                if ints {
                    let i = match safe_int_val(e) {
                        Some(i) => i as f64,
                        None => return Some(("bad_type", "array items must be safe integers".into())),
                    };
                    if bound(d, "min").is_some_and(|lo| !(i >= lo)) || bound(d, "max").is_some_and(|hi| !(i <= hi)) {
                        return Some(("out_of_domain", "array item outside min/max".into()));
                    }
                } else if !e.as_str().is_some_and(|st| (st.len() as f64) <= max_len) {
                    return Some(("bad_type", format!("array items must be strings of at most {max_len} UTF-8 bytes")));
                }
            }
            let n = a.len() as f64;
            if !(n >= num_or(d, "min_items", 0.0) && n <= num_or(d, "max_items", DEFAULT_MAX_ITEMS)) {
                return Some(("out_of_domain", "array length outside the declared bounds".into()));
            }
            None
        }
        _ => Some(("bad_type", "unknown declared type".into())),
    }
}

fn safe_int_val(x: &Value) -> Option<i64> {
    sint(Some(x))
}

/// `conformAction(doc, verb, params)` (NORMATIVE, rule 14 step 5). First failure wins: params not an object;
/// unknown verb; an undeclared key (UTF-8 byte order); then every declared path in UTF-8 byte order: missing and
/// required, else the value check.
pub fn conform_action(doc: &Value, verb: &str, params: &Value) -> ConformResult {
    let p = match params.as_object() {
        Some(p) => p,
        None => return ConformResult::bad("params_not_object", None, "params must be a JSON object"),
    };
    let v = match schema_verb(doc, verb) {
        Ok(Some(v)) => v,
        Ok(None) => return ConformResult::bad("unknown_verb", None, format!("verb '{verb}' is not declared by the schema")),
        Err(e) => return ConformResult::bad("unknown_verb", None, e),
    };
    let empty = Map::new();
    let decls = obj(v.get("params")).unwrap_or(&empty);
    let mut keys: Vec<String> = p.keys().cloned().collect();
    sort_utf8(&mut keys);
    for k in keys {
        let path = format!("action.params.{k}");
        if !decls.contains_key(&path) {
            return ConformResult::bad("undeclared_param", Some(path.clone()), format!("parameter '{path}' is not declared for '{verb}'"));
        }
    }
    let mut paths: Vec<String> = decls.keys().cloned().collect();
    sort_utf8(&mut paths);
    for path in paths {
        let d = match decls.get(&path).and_then(Value::as_object) {
            Some(d) => d,
            None => return ConformResult::bad("bad_type", Some(path), "malformed declaration"),
        };
        let name = path.strip_prefix("action.params.").unwrap_or(&path);
        match p.get(name) {
            None => {
                if d.get("required") != Some(&Value::Bool(false)) {
                    return ConformResult::bad("missing_param", Some(path.clone()), format!("required parameter '{path}' is missing"));
                }
            }
            Some(x) => {
                if let Some((code, why)) = param_value_violation(d, x) {
                    return ConformResult::bad(code, Some(path.clone()), format!("'{path}': {why}"));
                }
            }
        }
    }
    ConformResult::ok()
}

/// `canonProjection(doc, verb, params)`: for every PRESENT boolean / set / array parameter of the verb, its canonical
/// text. `Err` where the reference throws (a value outside the strict profile).
pub(crate) fn canon_projection(doc: &Value, verb: &str, params: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    let v = match schema_verb(doc, verb)? {
        Some(v) => v,
        None => return Ok(out),
    };
    let empty = Map::new();
    let decls = obj(v.get("params")).unwrap_or(&empty);
    let mut paths: Vec<String> = decls.keys().cloned().collect();
    sort_utf8(&mut paths);
    for path in paths {
        let name = path.strip_prefix("action.params.").unwrap_or(&path).to_string();
        let x = match params.get(&name) {
            Some(x) => x,
            None => continue,
        };
        match s(decls.get(&path).and_then(|d| d.get("type"))) {
            Some("boolean") => {
                out.insert(name, Value::String(if *x == Value::Bool(true) { "true" } else { "false" }.into()));
            }
            Some("set") => {
                let mut items: Vec<String> = Vec::new();
                for e in x.as_array().ok_or("set is not an array")? {
                    items.push(e.as_str().ok_or("set member is not a string")?.to_string());
                }
                sort_utf8(&mut items);
                let arr = Value::Array(items.into_iter().map(Value::String).collect());
                out.insert(name, Value::String(canonicalize_strict(&arr)?));
            }
            Some("array") => {
                out.insert(name, Value::String(canonicalize_strict(x)?));
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "k042_action_schema_test.rs"]
mod k042_test;
