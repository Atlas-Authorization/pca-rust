//! Intent Layer v2 (PCA 0.4.2), rule 14: signed action schemas (`pca-action-schema` v1, closed world).
//!
//! Faithful port of `packages/pca/src/action-schema.ts` (shape validation, signature verification under the site's discovery
//! keys, the content address, closed-world conformance `conformAction`, the value-dependent reversibility helpers) and of
//! `canonProjection` from `packages/pca/src/intent-v2.ts` (`env.canon`).
//!
//! Strict pass (TS 5e0a33a9): own-property reads (serde maps only hold own members; a JSON `__proto__` key is data),
//! `__proto__` / `constructor` / `prototype` refused as parameter names, a null `default` is malformed, absent = default and
//! present `null` = malformed. Suite capability: `sig.alg` / the key entry's `alg` absent = ed25519, a non-string is malformed,
//! a name outside the registry is `unsupported_suite`; a registered suite the guest does not implement (`crate::pq_suites`:
//! fn-dsa-*, less-*) fails closed with a reason containing `unsupported_suite` (the TS reference may accept it).
//!
//! Not ported (not on the verifier path): the MCP / OpenAPI draft importers, the wallet floor, `accumulationParams`.
//!
//! Key-order notes: the TS shape validator iterates `Object.keys` in insertion order and returns the FIRST error; serde maps
//! here iterate in sorted order. The VERDICT (well-formed or not) is identical; only the reason may name a different member
//! when a document carries several faults. `conformAction` / `canonProjection` sort by UTF-8 bytes in TS, as here.
//!
//! Off-contract inputs: `conform_action` / `canon_projection` assume a shape-valid document (as the TS does, which may throw
//! on e.g. a `null` verb entry); here they stay total (a non-object verb entry never matches, missing `values` = empty).

use crate::canonical::{canonical_bytes, canonicalize, strict_violation};
use crate::chain::{decode_b64u_strict};
use crate::commit::{b64u, hash_canonical};
use crate::jsnum::{non_neg, safe_int};
use serde_json::{json, Map, Value};

pub const ACTION_SCHEMA_DOMAIN: &str = "atlas-pca/action-schema/v1\0";
pub const ACTION_SCHEMA_REF_DOMAIN: &str = "atlas-pca/action-schema-ref/v1";
pub const ACTION_SCHEMA_KIND: &str = "pca-action-schema";

pub const MAX_SCHEMA_VERBS: usize = 256;
pub const MAX_SCHEMA_PARAMS: usize = 64;
pub const MAX_SCHEMA_VALUES: usize = 256;
pub const DEFAULT_MAX_LEN: i64 = 1024;
pub const DEFAULT_MAX_ITEMS: i64 = 64;

const SENSITIVITIES: [&str; 3] = ["free", "material", "critical"];
const REVERSIBILITY: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const PARAM_TYPES: [&str; 6] = ["string", "integer", "boolean", "date", "set", "array"];
const DOC_KEYS_V2_EXTRA: [&str; 3] = ["traits_digest", "trait_defs", "pack"];
const VERB_KEYS_V2_EXTRA: [&str; 4] = ["traits", "def", "floors", "confirmation"];
const PARAM_KEYS_V2_EXTRA: [&str; 4] = ["role", "format", "tags", "provenance_min"];
const PARAM_TYPES_V2_EXTRA: [&str; 3] = ["datetime", "duration", "object_ref"];
const V2_EFFECTS: [&str; 12] = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
const V2_TAGS: [&str; 9] = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"];
const V2_PROVENANCE: [&str; 3] = ["first_party", "tool", "agent"];
const DOC_KEYS: [&str; 9] = ["v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig"];
const VERB_KEYS: [&str; 12] =
    ["verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description"];
const PARAM_KEYS: [&str; 17] = [
    "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items", "max_items",
    "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description",
];
const SIG_KEYS: [&str; 4] = ["alg", "kid", "value", "pq_value"];
/// The closed signature-suite registry (`pq.ts` `SIG_SUITES`, all 14). What the guest implements is `crate::pq_suites`.
const SIG_ALGS: [&str; 14] = [
    "ed25519",
    "ml-dsa-65",
    "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65",
    "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f",
    "ml-dsa-87",
    "hybrid-ed25519-ml-dsa-87",
    "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s",
    "fn-dsa-512",
    "less-cat1",
    "hybrid-ed25519-less-cat1",
    "fn-dsa-1024",
];
const PARAMS_PREFIX: &str = "action.params.";

// ---- small helpers -------------------------------------------------------------------------------------------------

/// `isStr(v, max)`: a non-empty string of at most `max` UTF-8 bytes.
fn is_str(v: Option<&Value>, max: usize) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty() && s.len() <= max)
}
fn is_int(v: Option<&Value>) -> bool {
    v.and_then(safe_int).is_some()
}
fn is_non_neg(v: Option<&Value>) -> bool {
    v.and_then(non_neg).is_some()
}
fn str_in(v: Option<&Value>, set: &[&str]) -> bool {
    matches!(v, Some(Value::String(s)) if set.contains(&s.as_str()))
}
fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
/// `PARAM_PATH_RE`: `^action\.params\.[A-Za-z0-9_]{1,64}$`.
fn param_path_ok(p: &str) -> bool {
    p.strip_prefix(PARAMS_PREFIX).is_some_and(name_ok)
}
/// `UNIT_ID_RE`: `^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`.
fn unit_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}
fn distinct_strs(a: &[Value]) -> bool {
    let mut v: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
    let n = v.len();
    v.sort_unstable();
    v.dedup();
    v.len() == n
}
/// `decodeB64uStrict(s)` without a length: canonical base64url of any decoded length.
fn b64u_any_ok(v: Option<&Value>) -> bool {
    let s = match v {
        Some(Value::String(s)) => s,
        _ => return false,
    };
    if s.len() % 4 == 1 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return false;
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    match URL_SAFE_NO_PAD.decode(s.as_bytes()) {
        Ok(bytes) => b64u(&bytes) == *s,
        Err(_) => false,
    }
}
/// `suiteCapabilityError(alg, resolveSigAlg)` (intent-strict.ts) against the TS registry.
fn suite_err(v: Option<&Value>) -> Option<String> {
    match v {
        None => None,
        Some(Value::String(s)) if SIG_ALGS.contains(&s.as_str()) => None,
        Some(Value::String(s)) => Some(format!("unsupported_suite: '{s}'")),
        Some(_) => Some("alg must be a string".into()),
    }
}
/// Names the predicate DSL cannot address; refused as parameter names.
const RESERVED_NAMES: [&str; 3] = ["__proto__", "constructor", "prototype"];
/// `resolveSigAlg(alg)?.alg`: absent = `ed25519`; a registered name = itself; anything else (incl. `null`) = None.
fn resolve_sig_alg(v: Option<&Value>) -> Option<&str> {
    match v {
        None => Some("ed25519"),
        Some(Value::String(s)) => SIG_ALGS.iter().copied().find(|a| *a == s.as_str()),
        _ => None,
    }
}
fn js_str(v: Option<&Value>) -> String {
    crate::canonical::js_string(v)
}
/// `^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$`.
fn trait_id_shape(s: &str) -> bool {
    let Some((a, b)) = s.split_once('.') else { return false };
    let part = |p: &str, max: usize| !p.is_empty() && p.len() <= max && p.as_bytes()[0].is_ascii_lowercase() && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    part(a, 32) && part(b, 64)
}

// ---- shape -----------------------------------------------------------------------------------------------------------

/// `PARAM_PATH_RE_V2`: `action.params.` then 1..3 dot-separated names of `[A-Za-z0-9_]{1,64}`.
fn param_path_ok_v2(p: &str) -> bool {
    p.strip_prefix(PARAMS_PREFIX).is_some_and(|rest| {
        let segs: Vec<&str> = rest.split('.').collect();
        (1..=3).contains(&segs.len()) && segs.iter().all(|s| name_ok(s))
    })
}

fn param_decl_error(path: &str, d: &Value, units: Option<&Value>, v2: bool) -> Option<String> {
    if !(if v2 { param_path_ok_v2(path) } else { param_path_ok(path) }) {
        return Some(format!("parameter path '{path}' is not action.params.<name>"));
    }
    if path.strip_prefix(PARAMS_PREFIX).unwrap_or(path).split('.').any(|seg| RESERVED_NAMES.contains(&seg)) {
        return Some(format!("parameter name '{path}' is reserved (__proto__ / constructor / prototype)"));
    }
    let d = match d.as_object() {
        Some(o) => o,
        None => return Some(format!("{path}: declaration must be an object")),
    };
    if let Some(k) = d.keys().find(|k| !PARAM_KEYS.contains(&k.as_str()) && !(v2 && PARAM_KEYS_V2_EXTRA.contains(&k.as_str()))) {
        return Some(format!("{path}: unknown member '{k}'"));
    }
    let ty = d.get("type");
    if !(str_in(ty, &PARAM_TYPES) || (v2 && str_in(ty, &PARAM_TYPES_V2_EXTRA))) {
        return Some(format!("{path}: unknown type"));
    }
    let ty = ty.and_then(Value::as_str).unwrap_or("");
    if !is_str(d.get("semantic"), 128) {
        return Some(format!("{path}: semantic must be a non-empty string"));
    }
    if !str_in(d.get("sensitivity"), &SENSITIVITIES) {
        return Some(format!("{path}: unknown sensitivity"));
    }
    if d.get("required").is_some_and(|r| !r.is_boolean()) {
        return Some(format!("{path}: required must be a boolean"));
    }
    if let Some(vals) = d.get("values") {
        let ok = match vals.as_array() {
            Some(a) => !a.is_empty() && a.len() <= MAX_SCHEMA_VALUES && a.iter().all(|x| is_str(Some(x), 256)),
            None => false,
        };
        if !ok {
            return Some(format!("{path}: values must be 1..{MAX_SCHEMA_VALUES} strings"));
        }
        if !distinct_strs(vals.as_array().map(Vec::as_slice).unwrap_or(&[])) {
            return Some(format!("{path}: values must be distinct"));
        }
        if ty != "string" && ty != "set" {
            return Some(format!("{path}: values apply to string and set only"));
        }
    }
    if ty == "set" && d.get("values").is_none() {
        return Some(format!("{path}: a set needs values"));
    }
    let int_items = ty == "array" && d.get("items").and_then(Value::as_str) == Some("integer");
    for k in ["min", "max"] {
        if d.get(k).is_some() && (!is_int(d.get(k)) || (ty != "integer" && !(v2 && ty == "duration") && !int_items)) {
            return Some(format!("{path}: {k} must be a safe integer on an integer parameter"));
        }
    }
    if let (Some(lo), Some(hi)) = (d.get("min").and_then(safe_int), d.get("max").and_then(safe_int)) {
        if lo > hi {
            return Some(format!("{path}: min > max"));
        }
    }
    if let Some(u) = d.get("unit") {
        let declared = match (u.as_str(), units.and_then(Value::as_object)) {
            (Some(name), Some(us)) => us.contains_key(name),
            _ => false,
        };
        if ty != "integer" || !declared {
            return Some(format!("{path}: unit must name a declared unit of an integer parameter"));
        }
    }
    if d.get("max_len").is_some() && !d.get("max_len").and_then(safe_int).is_some_and(|n| n >= 1) {
        return Some(format!("{path}: max_len must be a positive safe integer"));
    }
    if d.get("items").is_some() && (ty != "array" || !is_str(d.get("items"), 64)) {
        return Some(format!("{path}: items applies to array only"));
    }
    for k in ["min_items", "max_items"] {
        if d.get(k).is_some() && (!is_non_neg(d.get(k)) || (ty != "set" && ty != "array")) {
            return Some(format!("{path}: {k} must be a non-negative safe integer on a set or array"));
        }
    }
    if let (Some(lo), Some(hi)) = (d.get("min_items").and_then(safe_int), d.get("max_items").and_then(safe_int)) {
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
    if let Some(acc) = d.get("accumulates_into") {
        if ty != "integer" {
            return Some(format!("{path}: accumulates_into applies to integer parameters only"));
        }
        let a = match acc.as_array() {
            Some(a) if !a.is_empty() && a.len() <= 8 => a,
            _ => return Some(format!("{path}: accumulates_into must be 1..8 unit ids")),
        };
        if !a.iter().all(|u| u.as_str().is_some_and(|s| s.len() <= 64 && unit_id_ok(s))) {
            return Some(format!("{path}: accumulates_into entries must be unit ids"));
        }
        if !distinct_strs(a) {
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
            if !f.as_str().is_some_and(format_known) || (ty != "string" && ty != "object_ref") {
                return Some(format!("{path}: format must be a known format on a string parameter"));
            }
        }
        if let Some(t) = d.get("tags") {
            let ok = t.as_array().is_some_and(|a| a.len() <= V2_TAGS.len() && distinct_strs(a) && a.iter().all(|x| x.as_str().is_some_and(|s| V2_TAGS.contains(&s))));
            if !ok {
                return Some(format!("{path}: tags must be distinct known tags"));
            }
        }
        if d.get("provenance_min").is_some() && !str_in(d.get("provenance_min"), &V2_PROVENANCE) {
            return Some(format!("{path}: unknown provenance_min"));
        }
    }
    None
}

/// `schemaFloorsError(f)`: a well-formed materialized profile (shape only; the semantic check is rule 22).
fn floors_shape_error(f: Option<&Value>) -> Option<String> {
    let f = match f.and_then(Value::as_object) {
        Some(f) => f,
        None => return Some("floors must be an object".into()),
    };
    if let Some(k) = f.keys().find(|k| !["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"].contains(&k.as_str())) {
        return Some(format!("floors: unknown member '{k}'"));
    }
    let rng = |k: &str, lo: i64, hi: i64| f.get(k).and_then(safe_int).is_some_and(|x| x >= lo && x <= hi);
    if !rng("risk", 0, 3) || !rng("esc", 0, 3) {
        return Some("floors.risk and floors.esc must be integers in 0..3".into());
    }
    if !str_in(f.get("rev"), &REVERSIBILITY) {
        return Some("floors.rev is not a reversibility class".into());
    }
    if !rng("blast_ppm", 0, 1_000_000) {
        return Some("floors.blast_ppm must be an integer in 0..1000000".into());
    }
    let sets: [(&str, &dyn Fn(&str) -> bool); 3] = [
        ("caveats", &|x| crate::rule22::CAVEAT_KINDS.contains(&x)),
        ("context", &crate::rule22::is_context_key),
        ("prules", &|x| crate::rule22::PARAM_RULE_IDS.contains(&x)),
    ];
    for (name, ok) in sets {
        let a = match f.get(name).and_then(Value::as_array) {
            Some(a) if a.len() <= 64 && a.iter().all(|x| x.as_str().is_some_and(ok)) => a,
            _ => return Some(format!("floors.{name} must be an array of known entries")),
        };
        for i in 1..a.len() {
            if a[i - 1].as_str() >= a[i].as_str() {
                return Some(format!("floors.{name} must be sorted and distinct"));
            }
        }
    }
    None
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
    let b64 = |k: &str, len: usize| c.get(k).and_then(Value::as_str).is_some_and(|s| decode_b64u_strict(s, len).is_some());
    if !b64("def_digest", 32) || !b64("traits_digest", 32) || !b64("facts_digest", 32) {
        return Some("confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests".into());
    }
    if !b64("sig", 64) {
        return Some("confirmation: sig must be a canonical base64url 64-byte signature".into());
    }
    let ft = match c.get("final_traits").and_then(Value::as_array) {
        Some(a) if a.len() <= 64 && a.iter().all(|x| x.as_str().is_some_and(trait_id_shape)) => a,
        _ => return Some("confirmation: final_traits must be trait ids".into()),
    };
    if ft.windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
        return Some("confirmation: final_traits must be sorted and distinct".into());
    }
    let dm = match c.get("dismissed").and_then(Value::as_array) {
        Some(a) if a.len() <= 64 => a,
        _ => return Some("confirmation: dismissed must be an array".into()),
    };
    for d in dm {
        let ok = d.as_object().is_some_and(|d| {
            d.keys().all(|k| k == "trait" || k == "reason") && d.get("trait").and_then(Value::as_str).is_some_and(trait_id_shape) && is_str(d.get("reason"), 256)
        });
        if !ok {
            return Some("confirmation: dismissed entries must be {trait, reason}".into());
        }
    }
    if !is_str(c.get("reviewer_kid"), 128) {
        return Some("confirmation: reviewer_kid must be a non-empty string".into());
    }
    if !is_non_neg(c.get("ts")) {
        return Some("confirmation: ts must be a non-negative safe integer".into());
    }
    None
}

fn verb_decl_error(v: &Value, units: Option<&Value>, v2: bool) -> Option<String> {
    let v = match v.as_object() {
        Some(o) => o,
        None => return Some("verb entry must be an object".into()),
    };
    if let Some(k) = v.keys().find(|k| !VERB_KEYS.contains(&k.as_str()) && !(v2 && VERB_KEYS_V2_EXTRA.contains(&k.as_str()))) {
        return Some(format!("verb entry: unknown member '{k}'"));
    }
    if !is_str(v.get("verb"), 128) {
        return Some("verb entry: verb must be a non-empty string".into());
    }
    let at = format!("verb '{}'", js_str(v.get("verb")));
    if !str_in(v.get("kind"), &["read", "write"]) {
        return Some(format!("{at}: kind must be read or write"));
    }
    let params = match v.get("params").and_then(Value::as_object) {
        Some(p) => p,
        None => return Some(format!("{at}: params must be an object")),
    };
    if params.len() > MAX_SCHEMA_PARAMS {
        return Some(format!("{at}: more than {MAX_SCHEMA_PARAMS} parameters"));
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
    if v.get("reversibility").is_some() && !str_in(v.get("reversibility"), &REVERSIBILITY) {
        return Some(format!("{at}: unknown reversibility"));
    }
    if let Some(r) = v.get("reversibility_by") {
        let r = match r.as_object() {
            Some(r) if r.keys().all(|k| ["param", "map", "default"].contains(&k.as_str())) => r,
            _ => return Some(format!("{at}: reversibility_by must be {{param, map, default?}}")),
        };
        if !r.get("param").and_then(Value::as_str).is_some_and(|p| params.contains_key(p)) {
            return Some(format!("{at}: reversibility_by.param must be a declared parameter"));
        }
        let map_ok = r
            .get("map")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty() && m.values().all(|x| str_in(Some(x), &REVERSIBILITY)));
        if !map_ok {
            return Some(format!("{at}: reversibility_by.map must map values to reversibility classes"));
        }
        if r.get("default").is_some() && !str_in(r.get("default"), &REVERSIBILITY) {
            return Some(format!("{at}: reversibility_by.default is not a reversibility class"));
        }
    }
    let single = |k: &str, member: &str| -> bool {
        match v.get(k) {
            None => true,
            Some(Value::Object(o)) => o.len() == 1 && o.contains_key(member) && is_str(o.get(member), 128),
            Some(_) => false,
        }
    };
    if !single("mcp", "tool") {
        return Some(format!("{at}: mcp must be {{tool}}"));
    }
    if !single("openapi", "operationId") {
        return Some(format!("{at}: openapi must be {{operationId}}"));
    }
    for k in ["harm", "effects", "returns"] {
        if v2 && k == "effects" {
            continue;
        }
        if v.get(k).is_some_and(|x| !x.is_object()) {
            return Some(format!("{at}: {k} must be an object"));
        }
    }
    if v2 {
        let ef = match v.get("effects").and_then(Value::as_array) {
            Some(a) if !a.is_empty() && a.len() <= V2_EFFECTS.len() && a.iter().all(|x| x.as_str().is_some_and(|s| V2_EFFECTS.contains(&s))) => a,
            _ => return Some(format!("{at}: effects must be 1..{} known effects", V2_EFFECTS.len())),
        };
        for i in 1..ef.len() {
            if ef[i - 1].as_str() >= ef[i].as_str() {
                return Some(format!("{at}: effects must be sorted and distinct"));
            }
        }
        if (v.get("kind").and_then(Value::as_str) == Some("read")) != ef.iter().all(|x| x.as_str() == Some("read")) {
            return Some(format!("{at}: kind read must hold exactly when every effect is read"));
        }
        let tr = match v.get("traits").and_then(Value::as_array) {
            Some(a) if a.len() <= 64 && a.iter().all(|x| x.as_str().is_some_and(trait_id_shape)) => a,
            _ => return Some(format!("{at}: traits must be trait ids")),
        };
        for i in 1..tr.len() {
            if tr[i - 1].as_str() >= tr[i].as_str() {
                return Some(format!("{at}: traits must be sorted and distinct"));
            }
        }
        if !v.get("def").and_then(Value::as_str).is_some_and(|d| decode_b64u_strict(d, 32).is_some()) {
            return Some(format!("{at}: def must be a canonical base64url SHA-256 digest"));
        }
        if let Some(fe) = floors_shape_error(v.get("floors")) {
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

/// `actionSchemaShapeError(doc, {signed})`: `None` = well-formed.
pub fn action_schema_shape_error(doc: &Value, signed: bool) -> Option<String> {
    let o = match doc.as_object() {
        Some(o) => o,
        None => return Some("schema is not an object".into()),
    };
    let v2 = o.get("v").and_then(safe_int) == Some(2);
    if let Some(k) = o.keys().find(|k| !DOC_KEYS.contains(&k.as_str()) && !(v2 && DOC_KEYS_V2_EXTRA.contains(&k.as_str()))) {
        return Some(format!("unknown member '{k}'"));
    }
    if !matches!(o.get("v").and_then(safe_int), Some(1) | Some(2)) {
        return Some("unsupported schema version".into());
    }
    if o.get("kind").and_then(Value::as_str) != Some(ACTION_SCHEMA_KIND) {
        return Some(format!("kind must be '{ACTION_SCHEMA_KIND}'"));
    }
    if !is_str(o.get("site"), 2048) || !is_str(o.get("aud"), 256) || !is_str(o.get("version"), 128) {
        return Some("site, aud and version must be non-empty strings".into());
    }
    if let Some(units) = o.get("units") {
        let units = match units.as_object() {
            Some(u) => u,
            None => return Some("units must be an object".into()),
        };
        for (id, u) in units {
            if !unit_id_ok(id) || id.len() > 64 {
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
            if u.get("exponent").is_some() && !u.get("exponent").and_then(non_neg).is_some_and(|e| e <= 18) {
                return Some(format!("unit '{id}': exponent must be an integer in [0, 18]"));
            }
        }
    }
    if o.get("state").is_some_and(|s| !s.is_array()) {
        return Some("state must be an array".into());
    }
    if v2 {
        if o.get("traits_digest").is_some() && !o.get("traits_digest").and_then(Value::as_str).is_some_and(|d| decode_b64u_strict(d, 32).is_some()) {
            return Some("traits_digest must be a canonical base64url SHA-256 digest".into());
        }
        if o.get("trait_defs").is_some_and(|t| !t.as_array().is_some_and(|a| a.len() <= 64 && a.iter().all(Value::is_object))) {
            return Some("trait_defs must be an array of up to 64 objects".into());
        }
        if let Some(pk) = o.get("pack") {
            let ok = pk.as_object().is_some_and(|p| {
                p.len() == 3 && is_str(p.get("ns"), 64) && is_str(p.get("version"), 128) && p.get("root").and_then(Value::as_str).is_some_and(|r| decode_b64u_strict(r, 32).is_some())
            });
            if !ok {
                return Some("pack must be {ns, version, root}".into());
            }
        }
    }
    let verbs = match o.get("verbs").and_then(Value::as_array) {
        Some(a) if !a.is_empty() && a.len() <= MAX_SCHEMA_VERBS => a,
        _ => return Some(format!("verbs must be 1..{MAX_SCHEMA_VERBS} entries")),
    };
    let mut seen: Vec<&str> = Vec::new();
    for v in verbs {
        if let Some(e) = verb_decl_error(v, o.get("units"), v2) {
            return Some(e);
        }
        let name = v.get("verb").and_then(Value::as_str).unwrap_or("");
        if seen.contains(&name) {
            return Some(format!("verb '{name}' is declared twice"));
        }
        seen.push(name);
    }
    if signed {
        let s = match o.get("sig").and_then(Value::as_object) {
            Some(s) => s,
            None => return Some("sig must be an object".into()),
        };
        if let Some(k) = s.keys().find(|k| !SIG_KEYS.contains(&k.as_str())) {
            return Some(format!("sig: unknown member '{k}'"));
        }
        if let Some(e) = suite_err(s.get("alg")) {
            return Some(format!("sig.alg: {e}"));
        }
        if !is_str(s.get("kid"), 128) {
            return Some("sig.kid must be a non-empty string".into());
        }
        if !b64u_any_ok(s.get("value")) {
            return Some("sig.value is not canonical base64url".into());
        }
        if s.get("pq_value").is_some() && !b64u_any_ok(s.get("pq_value")) {
            return Some("sig.pq_value is not canonical base64url".into());
        }
    } else if o.contains_key("sig") {
        return Some("an unsigned schema must not carry sig".into());
    }
    if let Some(e) = strict_violation(&body_of(o)) {
        return Some(format!("malformed schema: {e}"));
    }
    None
}

fn body_of(o: &Map<String, Value>) -> Value {
    let mut b = o.clone();
    b.remove("sig");
    Value::Object(b)
}

/// `domain || strictCanonical(doc without sig)`.
fn schema_message(o: &Map<String, Value>) -> Vec<u8> {
    let mut m = ACTION_SCHEMA_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(&canonical_bytes(&body_of(o)));
    m
}

/// `verifyActionSchema(doc, keys)`: shape, `sig.kid` names a listed key, the key's `pk` is canonical 32-byte b64u, `sig.alg`
/// equals the key entry's suite, the signature verifies. GUEST: only the Ed25519 suite verifies; a PQ / hybrid key entry
/// fails closed.
pub fn verify_action_schema(doc: &Value, keys: &Value) -> Result<(), String> {
    if let Some(e) = action_schema_shape_error(doc, true) {
        return Err(e);
    }
    let o = doc.as_object().ok_or("schema is not an object")?;
    let sig = o.get("sig").and_then(Value::as_object).ok_or("sig must be an object")?;
    let kid = sig.get("kid").and_then(Value::as_str).unwrap_or("");
    let keys = keys.as_array().ok_or("the schema keys must be an array")?;
    let key = match keys.iter().find(|k| k.is_object() && k.get("kid").and_then(Value::as_str) == Some(kid)) {
        Some(k) => k,
        None => return Err(format!("no schema key with kid '{kid}'")),
    };
    if key.get("pq_pk").is_some_and(|p| !p.is_string()) {
        return Err("the schema key pq_pk must be a string".into());
    }
    let pk = match key.get("pk").and_then(Value::as_str) {
        Some(pk) if decode_b64u_strict(pk, 32).is_some() => pk,
        _ => return Err("schema key pk is not canonical base64url (32 bytes)".into()),
    };
    if let Some(e) = suite_err(key.get("alg")) {
        return Err(format!("schema key: {e}"));
    }
    let ka = resolve_sig_alg(key.get("alg"));
    let sa = resolve_sig_alg(sig.get("alg"));
    if ka.is_none() || ka != sa {
        return Err("sig.alg does not match the pinned key suite".into());
    }
    // PCA 0.4.2: every suite the guest implements (pq_suites); the PQ key is the key entry's `pq_pk`, pinned by that same
    // entry (`pqPins: {[key.pk]: key.pq_pk}`); a suite the guest lacks fails closed with `unsupported_suite`.
    let key_pq = key.get("pq_pk").and_then(Value::as_str);
    let r = crate::pq_suites::verify_pinned_suite(
        ka,
        pk,
        key_pq,
        &schema_message(o),
        sig.get("value").and_then(Value::as_str),
        sig.get("pq_value").and_then(Value::as_str),
        key_pq,
    );
    match r {
        Ok(()) => Ok(()),
        Err(crate::pq_suites::SuiteError::Unsupported(a)) => Err(format!("schema signature invalid (unsupported_suite: {a})")),
        Err(_) => Err("schema signature invalid".into()),
    }
}

/// `actionSchemaDigest(doc)` = hashCanonical({d: ACTION_SCHEMA_REF_DOMAIN, s: doc}); `None` when strict canonicalization
/// would throw.
pub fn action_schema_digest(doc: &Value) -> Option<String> {
    let w = json!({ "d": ACTION_SCHEMA_REF_DOMAIN, "s": doc });
    if strict_violation(&w).is_some() {
        return None;
    }
    Some(hash_canonical(&w))
}

/// `schemaVerb(doc, verb)`: the first verb entry named `verb`.
pub fn schema_verb<'a>(doc: &'a Value, verb: &str) -> Option<&'a Value> {
    doc.get("verbs")?.as_array()?.iter().find(|v| v.get("verb").and_then(Value::as_str) == Some(verb))
}

// ---- closed-world conformance --------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conformance {
    pub code: String,
    pub path: Option<String>,
    pub reason: String,
}

fn is_calendar_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let mut n = 0u32;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u32::from(c - b'0');
        }
        Some(n)
    };
    let (y, mo, d) = match (num(0..4), num(5..7), num(8..10)) {
        (Some(y), Some(mo), Some(d)) => (y, mo, d),
        _ => return false,
    };
    if y < 1 || !(1..=12).contains(&mo) || d < 1 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(mo - 1) as usize];
    d <= dim
}


// ---- v2 string formats (syntactic; identical in every language) -----------------------------------------------------------

/// JS `\s`.
pub(crate) fn js_space(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
/// `/^[A-Za-z][A-Za-z0-9+.\-]{0,31}:\/\/[^\s/?#]+[^\s]*$/` (scheme None) or `https` fixed.
fn url_ok(s: &str, scheme: Option<&str>) -> bool {
    let Some((sch, rest)) = s.split_once("://") else { return false };
    let scheme_ok = match scheme {
        Some(x) => sch == x,
        None => !sch.is_empty() && sch.len() <= 32 && sch.as_bytes()[0].is_ascii_alphabetic() && sch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-'),
    };
    let mut cs = rest.chars();
    let first_ok = cs.next().is_some_and(|c| !js_space(c) && c != '/' && c != '?' && c != '#');
    scheme_ok && first_ok && !rest.chars().any(js_space)
}
fn email_ok(s: &str) -> bool {
    if s.encode_utf16().count() > 254 || !s.is_ascii() {
        return false;
    }
    let Some((local, dom)) = s.split_once('@') else { return false };
    let lc = |b: u8| b.is_ascii_alphanumeric() || b".%_+-".contains(&b);
    if local.is_empty() || local.len() > 64 || !local.bytes().all(lc) {
        return false;
    }
    let labels: Vec<&str> = dom.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}
fn iban_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 15 || b.len() > 34 || !b[0].is_ascii_uppercase() || !b[1].is_ascii_uppercase() || !b[2].is_ascii_digit() || !b[3].is_ascii_digit() {
        return false;
    }
    if !b[4..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    let mut rem: u64 = 0;
    for &c in b[4..].iter().chain(b[..4].iter()) {
        let v = if c >= b'A' { u64::from(c) - 55 } else { u64::from(c) - 48 };
        rem = (if v > 9 { rem * 100 + v } else { rem * 10 + v }) % 97;
    }
    rem == 1
}
fn canonical_num(s: &str, max: u32) -> bool {
    all_digits(s) && s.parse::<u32>().is_ok_and(|n| n <= max && n.to_string() == s)
}
fn cidr_ok(s: &str) -> bool {
    let Some((addr, pre)) = s.split_once('/') else { return false };
    let o: Vec<&str> = addr.split('.').collect();
    if o.len() == 4 && o.iter().all(|x| (1..=3).contains(&x.len()) && all_digits(x)) && pre.len() <= 2 && all_digits(pre) {
        return o.iter().all(|x| canonical_num(x, 255)) && canonical_num(pre, 32);
    }
    (2..=39).contains(&addr.len())
        && addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        && addr.matches(':').count() >= 2
        && !addr.contains(":::")
        && pre.len() <= 3
        && canonical_num(pre, 128)
}
fn semver_ok(s: &str) -> bool {
    let ident = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let idents = |x: &str| x.split('.').all(ident);
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
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| all_digits(p) && (*p == "0" || !p.starts_with('0')))
}
fn id_format(f: &str) -> bool {
    // ^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$
    f.strip_prefix("id:").is_some_and(|r| {
        let segs: Vec<&str> = r.split('.').collect();
        (1..=4).contains(&segs.len()) && segs.iter().all(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    })
}
const FORMATS: [&str; 11] = ["email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256"];
fn format_known(f: &str) -> bool {
    FORMATS.contains(&f) || id_format(f)
}
/// `formatCheck(f)(s)`; `None` when the format is unknown.
fn format_ok(f: &str, s: &str) -> Option<bool> {
    let up = |n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_uppercase());
    Some(match f {
        "email" => email_ok(s),
        "url" => url_ok(s, None),
        "uri_https" => url_ok(s, Some("https")),
        "uuid" => {
            let b = s.as_bytes();
            b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(c) })
        }
        "iban" => iban_ok(s),
        "phone_e164" => s.strip_prefix('+').is_some_and(|d| (7..=15).contains(&d.len()) && all_digits(d) && !d.starts_with('0')),
        "cidr" => cidr_ok(s),
        "iso_country" => up(2),
        "iso_currency" => up(3),
        "semver" => semver_ok(s),
        "sha256" => s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        _ if id_format(f) => (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b)),
        _ => return None,
    })
}
fn format_violation(d: &Value, x: &str) -> Option<(&'static str, String)> {
    let f = d.get("format")?.as_str()?;
    match format_ok(f, x) {
        Some(true) => None,
        _ => Some(("out_of_domain", format!("not a valid {f}"))),
    }
}
/// `DATETIME_RE` + calendar date: `YYYY-MM-DDTHH:MM:SS[.fff]Z` (UTC).
fn datetime_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || *b.last().unwrap() != b'Z' || !is_calendar_date(&s[..10]) {
        return false;
    }
    let d2 = |i: usize| b[i].is_ascii_digit() && b[i + 1].is_ascii_digit();
    let n = |i: usize| u32::from(b[i] - b'0') * 10 + u32::from(b[i + 1] - b'0');
    if !(d2(11) && d2(14) && d2(17)) || n(11) > 23 || n(14) > 59 || n(17) > 59 {
        return false;
    }
    match &s[19..s.len() - 1] {
        "" => true,
        frac => frac.strip_prefix('.').is_some_and(|f| (1..=3).contains(&f.len()) && all_digits(f)),
    }
}

/// JS `x < m` / `x > m` for a safe integer `x` against a declared bound (a number; anything else: no bound).
fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
}

/// `paramValueViolation(d, x)`: `None` = in the declared domain, else `(code, reason)`.
pub fn param_value_violation(d: &Value, x: &Value) -> Option<(&'static str, String)> {
    let max_len = match d.get("max_len") {
        None | Some(Value::Null) => DEFAULT_MAX_LEN,
        Some(m) => safe_int(m).unwrap_or(DEFAULT_MAX_LEN),
    };
    let values: Vec<&str> = d.get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let has_values = d.get("values").is_some_and(|v| !v.is_null());
    let lo = num(d.get("min"));
    let hi = num(d.get("max"));
    let items_bound = |k: &str, dflt: i64| -> i64 {
        match d.get(k) {
            None | Some(Value::Null) => dflt,
            Some(m) => safe_int(m).unwrap_or(dflt),
        }
    };
    match d.get("type").and_then(Value::as_str).unwrap_or("") {
        "string" => {
            let s = match x.as_str() {
                Some(s) => s,
                None => return Some(("bad_type", "expected a string".into())),
            };
            if s.len() as i64 > max_len {
                return Some(("out_of_domain", format!("longer than {max_len} UTF-8 bytes")));
            }
            if has_values && !values.contains(&s) {
                return Some(("out_of_domain", "not one of the declared values".into()));
            }
            format_violation(d, s)
        }
        "object_ref" => {
            let s = match x.as_str() {
                Some(s) if !s.is_empty() => s,
                _ => return Some(("bad_type", "expected a non-empty id string".into())),
            };
            if s.len() as i64 > max_len {
                return Some(("out_of_domain", format!("longer than {max_len} UTF-8 bytes")));
            }
            format_violation(d, s)
        }
        "datetime" => match x.as_str() {
            None => Some(("bad_type", "expected an RFC 3339 UTC string".into())),
            Some(s) if datetime_ok(s) => None,
            Some(_) => Some(("out_of_domain", "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z".into())),
        },
        "duration" => {
            let i = match safe_int(x) {
                Some(i) => i,
                None => return Some(("bad_type", "expected a safe integer (milliseconds)".into())),
            };
            if i < 0 {
                return Some(("out_of_domain", "a duration is not negative".into()));
            }
            if lo.is_some_and(|m| (i as f64) < m) {
                return Some(("out_of_domain", format!("below min {}", js_str(d.get("min")))));
            }
            if hi.is_some_and(|m| (i as f64) > m) {
                return Some(("out_of_domain", format!("above max {}", js_str(d.get("max")))));
            }
            None
        }
        "integer" => {
            let i = match safe_int(x) {
                Some(i) => i as f64,
                None => return Some(("bad_type", "expected a safe integer".into())),
            };
            if let Some(m) = lo {
                if i < m {
                    return Some(("out_of_domain", format!("below min {}", js_str(d.get("min")))));
                }
            }
            if let Some(m) = hi {
                if i > m {
                    return Some(("out_of_domain", format!("above max {}", js_str(d.get("max")))));
                }
            }
            None
        }
        "boolean" => {
            if x.is_boolean() {
                None
            } else {
                Some(("bad_type", "expected a boolean".into()))
            }
        }
        "date" => match x.as_str() {
            None => Some(("bad_type", "expected a YYYY-MM-DD string".into())),
            Some(s) if is_calendar_date(s) => None,
            Some(_) => Some(("out_of_domain", "not a calendar date YYYY-MM-DD".into())),
        },
        "set" => {
            let a = match x.as_array() {
                Some(a) if a.iter().all(Value::is_string) => a,
                _ => return Some(("bad_type", "expected an array of strings".into())),
            };
            if !distinct_strs(a) {
                return Some(("out_of_domain", "set members must be distinct".into()));
            }
            if !a.iter().all(|e| e.as_str().is_some_and(|s| values.contains(&s))) {
                return Some(("out_of_domain", "set member not among the declared values".into()));
            }
            let n = a.len() as i64;
            if n < items_bound("min_items", 0) || n > items_bound("max_items", values.len() as i64) {
                return Some(("out_of_domain", "set size outside the declared bounds".into()));
            }
            None
        }
        "array" => {
            let a = match x.as_array() {
                Some(a) => a,
                None => return Some(("bad_type", "expected an array".into())),
            };
            let ints = d.get("items").and_then(Value::as_str) == Some("integer");
            for e in a {
                if ints {
                    let i = match safe_int(e) {
                        Some(i) => i as f64,
                        None => return Some(("bad_type", "array items must be safe integers".into())),
                    };
                    if lo.is_some_and(|m| i < m) || hi.is_some_and(|m| i > m) {
                        return Some(("out_of_domain", "array item outside min/max".into()));
                    }
                } else if !e.as_str().is_some_and(|s| s.len() as i64 <= max_len) {
                    return Some(("bad_type", format!("array items must be strings of at most {max_len} UTF-8 bytes")));
                }
            }
            let n = a.len() as i64;
            if n < items_bound("min_items", 0) || n > items_bound("max_items", DEFAULT_MAX_ITEMS) {
                return Some(("out_of_domain", "array length outside the declared bounds".into()));
            }
            None
        }
        _ => Some(("bad_type", "unknown declared type".into())),
    }
}

fn fail(code: &str, path: Option<String>, reason: String) -> Result<(), Conformance> {
    Err(Conformance { code: code.into(), path, reason })
}

/// `conformAction(doc, verb, params)` (NORMATIVE, rule 14 step 5). First failure wins:
///   1. params not a JSON object -> params_not_object; 2. no verb entry -> unknown_verb;
///   3. a params key (UTF-8 byte order) whose path is undeclared -> undeclared_param;
///   4. every declared path (UTF-8 byte order): absent and required -> missing_param; present: the value check.
pub fn conform_action(doc: &Value, verb: &str, params: &Value) -> Result<(), Conformance> {
    let params = match params.as_object() {
        Some(p) => p,
        None => return fail("params_not_object", None, "params must be a JSON object".into()),
    };
    let v = match schema_verb(doc, verb) {
        Some(v) => v,
        None => return fail("unknown_verb", None, format!("verb '{verb}' is not declared by the schema")),
    };
    let empty = Map::new();
    let decls = v.get("params").and_then(Value::as_object).unwrap_or(&empty);
    // serde_json maps iterate in byte order of the keys == compareUtf8.
    for k in params.keys() {
        let path = format!("{PARAMS_PREFIX}{k}");
        if !decls.contains_key(&path) {
            let reason = format!("parameter '{path}' is not declared for '{verb}'");
            return fail("undeclared_param", Some(path), reason);
        }
    }
    for (path, d) in decls {
        let name = path.strip_prefix(PARAMS_PREFIX).unwrap_or(path);
        let x = match params.get(name) {
            Some(x) => x,
            None => {
                if d.get("required") != Some(&Value::Bool(false)) {
                    let reason = format!("required parameter '{path}' is missing");
                    return fail("missing_param", Some(path.clone()), reason);
                }
                continue;
            }
        };
        if let Some((code, why)) = param_value_violation(d, x) {
            return fail(code, Some(path.clone()), format!("'{path}': {why}"));
        }
    }
    Ok(())
}

/// `canonProjection(doc, verb, params)` (intent-v2.ts): `env.canon` for a conforming action. Booleans -> "true"/"false",
/// sets -> strict canonical JSON of the UTF-8-sorted members, arrays -> strict canonical JSON; other types are not projected.
pub fn canon_projection(doc: &Value, verb: &str, params: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    let v = match schema_verb(doc, verb) {
        Some(v) => v,
        None => return out,
    };
    let (decls, params) = match (v.get("params").and_then(Value::as_object), params.as_object()) {
        (Some(d), Some(p)) => (d, p),
        _ => return out,
    };
    for (path, d) in decls {
        let name = path.strip_prefix(PARAMS_PREFIX).unwrap_or(path);
        let x = match params.get(name) {
            Some(x) => x,
            None => continue,
        };
        let s = match d.get("type").and_then(Value::as_str) {
            Some("boolean") => (if *x == Value::Bool(true) { "true" } else { "false" }).to_string(),
            Some("set") => match x.as_array() {
                Some(a) if a.iter().all(Value::is_string) => {
                    let mut m: Vec<Value> = a.clone();
                    m.sort_by(|p, q| p.as_str().unwrap_or("").cmp(q.as_str().unwrap_or("")));
                    canonicalize(&Value::Array(m))
                }
                _ => canonicalize(x),
            },
            Some("array") => canonicalize(x),
            _ => continue,
        };
        out.insert(name.to_string(), Value::String(s));
    }
    out
}

// ---- value-dependent reversibility (§2.3) --------------------------------------------------------------------------

fn rev_rank(s: &str) -> u8 {
    match s {
        "reversible" => 0,
        "rate_limited" => 1,
        _ => 2,
    }
}
fn verb_default_rev(v: &Value) -> String {
    match v.get("reversibility").and_then(Value::as_str) {
        Some(r) => r.to_string(),
        None => (if v.get("kind").and_then(Value::as_str) == Some("read") { "reversible" } else { "irreversible" }).to_string(),
    }
}
fn rev_by_default(r: &Value) -> String {
    r.get("default").and_then(Value::as_str).unwrap_or("irreversible").to_string()
}

/// `reversibilityOf(v, params)`: rev_S(omega) (unmapped / absent value -> `default`, else irreversible).
pub fn reversibility_of(v: &Value, params: &Value) -> String {
    let r = match v.get("reversibility_by") {
        Some(r) if r.is_object() => r,
        _ => return verb_default_rev(v),
    };
    let p = r.get("param").and_then(Value::as_str).unwrap_or("");
    let name = p.strip_prefix(PARAMS_PREFIX).unwrap_or(p);
    let key = match params.get(name) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        Some(x) => safe_int(x).map(|i| i.to_string()),
        None => None,
    };
    if let Some(k) = key {
        if let Some(c) = r.get("map").and_then(|m| m.get(&k)).and_then(Value::as_str) {
            return c.to_string();
        }
    }
    rev_by_default(r)
}

/// `verbReversibility(v)`: max over the domain (the conservative projection).
pub fn verb_reversibility(v: &Value) -> String {
    let r = match v.get("reversibility_by") {
        Some(r) if r.is_object() => r,
        _ => return verb_default_rev(v),
    };
    let empty = Map::new();
    let map = r.get("map").and_then(Value::as_object).unwrap_or(&empty);
    let p = r.get("param").and_then(Value::as_str).unwrap_or("");
    let d = v.get("params").and_then(|ps| ps.get(p));
    let ty = d.and_then(|d| d.get("type")).and_then(Value::as_str);
    let domain: Option<Vec<String>> = match ty {
        Some("boolean") => Some(vec!["true".into(), "false".into()]),
        Some("string") => d
            .and_then(|d| d.get("values"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()),
        _ => None,
    };
    let covered = domain.is_some_and(|dom| dom.iter().all(|x| map.contains_key(x)));
    let mut classes: Vec<String> = map.values().filter_map(Value::as_str).map(String::from).collect();
    if !covered {
        classes.push(rev_by_default(r));
    }
    classes.into_iter().fold("reversible".to_string(), |a, b| if rev_rank(&b) > rev_rank(&a) { b } else { a })
}
