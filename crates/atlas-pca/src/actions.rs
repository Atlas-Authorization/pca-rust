//! Action kit (native port of the small deterministic core of the reference action-kit package): strict ActionDef parse,
//! normalize and canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema
//! floor integrity check), the pack Merkle root and inclusion proof, and T(d)/eff(d). Integers and sets only; every
//! function is pure. The shared vectors pin every output. ActionSchema v2 parsing and the v2 parameter checks live in
//! `action_schema.rs`.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::is_nfc;

use super::intent_strict::{b32, nonneg, sint, sort_utf8};
use super::{b64_encode, canonicalize_strict, hash_canonical_strict, leaf_hash, merkle_root, node_hash, split, verify_b64u, verify_inclusion};

pub const ACTION_DEF_KIND: &str = "pca-action-def";
const DEF_DIGEST_DOMAIN: &str = "atlas-pca/action-def/v1";
const TRAITS_DIGEST_DOMAIN: &str = "atlas-pca/action-traits/v1";
const ROLES_DIGEST_DOMAIN: &str = "atlas-pca/action-roles/v1";
const PACK_DIGEST_DOMAIN: &str = "atlas-pca/action-pack/v1";
const REVIEW_DOMAIN: &str = "atlas-pca/action-review/v2\0";
const VERB_FACTS_DOMAIN: &str = "atlas-pca/action-verb-facts/v1";
const KEY_ROLES: [&str; 4] = ["reviewer", "importer", "model", "publisher"];

const MAX_VERB_BYTES: usize = 128;
const MAX_TITLE_BYTES: usize = 120;
const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_DEF_PARAMS: usize = 64;
const MAX_DEF_ALIASES: usize = 16;
const MAX_DEF_TRAITS: usize = 32;
const MAX_DEF_CONTEXT: usize = 16;
const MAX_DEF_SIDE_EFFECTS: usize = 16;
const MAX_TRAIT_IMPLIES_DEPTH: usize = 8;
const MAX_REGISTRY_TRAITS: usize = 512;
const PPM_MAX: i64 = 1_000_000;
/// The sentinel the test loader puts where the wire had a lone surrogate (a Rust string cannot hold one).
const LONE: char = '\u{10FFFF}';

const EFFECTS: [&str; 12] = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
const REVERSIBILITY: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const BLAST_RADII: [&str; 4] = ["one", "bounded", "tenant", "global"];
const RESOURCE_SCOPES: [&str; 4] = ["one", "set", "tenant", "global"];
const PARAM_TYPES: [&str; 9] = ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"];
const SENSITIVITIES: [&str; 3] = ["free", "material", "critical"];
const PROVENANCE: [&str; 3] = ["first_party", "tool", "agent"];
const CORE_ROLES: [&str; 26] = [
    "money.amount", "money.currency", "money.fee", "party.payee", "party.payer", "contact.email", "contact.phone", "contact.address", "person.name",
    "person.dob", "person.national_id", "credential.secret", "credential.token", "credential.key", "path.fs", "query.sql", "query.search",
    "code.source", "code.command", "url.target", "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
];
const PARAM_TAGS: [&str; 9] = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"];
const PARAM_FORMATS: [&str; 11] = ["email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256"];
const UNIT_KINDS: [&str; 5] = ["money", "count", "bytes", "duration", "ratio"];
pub(crate) const CAVEAT_KINDS: [&str; 8] = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"];
pub(crate) const CONTEXT_KEYS: [&str; 6] = ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"];
pub(crate) const PARAM_RULE_IDS: [&str; 8] = [
    "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency",
    "recipient_param_declared", "secret_not_logged",
];
const IDEMPOTENCY_MODES: [&str; 3] = ["key_param", "natural", "none"];
const REVIEW_STATES: [&str; 4] = ["authored", "unreviewed", "suggested", "confirmed"];
const BINDING_KINDS: [&str; 6] = ["mcp", "openapi", "http", "graphql", "grpc", "asyncapi"];
const ID_CLASSES: [&str; 6] = ["digits", "hex", "alnum", "slug", "uuid", "any_safe"];
const RESERVED: [&str; 3] = ["__proto__", "constructor", "prototype"];
const INT_ROLES: [&str; 4] = ["money.amount", "money.fee", "count.limit", "bytes.size"];
const PARAM_KEYS: [&str; 19] = [
    "type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags", "provenance_min",
    "sensitivity", "accumulates", "default", "principal_neutral_default", "description",
];
const DEF_KEYS: [&str; 22] = [
    "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects", "idempotency",
    "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since",
];

fn rev_rank(r: &str) -> Option<i32> {
    REVERSIBILITY.iter().position(|x| *x == r).map(|i| i as i32)
}
fn blast_ppm_of(r: &str) -> i64 {
    match r {
        "one" => 50_000,
        "bounded" => 300_000,
        "tenant" => 700_000,
        _ => 1_000_000,
    }
}
fn scope_blast(s: &str) -> &'static str {
    match s {
        "one" => "one",
        "set" => "bounded",
        "tenant" => "tenant",
        _ => "global",
    }
}
fn sens_rank(s: &str) -> i32 {
    SENSITIVITIES.iter().position(|x| *x == s).unwrap_or(0) as i32
}

#[derive(Debug, Clone)]
pub struct ActionKitError {
    pub code: String,
    pub message: String,
}
impl ActionKitError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        ActionKitError { code: code.into(), message: message.into() }
    }
}
impl std::fmt::Display for ActionKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

// ---- small helpers --------------------------------------------------------------------------------------------------------

fn is_str(v: Option<&Value>, max: usize) -> bool {
    matches!(v, Some(Value::String(x)) if !x.is_empty() && x.len() <= max)
}
fn in_set(v: Option<&Value>, set: &[&str]) -> bool {
    matches!(v, Some(Value::String(x)) if set.contains(&x.as_str()))
}
fn sort_uniq(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    xs.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}
fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}
fn vstrs(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|x| Value::String(x.clone())).collect())
}
fn lcd(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
/// `[a-z][a-z0-9_]{0,first_max-1}` then `(\.[a-z0-9_]{1,rest_max}){min..=max}`.
fn dotted(s: &str, first_max: usize, rest_max: usize, min: usize, max: usize) -> bool {
    let mut it = s.split('.');
    let f = it.next().unwrap_or("");
    if f.is_empty() || f.len() > first_max || !f.as_bytes()[0].is_ascii_lowercase() || !f.bytes().all(lcd) {
        return false;
    }
    let rest: Vec<&str> = it.collect();
    rest.len() >= min && rest.len() <= max && rest.iter().all(|p| !p.is_empty() && p.len() <= rest_max && p.bytes().all(lcd))
}
fn is_verb(s: &str) -> bool {
    dotted(s, 32, 32, 1, 5)
}
fn is_alias(s: &str) -> bool {
    dotted(s, 32, 32, 0, 5)
}
fn is_resource_type(s: &str) -> bool {
    dotted(s, 32, 32, 0, 4)
}
fn is_trait_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((a, b)) => {
            let ok = |x: &str, max: usize| !x.is_empty() && x.len() <= max && x.as_bytes()[0].is_ascii_lowercase() && x.bytes().all(lcd);
            ok(a, 32) && ok(b, 64)
        }
        None => false,
    }
}
fn lcd_parts(s: &str, min: usize, max: usize) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() >= min && p.len() <= max && p.iter().all(|x| !x.is_empty() && x.bytes().all(lcd))
}
pub(crate) fn is_context_key(k: &str) -> bool {
    CONTEXT_KEYS.contains(&k) || k.strip_prefix("session_taint_max:").is_some_and(|t| (1..=16).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'))
}
fn is_role(r: &str) -> bool {
    CORE_ROLES.contains(&r) || r.strip_prefix("id.").is_some_and(|x| lcd_parts(x, 1, 4)) || r.strip_prefix("x.").is_some_and(|x| lcd_parts(x, 2, 4))
}
fn is_format(f: &str) -> bool {
    PARAM_FORMATS.contains(&f) || f.strip_prefix("id:").is_some_and(|x| lcd_parts(x, 1, 4))
}
fn param_name_ok(n: &str) -> bool {
    let p: Vec<&str> = n.split('.').collect();
    p.len() <= 3 && p.iter().all(|x| !x.is_empty() && x.len() <= 64 && x.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
}
pub(crate) fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}
fn str_list(v: Option<&Value>, max: usize, ok: impl Fn(&str) -> bool) -> bool {
    match v.and_then(Value::as_array) {
        Some(a) => {
            a.len() <= max && a.iter().all(|x| x.as_str().is_some_and(&ok)) && a.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() == a.len()
        }
        None => false,
    }
}

// ---- strict JSON profile + ActionDef validation ---------------------------------------------------------------------------

/// Strict JSON profile: objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32.
pub fn json_profile_error(v: &Value, depth: usize) -> Option<String> {
    if depth > 32 {
        return Some("nesting deeper than 32".into());
    }
    let bad_str = |s: &str| -> Option<String> {
        if s.contains(LONE) {
            Some("string has a lone surrogate".into())
        } else if !is_nfc(s) {
            Some("string is not NFC".into())
        } else {
            None
        }
    };
    match v {
        Value::Null | Value::Bool(_) => None,
        Value::Number(_) => sint(Some(v)).is_none().then(|| "numbers must be safe integers (no floats, no -0)".into()),
        Value::String(s) => bad_str(s),
        Value::Array(a) => a.iter().find_map(|x| json_profile_error(x, depth + 1)),
        Value::Object(o) => o.iter().find_map(|(k, x)| bad_str(k).map(|_| "member name is not NFC / has a lone surrogate".to_string()).or_else(|| json_profile_error(x, depth + 1))),
    }
}

fn in_class(s: &str, c: &str) -> bool {
    s.chars().all(|ch| match c {
        "digits" => ch.is_ascii_digit(),
        "hex" => ch.is_ascii_digit() || ('a'..='f').contains(&ch),
        "alnum" => ch.is_ascii_alphanumeric(),
        "slug" => ch.is_ascii_digit() || ch.is_ascii_lowercase() || ch == '-' || ch == '_',
        "uuid" => ch.is_ascii_digit() || ('a'..='f').contains(&ch) || ch == '-',
        _ => ch.is_ascii_alphanumeric() || "._-:/".contains(ch),
    })
}

fn id_pattern_error(p: Option<&Value>) -> Option<String> {
    let bad = || Some("resource.id must be '*', {exact} or {prefix, class, len}".to_string());
    let p = p?;
    if p.as_str() == Some("*") {
        return None;
    }
    let o = match p.as_object() {
        Some(o) => o,
        None => return bad(),
    };
    let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
    keys.sort();
    if keys == ["exact"] {
        return match o["exact"].as_str() {
            Some(e) if (1..=128).contains(&e.len()) && in_class(e, "any_safe") => None,
            _ => Some("resource.id.exact must be 1..128 safe characters".into()),
        };
    }
    if keys != ["class", "len", "prefix"] {
        return bad();
    }
    match o["prefix"].as_str() {
        Some(x) if x.len() <= 32 && in_class(x, "any_safe") => {}
        _ => return Some("resource.id.prefix must be up to 32 safe characters".into()),
    }
    if !in_set(o.get("class"), &ID_CLASSES) {
        return Some("resource.id.class is not an id class".into());
    }
    let len = o["len"].as_array();
    let ns: Vec<i64> = len.map(|l| l.iter().filter_map(|n| sint(Some(n)).filter(|n| (1..=128).contains(n))).collect()).unwrap_or_default();
    if len.map(Vec::len) != Some(2) || ns.len() != 2 {
        return Some("resource.id.len must be [min, max] in 1..128".into());
    }
    if ns[0] > ns[1] {
        return Some("resource.id.len: min > max".into());
    }
    if o["class"].as_str() == Some("uuid") && (o["prefix"].as_str() != Some("") || ns[0] != 36 || ns[1] != 36) {
        return Some("a uuid id has no prefix and length exactly [36, 36]".into());
    }
    None
}

fn param_error(name: &str, p: &Value, names: &BTreeSet<&str>) -> Option<String> {
    let p = match p.as_object() {
        Some(p) => p,
        None => return Some(format!("{name}: declaration must be an object")),
    };
    if let Some(k) = p.keys().find(|k| !PARAM_KEYS.contains(&k.as_str())) {
        return Some(format!("{name}: unknown member '{k}'"));
    }
    if !in_set(p.get("type"), &PARAM_TYPES) {
        return Some(format!("{name}: unknown type"));
    }
    let t = p["type"].as_str().unwrap_or("");
    if p.contains_key("role") && !p["role"].as_str().is_some_and(is_role) {
        return Some(format!("{name}: unknown role"));
    }
    if p.get("role").and_then(Value::as_str).is_some_and(|r| INT_ROLES.contains(&r)) && t != "integer" {
        return Some(format!("{name}: role requires an integer parameter"));
    }
    if p.get("required").is_some_and(|r| !r.is_boolean()) {
        return Some(format!("{name}: required must be a boolean"));
    }
    if let Some(vs) = p.get("values") {
        let a = vs.as_array();
        if !a.is_some_and(|a| !a.is_empty() && a.len() <= 256 && a.iter().all(|x| is_str(Some(x), 256))) {
            return Some(format!("{name}: values must be 1..256 non-empty strings"));
        }
        let a = a.unwrap();
        if a.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() != a.len() {
            return Some(format!("{name}: values must be distinct"));
        }
        if t != "string" && t != "set" {
            return Some(format!("{name}: values apply to string and set only"));
        }
    }
    if t == "set" && !p.contains_key("values") {
        return Some(format!("{name}: a set needs values"));
    }
    let int_like = t == "integer" || t == "duration" || (t == "array" && p.get("items").and_then(Value::as_str) == Some("integer"));
    for k in ["min", "max"] {
        if p.contains_key(k) && (sint(p.get(k)).is_none() || !int_like) {
            return Some(format!("{name}: {k} must be a safe integer on an integer parameter"));
        }
    }
    if let (Some(lo), Some(hi)) = (sint(p.get("min")), sint(p.get("max"))) {
        if lo > hi {
            return Some(format!("{name}: min > max"));
        }
    }
    if p.contains_key("max_len") && !(sint(p.get("max_len")).is_some_and(|m| (1..=16_777_216).contains(&m)) && ["string", "array", "object_ref"].contains(&t)) {
        return Some(format!("{name}: max_len must be 1..16777216 on a string or array"));
    }
    if p.contains_key("items") && (t != "array" || !is_str(p.get("items"), 64)) {
        return Some(format!("{name}: items applies to array only"));
    }
    for k in ["min_items", "max_items"] {
        if p.contains_key(k) && (nonneg(p.get(k)).is_none() || (t != "set" && t != "array")) {
            return Some(format!("{name}: {k} must be a non-negative integer on a set or array"));
        }
    }
    if let (Some(lo), Some(hi)) = (sint(p.get("min_items")), sint(p.get("max_items"))) {
        if lo > hi {
            return Some(format!("{name}: min_items > max_items"));
        }
    }
    if p.contains_key("format") && (!p["format"].as_str().is_some_and(is_format) || (t != "string" && t != "object_ref")) {
        return Some(format!("{name}: format must be a known format on a string parameter"));
    }
    if let Some(u) = p.get("unit") {
        if t != "integer" {
            return Some(format!("{name}: unit applies to integer parameters only"));
        }
        let u = match u.as_object() {
            Some(u) if in_set(u.get("kind"), &UNIT_KINDS) => u,
            _ => return Some(format!("{name}: unit.kind is not a known kind")),
        };
        if u["kind"].as_str() == Some("money") {
            if u.keys().any(|k| !["kind", "ccy", "exp"].contains(&k.as_str())) {
                return Some(format!("{name}: unit has unknown members"));
            }
            if !sint(u.get("exp")).is_some_and(|e| (0..=18).contains(&e)) {
                return Some(format!("{name}: unit.exp must be an integer in 0..18"));
            }
            match u.get("ccy") {
                Some(Value::String(c)) => {
                    if !(c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase())) {
                        return Some(format!("{name}: unit.ccy must be an ISO 4217 style code"));
                    }
                }
                Some(Value::Object(c)) if c.len() == 1 && c.get("from").and_then(Value::as_str).is_some_and(|f| names.contains(f)) => {}
                _ => return Some(format!("{name}: unit.ccy.from must name a declared parameter")),
            }
        } else if u.len() != 1 {
            return Some(format!("{name}: unit has unknown members"));
        }
    }
    if let Some(tg) = p.get("tags") {
        let ok = tg.as_array().is_some_and(|a| {
            a.len() <= PARAM_TAGS.len() && a.iter().all(|x| in_set(Some(x), &PARAM_TAGS)) && a.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() == a.len()
        });
        if !ok {
            return Some(format!("{name}: tags must be distinct known tags"));
        }
    }
    if p.contains_key("provenance_min") && !in_set(p.get("provenance_min"), &PROVENANCE) {
        return Some(format!("{name}: unknown provenance_min"));
    }
    if p.contains_key("sensitivity") && !in_set(p.get("sensitivity"), &SENSITIVITIES) {
        return Some(format!("{name}: unknown sensitivity"));
    }
    if let Some(a) = p.get("accumulates") {
        if t != "integer" {
            return Some(format!("{name}: accumulates applies to integer parameters only"));
        }
        let ok = a.as_array().is_some_and(|a| {
            !a.is_empty()
                && a.len() <= 8
                && a.iter().all(|x| x.as_str().is_some_and(|u| u.len() <= 64 && !u.is_empty() && u.split('.').all(|g| !g.is_empty() && g.bytes().all(lcd))))
                && a.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() == a.len()
        });
        if !ok {
            return Some(format!("{name}: accumulates must be 1..8 distinct unit ids"));
        }
    }
    if p.get("default") == Some(&Value::Null) {
        return Some(format!("{name}: default must not be null (absent = no default)"));
    }
    if p.get("principal_neutral_default").is_some_and(|x| !x.is_boolean()) {
        return Some(format!("{name}: principal_neutral_default must be a boolean"));
    }
    if p.get("principal_neutral_default") == Some(&Value::Bool(true)) && !p.contains_key("default") {
        return Some(format!("{name}: principal_neutral_default needs a default"));
    }
    if p.contains_key("description") && !is_str(p.get("description"), MAX_DESCRIPTION_BYTES) {
        return Some(format!("{name}: description must be a string up to {MAX_DESCRIPTION_BYTES} bytes"));
    }
    None
}

fn bindings_error(b: &Value) -> Option<String> {
    let b = match b.as_object() {
        Some(b) => b,
        None => return Some("bindings must be an object".into()),
    };
    for (k, v) in b {
        let (req, opt): (&[&str], &[&str]) = match k.as_str() {
            "mcp" => (&["tool"], &[]),
            "openapi" => (&["operationId"], &["method", "path"]),
            "http" => (&["method", "path"], &[]),
            "graphql" => (&["op", "field"], &[]),
            "grpc" => (&["service", "method"], &[]),
            "asyncapi" => (&["channel", "op"], &[]),
            _ => return Some(format!("bindings: unknown kind '{k}'")),
        };
        debug_assert!(BINDING_KINDS.contains(&k.as_str()));
        let v = match v.as_object() {
            Some(v) => v,
            None => return Some(format!("bindings.{k} must be an object")),
        };
        if let Some(m) = v.keys().find(|m| !req.contains(&m.as_str()) && !opt.contains(&m.as_str())) {
            return Some(format!("bindings.{k}: unknown member '{m}'"));
        }
        for m in req {
            if !is_str(v.get(*m), 256) {
                return Some(format!("bindings.{k}.{m} must be a non-empty string"));
            }
        }
        for m in opt {
            if v.contains_key(*m) && !is_str(v.get(*m), 256) {
                return Some(format!("bindings.{k}.{m} must be a non-empty string"));
            }
        }
    }
    if let Some(g) = b.get("graphql") {
        if !in_set(g.get("op"), &["query", "mutation", "subscription"]) {
            return Some("bindings.graphql.op is not a GraphQL operation kind".into());
        }
    }
    if let Some(g) = b.get("asyncapi") {
        if !in_set(g.get("op"), &["send", "receive"]) {
            return Some("bindings.asyncapi.op must be send or receive".into());
        }
    }
    None
}

fn review_error(r: Option<&Value>) -> Option<String> {
    let r = match r.and_then(Value::as_object) {
        Some(r) => r,
        None => return Some("review must be an object".into()),
    };
    if let Some(k) = r.keys().find(|k| !["state", "attestation", "suggested_by"].contains(&k.as_str())) {
        return Some(format!("review: unknown member '{k}'"));
    }
    if !in_set(r.get("state"), &REVIEW_STATES) {
        return Some("review.state is not a review state".into());
    }
    if let Some(a) = r.get("attestation") {
        let a = match a.as_object() {
            Some(a) => a,
            None => return Some("review.attestation must be an object".into()),
        };
        if let Some(k) = a.keys().find(|k| !["def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"].contains(&k.as_str())) {
            return Some(format!("review.attestation: unknown member '{k}'"));
        }
        if !is_str(a.get("def_digest"), 64) || !is_str(a.get("traits_digest"), 64) || !is_str(a.get("facts_digest"), 64) || !is_str(a.get("reviewer_kid"), 128) || nonneg(a.get("ts")).is_none() {
            return Some("review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required".into());
        }
        if !str_list(a.get("final_traits"), MAX_DEF_TRAITS, is_trait_id) {
            return Some("review.attestation.final_traits must be distinct trait ids".into());
        }
        let ok = a.get("dismissed").and_then(Value::as_array).is_some_and(|d| {
            d.len() <= MAX_DEF_TRAITS
                && d.iter().all(|x| {
                    x.as_object().is_some_and(|x| x.len() == 2 && x.get("trait").and_then(Value::as_str).is_some_and(is_trait_id) && is_str(x.get("reason"), 256))
                })
        });
        if !ok {
            return Some("review.attestation.dismissed must be {trait, reason} entries".into());
        }
        if a.contains_key("sig") && !is_str(a.get("sig"), 4096) {
            return Some("review.attestation.sig must be a string".into());
        }
    }
    None
}

/// `None` if `x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never panics.
pub fn validate_def(x: &Value) -> Option<String> {
    if let Some(je) = json_profile_error(x, 0) {
        return Some(format!("not strict JSON: {je}"));
    }
    let x = match x.as_object() {
        Some(x) => x,
        None => return Some("def must be an object".into()),
    };
    if let Some(k) = x.keys().find(|k| !DEF_KEYS.contains(&k.as_str())) {
        return Some(format!("unknown member '{k}'"));
    }
    if sint(x.get("v")) != Some(1) {
        return Some("unsupported def version".into());
    }
    if x.get("kind").and_then(Value::as_str) != Some(ACTION_DEF_KIND) {
        return Some(format!("kind must be '{ACTION_DEF_KIND}'"));
    }
    let verb = match x.get("verb").and_then(Value::as_str) {
        Some(v) if is_verb(v) && v.len() <= MAX_VERB_BYTES => v,
        _ => return Some("verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)".into()),
    };
    if x.contains_key("aliases") && (!str_list(x.get("aliases"), MAX_DEF_ALIASES, |s| is_alias(s) && s.len() <= MAX_VERB_BYTES) || strs(&x["aliases"]).iter().any(|a| a == verb)) {
        return Some("aliases must be distinct verb-shaped names other than the verb".into());
    }
    if !is_str(x.get("title"), MAX_TITLE_BYTES) {
        return Some(format!("title must be a non-empty string up to {MAX_TITLE_BYTES} bytes"));
    }
    if x.contains_key("description") && !is_str(x.get("description"), MAX_DESCRIPTION_BYTES) {
        return Some("description must be a string".into());
    }
    if !str_list(x.get("effects"), EFFECTS.len(), |s| EFFECTS.contains(&s)) || x["effects"].as_array().is_some_and(Vec::is_empty) {
        return Some("effects must be 1..12 distinct known effects".into());
    }
    let r = match x.get("resource").and_then(Value::as_object) {
        Some(r) if r.len() == 3 && r.contains_key("id") && r.contains_key("scope") && r.contains_key("type") => r,
        _ => return Some("resource must be {type, id, scope}".into()),
    };
    if !r["type"].as_str().is_some_and(|t| is_resource_type(t) && t.len() <= 128) {
        return Some("resource.type is malformed".into());
    }
    if let Some(e) = id_pattern_error(r.get("id")) {
        return Some(e);
    }
    if !in_set(r.get("scope"), &RESOURCE_SCOPES) {
        return Some("resource.scope is not a scope".into());
    }
    let params = match x.get("params").and_then(Value::as_object) {
        Some(p) => p,
        None => return Some("params must be an object".into()),
    };
    let names: Vec<&str> = params.keys().map(String::as_str).collect();
    if names.len() > MAX_DEF_PARAMS {
        return Some(format!("more than {MAX_DEF_PARAMS} parameters"));
    }
    let name_set: BTreeSet<&str> = names.iter().copied().collect();
    for n in &names {
        if !param_name_ok(n) {
            return Some(format!("param name '{n}' is malformed"));
        }
        if n.split('.').any(|s| RESERVED.contains(&s)) {
            return Some(format!("param name '{n}' is reserved"));
        }
        for m in &names {
            if m != n && m.starts_with(&format!("{n}.")) {
                return Some(format!("param '{n}' is both a value and the parent of '{m}'"));
            }
        }
    }
    for n in &names {
        if let Some(e) = param_error(n, &params[*n], &name_set) {
            return Some(e);
        }
    }
    if let Some(rv) = x.get("reversibility") {
        if rv.is_string() {
            if !in_set(Some(rv), &REVERSIBILITY) {
                return Some("unknown reversibility class".into());
            }
        } else {
            let o = match rv.as_object() {
                Some(o) if o.keys().all(|k| ["by", "map", "default"].contains(&k.as_str())) => o,
                _ => return Some("reversibility must be a class or {by, map, default?}".into()),
            };
            if !o.get("by").and_then(Value::as_str).is_some_and(|b| name_set.contains(b)) {
                return Some("reversibility.by must name a declared parameter".into());
            }
            let ok = o.get("map").and_then(Value::as_object).is_some_and(|m| {
                !m.is_empty() && m.len() <= 256 && m.iter().all(|(k, v)| !k.is_empty() && k.len() <= 128 && in_set(Some(v), &REVERSIBILITY))
            });
            if !ok {
                return Some("reversibility.map must map values to reversibility classes".into());
            }
            if o.contains_key("default") && !in_set(o.get("default"), &REVERSIBILITY) {
                return Some("reversibility.default is not a class".into());
            }
        }
    }
    if let Some(b) = x.get("blast") {
        let o = match b.as_object() {
            Some(o) if o.keys().all(|k| k == "radius" || k == "ppm") && in_set(o.get("radius"), &BLAST_RADII) => o,
            _ => return Some("blast must be {radius, ppm?}".into()),
        };
        if o.contains_key("ppm") && !sint(o.get("ppm")).is_some_and(|p| (0..=PPM_MAX).contains(&p)) {
            return Some("blast.ppm must be an integer in 0..1000000".into());
        }
    }
    if let Some(s) = x.get("side_effects") {
        let ok = s.as_array().is_some_and(|a| {
            a.len() <= MAX_DEF_SIDE_EFFECTS
                && a.iter().all(|e| e.as_object().is_some_and(|e| e.len() == 2 && is_str(e.get("target"), 128) && in_set(e.get("kind"), &EFFECTS)))
        });
        if !ok {
            return Some("side_effects must be {target, kind} entries".into());
        }
    }
    if let Some(i) = x.get("idempotency") {
        let o = match i.as_object() {
            Some(o) if o.keys().all(|k| k == "mode" || k == "param") && in_set(o.get("mode"), &IDEMPOTENCY_MODES) => o,
            _ => return Some("idempotency must be {mode, param?}".into()),
        };
        let bad = if o["mode"].as_str() == Some("key_param") { !o.get("param").and_then(Value::as_str).is_some_and(|p| name_set.contains(p)) } else { o.contains_key("param") };
        if bad {
            return Some("idempotency.param is required for key_param (a declared parameter) and forbidden otherwise".into());
        }
    }
    if x.contains_key("context") && !str_list(x.get("context"), MAX_DEF_CONTEXT, is_context_key) {
        return Some("context must be distinct known context keys".into());
    }
    if x.contains_key("traits") && !str_list(x.get("traits"), MAX_DEF_TRAITS, is_trait_id) {
        return Some("traits must be distinct trait ids".into());
    }
    if x.get("audience").is_some_and(|a| a.as_str() != Some("resource")) {
        return Some("audience must be 'resource'".into());
    }
    if x.contains_key("compensates") && !x["compensates"].as_str().is_some_and(is_verb) {
        return Some("compensates must be a verb".into());
    }
    if let Some(b) = x.get("bindings") {
        if let Some(e) = bindings_error(b) {
            return Some(e);
        }
    }
    if let Some(ex) = x.get("examples") {
        let a = match ex.as_array() {
            Some(a) if a.len() <= 32 => a,
            _ => return Some("examples must be an array of up to 32 entries".into()),
        };
        for e in a {
            let ok = e.as_object().is_some_and(|e| {
                e.keys().all(|k| ["params", "under", "expect"].contains(&k.as_str())) && e.get("params").is_some_and(Value::is_object) && in_set(e.get("expect"), &["allow", "escalate", "deny"])
            });
            if !ok {
                return Some("example must be {params, under?, expect}".into());
            }
        }
    }
    if let Some(e) = review_error(x.get("review")) {
        return Some(e);
    }
    if let Some(s) = x.get("source") {
        let ok = s.as_object().is_some_and(|s| {
            s.keys().all(|k| ["kind", "uri", "spec_digest", "licence", "imported_at"].contains(&k.as_str()))
                && is_str(s.get("kind"), 64)
                && is_str(s.get("uri"), 2048)
                && is_str(s.get("spec_digest"), 128)
                && is_str(s.get("licence"), 128)
                && (!s.contains_key("imported_at") || nonneg(s.get("imported_at")).is_some())
        });
        if !ok {
            return Some("source must be {kind, uri, spec_digest, licence, imported_at?}".into());
        }
    }
    if x.contains_key("since") && !is_str(x.get("since"), 64) {
        return Some("since must be a string".into());
    }
    None
}

// ---- profile lattice + trait registry -------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub risk: i64,
    pub rev: String,
    pub blast_ppm: i64,
    pub esc: i64,
    pub caveats: Vec<String>,
    pub context: Vec<String>,
    pub prules: Vec<String>,
}

impl Profile {
    pub fn bottom() -> Profile {
        Profile { risk: 0, rev: "reversible".into(), blast_ppm: 0, esc: 0, caveats: vec![], context: vec![], prules: vec![] }
    }
    pub fn to_value(&self) -> Value {
        json!({"risk": self.risk, "rev": self.rev, "blast_ppm": self.blast_ppm, "esc": self.esc,
               "caveats": self.caveats, "context": self.context, "prules": self.prules})
    }
    /// A well-formed canonical profile (`profile_error` is None), else None.
    pub fn from_value(v: &Value) -> Option<Profile> {
        if profile_error(v).is_some() {
            return None;
        }
        Some(Profile {
            risk: sint(v.get("risk"))?,
            rev: v["rev"].as_str()?.into(),
            blast_ppm: sint(v.get("blast_ppm"))?,
            esc: sint(v.get("esc"))?,
            caveats: strs(&v["caveats"]),
            context: strs(&v["context"]),
            prules: strs(&v["prules"]),
        })
    }
}

fn int_in(v: Option<&Value>, lo: i64, hi: i64) -> bool {
    sint(v).is_some_and(|x| (lo..=hi).contains(&x))
}

pub fn profile_error(p: &Value) -> Option<String> {
    let o = match p.as_object() {
        Some(o) => o,
        None => return Some("profile must be an object".into()),
    };
    if let Some(k) = o.keys().find(|k| !["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"].contains(&k.as_str())) {
        return Some(format!("profile: unknown member '{k}'"));
    }
    if !int_in(o.get("risk"), 0, 3) {
        return Some("profile.risk must be an integer in 0..3".into());
    }
    if !in_set(o.get("rev"), &REVERSIBILITY) {
        return Some("profile.rev is not a reversibility class".into());
    }
    if !int_in(o.get("blast_ppm"), 0, PPM_MAX) {
        return Some("profile.blast_ppm must be an integer in 0..1000000".into());
    }
    if !int_in(o.get("esc"), 0, 3) {
        return Some("profile.esc must be an integer in 0..3".into());
    }
    for name in ["caveats", "context", "prules"] {
        let ok_item = |x: &Value| match name {
            "caveats" => in_set(Some(x), &CAVEAT_KINDS),
            "context" => x.as_str().is_some_and(is_context_key),
            _ => in_set(Some(x), &PARAM_RULE_IDS),
        };
        let a = match o.get(name).and_then(Value::as_array) {
            Some(a) if a.len() <= 64 && a.iter().all(ok_item) => a,
            _ => return Some(format!("profile.{name} must be an array of known {name} entries")),
        };
        if a.windows(2).any(|w| w[0].as_str() >= w[1].as_str()) {
            return Some(format!("profile.{name} must be sorted and distinct"));
        }
    }
    None
}

pub fn join(p: &Profile, q: &Profile) -> Profile {
    Profile {
        risk: p.risk.max(q.risk),
        rev: if rev_rank(&p.rev) >= rev_rank(&q.rev) { p.rev.clone() } else { q.rev.clone() },
        blast_ppm: p.blast_ppm.max(q.blast_ppm),
        esc: p.esc.max(q.esc),
        caveats: sort_uniq(p.caveats.iter().chain(&q.caveats).cloned()),
        context: sort_uniq(p.context.iter().chain(&q.context).cloned()),
        prules: sort_uniq(p.prules.iter().chain(&q.prules).cloned()),
    }
}

fn subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}

pub fn leq(p: &Profile, q: &Profile) -> bool {
    p.risk <= q.risk
        && rev_rank(&p.rev) <= rev_rank(&q.rev)
        && p.blast_ppm <= q.blast_ppm
        && p.esc <= q.esc
        && subset(&p.caveats, &q.caveats)
        && subset(&p.context, &q.context)
        && subset(&p.prules, &q.prules)
}

#[derive(Debug, Clone)]
pub struct TraitDef {
    pub id: String,
    pub implies: Vec<String>,
    pub floor: Profile,
    pub card_phrase: String,
}

#[derive(Debug, Clone)]
pub struct Registry {
    pub traits: BTreeMap<String, TraitDef>,
}

/// Parse a trait definition from JSON (a custom trait of a signed document), checking its own shape.
pub fn parse_trait_def(v: &Value) -> Result<TraitDef, String> {
    let o = v.as_object().ok_or("trait must be an object")?;
    let id = o.get("id").and_then(Value::as_str).filter(|i| is_trait_id(i)).ok_or("trait id is malformed")?;
    let implies = o.get("implies").and_then(Value::as_array).filter(|a| a.len() <= 8 && a.iter().all(Value::is_string)).ok_or("implies must be up to 8 distinct trait ids")?;
    let implies = strs(&Value::Array(implies.clone()));
    if implies.iter().collect::<BTreeSet<_>>().len() != implies.len() {
        return Err(format!("trait '{id}': implies must be up to 8 distinct trait ids"));
    }
    let floor_v = o.get("floor").ok_or("floor is missing")?;
    if let Some(e) = profile_error(floor_v) {
        return Err(format!("trait '{id}': {e}"));
    }
    let cp = o.get("card_phrase").and_then(Value::as_str).filter(|c| (1..=120).contains(&utf16_len(c))).ok_or("card_phrase must be a non-empty string up to 120 characters")?;
    Ok(TraitDef { id: id.into(), implies, floor: Profile::from_value(floor_v).ok_or("bad floor")?, card_phrase: cp.into() })
}

/// `None` if `defs` form a valid registry, else the first reason.
pub fn registry_error(defs: &[TraitDef], core: bool) -> Option<String> {
    if defs.len() > MAX_REGISTRY_TRAITS {
        return Some(format!("a registry holds at most {MAX_REGISTRY_TRAITS} traits"));
    }
    let mut by: BTreeMap<&str, &TraitDef> = BTreeMap::new();
    for t in defs {
        if t.id.starts_with("pca.") && !core {
            return Some(format!("trait '{}': the pca. namespace is reserved for core traits", t.id));
        }
        if by.insert(&t.id, t).is_some() {
            return Some(format!("trait '{}' is defined twice", t.id));
        }
    }
    for t in defs {
        for u in &t.implies {
            match by.get(u.as_str()) {
                None => return Some(format!("trait '{}' implies unknown trait '{u}'", t.id)),
                Some(ud) if !leq(&ud.floor, &t.floor) => return Some(format!("trait '{}': floor is below the floor of implied '{u}'", t.id)),
                _ => {}
            }
        }
    }
    fn walk<'a>(id: &'a str, by: &BTreeMap<&'a str, &'a TraitDef>, depth: &mut BTreeMap<&'a str, i64>, visiting: &mut BTreeSet<&'a str>) -> i64 {
        if let Some(d) = depth.get(id) {
            return *d;
        }
        if !visiting.insert(id) {
            return -1;
        }
        let mut d = 1;
        for u in &by[id].implies {
            let du = walk(u, by, depth, visiting);
            if du < 0 {
                return -1;
            }
            d = d.max(du + 1);
        }
        visiting.remove(id);
        depth.insert(id, d);
        d
    }
    let (mut depth, mut visiting) = (BTreeMap::new(), BTreeSet::new());
    for t in defs {
        let d = walk(&t.id, &by, &mut depth, &mut visiting);
        if d < 0 {
            return Some(format!("trait '{}': implies cycle", t.id));
        }
        if d > MAX_TRAIT_IMPLIES_DEPTH as i64 {
            return Some(format!("trait '{}': implies depth {d} exceeds {MAX_TRAIT_IMPLIES_DEPTH}", t.id));
        }
    }
    None
}

pub fn build_registry(defs: Vec<TraitDef>, core: bool) -> Result<Registry, ActionKitError> {
    if let Some(e) = registry_error(&defs, core) {
        return Err(ActionKitError::new("bad_registry", e));
    }
    Ok(Registry { traits: defs.into_iter().map(|t| (t.id.clone(), t)).collect() })
}

/// Core registry extended with custom traits (JSON), which must not use `pca.` and must extend what they imply.
pub fn extend_registry(base: &Registry, custom: &[Value]) -> Result<Registry, ActionKitError> {
    let mut all: Vec<TraitDef> = base.traits.values().cloned().collect();
    for c in custom {
        let t = parse_trait_def(c).map_err(|e| ActionKitError::new("bad_registry", e))?;
        if base.traits.contains_key(&t.id) || t.id.starts_with("pca.") {
            return Err(ActionKitError::new("bad_registry", format!("custom trait '{}' may not redefine a core trait", t.id)));
        }
        all.push(t);
    }
    build_registry(all, true)
}

pub fn closure(reg: &Registry, ids: &[String]) -> Result<Vec<String>, ActionKitError> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = ids.to_vec();
    while let Some(id) = stack.pop() {
        if seen.contains(&id) {
            continue;
        }
        let t = reg.traits.get(&id).ok_or_else(|| ActionKitError::new("unknown_trait", format!("unknown trait '{id}'")))?;
        stack.extend(t.implies.iter().cloned());
        seen.insert(id);
    }
    Ok(seen.into_iter().collect())
}

pub fn floor_of(reg: &Registry, ids: &[String]) -> Result<Profile, ActionKitError> {
    Ok(closure(reg, ids)?.iter().fold(Profile::bottom(), |acc, i| join(&acc, &reg.traits[i].floor)))
}

pub struct GrantFacts {
    pub caveats: Vec<String>,
    pub max_esc: i64,
    pub preauth_esc: i64,
}

/// FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a caveat or context key is missing or rho.esc > G.preauth_esc; else allow.
pub fn floor_decision(g: &GrantFacts, call_context: &[String], rho: &Profile) -> &'static str {
    if rho.esc > g.max_esc {
        return "deny";
    }
    if !subset(&rho.caveats, &g.caveats) || !subset(&rho.context, call_context) || rho.esc > g.preauth_esc {
        return "escalate";
    }
    "allow"
}

type Row = (&'static str, &'static [&'static str], i64, &'static str, i64, i64, &'static [&'static str], &'static [&'static str], &'static [&'static str], &'static str);
// (name, implies, risk, rev, blast_ppm, esc, caveats, context, prules, card phrase)
const TABLE: [Row; 22] = [
    ("money_moving", &[], 3, "rate_limited", 700_000, 2, &["amount_cap", "count_cap", "window"], &["idempotency"], &["money_has_currency", "money_amount_bounded", "pay_has_idempotency"], "moves money"),
    ("destructive", &[], 2, "rate_limited", 0, 1, &["resource_scope"], &[], &["id_not_wildcard"], "deletes or destroys data"),
    ("irreversible", &[], 2, "irreversible", 0, 1, &[], &["fresh_revocation"], &[], "cannot be undone"),
    ("external_communication", &[], 2, "irreversible", 0, 0, &["recipient_scope", "rate_cap"], &[], &["recipient_param_declared"], "sends to people outside your organisation"),
    ("data_export", &[], 2, "reversible", 0, 0, &["resource_scope", "count_cap"], &[], &["export_bounded"], "exports data"),
    ("privilege_change", &[], 3, "reversible", 0, 3, &["resource_scope", "short_expiry"], &[], &[], "changes who can do what"),
    ("code_execution", &[], 3, "irreversible", 0, 2, &["resource_scope"], &["sandbox_attested"], &[], "runs code or commands"),
    ("credential_access", &[], 3, "reversible", 0, 3, &[], &[], &["secret_not_logged"], "reads or handles credentials"),
    ("bulk", &[], 2, "reversible", 0, 0, &["count_cap"], &[], &["array_bounded"], "acts on many items at once"),
    ("pii_access", &[], 1, "reversible", 0, 0, &["resource_scope"], &[], &[], "touches personal data"),
    ("public_exposure", &[], 2, "irreversible", 0, 1, &[], &[], &[], "makes content public"),
    ("persistence", &[], 2, "reversible", 0, 0, &["short_expiry"], &["revocable"], &[], "creates standing access or infrastructure"),
    ("infra_mutation", &[], 2, "rate_limited", 0, 0, &["resource_scope"], &[], &[], "changes infrastructure"),
    ("cost_incurring", &[], 1, "reversible", 0, 0, &["amount_cap"], &[], &[], "incurs cost"),
    ("legal_binding", &[], 3, "irreversible", 0, 3, &[], &[], &[], "legally or cryptographically binds you"),
    ("impersonation", &["external_communication"], 2, "reversible", 0, 1, &[], &[], &[], "acts as a person"),
    ("network_egress", &[], 1, "reversible", 0, 0, &["recipient_scope"], &[], &[], "reaches out to the network"),
    ("financial_data_read", &[], 1, "reversible", 0, 0, &["resource_scope"], &[], &[], "reads financial data"),
    ("regulated_data", &[], 2, "reversible", 0, 1, &[], &[], &[], "handles regulated data"),
    ("scheduled", &[], 2, "reversible", 0, 0, &["short_expiry", "count_cap"], &[], &[], "runs later or repeatedly"),
    ("unreviewed", &[], 3, "irreversible", 1_000_000, 2, &["approval_ref", "resource_scope"], &["dry_run_first"], &[], "has not been reviewed yet"),
    ("agent_spawning", &[], 2, "reversible", 0, 0, &["count_cap"], &[], &[], "starts another agent"),
];

fn owned(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// The core registry (22 traits).
pub fn core_registry() -> Registry {
    let mut floors: BTreeMap<String, Profile> = BTreeMap::new();
    let mut defs = Vec::new();
    for (name, implies, risk, rev, blast, esc, cav, ctx, pr, phrase) in TABLE {
        let id = format!("pca.{name}");
        let imp: Vec<String> = implies.iter().map(|n| format!("pca.{n}")).collect();
        let mut fl = Profile { risk, rev: rev.into(), blast_ppm: blast, esc, caveats: sort_uniq(owned(cav)), context: sort_uniq(owned(ctx)), prules: sort_uniq(owned(pr)) };
        for u in &imp {
            fl = join(&fl, &floors[u]);
        }
        floors.insert(id.clone(), fl.clone());
        defs.push(TraitDef { id, implies: imp, floor: fl, card_phrase: phrase.into() });
    }
    build_registry(defs, true).expect("the core registry is valid")
}

const EFFECT_TRAITS: [(&str, &[&str]); 12] = [
    ("read", &[]), ("create", &[]), ("update", &[]), ("delete", &["pca.destructive"]), ("send", &["pca.external_communication"]), ("pay", &["pca.money_moving"]),
    ("exec", &["pca.code_execution"]), ("privilege", &["pca.privilege_change"]), ("export", &["pca.data_export"]), ("publish", &["pca.public_exposure"]),
    ("provision", &["pca.persistence", "pca.scheduled"]), ("sign", &["pca.legal_binding"]),
];
const TAG_TRAITS: [(&str, &[&str]); 5] = [
    ("pii", &["pca.pii_access"]), ("phi", &["pca.pii_access", "pca.regulated_data"]), ("pci", &["pca.regulated_data"]),
    ("secret", &["pca.credential_access"]), ("credential", &["pca.credential_access"]),
];
const ROLE_TRAITS: [(&str, &[&str]); 4] = [
    ("credential.secret", &["pca.credential_access"]), ("credential.token", &["pca.credential_access"]), ("credential.key", &["pca.credential_access"]),
    ("url.target", &["pca.network_egress"]),
];
const ROLE_SENS: [(&str, &str); 17] = [
    ("money.amount", "critical"), ("money.currency", "material"), ("money.fee", "material"), ("party.payee", "critical"), ("party.payer", "material"),
    ("contact.email", "material"), ("contact.phone", "material"), ("contact.address", "material"), ("person.name", "material"), ("person.dob", "material"),
    ("person.national_id", "critical"), ("credential.secret", "critical"), ("credential.token", "critical"), ("credential.key", "critical"),
    ("code.command", "critical"), ("query.sql", "critical"), ("text.message", "material"),
];
const TAG_SENS: [(&str, &str); 9] = [
    ("pii", "material"), ("phi", "material"), ("pci", "material"), ("secret", "critical"), ("credential", "critical"), ("free_text_outbound", "material"),
    ("code", "material"), ("path", "material"), ("sql", "material"),
];

fn lookup<'a, T>(t: &'a [(&str, T)], k: &str) -> Option<&'a T> {
    t.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
}

/// Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`.
pub fn traits_digest(reg: &Registry) -> String {
    let ts: Vec<Value> = reg
        .traits
        .values()
        .map(|t| json!({"id": t.id, "implies": sort_uniq(t.implies.clone()), "floor": t.floor.to_value(), "card_phrase": t.card_phrase}))
        .collect();
    hash_canonical_strict(&json!({"d": TRAITS_DIGEST_DOMAIN, "traits": ts})).expect("in profile")
}

pub fn tables_digest() -> String {
    let m = |t: &[(&str, &[&str])]| Value::Object(t.iter().map(|(k, v)| (k.to_string(), json!(v))).collect());
    let ms = |t: &[(&str, &str)]| Value::Object(t.iter().map(|(k, v)| (k.to_string(), json!(v))).collect());
    hash_canonical_strict(&json!({
        "d": ROLES_DIGEST_DOMAIN, "roles": CORE_ROLES, "effect_traits": m(&EFFECT_TRAITS), "role_traits": m(&ROLE_TRAITS), "tag_traits": m(&TAG_TRAITS),
        "role_sensitivity": ms(&ROLE_SENS), "tag_sensitivity": ms(&TAG_SENS),
    }))
    .expect("in profile")
}

// ---- normalize + digest ---------------------------------------------------------------------------------------------------

pub fn is_read_only(effects: &[String]) -> bool {
    !effects.is_empty() && effects.iter().all(|e| e == "read")
}

fn max_sens<'a>(a: &'a str, b: &'a str) -> &'a str {
    if sens_rank(a) >= sens_rank(b) {
        a
    } else {
        b
    }
}

fn param_sensitivity(p: &Map<String, Value>) -> String {
    let mut f = "free";
    if let Some(r) = p.get("role").and_then(Value::as_str).and_then(|r| lookup(&ROLE_SENS, r)) {
        f = max_sens(f, r);
    }
    for t in p.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        if let Some(s) = lookup(&TAG_SENS, t) {
            f = max_sens(f, s);
        }
    }
    max_sens(p.get("sensitivity").and_then(Value::as_str).unwrap_or("free"), f).to_string()
}

fn max_rev(xs: &[String]) -> String {
    let mut out = "reversible".to_string();
    for b in xs {
        if rev_rank(b).is_some_and(|r| r > rev_rank(&out).unwrap_or(0)) {
            out = b.clone();
        }
    }
    out
}

/// Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have.
pub fn worst_reversibility(r: &Value, params: &Map<String, Value>) -> String {
    if let Some(s) = r.as_str() {
        return s.to_string();
    }
    let map = r.get("map").and_then(Value::as_object);
    let mapped: Vec<String> = map.map(|m| m.values().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let d = r.get("by").and_then(Value::as_str).and_then(|b| params.get(b)).and_then(Value::as_object);
    let domain: Option<Vec<String>> = match d.and_then(|d| d.get("type")).and_then(Value::as_str) {
        Some("boolean") => Some(vec!["true".into(), "false".into()]),
        Some("string") => d.and_then(|d| d.get("values")).filter(|v| v.is_array()).map(strs),
        _ => None,
    };
    let covered = domain.is_some_and(|dm| dm.iter().all(|x| map.is_some_and(|m| m.contains_key(x))));
    if covered {
        max_rev(&mapped)
    } else {
        let mut all = mapped;
        all.push(r.get("default").and_then(Value::as_str).unwrap_or("irreversible").to_string());
        max_rev(&all)
    }
}

fn declared_reversibility(d: &Map<String, Value>) -> Value {
    match d.get("reversibility") {
        Some(r) => r.clone(),
        None => Value::String(if is_read_only(&strs(&d["effects"])) { "reversible" } else { "irreversible" }.into()),
    }
}

fn normalize_param(p: &Map<String, Value>) -> Value {
    let mut out = p.clone();
    out.insert("required".into(), p.get("required").cloned().unwrap_or(Value::Bool(true)));
    if let Some(t) = p.get("tags") {
        out.insert("tags".into(), vstrs(&sort_uniq(strs(t))));
    }
    out.insert("sensitivity".into(), Value::String(param_sensitivity(p)));
    if let Some(a) = p.get("accumulates") {
        out.insert("accumulates".into(), vstrs(&sort_uniq(strs(a))));
    } else if p.get("role").and_then(Value::as_str) == Some("money.amount") {
        if let Some(u) = p.get("unit").and_then(Value::as_object) {
            if u.get("kind").and_then(Value::as_str) == Some("money") {
                if let Some(c) = u.get("ccy").and_then(Value::as_str) {
                    out.insert("accumulates".into(), json!([format!("money.{}", c.to_ascii_lowercase())]));
                }
            }
        }
    }
    Value::Object(out)
}

/// The authoring-independent form of a def (assumes `validate_def` passed): defaults filled, sets sorted, review/examples/source/since removed.
pub fn normalize(d: &Value) -> Value {
    let d = d.as_object().expect("a validated def is an object");
    let rev = declared_reversibility(d);
    let res = &d["resource"];
    let radius = d.get("blast").and_then(|b| b.get("radius")).and_then(Value::as_str).unwrap_or_else(|| scope_blast(res["scope"].as_str().unwrap_or("one"))).to_string();
    let ppm = blast_ppm_of(&radius).max(d.get("blast").and_then(|b| sint(b.get("ppm"))).unwrap_or(0));
    let mut pnames: Vec<&String> = d["params"].as_object().unwrap().keys().collect();
    pnames.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let params: Map<String, Value> = pnames.into_iter().map(|k| (k.clone(), normalize_param(d["params"][k].as_object().unwrap()))).collect();
    let nrev = match rev.as_object() {
        Some(o) => {
            let mut m = Map::new();
            m.insert("by".into(), o["by"].clone());
            m.insert("map".into(), o["map"].clone());
            if let Some(df) = o.get("default") {
                m.insert("default".into(), df.clone());
            }
            Value::Object(m)
        }
        None => rev.clone(),
    };
    let mut idem = Map::new();
    idem.insert("mode".into(), d.get("idempotency").and_then(|i| i.get("mode")).cloned().unwrap_or_else(|| "none".into()));
    if let Some(p) = d.get("idempotency").and_then(|i| i.get("param")) {
        idem.insert("param".into(), p.clone());
    }
    let mut se: Vec<(Vec<u16>, String, Value)> = d
        .get("side_effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|s| (s["target"].as_str().unwrap_or("").encode_utf16().collect(), s["kind"].as_str().unwrap_or("").to_string(), json!({"target": s["target"], "kind": s["kind"]})))
        .collect();
    se.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let strs_of = |k: &str| vstrs(&sort_uniq(d.get(k).map(strs).unwrap_or_default()));
    let mut out = Map::new();
    out.insert("v".into(), json!(1));
    out.insert("kind".into(), d["kind"].clone());
    out.insert("verb".into(), d["verb"].clone());
    out.insert("aliases".into(), strs_of("aliases"));
    out.insert("title".into(), d["title"].clone());
    out.insert("effects".into(), strs_of("effects"));
    out.insert("resource".into(), json!({"type": res["type"], "id": res["id"], "scope": res["scope"]}));
    out.insert("params".into(), Value::Object(params));
    out.insert("reversibility".into(), nrev);
    out.insert("blast".into(), json!({"radius": radius, "ppm": ppm}));
    out.insert("side_effects".into(), Value::Array(se.into_iter().map(|x| x.2).collect()));
    out.insert("idempotency".into(), Value::Object(idem));
    out.insert("context".into(), strs_of("context"));
    out.insert("traits".into(), strs_of("traits"));
    out.insert("bindings".into(), d.get("bindings").cloned().unwrap_or_else(|| json!({})));
    for k in ["description", "audience", "compensates"] {
        if let Some(v) = d.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    Value::Object(out)
}

/// b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it.
pub fn def_digest(d: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": DEF_DIGEST_DOMAIN, "def": normalize(d)}))
}

// ---- pack Merkle root + inclusion proof -----------------------------------------------------------------------------------

fn leaf(digest: &str) -> Value {
    json!({"d": PACK_DIGEST_DOMAIN, "def": digest})
}

fn sorted_digests(digests: &[String]) -> Result<Vec<String>, ActionKitError> {
    let mut s: Vec<String> = digests.to_vec();
    sort_utf8(&mut s);
    s.dedup();
    if s.len() != digests.len() {
        return Err(ActionKitError::new("duplicate_def", "a pack lists a def digest twice"));
    }
    if s.is_empty() {
        return Err(ActionKitError::new("empty_pack", "a pack has at least one def"));
    }
    Ok(s)
}

/// Merkle root over the sorted def digests (RFC 6962 shape, domain separated leaves).
pub fn pack_root(digests: &[String]) -> Result<String, ActionKitError> {
    let leaves: Vec<Value> = sorted_digests(digests)?.iter().map(|d| leaf(d)).collect();
    merkle_root(&leaves).map_err(|e| ActionKitError::new("bad_leaf", e))
}

fn subroot(hs: &[Vec<u8>]) -> Vec<u8> {
    if hs.len() == 1 {
        return hs[0].clone();
    }
    let k = split(hs.len() as u64) as usize;
    node_hash(&subroot(&hs[..k]), &subroot(&hs[k..]))
}

/// RFC 6962 inclusion proof of `digest`: {index, size, path: [{side, hash}]} bottom-up.
pub fn pack_proof(digests: &[String], digest: &str) -> Result<Value, ActionKitError> {
    let s = sorted_digests(digests)?;
    let i = s.iter().position(|d| d == digest).ok_or_else(|| ActionKitError::new("not_in_pack", "the digest is not in the pack"))?;
    let hs: Vec<Vec<u8>> = s.iter().map(|d| leaf_hash(&leaf(d)).expect("in profile")).collect();
    let (mut seg, mut idx, mut path) = (&hs[..], i, Vec::new());
    while seg.len() > 1 {
        let k = split(seg.len() as u64) as usize;
        if idx < k {
            path.push(json!({"side": "R", "hash": b64_encode(&subroot(&seg[k..]))}));
            seg = &seg[..k];
        } else {
            path.push(json!({"side": "L", "hash": b64_encode(&subroot(&seg[..k]))}));
            seg = &seg[k..];
            idx -= k;
        }
    }
    path.reverse();
    Ok(json!({"index": i, "size": s.len(), "path": path}))
}

/// Does `proof` show `digest` is in the pack with root `root`?
pub fn pack_verify(root: &str, proof: &Value, digest: &str) -> bool {
    verify_inclusion(root, proof.as_object(), &leaf(digest))
}

// ---- T(d), decl(d), eff(d) ------------------------------------------------------------------------------------------------

pub struct ParamFacts {
    pub ty: Option<String>,
    pub role: Option<String>,
    pub tags: Vec<String>,
    pub has_max_items: bool,
}

impl ParamFacts {
    pub fn of(p: &Value) -> ParamFacts {
        ParamFacts {
            ty: p.get("type").and_then(Value::as_str).map(String::from),
            role: p.get("role").and_then(Value::as_str).map(String::from),
            tags: p.get("tags").map(strs).unwrap_or_default(),
            has_max_items: p.get("max_items").is_some(),
        }
    }
}

/// Traits implied by effects, roles, tags, scope and reversibility. Err on an unknown effect (a forged document).
pub fn implied_from_facts(effects: &[String], params: &[ParamFacts], scope: Option<&str>, worst_rev: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for e in effects {
        out.extend(lookup(&EFFECT_TRAITS, e).ok_or_else(|| format!("unknown effect {e}"))?.iter().map(|s| s.to_string()));
    }
    let ro = is_read_only(effects);
    for p in params {
        if let Some(r) = &p.role {
            if let Some(t) = lookup(&ROLE_TRAITS, r) {
                out.extend(t.iter().map(|s| s.to_string()));
            }
            if ro && r.starts_with("money.") {
                out.push("pca.financial_data_read".into());
            }
        }
        for t in &p.tags {
            if let Some(ts) = lookup(&TAG_TRAITS, t) {
                out.extend(ts.iter().map(|s| s.to_string()));
            }
        }
        if p.ty.as_deref() == Some("array") && !p.has_max_items {
            out.push("pca.bulk".into());
        }
    }
    if scope.is_some_and(|s| s != "one") {
        out.push("pca.bulk".into());
    }
    if worst_rev == "irreversible" {
        out.push("pca.irreversible".into());
    }
    Ok(sort_uniq(out))
}

// ---- confirmation: the signed human review, the ONLY thing that lowers an action's traits below the top of the registry --------

/// The top of the registry: every trait id (sorted). What an UNCONFIRMED def or verb is treated as carrying.
pub fn top_traits(reg: &Registry) -> Vec<String> {
    reg.traits.keys().cloned().collect()
}

/// `None` if the reviewer pin set `{keys: [...], traits_digests?: [...]}` is sound. Any error means nothing is confirmed.
pub fn reviewer_pins_error(p: &Value) -> Option<String> {
    let keys = match p.get("keys").and_then(Value::as_array) {
        Some(k) => k,
        None => return Some("pins must be {keys: [...]}".into()),
    };
    let (mut kids, mut machine_pks) = (BTreeSet::new(), BTreeSet::new());
    for k in keys {
        let kid = match k.get("kid").and_then(Value::as_str) {
            Some(i) if !i.is_empty() && utf16_len(i) <= 128 => i,
            _ => return Some("a pinned key needs a kid".into()),
        };
        if !kids.insert(kid) {
            return Some(format!("kid '{kid}' is pinned twice"));
        }
        if !b32(k.get("pk")) {
            return Some(format!("key '{kid}': pk is not canonical base64url (32 bytes)"));
        }
        let roles = strs_exact(k.get("roles"));
        match &roles {
            Some(r) if !r.is_empty() && r.iter().all(|x| KEY_ROLES.contains(&x.as_str())) && r.iter().collect::<BTreeSet<_>>().len() == r.len() => {}
            _ => return Some(format!("key '{kid}': roles must be distinct known roles")),
        }
        let has = |r: &str| roles.as_ref().is_some_and(|x| x.iter().any(|y| y == r));
        if has("reviewer") && (has("importer") || has("model")) {
            return Some(format!("key '{kid}': an importer or model key cannot hold the reviewer role"));
        }
        for m in ["not_before", "not_after"] {
            if k.get(m).is_some() && nonneg(k.get(m)).is_none() {
                return Some(format!("key '{kid}': {m} must be a non-negative integer"));
            }
        }
        if has("importer") || has("model") {
            machine_pks.insert(k["pk"].as_str().unwrap_or(""));
        }
    }
    // the same key material under a second kid must not smuggle a machine key into the reviewer role
    for k in keys {
        if strs_exact(k.get("roles")).is_some_and(|r| r.iter().any(|x| x == "reviewer")) && machine_pks.contains(k["pk"].as_str().unwrap_or("")) {
            return Some(format!("key '{}': the same key material is pinned as an importer or model key", k["kid"].as_str().unwrap_or("")));
        }
    }
    None
}

/// An array of strings, or None if it is not exactly that.
fn strs_exact(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
}

/// `reviewMessage`: `REVIEW_DOMAIN \0 strictCanonical({def_digest, traits_digest, facts_digest, final_traits (sorted, distinct), dismissed (sorted by trait),
/// reviewer_kid, ts})`. None if the attestation is not well typed or not strictly canonical.
fn review_message(a: &Map<String, Value>) -> Option<Vec<u8>> {
    let fin = sort_uniq(strs_exact(a.get("final_traits"))?);
    let mut dm: Vec<(String, String)> = Vec::new();
    for d in a.get("dismissed")?.as_array()? {
        dm.push((d.get("trait")?.as_str()?.into(), d.get("reason")?.as_str()?.into()));
    }
    dm.sort_by(|x, y| x.0.cmp(&y.0));
    let body = json!({
        "def_digest": a.get("def_digest")?, "traits_digest": a.get("traits_digest")?, "facts_digest": a.get("facts_digest")?, "final_traits": fin,
        "dismissed": dm.iter().map(|(t, r)| json!({"trait": t, "reason": r})).collect::<Vec<_>>(),
        "reviewer_kid": a.get("reviewer_kid")?, "ts": a.get("ts")?,
    });
    let mut m = REVIEW_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(&body).ok()?.as_bytes());
    Some(m)
}

/// What def-level and verb-level confirmation share (the caller has checked the digest binding and the trait-set rule): the
/// accepted registry digest, a dismissed trait is never also final and has a reason, the pinned `reviewer` key inside its
/// validity window, and the Ed25519 signature. Total: any odd shape is `false`.
fn attestation_signed_ok(a: &Map<String, Value>, pins: &Value, reg: &Registry) -> bool {
    let sig = match a.get("sig").and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    let td = a.get("traits_digest").and_then(Value::as_str);
    let accepted = td.is_some_and(|d| d == traits_digest(reg) || pins.get("traits_digests").and_then(Value::as_array).is_some_and(|x| x.iter().any(|y| y.as_str() == Some(d))));
    let (Some(fin), Some(dm), Some(ts), Some(kid)) = (strs_exact(a.get("final_traits")), a.get("dismissed").and_then(Value::as_array), sint(a.get("ts")), a.get("reviewer_kid").and_then(Value::as_str)) else {
        return false;
    };
    let dismissed_ok = dm.iter().all(|d| match (d.get("trait").and_then(Value::as_str), d.get("reason").and_then(Value::as_str)) {
        (Some(t), Some(r)) => !fin.iter().any(|f| f == t) && !r.trim().is_empty(),
        _ => false,
    });
    let key = pins["keys"].as_array().and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(Value::as_str) == Some(kid)));
    let Some(key) = key else { return false };
    let reviewer = strs_exact(key.get("roles")).is_some_and(|r| r.iter().any(|x| x == "reviewer"));
    let in_window = sint(key.get("not_before")).map_or(true, |b| ts >= b) && sint(key.get("not_after")).map_or(true, |e| ts <= e);
    accepted && dismissed_ok && reviewer && in_window && review_message(a).is_some_and(|m| verify_b64u(key["pk"].as_str().unwrap_or(""), &m, sig))
}

/// `verifyAttestation(def, {pins, registry}).ok`: the def is `confirmed`, its attestation names exactly this def digest, its final
/// traits are the def's declared traits, and it is signed by a pinned reviewer key. Never panics; every failure is `false`.
pub fn is_confirmed(d: &Value, reg: &Registry, pins: Option<&Value>) -> bool {
    let Some(pins) = pins.filter(|p| reviewer_pins_error(p).is_none()) else { return false };
    let Some(a) = d["review"].get("attestation").and_then(Value::as_object).filter(|_| d["review"]["state"].as_str() == Some("confirmed")) else { return false };
    let declared = d.get("traits").map_or(Some(vec![]), |t| strs_exact(Some(t)));
    a.get("def_digest").and_then(Value::as_str).is_some_and(|x| def_digest(d).as_deref() == Some(x))
        && declared.zip(strs_exact(a.get("final_traits"))).is_some_and(|(dec, fin)| sort_uniq(dec) == sort_uniq(fin))
        && attestation_signed_ok(a, pins, reg)
}

/// `factsDigest(verb)`: the verb as presented minus `traits`, `floors`, `confirmation` and `def`, so a confirmation binds the verb's own facts.
fn facts_digest(v: &Value) -> Option<String> {
    let mut o = v.as_object()?.clone();
    for k in ["traits", "floors", "confirmation", "def"] {
        o.remove(k);
    }
    hash_canonical_strict(&json!({"d": VERB_FACTS_DOMAIN, "verb": o}))
}

/// `verbConfirmationError(verb, reg, pins) === null`: the verb carries a valid human confirmation over exactly the def digest it
/// names, whose final traits the verb carries, signed by a pinned reviewer key. No pins / bad pins / anything else: unconfirmed.
pub fn verb_is_confirmed(v: &Value, reg: &Registry, pins: Option<&Value>) -> bool {
    let Some(pins) = pins.filter(|p| reviewer_pins_error(p).is_none()) else { return false };
    let Some(a) = v.get("confirmation").and_then(Value::as_object) else { return false };
    let carried = strs_exact(v.get("traits"));
    let covered = strs_exact(a.get("final_traits")).zip(carried).is_some_and(|(fin, car)| fin.iter().all(|t| car.contains(t)));
    v.get("def").and_then(Value::as_str).is_some_and(|x| a.get("def_digest").and_then(Value::as_str) == Some(x)) && covered
        && a.get("facts_digest").and_then(Value::as_str).is_some_and(|f| facts_digest(v).as_deref() == Some(f))
        && attestation_signed_ok(a, pins, reg)
}

/// The author/machine view of a def's traits: declared + implied by its own facts. A HINT that never reaches enforcement unless a
/// signed confirmation says so (see [`traits_of`]).
pub fn hint_traits(d: &Value) -> Vec<String> {
    let n = normalize(d);
    let params = n["params"].as_object().unwrap();
    let facts: Vec<ParamFacts> = params.values().map(ParamFacts::of).collect();
    let worst = worst_reversibility(&n["reversibility"], params);
    let mut ids = strs(&n["traits"]);
    ids.extend(implied_from_facts(&strs(&n["effects"]), &facts, n["resource"]["scope"].as_str(), &worst).unwrap_or_default());
    sort_uniq(ids)
}

/// T(d), the EFFECTIVE trait set. "Unconfirmed means maximally dangerous": without a valid signed confirmation by a pinned
/// reviewer it is the top of the registry, whatever the def, a pack, a classifier or a model said.
pub fn traits_of(d: &Value, reg: &Registry, pins: Option<&Value>) -> Vec<String> {
    if is_confirmed(d, reg, pins) { hint_traits(d) } else { top_traits(reg) }
}

pub fn decl_profile(d: &Value) -> Profile {
    let n = normalize(d);
    let params = n["params"].as_object().unwrap();
    let critical = params.values().any(|p| p["sensitivity"].as_str() == Some("critical"));
    Profile {
        risk: if critical { 2 } else if is_read_only(&strs(&n["effects"])) { 0 } else { 1 },
        rev: worst_reversibility(&n["reversibility"], params),
        blast_ppm: sint(n["blast"].get("ppm")).unwrap_or(0),
        esc: 0,
        caveats: vec![],
        context: sort_uniq(strs(&n["context"])),
        prules: vec![],
    }
}

pub struct Effective {
    /// A valid signed confirmation counted; when false, `traits` is the top of the registry.
    pub confirmed: bool,
    pub traits: Vec<String>,
    pub closure: Vec<String>,
    pub floor: Profile,
    pub decl: Profile,
    pub eff: Profile,
}

pub fn effective(d: &Value, reg: &Registry, pins: Option<&Value>) -> Result<Effective, ActionKitError> {
    let confirmed = is_confirmed(d, reg, pins);
    let traits = if confirmed { hint_traits(d) } else { top_traits(reg) };
    let floor = floor_of(reg, &traits)?;
    let decl = decl_profile(d);
    Ok(Effective { confirmed, closure: closure(reg, &traits)?, eff: join(&decl, &floor), floor, decl, traits })
}

// ---- rule 22: whole-document integrity of the carried traits and floors --------------------------------------------------

const PFX: &str = "action.params.";

/// Recompute from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at least
/// the floor of the traits' closure and of the declared reversibility. `None` = consistent; else `<code>: <reason>`.
pub fn schema_verb_floor_error(v: &Value, reg: &Registry, pins: Option<&Value>) -> Option<String> {
    let forged = |m: &str| Some(format!("schema_floor_forged: {m}"));
    let (effects, traits) = match (v.get("effects").and_then(Value::as_array), v.get("traits").and_then(Value::as_array)) {
        (Some(e), Some(t)) if v.get("floors").is_some() => (strs(&Value::Array(e.clone())), strs(&Value::Array(t.clone()))),
        _ => return forged("not a v2 verb"),
    };
    let params = match v.get("params").and_then(Value::as_object) {
        Some(p) => p,
        None => return forged("params"),
    };
    let mut by_name = Map::new();
    let mut facts = Vec::new();
    for (path, p) in params {
        let name = path.get(PFX.len()..).unwrap_or("").to_string();
        let mut e = Map::new();
        e.insert("type".into(), p.get("type").cloned().unwrap_or(Value::Null));
        if let Some(vs) = p.get("values") {
            e.insert("values".into(), vs.clone());
        }
        by_name.insert(name, Value::Object(e));
        facts.push(ParamFacts::of(p));
    }
    let decl = match v.get("reversibility_by").filter(|r| !r.is_null()) {
        Some(rb) => {
            let mut m = Map::new();
            m.insert("by".into(), Value::String(rb.get("param").and_then(Value::as_str).and_then(|p| p.get(PFX.len()..)).unwrap_or("").into()));
            m.insert("map".into(), rb.get("map").cloned().unwrap_or(Value::Null));
            if let Some(df) = rb.get("default") {
                m.insert("default".into(), df.clone());
            }
            Value::Object(m)
        }
        None => v.get("reversibility").cloned().unwrap_or_else(|| Value::String(if v.get("kind").and_then(Value::as_str) == Some("read") { "reversible" } else { "irreversible" }.into())),
    };
    let worst = worst_reversibility(&decl, &by_name);
    let implied = match implied_from_facts(&effects, &facts, None, &worst) {
        Ok(i) => i,
        Err(e) => return forged(&e),
    };
    for t in &implied {
        if !traits.contains(t) {
            return Some(format!("schema_traits_forged: missing implied trait {t}"));
        }
    }
    // unconfirmed means maximally dangerous: no valid signed confirmation => the verb must carry EVERY trait of the registry
    if !verb_is_confirmed(v, reg, pins) {
        if let Some(t) = top_traits(reg).iter().find(|t| !traits.contains(t)) {
            return Some(format!("schema_traits_forged: unconfirmed action must carry every trait (missing {t})"));
        }
    }
    let fl = match floor_of(reg, &traits) {
        Ok(f) => f,
        Err(e) => return Some(e.to_string()),
    };
    let floors = match Profile::from_value(&v["floors"]) {
        Some(f) => f,
        None => return forged("floors are malformed"),
    };
    if !leq(&fl, &floors) {
        return forged("floors are below the floor of the carried traits");
    }
    if rev_rank(&floors.rev).unwrap_or(-1) < rev_rank(&worst).unwrap_or(-1) {
        return forged("floors.rev is below the declared reversibility");
    }
    None
}

/// Core + the document's own `trait_defs` (checked); when it carries `traits_digest` the registry must hash to it.
pub fn registry_of_schema(doc: &Value) -> Result<Registry, ActionKitError> {
    let core = core_registry();
    let reg = match doc.get("trait_defs").and_then(Value::as_array) {
        Some(td) if !td.is_empty() => extend_registry(&core, td)?,
        _ => core,
    };
    if let Some(d) = doc.get("traits_digest") {
        if d.as_str() != Some(traits_digest(&reg).as_str()) {
            return Err(ActionKitError::new("traits_digest_mismatch", "the document's traits_digest does not match its trait registry"));
        }
    }
    Ok(reg)
}

/// Rule 22's integrity half for a whole v2 document. `None` = consistent.
pub fn schema_floor_error(doc: &Value, pins: Option<&Value>) -> Option<String> {
    let reg = match registry_of_schema(doc) {
        Ok(r) => r,
        Err(e) => return Some(e.to_string()),
    };
    for v in doc.get("verbs").and_then(Value::as_array).into_iter().flatten() {
        if let Some(e) = schema_verb_floor_error(v, &reg, pins) {
            return Some(format!("{}: {e}", v.get("verb").and_then(Value::as_str).unwrap_or("")));
        }
    }
    None
}
