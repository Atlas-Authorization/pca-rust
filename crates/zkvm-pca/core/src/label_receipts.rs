//! Intent Layer v2 W-B: site-signed `pca-labels` receipts and flow rules (checked inside conformance rule 17).
//! Faithful port of `packages/pca/src/label-receipts.ts` (`validateLabelsWire`, `labelsRef`, `verifyLabels`,
//! `flowRuleFor`, `flowAllowed`, `validateFlowRules`). Signed under the receipt's suite with the signer the verifier pins for
//! (site, kid) (`unsupported_suite` first; PQ only under the pin's `pq_pk`). The read-side purpose helper (`decideReadPurpose`) is not part of rule 17 and is not ported. Never panics.
use crate::jsnum::{non_neg, safe_int};
use crate::oracle_facts::{artifact_ref, artifact_suite_error, closed_members, pin_of, pin_pq_ok, SUITE_MEMBERS, is_bounded_string, is_data_class, is_digest, verify_artifact_sig};
use serde_json::{Map, Value};

pub const LABELS_DOMAIN: &str = "atlas-pca/labels/v1\0";
pub const LABELS_REF_DOMAIN: &str = "atlas-pca/labels-ref/v1";
pub const MAX_LABEL_FIELDS: usize = 64;
pub const PUBLIC_CLASS: &str = "public";

/// `validateLabelsWire`: `None` = well-formed.
pub fn validate_labels_wire(l: &Value) -> Option<String> {
    let o = match l.as_object() {
        Some(o) => o,
        None => return Some("label receipt must be an object".into()),
    };
    if !closed_members(o, &["v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"], &SUITE_MEMBERS) {
        return Some("label receipt has unknown or missing members".into());
    }
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    if safe_int(g("v")) != Some(1) || g("kind").as_str() != Some("pca-labels") {
        return Some("label receipt must be {v: 1, kind: \"pca-labels\"}".into());
    }
    if !is_bounded_string(g("site"), 256) {
        return Some("'labels.site' must be a non-empty string (<= 256 bytes)".into());
    }
    if !is_digest(g("session")) {
        return Some("'labels.session' must be canonical base64url (32 bytes)".into());
    }
    if !is_digest(g("response_digest")) {
        return Some("'labels.response_digest' must be canonical base64url (32 bytes)".into());
    }
    let fields = match g("fields").as_object() {
        Some(f) => f,
        None => return Some("'labels.fields' must be an object".into()),
    };
    if fields.is_empty() || fields.len() > MAX_LABEL_FIELDS {
        return Some(format!("'labels.fields' must hold 1..{MAX_LABEL_FIELDS} fields"));
    }
    for (k, f) in fields {
        if k.is_empty() || k.len() > 256 {
            return Some("label field paths must be non-empty strings (<= 256 bytes)".into());
        }
        let f = match f.as_object() {
            Some(f) if closed_members(f, &["class", "value_digest"], &[]) => f,
            _ => return Some(format!("label field '{k}' must be exactly {{class, value_digest}}")),
        };
        // `f.class.length > 128` counts UTF-16 units; a valid class is ASCII, so bytes == units where it matters.
        if !matches!(f.get("class"), Some(Value::String(c)) if c.encode_utf16().count() <= 128 && is_data_class(c)) {
            return Some(format!("label field '{k}': invalid data class"));
        }
        if !is_digest(f.get("value_digest").unwrap_or(&Value::Null)) {
            return Some(format!("label field '{k}': value_digest must be canonical base64url (32 bytes)"));
        }
    }
    if non_neg(g("issued_at")).is_none() {
        return Some("'labels.issued_at' must be a non-negative safe integer".into());
    }
    if !is_bounded_string(g("kid"), 64) {
        return Some("'labels.kid' must be a non-empty string (<= 64 bytes)".into());
    }
    if !g("sig").is_string() {
        return Some("'labels.sig' must be a string".into());
    }
    None
}

/// `labelsRef(l)`; `None` where TS throws.
pub fn labels_ref(l: &Value) -> Option<String> {
    artifact_ref(LABELS_REF_DOMAIN, "l", l)
}

/// `verifyLabels(l, keys)`: wire shape and signature under the FIRST key pinned for (site, kid). `None` = valid.
pub fn verify_labels(l: &Value, keys: &[Value]) -> Option<String> {
    if let Some(w) = validate_labels_wire(l) {
        return Some(w);
    }
    if let Some(se) = artifact_suite_error(l) {
        return Some(format!("signature suite: {se}"));
    }
    let site = l.get("site").and_then(Value::as_str);
    let kid = l.get("kid").and_then(Value::as_str);
    let key = keys.iter().find(|k| k.get("site").and_then(Value::as_str) == site && k.get("kid").and_then(Value::as_str) == kid);
    let key = match key {
        Some(k) => k,
        None => return Some(format!("no pinned label key for site '{}' kid '{}'", site.unwrap_or(""), kid.unwrap_or(""))),
    };
    let (pk, pq) = pin_of(key);
    if verify_artifact_sig(LABELS_DOMAIN, l, pk, pq) {
        None
    } else {
        Some("bad label receipt signature".into())
    }
}

/// `isLabelKey(k)`: `{site (1..256 B), kid (1..64 B), pk (digest), pq_pk? (non-empty string)}`.
pub fn is_label_key(k: &Value) -> bool {
    k.as_object().map_or(false, |o| {
        closed_members(o, &["site", "kid", "pk"], &["pq_pk"])
            && is_bounded_string(o.get("site").unwrap_or(&Value::Null), 256)
            && is_bounded_string(o.get("kid").unwrap_or(&Value::Null), 64)
            && is_digest(o.get("pk").unwrap_or(&Value::Null))
            && pin_pq_ok(o)
    })
}

/// `flowRuleFor(rules, cls)`: the most specific matching pattern (exact > longest `prefix.*` > `*`).
pub fn flow_rule_for<'a>(rules: &'a Map<String, Value>, cls: &str) -> Option<&'a str> {
    if let Some((k, _)) = rules.get_key_value(cls) {
        return Some(k.as_str());
    }
    let mut best: Option<&str> = None;
    for p in rules.keys() {
        if let Some(stem) = p.strip_suffix('*') {
            if !p.ends_with(".*") {
                continue;
            }
            if cls.starts_with(stem) && best.map_or(true, |b| p.encode_utf16().count() > b.encode_utf16().count()) {
                best = Some(p.as_str());
            }
        }
    }
    if best.is_some() {
        return best;
    }
    rules.get_key_value("*").map(|(k, _)| k.as_str())
}

/// `flowAllowed(rules, cls, origin, aud)`: back to the origin or `public`: yes; else the most specific rule lists `aud`.
pub fn flow_allowed(rules: &Map<String, Value>, cls: &str, origin: &str, aud: &Value) -> bool {
    if aud.as_str() == Some(origin) || cls == PUBLIC_CLASS {
        return true;
    }
    match flow_rule_for(rules, cls) {
        None => false,
        Some(p) => matches!(rules.get(p), Some(Value::Array(sinks)) if sinks.iter().any(|s| s == aud)),
    }
}

/// `validateFlowRules`: `None` = well-formed.
pub fn validate_flow_rules(rules: &Value) -> Option<String> {
    let r = match rules.as_object() {
        Some(r) => r,
        None => return Some("flows must be an object".into()),
    };
    for (p, sinks) in r {
        let base = if p == "*" {
            "x"
        } else if let Some(b) = p.strip_suffix(".*") {
            b
        } else {
            p.as_str()
        };
        if !is_data_class(base) {
            return Some(format!("flow pattern '{p}' is not a class, a 'prefix.*' or '*'"));
        }
        if !matches!(sinks, Value::Array(a) if a.iter().all(|s| is_bounded_string(s, 256))) {
            return Some(format!("flow pattern '{p}' needs a list of audiences"));
        }
    }
    None
}

// ---- read side: purpose limitation (`decideReadPurpose`, conformance `primitives.intent_read_purpose`) ----------------

/// `decideReadPurpose` outcome: `allow` / `question` / `deny`, the fields to minimise and the uncovered required fields
/// (both de-duplicated, UTF-8 byte order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPurposeDecision {
    pub outcome: &'static str,
    pub minimise: Vec<String>,
    pub uncovered: Vec<String>,
}

fn read_class_covered(patterns: &[Value], cls: &str) -> bool {
    cls == "public"
        || patterns.iter().filter_map(Value::as_str).any(|p| p == "*" || p == cls || (p.ends_with(".*") && cls.starts_with(&p[..p.len() - 1])))
}

/// `decideReadPurpose(fields, purpose, coverage, onUncovered = 'question')` (label-receipts.ts). `on_uncovered` None =
/// absent (the default). Malformed input (JSON null included) is `deny` with empty lists. Total.
pub fn decide_read_purpose(fields: Option<&Value>, purpose: Option<&Value>, coverage: Option<&Value>, on_uncovered: Option<&Value>) -> ReadPurposeDecision {
    let malformed = ReadPurposeDecision { outcome: "deny", minimise: vec![], uncovered: vec![] };
    let on: &'static str = match on_uncovered {
        None => "question",
        Some(Value::String(s)) if s == "question" => "question",
        Some(Value::String(s)) if s == "deny" => "deny",
        _ => return malformed,
    };
    let (Some(Value::Array(fields)), Some(Value::String(purpose)), Some(Value::Object(coverage))) = (fields, purpose, coverage) else {
        return malformed;
    };
    if !coverage.values().all(|p| p.as_array().is_some_and(|a| a.iter().all(Value::is_string))) {
        return malformed;
    }
    for f in fields {
        let ok = f.as_object().is_some_and(|o| {
            o.get("path").is_some_and(Value::is_string) && o.get("class").is_some_and(Value::is_string) && o.get("optional").map_or(true, Value::is_boolean)
        });
        if !ok {
            return malformed;
        }
    }
    let empty = Vec::new();
    let patterns = coverage.get(purpose.as_str()).and_then(Value::as_array).unwrap_or(&empty);
    let mut minimise = std::collections::BTreeSet::new();
    let mut uncovered = std::collections::BTreeSet::new();
    for f in fields {
        let cls = f["class"].as_str().unwrap_or("");
        if read_class_covered(patterns, cls) {
            continue;
        }
        let path = f["path"].as_str().unwrap_or("").to_string();
        if f.get("optional") == Some(&Value::Bool(true)) {
            minimise.insert(path);
        } else {
            uncovered.insert(path);
        }
    }
    ReadPurposeDecision { outcome: if uncovered.is_empty() { "allow" } else { on }, minimise: minimise.into_iter().collect(), uncovered: uncovered.into_iter().collect() }
}
