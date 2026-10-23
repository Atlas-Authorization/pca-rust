//! Intent Layer v2 W-B, NORMATIVE conformance rule 18 (`classes`, `primitives.intent_classifier`): classifier-derived
//! categorical dimensions from allowlisted, k-of-n, session- and content-bound verdicts.
//! Faithful port of `packages/pca/src/intent-classifier.ts` (`decideClassifierDimensions`, `classifierCheckActive`,
//! `validateClassifierPolicy`, `validateClassifierVerdictWire`). The verdict is verified under its suite with its
//! `judge` (a PQ suite only under `pq_keys[judge]`; `unsupported_suite` first), which must be on the classifier's allowlist. The TS-only TEE gate (`verifyClassifierAttestation`) is not part
//! of rule 18 and is not ported. Votes are tallied per (classifier, label) in sorted maps, so ids and labels spelled like
//! `Object.prototype` members are ordinary keys (the TS tallies are `Map`s). Never panics.
use crate::jsnum::safe_int;
use crate::oracle_facts::{artifact_ref, artifact_suite_error, checked_params, closed_members, SUITE_MEMBERS, is_bounded_string, is_digest, is_intent_name, is_param_path, non_empty_array, resolve_param_path, strict_hash, verify_artifact_sig};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const INTENT_CLASSIFIER_DOMAIN: &str = "atlas-pca/intent-classifier/v1\0";
pub const INTENT_CLASSIFIER_REF_DOMAIN: &str = "atlas-pca/intent-classifier-ref/v1";
pub const MAX_COMMITTED_CLASSES: usize = 8;
pub const MAX_CLASSIFIER_LABELS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct ClassResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub classes: Map<String, Value>,
}

/// `validateClassifierVerdictWire`: `None` = well-formed.
pub fn validate_classifier_verdict_wire(v: &Value) -> Option<String> {
    let o = match v.as_object() {
        Some(o) => o,
        None => return Some("verdict must be an object".into()),
    };
    if !closed_members(o, &["v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"], &SUITE_MEMBERS) {
        return Some("verdict has unknown or missing members".into());
    }
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    if safe_int(g("v")) != Some(1) || g("kind").as_str() != Some("pca-intent-classification") {
        return Some("verdict must be {v: 1, kind: \"pca-intent-classification\"}".into());
    }
    if !g("classifier").as_str().map_or(false, is_intent_name) {
        return Some("'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$".into());
    }
    if !is_digest(g("session")) {
        return Some("'verdict.session' must be canonical base64url (32 bytes)".into());
    }
    if !is_digest(g("content_digest")) {
        return Some("'verdict.content_digest' must be canonical base64url (32 bytes)".into());
    }
    if !is_bounded_string(g("label"), 64) {
        return Some("'verdict.label' must be a non-empty string (<= 64 bytes)".into());
    }
    if !is_bounded_string(g("measurement"), 256) {
        return Some("'verdict.measurement' must be a non-empty string (<= 256 bytes)".into());
    }
    if !is_digest(g("judge")) {
        return Some("'verdict.judge' must be canonical base64url (32 bytes)".into());
    }
    if !g("sig").is_string() {
        return Some("'verdict.sig' must be a string".into());
    }
    None
}

/// `classifierVerdictRef(v)`; `None` where TS throws.
pub fn classifier_verdict_ref(v: &Value) -> Option<String> {
    artifact_ref(INTENT_CLASSIFIER_REF_DOMAIN, "c", v)
}

/// `validateClassifierPolicy` (rule 18 step 0): `None` = well-formed.
pub fn validate_classifier_policy(p: &Value) -> Option<String> {
    let cs = match p.as_object().and_then(|o| o.get("classifiers")).and_then(Value::as_array) {
        Some(c) => c,
        None => return Some("classifier policy needs a classifiers list".into()),
    };
    if !p.as_object().map_or(false, |o| closed_members(o, &["classifiers"], &[])) {
        return Some("unknown member in the classifier policy".into());
    }
    let mut ids: Vec<&str> = Vec::new();
    for c in cs {
        if !c.as_object().map_or(false, |o| closed_members(o, &["id", "param", "labels", "keys", "k"], &["measurements", "pq_keys"])) {
            return Some("every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}".into());
        }
        let id = match c.as_object().and_then(|o| o.get("id")).and_then(Value::as_str) {
            Some(id) if is_intent_name(id) && !ids.contains(&id) => id,
            _ => return Some("every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$".into()),
        };
        ids.push(id);
        if !is_param_path(c.get("param").unwrap_or(&Value::Null)) {
            return Some(format!("classifier '{id}': param must be an action.params path"));
        }
        let labels = match c.get("labels").and_then(Value::as_array) {
            Some(l) if !l.is_empty() && l.len() <= MAX_CLASSIFIER_LABELS => l,
            _ => return Some(format!("classifier '{id}': labels must hold 1..{MAX_CLASSIFIER_LABELS} strings")),
        };
        if !labels.iter().all(|l| is_bounded_string(l, 64)) || has_dup(labels) {
            return Some(format!("classifier '{id}': labels must be distinct non-empty strings"));
        }
        let keys = match c.get("keys").and_then(Value::as_array) {
            Some(k) if !k.is_empty() && k.iter().all(is_digest) && !has_dup(k) => k,
            _ => return Some(format!("classifier '{id}': keys must be distinct 32-byte keys")),
        };
        match c.get("k").and_then(safe_int) {
            Some(k) if k >= 1 && (k as u64) <= keys.len() as u64 => {}
            _ => return Some(format!("classifier '{id}': k must be an integer in [1, {}]", keys.len())),
        }
        if let Some(m) = c.get("measurements") {
            if !matches!(m, Value::Array(a) if a.iter().all(Value::is_string)) {
                return Some(format!("classifier '{id}': measurements must be a list of strings"));
            }
        }
        if let Some(pq) = c.get("pq_keys") {
            let ok = pq.as_object().map_or(false, |m| m.iter().all(|(k, v)| keys.iter().any(|x| x.as_str() == Some(k.as_str())) && matches!(v, Value::String(s) if !s.is_empty())));
            if !ok {
                return Some(format!("classifier '{id}': pq_keys must map allowlisted keys to PQ keys"));
            }
        }
    }
    None
}

fn has_dup(xs: &[Value]) -> bool {
    xs.iter().enumerate().any(|(i, x)| xs[..i].contains(x))
}

/// `classifierCheckActive({committed, policy})`: `committed` or `policy.classifiers` a non-empty ARRAY (strict typing).
pub fn classifier_check_active(committed: &Value, policy: &Value) -> bool {
    non_empty_array(Some(committed)) || non_empty_array(policy.get("classifiers"))
}

/// NORMATIVE rule 18 (`decideClassifierDimensions`): compute `env.class`. First failure wins. Never panics.
pub fn decide_classifier_dimensions(input: &Value) -> ClassResult {
    let fail = |r: &str| ClassResult { ok: false, reason: Some(format!("classes: {r}")), classes: Map::new() };
    if !input.is_object() {
        return fail("input must be an object");
    }
    let policy = input.get("policy").unwrap_or(&Value::Null);
    if let Some(pe) = validate_classifier_policy(policy) {
        return fail(&format!("policy misconfigured (fail closed): {pe}"));
    }
    let empty: Vec<Value> = Vec::new();
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail.
    let committed = match input.get("committed") {
        None => &empty,
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_CLASSES => a,
        Some(_) => return fail(&format!("committed verdicts must be a list of at most {MAX_COMMITTED_CLASSES} digests")),
    };
    let mut seen: Vec<&str> = Vec::new();
    for d in committed {
        if !is_digest(d) || seen.contains(&d.as_str().unwrap_or("")) {
            return fail("committed verdicts must be distinct canonical 32-byte digests");
        }
        seen.push(d.as_str().unwrap_or(""));
    }
    let supplied: &[Value] = match input.get("verdicts") {
        None => &[],
        Some(Value::Array(a)) => a,
        Some(_) => return fail("verdicts must be an array"),
    };
    let params = match checked_params(input.get("action")) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let mut by_ref: BTreeMap<String, &Value> = BTreeMap::new();
    for v in supplied {
        if validate_classifier_verdict_wire(v).is_some() {
            continue;
        }
        if let Some(r) = classifier_verdict_ref(v) {
            by_ref.insert(r, v);
        }
    }
    let classifiers = policy.get("classifiers").and_then(Value::as_array).unwrap_or(&empty);
    let mut votes: BTreeMap<&str, BTreeMap<&str, u64>> = BTreeMap::new();
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let s = |v: &Value, k: &str| -> String { v.get(k).and_then(Value::as_str).unwrap_or("").to_string() };
    for d in committed {
        let v = match d.as_str().and_then(|d| by_ref.get(d)) {
            Some(v) => *v,
            None => return fail("a committed verdict was not supplied (or is malformed)"),
        };
        if let Some(se) = artifact_suite_error(v) {
            return fail(&format!("verdict signature suite: {se}"));
        }
        let vc = v.get("classifier").and_then(Value::as_str).unwrap_or("");
        let c = match classifiers.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(vc)) {
            Some(c) => c,
            None => return fail(&format!("verdict for undeclared classifier '{vc}'")),
        };
        let id = c.get("id").and_then(Value::as_str).unwrap_or("");
        let judge = v.get("judge").unwrap_or(&Value::Null);
        if !c.get("keys").and_then(Value::as_array).map_or(false, |ks| ks.contains(judge)) {
            return fail(&format!("classifier '{id}': judge key is not on the allowlist"));
        }
        let judge = judge.as_str().unwrap_or("");
        let pq = c.get("pq_keys").and_then(|m| m.get(judge)).and_then(Value::as_str);
        if !verify_artifact_sig(INTENT_CLASSIFIER_DOMAIN, v, judge, pq) {
            return fail(&format!("classifier '{id}': bad verdict signature"));
        }
        if v.get("session").unwrap_or(&Value::Null) != input.get("session").unwrap_or(&Value::Null) {
            return fail(&format!("classifier '{id}': verdict bound to another session"));
        }
        let param = c.get("param").and_then(Value::as_str).unwrap_or("");
        let content = match resolve_param_path(params, param) {
            Some(x) => x,
            None => return fail(&format!("classifier '{id}': the action carries no '{param}'")),
        };
        match strict_hash(content) {
            None => return fail("evaluation error (fail closed)"),
            Some(h) if Some(h.as_str()) != v.get("content_digest").and_then(Value::as_str) => {
                return fail(&format!("classifier '{id}': verdict is about other content"))
            }
            Some(_) => {}
        }
        let label = v.get("label").unwrap_or(&Value::Null);
        if !c.get("labels").and_then(Value::as_array).map_or(false, |ls| ls.contains(label)) {
            return fail(&format!("classifier '{id}': label '{}' is not in its label set", s(v, "label")));
        }
        if let Some(ms) = c.get("measurements") {
            if !ms.as_array().map_or(false, |ms| ms.contains(v.get("measurement").unwrap_or(&Value::Null))) {
                return fail(&format!("classifier '{id}': measurement is not pinned"));
            }
        }
        if pairs.contains(&(id, judge)) {
            return fail(&format!("classifier '{id}': two verdicts from one judge"));
        }
        pairs.push((id, judge));
        *votes.entry(id).or_default().entry(label.as_str().unwrap_or("")).or_insert(0) += 1;
    }
    let mut classes = Map::new();
    let none = BTreeMap::new();
    for c in classifiers {
        let id = c.get("id").and_then(Value::as_str).unwrap_or("");
        let k = c.get("k").and_then(safe_int).unwrap_or(1).max(1) as u64;
        let t = votes.get(id).unwrap_or(&none);
        let winners: Vec<&str> = c
            .get("labels")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .filter(|l| t.get(l).copied().unwrap_or(0) >= k)
            .collect();
        match winners.len() {
            0 => return fail(&format!("classifier '{id}': no label reaches the quorum {k}")),
            1 => {
                classes.insert(id.to_string(), Value::String(winners[0].to_string()));
            }
            n => return fail(&format!("classifier '{id}': ambiguous, {n} labels reach the quorum")),
        }
    }
    ClassResult { ok: true, reason: None, classes }
}
