//! Intent Layer v2 W-B, NORMATIVE conformance rule 17 (`provenance`, `primitives.intent_provenance`): per-parameter
//! provenance with an injected trusted-input registry, label-receipt refs and flow rules.
//! Faithful port of `packages/pca/src/param-provenance.ts` (`decideParamProvenance`, `validateProvenancePolicy`,
//! `validateProvWire`, `parseLabelRef`) with the label lattice of `taint.ts`:
//!     trusted (0) < first_party (1) < tool (2) < web (3) < agent (4); join = highest rank; TAINTED = rank >= 2.
//! A parameter's label is the join of its refs' labels; the refs' `tool` ids are explanatory only and do not reach the
//! result (`levelOf(joinLabels(..))`), so the join here is the max rank. Never panics.
use crate::label_receipts::{flow_allowed, is_label_key, labels_ref, validate_flow_rules, validate_labels_wire, verify_labels};
use crate::oracle_facts::{checked_params, is_bounded_string, is_digest, is_param_path_str, resolve_param_path, strict_hash};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const LABEL_REF_PREFIX: &str = "pca-labels:";
pub const MAX_PROV_PATHS: usize = 32;
pub const MAX_PROV_REFS: usize = 8;
pub const MAX_COMMITTED_LABELS: usize = 16;

/// The taint lattice of `taint.ts`, least-trusted last.
pub const TAINT_LEVELS: [&str; 5] = ["trusted", "first_party", "tool", "web", "agent"];
const TAINTED_RANK: usize = 2;
const AGENT: usize = 4;

/// `isTaintLevel` + `RANK`: the rank of one of the five level names (own names only), else `None`.
pub fn taint_rank(v: &Value) -> Option<usize> {
    v.as_str().and_then(|s| TAINT_LEVELS.iter().position(|l| *l == s))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvOutcome {
    Pass,
    Question,
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvResult {
    pub outcome: ProvOutcome,
    pub reason: Option<String>,
    /// `tap` | `typed` (present iff the outcome is `Question`).
    pub friction: Option<String>,
    /// `env.prov`: the labels nested by path (`{}` on deny).
    pub env: Value,
    /// prov_d per classified parameter path.
    pub labels: Map<String, Value>,
    /// Sorted, de-duplicated data classes per parameter path (from label receipts).
    pub classes: Map<String, Value>,
}

/// `isProvPath`: `action.params.<[A-Za-z0-9_]{1,64}>`, never a prototype name.
pub fn is_prov_path(k: &str) -> bool {
    match k.strip_prefix("action.params.") {
        Some(n) => {
            !n.is_empty() && n.len() <= 64 && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') && !matches!(n, "__proto__" | "constructor" | "prototype")
        }
        None => false,
    }
}

const MODES: [&str; 4] = ["allow", "question", "question_typed", "deny"];

/// `validateProvenancePolicy` (rule 17 step 0): `None` = well-formed.
pub fn validate_provenance_policy(p: &Value) -> Option<String> {
    let params = match p.as_object().and_then(|o| o.get("params")).and_then(Value::as_object) {
        Some(m) => m,
        None => return Some("provenance policy needs a params map".into()),
    };
    let known = ["registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"];
    if !p.as_object().map_or(false, |o| crate::oracle_facts::closed_members(o, &["params"], &known)) {
        return Some("unknown member in the provenance policy".into());
    }
    for (k, v) in params {
        if !is_param_path_str(k) {
            return Some(format!("policy param '{k}' is not an action.params path"));
        }
        if !matches!(v.as_str(), Some("material" | "critical")) {
            return Some(format!("policy param '{k}': sensitivity must be material or critical"));
        }
    }
    if let Some(r) = p.get("registry") {
        let r = match r.as_object() {
            Some(r) => r,
            None => return Some("registry must be an object".into()),
        };
        for (k, v) in r {
            if k.is_empty() || k.len() > 256 || taint_rank(v).is_none() {
                return Some(format!("registry entry '{k}' must map to a taint level"));
            }
        }
    }
    if let Some(lk) = p.get("label_keys") {
        let lk = match lk.as_array() {
            Some(a) => a,
            None => return Some("label_keys must be a list".into()),
        };
        if !lk.iter().all(is_label_key) {
            return Some("every label key needs site, kid, a 32-byte pk and an optional string pq_pk".into());
        }
    }
    if let Some(c) = p.get("critical_max") {
        if taint_rank(c).is_none() {
            return Some("critical_max must be a taint level".into());
        }
    }
    if let Some(m) = p.get("material_tainted") {
        if !m.as_str().map_or(false, |s| MODES.contains(&s)) {
            return Some("material_tainted must be allow | question | question_typed | deny".into());
        }
    }
    if let Some(m) = p.get("critical_tainted") {
        if !m.as_str().map_or(false, |s| s != "allow" && MODES.contains(&s)) {
            return Some("critical_tainted must be question | question_typed | deny".into());
        }
    }
    if let Some(f) = p.get("flows") {
        if let Some(e) = validate_flow_rules(f) {
            return Some(e);
        }
    }
    None
}

/// `validateProvWire` (the `intent_session.prov` member): `None` = well-formed.
pub fn validate_prov_wire(prov: &Value) -> Option<String> {
    let o = match prov.as_object() {
        Some(o) => o,
        None => return Some("'prov' must be an object".into()),
    };
    if o.len() > MAX_PROV_PATHS {
        return Some(format!("'prov' holds more than {MAX_PROV_PATHS} paths"));
    }
    for (k, refs) in o {
        if !is_prov_path(k) {
            return Some(format!("'prov' key '{k}' is not action.params.<name>"));
        }
        let refs = match refs.as_array() {
            Some(r) if !r.is_empty() && r.len() <= MAX_PROV_REFS => r,
            _ => return Some(format!("'prov.{k}' must hold 1..{MAX_PROV_REFS} refs")),
        };
        if !refs.iter().all(|r| is_bounded_string(r, 256)) {
            return Some(format!("'prov.{k}' refs must be non-empty strings (<= 256 bytes)"));
        }
    }
    None
}

/// `parseLabelRef`: `pca-labels:<receipt digest>#<field>` (split at the FIRST `#`, non-empty field).
pub fn parse_label_ref(r: &str) -> Option<(&str, &str)> {
    let rest = r.strip_prefix(LABEL_REF_PREFIX)?;
    let i = rest.find('#')?;
    let (receipt, field) = (&rest[..i], &rest[i + 1..]);
    (decode_ok(receipt) && !field.is_empty()).then_some((receipt, field))
}

fn decode_ok(s: &str) -> bool {
    crate::chain::decode_b64u_strict(s, 32).is_some()
}

/// `setNested(root, path, value)`: false (root possibly partially extended, as in TS) when the path collides.
fn set_nested(root: &mut Map<String, Value>, path: &str, value: Value) -> bool {
    let segs: Vec<&str> = path.split('.').collect();
    let (last, init) = match segs.split_last() {
        Some(x) => x,
        None => return false,
    };
    let mut cur = root;
    for k in init {
        let next = cur.entry(k.to_string()).or_insert_with(|| Value::Object(Map::new()));
        cur = match next.as_object_mut() {
            Some(m) => m,
            None => return false,
        };
    }
    if cur.contains_key(*last) {
        return false;
    }
    cur.insert(last.to_string(), value);
    true
}

/// NORMATIVE rule 17 (`decideParamProvenance`). Every failure is `Deny`; first failure wins. Never panics.
pub fn decide_param_provenance(input: &Value) -> ProvResult {
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    let mut classes: Map<String, Value> = Map::new();
    let lab = |l: &BTreeMap<String, usize>| -> Map<String, Value> { l.iter().map(|(k, r)| (k.clone(), Value::String(TAINT_LEVELS[*r].into()))).collect() };
    macro_rules! deny {
        ($($t:tt)*) => {
            return ProvResult {
                outcome: ProvOutcome::Deny,
                reason: Some(format!("provenance: {}", format!($($t)*))),
                friction: None,
                env: Value::Object(Map::new()),
                labels: lab(&labels),
                classes,
            }
        };
    }
    if !input.is_object() {
        deny!("input must be an object");
    }
    let empty_obj = Value::Object(Map::new());
    let policy = input.get("policy").unwrap_or(&Value::Null);
    if let Some(pe) = validate_provenance_policy(policy) {
        deny!("policy misconfigured (fail closed): {pe}");
    }
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) deny.
    let prov = input.get("prov").unwrap_or(&empty_obj);
    if let Some(we) = validate_prov_wire(prov) {
        deny!("{we}");
    }
    let empty_arr: Vec<Value> = Vec::new();
    let committed = match input.get("committed_labels") {
        None => &empty_arr,
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_LABELS => a,
        Some(_) => deny!("committed labels must be a list of at most {MAX_COMMITTED_LABELS} digests"),
    };
    let mut committed_set: Vec<&str> = Vec::new();
    for d in committed {
        if !is_digest(d) || committed_set.contains(&d.as_str().unwrap_or("")) {
            deny!("committed labels must be distinct canonical 32-byte digests");
        }
        committed_set.push(d.as_str().unwrap_or(""));
    }
    let params = match checked_params(input.get("action")) {
        Ok(p) => p,
        Err(e) => deny!("{e}"),
    };
    let supplied_labels: &[Value] = match input.get("labels") {
        None => &[],
        Some(Value::Array(a)) => a,
        Some(_) => deny!("labels must be an array"),
    };
    let prov_map = prov.as_object().cloned().unwrap_or_default();
    let paths: Vec<&String> = prov_map.keys().collect(); // BTreeMap order == the bytewise sort of ASCII paths
    for p in &paths {
        if resolve_param_path(params, p).is_none() {
            deny!("prov names '{p}', a parameter the action does not carry");
        }
    }
    for a in &paths {
        for b in &paths {
            if a != b && b.starts_with(&format!("{a}.")) {
                deny!("prov paths '{a}' and '{b}' overlap");
            }
        }
    }

    // receipts by reference (supplied receipts nobody committed are ignored)
    let mut receipts: BTreeMap<String, &Value> = BTreeMap::new();
    for r in supplied_labels {
        if validate_labels_wire(r).is_none() {
            if let Some(rf) = labels_ref(r) {
                receipts.insert(rf, r);
            }
        }
    }
    let empty_map = Map::new();
    let reg = policy.get("registry").and_then(Value::as_object).unwrap_or(&empty_map);
    let label_keys = policy.get("label_keys").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let aud = input.get("aud").unwrap_or(&Value::Null);
    let session = input.get("session").unwrap_or(&Value::Null);
    let mut origins: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();

    for p in &paths {
        let value = resolve_param_path(params, p).unwrap_or(&Value::Null);
        let mut rank = 0usize; // refs are non-empty (wire), so the join is the max over them
        for rf in prov_map.get(*p).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            let rf = rf.as_str().unwrap_or("");
            if !rf.starts_with(LABEL_REF_PREFIX) {
                // classifyRef with the registry (own entries only), else agent
                rank = rank.max(reg.get(rf).and_then(taint_rank).unwrap_or(AGENT));
                continue;
            }
            let (receipt_ref, field) = match parse_label_ref(rf) {
                Some(x) => x,
                None => deny!("malformed label ref on '{p}'"),
            };
            if !committed_set.contains(&receipt_ref) {
                deny!("label ref on '{p}' names a receipt the PCActn does not commit");
            }
            let rc = match receipts.get(receipt_ref) {
                Some(r) => *r,
                None => deny!("label receipt for '{p}' was not supplied"),
            };
            if let Some(ve) = verify_labels(rc, label_keys) {
                deny!("label receipt for '{p}': {ve}");
            }
            if rc.get("session").unwrap_or(&Value::Null) != session {
                deny!("label receipt for '{p}' is bound to another session");
            }
            let f = match rc.get("fields").and_then(|fs| fs.get(field)) {
                Some(f) => f,
                None => deny!("label receipt for '{p}' has no field '{field}'"),
            };
            let site = rc.get("site").and_then(Value::as_str).unwrap_or("");
            let matched = strict_hash(value).map_or(false, |h| f.get("value_digest").and_then(Value::as_str) == Some(h.as_str()));
            rank = rank.max(if matched {
                if aud.as_str() == Some(site) {
                    1
                } else {
                    2
                }
            } else {
                AGENT
            });
            origins.entry(p.to_string()).or_default().push((f.get("class").and_then(Value::as_str).unwrap_or("").to_string(), site.to_string()));
        }
        labels.insert(p.to_string(), rank);
    }
    let pparams = policy.get("params").and_then(Value::as_object).unwrap_or(&empty_map);
    for p in pparams.keys() {
        if labels.contains_key(p) {
            continue;
        }
        if resolve_param_path(params, p).is_some() {
            labels.insert(p.clone(), AGENT);
        }
    }
    let flows = policy.get("flows").and_then(Value::as_object).unwrap_or(&empty_map);
    for (p, os) in &origins {
        let mut cs: Vec<&str> = os.iter().map(|(c, _)| c.as_str()).collect();
        cs.sort_unstable();
        cs.dedup();
        classes.insert(p.clone(), Value::Array(cs.iter().map(|c| Value::String(c.to_string())).collect()));
        for (c, origin) in os {
            if !flow_allowed(flows, c, origin, aud) {
                deny!("flow: class '{c}' from '{origin}' may not reach '{}' (parameter '{p}')", aud.as_str().unwrap_or(""));
            }
        }
    }
    let cap = policy.get("critical_max").and_then(taint_rank).unwrap_or(AGENT);
    let sens = |p: &str| pparams.get(p).and_then(Value::as_str);
    for (p, r) in &labels {
        if sens(p) == Some("critical") && *r > cap {
            deny!("critical parameter '{p}' has provenance '{}', above the policy maximum", TAINT_LEVELS[*r]);
        }
    }
    let (mut question, mut typed) = (false, false);
    for (p, r) in &labels {
        let s = match sens(p) {
            Some(s) if *r >= TAINTED_RANK => s,
            _ => continue,
        };
        let mode = if s == "critical" {
            policy.get("critical_tainted").and_then(Value::as_str).unwrap_or("question_typed")
        } else {
            policy.get("material_tainted").and_then(Value::as_str).unwrap_or("question")
        };
        if mode == "deny" {
            deny!("tainted {s} parameter '{p}' (provenance '{}') is denied by policy", TAINT_LEVELS[*r]);
        }
        if mode == "question" || mode == "question_typed" {
            question = true;
        }
        if mode == "question_typed" {
            typed = true;
        }
    }
    let mut env = Map::new();
    for (p, r) in &labels {
        if !set_nested(&mut env, p, Value::String(TAINT_LEVELS[*r].into())) {
            deny!("provenance paths overlap at '{p}'");
        }
    }
    let labels_out = lab(&labels);
    if question {
        ProvResult {
            outcome: ProvOutcome::Question,
            reason: Some("provenance: a tainted value needs the principal (lazy question)".into()),
            friction: Some(if typed { "typed" } else { "tap" }.into()),
            env: Value::Object(env),
            labels: labels_out,
            classes,
        }
    } else {
        ProvResult { outcome: ProvOutcome::Pass, reason: None, friction: None, env: Value::Object(env), labels: labels_out, classes }
    }
}
