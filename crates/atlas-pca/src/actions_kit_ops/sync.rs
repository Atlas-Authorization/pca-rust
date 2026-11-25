//! Keep a platform's action definitions in step with the sources they were imported from (sync.ts). Pure: the caller fetches the
//! source and stores the lock. A def the lock does not attribute to this source is never touched; a changed operation is never
//! carried over as confirmed.

use super::deps;
use super::{u16cmp, Verifier};
use crate::actions::{core_registry, def_digest, validate_def, Registry};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn as_imported(d: &Value) -> Value {
    if d["review"]["state"] == "confirmed" {
        let mut o = d.as_object().cloned().unwrap_or_default();
        o.insert("review".into(), json!({"state": "unreviewed"}));
        Value::Object(o)
    } else {
        d.clone()
    }
}

fn dg(d: &Value) -> Result<String, String> {
    if let Some(e) = validate_def(d) {
        return Err(format!("invalid definition: {e}"));
    }
    def_digest(d).ok_or_else(|| "the definition is not strictly canonical".to_string())
}

/// Merge a fresh import of one source into the current defs: `{defs, entries, deprecated, lock, needsReview}`.
/// `lock` is `{spec_digest, ops, synced_at}` or absent. Errors on an imported def that is not a valid def (fail closed).
pub fn sync_source(
    current: &[Value],
    imported: &[Value],
    spec_digest: &str,
    now: &Value,
    lock: Option<&Value>,
    registry: Option<&Registry>,
    v: Verifier,
) -> Result<Value, String> {
    let core = core_registry();
    let reg = registry.unwrap_or(&core);
    let verb = |d: &Value| d["verb"].as_str().unwrap_or("").to_string();
    let cur: BTreeMap<String, &Value> = current.iter().map(|d| (verb(d), d)).collect();
    let imp: BTreeMap<Vec<u16>, (String, Value)> = imported.iter().map(|d| (verb(d).encode_utf16().collect(), (verb(d), as_imported(d)))).collect();
    let locked_ops = lock.and_then(|l| l.get("ops")).and_then(Value::as_object).cloned().unwrap_or_default();
    let mut ops = Map::new();
    let (mut entries, mut defs): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    for (_, (name, d)) in imp.iter() {
        let digest = dg(d)?;
        ops.insert(name.clone(), json!(digest));
        let locked = if lock.is_some() { locked_ops.get(name).and_then(Value::as_str) } else { None };
        match cur.get(name) {
            None => {
                entries.push(json!({"verb": name, "change": "added"}));
                defs.push(d.clone());
            }
            Some(old) if locked == Some(digest.as_str()) || (locked.is_none() && def_digest(old).as_deref() == Some(digest.as_str())) => {
                entries.push(json!({"verb": name, "change": "unchanged"}));
                defs.push((*old).clone());
            }
            Some(old) => {
                let diff = deps::diff_defs(old, d, reg, v).unwrap_or_else(|e| json!({"class": "incomparable", "reasons": [e]}));
                entries.push(json!({"verb": name, "change": "changed", "diff": diff}));
                defs.push(d.clone());
            }
        }
    }
    let mut deprecated: Vec<String> = locked_ops.keys().filter(|k| !imp.contains_key(&k.encode_utf16().collect::<Vec<u16>>())).cloned().collect();
    deprecated.sort_by(|a, b| u16cmp(a, b));
    for x in &deprecated {
        entries.push(json!({"verb": x, "change": "removed"}));
    }
    let needs = entries.iter().any(|e| matches!(e["change"].as_str(), Some("added") | Some("changed")));
    Ok(
        json!({"defs": defs, "entries": entries, "deprecated": deprecated, "lock": {"spec_digest": spec_digest, "ops": ops, "synced_at": now}, "needsReview": needs}),
    )
}

/// One line per changed entry, then a summary.
pub fn sync_text(r: &Value) -> String {
    let entries = r["entries"].as_array().cloned().unwrap_or_default();
    let mut lines = Vec::new();
    for e in &entries {
        let ch = e["change"].as_str().unwrap_or("");
        if ch == "unchanged" {
            continue;
        }
        let extra = match e.get("diff").filter(|d| !d.is_null()) {
            Some(d) => {
                let rs: Vec<&str> = d["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                format!("  ({}{})", d["class"].as_str().unwrap_or(""), if rs.is_empty() { String::new() } else { format!(": {}", rs.join(", ")) })
            }
            None => String::new(),
        };
        lines.push(format!("{ch:<9} {}{extra}", e["verb"].as_str().unwrap_or("")));
    }
    let n = |c: &str| entries.iter().filter(|e| e["change"] == c).count();
    lines.push(format!(
        "{} added, {} changed, {} removed (deprecated), {} unchanged{}",
        n("added"),
        n("changed"),
        n("removed"),
        n("unchanged"),
        if r["needsReview"] == Value::Bool(true) { "; added and changed actions are unreviewed (strict) until a reviewer confirms them" } else { "" }
    ));
    lines.join("\n")
}
