//! Forbid-wins certificate check (security contract C-241) and linked policy templates (C-242, C-243): a port of
//! `certificateConsistent` in packages/pca/src/forbid-certificate.ts and of packages/pca/src/policy-link.ts (the TypeScript is
//! authoritative). Every function is total; anything malformed fails closed. Results of the fallible functions are
//! `Ok(value)` / `Err(reason)` with the reference's reason text.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

const TEMPLATE_SIG_DOMAIN: &str = "atlas-pca/policy-template/v1\0";
const TIGHTEN_SIG_DOMAIN: &str = "atlas-pca/template-tighten/v1\0";
const NAME_SOURCE: &str = "^[a-z][a-z0-9_]{0,63}$";
const MAX_SLOTS: usize = 32;
const MAX_SLOT_STRING: usize = 256;
const MAX_SLOT_SET: usize = 64;

fn is_one(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64() == Some(1.0))
}

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// Order by UTF-16 code unit like JavaScript's `<`.
fn u16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

// ---- forbid-wins certificate ----------------------------------------------------------------

/// Whether the certificate's own table entails its decision, winner and shadowed list. `precedence` lists signers from most to
/// least authoritative. No predicate evaluator is needed.
pub fn forbid_certificate_consistent(cert: &Value, precedence: &[String]) -> bool {
    let c = match cert.as_object() {
        Some(c) => c,
        None => return false,
    };
    if !is_one(c.get("v")) || c.get("kind").and_then(Value::as_str) != Some("forbid-wins") {
        return false;
    }
    let (rows, winner, shadowed) = match (
        c.get("clauses").and_then(Value::as_array),
        c.get("winner").and_then(Value::as_object),
        c.get("shadowed").and_then(Value::as_array),
    ) {
        (Some(r), Some(w), Some(s)) => (r, w, s),
        _ => return false,
    };
    if winner.get("kind").and_then(Value::as_str) == Some("malformed") {
        return rows.is_empty()
            && c.get("decision").and_then(Value::as_str) == Some("deny")
            && winner.get("id").map_or(false, Value::is_null)
            && shadowed.is_empty();
    }
    struct Row<'a> {
        id: &'a str,
        kind: &'a str,
        value: &'a str,
        signer: Option<&'a str>,
    }
    let mut table: Vec<Row> = Vec::with_capacity(rows.len());
    for r in rows {
        let o = match r.as_object() {
            Some(o) => o,
            None => return false,
        };
        let (id, kind, value) = match (
            o.get("id").and_then(Value::as_str),
            o.get("kind").and_then(Value::as_str),
            o.get("value").and_then(Value::as_str),
        ) {
            (Some(i), Some(k), Some(v))
                if matches!(k, "permit" | "forbid" | "escalate")
                    && matches!(v, "true" | "false" | "unknown") =>
            {
                (i, k, v)
            }
            _ => return false,
        };
        table.push(Row {
            id,
            kind,
            value,
            signer: o.get("signer").and_then(Value::as_str),
        });
    }
    let rank = |r: &Row| -> usize {
        r.signer
            .and_then(|s| precedence.iter().position(|p| p == s))
            .unwrap_or(precedence.len())
    };
    let hit = |kind: &str| -> Vec<&Row> {
        table
            .iter()
            .filter(|r| r.kind == kind && r.value != "false")
            .collect()
    };
    let mut forbids = hit("forbid");
    forbids.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| u16_cmp(a.id, b.id)));
    let permits = hit("permit");
    let escalates = hit("escalate");
    let (win, decision, kind): (Option<&Row>, &str, &str) = if !forbids.is_empty() {
        (Some(forbids[0]), "deny", "forbid")
    } else if permits.is_empty() {
        (None, "deny", "none")
    } else if !escalates.is_empty() {
        (Some(escalates[0]), "escalate", "escalate")
    } else {
        (Some(permits[0]), "allow", "permit")
    };
    let others: Vec<&str> = forbids
        .iter()
        .chain(permits.iter())
        .chain(escalates.iter())
        .filter(|r| win.map_or(true, |w| !std::ptr::eq(**r, w)))
        .map(|r| r.id)
        .collect();
    let want_id = win.map(|w| w.id);
    c.get("decision").and_then(Value::as_str) == Some(decision)
        && winner.get("kind").and_then(Value::as_str) == Some(kind)
        && winner.get("id").and_then(Value::as_str) == want_id
        && (want_id.is_some() || winner.get("id").map_or(false, Value::is_null))
        && shadowed.len() == others.len()
        && shadowed
            .iter()
            .zip(others.iter())
            .all(|(a, b)| a.as_str() == Some(*b))
}

// ---- linked templates ------------------------------------------------------------------------

fn js_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(_) => "object".into(),
    }
}

fn safe_int_value(v: &Value) -> Option<i64> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

fn scan(v: &Value, decl: &Map<String, Value>, used: &mut BTreeSet<String>) -> Option<String> {
    match v {
        Value::Array(a) => a.iter().find_map(|x| scan(x, decl, used)),
        Value::Object(o) => {
            if let Some(k) = o
                .keys()
                .find(|k| matches!(k.as_str(), "__proto__" | "constructor" | "prototype"))
            {
                return Some(format!("body has the forbidden key '{k}'"));
            }
            if let Some(slot) = o.get("$slot") {
                if let Some(k) = o
                    .keys()
                    .find(|k| !matches!(k.as_str(), "$slot" | "pre" | "post"))
                {
                    return Some(format!("placeholder has unknown member '{k}'"));
                }
                match slot.as_str() {
                    Some(name) if decl.contains_key(name) => {
                        for k in ["pre", "post"] {
                            if o.get(k).map_or(false, |x| !x.is_string()) {
                                return Some(format!("placeholder {k} must be a string"));
                            }
                        }
                        used.insert(name.to_string());
                        None
                    }
                    _ => Some(format!(
                        "placeholder names undeclared slot '{}'",
                        js_string(Some(slot))
                    )),
                }
            } else {
                o.values().find_map(|x| scan(x, decl, used))
            }
        }
        _ => None,
    }
}

/// `None` for a well-formed template definition, else the first problem.
pub fn template_def_error(d: &Value) -> Option<String> {
    let o = match d.as_object() {
        Some(o) => o,
        None => return Some("template must be an object".into()),
    };
    if !is_one(o.get("v")) || o.get("kind").and_then(Value::as_str) != Some("pca-policy-template") {
        return Some("template v / kind mismatch".into());
    }
    if !o.get("id").and_then(Value::as_str).map_or(false, name_ok) {
        return Some(format!("template id must match {NAME_SOURCE}"));
    }
    if !o
        .get("version")
        .and_then(Value::as_str)
        .map_or(false, |s| !s.is_empty() && u16len(s) <= 64)
    {
        return Some("template version must be a string of 1..64 characters".into());
    }
    let slots = match o.get("slots").and_then(Value::as_object) {
        Some(s) => s,
        None => return Some("slots must be an object".into()),
    };
    if slots.len() > MAX_SLOTS {
        return Some(format!("more than {MAX_SLOTS} slots"));
    }
    for (n, s) in slots {
        if !name_ok(n) {
            return Some(format!("slot name '{n}' must match {NAME_SOURCE}"));
        }
        let so = match s.as_object() {
            Some(x) => x,
            None => return Some(format!("slot '{n}' must be an object")),
        };
        let ty = so.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(ty, "string" | "integer" | "set") {
            return Some(format!("slot '{n}'.type must be string, integer or set"));
        }
        if ty == "set" && !so.get("values").map_or(false, Value::is_array) {
            return Some(format!("set slot '{n}' needs a closed values list"));
        }
        if let Some(vals) = so.get("values") {
            let ok = vals.as_array().map_or(false, |a| {
                a.len() <= MAX_SLOT_SET && a.iter().all(Value::is_string)
            });
            if !ok {
                return Some(format!("slot '{n}'.values must be a list of strings"));
            }
        }
        if ty == "integer" {
            for k in ["min", "max"] {
                if so.get(k).map_or(false, |x| safe_int_value(x).is_none()) {
                    return Some(format!("slot '{n}'.{k} must be a safe integer"));
                }
            }
        }
    }
    let body = match o.get("body").and_then(Value::as_object) {
        Some(b) if b.get("predicates").map_or(false, Value::is_array) => b,
        _ => return Some("body.predicates must be an array".into()),
    };
    if body.get("caveats").map_or(false, |c| !c.is_array()) {
        return Some("body.caveats must be an array".into());
    }
    let mut used = BTreeSet::new();
    if let Some(e) = scan(&Value::Object(body.clone()), slots, &mut used) {
        return Some(e);
    }
    slots
        .keys()
        .find(|n| !used.contains(*n))
        .map(|n| format!("slot '{n}' is declared but never used"))
}

/// hashCanonical of the definition (the strict form).
pub fn template_digest(def: &Value) -> Option<String> {
    super::hash_canonical_strict(def)
}

fn message(domain: &str, digest: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(&Sha256::digest(digest.as_bytes()));
    m
}

fn trusted_signer<'a>(signer: Option<&'a Value>, trusted: &[String]) -> Option<&'a str> {
    signer
        .and_then(Value::as_str)
        .filter(|s| trusted.iter().any(|t| t == s))
}

/// Verify a signed template `{def, signer, sig}` against the trusted organisation keys.
pub fn verify_template(t: &Value, trusted: &[String]) -> Result<(), String> {
    let def = t.get("def").unwrap_or(&Value::Null);
    if let Some(e) = template_def_error(def) {
        return Err(e);
    }
    let signer = trusted_signer(t.get("signer"), trusted)
        .ok_or_else(|| "template signer is not trusted".to_string())?;
    let digest = template_digest(def).ok_or_else(|| "bad template signature".to_string())?;
    match t.get("sig").and_then(Value::as_str) {
        Some(sig) if super::verify_b64u(signer, &message(TEMPLATE_SIG_DOMAIN, &digest), sig) => {
            Ok(())
        }
        _ => Err("bad template signature".into()),
    }
}

/// `None` for a well-formed tighten overlay: it may only add `where` conditions and caveats.
pub fn tighten_overlay_error(o: &Value) -> Option<String> {
    let m = match o.as_object() {
        Some(m) => m,
        None => return Some("overlay must be an object".into()),
    };
    if !is_one(m.get("v")) || m.get("kind").and_then(Value::as_str) != Some("pca-template-tighten")
    {
        return Some("overlay v / kind mismatch".into());
    }
    if let Some(k) = m.keys().find(|k| {
        !matches!(
            k.as_str(),
            "v" | "kind" | "template_id" | "version_digest" | "add_where" | "add_caveats"
        )
    }) {
        return Some(format!("overlay has unknown member '{k}' (an overlay can only add where conditions and caveats)"));
    }
    if !m
        .get("template_id")
        .and_then(Value::as_str)
        .map_or(false, name_ok)
    {
        return Some("overlay template_id invalid".into());
    }
    if !m
        .get("version_digest")
        .and_then(Value::as_str)
        .map_or(false, |s| !s.is_empty())
    {
        return Some("overlay version_digest invalid".into());
    }
    if let Some(w) = m.get("add_where") {
        if !w
            .as_array()
            .map_or(false, |a| a.iter().all(Value::is_object))
        {
            return Some("overlay add_where must be a list of conditions".into());
        }
    }
    if let Some(w) = m.get("add_caveats") {
        if !w.as_array().map_or(false, |a| {
            a.iter()
                .all(|c| c.get("type").map_or(false, Value::is_string))
        }) {
            return Some("overlay add_caveats must be a list of caveats".into());
        }
    }
    None
}

/// Verify a signed overlay `{overlay, signer, sig}`.
pub fn verify_tighten(t: &Value, trusted: &[String]) -> Result<(), String> {
    let ov = t.get("overlay").unwrap_or(&Value::Null);
    if let Some(e) = tighten_overlay_error(ov) {
        return Err(e);
    }
    let signer = trusted_signer(t.get("signer"), trusted)
        .ok_or_else(|| "overlay signer is not trusted".to_string())?;
    let digest =
        super::hash_canonical_strict(ov).ok_or_else(|| "bad overlay signature".to_string())?;
    match t.get("sig").and_then(Value::as_str) {
        Some(sig) if super::verify_b64u(signer, &message(TIGHTEN_SIG_DOMAIN, &digest), sig) => {
            Ok(())
        }
        _ => Err("bad overlay signature".into()),
    }
}

fn slot_value_error(name: &str, d: &Map<String, Value>, v: &Value) -> Option<String> {
    let values: Option<Vec<&str>> = d
        .get("values")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect());
    match d.get("type").and_then(Value::as_str).unwrap_or("") {
        "string" => {
            let s = match v.as_str() {
                Some(s) if !s.is_empty() && u16len(s) <= MAX_SLOT_STRING => s,
                _ => {
                    return Some(format!(
                        "slot '{name}' must be a string of 1..{MAX_SLOT_STRING} characters"
                    ))
                }
            };
            if values.as_ref().map_or(false, |vs| !vs.contains(&s)) {
                return Some(format!("slot '{name}' is outside its closed value set"));
            }
            None
        }
        "integer" => {
            let n = match safe_int_value(v) {
                Some(n) => n,
                None => return Some(format!("slot '{name}' must be a safe integer")),
            };
            if d.get("min")
                .and_then(safe_int_value)
                .map_or(false, |m| n < m)
            {
                return Some(format!("slot '{name}' is below its minimum"));
            }
            if d.get("max")
                .and_then(safe_int_value)
                .map_or(false, |m| n > m)
            {
                return Some(format!("slot '{name}' is above its maximum"));
            }
            None
        }
        _ => {
            let a = match v.as_array() {
                Some(a)
                    if !a.is_empty()
                        && a.len() <= MAX_SLOT_SET
                        && a.iter().all(Value::is_string) =>
                {
                    a
                }
                _ => return Some(format!("slot '{name}' must be a non-empty list of strings")),
            };
            let strs: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            if strs.iter().collect::<BTreeSet<_>>().len() != strs.len() {
                return Some(format!("slot '{name}' has duplicate members"));
            }
            if values
                .as_ref()
                .map_or(false, |vs| strs.iter().any(|s| !vs.contains(s)))
            {
                return Some(format!("slot '{name}' has a member outside its closed set"));
            }
            None
        }
    }
}

fn fill(v: &Value, slots: &Map<String, Value>, key: Option<&str>) -> Result<Value, String> {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|x| fill(x, slots, key))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(o) => {
            if let Some(name) = o.get("$slot").and_then(Value::as_str) {
                let val = slots.get(name).cloned().unwrap_or(Value::Null);
                if matches!(key, Some("verb") | Some("resource")) {
                    let items: Vec<&Value> = match &val {
                        Value::Array(a) => a.iter().collect(),
                        x => vec![x],
                    };
                    if items.iter().any(|x| {
                        x.as_str()
                            .map_or(false, |s| s.contains('*') || s.starts_with("re:"))
                    }) {
                        return Err(format!("slot '{name}' would inject a wildcard or regex matcher into a verb or resource"));
                    }
                }
                let pre = o.get("pre").and_then(Value::as_str).unwrap_or("");
                let post = o.get("post").and_then(Value::as_str).unwrap_or("");
                if pre.is_empty() && post.is_empty() {
                    return Ok(val);
                }
                let s = match val.as_str() {
                    Some(s) if !s.contains('*') && !s.contains('\0') => s,
                    _ => {
                        return Err(format!(
                        "slot '{name}' cannot be spliced into a string (wildcard or non-string)"
                    ))
                    }
                };
                let out = format!("{pre}{s}{post}");
                if pre.is_empty() && out.starts_with("re:") {
                    return Err(format!("slot '{name}' would inject a regex matcher"));
                }
                return Ok(Value::String(out));
            }
            let mut m = Map::new();
            for (k, x) in o {
                m.insert(k.clone(), fill(x, slots, Some(k))?);
            }
            Ok(Value::Object(m))
        }
        x => Ok(x.clone()),
    }
}

/// Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots and any slot value that would inject a
/// wildcard or a regex into a verb or resource. On success the policy is `{predicates, caveats}`.
pub fn instantiate_template(def: &Value, slots: &Value) -> Result<Value, String> {
    if let Some(e) = template_def_error(def) {
        return Err(e);
    }
    let sl = slots
        .as_object()
        .ok_or_else(|| "slots must be an object".to_string())?;
    let decl = def["slots"]
        .as_object()
        .ok_or_else(|| "slots must be an object".to_string())?;
    if let Some(k) = sl.keys().find(|k| !decl.contains_key(*k)) {
        return Err(format!("slot '{k}' is not declared by the template"));
    }
    for (n, d) in decl {
        let v = sl
            .get(n)
            .ok_or_else(|| format!("slot '{n}' is not filled"))?;
        if let Some(e) = slot_value_error(n, d.as_object().ok_or("slot must be an object")?, v) {
            return Err(e);
        }
    }
    let body = fill(&def["body"], sl, None)?;
    let mut m = Map::new();
    m.insert("predicates".into(), body["predicates"].clone());
    m.insert(
        "caveats".into(),
        body.get("caveats")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![])),
    );
    Ok(Value::Object(m))
}

/// `None` for a well-formed reference `{template_id, version_digest, slots}`.
pub fn template_ref_error(r: &Value) -> Option<String> {
    let m = match r.as_object() {
        Some(m) => m,
        None => return Some("template_ref must be an object".into()),
    };
    if let Some(k) = m
        .keys()
        .find(|k| !matches!(k.as_str(), "template_id" | "version_digest" | "slots" | "bind_params_digest"))
    {
        return Some(format!("template_ref has unknown member '{k}'"));
    }
    if !m
        .get("template_id")
        .and_then(Value::as_str)
        .map_or(false, name_ok)
    {
        return Some("template_ref.template_id invalid".into());
    }
    if !m
        .get("version_digest")
        .and_then(Value::as_str)
        .map_or(false, |s| !s.is_empty() && s.len() <= 128)
    {
        return Some("template_ref.version_digest invalid".into());
    }
    if m.contains_key("slots") && m.contains_key("bind_params_digest") {
        return Some("template_ref has both slots and bind_params_digest".into());
    }
    if let Some(d) = m.get("bind_params_digest") {
        return match d.as_str() {
            Some(d) if !d.is_empty() && d.encode_utf16().count() <= 128 => None,
            _ => Some("template_ref.bind_params_digest invalid".into()),
        };
    }
    if !m.get("slots").map_or(false, Value::is_object) {
        return Some("template_ref.slots must be an object".into());
    }
    None
}

/// Rebuild the policy a reference denotes from a registry `{templates, overlays?, trusted}`: the template (signature checked)
/// filled with the slots, then every verified overlay for this version. Returns the policy and the number of overlays applied.
pub fn resolve_link(reference: &Value, reg: &Value) -> Result<(Value, usize), String> {
    if let Some(e) = template_ref_error(reference) {
        return Err(e);
    }
    let trusted: Vec<String> = reg["trusted"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let digest = reference["version_digest"].as_str().unwrap_or("");
    let t = reg["templates"]
        .get(digest)
        .ok_or_else(|| "template version is not in the registry".to_string())?;
    verify_template(t, &trusted)?;
    if template_digest(&t["def"]).as_deref() != Some(digest) {
        return Err("registry entry does not match its digest".into());
    }
    if t["def"]["id"] != reference["template_id"] {
        return Err("template id does not match the reference".into());
    }
    let mut slots = &reference["slots"];
    if let Some(bd) = reference.get("bind_params_digest").and_then(Value::as_str) {
        let bound = reg.get("params").and_then(|p| p.get(bd)).filter(|b| b.is_object());
        let Some(bound) = bound else { return Err("parameter object is not available".into()) };
        match super::hash_canonical_strict(bound) {
            None => return Err("link resolution error (fail closed)".into()),
            Some(d) if d != bd => return Err("parameter object does not match bind_params_digest".into()),
            Some(_) => {}
        }
        slots = bound;
    }
    let inst = instantiate_template(&t["def"], slots)?;
    let mut predicates = inst["predicates"].as_array().cloned().unwrap_or_default();
    let mut caveats = inst["caveats"].as_array().cloned().unwrap_or_default();
    let mut applied = 0;
    for o in reg
        .get("overlays")
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[])
    {
        let ov = &o["overlay"];
        if !ov.is_object()
            || ov["version_digest"] != reference["version_digest"]
            || ov["template_id"] != reference["template_id"]
        {
            continue;
        }
        verify_tighten(o, &trusted)?;
        let add = ov
            .get("add_where")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        predicates = predicates
            .into_iter()
            .map(|p| {
                let mut m = p.as_object().cloned().unwrap_or_default();
                let mut w = m
                    .get("where")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                w.extend(add.iter().cloned());
                m.insert("where".into(), Value::Array(w));
                Value::Object(m)
            })
            .collect();
        caveats.extend(
            ov.get("add_caveats")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        applied += 1;
    }
    let mut m = Map::new();
    m.insert("predicates".into(), Value::Array(predicates));
    m.insert("caveats".into(), Value::Array(caveats));
    Ok((Value::Object(m), applied))
}
