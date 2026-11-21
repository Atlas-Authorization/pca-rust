//! The outcome space derived from a site's signed action schema (`schema.ts` with the wallet-floor helpers of the core intent
//! extension): dimensions only for parameters whose effective sensitivity (after the wallet floor) is material or critical,
//! canonical projections for boolean / set / array parameters, and default sets for silent parameters.
//!
//! The literal-derived base space comes from [`crate::intent_kit::omega::derive_omega`] (the omega port).
use super::{js_str, num_json};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const WALLET_FLOOR_PREFIXES: [&str; 5] = ["money.", "party.", "contact.", "person.", "credential."];
pub const WALLET_FLOOR_EXACT: [&str; 1] = ["text.message"];
const REV: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const OTHER: &str = "\u{22a5}";

fn str_list(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
}

fn floor_applies(semantic: &str, floor: Option<&Value>) -> bool {
    let f = floor.filter(|f| f.is_object());
    let pre = f.and_then(|f| str_list(f.get("prefixes"))).unwrap_or_else(|| WALLET_FLOOR_PREFIXES.iter().map(|s| s.to_string()).collect());
    let ex = f.and_then(|f| str_list(f.get("exact"))).unwrap_or_else(|| WALLET_FLOOR_EXACT.iter().map(|s| s.to_string()).collect());
    ex.iter().any(|e| e == semantic) || pre.iter().any(|p| semantic.starts_with(p.as_str()))
}

/// A site `free` on a floored semantic type becomes `material`.
pub fn effective_sensitivity(d: &Value, floor: Option<&Value>) -> Result<Value, String> {
    let s = d.get("sensitivity");
    if s.and_then(Value::as_str) == Some("free") {
        let sem = d.get("semantic").and_then(Value::as_str).ok_or("effectiveSensitivity: semantic must be a string")?;
        if floor_applies(sem, floor) {
            return Ok(json!("material"));
        }
    }
    Ok(s.cloned().unwrap_or(Value::Null))
}

fn rank(r: &str) -> i32 {
    REV.iter().position(|x| *x == r).map_or(-1, |i| i as i32)
}

/// rev(v) = max over outcomes of the declared reversibility (the conservative projection).
pub fn verb_reversibility(v: &Value) -> Result<String, String> {
    let rb = v.get("reversibility_by").filter(|r| crate::wallet_omega::truthy(r));
    let Some(rb) = rb else {
        return Ok(match v.get("reversibility").filter(|r| crate::wallet_omega::truthy(r)).and_then(Value::as_str) {
            Some(r) => r.to_string(),
            None if v.get("kind").and_then(Value::as_str) == Some("read") => "reversible".into(),
            None => "irreversible".into(),
        });
    };
    let param = rb.get("param").and_then(Value::as_str).ok_or("reversibility_by.param must be a string")?;
    let d = v.get("params").and_then(|p| p.get(param)).filter(|d| d.is_object());
    let map = rb.get("map").and_then(Value::as_object).ok_or("reversibility_by.map must be an object")?;
    let mut items: Vec<String> = map.values().map(|x| js_str(Some(x))).collect();
    let dtype = d.and_then(|d| d.get("type")).and_then(Value::as_str);
    let domain: Option<Vec<String>> = match dtype {
        Some("boolean") => Some(vec!["true".into(), "false".into()]),
        Some("string") => str_list(d.and_then(|d| d.get("values"))).filter(|v| !v.is_empty()),
        _ => None,
    };
    let covered = domain.as_ref().is_some_and(|dom| dom.iter().all(|x| map.contains_key(x)));
    if !covered {
        items.push(rb.get("default").filter(|x| crate::wallet_omega::truthy(x)).map_or("irreversible".to_string(), |x| js_str(Some(x))));
    }
    let mut best: Option<&String> = None;
    for it in &items {
        if best.map_or(true, |b| rank(it) > rank(b)) {
            best = Some(it);
        }
    }
    Ok(best.cloned().unwrap_or_else(|| "reversible".into()))
}

/// Every override the wallet floor makes on a schema (`doc = {verbs}`).
pub fn wallet_floor_overrides(doc: &Value, floor: Option<&Value>) -> Result<Value, String> {
    let mut out = vec![];
    for v in doc.get("verbs").and_then(Value::as_array).ok_or("verbs must be a list")? {
        let params = v.get("params").and_then(Value::as_object).ok_or("params must be an object")?;
        let mut keys: Vec<&String> = params.keys().collect();
        keys.sort();
        for path in keys {
            let d = &params[path.as_str()];
            let eff = effective_sensitivity(d, floor)?;
            let declared = d.get("sensitivity").cloned().unwrap_or(Value::Null);
            if eff != declared {
                out.push(json!({ "verb": v["verb"], "path": path, "semantic": d["semantic"], "declared": declared, "effective": eff }));
            }
        }
    }
    Ok(Value::Array(out))
}

fn canon_path(p: &str) -> String {
    format!("env.canon.{}", p.strip_prefix("action.params.").map_or_else(|| p.chars().skip(14).collect::<String>(), str::to_string))
}

fn uses_canon(d: &Value) -> bool {
    matches!(d.get("type").and_then(Value::as_str), Some("boolean" | "set" | "array"))
}

/// The canonical text a value of a canon-projected parameter has.
pub fn canon_value(d: &Value, x: &Value) -> Result<String, String> {
    match d.get("type").and_then(Value::as_str) {
        Some("boolean") => Ok(if x == &Value::Bool(true) { "true" } else { "false" }.to_string()),
        Some("set") => {
            let a = x.as_array().ok_or("x is not iterable")?;
            let mut strs: Vec<&Value> = a.iter().collect();
            // UTF-8 byte order is `str` order for any valid string
            strs.sort_by(|p, q| p.as_str().unwrap_or("").cmp(q.as_str().unwrap_or("")));
            crate::canonicalize_strict(&Value::Array(strs.into_iter().cloned().collect()))
        }
        _ => crate::canonicalize_strict(x),
    }
}

fn is_safe_int(x: &Value) -> bool {
    x.is_number() && x.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0)
}

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

/// Derive the schema outcome space: `{omega, overrides, defaults, canonOf}`.
pub fn derive_omega_from_schema(o: &Value) -> Result<Value, String> {
    let schema_verbs: Vec<Value> = o.get("schema").and_then(|s| s.get("verbs")).and_then(Value::as_array).cloned().ok_or("schema.verbs must be a list")?;
    let slots = o.get("slots").filter(|s| !s.is_null());
    let mut verb_names: Vec<String> = vec![];
    match o.get("verbs").filter(|v| !v.is_null()) {
        Some(vs) => verb_names = vs.as_array().ok_or("verbs must be a list")?.iter().map(|x| js_str(Some(x))).collect(),
        None => {
            let mut push = |s: String| {
                if !verb_names.contains(&s) {
                    verb_names.push(s);
                }
            };
            for v in schema_verbs.iter().filter(|v| v.get("kind").and_then(Value::as_str) == Some("write")) {
                push(js_str(v.get("verb")));
            }
            for v in slots.and_then(|s| s.get("verbs")).and_then(Value::as_array).into_iter().flatten() {
                push(js_str(Some(v)));
            }
        }
    }
    let base = crate::intent_kit::omega::derive_omega(&json!({
        "policies": o.get("policies").filter(|p| !p.is_null()).cloned().unwrap_or(json!([])),
        "slots": slots.cloned().unwrap_or(Value::Null),
        "extraVerbs": verb_names,
    }))?
    .to_json();
    let base_verbs: Vec<Value> = base.get("verbs").and_then(Value::as_array).cloned().unwrap_or_default();
    let (confirmed, floor) = (o.get("confirmed").filter(|c| c.is_object()), o.get("floor").filter(|f| !f.is_null()));
    let domains = o.get("domains").filter(|d| d.is_object());
    let mut defaults: Vec<Value> = vec![];
    let mut canon_of = Map::new();
    let mut verbs: Vec<Value> = vec![];
    let mut sorted_names = verb_names.clone();
    sorted_names.sort();
    for verb in &sorted_names {
        let Some(decl) = schema_verbs.iter().find(|v| v.get("verb").and_then(Value::as_str) == Some(verb.as_str())) else { continue };
        let lits = base_verbs.iter().find(|v| v.get("verb").and_then(Value::as_str) == Some(verb.as_str()));
        let lit_dims: &[Value] = lits.and_then(|l| l.get("dims")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
        let path_of = |d: &Value| d.get("path").and_then(Value::as_str).unwrap_or("").to_string();
        let mut dims: Vec<Value> = lit_dims.iter().filter(|d| !path_of(d).starts_with("action.params.")).cloned().collect();
        let params = decl.get("params").and_then(Value::as_object).ok_or("params must be an object")?;
        let mut paths: Vec<&String> = params.keys().collect();
        paths.sort();
        for path in paths {
            let pd = &params[path.as_str()];
            if effective_sensitivity(pd, floor)?.as_str() == Some("free") {
                continue;
            }
            let lit = lit_dims.iter().find(|d| path_of(d) == *path);
            let silent = lit.is_none();
            let mut default_set: Vec<Value> = confirmed.and_then(|c| c.get(path.as_str())).and_then(Value::as_array).cloned().unwrap_or_default();
            if pd.get("principal_neutral_default") == Some(&Value::Bool(true)) {
                if let Some(dv) = pd.get("default") {
                    default_set.push(dv.clone());
                }
            }
            if pd.get("type").and_then(Value::as_str) == Some("integer") {
                let mut cuts: Vec<f64> = match lit {
                    Some(l) if l.get("kind").and_then(Value::as_str) == Some("num") => {
                        l.get("cuts").and_then(Value::as_array).map(|a| a.iter().map(f).collect()).unwrap_or_default()
                    }
                    _ => vec![],
                };
                for x in &default_set {
                    if is_safe_int(x) && !cuts.contains(&f(x)) {
                        cuts.push(f(x));
                    }
                }
                cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                cuts.dedup();
                let max_cut = cuts.last().copied().unwrap_or(0.0);
                let dom = domains.and_then(|d| d.get(path.as_str())).filter(|d| d.is_object());
                let pick = |dv: Option<&Value>, pv: Option<&Value>, fallback: f64| -> f64 {
                    dv.filter(|v| !v.is_null()).or(pv.filter(|v| !v.is_null())).map_or(fallback, f)
                };
                let lo = pick(dom.and_then(|d| d.get("lo")), pd.get("min"), f64::min(0.0, cuts.first().map_or(0.0, |c| c - 1.0)));
                let hi = pick(dom.and_then(|d| d.get("hi")), pd.get("max"), f64::max(f64::max(10.0, 2.0 * max_cut), max_cut + 10.0));
                let kept: Vec<Value> = cuts.iter().filter(|&&c| c >= lo && c <= hi).map(|&c| num_json(c)).collect();
                dims.push(json!({ "kind": "num", "path": path, "lo": num_json(lo), "hi": num_json(hi), "cuts": kept, "dist": if lo >= 0.0 { "loguniform" } else { "uniform" } }));
                let nums: Vec<&Value> = default_set.iter().filter(|x| x.is_number()).collect();
                if silent && nums.len() == 1 {
                    defaults.push(json!({ "verb": verb, "path": path, "min": nums[0], "max": nums[0] }));
                }
                continue;
            }
            let canon = uses_canon(pd);
            let dim_path = if canon { canon_path(path) } else { path.clone() };
            if canon {
                canon_of.insert(dim_path.clone(), json!(path));
            }
            let (mut exacts, mut prefixes): (BTreeSet<String>, BTreeSet<String>) = (BTreeSet::new(), BTreeSet::new());
            if let Some(l) = lit.filter(|l| l.get("kind").and_then(Value::as_str) == Some("cat")) {
                for v in l.get("values").and_then(Value::as_array).into_iter().flatten() {
                    let val = js_str(v.get("value"));
                    match v.get("kind").and_then(Value::as_str) {
                        Some("exact") => {
                            exacts.insert(val);
                        }
                        Some("prefix") => {
                            prefixes.insert(val);
                        }
                        _ => {}
                    }
                }
            }
            if pd.get("type").and_then(Value::as_str) == Some("string") {
                for v in pd.get("values").and_then(Value::as_array).into_iter().flatten() {
                    exacts.insert(js_str(Some(v)));
                }
            }
            if pd.get("type").and_then(Value::as_str) == Some("boolean") {
                exacts.insert("false".into());
                exacts.insert("true".into());
            }
            let mut def_texts: Vec<String> = vec![];
            for x in &default_set {
                def_texts.push(if canon { canon_value(pd, x)? } else { js_str(Some(x)) });
            }
            exacts.extend(def_texts.iter().cloned());
            let mut values: Vec<Value> = exacts.iter().map(|v| json!({ "kind": "exact", "value": v })).collect();
            values.extend(prefixes.iter().map(|v| json!({ "kind": "prefix", "value": v })));
            values.push(json!({ "kind": "other", "value": OTHER }));
            dims.push(json!({ "kind": "cat", "path": dim_path, "values": values }));
            if silent && !def_texts.is_empty() {
                let one_of: BTreeSet<&String> = def_texts.iter().collect();
                defaults.push(json!({ "verb": verb, "path": dim_path, "oneOf": one_of }));
            }
        }
        dims.sort_by(|a, b| path_of(a).cmp(&path_of(b)));
        verbs.push(json!({ "verb": verb, "reversibility": verb_reversibility(decl)?, "weight": 0, "dims": dims }));
    }
    let w = 1.0 / (verbs.len().max(1) as f64);
    for v in &mut verbs {
        v["weight"] = serde_json::Number::from_f64(w).map(Value::Number).unwrap_or(Value::Null);
    }
    let kept: Vec<Value> =
        schema_verbs.iter().filter(|v| verb_names.iter().any(|n| Some(n.as_str()) == v.get("verb").and_then(Value::as_str))).cloned().collect();
    let overrides = wallet_floor_overrides(&json!({ "verbs": kept }), floor)?;
    Ok(
        json!({ "omega": { "v": 1, "verbs": verbs, "approximate": base.get("approximate").cloned().unwrap_or(json!([])) }, "overrides": overrides, "defaults": defaults, "canonOf": canon_of }),
    )
}
