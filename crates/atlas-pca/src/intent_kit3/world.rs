//! Outcome-space dimensions filled by the verifier: world facts (`env.world.*`), provenance (`env.prov.*`) and attested classifier
//! labels (`env.class.*`) (`world.ts`). Every helper only adds a dimension, which refines the space.
use crate::grants::u16key;
use serde_json::{json, Map, Value};

pub const WORLD_PREFIX: &str = "env.world.";
pub const PROV_PREFIX: &str = "env.prov.";
pub const CLASS_PREFIX: &str = "env.class.";
const OTHER: &str = "\u{22a5}";

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

/// A numeric world dimension `env.world.<name>`: `o = {lo, hi, cuts?, dist?}`.
pub fn world_dim(name: &str, o: &Value) -> Result<Value, String> {
    let (lo, hi) = (o.get("lo").ok_or("worldDim: lo is required")?, o.get("hi").ok_or("worldDim: hi is required")?);
    let cuts_in: &[Value] = match o.get("cuts") {
        Some(Value::Array(a)) => a,
        None | Some(Value::Null) => &[],
        Some(_) => return Err("object is not iterable".into()),
    };
    let mut cuts: Vec<&Value> = vec![];
    for c in cuts_in {
        if !cuts.iter().any(|x| f(x) == f(c)) && f(c) >= f(lo) && f(c) <= f(hi) {
            cuts.push(c);
        }
    }
    cuts.sort_by(|a, b| f(a).partial_cmp(&f(b)).unwrap_or(std::cmp::Ordering::Equal));
    let dist = o.get("dist").filter(|d| !d.is_null()).cloned().unwrap_or(json!("uniform"));
    Ok(json!({ "kind": "num", "path": format!("{WORLD_PREFIX}{name}"), "lo": lo, "hi": hi, "cuts": cuts, "dist": dist }))
}

/// The optimality dimension: excess >= 0, cuts at 0 and at every slack literal.
pub fn excess_dim(name: &str, hi: &Value, slacks: &[Value]) -> Result<Value, String> {
    let mut cuts = vec![json!(0)];
    cuts.extend(slacks.iter().cloned());
    world_dim(name, &json!({ "lo": 0, "hi": hi, "cuts": cuts, "dist": "loguniform" }))
}

/// The default slot compiler's optimality constraint: `excess <= slack` (default slack 0).
pub fn optimality_condition(name: &str, slack: Option<&Value>) -> Value {
    json!({ "field": format!("{WORLD_PREFIX}{name}"), "op": "lte", "value": slack.cloned().unwrap_or(json!(0)) })
}

/// `env.prov.<path>` with the cells {first_party}, {trusted} and the OTHER cell (the tainted values).
pub fn provenance_dim(param_path: &str) -> Value {
    json!({ "kind": "cat", "path": format!("{PROV_PREFIX}{param_path}"),
        "values": [{ "kind": "exact", "value": "first_party" }, { "kind": "exact", "value": "trusted" }, { "kind": "other", "value": OTHER }] })
}

/// `env.class.<id>` over the classifier's closed label set (the OTHER cell is never output).
pub fn classifier_dim(id: &str, labels: &[String]) -> Value {
    let mut uniq: Vec<&String> = vec![];
    for l in labels {
        if !uniq.contains(&l) {
            uniq.push(l);
        }
    }
    uniq.sort(); // UTF-8 byte order
    let mut values: Vec<Value> = uniq.into_iter().map(|v| json!({ "kind": "exact", "value": v })).collect();
    values.push(json!({ "kind": "other", "value": OTHER }));
    json!({ "kind": "cat", "path": format!("{CLASS_PREFIX}{id}"), "values": values })
}

/// A copy of the space with `dims` added to `verb` (dimensions kept sorted by path).
pub fn with_dims(omega: &Value, verb: &str, dims: &[Value]) -> Result<Value, String> {
    let mut verbs: Vec<Value> = vec![];
    for vs in omega.get("verbs").and_then(Value::as_array).ok_or("omega.verbs must be a list")? {
        if vs.get("verb").and_then(Value::as_str) != Some(verb) {
            verbs.push(vs.clone());
            continue;
        }
        let have: Vec<&str> = vs.get("dims").and_then(Value::as_array).into_iter().flatten().filter_map(|d| d.get("path").and_then(Value::as_str)).collect();
        for d in dims {
            let p = d.get("path").and_then(Value::as_str).unwrap_or("");
            if have.contains(&p) {
                return Err(format!("withDims: {verb} already has a dimension {p}"));
            }
        }
        let mut all: Vec<Value> = vs.get("dims").and_then(Value::as_array).cloned().unwrap_or_default();
        all.extend(dims.iter().cloned());
        all.sort_by_key(|d| u16key(d.get("path").and_then(Value::as_str).unwrap_or("")));
        let mut out = vs.clone();
        out["dims"] = Value::Array(all);
        verbs.push(out);
    }
    if !verbs.iter().any(|v| v.get("verb").and_then(Value::as_str) == Some(verb)) {
        return Err(format!("withDims: no verb {verb} in \u{3a9}"));
    }
    let mut out = omega.clone();
    out["verbs"] = Value::Array(verbs);
    Ok(out)
}

fn get_path<'a>(root: Option<&'a Value>, segs: &[&str]) -> Option<&'a Value> {
    let mut cur = root?;
    for s in segs {
        cur = match cur {
            Value::Object(m) => m.get(*s)?,
            Value::Array(a) => {
                let i: usize = s.parse().ok().filter(|i: &usize| i.to_string() == *s)?;
                a.get(i)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

/// Lift a concrete outcome with the verifier-computed env: fill every world / prov / class dimension path from it. A provenance
/// dimension with no computed label is `agent` (fail closed: the tainted cell).
pub fn lift_outcome(o: &Value, env: &Value, dim_paths: &[String]) -> Result<Value, String> {
    let mut values: Map<String, Value> = o.get("values").and_then(Value::as_object).cloned().ok_or("outcome.values must be an object")?;
    let (world, prov, cls) = (env.get("world"), env.get("prov"), env.get("class"));
    for p in dim_paths {
        if let Some(name) = p.strip_prefix(WORLD_PREFIX) {
            if let Some(v) = get_path(world, &[name]).filter(|v| v.is_number() || v.is_string()) {
                values.insert(p.clone(), v.clone());
            }
        } else if let Some(rest) = p.strip_prefix(PROV_PREFIX) {
            let segs: Vec<&str> = rest.split('.').collect();
            let v = get_path(prov, &segs).filter(|v| v.is_string()).cloned().unwrap_or(json!("agent"));
            values.insert(p.clone(), v);
        } else if let Some(name) = p.strip_prefix(CLASS_PREFIX) {
            if let Some(v) = get_path(cls, &[name]).filter(|v| v.is_string()) {
                values.insert(p.clone(), v.clone());
            }
        }
    }
    Ok(json!({ "verb": o["verb"], "values": values }))
}
