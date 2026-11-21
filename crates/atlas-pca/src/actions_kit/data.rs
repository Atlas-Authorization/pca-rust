//! The built-in connector defs, the domain-vocabulary defs and bindings and the legacy catalog tables (native port of `builtin.ts`,
//! `builtin-review.ts` and `domain.ts` of the reference). The tables are the reference's own data, embedded as JSON. Without a
//! release signing step the built-ins carry no attestation: unconfirmed, maximally dangerous. The starter templates are
//! not here (they belong to the templates port).

use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::derive::{effect_class, to_ontology};
use super::{arr, get, opt};
use crate::actions::{core_registry, def_digest, Registry};

fn data() -> &'static Value {
    static D: OnceLock<Value> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(include_str!("builtin_data.json")).expect("the embedded action data is valid JSON"))
}

fn list(k: &str) -> Vec<Value> {
    arr(&data()[k]).to_vec()
}

/// The built-in connector defs.
pub fn builtin_defs() -> Vec<Value> {
    list("builtin")
}

/// The domain-vocabulary defs.
pub fn domain_defs() -> Vec<Value> {
    list("domain")
}

/// Built-ins then domain defs: the core pack.
pub fn core_pack_defs() -> Vec<Value> {
    let mut v = builtin_defs();
    v.extend(domain_defs());
    v
}

pub fn legacy_catalog() -> Value {
    data()["legacyCatalog"].clone()
}

pub fn legacy_ontology_effect() -> Value {
    data()["legacyOntologyEffect"].clone()
}

pub fn resolutions() -> Value {
    data()["resolutions"].clone()
}

/// `DOMAIN_VERBS`: the domain bindings by domain.
pub fn domain_verb_bindings() -> Value {
    data()["domainVerbs"].clone()
}

/// `[[verb, defDigest]]` over the core pack, in order.
pub fn core_digests() -> Result<Value, String> {
    let mut out = Vec::new();
    for d in core_pack_defs() {
        out.push(json!([get(&d, "verb"), def_digest(&d).ok_or("the def is not in the strict JSON profile")?]));
    }
    Ok(Value::Array(out))
}

/// The built-in defs with their release attestation where the package carries one: it carries none, so they are unchanged.
pub fn released_builtin_defs() -> Vec<Value> {
    builtin_defs()
}

/// Whether the built-ins are confirmed by a release signature: they are not (no pinned release reviewer key yet).
pub fn builtin_confirmed() -> bool {
    false
}

fn def_of(verb: &str) -> Result<Value, String> {
    core_pack_defs().into_iter().find(|d| get(d, "verb").as_str() == Some(verb)).ok_or_else(|| format!("domain binding names unknown def '{verb}'"))
}

fn bindings(domain: &str) -> Result<Vec<Value>, String> {
    data()["domainVerbs"].get(domain).and_then(Value::as_array).cloned().ok_or_else(|| format!("unknown domain '{domain}'"))
}

/// The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, never assigned). `reg`: the core registry when absent.
pub fn domain_verbs(domain: &str, reg: Option<&Registry>) -> Result<Value, String> {
    let core = core_registry();
    let reg = reg.unwrap_or(&core);
    let bs = bindings(domain)?;
    let defs: Vec<Value> = bs.iter().map(|b| def_of(get(b, "verb").as_str().unwrap_or(""))).collect::<Result<_, _>>()?;
    let onto = to_ontology(&defs, reg, None)?;
    let mut verbs = Vec::new();
    let mut aliases = Map::new();
    for (b, d) in bs.iter().zip(&defs) {
        let id = get(b, "id").as_str().unwrap_or("");
        let bverb = get(b, "verb").as_str().unwrap_or("");
        if !arr(get(d, "aliases")).iter().any(|a| a.as_str() == Some(id)) {
            return Err(format!("domain binding '{id}' is not an alias of '{bverb}'"));
        }
        let ov = arr(&onto["verbs"]).iter().find(|v| v["id"].as_str() == Some(bverb)).ok_or("the ontology lacks the bound verb")?;
        let mut params = Map::new();
        for (nl, dp) in get(b, "params").as_object().into_iter().flatten() {
            let p = ov["params"]
                .get(dp.as_str().unwrap_or(""))
                .filter(|p| !p.is_null())
                .ok_or_else(|| format!("domain binding '{id}' surfaces unknown parameter '{}'", dp.as_str().unwrap_or("")))?;
            let money_ccys = opt(b, "ccys");
            params.insert(
                nl.clone(),
                if p["kind"].as_str() == Some("money") && money_ccys.is_some() { json!({"kind": "money", "ccys": money_ccys}) } else { p.clone() },
            );
        }
        verbs.push(json!({"id": id, "effect": effect_class(d), "resource_type": get(b, "resourceType"), "params": Value::Object(params)}));
        for a in arr(get(d, "aliases")) {
            if a.as_str() != Some(id) {
                aliases.insert(a.as_str().unwrap_or("").to_string(), json!(id));
            }
        }
    }
    Ok(json!({"verbs": verbs, "aliases": Value::Object(aliases)}))
}

/// The role map of a domain verb for the selector layer: role -> NL parameter names carrying it.
pub fn domain_roles(domain: &str) -> Result<Value, String> {
    let mut out = Map::new();
    for b in bindings(domain)? {
        let d = def_of(get(&b, "verb").as_str().unwrap_or(""))?;
        let mut roles: Map<String, Value> = Map::new();
        for (nl, dp) in get(&b, "params").as_object().into_iter().flatten() {
            let role = get(&d, "params").get(dp.as_str().unwrap_or("")).and_then(|pd| opt(pd, "role")).and_then(Value::as_str);
            if let Some(r) = role {
                match roles.get_mut(r).and_then(Value::as_array_mut) {
                    Some(a) => a.push(json!(nl)),
                    None => {
                        roles.insert(r.to_string(), json!([nl]));
                    }
                }
            }
        }
        out.insert(get(&b, "id").as_str().unwrap_or("").to_string(), Value::Object(roles));
    }
    Ok(Value::Object(out))
}
