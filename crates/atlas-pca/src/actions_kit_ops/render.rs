//! Approval-render wrappers, the facade view of a def and the provenance-gate facts (approval-render.ts, facade-spec.ts and
//! provenance.ts). The render itself is `approval::render_approval`. The verifier is the caller's confirmation verifier
//! (absent: nothing is confirmed).

use super::effective::{effective_with, is_confirmed, traits_of_with};
use super::{kerr, u16cmp, Verifier};
use crate::actions::{core_registry, normalize, ActionKitError, Registry};
use crate::approval::{approval_render_digest, render_approval};
use crate::params_digest;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn ae(e: crate::approval::ApprovalError) -> ActionKitError {
    kerr(&e.code, e.message)
}

/// `render_approval`, with the confirmation decided by the verifier (asked only after the render itself succeeded).
pub fn render_approval_with(d: &Value, params: &Value, v: Verifier) -> Result<Value, ActionKitError> {
    let mut r = render_approval(d, params, false).map_err(ae)?;
    r["unreviewed"] = Value::Bool(!is_confirmed(d, v));
    Ok(r)
}

/// H(R) for an executed action; refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb.
pub fn render_digest_for_action(d: &Value, params: &Value, pcactn: &Value, v: Verifier) -> Result<String, ActionKitError> {
    let verb = pcactn["action"]["verb"].as_str();
    if verb != d["verb"].as_str() {
        return Err(kerr(
            "render_verb_mismatch",
            format!(
                "the PCActn is for '{}', the definition for '{}'",
                crate::intent_v2::js_value_string(&pcactn["action"]["verb"]),
                d["verb"].as_str().unwrap_or("")
            ),
        ));
    }
    if pcactn["action"].get("params_digest").and_then(Value::as_str) != Some(params_digest(Some(params)).as_str()) {
        return Err(kerr("render_params_mismatch", "the supplied params are not the params the PCActn signed"));
    }
    approval_render_digest(&render_approval_with(d, params, v)?).map_err(|e| kerr("render_bad", e))
}

/// The approver client's check before it signs: re-render from the pinned def and require the requested digest. Returns the digest to sign.
pub fn approver_render_check(d: &Value, params: &Value, requested: &str, v: Verifier) -> Result<String, ActionKitError> {
    let dg = approval_render_digest(&render_approval_with(d, params, v)?).map_err(|e| kerr("render_bad", e))?;
    if dg != requested {
        return Err(kerr("render_mismatch", "the approval request commits to a render this definition and these params do not produce"));
    }
    Ok(dg)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|x| x != 0.0 && !x.is_nan()),
        _ => true,
    }
}

/// Single-tap (one-gesture) approval is allowed only for a confirmed definition.
pub fn single_tap_allowed(r: &Value) -> bool {
    !truthy(r.get("unreviewed"))
}

/// The step-up renderer derived from the pinned defs (found by verb or alias); an unknown verb is an error, which makes the review a deny.
pub struct Renderer<'a> {
    by_verb: BTreeMap<String, &'a Value>,
    verifier: Verifier<'a>,
}

pub fn renderers_from_defs<'a>(defs: &'a [Value], v: Verifier<'a>) -> Renderer<'a> {
    let mut by_verb: BTreeMap<String, &Value> = BTreeMap::new();
    for d in defs {
        if let Some(x) = d["verb"].as_str() {
            by_verb.insert(x.to_string(), d);
        }
        for a in d.get("aliases").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            by_verb.entry(a.to_string()).or_insert(d);
        }
    }
    Renderer { by_verb, verifier: v }
}

impl Renderer<'_> {
    pub fn render(&self, verb: &str, _resource: &str, params: Option<&Value>) -> Result<Value, ActionKitError> {
        let d = self.by_verb.get(verb).ok_or_else(|| kerr("render_unknown_verb", format!("no pinned action definition for '{verb}'")))?;
        render_approval_with(d, &params.cloned().unwrap_or_else(|| json!({})), self.verifier)
    }
}

// ---- facade-spec.ts ---------------------------------------------------------------------------------------------------------

/// The unique `money.amount`-style parameter of a role, if there is exactly one.
fn param_by_role(d: &Value, role: &str) -> Option<String> {
    let mut hits: Vec<&String> = d["params"].as_object()?.iter().filter(|(_, p)| p.get("role").and_then(Value::as_str) == Some(role)).map(|(n, _)| n).collect();
    hits.sort_by(|a, b| u16cmp(a, b));
    (hits.len() == 1).then(|| hits[0].clone())
}

/// One def to one facade row: reversibility and blast are the EFFECTIVE values; `reviewed` prices the def as reviewed.
pub fn spec_of_def(d: &Value, reg: Option<&Registry>, v: Verifier, reviewed: bool) -> Result<Value, ActionKitError> {
    let core = core_registry();
    let full = effective_with(d, reg.unwrap_or(&core), v)?;
    let e = if reviewed { &full.hint } else { &full.main };
    let verb = d["verb"].as_str().unwrap_or("");
    let mut parts = verb.split('.');
    let connector = parts.next().unwrap_or("");
    let action: Vec<&str> = parts.collect();
    let mut out = Map::new();
    out.insert("connector".into(), json!(connector));
    out.insert("action".into(), json!(action.join(".")));
    out.insert("verb".into(), json!(verb));
    out.insert("reversibility".into(), json!(e.eff.rev));
    out.insert("blastRadius".into(), json!(e.eff.blast_ppm as f64 / 1_000_000.0));
    if let Some(a) = param_by_role(d, "money.amount") {
        out.insert("amountField".into(), json!(a));
    }
    out.insert("description".into(), d.get("description").filter(|x| !x.is_null()).cloned().unwrap_or_else(|| d["title"].clone()));
    if let Some(al) = d.get("aliases").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        let mut s: Vec<String> = al.iter().filter_map(|x| x.as_str().map(String::from)).collect();
        super::sort_u16(&mut s);
        out.insert("aliases".into(), super::jstrs(&s));
    }
    out.insert("traits".into(), super::jstrs(&e.closure));
    Ok(Value::Object(out))
}

pub fn facade_specs(defs: &[Value], reg: Option<&Registry>, v: Verifier, reviewed: bool) -> Result<Vec<Value>, ActionKitError> {
    defs.iter().map(|d| spec_of_def(d, reg, v, reviewed)).collect()
}

// ---- provenance.ts ----------------------------------------------------------------------------------------------------------

/// The gate facts of one def. Unconfirmed means maximally dangerous: no effects, the top trait set, provenance relaxations ignored.
pub fn provenance_info_of(d: &Value, reg: Option<&Registry>, v: Verifier) -> Value {
    let core = core_registry();
    let traits = traits_of_with(d, reg.unwrap_or(&core), v);
    if !is_confirmed(d, v) {
        return json!({"effects": [], "traits": traits});
    }
    let n = normalize(d);
    let mut params = Map::new();
    for (name, p) in n["params"].as_object().into_iter().flatten() {
        if let Some(pm) = p.get("provenance_min") {
            params.insert(name.clone(), pm.clone());
        }
    }
    let mut out = Map::new();
    out.insert("effects".into(), n["effects"].clone());
    out.insert("traits".into(), json!(traits));
    if !params.is_empty() {
        out.insert("params".into(), Value::Object(params));
    }
    Value::Object(out)
}

/// The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb, `None` for an unknown verb.
/// Two defs claiming one name are an error.
pub struct ProvenanceActions {
    by_verb: BTreeMap<String, Value>,
}

pub fn provenance_actions(defs: &[Value], reg: Option<&Registry>, v: Verifier) -> Result<ProvenanceActions, String> {
    let mut by_verb: BTreeMap<String, Value> = BTreeMap::new();
    for d in defs {
        let n = normalize(d);
        let info = provenance_info_of(d, reg, v);
        let mut names = vec![n["verb"].as_str().unwrap_or("").to_string()];
        names.extend(n["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
        for name in names {
            if by_verb.contains_key(&name) {
                return Err(format!("provenanceActions: two definitions claim the verb '{name}'"));
            }
            by_verb.insert(name, info.clone());
        }
    }
    Ok(ProvenanceActions { by_verb })
}

impl ProvenanceActions {
    pub fn apply(&self, verb: &str) -> Option<&Value> {
        self.by_verb.get(verb)
    }
}
