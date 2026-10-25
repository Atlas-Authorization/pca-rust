//! Intent Layer v2 V5, the verifier side of layered intent (`packages/pca/src/intent-layers.ts`, `decideLayerCeilings` /
//! `decideLayers`): the action must be inside G^org, then G^site, then G^std. Each ceiling is a predicate set evaluated by
//! the ONE predicate evaluator ([`crate::predicates::evaluate_predicates`]) against the same root as the admitting grant's
//! predicates. CLOSED AND TYPED: the layers object is `{org?, site?, std?}` (an unknown member fails, reported as `org`), a
//! layer is exactly `{predicates: [...]}`; an ABSENT ceiling is no constraint, a ceiling PRESENT with `null` or any other
//! value is malformed and fails as that ceiling. The first ceiling that denies is named; a ceiling is never a question.
use crate::predicates::{evaluate_predicates, Ctx};
use serde_json::Value;

pub const LAYER_CEILINGS: [&str; 3] = ["org", "site", "std"];

/// `isLayerPolicy`: an object with exactly one member, `predicates`, an array.
pub fn is_layer_policy(l: &Value) -> bool {
    match l {
        Value::Object(o) => o.len() == 1 && o.get("predicates").is_some_and(Value::is_array),
        _ => false,
    }
}

fn layer_admits(layer: &Value, root: &Value) -> bool {
    match layer.get("predicates").and_then(Value::as_array) {
        Some(preds) => evaluate_predicates(preds, &Ctx::new(root)).allowed,
        None => false,
    }
}

fn ceilings_of(layers: &Value, root: &Value) -> Result<(), (&'static str, String)> {
    let o = match layers {
        Value::Object(o) => o,
        _ => return Err(("org", "layers: the layers member is malformed (not an object)".into())),
    };
    for k in LAYER_CEILINGS {
        let Some(l) = o.get(k) else { continue };
        if !is_layer_policy(l) {
            return Err((k, format!("layers: the {k} ceiling is malformed (null or not {{predicates: [...]}})")));
        }
        if !layer_admits(l, root) {
            return Err((k, format!("layers: the action is outside the {k} ceiling (a ceiling is never a question)")));
        }
    }
    Ok(())
}

/// `decideLayerCeilings(layers, ctx)`: `Ok(())` = pass; `Err((layer, reason))` names the first ceiling the action is outside
/// (or that is malformed). `root` is the predicate root `{action: {verb, resource, params}, env: {canon?}}`.
pub fn decide_layer_ceilings(layers: &Value, root: &Value) -> Result<(), (&'static str, String)> {
    if let Value::Object(o) = layers {
        if o.keys().any(|k| !LAYER_CEILINGS.contains(&k.as_str())) {
            return Err(("org", "layers: unknown member (the layers object is {org?, site?, std?})".into()));
        }
    }
    ceilings_of(layers, root)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayerDecision {
    Admit(usize),
    Ceiling(&'static str),
    IntentDenied,
    IntentRequired,
}

/// `decideLayers(g, ctx)`: ceilings, then denied regions (veto), then G^task_0 / deltas, else the lazy question. A grant
/// member other than org / site / std / task / denied, a non-array `task` (required) or present `denied`, or an entry that
/// is not a layer is `intent_denied` (fail closed).
pub fn decide_layers(g: &Value, root: &Value) -> LayerDecision {
    if let Value::Object(o) = g {
        if o.keys().any(|k| !LAYER_CEILINGS.contains(&k.as_str()) && k != "task" && k != "denied") {
            return LayerDecision::IntentDenied;
        }
    }
    if let Err((layer, _)) = ceilings_of(g, root) {
        return LayerDecision::Ceiling(layer);
    }
    let empty = Vec::new();
    let denied = match g.get("denied") {
        None => &empty,
        Some(Value::Array(a)) => a,
        Some(_) => return LayerDecision::IntentDenied,
    };
    let task = match g.get("task") {
        Some(Value::Array(a)) => a,
        _ => return LayerDecision::IntentDenied,
    };
    if !denied.iter().all(is_layer_policy) || !task.iter().all(is_layer_policy) {
        return LayerDecision::IntentDenied;
    }
    if denied.iter().any(|d| layer_admits(d, root)) {
        return LayerDecision::IntentDenied;
    }
    match task.iter().position(|t| layer_admits(t, root)) {
        Some(i) => LayerDecision::Admit(i),
        None => LayerDecision::IntentRequired,
    }
}
