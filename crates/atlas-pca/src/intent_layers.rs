//! The layer decision of the v2 verification order (packages/pca/src/intent-layers.ts): `decideLayerCeilings` (the action must be
//! inside G^org, then G^site, then G^std) and `decideLayers` (ceilings, then the denied regions, then G^task_0 and the deltas, then the
//! lazy question). Total: a malformed grant is `intent_denied`, a malformed ceiling is a named `ceiling`; nothing here panics.
use crate::intent_kit::layers::LAYER_CEILINGS;
use crate::predicates::{evaluate_predicates, Ctx};
use serde_json::{json, Value};

/// A well-formed layer: an object with exactly one member, `predicates`, an array.
pub fn is_layer_policy(l: &Value) -> bool {
    l.as_object().is_some_and(|m| m.len() == 1 && m.get("predicates").is_some_and(Value::is_array))
}

fn layer_admits(l: &Value, ctx: &Value) -> bool {
    l.get("predicates").and_then(Value::as_array).is_some_and(|p| evaluate_predicates(p, &Ctx::new(ctx)))
}

fn closed_to(o: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str()))
}

fn fail(layer: &str, reason: String) -> Value {
    json!({"status": "fail", "layer": layer, "reason": reason})
}

fn ceilings_of(layers: &Value, ctx: &Value) -> Value {
    let Some(m) = layers.as_object() else { return fail("org", "layers: the layers member is malformed (not an object)".into()) };
    for k in LAYER_CEILINGS {
        let Some(layer) = m.get(k) else { continue };
        if !is_layer_policy(layer) {
            return fail(k, format!("layers: the {k} ceiling is malformed (null or not {{predicates: [...]}})"));
        }
        if !layer_admits(layer, ctx) {
            return fail(k, format!("layers: the action is outside the {k} ceiling (a ceiling is never a question)"));
        }
    }
    json!({"status": "pass"})
}

/// `decideLayerCeilings`: `{status: "pass"}` or `{status: "fail", layer, reason}` naming the first ceiling that denies. `layers` must be
/// an object with no member other than `org`, `site`, `std` (an unknown member fails, reported as `org`). `ctx` is the action context.
pub fn decide_layer_ceilings(layers: &Value, ctx: &Value) -> Value {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match layers.as_object() {
        Some(m) if !closed_to(m, &LAYER_CEILINGS) => fail("org", "layers: unknown member (the layers object is {org?, site?, std?})".into()),
        _ => ceilings_of(layers, ctx),
    }))
    .unwrap_or_else(|_| fail("org", "layers: evaluation error (fail closed)".into()))
}

/// `decideLayers`: the full layer decision for one action, in order: outside a ceiling is `{decision: "ceiling", layer}`; inside a denied
/// region `{decision: "intent_denied"}`; inside G^task_0 or some delta `{decision: "admit", by}` (0 for G^task_0, k for D_k); otherwise
/// `{decision: "intent_required"}` (an uncertain cell: the lazy question). A grant member other than org / site / std / task / denied, a
/// `denied` that is present but not an array, a `task` that is not an array (it is required), or an entry that is not `{predicates: [...]}`
/// is malformed and yields `intent_denied`: never a question, never an admission.
pub fn decide_layers(g: &Value, ctx: &Value) -> Value {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let denied_out = || json!({"decision": "intent_denied"});
        // a grant that is not an object fails the ceilings check first (named `org`), as the reference does
        let Some(m) = g.as_object() else { return json!({"decision": "ceiling", "layer": "org"}) };
        let mut known: Vec<&str> = LAYER_CEILINGS.to_vec();
        known.extend(["task", "denied"]);
        if !closed_to(m, &known) {
            return denied_out();
        }
        let c = ceilings_of(g, ctx);
        if c["status"] == "fail" {
            return json!({"decision": "ceiling", "layer": c["layer"]});
        }
        let empty = Value::Array(vec![]);
        let (denied, task) = (m.get("denied").unwrap_or(&empty), m.get("task"));
        fn well_formed(v: &Value) -> Option<&Vec<Value>> {
            v.as_array().filter(|a| a.iter().all(is_layer_policy))
        }
        let (Some(denied), Some(task)) = (well_formed(denied), task.and_then(well_formed)) else { return denied_out() };
        if denied.iter().any(|d| layer_admits(d, ctx)) {
            return denied_out();
        }
        match task.iter().position(|t| layer_admits(t, ctx)) {
            Some(by) => json!({"decision": "admit", "by": by}),
            None => json!({"decision": "intent_required"}),
        }
    }))
    .unwrap_or_else(|_| json!({"decision": "intent_denied"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(amount: i64) -> Value {
        json!({"action": {"verb": "pay.create", "resource": "acct", "params": {"amount": amount}}})
    }
    fn layer(max: i64) -> Value {
        json!({"predicates": [{"verb": "pay.create", "resource": "*", "where": [{"field": "action.params.amount", "op": "lte", "value": max}]}]})
    }

    #[test]
    fn ceilings_denied_task_and_the_lazy_question() {
        let g = json!({"org": layer(100), "task": [layer(10), layer(50)], "denied": [layer(0)]});
        assert_eq!(decide_layers(&g, &ctx(0)), json!({"decision": "intent_denied"}), "a denied region wins over the task grants");
        let g = json!({"org": layer(100), "task": [layer(10), layer(50)], "denied": []});
        assert_eq!(decide_layers(&g, &ctx(5)), json!({"decision": "admit", "by": 0}));
        assert_eq!(decide_layers(&g, &ctx(30)), json!({"decision": "admit", "by": 1}));
        assert_eq!(decide_layers(&g, &ctx(70)), json!({"decision": "intent_required"}));
        assert_eq!(decide_layers(&g, &ctx(500)), json!({"decision": "ceiling", "layer": "org"}));
        assert_eq!(decide_layers(&json!({"org": layer(100), "task": [], "denied": [layer(100)]}), &ctx(5)), json!({"decision": "intent_denied"}));
    }

    #[test]
    fn malformed_grants_fail_closed() {
        for g in [
            json!({"task": "x"}),
            json!({"task": [{"predicates": []}], "extra": 1}),
            json!({}),
            json!({"task": [], "denied": null}),
            json!({"task": [json!({"predicates": [], "x": 1})]}),
        ] {
            assert_eq!(decide_layers(&g, &ctx(1)), json!({"decision": "intent_denied"}), "{g}");
        }
        assert_eq!(decide_layers(&json!(null), &ctx(1)), json!({"decision": "ceiling", "layer": "org"}));
        assert_eq!(decide_layer_ceilings(&json!({"bogus": 1}), &ctx(1))["layer"], "org");
        assert_eq!(decide_layer_ceilings(&json!({"site": null}), &ctx(1))["layer"], "site");
        assert_eq!(decide_layer_ceilings(&json!({"std": {"predicates": []}}), &ctx(1))["status"], "fail");
        assert_eq!(decide_layer_ceilings(&json!({}), &ctx(1))["status"], "pass");
    }
}
