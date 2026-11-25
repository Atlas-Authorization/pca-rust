//! The relational queries over the bounded engine: reachability, vacuity, totality, subsumption, disjointness, equivalence,
//! intent conformance.

use super::enumerate::*;
use super::js::*;
use crate::predicates::MAX_RE_RESOURCE_LEN;
use serde_json::{Map, Value};

/// The grid bound; anything but a non-negative finite number falls back to the default.
pub(crate) fn bound(opts: &Value) -> f64 {
    match fin(own(opts, "maxCombinations")) {
        Some(f) if f >= 0.0 => f,
        _ => DEFAULT_MAX_COMBINATIONS,
    }
}

pub(crate) fn merge_witness(witness: &Value, provided: &Value) -> Value {
    let mut params = match own(witness, "params") {
        p if is_obj(p) => copy_map(p),
        _ => Map::new(),
    };
    for (k, v) in spread(&nil_if_undef(get(provided, "params"))) {
        params.insert(k, v);
    }
    let mut out = u_map(vec![("verb", get(provided, "verb").clone()), ("resource", get(provided, "resource").clone()), ("params", Value::Object(params))]);
    let mut rc = get(provided, "reversibilityClass").clone();
    if is_undef(&rc) || rc.is_null() {
        rc = if has(witness, "reversibilityClass") { own(witness, "reversibilityClass").clone() } else { undef_v() };
    }
    if !is_undef(&rc) {
        out.insert("reversibilityClass".into(), rc);
    }
    if has(witness, "subject") {
        out.insert("subject".into(), own(witness, "subject").clone());
    }
    if has(witness, "env") {
        out.insert("env".into(), own(witness, "env").clone());
    }
    Value::Object(out)
}

pub(crate) fn reason_of(model: &Value) -> Value {
    if has(model, "caveatReason") {
        own(model, "caveatReason").clone()
    } else {
        s("unknown")
    }
}

fn probe_inputs(sets: Vec<Value>, vary: bool) -> Value {
    u(vec![("predicateSets", Value::Array(sets)), ("varyReversibility", Value::Bool(vary))])
}

/// Can any input complete `action` into one the policy admits?
pub(crate) fn reachable(policy: &Value, action: &Value, opts: &Value) -> Value {
    let model = to_model(policy);
    let mx = bound(opts);
    if !caveat_sat(&model) {
        return u(vec![("reachable", Value::Bool(false)), ("reason", s(&format!("caveats unsatisfiable: {}", js(&reason_of(&model)))))]);
    }
    let rc = get(action, "reversibilityClass");
    let cap = rev_cap(&model);
    if let (false, Some(c)) = (is_undef(rc), cap) {
        let idx = rev_index(rc);
        if idx < 0 || idx > c {
            return u(vec![("reachable", Value::Bool(false)), ("reason", s(&format!("reversibility class '{}' exceeds the caveat cap", js(rc))))]);
        }
    }
    if admits_action(&model, action) {
        return u(vec![("reachable", Value::Bool(true)), ("witness", action.clone())]);
    }
    let has_cap = cap.is_some();
    let base = collect_probes(&probe_inputs(vec![Value::Array(probe_set(&model))], has_cap));
    let empty = empty_obj();
    let provided = nn(get(action, "params"), &empty);
    let mut fields: Vec<ProbeField> = vec![];
    for f in &base.fields {
        if let Some(key) = f.path.strip_prefix("action.params.") {
            if let Some(v) = obj(provided).and_then(|m| m.get(key)) {
                fields.push(ProbeField { path: f.path.clone(), values: vec![v.clone()] });
                continue;
            }
        }
        fields.push(f.clone());
    }
    let rev_classes: Vec<Value> = if !is_undef(rc) {
        vec![rc.clone()]
    } else if has_cap {
        rev_list()
    } else {
        vec![Value::Null]
    };
    let pr = Probes { verbs: vec![get(action, "verb").clone()], resources: vec![get(action, "resource").clone()], rev_classes, fields };
    let (hit, overflow) = search(&pr, &mut |rep: &Rep| admits(&model, rep), mx);
    if let Some(h) = hit {
        return u(vec![("reachable", Value::Bool(true)), ("witness", merge_witness(&rep_to_action(&h), action))]);
    }
    if overflow {
        return u(vec![
            ("reachable", Value::Bool(true)),
            ("approximate", Value::Bool(true)),
            ("reason", s("representative grid exceeded the bound; could not prove unreachable")),
        ]);
    }
    let und = req_list(get(&model, "undecidable"));
    if !und.is_empty() {
        return u(vec![
            ("reachable", Value::Bool(true)),
            ("approximate", Value::Bool(true)),
            ("reason", s(&format!("over-approximated ({}); could not construct a witness but cannot prove unreachable", join(und, "; ")))),
        ]);
    }
    u(vec![("reachable", Value::Bool(false)), ("reason", s("no predicate admits this action for any input (proven over the decided fragment)"))])
}

pub(crate) fn probes_for(models: &[Value], verb: &Value) -> Probes {
    let mut sets = vec![];
    let mut vary = false;
    for m in models {
        sets.push(Value::Array(probe_set(m)));
        if has(m, "revCap") {
            vary = true;
        }
    }
    let mut pr = collect_probes(&probe_inputs(sets, vary));
    if !verb.is_null() && !is_undef(verb) {
        pr.verbs = vec![verb.clone()];
    }
    pr
}

/// Does the policy deny everything (optionally restricted to `verb`)?
pub(crate) fn always_denies(policy: &Value, verb: &Value, opts: &Value) -> Value {
    let model = to_model(policy);
    let mx = bound(opts);
    if !caveat_sat(&model) {
        return u(vec![("alwaysDenies", Value::Bool(true)), ("reason", s(&format!("caveats unsatisfiable: {}", js(&reason_of(&model)))))]);
    }
    let (hit, overflow) = search(&probes_for(std::slice::from_ref(&model), verb), &mut |rep: &Rep| admits(&model, rep), mx);
    if let Some(h) = hit {
        return u(vec![("alwaysDenies", Value::Bool(false)), ("witness", rep_to_action(&h))]);
    }
    if overflow {
        return u(vec![
            ("alwaysDenies", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("reason", s("grid exceeded the bound; cannot prove vacuity")),
        ]);
    }
    let und = req_list(get(&model, "undecidable"));
    if !und.is_empty() {
        return u(vec![
            ("alwaysDenies", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("reason", s(&format!("over-approximated ({}); cannot prove vacuity", join(und, "; ")))),
        ]);
    }
    u(vec![("alwaysDenies", Value::Bool(true))])
}

/// Does the policy admit EVERY action of `verb`?
pub(crate) fn always_allows(policy: &Value, verb: &Value, opts: &Value) -> Value {
    let model = to_model(policy);
    let mx = bound(opts);
    if !caveat_sat(&model) {
        return u(vec![("alwaysAllows", Value::Bool(false)), ("reason", s(&format!("caveats unsatisfiable: {}", js(&reason_of(&model)))))]);
    }
    let (hit, overflow) = search(&probes_for(std::slice::from_ref(&model), verb), &mut |rep: &Rep| !admits(&model, rep), mx);
    if let Some(h) = hit {
        return u(vec![("alwaysAllows", Value::Bool(false)), ("counterexample", rep_to_action(&h))]);
    }
    if overflow {
        return u(vec![
            ("alwaysAllows", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("reason", s("grid exceeded the bound; cannot prove totality")),
        ]);
    }
    let und = req_list(get(&model, "undecidable"));
    if !und.is_empty() {
        return u(vec![
            ("alwaysAllows", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("reason", s(&format!("over-approximated ({}); cannot prove totality", join(und, "; ")))),
        ]);
    }
    u(vec![("alwaysAllows", Value::Bool(true))])
}

fn approx_note(models: &[&Value], overflow: bool) -> Option<String> {
    if overflow {
        return Some("representative grid exceeded the bound; cannot prove the relation".to_string());
    }
    let mut reasons = OrdSet::default();
    for m in models {
        for r in req_list(get(m, "undecidable")) {
            reasons.add(r.as_str().unwrap_or(""));
        }
    }
    if !reasons.keys.is_empty() {
        return Some(format!("over-approximated ({}); cannot prove the relation", reasons.keys.join("; ")));
    }
    None
}

fn relation(a: &Value, b: &Value, opts: &Value, pred: &dyn Fn(&Value, &Value, &Rep) -> bool, key: &str, witness_key: &str) -> Value {
    let ma = to_model(a);
    let mb = to_model(b);
    let mx = bound(opts);
    let pr = probes_for(&[ma.clone(), mb.clone()], &Value::Null);
    let (hit, overflow) = search(&pr, &mut |rep: &Rep| pred(&ma, &mb, rep), mx);
    if let Some(h) = hit {
        return u(vec![(key, Value::Bool(false)), (witness_key, rep_to_action(&h))]);
    }
    if let Some(note) = approx_note(&[&ma, &mb], overflow) {
        return u(vec![(key, Value::Bool(false)), ("approximate", Value::Bool(true)), ("reason", s(&note))]);
    }
    u(vec![(key, Value::Bool(true))])
}

/// Does `a` permit everything `b` permits? A counterexample is an action `b` admits that `a` denies.
pub(crate) fn subsumes(a: &Value, b: &Value, opts: &Value) -> Value {
    relation(a, b, opts, &|ma, mb, r| admits(mb, r) && !admits(ma, r), "subsumes", "counterexample")
}

/// Is there no action both policies admit?
pub(crate) fn disjoint(a: &Value, b: &Value, opts: &Value) -> Value {
    relation(a, b, opts, &|ma, mb, r| admits(ma, r) && admits(mb, r), "disjoint", "witness")
}

/// Do the policies admit exactly the same actions?
pub(crate) fn equivalent(a: &Value, b: &Value, opts: &Value) -> Value {
    relation(a, b, opts, &|ma, mb, r| admits(ma, r) != admits(mb, r), "equivalent", "counterexample")
}

fn scope_matches(scope: &Value, resource: &Value) -> bool {
    let sc = match scope.as_str() {
        Some(t) => t,
        None => fail("scope.startsWith is not a function"),
    };
    if sc == "*" {
        return true;
    }
    if let Some(src) = sc.strip_prefix("re:") {
        let res = req_str(resource, "resource");
        if src.encode_utf16().count() > 200 || res.encode_utf16().count() > MAX_RE_RESOURCE_LEN {
            return false;
        }
        return crate::safe_regex::full_match(src, res);
    }
    if let Some(prefix) = sc.strip_suffix('*') {
        return req_str(resource, "resource").starts_with(prefix);
    }
    resource.as_str() == Some(sc)
}

fn intent_violation_kinds(action: &Value, intent: &Value, amount_field: &Value, min_amount: &Value) -> Vec<Value> {
    let mut kinds = vec![];
    let verbs = get(intent, "verbs");
    if !(includes(verbs, &s("*")) || includes(verbs, own(action, "verb"))) {
        kinds.push(s("off-verb"));
    }
    let empty = empty_arr();
    let scopes = req_list(nn(get(intent, "resourceScopes"), &empty));
    if !scopes.is_empty() && !scopes.iter().any(|sc| scope_matches(sc, own(action, "resource"))) {
        kinds.push(s("off-scope"));
    }
    let max_amount = get(intent, "maxAmount");
    if !is_undef(max_amount) {
        let af = amount_field.as_str().unwrap_or("");
        let eo = empty_obj();
        let amt = own(nn(own(action, "params"), &eo), af);
        if is_fin(amt) {
            if gt(amt, max_amount) {
                kinds.push(s("over-amount"));
            } else if lt(amt, min_amount) {
                kinds.push(s("under-amount"));
            }
        }
    }
    kinds
}

fn scope_starts_re(sc: &Value) -> bool {
    match sc.as_str() {
        Some(t) => t.starts_with("re:"),
        None => fail("s.startsWith is not a function"),
    }
}

/// Does the policy admit ONLY actions inside the declared intent envelope?
pub(crate) fn intent_conformance(policy: &Value, intent: &Value, opts: &Value) -> Value {
    let model = to_model(policy);
    let mx = bound(opts);
    let default_field = s("amount");
    let default_min = num(0.0);
    let amount_field = nn(get(intent, "amountField"), &default_field);
    let min_amount = nn(get(intent, "minAmount"), &default_min);
    if !caveat_sat(&model) {
        return u(vec![("conforms", Value::Bool(true)), ("violations", empty_arr())]);
    }
    let mut extra: Vec<Value> = vec![];
    let max_amount = get(intent, "maxAmount");
    if !is_undef(max_amount) {
        let path = format!("action.params.{}", js(amount_field));
        extra.push(u(vec![("path", s(&path)), ("cond", u(vec![("field", s(&path)), ("op", s("lte")), ("value", max_amount.clone())]))]));
        extra.push(u(vec![("path", s(&path)), ("cond", u(vec![("field", s(&path)), ("op", s("gte")), ("value", min_amount.clone())]))]));
    }
    let verbs = req_list(get(intent, "verbs"));
    let extra_verbs: Vec<Value> = verbs.iter().filter(|v| v.as_str() != Some("*")).cloned().collect();
    let has_cap = rev_cap(&model).is_some();
    let empty = empty_arr();
    let pr = collect_probes(&u(vec![
        ("predicateSets", Value::Array(vec![Value::Array(probe_set(&model))])),
        ("extraVerbs", Value::Array(extra_verbs)),
        ("extraResources", nn(get(intent, "resourceScopes"), &empty).clone()),
        ("extraFieldConditions", Value::Array(extra)),
        ("varyReversibility", Value::Bool(has_cap)),
    ]));
    let mut fp = 1.0;
    for f in &pr.fields {
        fp *= f.values.len() as f64;
    }
    if pr.verbs.len() as f64 * pr.resources.len() as f64 * pr.rev_classes.len() as f64 * fp > mx {
        return u(vec![
            ("conforms", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("violations", empty_arr()),
            ("reason", s("grid exceeded the bound; cannot prove conformance")),
        ]);
    }
    let mut violations: Vec<Value> = vec![];
    each_rep(&pr, &mut |rep: &Rep| {
        if !admits(&model, rep) {
            return false;
        }
        let action = rep_to_action(rep);
        let kinds = intent_violation_kinds(&action, intent, amount_field, min_amount);
        if !kinds.is_empty() {
            violations.push(u(vec![("action", action), ("kinds", Value::Array(kinds))]));
            if violations.len() >= 16 {
                return true;
            }
        }
        false
    });
    if !violations.is_empty() {
        return u(vec![("conforms", Value::Bool(false)), ("violations", Value::Array(violations))]);
    }
    let mut intent_regex = false;
    for sc in req_list(nn(get(intent, "resourceScopes"), &empty)) {
        if scope_starts_re(sc) {
            intent_regex = true;
            break;
        }
    }
    let und = req_list(get(&model, "undecidable"));
    if !und.is_empty() || intent_regex {
        let mut reasons = und.clone();
        if intent_regex {
            reasons.push(s("re: intent resource scope not enumerated soundly"));
        }
        return u(vec![
            ("conforms", Value::Bool(false)),
            ("approximate", Value::Bool(true)),
            ("violations", empty_arr()),
            ("reason", s(&format!("over-approximated ({}); cannot prove conformance", join(&reasons, "; ")))),
        ]);
    }
    u(vec![("conforms", Value::Bool(true)), ("violations", empty_arr())])
}

/// The exact admission of a fully-specified action (no existential search).
pub(crate) fn admits_concrete(policy: &Value, action: &Value) -> bool {
    admits_action(&to_model(policy), action)
}
