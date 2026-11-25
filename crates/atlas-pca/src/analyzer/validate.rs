//! Lint a policy against the action schema / action definitions it is written for.

use super::enumerate::to_model;
use super::filter::typeof_v;
use super::js::*;
use super::query::always_denies;
use serde_json::{Map, Value};
use std::collections::HashMap;

fn def_shape(p: &Value) -> Value {
    let mut out = Map::new();
    if let Some(t) = get(p, "type").as_str() {
        if matches!(t, "string" | "integer" | "boolean" | "date" | "set" | "array") {
            out.insert("type".into(), s(t));
        }
    }
    let v = get(p, "role");
    if truthy(v) {
        out.insert("semantic".into(), v.clone());
    }
    let v = get(p, "values");
    if truthy(v) {
        out.insert("values".into(), v.clone());
    }
    for k in ["min", "max"] {
        let v = get(p, k);
        if !is_undef(v) {
            out.insert(k.into(), v.clone());
        }
    }
    let v = get(p, "sensitivity");
    if truthy(v) {
        out.insert("sensitivity".into(), v.clone());
    }
    let v = get(p, "required");
    if !is_undef(v) {
        out.insert("required".into(), v.clone());
    }
    Value::Object(out)
}

/// `Object.entries(o ?? {})`: the object and its keys in JavaScript order.
fn entry_keys(o: &Value) -> (Map<String, Value>, Vec<String>) {
    let eo = empty_obj();
    match obj(nn(o, &eo)) {
        Some(m) => (m.clone(), keys(m)),
        None => fail("Object.entries requires an object"),
    }
}

fn param_shapes(params: &Value) -> Map<String, Value> {
    let (m, ks) = entry_keys(params);
    let mut out = Map::new();
    for k in ks {
        out.insert(k.clone(), def_shape(&m[k.as_str()]));
    }
    out
}

pub(crate) fn verb_shapes_from_action_defs(defs: &Value) -> Value {
    Value::Array(req_list(defs).iter().map(|d| u(vec![("verb", get(d, "verb").clone()), ("params", Value::Object(param_shapes(get(d, "params"))))])).collect())
}

/// The verbs and parameters of a signed action schema (`{verbs: [...]}`), a list of shapes, or a list of action definitions.
pub(crate) fn verb_shapes(src: &Value) -> Value {
    if let Some(sm) = obj(src) {
        if sm.contains_key("verbs") {
            let mut out: Vec<Value> = vec![];
            for v in req_list(&sm["verbs"]) {
                let mut params = Map::new();
                let (pm, ks) = entry_keys(get(v, "params"));
                for k in ks {
                    let d = &pm[k.as_str()];
                    let mut sh: Vec<(&str, Value)> = vec![("type", get(d, "type").clone())];
                    let x = get(d, "values");
                    if truthy(x) {
                        sh.push(("values", x.clone()));
                    }
                    for f in ["min", "max"] {
                        let x = get(d, f);
                        if !is_undef(x) {
                            sh.push((f, x.clone()));
                        }
                    }
                    let x = get(d, "unit");
                    if truthy(x) {
                        sh.push(("unit", x.clone()));
                    }
                    sh.push(("semantic", get(d, "semantic").clone()));
                    sh.push(("sensitivity", get(d, "sensitivity").clone()));
                    let x = get(d, "required");
                    if !is_undef(x) {
                        sh.push(("required", x.clone()));
                    }
                    params.insert(k, u(sh));
                }
                out.push(u(vec![("verb", get(v, "verb").clone()), ("params", Value::Object(params))]));
            }
            return Value::Array(out);
        }
    }
    let lst = req_list(src);
    let mut shapes: Vec<(Value, Map<String, Value>)> = vec![];
    for d in lst {
        let mut v: Value = Value::Bool(false);
        if has(d, "verb") {
            v = own(d, "verb").clone();
        }
        if !truthy(&v) {
            v = Value::Bool(false);
            if has(d, "id") {
                v = own(d, "id").clone();
            }
        }
        if !truthy(&v) {
            v = s("");
        }
        shapes.push((v, param_shapes(get(d, "params"))));
    }
    let mut out: Vec<Value> = vec![];
    for (i, (v, mut params)) in shapes.into_iter().enumerate() {
        let orig = nn(get(&lst[i], "params"), &empty_obj()).clone();
        let names: Vec<String> = params.keys().cloned().collect();
        for k in names {
            if let Some(Value::Object(pm)) = params.get_mut(&k) {
                for f in ["semantic", "unit"] {
                    if !is_undef(oget(own(&orig, &k), f)) {
                        pm.insert(f.into(), get(get(&orig, &k), f).clone());
                    }
                }
            }
        }
        let mut m = Map::new();
        m.insert("verb".into(), v);
        m.insert("params".into(), Value::Object(params));
        out.push(Value::Object(m));
    }
    Value::Array(out)
}

fn leaves(c: &Value, into: &mut Vec<Value>) {
    let m = match obj(c) {
        Some(m) => m,
        None => return,
    };
    if is_group_map(m) {
        if let Some(xs) = m.get("all_of").and_then(Value::as_array) {
            for x in xs {
                leaves(x, into);
            }
        } else if let Some(xs) = m.get("any_of").and_then(Value::as_array) {
            for x in xs {
                leaves(x, into);
            }
        } else if let Some(n) = m.get("not") {
            leaves(n, into);
        }
        return;
    }
    into.push(c.clone());
}

fn type_ok(t: &Value, v: &Value) -> bool {
    if is_undef(t) {
        return true;
    }
    match t.as_str().unwrap_or("") {
        "integer" => is_fin(v),
        "boolean" => v.is_boolean(),
        "string" | "date" => v.is_string(),
        _ => true,
    }
}

fn semantic_money(d: &Value) -> bool {
    let e = s("");
    match nn(get(d, "semantic"), &e).as_str() {
        Some(t) => t.starts_with("money."),
        None => fail("startsWith is not a function"),
    }
}

fn grants(p: &Value, verb: &Value) -> bool {
    let pv = get(p, "verb");
    if strict_eq(pv, &s("*")) || strict_eq(pv, verb) {
        return true;
    }
    if let Some(l) = pv.as_array() {
        return l.iter().any(|e| strict_eq(e, &s("*")) || strict_eq(e, verb));
    }
    false
}

fn num_of(v: &Value) -> String {
    num_str(to_number(v))
}

fn is_numeric_op(op: &str) -> bool {
    matches!(op, "lt" | "lte" | "gt" | "gte")
}

struct Lint<'a> {
    shape_verbs: Vec<Value>,
    by_verb: HashMap<String, &'a Value>,
    units: &'a Value,
    schema_units: &'a Value,
    findings: Vec<Value>,
}

impl<'a> Lint<'a> {
    fn add(&mut self, code: &str, severity: &str, where_: &str, message: String) {
        self.findings.push(u(vec![("code", s(code)), ("severity", s(severity)), ("where", s(where_)), ("message", s(&message))]));
    }

    fn lookup(&self, v: &Value) -> Option<&'a Value> {
        v.as_str().and_then(|t| self.by_verb.get(t).copied())
    }

    fn check(&mut self, p: &Value, where_: &str, is_veto: bool) {
        let pv = get(p, "verb");
        let list = pv.as_array();
        let verbs: Vec<Value> = if strict_eq(pv, &s("*")) || list.is_some_and(|l| l.iter().any(|x| strict_eq(x, &s("*")))) {
            self.shape_verbs.clone()
        } else if let Some(l) = list {
            l.clone()
        } else {
            vec![pv.clone()]
        };
        for v in &verbs {
            if self.lookup(v).is_none() {
                let sev = if is_veto { "warn" } else { "error" };
                self.add("undeclared-verb", sev, where_, format!("verb '{}' is not declared by the schema", js(v)));
            }
        }
        let declared: Vec<&Value> = verbs.iter().filter_map(|v| self.lookup(v)).collect();
        if declared.is_empty() {
            return;
        }
        for (wi, w) in req_list(nn(get(p, "where"), &empty_arr())).iter().enumerate() {
            let mut ls: Vec<Value> = vec![];
            leaves(w, &mut ls);
            for cv in &ls {
                let c = match leaf(cv) {
                    Some(c) => c,
                    None => continue,
                };
                let field = mg(c, "field").as_str().unwrap_or("");
                if !field.starts_with("action.params.") {
                    continue;
                }
                let name = field["action.params.".len()..].split('.').next().unwrap_or("").to_string();
                let at = format!("{where_}.where[{wi}]");
                let mut having: Vec<&Value> = vec![];
                let mut lacking: Vec<&Value> = vec![];
                for sh in &declared {
                    if has(get(sh, "params"), &name) {
                        having.push(sh);
                    } else {
                        lacking.push(sh);
                    }
                }
                let verb_names = |xs: &[&Value]| -> String { xs.iter().map(|x| js(own(x, "verb"))).collect::<Vec<_>>().join(", ") };
                if having.is_empty() {
                    self.add("undeclared-param", "error", &at, format!("parameter '{name}' is declared by none of {}", verb_names(&declared)));
                    continue;
                }
                if having.len() < declared.len() {
                    self.add("undeclared-param", "warn", &at, format!("parameter '{name}' is not declared by {}", verb_names(&lacking)));
                }
                let d = get(get(having[0], "params"), &name);
                let (op, val) = (mg(c, "op"), mg(c, "value"));
                let ops = op.as_str().unwrap_or("\u{0}");
                let vals: Vec<Value> = match val.as_array() {
                    Some(l) if ops == "in" || ops == "nin" => l.clone(),
                    _ => vec![val.clone()],
                };
                let dtype = own(d, "type");
                let has_ref = c.contains_key("ref");
                if !has_ref && (matches!(ops, "eq" | "ne" | "in" | "nin") || is_numeric_op(ops)) {
                    for x in &vals {
                        if !type_ok(dtype, x) {
                            self.add("type-mismatch", "error", &at, format!("'{name}' is {} but is compared ({}) with {}", js(dtype), js(op), typeof_v(x)));
                        }
                    }
                }
                if is_numeric_op(ops) && !is_undef(dtype) && dtype.as_str() != Some("integer") {
                    if matches!(dtype.as_str(), Some("string") | Some("date")) {
                        self.add("ordering-on-string", "warn", &at, format!("'{name}' is {}: ordering follows UTF-8 byte order", js(dtype)));
                    } else {
                        self.add("type-mismatch", "error", &at, format!("ordering operator {} on {} parameter '{name}'", js(op), js(dtype)));
                    }
                }
                let dvals = own(d, "values");
                let first: Value = vals.first().cloned().unwrap_or_else(undef_v);
                if truthy(dvals) && (ops == "eq" || ops == "in") && first.is_string() {
                    let missing: Vec<Value> = vals.iter().filter(|x| x.is_string() && !includes(dvals, x)).cloned().collect();
                    if missing.len() == vals.len() {
                        self.add(
                            "value-not-in-enum",
                            "error",
                            &at,
                            format!("no value of {} {} is in the schema's set for '{name}'", js(op), json_str(&Value::Array(vals.clone()))),
                        );
                    } else if !missing.is_empty() {
                        self.add("value-not-in-enum", "warn", &at, format!("{} are not in the schema's set for '{name}'", json_str(&Value::Array(missing))));
                    }
                }
                let (dmin, dmax) = (own(d, "min"), own(d, "max"));
                if dtype.as_str() == Some("integer") && is_num(val) && !has_ref {
                    let v = to_number(val);
                    let (has_min, has_max) = (!is_undef(dmin), !is_undef(dmax));
                    let (mn, mx) = (to_number(dmin), to_number(dmax));
                    let dead = (ops == "eq" && ((has_max && v > mx) || (has_min && v < mn)))
                        || (ops == "gt" && has_max && v >= mx)
                        || (ops == "gte" && has_max && v > mx)
                        || (ops == "lt" && has_min && v <= mn)
                        || (ops == "lte" && has_min && v < mn);
                    let mut lo = "-inf".to_string();
                    let mut hi = "inf".to_string();
                    if has_min && !dmin.is_null() {
                        lo = num_of(dmin);
                    }
                    if has_max && !dmax.is_null() {
                        hi = num_of(dmax);
                    }
                    if dead {
                        self.add(
                            "out-of-range",
                            "error",
                            &at,
                            format!("'{name}' {} {} can never hold: the schema bounds it to [{lo}, {hi}]", js(op), num_of(val)),
                        );
                    } else if (ops == "lte" && has_max && v >= mx) || (ops == "gte" && has_min && v <= mn) {
                        self.add(
                            "redundant-bound",
                            "info",
                            &at,
                            format!("'{name}' {} {} never binds: the schema already bounds it to [{lo}, {hi}]", js(op), num_of(val)),
                        );
                    }
                }
                let dunit = own(d, "unit");
                if truthy(dunit) && !is_undef(self.units) && (is_numeric_op(ops) || ops == "eq") && !is_veto {
                    let mut tag = own(self.units, field).clone();
                    if is_undef(&tag) || tag.is_null() {
                        tag = own(self.units, &format!("action.params.{name}")).clone();
                    }
                    let mut sch = undef_v();
                    if let (Some(sm), Some(us)) = (obj(self.schema_units), dunit.as_str()) {
                        if let Some(x) = sm.get(us) {
                            sch = x.clone();
                        }
                    }
                    if is_undef(&tag) || tag.is_null() {
                        self.add(
                            "unit-missing",
                            "error",
                            &at,
                            format!("'{name}' carries unit '{}' but the policy has no unit tag for it (rule 20)", js(dunit)),
                        );
                    } else if truthy(&sch)
                        && (!strict_eq(get(&tag, "kind"), get(&sch, "kind"))
                            || !strict_eq(get(&tag, "currency"), get(&sch, "currency"))
                            || !strict_eq(get(&tag, "exponent"), get(&sch, "exponent")))
                    {
                        self.add(
                            "unit-mismatch",
                            "error",
                            &at,
                            format!("'{name}': policy unit {} differs from the schema's {} (rule 20)", json_str(&tag), json_str(&sch)),
                        );
                    }
                }
            }
        }
    }
}

/// Lints a policy against the schema it is written for: `{ok, findings}`; `ok` is false when a finding is an error.
pub(crate) fn validate_policy_against_schema(policy: &Value, src: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let o = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let shapes_v = verb_shapes(src);
    let shapes = req_list(&shapes_v);
    let mut by_verb: HashMap<String, &Value> = HashMap::new();
    let mut shape_verbs: Vec<Value> = vec![];
    for sh in shapes {
        shape_verbs.push(own(sh, "verb").clone());
        if let Some(vs) = own(sh, "verb").as_str() {
            by_verb.insert(vs.to_string(), sh);
        }
    }
    let mut schema_units = get(o, "schemaUnits");
    if is_undef(schema_units) || schema_units.is_null() {
        schema_units = own(src, "units");
    }
    let model = to_model(policy);
    let units = get(o, "units");
    let list_ungranted = truthy(get(o, "listUngranted"));
    let mut cx = Lint { shape_verbs, by_verb, units, schema_units, findings: vec![] };

    for (i, p) in req_list(get(&model, "predicates")).iter().enumerate() {
        if !is_obj(p) && !p.is_array() {
            continue;
        }
        cx.check(p, &format!("predicates[{i}]"), false);
        let r = always_denies(&u(vec![("predicates", Value::Array(vec![p.clone()]))]), &Value::Null, &Value::Null);
        if get(&r, "alwaysDenies").as_bool() == Some(true) && !truthy(own(&r, "approximate")) {
            cx.add("unreachable-predicate", "warn", &format!("predicates[{i}]"), "no action can ever match this predicate".to_string());
        }
    }
    for (i, v) in req_list(get(&model, "vetoes")).iter().enumerate() {
        cx.check(get(v, "when"), &format!("vetoes[{i}]"), true);
    }

    // a money verb with no ceiling in any predicate that grants it
    let preds = req_list(get(&model, "predicates"));
    for sh in shapes {
        let sverb = own(sh, "verb");
        let params = match obj(get(sh, "params")) {
            Some(m) => m,
            None => fail("params is not an object"),
        };
        let mut money: Vec<String> = vec![];
        for name in keys(params) {
            if semantic_money(&params[name.as_str()]) {
                money.push(name);
            }
        }
        if money.is_empty() {
            continue;
        }
        let granting: Vec<&Value> = preds.iter().filter(|p| grants(p, sverb)).collect();
        if granting.is_empty() {
            if list_ungranted {
                cx.add("verb-not-granted", "info", &js(sverb), format!("the schema declares '{}' but no predicate grants it", js(sverb)));
            }
            continue;
        }
        for name in &money {
            let path = format!("action.params.{name}");
            let bounded = |p: &Value| -> bool {
                for w in req_list(nn(get(p, "where"), &empty_arr())) {
                    let src_w: Value = if is_group(w) {
                        let all = own(w, "all_of");
                        let all = if is_undef(all) { empty_arr() } else { all.clone() };
                        u(vec![("all_of", all)])
                    } else {
                        w.clone()
                    };
                    let mut ls: Vec<Value> = vec![];
                    leaves(&src_w, &mut ls);
                    for cv in &ls {
                        if let Some(c) = leaf(cv) {
                            if mg(c, "field").as_str() == Some(path.as_str())
                                && matches!(mg(c, "op").as_str(), Some("lt") | Some("lte") | Some("eq") | Some("in"))
                            {
                                return true;
                            }
                        }
                    }
                }
                false
            };
            let all = granting.iter().all(|p| bounded(*p));
            if !all {
                cx.add(
                    "unbounded-money",
                    "warn",
                    &js(sverb),
                    format!("'{}' can move '{name}' with no per-action ceiling in at least one granting predicate", js(sverb)),
                );
            }
        }
    }
    if list_ungranted {
        for sh in shapes {
            let params = match obj(get(sh, "params")) {
                Some(m) => m,
                None => fail("params is not an object"),
            };
            let mut is_money = false;
            for d in params.values() {
                if semantic_money(d) {
                    is_money = true;
                    break;
                }
            }
            if is_money {
                continue;
            }
            let sverb = own(sh, "verb");
            let granted = preds.iter().any(|p| grants(p, sverb));
            if !granted {
                cx.add("verb-not-granted", "info", &js(sverb), format!("the schema declares '{}' but no predicate grants it", js(sverb)));
            }
        }
    }
    let ok = !cx.findings.iter().any(|f| get(f, "severity").as_str() == Some("error"));
    u(vec![("ok", Value::Bool(ok)), ("findings", Value::Array(cx.findings))])
}
