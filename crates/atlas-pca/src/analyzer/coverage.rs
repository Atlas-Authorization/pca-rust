//! Policy coverage: which clause decided an action, which clauses never matched, how close traffic came to each threshold, and which
//! single-edit mutants the traffic cannot tell from the policy.

use super::enumerate::*;
use super::exposure::thresholds_of;
use super::js::*;
use super::query::{always_denies, equivalent};
use super::residual::policy_digest_of;
use crate::predicates::{evaluate_condition_tri, predicate_matches, Ctx, Tri};
use serde_json::{Map, Value};
use std::collections::HashMap;

pub(crate) fn permit_id(i: usize) -> String {
    format!("permit[{i}]")
}

fn id_of(x: &Value) -> Value {
    if is_undef(x) {
        Value::Null
    } else {
        x.clone()
    }
}

/// The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit.
pub(crate) fn witness_of(model: &Value, action: &Value) -> Value {
    let decision = decide_action(model, action);
    let ctx = context_of_action(action);
    let mut permits: Vec<Value> = vec![];
    for (i, p) in req_list(get(model, "predicates")).iter().enumerate() {
        if predicate_matches(p, &Ctx::new(&ctx)) {
            permits.push(s(&permit_id(i)));
        }
    }
    let mut vetoes: Vec<&Value> = vec![];
    let mut tighten: Vec<&Value> = vec![];
    for v in req_list(get(model, "vetoes")) {
        if veto_applies(v, &ctx) {
            vetoes.push(v);
        }
    }
    for t in req_list(get(model, "tighten")) {
        let w = nil_if_undef(get(t, "when"));
        if evaluate_condition_tri(&w, &Ctx::new(&ctx)) != Tri::False {
            tighten.push(t);
        }
    }
    let others = |win: &Value| -> Vec<Value> {
        let mut all: Vec<Value> = permits.clone();
        for v in &vetoes {
            all.push(id_of(get(v, "id")));
        }
        for t in &tighten {
            all.push(id_of(get(t, "id")));
        }
        all.into_iter().filter(|i| !strict_eq(i, win)).collect()
    };
    let done = |kind: &str, id: &Value| -> Value {
        let id = id_of(id);
        u(vec![("decision", s(decision)), ("winner", u(vec![("kind", s(kind)), ("id", id.clone())])), ("also", Value::Array(others(&id)))])
    };
    let first = |xs: &[&Value], key: &str, want: &str| -> Option<Value> { xs.iter().find(|x| get(x, key).as_str() == Some(want)).map(|x| (*x).clone()) };
    if !caveat_sat(model) || decision == "deny" {
        if !caveat_sat(model) {
            return done("caveat", &s("caveats"));
        }
        if permits.is_empty() {
            return u(vec![
                ("decision", s(decision)),
                ("winner", u(vec![("kind", s("none")), ("id", Value::Null)])),
                ("also", Value::Array(others(&Value::Null))),
            ]);
        }
        if let Some(v) = first(&vetoes[..], "kind", "deny") {
            return done("veto", get(&v, "id"));
        }
        if let Some(t) = first(&tighten[..], "signal", "deny") {
            return done("tighten", get(&t, "id"));
        }
        return done("caveat", &s("caveats")); // reversibility cap or an ancestor of the chain
    }
    if decision == "escalate" {
        if let Some(v) = first(&vetoes[..], "kind", "approval") {
            return done("veto", get(&v, "id"));
        }
        if !tighten.is_empty() {
            return done("tighten", get(tighten[0], "id"));
        }
        return done("tighten", &Value::Null);
    }
    if !permits.is_empty() {
        return done("permit", &permits[0]);
    }
    done("permit", &Value::Null)
}

// ---- mutants ----------------------------------------------------------------------------------------------------------------

fn flip_op(op: &str) -> Option<&'static str> {
    Some(match op {
        "lt" => "lte",
        "lte" => "lt",
        "gt" => "gte",
        "gte" => "gt",
        "eq" => "ne",
        "ne" => "eq",
        "in" => "nin",
        "nin" => "in",
        _ => return None,
    })
}

fn variants_of_cond(c: &Value, eps: f64) -> Vec<(Value, String)> {
    let m = match obj(c) {
        Some(m) => m,
        None => return vec![],
    };
    let mut out: Vec<(Value, String)> = vec![];
    if is_group_map(m) {
        if let Some(n) = m.get("not") {
            for (cond, what) in variants_of_cond(n, eps) {
                out.push((u(vec![("not", cond)]), format!("not({what})")));
            }
            return out;
        }
        let (key, kids_v) = if m.contains_key("all_of") { ("all_of", &m["all_of"]) } else { ("any_of", mg(m, "any_of")) };
        let kids = req_list(kids_v);
        for (i, k) in kids.iter().enumerate() {
            for (cond, what) in variants_of_cond(k, eps) {
                let mut nxt = kids.clone();
                nxt[i] = cond;
                out.push((u(vec![(key, Value::Array(nxt))]), format!("{key}[{i}] {what}")));
            }
        }
        return out;
    }
    let lf = match leaf(c) {
        Some(l) if !l.contains_key("ref") => l,
        _ => return vec![],
    };
    let field = mg(lf, "field").as_str().unwrap_or("");
    let name = field.strip_prefix("action.params.").unwrap_or(field);
    let (val, op) = (mg(lf, "value"), mg(lf, "op"));
    let ops = op.as_str().unwrap_or("");
    if is_fin(val) && matches!(ops, "lt" | "lte" | "gt" | "gte" | "eq") {
        let vf = to_number(val);
        for nv in [vf + eps, vf - eps] {
            let mut c2 = lf.clone();
            c2.insert("value".into(), num(nv));
            out.push((Value::Object(c2), format!("{name} {ops} {} -> {}", num_str(vf), num_str(nv))));
        }
    }
    if let Some(f) = flip_op(ops) {
        let mut c2 = lf.clone();
        c2.insert("op".into(), s(f));
        out.push((Value::Object(c2), format!("{name} {ops} -> {f}")));
    }
    out
}

struct Mutant {
    id: String,
    description: String,
    policy: Value,
}

fn without(xs: &[Value], i: usize) -> Vec<Value> {
    xs.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, x)| x.clone()).collect()
}

fn replace(xs: &[Value], i: usize, v: Value) -> Vec<Value> {
    let mut r = xs.to_vec();
    r[i] = v;
    r
}

fn mutants_of(policy: &Value, eps: f64) -> Vec<Mutant> {
    let mut out: Vec<Mutant> = vec![];
    let mk = |over: Vec<(&str, Value)>| -> Value {
        let mut p = Map::new();
        for k in ["predicates", "caveats", "vetoes", "tighten"] {
            p.insert(k.to_string(), own(policy, k).clone());
        }
        for (k, v) in over {
            p.insert(k.to_string(), v);
        }
        Value::Object(p)
    };
    let preds = req_list(get(policy, "predicates")).clone();
    let empty = empty_arr();
    for (i, p) in preds.iter().enumerate() {
        let pid = permit_id(i);
        out.push(Mutant { id: format!("drop-{pid}"), description: format!("drop {pid}"), policy: mk(vec![("predicates", Value::Array(without(&preds, i)))]) });
        let where_ = req_list(nn(get(p, "where"), &empty)).clone();
        for (j, c) in where_.iter().enumerate() {
            for (cond, what) in variants_of_cond(c, eps) {
                let mut np = spread(p);
                np.insert("where".into(), Value::Array(replace(&where_, j, cond)));
                out.push(Mutant {
                    id: format!("{pid}.where[{j}]:{what}"),
                    description: format!("{pid}: {what}"),
                    policy: mk(vec![("predicates", Value::Array(replace(&preds, i, Value::Object(np))))]),
                });
            }
            let mut np = spread(p);
            np.insert("where".into(), Value::Array(without(&where_, j)));
            out.push(Mutant {
                id: format!("{pid}.where[{j}]:drop"),
                description: format!("{pid}: drop condition {j}"),
                policy: mk(vec![("predicates", Value::Array(replace(&preds, i, Value::Object(np))))]),
            });
        }
    }
    let vetoes = req_list(get(policy, "vetoes")).clone();
    for (i, v) in vetoes.iter().enumerate() {
        let vid = js(get(v, "id"));
        out.push(Mutant {
            id: format!("drop-veto:{vid}"),
            description: format!("drop prohibition {vid}"),
            policy: mk(vec![("vetoes", Value::Array(without(&vetoes, i)))]),
        });
        let over = get(v, "over");
        if truthy(over) {
            let mut no = spread(over);
            no.insert("threshold".into(), num(to_number(get(over, "threshold")) + eps));
            let mut nv = spread(v);
            nv.insert("over".into(), Value::Object(no));
            out.push(Mutant {
                id: format!("veto:{vid}:threshold+"),
                description: format!("raise the {vid} threshold by {}", num_str(eps)),
                policy: mk(vec![("vetoes", Value::Array(replace(&vetoes, i, Value::Object(nv))))]),
            });
        }
    }
    let tighten = req_list(get(policy, "tighten")).clone();
    for (i, t) in tighten.iter().enumerate() {
        let tid = js(get(t, "id"));
        out.push(Mutant {
            id: format!("drop-tighten:{tid}"),
            description: format!("drop tighten rule {tid}"),
            policy: mk(vec![("tighten", Value::Array(without(&tighten, i)))]),
        });
    }
    out
}

/// `true` / `false` / `"unknown"`: can any action reach the clause?
fn reach(model: &Value, kind: &str, idx: usize) -> Value {
    let r = match kind {
        "permit" => always_denies(
            &u(vec![("predicates", Value::Array(vec![req_list(get(model, "predicates"))[idx].clone()])), ("caveats", get(model, "caveats").clone())]),
            &Value::Null,
            &Value::Null,
        ),
        "veto" => {
            always_denies(&u(vec![("predicates", Value::Array(vec![get(&req_list(get(model, "vetoes"))[idx], "when").clone()]))]), &Value::Null, &Value::Null)
        }
        _ => return s("unknown"),
    };
    if truthy(get(&r, "approximate")) {
        return s("unknown");
    }
    Value::Bool(get(&r, "alwaysDenies").as_bool() != Some(true))
}

struct Clause {
    id: Value,
    matched: usize,
    decisive: usize,
    reachable: Value,
}

fn is_false(v: &Value) -> bool {
    v.as_bool() == Some(false)
}

/// The coverage of `policy` by `traffic` (actions): clauses, boundaries, mutants and the 0..1 scores.
pub(crate) fn coverage(policy: &Value, traffic_in: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let o = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let traffic = req_list(traffic_in);
    let model = to_model(policy);
    let one = num(1.0);
    let eps = to_number(nn(get(o, "epsilon"), &one));
    let mut ids: Vec<(Value, &'static str)> = vec![];
    let preds = req_list(get(&model, "predicates"));
    let vetoes = req_list(get(&model, "vetoes"));
    let tighten = req_list(get(&model, "tighten"));
    for i in 0..preds.len() {
        ids.push((s(&permit_id(i)), "permit"));
    }
    for v in vetoes {
        ids.push((id_of(get(v, "id")), "veto"));
    }
    for t in tighten {
        ids.push((id_of(get(t, "id")), "tighten"));
    }
    let mut matched: HashMap<String, usize> = HashMap::new();
    let mut decisive: HashMap<String, usize> = HashMap::new();
    fn bump(m: &mut HashMap<String, usize>, k: &Value) {
        if !k.is_null() {
            *m.entry(json_str(k)).or_insert(0) += 1;
        }
    }
    for a in traffic {
        let w = witness_of(&model, a);
        let win = get(get(&w, "winner"), "id");
        bump(&mut decisive, win);
        bump(&mut matched, win);
        for i in req_list(get(&w, "also")) {
            bump(&mut matched, i);
        }
    }
    let (np, nv) = (preds.len(), vetoes.len());
    let mut clauses: Vec<Value> = vec![];
    let mut cls: Vec<Clause> = vec![];
    for (n, (cid, kind)) in ids.iter().enumerate() {
        let idx = if *kind == "veto" {
            n - np
        } else if *kind == "tighten" {
            n - np - nv
        } else {
            n
        };
        let mut x = Clause { id: cid.clone(), matched: 0, decisive: 0, reachable: reach(&model, kind, idx) };
        if !cid.is_null() {
            x.matched = matched.get(&json_str(cid)).copied().unwrap_or(0);
            x.decisive = decisive.get(&json_str(cid)).copied().unwrap_or(0);
        }
        clauses.push(u(vec![
            ("id", cid.clone()),
            ("kind", s(kind)),
            ("matched", num(x.matched as f64)),
            ("decisive", num(x.decisive as f64)),
            ("reachable", x.reachable.clone()),
        ]));
        cls.push(x);
    }
    let mut path_set = OrdSet::default();
    fn walk(c: &Value, path_set: &mut OrdSet) {
        let m = match obj(c) {
            Some(m) => m,
            None => return,
        };
        if is_group_map(m) {
            if m.contains_key("all_of") {
                for x in req_list(&m["all_of"]) {
                    walk(x, path_set);
                }
            } else if m.contains_key("any_of") {
                for x in req_list(&m["any_of"]) {
                    walk(x, path_set);
                }
            } else {
                walk(&m["not"], path_set);
            }
            return;
        }
        if let Some(lf) = leaf(c) {
            let f = mg(lf, "field").as_str().unwrap_or("");
            if f.starts_with("action.params.") && matches!(mg(lf, "op").as_str().unwrap_or(""), "lt" | "lte" | "gt" | "gte" | "eq" | "in" | "nin") {
                path_set.add(f);
            }
        }
    }
    for p in probe_set(&model) {
        for c in req_list(nn(get(&p, "where"), &empty_arr())) {
            walk(c, &mut path_set);
        }
    }
    for v in vetoes {
        let over = get(v, "over");
        if truthy(over) {
            path_set.add(req_str(get(over, "path"), "path"));
        }
    }
    let mut paths: Vec<String> = path_set.keys.clone();
    stable_sort_by_less(&mut paths, &|a, b| unit_less(a, b));
    let mut boundaries: Vec<Value> = vec![];
    for path in &paths {
        let r: Vec<char> = path.chars().collect();
        let name: String = if r.len() > 14 { r[14..].iter().collect() } else { String::new() };
        let mut vals: Vec<f64> = vec![];
        for a in traffic {
            let x = own(nn(get(a, "params"), &empty_obj()), &name).clone();
            if is_num(&x) {
                vals.push(to_number(&x));
            }
        }
        for t in thresholds_of(&model, path) {
            let tf = to_number(&t);
            let (mut at, mut below, mut above) = (false, false, false);
            for v in &vals {
                at = at || *v == tf;
                below = below || (*v < tf && *v >= tf - eps);
                above = above || (*v > tf && *v <= tf + eps);
            }
            boundaries.push(u(vec![
                ("path", s(path)),
                ("threshold", t.clone()),
                ("at", Value::Bool(at)),
                ("below", Value::Bool(below)),
                ("above", Value::Bool(above)),
            ]));
        }
    }
    let mut survivors: Vec<Value> = vec![];
    let (mut killed, mut equiv) = (0usize, 0usize);
    let d200 = num(200.0);
    let mm = to_number(nn(get(o, "maxMutants"), &d200));
    let mut allm: Vec<Mutant> = vec![];
    if !mm.is_nan() {
        let mut all = mutants_of(&model, eps);
        let n = all.len() as i64;
        let mut end = jmax(jmin(mm, 1_073_741_824.0), -1_073_741_824.0).trunc() as i64;
        if end < 0 {
            end = (n + end).max(0);
        }
        if end > n {
            end = n;
        }
        all.truncate(end as usize);
        allm = all;
    }
    let base: Vec<&'static str> = traffic.iter().map(|a| decide_action(&model, a)).collect();
    for m in &allm {
        let mmod = to_model(&m.policy);
        let diff = traffic.iter().enumerate().any(|(i, a)| decide_action(&mmod, a) != base[i]);
        if diff {
            killed += 1;
            continue;
        }
        let eq = equivalent(policy, &m.policy, &Value::Null);
        if get(&eq, "equivalent").as_bool() == Some(true) {
            equiv += 1;
            continue;
        }
        let mut sv = u_map(vec![("id", s(&m.id)), ("description", s(&m.description))]);
        let ce = own(&eq, "counterexample");
        if has(&eq, "counterexample") && truthy(ce) {
            sv.insert("killer".into(), ce.clone());
        }
        survivors.push(Value::Object(sv));
    }
    let ratio = |n: usize, d: i64| -> f64 {
        if d == 0 {
            1.0
        } else {
            n as f64 / d as f64
        }
    };
    let (mut live, mut live_decisive) = (0usize, 0usize);
    let (mut never_matched, mut never_decisive, mut untested, mut unreachable): (Vec<Value>, Vec<Value>, Vec<Value>, Vec<Value>) =
        (vec![], vec![], vec![], vec![]);
    for c in &cls {
        if !is_false(&c.reachable) {
            live += 1;
            if c.decisive > 0 {
                live_decisive += 1;
            }
        }
        if c.matched == 0 {
            never_matched.push(c.id.clone());
            if !is_false(&c.reachable) {
                untested.push(c.id.clone());
            }
        }
        if c.decisive == 0 {
            never_decisive.push(c.id.clone());
        }
        if is_false(&c.reachable) {
            unreachable.push(c.id.clone());
        }
    }
    let full = boundaries
        .iter()
        .filter(|b| get(b, "at").as_bool() == Some(true) && get(b, "below").as_bool() == Some(true) && get(b, "above").as_bool() == Some(true))
        .count();
    u(vec![
        ("traffic", num(traffic.len() as f64)),
        ("policyDigest", s(&policy_digest_of(&model))),
        ("clauses", Value::Array(clauses)),
        ("neverMatched", Value::Array(never_matched)),
        ("neverDecisive", Value::Array(never_decisive)),
        ("untested", Value::Array(untested)),
        ("unreachable", Value::Array(unreachable)),
        ("boundaries", Value::Array(boundaries.clone())),
        (
            "mutants",
            u(vec![
                ("total", num(allm.len() as f64)),
                ("killed", num(killed as f64)),
                ("equivalent", num(equiv as f64)),
                ("survivors", Value::Array(survivors)),
            ]),
        ),
        (
            "score",
            u(vec![
                ("clauses", num(ratio(live_decisive, live as i64))),
                ("boundaries", num(ratio(full, boundaries.len() as i64))),
                ("mutation", num(ratio(killed, allm.len() as i64 - equiv as i64))),
            ]),
        ),
    ])
}

/// A CI gate over a coverage report: `{ok, reasons}`.
pub(crate) fn coverage_gate(r: &Value, minimum: &Value) -> Value {
    let empty = empty_obj();
    let mn = if minimum.is_null() || is_undef(minimum) { &empty } else { minimum };
    let mut reasons: Vec<Value> = vec![];
    let score = get(r, "score");
    for (k, label) in [("clauses", "clause coverage"), ("boundaries", "boundary coverage"), ("mutation", "mutation score")] {
        let lim = get(mn, k);
        let sc = to_number(get(score, k));
        let zero = num(0.0);
        if sc < to_number(nn(lim, &zero)) {
            reasons.push(s(&format!("{label} {} < {}", to_fixed(sc, 2), js(lim))));
        }
    }
    let surv = req_list(get(get(r, "mutants"), "survivors"));
    let ms = get(mn, "maxSurvivors");
    if !is_undef(ms) && surv.len() as f64 > to_number(ms) {
        reasons.push(s(&format!("{} surviving mutants > {}", surv.len(), js(ms))));
    }
    let un = req_list(get(r, "unreachable"));
    if !un.is_empty() {
        let parts: Vec<String> = un.iter().map(js).collect();
        reasons.push(s(&format!("unreachable clauses: {}", parts.join(", "))));
    }
    u(vec![("ok", Value::Bool(reasons.is_empty())), ("reasons", Value::Array(reasons))])
}
