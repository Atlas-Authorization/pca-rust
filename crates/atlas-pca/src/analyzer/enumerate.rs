//! The analyzable model of a policy, the finite probe grid, representative actions and the ternary decision at a concrete context.

use super::caveats::analyze_caveats;
use super::field::field_probes;
use super::js::*;
use crate::predicates::{evaluate_condition_tri, evaluate_predicates, Ctx, Tri};
use serde_json::{Map, Value};
use std::collections::HashMap;

pub(crate) const FRESH_VERB: &str = "\u{0}atlas-analyzer::fresh-verb\u{0}";
pub(crate) const FRESH_RESOURCE: &str = "\u{0}atlas-analyzer::fresh-resource\u{0}";
pub(crate) const DEFAULT_MAX_COMBINATIONS: f64 = 200000.0;

// ---- model ------------------------------------------------------------------------------------------------------------------

/// A value that is not a policy is an empty policy (the verifier admits nothing under it).
fn normalize_policy(p: &Value) -> Value {
    let arr = |k: &str| -> Value {
        match obj(p).and_then(|m| m.get(k)) {
            Some(l) if l.is_array() => l.clone(),
            _ => empty_arr(),
        }
    };
    u(vec![("predicates", arr("predicates")), ("caveats", arr("caveats")), ("vetoes", arr("vetoes")), ("tighten", arr("tighten"))])
}

/// The predicates whose literals shape the grid: the permits plus every veto and tighten trigger.
pub(crate) fn probe_set(m: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = req_list(get(m, "predicates")).clone();
    for v in req_list(get(m, "vetoes")) {
        out.push(get(v, "when").clone());
        if let Some(un) = get(v, "unless").as_array() {
            if !un.is_empty() {
                out.push(lit(vec![("verb", s("*")), ("where", Value::Array(un.clone()))]));
            }
        }
        let over = get(v, "over");
        if truthy(over) {
            let cond = lit(vec![("field", get(over, "path").clone()), ("op", s("gt")), ("value", get(over, "threshold").clone())]);
            out.push(lit(vec![("verb", s("*")), ("where", Value::Array(vec![cond]))]));
        }
    }
    for t in req_list(get(m, "tighten")) {
        out.push(lit(vec![("verb", s("*")), ("where", Value::Array(vec![get(t, "when").clone()]))]));
    }
    for x in req_list(get(m, "meets")) {
        out.extend(probe_set(x));
    }
    out
}

/// An object literal that keeps undefined members as the marker (they are inert in every reader).
fn lit(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

fn condition_undecidable(cc: &Value, reasons: &mut OrdSet) {
    let c = match obj(cc) {
        Some(c) => c,
        None => return,
    };
    if is_group_map(c) {
        if let Some(xs) = c.get("all_of").and_then(Value::as_array) {
            for x in xs {
                condition_undecidable(x, reasons);
            }
        } else if let Some(xs) = c.get("any_of").and_then(Value::as_array) {
            for x in xs {
                condition_undecidable(x, reasons);
            }
        } else if let Some(n) = c.get("not") {
            condition_undecidable(n, reasons);
        }
        return;
    }
    if leaf(cc).is_none() {
        return;
    }
    if c.contains_key("ref") {
        reasons.add("cross-field `ref` condition \u{2014} the relation between two fields is not resolved");
    }
    if c.get("field").and_then(Value::as_str) == Some("action.params") {
        reasons.add("condition on the whole `action.params` object is not enumerated precisely");
    }
    let op = mg(c, "op").as_str().unwrap_or("");
    match op {
        "lt" | "lte" | "gt" | "gte" => {
            if !is_fin(mg(c, "value")) {
                reasons.add(&format!("`{op}` against a non-numeric operand \u{2014} string ordering is not enumerated exactly"));
            }
        }
        "like" | "matches" | "is_a" | "member_of" => {
            reasons.add(&format!("`{op}` condition \u{2014} matched by over-approximation, not enumerated exactly"));
        }
        _ => {}
    }
}

fn detect_undecidable(predicates: &[Value]) -> Vec<Value> {
    let mut reasons = OrdSet::default();
    for p in predicates {
        let pm = match obj(p) {
            Some(m) => m,
            None => continue,
        };
        if let Some(r) = pm.get("resource").and_then(Value::as_str) {
            if r.starts_with("re:") {
                reasons.add("re: regex resource matcher \u{2014} resource dimension cannot be soundly enumerated");
            }
        }
        if let Some(w) = pm.get("where").and_then(Value::as_array) {
            for c in w {
                condition_undecidable(c, &mut reasons);
            }
        }
    }
    reasons.list()
}

/// The analyzable model of a policy: `{predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?, undecidable}`.
pub(crate) fn to_model(p: &Value) -> Value {
    let n = normalize_policy(p);
    let ca = analyze_caveats(get(&n, "caveats"));
    let mut meets: Vec<Value> = vec![];
    if let Some(ms) = obj(p).and_then(|m| m.get("meet")).and_then(Value::as_array) {
        for x in ms {
            meets.push(to_model(x));
        }
    }
    let all_sat = meets.iter().all(|x| get(x, "caveatSat").as_bool() == Some(true));
    let ca_sat = get(&ca, "sat").as_bool() == Some(true);
    let reason: Value = if ca_sat {
        meets.iter().find(|x| get(x, "caveatSat").as_bool() != Some(true)).map_or(undef_v(), |x| get(x, "caveatReason").clone())
    } else {
        get(&ca, "reason").clone()
    };
    let mut m = Map::new();
    for k in ["predicates", "caveats", "vetoes", "tighten"] {
        m.insert(k.to_string(), get(&n, k).clone());
    }
    m.insert("meets".into(), Value::Array(meets.clone()));
    m.insert("caveatSat".into(), Value::Bool(ca_sat && all_sat));
    if !is_undef(&reason) && !reason.is_null() {
        m.insert("caveatReason".into(), reason);
    }
    let mut capv: i64 = get(&ca, "revCap").as_i64().unwrap_or(-1);
    for x in &meets {
        if let Some(c) = get(x, "revCap").as_i64() {
            if capv < 0 || c < capv {
                capv = c;
            }
        }
    }
    if capv >= 0 {
        m.insert("revCap".into(), num(capv as f64));
    }
    let mv = Value::Object(m);
    let mut seen = OrdSet::default();
    for r in detect_undecidable(&probe_set(&mv)) {
        seen.add(r.as_str().unwrap_or(""));
    }
    for x in &meets {
        for r in req_list(get(x, "undecidable")) {
            seen.add(r.as_str().unwrap_or(""));
        }
    }
    let mut mm = match mv {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    mm.insert("undecidable".into(), Value::Array(seen.list()));
    Value::Object(mm)
}

/// `model.revCap` as an index, if the model has one.
pub(crate) fn rev_cap(model: &Value) -> Option<i64> {
    obj(model).and_then(|m| m.get("revCap")).and_then(Value::as_i64)
}

pub(crate) fn caveat_sat(model: &Value) -> bool {
    get(model, "caveatSat").as_bool() == Some(true)
}

// ---- probe collection --------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ProbeField {
    pub path: String,
    pub values: Vec<Value>,
}

/// The grid dimensions of a set of predicate sets.
#[derive(Clone, Debug, Default)]
pub struct Probes {
    pub verbs: Vec<Value>,
    pub resources: Vec<Value>,
    pub rev_classes: Vec<Value>,
    pub fields: Vec<ProbeField>,
}

impl Probes {
    pub fn to_json(&self) -> Value {
        let fs: Vec<Value> = self
            .fields
            .iter()
            .map(|f| {
                let vs: Vec<Value> = f.values.iter().map(|v| if is_absent(v) { lit(vec![("$absent", Value::Bool(true))]) } else { v.clone() }).collect();
                u(vec![("path", s(&f.path)), ("values", Value::Array(vs))])
            })
            .collect();
        u(vec![
            ("verbs", Value::Array(self.verbs.clone())),
            ("resources", Value::Array(self.resources.clone())),
            ("revClasses", Value::Array(self.rev_classes.clone())),
            ("fields", Value::Array(fs)),
        ])
    }

    pub fn product_size(&self) -> f64 {
        let mut n = self.verbs.len() as f64 * self.resources.len() as f64 * self.rev_classes.len() as f64;
        for f in &self.fields {
            n *= f.values.len() as f64;
        }
        n
    }
}

fn add_verb_literals(c: &Map<String, Value>, into: &mut OrdVals) {
    let v = mg(c, "value");
    match mg(c, "op").as_str().unwrap_or("") {
        "eq" | "ne" | "prefix" | "like" | "is_a" => {
            if v.is_string() {
                into.add(v);
            }
        }
        "in" | "nin" => {
            if let Some(xs) = v.as_array() {
                for x in xs {
                    if x.is_string() {
                        into.add(x);
                    }
                }
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct Collector {
    verbs: OrdVals,
    resources: OrdSet,
    field_order: Vec<String>,
    field_conds: HashMap<String, Vec<Value>>,
}

impl Collector {
    fn classify_resource(&mut self, r: &Value) {
        if is_undef(r) {
            return;
        }
        let t = match r.as_str() {
            Some(t) => t,
            None => fail("resource matcher is not a string"),
        };
        if t == "*" || t.starts_with("re:") {
            return;
        }
        if let Some(body) = t.strip_suffix('*') {
            self.resources.add(body);
            self.resources.add(&format!("{body}x"));
            return;
        }
        self.resources.add(t);
    }

    fn handle_cond(&mut self, cc: &Value) {
        let c = match obj(cc) {
            Some(c) => c,
            None => return,
        };
        if is_group_map(c) {
            if let Some(xs) = c.get("all_of").and_then(Value::as_array) {
                for x in xs {
                    self.handle_cond(x);
                }
            } else if let Some(xs) = c.get("any_of").and_then(Value::as_array) {
                for x in xs {
                    self.handle_cond(x);
                }
            } else if let Some(n) = c.get("not") {
                self.handle_cond(n);
            }
            return;
        }
        if leaf(cc).is_none() {
            return;
        }
        let field = mg(c, "field").as_str().unwrap_or("").to_string();
        match field.as_str() {
            "action.verb" => {
                add_verb_literals(c, &mut self.verbs);
                return;
            }
            "action.resource" => {
                let v = mg(c, "value");
                if let Some(t) = v.as_str() {
                    if mg(c, "op").as_str() == Some("prefix") {
                        self.classify_resource(&s(&format!("{t}*")));
                    } else {
                        self.classify_resource(v);
                    }
                } else if let Some(xs) = v.as_array() {
                    for x in xs {
                        if x.is_string() {
                            self.classify_resource(x);
                        }
                    }
                }
                return;
            }
            _ => {}
        }
        if !self.field_conds.contains_key(&field) {
            self.field_order.push(field.clone());
        }
        self.field_conds.entry(field).or_default().push(cc.clone());
    }
}

/// The grid dimensions of a set of predicate sets (`{predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility}`);
/// an absent value is the absent marker.
pub(crate) fn collect_probes(inputs: &Value) -> Probes {
    let mut col = Collector::default();
    let empty = Value::Array(vec![]);
    for v in req_list(nn(own(inputs, "extraVerbs"), &empty)) {
        col.verbs.add(v);
    }
    for lst in req_list(own(inputs, "predicateSets")) {
        for p in req_list(lst) {
            let pm = match obj(p) {
                Some(m) => m,
                None => continue,
            };
            match pm.get("verb") {
                Some(Value::String(verb)) => {
                    if verb != "*" {
                        col.verbs.add(&s(verb));
                    }
                }
                Some(Value::Array(vs)) => {
                    for v in vs {
                        if let Some(t) = v.as_str() {
                            if t != "*" {
                                col.verbs.add(v);
                            }
                        }
                    }
                }
                _ => {}
            }
            col.classify_resource(mg(pm, "resource"));
            if let Some(w) = pm.get("where").and_then(Value::as_array) {
                for c in w {
                    col.handle_cond(c);
                }
            }
        }
    }
    for r in req_list(nn(own(inputs, "extraResources"), &empty)) {
        col.classify_resource(r);
    }
    for ec in req_list(nn(own(inputs, "extraFieldConditions"), &empty)) {
        let mut cond = match obj(get(ec, "cond")) {
            Some(m) => m.clone(),
            None => fail("cond is not an object"),
        };
        cond.insert("field".into(), get(ec, "path").clone());
        col.handle_cond(&Value::Object(cond));
    }
    let mut pr = Probes::default();
    for path in &col.field_order {
        let mut values = field_probes(&Value::Array(col.field_conds[path].clone()));
        values.push(absent_v());
        pr.fields.push(ProbeField { path: path.clone(), values });
    }
    pr.verbs = col.verbs.vals.clone();
    pr.verbs.push(s(FRESH_VERB));
    pr.resources = col.resources.list();
    pr.resources.push(s(FRESH_RESOURCE));
    if truthy(own(inputs, "varyReversibility")) {
        pr.rev_classes = rev_list();
    } else {
        pr.rev_classes = vec![Value::Null];
    }
    pr
}

// ---- representatives --------------------------------------------------------------------------------------------------------

/// An insertion-ordered path -> value assignment.
#[derive(Clone, Debug, Default)]
pub struct Asg {
    pub items: Vec<(String, Value)>,
}

impl Asg {
    fn set(&mut self, k: &str, v: Value) {
        match self.items.iter_mut().find(|(x, _)| x == k) {
            Some(e) => e.1 = v,
            None => self.items.push((k.to_string(), v)),
        }
    }

    fn pop(&mut self, k: &str) {
        self.items.retain(|(x, _)| x != k);
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in &self.items {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    }
}

/// A grid point `{verb, resource, revClass (Null = no class), assignments}`.
#[derive(Clone, Debug)]
pub struct Rep {
    pub verb: Value,
    pub resource: Value,
    pub rev_class: Value,
    pub asg: Asg,
}

fn enum_fields(fields: &[ProbeField], i: usize, acc: &mut Asg, y: &mut dyn FnMut(&Asg) -> bool) -> bool {
    if i >= fields.len() {
        return y(acc);
    }
    let f = &fields[i];
    for v in &f.values {
        if is_absent(v) {
            acc.pop(&f.path);
        } else {
            acc.set(&f.path, v.clone());
        }
        if enum_fields(fields, i + 1, acc, y) {
            return true;
        }
    }
    false
}

/// Walks every grid point; `y` returns true to stop.
pub(crate) fn each_rep(pr: &Probes, y: &mut dyn FnMut(&Rep) -> bool) {
    for verb in &pr.verbs {
        for res in &pr.resources {
            for rev in &pr.rev_classes {
                let mut acc = Asg::default();
                let stop = enum_fields(&pr.fields, 0, &mut acc, &mut |a: &Asg| {
                    let rep = Rep { verb: verb.clone(), resource: res.clone(), rev_class: rev.clone(), asg: a.clone() };
                    y(&rep)
                });
                if stop {
                    return;
                }
            }
        }
    }
}

enum Node {
    Leaf(Value),
    Map(Vec<(String, Node)>),
}

fn insert(root: &mut Vec<(String, Node)>, segs: &[&str], value: Value) {
    let (last, init) = match segs.split_last() {
        Some(x) => x,
        None => return,
    };
    let mut node: &mut Vec<(String, Node)> = root;
    for key in init {
        let i = match node.iter().position(|(k, _)| k == *key) {
            Some(i) => {
                if !matches!(node[i].1, Node::Map(_)) {
                    node[i].1 = Node::Map(vec![]);
                }
                i
            }
            None => {
                node.push((key.to_string(), Node::Map(vec![])));
                node.len() - 1
            }
        };
        node = match &mut node[i].1 {
            Node::Map(m) => m,
            Node::Leaf(_) => return,
        };
    }
    match node.iter().position(|(k, _)| k == *last) {
        Some(i) => node[i].1 = Node::Leaf(value),
        None => node.push((last.to_string(), Node::Leaf(value))),
    }
}

fn materialize(n: &Node) -> Value {
    match n {
        Node::Leaf(v) => v.clone(),
        Node::Map(m) => materialize_map(m),
    }
}

fn materialize_map(m: &[(String, Node)]) -> Value {
    let mut out = Map::new();
    for (k, c) in m {
        out.insert(k.clone(), materialize(c));
    }
    Value::Object(out)
}

pub(crate) fn build_roots(rep: &Rep) -> Value {
    let mut roots: [(&str, Vec<(String, Node)>); 3] = [("action", vec![]), ("subject", vec![]), ("env", vec![])];
    for (path, value) in &rep.asg.items {
        let segs: Vec<&str> = path.split('.').collect();
        if segs.len() < 2 {
            continue;
        }
        if let Some(r) = roots.iter_mut().find(|(n, _)| *n == segs[0]) {
            insert(&mut r.1, &segs[1..], value.clone());
        }
    }
    let mut action = Map::new();
    action.insert("params".into(), empty_obj());
    if !is_undef(&rep.verb) {
        action.insert("verb".into(), rep.verb.clone());
    }
    if !is_undef(&rep.resource) {
        action.insert("resource".into(), rep.resource.clone());
    }
    for (key, child) in &roots[0].1 {
        match key.as_str() {
            "verb" | "resource" => {}
            "params" => {
                if !matches!(child, Node::Leaf(_)) {
                    action.insert("params".into(), materialize(child));
                }
            }
            _ => {
                action.insert(key.clone(), materialize(child));
            }
        }
    }
    if !rep.rev_class.is_null() && !is_undef(&rep.rev_class) {
        action.insert("reversibility_class".into(), rep.rev_class.clone());
    }
    let mut out = Map::new();
    out.insert("action".into(), Value::Object(action));
    out.insert("subject".into(), materialize_map(&roots[1].1));
    out.insert("env".into(), materialize_map(&roots[2].1));
    Value::Object(out)
}

pub(crate) fn reversibility_ok(model: &Value, rev: &Value) -> bool {
    let c = match rev_cap(model) {
        Some(c) => c,
        None => return true,
    };
    if rev.is_null() || is_undef(rev) {
        return false; // a reversibility_max caveat denies an action with no class
    }
    let i = rev_index(rev);
    i >= 0 && i <= c
}

/// Does a veto apply at this context? Veto polarity: whatever cannot be decided counts as applying.
pub(crate) fn veto_applies(v: &Value, ctx: &Value) -> bool {
    let w = nil_if_undef(get(v, "when"));
    if !crate::forbid::when_matches(&w, ctx) {
        return false;
    }
    let over = get(v, "over");
    if truthy(over) {
        let found = get(over, "path").as_str().and_then(|p| Ctx::new(ctx).resolve(p));
        let mut is_over = match found {
            None => true,
            Some(val) => !is_fin(val),
        };
        if !is_over {
            let val = found.unwrap_or(undef());
            let f = fin(val).unwrap_or(0.0);
            is_over = f < 0.0 || gt(val, get(over, "threshold"));
        }
        if !is_over {
            return false;
        }
    }
    let unless = get(v, "unless");
    if get(v, "kind").as_str() != Some("approval") && truthy(unless) {
        let ul = match unless.as_array() {
            Some(l) => l,
            None => fail("unless.every is not a function"),
        };
        let all = ul.iter().all(|c| evaluate_condition_tri(c, &Ctx::new(ctx)) == Tri::True);
        if all {
            return false;
        }
    }
    true
}

/// The ternary decision `allow` | `escalate` | `deny` of the permission layer at a concrete context.
pub(crate) fn decision_at_context(model: &Value, ctx: &Value) -> &'static str {
    if !evaluate_predicates(req_list(get(model, "predicates")), &Ctx::new(ctx)) {
        return "deny";
    }
    let mut escalate = false;
    for v in req_list(get(model, "vetoes")) {
        if !veto_applies(v, ctx) {
            continue;
        }
        if get(v, "kind").as_str() == Some("deny") {
            return "deny";
        }
        escalate = true;
    }
    for t in req_list(get(model, "tighten")) {
        let w = nil_if_undef(get(t, "when"));
        if evaluate_condition_tri(&w, &Ctx::new(ctx)) == Tri::False {
            continue;
        }
        if get(t, "signal").as_str() == Some("deny") {
            return "deny";
        }
        escalate = true;
    }
    let mut own_d = if escalate { "escalate" } else { "allow" };
    for x in req_list(get(model, "meets")) {
        let d = decision_at_context(x, ctx);
        if d == "deny" {
            return "deny";
        }
        if d == "escalate" {
            own_d = "escalate";
        }
    }
    own_d
}

/// The ternary decision of a representative (the static caveat gate first).
pub(crate) fn decide(model: &Value, rep: &Rep) -> &'static str {
    if !caveat_sat(model) || !reversibility_ok(model, &rep.rev_class) {
        return "deny";
    }
    decision_at_context(model, &build_roots(rep))
}

pub(crate) fn admits(model: &Value, rep: &Rep) -> bool {
    decide(model, rep) != "deny"
}

pub(crate) fn context_of_action(action: &Value) -> Value {
    let mut act = Map::new();
    let v = get(action, "verb");
    if !is_undef(v) {
        act.insert("verb".into(), v.clone());
    }
    let v = get(action, "resource");
    if !is_undef(v) {
        act.insert("resource".into(), v.clone());
    }
    act.insert("params".into(), Value::Object(spread(&nil_if_undef(get(action, "params")))));
    let v = get(action, "reversibilityClass");
    if !is_undef(v) {
        act.insert("reversibility_class".into(), v.clone());
    }
    let mut out = Map::new();
    out.insert("action".into(), Value::Object(act));
    out.insert("subject".into(), Value::Object(spread(&nil_if_undef(get(action, "subject")))));
    out.insert("env".into(), Value::Object(spread(&nil_if_undef(get(action, "env")))));
    Value::Object(out)
}

/// The ternary decision of a fully-specified action.
pub(crate) fn decide_action(model: &Value, action: &Value) -> &'static str {
    if !caveat_sat(model) {
        return "deny";
    }
    if !reversibility_ok(model, get(action, "reversibilityClass")) {
        return "deny";
    }
    decision_at_context(model, &context_of_action(action))
}

pub(crate) fn admits_action(model: &Value, action: &Value) -> bool {
    decide_action(model, action) != "deny"
}

pub(crate) fn rep_to_action(rep: &Rep) -> Value {
    let roots = build_roots(rep);
    let params = Value::Object(copy_map(get(get(&roots, "action"), "params")));
    let mut action = Map::new();
    action.insert("verb".into(), rep.verb.clone());
    action.insert("resource".into(), rep.resource.clone());
    action.insert("params".into(), params);
    if !rep.rev_class.is_null() {
        action.insert("reversibilityClass".into(), rep.rev_class.clone());
    }
    if obj(get(&roots, "subject")).is_some_and(|m| !m.is_empty()) {
        action.insert("subject".into(), get(&roots, "subject").clone());
    }
    if obj(get(&roots, "env")).is_some_and(|m| !m.is_empty()) {
        action.insert("env".into(), get(&roots, "env").clone());
    }
    Value::Object(action)
}

/// Walks the grid to the first representative the predicate accepts (`overflow` when the grid is over `mx`).
pub(crate) fn search(pr: &Probes, pred: &mut dyn FnMut(&Rep) -> bool, mx: f64) -> (Option<Rep>, bool) {
    if pr.product_size() > mx {
        return (None, true);
    }
    let mut hit: Option<Rep> = None;
    each_rep(pr, &mut |r: &Rep| {
        if pred(r) {
            hit = Some(r.clone());
            true
        } else {
            false
        }
    });
    (hit, false)
}

/// `search` collecting up to `limit` accepted representatives.
pub(crate) fn collect(pr: &Probes, pred: &mut dyn FnMut(&Rep) -> bool, mx: f64, limit: usize) -> (Vec<Rep>, bool) {
    if pr.product_size() > mx {
        return (vec![], true);
    }
    let mut hits: Vec<Rep> = vec![];
    each_rep(pr, &mut |r: &Rep| {
        if pred(r) {
            hits.push(r.clone());
            hits.len() >= limit
        } else {
            false
        }
    });
    (hits, false)
}
