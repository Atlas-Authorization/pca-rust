//! Static exposure of a workflow body (steps, dependency DAG, edges, budget). A body that is not a DAG is refused.

use super::js::*;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

const PATH_CAP: f64 = 1000000.0;

/// A step id: ids are strings; anything else cannot name a step.
fn dag_id(v: &Value) -> String {
    match v.as_str() {
        Some(t) => t.to_string(),
        None => fail("step id is not a string"),
    }
}

/// `x.length` of an array or a string (UTF-16 units); anything else throws.
pub(crate) fn js_len(v: &Value) -> usize {
    match v {
        Value::Array(a) => a.len(),
        Value::String(t) => t.encode_utf16().count(),
        _ => fail(format!("cannot read properties of {} (reading 'length')", if v.is_null() { "null" } else { "undefined" })),
    }
}

struct Visit<'a> {
    by_id: HashMap<String, &'a Value>,
    level: HashMap<String, usize>,
    anc: HashMap<String, HashSet<String>>,
    visiting: HashSet<String>,
}

impl Visit<'_> {
    fn visit(&mut self, id: &str) {
        if self.level.contains_key(id) {
            return;
        }
        if self.visiting.contains(id) {
            fail("dagExposure: cycle");
        }
        self.visiting.insert(id.to_string());
        let st = match self.by_id.get(id) {
            Some(st) => *st,
            None => fail(format!("dagExposure: unknown step {id}")),
        };
        let mut a: HashSet<String> = HashSet::new();
        let mut lv = 0usize;
        for dv in req_list(get(st, "deps")) {
            let d = dag_id(dv);
            self.visit(&d);
            a.insert(d.clone());
            if let Some(ad) = self.anc.get(&d) {
                for k in ad {
                    a.insert(k.clone());
                }
            }
            let dl = self.level.get(&d).copied().unwrap_or(0);
            if dl + 1 > lv {
                lv = dl + 1;
            }
        }
        self.visiting.remove(id);
        self.anc.insert(id.to_string(), a);
        self.level.insert(id.to_string(), lv);
    }
}

fn to_leaves(id: &str, children: &HashMap<String, Vec<String>>, memo: &mut HashMap<String, f64>, capped: &mut bool) -> f64 {
    if let Some(n) = memo.get(id) {
        return *n;
    }
    let kids: Vec<String> = children.get(id).cloned().unwrap_or_default();
    let mut n = if kids.is_empty() { 1.0 } else { 0.0 };
    for k in &kids {
        n += to_leaves(k, children, memo, capped);
    }
    if n > PATH_CAP {
        n = PATH_CAP;
        *capped = true;
    }
    memo.insert(id.to_string(), n);
    n
}

fn lineage_of(id: &str, feeds: &HashMap<String, HashSet<String>>, seen: &mut HashSet<String>) {
    let f = match feeds.get(id) {
        Some(f) => f,
        None => fail("feeds.get is not a function or its return value is not iterable"),
    };
    let ks: Vec<String> = f.iter().cloned().collect();
    for k in ks {
        if seen.insert(k.clone()) {
            lineage_of(&k, feeds, seen);
        }
    }
}

fn edge_to(e: &Value) -> String {
    dag_id(get(get(e, "to"), "step"))
}

pub(crate) fn dag_exposure(b: &Value) -> Value {
    let steps = req_list(get(b, "steps"));
    let mut by_id: HashMap<String, &Value> = HashMap::new();
    for st in steps {
        by_id.insert(dag_id(get(st, "id")), st);
    }
    if by_id.len() != steps.len() {
        fail("dagExposure: duplicate step id");
    }
    let mut vs = Visit { by_id, level: HashMap::new(), anc: HashMap::new(), visiting: HashSet::new() };
    for st in steps {
        let id = dag_id(get(st, "id"));
        vs.visit(&id);
    }
    let mut max_level = 0usize;
    let mut widths: HashMap<usize, usize> = HashMap::new();
    for lv in vs.level.values() {
        if *lv > max_level {
            max_level = *lv;
        }
        *widths.entry(*lv).or_insert(0) += 1;
    }
    let mut level_width = f64::NEG_INFINITY;
    for w in widths.values() {
        if *w as f64 > level_width {
            level_width = *w as f64;
        }
    }
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for st in steps {
        children.insert(dag_id(get(st, "id")), vec![]);
    }
    for st in steps {
        for d in req_list(get(st, "deps")) {
            let sid = dag_id(get(st, "id"));
            children.entry(dag_id(d)).or_default().push(sid);
        }
    }
    let mut memo: HashMap<String, f64> = HashMap::new();
    let mut capped = false;
    let mut paths = 0.0f64;
    for st in steps {
        if js_len(get(st, "deps")) == 0 {
            let id = dag_id(get(st, "id"));
            paths = jmin(PATH_CAP, paths + to_leaves(&id, &children, &mut memo, &mut capped));
        }
    }

    let budget = get(b, "budget");
    let caps = match obj(get(budget, "caps")) {
        Some(c) => c,
        None => fail("Object.entries requires an object"),
    };
    let mut cost = Map::new();
    for name in keys(caps) {
        let capv = &caps[name.as_str()];
        let mut total = 0.0;
        for st in steps {
            if let Some(sc) = obj(get(st, "cost")) {
                if let Some(c) = sc.get(&name) {
                    if !c.is_null() {
                        total += to_number(c);
                    }
                }
            }
        }
        cost.insert(name.clone(), u(vec![("cap", capv.clone()), ("total", num(total)), ("maxSpend", num(jmin(to_number(capv), total)))]));
    }
    let max_steps = get(budget, "max_steps");
    let mut never: Vec<Value> = vec![];
    for st in steps {
        let id = get(st, "id");
        let mut over = false;
        if let Some(sc) = obj(get(st, "cost")) {
            for (n, c) in sc {
                let zero = num(0.0);
                if to_number(c) > to_number(nn(mg(caps, n), &zero)) {
                    over = true;
                }
            }
        }
        if over {
            never.push(u(vec![("step", id.clone()), ("reason", s("cost_over_cap"))]));
        } else if is_num(max_steps) {
            let na = vs.anc.get(&dag_id(id)).map_or(0, |a| a.len());
            if (na + 1) as f64 > to_number(max_steps) {
                never.push(u(vec![("step", id.clone()), ("reason", s("needs_more_steps_than_budget"))]));
            }
        }
    }

    let edges = req_list(get(b, "edges"));
    let mut feeds: HashMap<String, HashSet<String>> = HashMap::new();
    for st in steps {
        feeds.insert(dag_id(get(st, "id")), HashSet::new());
    }
    for e in edges {
        let to = edge_to(e);
        let from = dag_id(get(get(e, "from"), "step"));
        match feeds.get_mut(&to) {
            Some(f) => {
                f.insert(from);
            }
            None => fail("cannot read properties of undefined (reading 'add')"),
        }
    }
    let mut sinks: Vec<Value> = vec![];
    let mut unprotected: Vec<Value> = vec![];
    for st in steps {
        let sk = get(st, "sink");
        if sk.is_null() {
            continue;
        }
        let sid = dag_id(get(st, "id"));
        let mut seen: HashSet<String> = HashSet::new();
        lineage_of(&sid, &feeds, &mut seen);
        let mut names: Vec<String> = seen.into_iter().collect();
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let lineage: Vec<Value> = names.iter().map(|n| s(n)).collect();
        let mut protected = js_len(get(st, "deny_labels")) > 0 || js_len(get(st, "escalate_labels")) > 0;
        for e in edges {
            if edge_to(e) == sid && js_len(get(e, "deny_labels")) > 0 {
                protected = true;
            }
        }
        let has_lineage = !lineage.is_empty();
        sinks.push(u(vec![("step", s(&sid)), ("sink", sk.clone()), ("lineage", Value::Array(lineage)), ("protected", Value::Bool(protected))]));
        if !protected && has_lineage {
            unprotected.push(s(&sid));
        }
    }
    let mut ordering_only: Vec<Value> = vec![];
    for st in steps {
        if js_len(get(st, "deps")) == 0 {
            continue;
        }
        let id = dag_id(get(st, "id"));
        let mut fed = false;
        for e in edges {
            if edge_to(e) == id {
                fed = true;
            }
        }
        if !fed {
            ordering_only.push(get(st, "id").clone());
        }
    }
    let mut pipelinable: Vec<Value> = vec![];
    for (i, e) in edges.iter().enumerate() {
        if !get(e, "promise").is_null() {
            pipelinable.push(num(i as f64));
        }
    }
    let max_steps_out = if is_num(max_steps) { num(jmin(steps.len() as f64, to_number(max_steps))) } else { Value::Null };
    u(vec![
        ("steps", num(steps.len() as f64)),
        ("maxSteps", max_steps_out),
        ("depth", num((max_level + 1) as f64)),
        ("levelWidth", num(level_width)),
        ("paths", num(paths)),
        ("pathsCapped", Value::Bool(capped)),
        ("cost", Value::Object(cost)),
        ("neverRunnable", Value::Array(never)),
        ("sinks", Value::Array(sinks)),
        ("unprotectedSinks", Value::Array(unprotected)),
        ("orderingOnly", Value::Array(ordering_only)),
        ("pipelinable", Value::Array(pipelinable)),
    ])
}
