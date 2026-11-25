//! An OpenFGA / Zanzibar model plus relationship tuples as one permit per (user, object, relation) triple that holds.
use super::*;
use std::collections::{HashMap, HashSet};

const MAX_DEPTH: usize = 32;

enum Plan {
    Direct,
    Computed(String),
    Union(Vec<Plan>),
    Intersection(Vec<Plan>),
    Difference(Box<Plan>, Box<Plan>),
    Ttu { tupleset: String, computed: String },
}

struct Built {
    plan: Option<Plan>,
    partial: bool,
    reason: String,
}

fn ok(plan: Plan, partial: bool) -> Built {
    Built { plan: Some(plan), partial, reason: String::new() }
}

fn fail(partial: bool, reason: String) -> Built {
    Built { plan: None, partial, reason }
}

fn has_own(o: &Value, k: &str) -> bool {
    o.as_object().is_some_and(|m| m.contains_key(k))
}

/// `container.child` as an array, for an object or array container.
fn child_nodes(container: &Value) -> Option<&Vec<Value>> {
    match container {
        Value::Object(m) => m.get("child").and_then(Value::as_array),
        _ => None,
    }
}

/// `v.relation` as a non-empty string.
fn relation_of(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Object(m)) => m.get("relation").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from),
        _ => None,
    }
}

fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

fn describe_plan(plan: &Plan) -> String {
    match plan {
        Plan::Direct => "direct".into(),
        Plan::Computed(r) => format!("computed {r}"),
        Plan::Union(c) => format!("union[{}]", c.iter().map(describe_plan).collect::<Vec<_>>().join(", ")),
        Plan::Intersection(c) => format!("intersection[{}]", c.iter().map(describe_plan).collect::<Vec<_>>().join(", ")),
        Plan::Difference(b, s) => format!("difference({} - {})", describe_plan(b), describe_plan(s)),
        Plan::Ttu { tupleset, computed } => format!("{computed} from {tupleset}"),
    }
}

fn build_plan(node: &Value, depth: usize) -> Built {
    if depth > MAX_FRAMES {
        return fail(false, "unknown rewrite node".into());
    }
    if has_own(node, "this") {
        return ok(Plan::Direct, false);
    }
    if has_own(node, "computedUserset") {
        return match relation_of(member(node, "computedUserset")) {
            Some(rel) => ok(Plan::Computed(rel), false),
            None => fail(false, "computedUserset without a relation".into()),
        };
    }
    if has_own(node, "union") {
        let children = match child_nodes(&node["union"]) {
            Some(c) => c,
            None => return fail(false, "union without children".into()),
        };
        let mut subs = Vec::new();
        let mut partial = false;
        for child in children {
            if !is_obj(child) {
                partial = true;
                continue;
            }
            let sub = build_plan(child, depth + 1);
            match sub.plan {
                None => partial = true, // OR under-approximates safely: drop the unmodeled child
                Some(p) => {
                    if sub.partial {
                        partial = true;
                    }
                    subs.push(p);
                }
            }
        }
        if subs.is_empty() {
            return fail(partial, "union with no modeled children".into());
        }
        return ok(Plan::Union(subs), partial);
    }
    if has_own(node, "intersection") {
        let children = match child_nodes(&node["intersection"]) {
            Some(c) => c,
            None => return fail(false, "intersection without children".into()),
        };
        let mut subs = Vec::new();
        for child in children {
            if !is_obj(child) {
                return fail(false, "intersection child is not a rewrite".into());
            }
            let sub = build_plan(child, depth + 1);
            match sub.plan {
                None => return fail(false, format!("intersection child unmodeled ({})", sub.reason)),
                Some(p) => subs.push(p),
            }
        }
        if subs.is_empty() {
            return fail(false, "intersection with no children".into());
        }
        return ok(Plan::Intersection(subs), false);
    }
    if has_own(node, "difference") {
        let diff = &node["difference"];
        if !is_obj(diff) {
            return fail(false, "malformed difference".into());
        }
        let (base_node, sub_node) = (member(diff, "base"), member(diff, "subtract"));
        let (base_node, sub_node) = match (base_node, sub_node) {
            (Some(b), Some(s)) if is_obj(b) && is_obj(s) => (b, s),
            _ => return fail(false, "difference needs both base and subtract".into()),
        };
        let base = build_plan(base_node, depth + 1);
        let subtract = build_plan(sub_node, depth + 1);
        let partial = base.partial || subtract.partial;
        let b = match base.plan {
            Some(b) => b,
            None => return fail(false, format!("difference base unmodeled ({})", base.reason)),
        };
        let s = match subtract.plan {
            Some(s) => s,
            None => return fail(false, format!("difference subtract unmodeled ({})", subtract.reason)),
        };
        return ok(Plan::Difference(Box::new(b), Box::new(s)), partial);
    }
    if has_own(node, "tupleToUserset") {
        let ttu = &node["tupleToUserset"];
        if !is_obj(ttu) {
            return fail(false, "malformed tupleToUserset".into());
        }
        let tupleset = relation_of(member(ttu, "tupleset"));
        let computed = relation_of(member(ttu, "computedUserset"));
        return match (tupleset, computed) {
            (None, _) => fail(false, "tupleToUserset without a tupleset relation".into()),
            (_, None) => fail(false, "tupleToUserset without a computedUserset relation".into()),
            (Some(tupleset), Some(computed)) => ok(Plan::Ttu { tupleset, computed }, false),
        };
    }
    fail(false, "unknown rewrite node".into())
}

/// `type_definitions` as (type, relations) in definition order; a repeated type replaces the earlier one in place.
fn parse_model<'a>(model: &'a Value, report: &mut Report) -> Option<Vec<(String, Vec<(String, &'a Value)>)>> {
    if !is_obj(model) {
        report.errors.push("model is not an object".into());
        return None;
    }
    let defs = match member(model, "type_definitions").and_then(Value::as_array) {
        Some(d) => d,
        None => {
            report.errors.push("model.type_definitions is missing or not an array".into());
            return None;
        }
    };
    let mut out: Vec<(String, Vec<(String, &Value)>)> = Vec::new();
    for d in defs {
        if !is_obj(d) {
            continue;
        }
        let t = match member(d, "type").and_then(Value::as_str) {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        let mut rel_map: Vec<(String, &Value)> = Vec::new();
        if let Some(es) = member(d, "relations").and_then(entries) {
            for (name, node) in es {
                if is_obj(node) {
                    rel_map.push((name, node));
                }
            }
        }
        match out.iter().position(|(k, _)| k == t) {
            Some(i) => out[i].1 = rel_map,
            None => out.push((t.to_string(), rel_map)),
        }
    }
    Some(out)
}

struct Tuple {
    user: String,
    relation: String,
    object: String,
}

fn parse_tuples(tuples: Option<&Value>, report: &mut Report) -> Vec<Tuple> {
    let list = match tuples {
        Some(Value::Array(a)) => a,
        Some(_) => {
            report.errors.push("tuples is not an array".into());
            return vec![];
        }
        None => return vec![],
    };
    let mut out = Vec::new();
    for t in list {
        let get = |k: &str| t.as_object().and_then(|m| m.get(k)).and_then(Value::as_str).map(String::from);
        if let (Some(user), Some(relation), Some(object)) = (get("user"), get("relation"), get("object")) {
            out.push(Tuple { user, relation, object });
        }
    }
    out
}

fn type_of(obj: &str) -> &str {
    obj.find(':').map_or(obj, |i| &obj[..i])
}

fn object_of_userset(p: &str) -> &str {
    p.find('#').map_or(p, |i| &p[..i])
}

fn key(a: &str, b: &str) -> String {
    format!("{a}\u{0}{b}")
}

struct Eval<'a> {
    plans: &'a HashMap<String, Plan>,
    direct: &'a HashMap<String, HashSet<String>>,
}

impl Eval<'_> {
    fn holds_rel(&self, user: &str, obj: &str, relation: &str, depth: usize, visited: &mut Vec<String>) -> bool {
        let k = key(obj, relation);
        if depth > MAX_DEPTH || visited.contains(&k) {
            return false;
        }
        let plan = match self.plans.get(&key(type_of(obj), relation)) {
            Some(p) => p,
            None => return false,
        };
        visited.push(k);
        let r = self.eval_plan(user, obj, relation, plan, depth, visited);
        visited.pop();
        r
    }

    fn eval_plan(&self, user: &str, obj: &str, relation: &str, plan: &Plan, depth: usize, visited: &mut Vec<String>) -> bool {
        match plan {
            Plan::Direct => self.direct.get(&key(obj, relation)).is_some_and(|s| s.contains(user) || s.contains(&format!("{}:*", type_of(user)))),
            Plan::Computed(r) => self.holds_rel(user, obj, r, depth + 1, visited),
            Plan::Union(cs) => cs.iter().any(|c| self.eval_plan(user, obj, relation, c, depth, visited)),
            Plan::Intersection(cs) => cs.iter().all(|c| self.eval_plan(user, obj, relation, c, depth, visited)),
            Plan::Difference(b, s) => self.eval_plan(user, obj, relation, b, depth, visited) && !self.eval_plan(user, obj, relation, s, depth, visited),
            Plan::Ttu { tupleset, computed } => match self.direct.get(&key(obj, tupleset)) {
                None => false,
                Some(related) => related.iter().any(|p| self.holds_rel(user, object_of_userset(p), computed, depth + 1, visited)),
            },
        }
    }
}

fn is_wildcard(user: &str) -> bool {
    user.ends_with(":*") && user.encode_utf16().count() > 2 && !user.contains('#')
}

fn escape_glob(t: &str) -> String {
    let mut out = String::new();
    for c in t.chars() {
        if matches!(c, '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn sorted16(set: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort_by(cmp16);
    v
}

/// An OpenFGA / Zanzibar model plus relationship tuples as one permit per (user, object, relation) triple that holds (`this`,
/// computedUserset, union, intersection, difference, tupleToUserset; bounded and cycle-guarded). `tuples = None` is an absent argument
/// (no error); anything but an array otherwise is reported.
pub fn openfga_to_pca(model: &Value, tuples: Option<&Value>) -> Value {
    let mut report = Report::new("openfga");
    let mut predicates: Vec<Value> = Vec::new();
    let type_relations = parse_model(model, &mut report);
    let tuple_list = parse_tuples(tuples, &mut report);
    let type_relations = match type_relations {
        Some(t) => t,
        None => return result(predicates, vec![], report),
    };

    let mut direct: HashMap<String, HashSet<String>> = HashMap::new();
    let mut users_seen: HashSet<String> = HashSet::new();
    let mut wildcard_types: HashSet<String> = HashSet::new();
    let mut objects_seen: HashSet<String> = HashSet::new();
    let mut userset_tuples = 0usize;
    for t in &tuple_list {
        objects_seen.insert(t.object.clone());
        direct.entry(key(&t.object, &t.relation)).or_default().insert(t.user.clone());
        if t.user.contains('#') {
            userset_tuples += 1;
        } else if is_wildcard(&t.user) {
            wildcard_types.insert(t.user[..t.user.len() - 2].to_string());
        } else {
            users_seen.insert(t.user.clone());
        }
    }
    if userset_tuples > 0 {
        report.skipped.push(format!("{userset_tuples} userset-valued tuple(s) (user contains '#') not expanded to concrete users"));
    }

    let mut plans: HashMap<String, Plan> = HashMap::new();
    for (type_, relations) in &type_relations {
        for (relation, node) in relations {
            let built = build_plan(node, 0);
            let plan = match built.plan {
                Some(p) => p,
                None => {
                    report.skipped.push(format!("relation {type_}#{relation}: {} \u{2014} skipped", built.reason));
                    continue;
                }
            };
            if built.partial {
                report.skipped.push(format!("relation {type_}#{relation}: some union children unsupported and dropped (under-approximated)"));
            }
            report.translated.push(format!("relation {type_}#{relation} ({})", describe_plan(&plan)));
            plans.insert(key(type_, relation), plan);
        }
    }

    let ev = Eval { plans: &plans, direct: &direct };
    let sorted_users = sorted16(&users_seen);
    let sorted_wild = sorted16(&wildcard_types);
    for obj in sorted16(&objects_seen) {
        let type_ = type_of(&obj);
        let relations = match type_relations.iter().find(|(k, _)| k == type_) {
            Some((_, r)) => r,
            None => {
                report.skipped.push(format!("object {obj}: type \"{type_}\" not defined in model \u{2014} ignored"));
                continue;
            }
        };
        let mut names: Vec<String> = relations.iter().map(|(n, _)| n.clone()).collect();
        names.sort_by(cmp16);
        for relation in &names {
            if !plans.contains_key(&key(type_, relation)) {
                continue;
            }
            for user in &sorted_users {
                if ev.holds_rel(user, &obj, relation, 0, &mut Vec::new()) {
                    predicates.push(json!({ "verb": relation, "resource": obj, "where": [{ "field": "subject.id", "op": "eq", "value": user }] }));
                }
            }
            // a public tuple (`type:*`) grants every subject of that type, including ones no tuple names
            for wtype in &sorted_wild {
                if !ev.holds_rel(&format!("{wtype}:\u{0}anyone"), &obj, relation, 0, &mut Vec::new()) {
                    continue;
                }
                let named: Vec<&String> = sorted_users.iter().filter(|u| type_of(u) == wtype.as_str()).collect();
                let mut where_ = vec![json!({ "field": "subject.id", "op": "like", "value": format!("{}:*", escape_glob(wtype)) })];
                if !named.is_empty() {
                    where_.push(json!({ "not": { "field": "subject.id", "op": "in", "value": named } }));
                }
                predicates.push(json!({ "verb": relation, "resource": obj, "where": where_ }));
            }
        }
    }
    result(predicates, vec![], report)
}
