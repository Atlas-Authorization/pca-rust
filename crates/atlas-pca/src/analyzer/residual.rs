//! Partial evaluation, residual policies and "what may I do?" discovery. Everything here is advisory: the verifier stays authoritative.

use super::enumerate::*;
use super::exposure::thresholds_of;
use super::js::*;
use super::query::reason_of;
use crate::predicates::{evaluate_condition_tri, predicate_matches, Ctx, Tri};
use serde_json::{Map, Value};
use std::collections::HashMap;

const UNKNOWN_VERB: &str = "\u{0}unknown-verb\u{0}";
const UNKNOWN_RESOURCE: &str = "\u{0}unknown-resource\u{0}";

/// A path is symbolic when it is an unknown path, below one, or an ancestor of one.
fn is_unknown_path(path: &Value, unknown: &[String]) -> bool {
    let p = match path.as_str() {
        Some(p) => p,
        None => return false,
    };
    unknown.iter().any(|u| p == u || p.starts_with(&format!("{u}.")) || u.starts_with(&format!("{p}.")))
}

/// The partial evaluation of a condition: a constant ("true" | "false" | "unknown", with its source) or a symbolic condition.
#[derive(Clone)]
struct Pe {
    cond: bool,
    v: &'static str,
    src: Value,
    c: Value,
}

fn pe_const(v: &'static str, src: &Value) -> Pe {
    Pe { cond: false, v, src: src.clone(), c: Value::Null }
}

impl Pe {
    fn is_const(&self, v: &str) -> bool {
        !self.cond && self.v == v
    }

    fn out(&self) -> Value {
        if self.cond {
            self.c.clone()
        } else {
            self.src.clone()
        }
    }
}

fn tri_name(t: Tri) -> &'static str {
    match t {
        Tri::True => "true",
        Tri::False => "false",
        Tri::Unknown => "unknown",
    }
}

fn pe_group(list: &Value, ctx: &Value, unk: &[String], c: &Value, key: &str, absorbing: &'static str, neutral: &'static str) -> Pe {
    let a = match list.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return pe_const("unknown", c),
    };
    let rs: Vec<Pe> = a.iter().map(|x| pe(x, ctx, unk)).collect();
    if rs.iter().any(|r| r.is_const(absorbing)) {
        return pe_const(absorbing, c);
    }
    let kept: Vec<&Pe> = rs.iter().filter(|r| !r.is_const(neutral)).collect();
    if kept.is_empty() {
        return pe_const(neutral, c);
    }
    if kept.iter().all(|r| !r.cond) {
        return pe_const("unknown", c);
    }
    let mut cs: Vec<Value> = kept.iter().map(|r| r.out()).collect();
    if cs.len() == 1 {
        return Pe { cond: true, v: "", src: Value::Null, c: cs.remove(0) };
    }
    let mut m = Map::new();
    m.insert(key.to_string(), Value::Array(cs));
    Pe { cond: true, v: "", src: Value::Null, c: Value::Object(m) }
}

fn pe(c: &Value, ctx: &Value, unk: &[String]) -> Pe {
    let m = obj(c);
    if m.is_none() && !c.is_array() {
        return pe_const("unknown", c);
    }
    if let Some(m) = m {
        if is_group_map(m) {
            if m.contains_key("all_of") {
                return pe_group(&m["all_of"], ctx, unk, c, "all_of", "false", "true");
            }
            if m.contains_key("any_of") {
                return pe_group(&m["any_of"], ctx, unk, c, "any_of", "true", "false");
            }
            let r = pe(&m["not"], ctx, unk);
            if r.cond {
                let mut o = Map::new();
                o.insert("not".into(), r.c.clone());
                return Pe { cond: true, v: "", src: Value::Null, c: Value::Object(o) };
            }
            return match r.v {
                "true" => pe_const("false", c),
                "false" => pe_const("true", c),
                _ => pe_const("unknown", c),
            };
        }
    }
    if let Some(lf) = leaf(c) {
        if is_unknown_path(mg(lf, "field"), unk) || is_unknown_path(mg(lf, "ref"), unk) || is_unknown_path(mg(lf, "collection"), unk) {
            return Pe { cond: true, v: "", src: Value::Null, c: c.clone() };
        }
    }
    pe_const(tri_name(evaluate_condition_tri(c, &Ctx::new(ctx))), c)
}

/// The AND of a `where` list: ("v", "true" | "false" | "unknown", []) or ("cs", "", symbolic conditions).
fn pe_all(where_: &Value, ctx: &Value, unk: &[String]) -> (&'static str, &'static str, Vec<Value>) {
    if is_undef(where_) {
        return ("v", "true", vec![]);
    }
    let list = match where_.as_array() {
        Some(l) => l,
        None => return ("v", "unknown", vec![]),
    };
    let rs: Vec<Pe> = list.iter().map(|w| pe(w, ctx, unk)).collect();
    if rs.iter().any(|r| r.is_const("false")) {
        return ("v", "false", vec![]);
    }
    let kept: Vec<&Pe> = rs.iter().filter(|r| !r.is_const("true")).collect();
    if kept.is_empty() {
        return ("v", "true", vec![]);
    }
    if kept.iter().all(|r| !r.cond) {
        return ("v", "unknown", vec![]);
    }
    ("cs", "", kept.iter().map(|r| r.out()).collect())
}

pub(crate) fn context_of_known(k: &Value) -> Value {
    let verb = get(k, "verb");
    let resource = get(k, "resource");
    let params = get(k, "params");
    let subj = get(k, "subject");
    let env = get(k, "env");
    let rc = get(k, "reversibilityClass");
    let mut action = Map::new();
    action.insert("verb".into(), if is_undef(verb) || verb.is_null() { s(UNKNOWN_VERB) } else { verb.clone() });
    action.insert("resource".into(), if is_undef(resource) || resource.is_null() { s(UNKNOWN_RESOURCE) } else { resource.clone() });
    action.insert("params".into(), Value::Object(spread(&nil_if_undef(params))));
    if !is_undef(rc) {
        action.insert("reversibility_class".into(), rc.clone());
    }
    let mut out = Map::new();
    out.insert("action".into(), Value::Object(action));
    out.insert("subject".into(), Value::Object(spread(&nil_if_undef(subj))));
    out.insert("env".into(), Value::Object(spread(&nil_if_undef(env))));
    Value::Object(out)
}

pub(crate) fn policy_digest_of(model: &Value) -> String {
    let meet: Vec<Value> = req_list(get(model, "meets")).iter().map(|m| s(&policy_digest_of(m))).collect();
    let mut m = Map::new();
    for k in ["predicates", "caveats", "vetoes", "tighten"] {
        m.insert(k.to_string(), get(model, k).clone());
    }
    m.insert("meet".into(), Value::Array(meet));
    match crate::hash_canonical_strict(&Value::Object(m)) {
        Some(h) => h,
        None => fail("policy digest: not canonicalisable"),
    }
}

fn flatten(m: &Value) -> Vec<Value> {
    let mut out = vec![m.clone()];
    for x in req_list(get(m, "meets")) {
        out.extend(flatten(x));
    }
    out
}

/// `predicate_matches` over a `{verb, resource}` pattern (an undefined member is left out).
fn pm(verb: &Value, resource: &Value, ctx: &Value) -> bool {
    let mut pat = Map::new();
    if !is_undef(verb) {
        pat.insert("verb".into(), verb.clone());
    }
    if !is_undef(resource) {
        pat.insert("resource".into(), resource.clone());
    }
    predicate_matches(&Value::Object(pat), &Ctx::new(ctx))
}

fn residual_part(part: &Value, ctx: &Value, unk: &[String], verb_known: bool, res_known: bool) -> Value {
    let mut predicates: Vec<Value> = vec![];
    for p in req_list(get(part, "predicates")) {
        if !is_obj(p) && !p.is_array() {
            continue;
        }
        let (pv, pr) = (get(p, "verb"), get(p, "resource"));
        if verb_known && !pm(pv, &s("*"), ctx) {
            continue;
        }
        if res_known && !pm(&s("*"), pr, ctx) {
            continue;
        }
        let (kind, v, cs) = pe_all(get(p, "where"), ctx, unk);
        if kind == "v" && v != "true" {
            continue; // false and unknown both fail closed for a permit
        }
        let verb = if verb_known { s("*") } else { pv.clone() };
        let mut item = u_map(vec![("verb", verb)]);
        if !res_known && !is_undef(pr) {
            item.insert("resource".into(), pr.clone());
        }
        if kind == "cs" {
            item.insert("where".into(), Value::Array(cs));
        }
        predicates.push(Value::Object(item));
    }
    let mut vetoes: Vec<Value> = vec![];
    for v in req_list(get(part, "vetoes")) {
        if let Some(r) = pe_veto(v, ctx, unk, verb_known, res_known) {
            vetoes.push(r);
        }
    }
    let mut tighten: Vec<Value> = vec![];
    for t in req_list(get(part, "tighten")) {
        let tw = get(t, "when");
        let inp = if is_undef(tw) { Value::Null } else { tw.clone() };
        let r = pe(&inp, ctx, unk);
        if r.is_const("false") {
            continue; // a veto-polarity rule that cleanly cannot hold
        }
        let mut nt = spread(t);
        if r.cond {
            nt.insert("when".into(), r.c.clone());
        } else {
            nt.insert("when".into(), tw.clone());
        }
        tighten.push(u_from_map(nt));
    }
    u(vec![
        ("predicates", Value::Array(predicates)),
        ("caveats", get(part, "caveats").clone()),
        ("vetoes", Value::Array(vetoes)),
        ("tighten", Value::Array(tighten)),
    ])
}

fn pe_veto(v: &Value, ctx: &Value, unk: &[String], verb_known: bool, res_known: bool) -> Option<Value> {
    let when = get(v, "when");
    let wv = get(when, "verb");
    if verb_known && !pm(wv, &s("*"), ctx) {
        return None;
    }
    let wr = get(when, "resource");
    if res_known && !is_undef(wr) && !pm(&s("*"), wr, ctx) {
        return None;
    }
    let (kind, val, cs) = pe_all(get(when, "where"), ctx, unk);
    if kind == "v" && val == "false" {
        return None; // veto polarity: a clean false removes the veto; true and unknown mean it applies
    }
    let verb = if verb_known { s("*") } else { wv.clone() };
    let mut nw = u_map(vec![("verb", verb)]);
    if !res_known && !is_undef(wr) {
        nw.insert("resource".into(), wr.clone());
    }
    if kind == "cs" {
        nw.insert("where".into(), Value::Array(cs));
    }
    let mut out = u_map(vec![("id", get(v, "id").clone()), ("kind", get(v, "kind").clone()), ("when", Value::Object(nw))]);
    let over = get(v, "over");
    if truthy(over) {
        if is_unknown_path(get(over, "path"), unk) {
            out.insert("over".into(), over.clone());
        } else {
            let found = get(over, "path").as_str().and_then(|p| Ctx::new(ctx).resolve(p));
            let is_over = match found {
                None => true,
                Some(val) => !is_fin(val) || to_number(val) < 0.0 || gt(val, get(over, "threshold")),
            };
            if !is_over {
                return None;
            }
        }
    }
    let unless = get(v, "unless");
    if truthy(unless) && get(v, "kind").as_str() == Some("approval") {
        out.insert("unless".into(), unless.clone()); // the evidence of approval: carried, never used to drop the veto
    } else if truthy(unless) {
        let (uk, uv, ucs) = pe_all(unless, ctx, unk);
        if uk == "cs" {
            out.insert("unless".into(), Value::Array(ucs));
        } else if uv == "true" {
            return None; // the exception certainly holds: the veto never applies
        }
    }
    Some(Value::Object(out))
}

fn empty_policy() -> Value {
    u(vec![("predicates", empty_arr()), ("caveats", empty_arr()), ("vetoes", empty_arr()), ("tighten", empty_arr())])
}

/// Specialises `policy` to `known`; everything under `opts.unknown` stays symbolic. Returns `{decision: 'never' | 'always' | 'conditional',
/// reason?, policy, policyDigest}`.
pub(crate) fn residual(policy: &Value, known: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let opts = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let model = to_model(policy);
    let digest = policy_digest_of(&model);
    let verb_known = !is_undef(get(known, "verb"));
    let res_known = !is_undef(get(known, "resource")) && get(opts, "resourceUnknown").as_bool() != Some(true);
    let dflt = Value::Array(vec![s("action.params")]);
    let mut unk: Vec<String> = vec![];
    for x in req_list(nn(get(opts, "unknown"), &dflt)) {
        unk.push(req_str(x, "unknown path").to_string());
    }
    if !verb_known {
        unk.push("action.verb".to_string());
    }
    if !res_known {
        unk.push("action.resource".to_string());
    }
    let ctx = context_of_known(known);
    let never = |reason: &str| u(vec![("decision", s("never")), ("reason", s(reason)), ("policy", empty_policy()), ("policyDigest", s(&digest))]);
    if !caveat_sat(&model) {
        return never(&format!("caveats unsatisfiable: {}", js(&reason_of(&model))));
    }
    let rc = get(known, "reversibilityClass");
    if let (Some(c), false) = (rev_cap(&model), is_undef(rc)) {
        let idx = rev_index(rc);
        if idx < 0 || idx > c {
            return never("reversibility class exceeds the caveat cap");
        }
    }
    let parts: Vec<Value> = flatten(&model).iter().map(|m| residual_part(m, &ctx, &unk, verb_known, res_known)).collect();
    let mut pol = copy_map(&parts[0]);
    if parts.len() > 1 {
        pol.insert("meet".into(), Value::Array(parts[1..].to_vec()));
    }
    let mut res = u_map(vec![("decision", s("conditional")), ("policy", Value::Object(pol)), ("policyDigest", s(&digest))]);
    for p in &parts {
        if req_list(get(p, "predicates")).is_empty() {
            return never("no permit survives the known facts");
        }
    }
    for p in &parts {
        for vm in req_list(get(p, "vetoes")) {
            let w = get(vm, "when");
            let wr = own(w, "resource");
            let wh = own(w, "where").as_array();
            if get(vm, "kind").as_str() == Some("deny")
                && (!has(w, "resource") || wr.as_str() == Some("*"))
                && wh.map_or(true, |l| l.is_empty())
                && !has(vm, "unless")
                && !has(vm, "over")
            {
                return never(&format!("veto {} applies to every completion", js(own(vm, "id"))));
            }
        }
    }
    let mut always = true;
    for p in &parts {
        let unconditional = req_list(get(p, "predicates")).iter().any(|x| !has(x, "where"));
        if !unconditional || !req_list(get(p, "vetoes")).is_empty() || !req_list(get(p, "tighten")).is_empty() {
            always = false;
        }
    }
    if always {
        res.insert("decision".into(), s("always"));
    }
    Value::Object(res)
}

/// The residual as a policy the analyzer and the real evaluator both understand.
pub(crate) fn residual_policy(r: &Value) -> Value {
    let pol = get(r, "policy");
    if !is_obj(pol) {
        fail("policy is not an object");
    }
    let mut own_p = copy_map(pol);
    own_p.remove("meet");
    let meet = own(pol, "meet");
    if truthy(meet) {
        let ms: Vec<Value> = req_list(meet).iter().map(|m| Value::Object(spread(m))).collect();
        own_p.insert("meet".into(), Value::Array(ms));
    }
    Value::Object(own_p)
}

/// The ternary decision of a residual once the unknown fields are bound.
pub(crate) fn evaluate_residual(r: &Value, ctx: &Value) -> &'static str {
    if get(r, "decision").as_str() == Some("never") {
        return "deny";
    }
    let a = get(ctx, "action");
    let mut action = u_map(vec![("verb", get(a, "verb").clone()), ("resource", get(a, "resource").clone())]);
    let v = get(a, "params");
    if truthy(v) {
        action.insert("params".into(), v.clone());
    }
    let v = get(ctx, "subject");
    if truthy(v) {
        action.insert("subject".into(), v.clone());
    }
    let v = get(ctx, "env");
    if truthy(v) {
        action.insert("env".into(), v.clone());
    }
    let v = get(a, "reversibility_class");
    if truthy(v) {
        action.insert("reversibilityClass".into(), v.clone());
    }
    decide_action(&to_model(&residual_policy(r)), &Value::Object(action))
}

// ---- "what may I do?" ---------------------------------------------------------------------------------------------------------

fn range_lo(r: &Map<String, Value>) -> f64 {
    match r.get("lo") {
        Some(v) => to_number(v),
        None => f64::NEG_INFINITY,
    }
}

fn range_hi(r: &Map<String, Value>) -> f64 {
    match r.get("hi") {
        Some(v) => to_number(v),
        None => f64::INFINITY,
    }
}

fn b2i(v: &Value) -> f64 {
    if truthy(v) {
        1.0
    } else {
        0.0
    }
}

fn merge_ranges(rs: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
    let cmp = |a: &Map<String, Value>, b: &Map<String, Value>| -> f64 {
        let (la, lb) = (range_lo(a), range_lo(b));
        let mut d = f64::NAN;
        if !(la == lb && la.is_infinite()) {
            d = la - lb;
        }
        if d.is_nan() || d == 0.0 {
            return b2i(mg(b, "loInclusive")) - b2i(mg(a, "loInclusive"));
        }
        d
    };
    let mut sorted = rs;
    stable_sort_by_less(&mut sorted, &|a, b| cmp(a, b) < 0.0);
    let mut out: Vec<Map<String, Value>> = vec![];
    for r in sorted {
        let (rlo, rhi) = (range_lo(&r), range_hi(&r));
        let merge = match out.last() {
            Some(last) => {
                let lhi = range_hi(last);
                lhi >= rlo && !(lhi == rlo && !truthy(mg(last, "hiInclusive")) && !truthy(mg(&r, "loInclusive")))
            }
            None => false,
        };
        if merge {
            let last = out.last_mut().unwrap();
            let lhi = range_hi(last);
            if rhi > lhi || (rhi == lhi && truthy(mg(&r, "hiInclusive"))) {
                match r.get("hi") {
                    None => {
                        last.remove("hi");
                    }
                    Some(hv) => {
                        last.insert("hi".into(), hv.clone());
                    }
                }
                if truthy(mg(&r, "hiInclusive")) {
                    last.insert("hiInclusive".into(), Value::Bool(true));
                } else {
                    last.remove("hiInclusive");
                }
            }
        } else {
            out.push(r);
        }
    }
    out
}

fn cell_range(value: &Value, t: &[Value]) -> Map<String, Value> {
    let vf = to_number(value);
    if t.iter().any(|x| to_number(x) == vf) {
        return u_map(vec![("lo", value.clone()), ("hi", value.clone()), ("loInclusive", Value::Bool(true)), ("hiInclusive", Value::Bool(true))]);
    }
    let mut out = Map::new();
    for x in t.iter().rev() {
        if lt(x, value) {
            out.insert("lo".into(), x.clone());
            break;
        }
    }
    for x in t {
        if gt(x, value) {
            out.insert("hi".into(), x.clone());
            break;
        }
    }
    out
}

struct SeenVal {
    value: Value,
    allow: bool,
    escalate: bool,
}

#[derive(Default)]
struct SeenSet {
    order: Vec<SeenVal>,
    idx: HashMap<String, usize>,
}

#[derive(Default)]
struct ResFlags {
    allow: bool,
    escalate: bool,
}

/// Per verb shape (`{verb, params}`): autonomous / approval-only / denied for the known principal, and which parameter values and
/// resources are still allowed. Advisory; sound on the decided fragment, otherwise `approximate`.
pub(crate) fn what_may_i_do(policy: &Value, verbs: &Value, known_in: &Value, o_in: &Value) -> Value {
    let empty = empty_obj();
    let known = if known_in.is_null() || is_undef(known_in) { &empty } else { known_in };
    let o = if o_in.is_null() || is_undef(o_in) { &empty } else { o_in };
    let mut out: Vec<Value> = vec![];
    let mut mx = DEFAULT_MAX_COMBINATIONS;
    let mc = get(o, "maxCombinations");
    if is_num(mc) {
        mx = to_number(mc);
    }
    for shape in req_list(verbs) {
        let sverb = get(shape, "verb");
        let mut kn = spread(known);
        kn.insert("verb".into(), sverb.clone());
        let res = residual(policy, &u_from_map(kn), &Value::Null);
        let mut env = u_map(vec![
            ("verb", sverb.clone()),
            ("status", s("denied")),
            ("params", empty_obj()),
            ("resources", u(vec![("autonomous", empty_arr()), ("withApproval", empty_arr()), ("other", Value::Bool(false))])),
            ("policyDigest", get(&res, "policyDigest").clone()),
            ("advisory", Value::Bool(true)),
        ]);
        let rem = get(o, "remaining");
        if truthy(rem) {
            env.insert("remaining".into(), Value::Object(spread(rem)));
        }
        let md = get(o, "missingDischarges");
        if truthy(md) {
            env.insert("missingDischarges".into(), Value::Array(req_list(md).clone()));
        }
        if get(&res, "decision").as_str() == Some("never") {
            if has(&res, "reason") {
                env.insert("reason".into(), own(&res, "reason").clone());
            }
            out.push(Value::Object(env));
            continue;
        }
        let rp = to_model(&residual_policy(&res));
        let sparams = match obj(get(shape, "params")) {
            Some(m) => m,
            None => fail("Object.entries requires an object"),
        };
        let names = keys(sparams);
        let mut extra: Vec<Value> = vec![];
        for name in &names {
            let d = &sparams[name.as_str()];
            let vals = get(d, "values");
            if !is_undef(vals) {
                let p = format!("action.params.{name}");
                extra.push(u(vec![("path", s(&p)), ("cond", u(vec![("field", s(&p)), ("op", s("in")), ("value", vals.clone())]))]));
            }
        }
        for name in &names {
            let d = &sparams[name.as_str()];
            let p = format!("action.params.{name}");
            let v = get(d, "min");
            if !is_undef(v) {
                extra.push(u(vec![("path", s(&p)), ("cond", u(vec![("field", s(&p)), ("op", s("gte")), ("value", v.clone())]))]));
            }
            let v = get(d, "max");
            if !is_undef(v) {
                extra.push(u(vec![("path", s(&p)), ("cond", u(vec![("field", s(&p)), ("op", s("lte")), ("value", v.clone())]))]));
            }
        }
        let has_cap = has(&rp, "revCap");
        let mut pr = collect_probes(&u(vec![
            ("predicateSets", Value::Array(vec![Value::Array(probe_set(&rp))])),
            ("extraFieldConditions", Value::Array(extra)),
            ("varyReversibility", Value::Bool(has_cap)),
        ]));
        pr.verbs = vec![sverb.clone()];
        if pr.product_size() > mx {
            env.insert("status".into(), s("needs-approval"));
            env.insert("approximate".into(), Value::Bool(true));
            env.insert("reason".into(), s("representative grid exceeded the bound; no domain is claimed"));
            out.push(Value::Object(env));
            continue;
        }
        let kres = get(known, "resource");
        if !is_undef(kres) {
            pr.resources = vec![kres.clone()];
        }
        let mut seen: HashMap<String, SeenSet> = HashMap::new();
        let mut res_seen: HashMap<String, ResFlags> = HashMap::new();
        let (mut any_allow, mut any_escalate, mut fresh_res) = (false, false, false);
        each_rep(&pr, &mut |rep: &Rep| {
            let d = decide(&rp, rep);
            if d == "deny" {
                return false;
            }
            if d == "allow" {
                any_allow = true;
            } else {
                any_escalate = true;
            }
            let act = rep_to_action(rep);
            let params = obj(own(&act, "params"));
            for name in &names {
                let pv = params.and_then(|m| m.get(name.as_str()));
                let v = pv.cloned().unwrap_or_else(undef_v);
                let set = seen.entry(name.clone()).or_default();
                let k = if pv.is_some() { json_str(&v) } else { "\u{0}absent".to_string() };
                let i = match set.idx.get(&k) {
                    Some(i) => *i,
                    None => {
                        set.order.push(SeenVal { value: v, allow: false, escalate: false });
                        set.idx.insert(k, set.order.len() - 1);
                        set.order.len() - 1
                    }
                };
                if d == "allow" {
                    set.order[i].allow = true;
                } else {
                    set.order[i].escalate = true;
                }
            }
            let rname = js(own(&act, "resource"));
            let rr = res_seen.entry(rname.clone()).or_default();
            if d == "allow" {
                rr.allow = true;
            } else {
                rr.escalate = true;
            }
            if rname.starts_with('\u{0}') {
                fresh_res = true;
            }
            false
        });
        if any_allow {
            env.insert("status".into(), s("autonomous"));
        } else if any_escalate {
            env.insert("status".into(), s("needs-approval"));
        }
        let mut env_params = Map::new();
        for name in &names {
            let decl = &sparams[name.as_str()];
            let t = thresholds_of(&rp, &format!("action.params.{name}"));
            let vals: &[SeenVal] = seen.get(name).map_or(&[][..], |x| x.order.as_slice());
            let (dmin, dmax) = (get(decl, "min"), get(decl, "max"));
            let mut nums: Vec<&SeenVal> = vec![];
            let mut strs: Vec<&SeenVal> = vec![];
            for x in vals {
                if is_num(&x.value) && (is_undef(dmin) || to_number(&x.value) >= to_number(dmin)) && (is_undef(dmax) || to_number(&x.value) <= to_number(dmax))
                {
                    nums.push(x);
                }
                if x.value.is_string() {
                    strs.push(x);
                }
            }
            let dvalues = get(decl, "values");
            if get(decl, "type").as_str() == Some("integer") || !nums.is_empty() {
                let clip = |r: Map<String, Value>| -> Map<String, Value> {
                    let mut n = r.clone();
                    if !is_undef(dmin) {
                        let need = match r.get("lo") {
                            None => true,
                            Some(lo) => to_number(lo) < to_number(dmin),
                        };
                        if need {
                            n.insert("lo".into(), dmin.clone());
                            n.insert("loInclusive".into(), Value::Bool(true));
                        }
                    }
                    if !is_undef(dmax) {
                        let need = match r.get("hi") {
                            None => true,
                            Some(hi) => to_number(hi) > to_number(dmax),
                        };
                        if need {
                            n.insert("hi".into(), dmax.clone());
                            n.insert("hiInclusive".into(), Value::Bool(true));
                        }
                    }
                    n
                };
                let ranges = |pick: &dyn Fn(&SeenVal) -> bool| -> Vec<Value> {
                    let rs: Vec<Map<String, Value>> = nums.iter().filter(|x| pick(**x)).map(|x| clip(cell_range(&x.value, &t))).collect();
                    merge_ranges(rs).into_iter().map(Value::Object).collect()
                };
                env_params.insert(
                    name.clone(),
                    u(vec![
                        ("kind", s("numeric")),
                        ("autonomous", Value::Array(ranges(&|x| x.allow))),
                        ("withApproval", Value::Array(ranges(&|x| x.escalate && !x.allow))),
                    ]),
                );
            } else if !is_undef(dvalues) || !strs.is_empty() {
                let pick_list = |f: &dyn Fn(&SeenVal) -> bool| -> Vec<Value> {
                    let l: Vec<String> = strs.iter().filter_map(|x| x.value.as_str().filter(|t| f(*x) && !t.starts_with('\u{0}')).map(String::from)).collect();
                    sorted_units(l)
                };
                let fresh = strs.iter().find(|x| x.value.as_str().is_some_and(|t| t.starts_with('\u{0}')));
                env_params.insert(
                    name.clone(),
                    u(vec![
                        ("kind", s("enum")),
                        ("autonomous", Value::Array(pick_list(&|x| x.allow))),
                        ("withApproval", Value::Array(pick_list(&|x| x.escalate && !x.allow))),
                        ("otherAutonomous", Value::Bool(is_undef(dvalues) && fresh.is_some_and(|f| f.allow))),
                        ("otherWithApproval", Value::Bool(is_undef(dvalues) && fresh.is_some_and(|f| f.escalate && !f.allow))),
                    ]),
                );
            } else {
                env_params.insert(name.clone(), u(vec![("kind", s("unconstrained"))]));
            }
        }
        env.insert("params".into(), Value::Object(env_params));
        let mut r_auto: Vec<String> = vec![];
        let mut r_app: Vec<String> = vec![];
        for (r, v) in &res_seen {
            if r.starts_with('\u{0}') {
                continue;
            }
            if v.allow {
                r_auto.push(r.clone());
            }
            if v.escalate && !v.allow {
                r_app.push(r.clone());
            }
        }
        env.insert(
            "resources".into(),
            u(vec![("autonomous", Value::Array(sorted_units(r_auto))), ("withApproval", Value::Array(sorted_units(r_app))), ("other", Value::Bool(fresh_res))]),
        );
        let und = req_list(get(&rp, "undecidable"));
        if !und.is_empty() {
            env.insert("approximate".into(), Value::Bool(true));
            env.insert("reason".into(), s(&format!("over-approximated ({})", join(und, "; "))));
        }
        out.push(Value::Object(env));
    }
    Value::Array(out)
}
