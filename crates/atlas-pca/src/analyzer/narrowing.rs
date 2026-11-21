//! Least privilege from observed behaviour: propose a narrower grant from what its holder really did (proven subsumed by the original,
//! never applied), unused-permission findings, and signed access requests.

use super::enumerate::to_model;
use super::exposure::diff_policies;
use super::js::*;
use super::query::{admits_concrete, subsumes};
use super::residual::policy_digest_of;
use crate::agent::KeyPair;
use crate::predicates::{predicate_matches, Ctx};
use serde_json::{Map, Value};
use std::collections::HashMap;

const ACCESS_REQUEST_SIG_DOMAIN: &str = "atlas-pca/access-request/v1\u{0}";

fn rev_weight(r: &Value) -> f64 {
    match r.as_str() {
        Some(t) => REV_ORDER.iter().position(|x| *x == t).map_or(0.0, |i| (i + 1) as f64),
        None => 0.0,
    }
}

/// The spec of a catalogued verb, else the fail-closed spec (irreversible, maximum blast radius).
fn resolve_action(catalog: &Value, verb: &Value) -> Value {
    let v = js(verb);
    if catalog.is_null() || is_undef(catalog) {
        if let Some(a) = crate::catalog_risk::BUILTIN_CATALOG.iter().find(|a| a.0 == v) {
            return u(vec![("blastRadius", num(a.2)), ("reversibility", s(a.1))]);
        }
    } else if let Some(m) = obj(catalog) {
        if let Some(sp) = m.get(&v) {
            if is_obj(sp) {
                return sp.clone();
            }
        }
    } else if let Some(l) = catalog.as_array() {
        let mut found: Option<&Value> = None;
        for a in l {
            if is_obj(a) && own(a, "verb").as_str() == Some(v.as_str()) {
                found = Some(a);
            }
        }
        if let Some(f) = found {
            return f.clone();
        }
    }
    u(vec![("blastRadius", num(1.0)), ("reversibility", s("irreversible"))])
}

fn common_prefix(rs: &[String]) -> String {
    let mut p: Vec<char> = if rs.is_empty() { vec![] } else { rs[0].chars().collect() };
    for r in rs {
        let rr: Vec<char> = r.chars().collect();
        let mut i = 0;
        while i < p.len() && i < rr.len() && p[i] == rr[i] {
            i += 1;
        }
        p.truncate(i);
    }
    let t: String = p.into_iter().collect();
    match t.rfind('/') {
        Some(cut) => t[..cut + 1].to_string(),
        None => String::new(),
    }
}

fn is_integer_num(v: &Value) -> bool {
    let f = to_number(v);
    is_num(v) && f.is_finite() && f == f.trunc()
}

fn upper_bound_of(where_: &Value, path: &str) -> f64 {
    let mut ub = f64::INFINITY;
    let empty = empty_arr();
    for c in req_list(nn(where_, &empty)) {
        let m = match obj(c) {
            Some(m) => m,
            None => continue,
        };
        if m.get("field").and_then(Value::as_str) != Some(path) {
            continue;
        }
        let op = mg(m, "op").as_str().unwrap_or("");
        if (op == "lte" || op == "lt") && is_num(mg(m, "value")) {
            ub = jmin(ub, to_number(&m["value"]));
        }
    }
    ub
}

fn narrow_ctx(a: &Value) -> Value {
    let mut act = Map::new();
    let v = get(a, "verb");
    if !is_undef(v) {
        act.insert("verb".into(), v.clone());
    }
    let v = get(a, "resource");
    if !is_undef(v) {
        act.insert("resource".into(), v.clone());
    }
    let params = get(a, "params");
    act.insert("params".into(), if is_undef(params) || params.is_null() { empty_obj() } else { params.clone() });
    let mut out = Map::new();
    out.insert("action".into(), Value::Object(act));
    Value::Object(out)
}

fn narrow_matches(p: &Value, a: &Value) -> bool {
    let ctx = narrow_ctx(a);
    predicate_matches(p, &Ctx::new(&ctx))
}

fn params_of(a: &Value) -> Value {
    nn(get(a, "params"), &empty_obj()).clone()
}

fn sort_strs(set: Vec<String>) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<String> = vec![];
    for t in set {
        if seen.insert(t.clone()) {
            out.push(t);
        }
    }
    stable_sort_by_less(&mut out, &|a, b| unit_less(a, b));
    out
}

fn strs_to_any(xs: &[String]) -> Vec<Value> {
    xs.iter().map(|x| s(x)).collect()
}

fn finding(kind: &str, i: usize, spec: &Value) -> Map<String, Value> {
    let br = to_number(&nil_if_undef(own(spec, "blastRadius")));
    u_map(vec![
        ("kind", s(kind)),
        ("predicate", num(i as f64)),
        ("blastRadius", num(br)),
        ("reversibility", own(spec, "reversibility").clone()),
        ("rank", num(br * rev_weight(own(spec, "reversibility")))),
    ])
}

fn build(narrow: bool, base: &[Value], trusted: &[Value], margin: f64, min_samples: f64, enum_limit: f64) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    let empty = empty_arr();
    for p in base {
        let hits: Vec<&Value> = trusted.iter().filter(|a| narrow_matches(p, a)).collect();
        if hits.is_empty() {
            continue;
        }
        let mut vs: Vec<String> = vec![];
        let mut rs: Vec<String> = vec![];
        for h in &hits {
            vs.push(req_str(get(h, "verb"), "verb").to_string());
            rs.push(req_str(get(h, "resource"), "resource").to_string());
        }
        let verbs = sort_strs(vs);
        let resources = sort_strs(rs);
        let mut nxt = Map::new();
        if verbs.len() == 1 {
            nxt.insert("verb".into(), s(&verbs[0]));
        } else {
            nxt.insert("verb".into(), Value::Array(strs_to_any(&verbs)));
        }
        let pres = get(p, "resource");
        if narrow {
            if resources.len() == 1 {
                nxt.insert("resource".into(), s(&resources[0]));
            } else {
                let pre = common_prefix(&resources);
                if pre.chars().count() > 1 {
                    nxt.insert("resource".into(), s(&format!("{pre}*")));
                } else if !is_undef(pres) {
                    nxt.insert("resource".into(), pres.clone());
                }
            }
        } else if !is_undef(pres) {
            nxt.insert("resource".into(), pres.clone());
        }
        let mut where_: Vec<Value> = req_list(nn(get(p, "where"), &empty)).clone();
        let mut names: Vec<String> = vec![];
        for h in &hits {
            names.extend(spread(&params_of(h)).keys().cloned());
        }
        for name in sort_strs(names) {
            let path = format!("action.params.{name}");
            let mut vals: Vec<Value> = vec![];
            let mut missing = false;
            for h in &hits {
                let v = own(&params_of(h), &name).clone();
                if is_undef(&v) {
                    missing = true;
                }
                vals.push(v);
            }
            if (vals.len() as f64) < min_samples || missing {
                continue;
            }
            let (mut all_num, mut all_str, mut all_int) = (true, true, true);
            let mut mx = f64::NEG_INFINITY;
            for v in &vals {
                match fin(v) {
                    None => all_num = false,
                    Some(f) => mx = jmax(mx, f),
                }
                if !v.is_string() {
                    all_str = false;
                }
                if !is_integer_num(v) {
                    all_int = false;
                }
            }
            if all_num {
                let v = mx * (1.0 + margin);
                let ceil = if all_int { v.ceil() } else { v };
                if ceil < upper_bound_of(get(p, "where"), &path) {
                    where_.push(u(vec![("field", s(&path)), ("op", s("lte")), ("value", num(ceil))]));
                }
            } else if all_str {
                let ss: Vec<String> = vals.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect();
                let st = sort_strs(ss);
                if (st.len() as f64) <= enum_limit {
                    where_.push(u(vec![("field", s(&path)), ("op", s("in")), ("value", Value::Array(strs_to_any(&st)))]));
                }
            }
        }
        if !where_.is_empty() {
            nxt.insert("where".into(), Value::Array(where_));
        }
        out.push(Value::Object(nxt));
    }
    out
}

/// Proposes a narrower replacement for `policy` from the ledger-sourced `observed` actions, plus unused-permission findings and access
/// requests for refused attempts. Never applies anything.
pub(crate) fn suggest_narrowing(policy: &Value, observed_in: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let o = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let d1 = num(0.1);
    let d5 = num(5.0);
    let d8 = num(8.0);
    let margin = to_number(nn(get(o, "margin"), &d1));
    let min_samples = to_number(nn(get(o, "minSamples"), &d5));
    let enum_limit = to_number(nn(get(o, "enumLimit"), &d8));
    let catalog = get(o, "catalog");
    let model = to_model(policy);
    let digest = policy_digest_of(&model);
    let observed = req_list(observed_in);

    let mut trusted: Vec<Value> = vec![];
    let mut refused: Vec<Value> = vec![];
    let mut rejected = 0usize;
    for x in observed {
        let (src, out) = (get(x, "source"), get(x, "outcome"));
        let ledger = src.as_str() == Some("ledger");
        if ledger && out.as_str() != Some("denied") {
            trusted.push(x.clone());
        }
        if !ledger {
            rejected += 1;
        }
        if ledger && out.as_str() == Some("denied") {
            refused.push(x.clone());
        }
    }
    let mut findings: Vec<Value> = vec![];
    let base: Vec<Value> = get(policy, "predicates").as_array().cloned().unwrap_or_default();

    for (i, p) in base.iter().enumerate() {
        let hit = trusted.iter().any(|a| narrow_matches(p, a));
        let pv = get(p, "verb");
        let verbs: Vec<Value> = if pv.is_string() { vec![pv.clone()] } else { pv.as_array().cloned().unwrap_or_default() };
        if !hit {
            let v: Value = if !verbs.is_empty() && !verbs[0].is_null() { verbs[0].clone() } else { s("*") };
            let name = if v.as_str() == Some("*") { s("unknown.any") } else { v.clone() };
            let mut f = finding("unused-predicate", i, &resolve_action(catalog, &name));
            f.insert("verb".into(), v);
            let jsv: Vec<String> = verbs.iter().map(|x| if x.is_null() { String::new() } else { js(x) }).collect();
            let mut joined = jsv.join(", ");
            if joined.is_empty() {
                joined = "*".to_string();
            }
            f.insert("detail".into(), s(&format!("no observed action used predicate {i} ({joined})")));
            findings.push(Value::Object(f));
            continue;
        }
        for v in &verbs {
            if v.as_str() == Some("*") {
                continue;
            }
            let used = trusted.iter().any(|a| strict_eq(get(a, "verb"), v) && narrow_matches(p, a));
            if !used {
                let mut f = finding("unused-verb", i, &resolve_action(catalog, v));
                f.insert("verb".into(), v.clone());
                f.insert("detail".into(), s(&format!("verb {} is granted by predicate {i} but never used", js(v))));
                findings.push(Value::Object(f));
            }
        }
        for c in req_list(nn(get(p, "where"), &empty_arr())) {
            let cm = match obj(c) {
                Some(m) => m,
                None => continue,
            };
            let field = mg(cm, "field").as_str();
            let op = mg(cm, "op").as_str().unwrap_or("");
            let field = match field {
                Some(f) if (op == "lte" || op == "lt") && is_num(mg(cm, "value")) && f.starts_with("action.params.") => f,
                _ => continue,
            };
            let name = &field["action.params.".len()..];
            let mut vals: Vec<f64> = vec![];
            for a in &trusted {
                if narrow_matches(p, a) {
                    let x = own(&params_of(a), name).clone();
                    if is_num(&x) {
                        vals.push(to_number(&x));
                    }
                }
            }
            if (vals.len() as f64) < min_samples {
                continue;
            }
            if vals.is_empty() {
                fail("max() of an empty sequence");
            }
            let mut top = vals[0];
            for x in &vals {
                top = jmax(top, *x);
            }
            let capv = to_number(&cm["value"]);
            if top < capv / 2.0 {
                let v0: Value = verbs.first().cloned().unwrap_or_else(undef_v);
                let rv: Value = if !is_undef(&v0) && !v0.is_null() { v0.clone() } else { s("unknown.any") };
                let mut f = finding("unreached-cap", i, &resolve_action(catalog, &rv));
                if truthy(&v0) {
                    f.insert("verb".into(), v0.clone());
                }
                f.insert("detail".into(), s(&format!("{name} <= {} but the largest observed value is {}", num_str(capv), num_str(top))));
                findings.push(Value::Object(f));
            }
        }
    }
    stable_sort_by_less(&mut findings, &|a, b| {
        let (ra, rb) = (to_number(own(a, "rank")), to_number(own(b, "rank")));
        if ra != rb {
            return ra > rb;
        }
        to_number(own(a, "predicate")) < to_number(own(b, "predicate"))
    });

    let mut group_order: Vec<Map<String, Value>> = vec![];
    let mut groups: HashMap<String, usize> = HashMap::new();
    for a in &refused {
        let k = format!("{}\u{0}{}", js(get(a, "verb")), js(get(a, "resource")));
        if let Some(i) = groups.get(&k) {
            let c = to_number(&group_order[*i]["denied_count"]) + 1.0;
            group_order[*i].insert("denied_count".into(), num(c));
            continue;
        }
        let mut r = u_map(vec![
            ("v", num(1.0)),
            ("kind", s("pca-access-request")),
            ("verb", get(a, "verb").clone()),
            ("resource", get(a, "resource").clone()),
            ("example_params", Value::Object(spread(&params_of(a)))),
            ("denied_count", num(1.0)),
            ("policy_digest", s(&digest)),
        ]);
        let tb = get(o, "taskBinding");
        if truthy(tb) {
            r.insert("task_binding".into(), tb.clone());
        }
        groups.insert(k, group_order.len());
        group_order.push(r);
    }
    stable_sort_by_less(&mut group_order, &|a, b| {
        let (ca, cb) = (to_number(&a["denied_count"]), to_number(&b["denied_count"]));
        if ca != cb {
            return ca > cb;
        }
        unit_less(req_str(mg(a, "verb"), "verb"), req_str(mg(b, "verb"), "verb"))
    });
    let access_requests: Vec<Value> = group_order.into_iter().map(Value::Object).collect();

    let mut res = u_map(vec![
        ("used", num(trusted.len() as f64)),
        ("rejected", num(rejected as f64)),
        ("denied", num(refused.len() as f64)),
        ("coversObserved", Value::Bool(false)),
        ("findings", Value::Array(findings)),
        ("accessRequests", Value::Array(access_requests)),
    ]);
    let tb = get(o, "taskBinding");
    if truthy(tb) {
        res.insert("taskBinding".into(), tb.clone());
    }
    let mut caveats: Vec<Value> = vec![];
    if let Some(cv) = get(&model, "caveats").as_array() {
        caveats.extend(cv.iter().cloned());
    }
    let decay = get(o, "decay");
    if truthy(decay) {
        caveats.push(u(vec![("type", s("expires")), ("at", num(to_number(get(decay, "nowSec")) + to_number(get(decay, "expiresInSecs"))))]));
    }
    for narrow in [true, false] {
        let preds = build(narrow, &base, &trusted, margin, min_samples, enum_limit);
        if preds.is_empty() {
            res.insert("reason".into(), s("no ledger observation matches any predicate"));
            return Value::Object(res);
        }
        let proposal = u(vec![
            ("predicates", Value::Array(preds)),
            ("caveats", Value::Array(caveats.clone())),
            ("vetoes", get(&model, "vetoes").clone()),
            ("tighten", get(&model, "tighten").clone()),
        ]);
        let proof = subsumes(policy, &proposal, &Value::Null);
        if own(&proof, "subsumes").as_bool() != Some(true) || own(&proof, "approximate").as_bool() == Some(true) {
            if has(&proof, "reason") {
                res.insert("reason".into(), own(&proof, "reason").clone());
            } else {
                res.insert("reason".into(), s("the proposal could not be proven narrower than the original"));
            }
            continue;
        }
        res.remove("reason");
        res.insert("proposal".into(), proposal.clone());
        let mut covers = true;
        for a in &trusted {
            let act = u(vec![("verb", get(a, "verb").clone()), ("resource", get(a, "resource").clone()), ("params", params_of(a))]);
            if !admits_concrete(&proposal, &act) {
                covers = false;
                break;
            }
        }
        res.insert("coversObserved".into(), Value::Bool(covers));
        res.insert("diff".into(), diff_policies(policy, &proposal, &Value::Null));
        return Value::Object(res);
    }
    Value::Object(res)
}

// ---- access requests ----------------------------------------------------------------------------------------------------------

fn request_message(r: &Value) -> Vec<u8> {
    let h = match crate::hash_canonical_strict(r) {
        Some(h) => h,
        None => fail("request hash: not canonicalisable"),
    };
    let mut m = ACCESS_REQUEST_SIG_DOMAIN.as_bytes().to_vec();
    m.extend(crate::sha(h.as_bytes()));
    m
}

/// The holder's signed ask (a request for a human to read; nothing here turns it into authority).
pub(crate) fn sign_access_request(r: &Value, kp: &KeyPair) -> Value {
    u(vec![("request", r.clone()), ("signer", s(&kp.public)), ("sig", s(&crate::b64_encode(&kp.sign(&request_message(r)))))])
}

/// Verifies a signed access request, optionally against an expected signer public key; any failure is false.
pub(crate) fn verify_access_request(sv: &Value, expected: &Value) -> bool {
    try_js(|| {
        if !is_obj(sv) {
            return false;
        }
        let req = own(sv, "request");
        if !is_obj(req) || own(req, "kind").as_str() != Some("pca-access-request") || !strict_eq(own(req, "v"), &num(1.0)) {
            return false;
        }
        if !expected.is_null() && !is_undef(expected) && !strict_eq(own(sv, "signer"), expected) {
            return false;
        }
        let sig = match own(sv, "sig").as_str() {
            Some(t) => t,
            None => return false,
        };
        let signer = own(sv, "signer").as_str().unwrap_or("");
        let pk = crate::decode_b64u_strict(signer, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let sg = crate::decode_b64u_strict(sig, Some(64)).and_then(|b| <[u8; 64]>::try_from(b).ok());
        match (pk, sg) {
            (Some(pk), Some(sg)) => crate::verify_ed25519_strict(&pk, &request_message(req), &sg),
            _ => false,
        }
    })
    .unwrap_or(false)
}
