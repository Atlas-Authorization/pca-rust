//! Quantitative and ternary static queries over a policy: the most that can ever be spent, the actions that need a human, the
//! reach of a delegation chain, a first-class diff of two policies, and the check of an external solver's answer.

use super::caveats::vetoes_from_constitution;
use super::enumerate::*;
use super::js::*;
use super::query::{bound, probes_for};
use serde_json::{Map, Value};
use std::collections::HashMap;

const HUGE: f64 = 9007199254740991.0;
const INF: f64 = f64::INFINITY;
const WIDEN: [&str; 3] = ["deny->allow", "deny->escalate", "escalate->allow"];

fn cond_thresholds(c: &Value, path: &str, into: &mut Vec<Value>) {
    let m = match obj(c) {
        Some(m) => m,
        None => return,
    };
    if is_group_map(m) {
        if let Some(xs) = m.get("all_of").and_then(Value::as_array) {
            for x in xs {
                cond_thresholds(x, path, into);
            }
        } else if let Some(xs) = m.get("any_of").and_then(Value::as_array) {
            for x in xs {
                cond_thresholds(x, path, into);
            }
        } else if let Some(n) = m.get("not") {
            cond_thresholds(n, path, into);
        }
        return;
    }
    let lf = match leaf(c) {
        Some(l) => l,
        None => return,
    };
    if mg(lf, "field").as_str() != Some(path) {
        return;
    }
    let v = mg(m, "value");
    if is_fin(v) {
        into.push(v.clone());
    } else if let Some(xs) = v.as_array() {
        for x in xs {
            if is_fin(x) {
                into.push(x.clone());
            }
        }
    }
}

/// Every numeric literal the policy compares `path` against, ascending and de-duplicated.
pub(crate) fn thresholds_of(model: &Value, path: &str) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    let empty = empty_arr();
    for p in probe_set(model) {
        for c in req_list(nn(get(&p, "where"), &empty)) {
            cond_thresholds(c, path, &mut out);
        }
    }
    for v in req_list(get(model, "vetoes")) {
        let over = get(v, "over");
        if truthy(over) && get(over, "path").as_str() == Some(path) && is_num(get(over, "threshold")) {
            out.push(get(over, "threshold").clone());
        }
    }
    let mut seen: Vec<(f64, Value)> = vec![];
    for x in out {
        let f = to_number(&x);
        if !seen.iter().any(|(k, _)| *k == f) {
            seen.push((f, x));
        }
    }
    seen.sort_by(|a, b| cmp_f64(a.0, b.0));
    seen.into_iter().map(|(_, v)| v).collect()
}

fn pinned(pr: &Probes, path: &str, value: Value, resource: &Value) -> Probes {
    let mut c = pr.clone();
    if !is_undef(resource) {
        c.resources = vec![resource.clone()];
    }
    c.fields = pr.fields.iter().filter(|f| f.path != path).cloned().collect();
    c.fields.push(ProbeField { path: path.to_string(), values: vec![value] });
    c
}

fn unbounded_peak() -> Value {
    u(vec![("admitted", Value::Bool(true)), ("max", num(INF)), ("attained", Value::Bool(false))])
}

/// The largest amount the policy admits (level "admit": anything but a deny; "allow": without a human). The flag is the grid overflow.
fn peak_at(model: &Value, o: &Value, level: &str) -> (Value, bool) {
    let default_field = s("amount");
    let fname = js(nn(own(o, "amountField"), &default_field));
    let path = format!("action.params.{fname}");
    let mx = bound(o);
    let mut base = probes_for(std::slice::from_ref(model), &Value::Null);
    base.verbs = vec![own(o, "verb").clone()];
    let t: Vec<f64> = thresholds_of(model, &path).iter().map(to_number).collect();
    let zero = num(0.0);
    let inf_v = num(INF);
    let lo = jmax(0.0, to_number(nn(own(o, "min"), &zero)));
    let hi = to_number(nn(own(o, "max"), &inf_v));
    let mut raw: Vec<f64> = vec![];
    for (i, tv) in t.iter().enumerate() {
        raw.push(tv - 1.0);
        raw.push(*tv);
        if i + 1 < t.len() {
            raw.push((tv + t[i + 1]) / 2.0);
        }
    }
    if let Some(last) = t.last() {
        raw.push(last + 1.0);
    } else {
        raw.push(0.0);
    }
    raw.push(HUGE);
    raw.push(lo);
    if hi.is_finite() {
        raw.push(hi);
    }
    let mut cands: Vec<f64> = vec![];
    for c in raw {
        if !cands.iter().any(|x| *x == c) && lo <= c && c <= hi && c.is_finite() {
            cands.push(c);
        }
    }
    sort_f64(&mut cands);
    cands.reverse();
    let resource = own(o, "resource");
    let holds_level = |d: &str| if level == "allow" { d == "allow" } else { d != "deny" };
    for c in cands {
        let pr = pinned(&base, &path, num(c), resource);
        let (hit, overflow) = search(&pr, &mut |rep: &Rep| holds_level(decide(model, rep)), mx);
        if overflow {
            return (u(vec![("admitted", Value::Bool(false)), ("max", num(0.0)), ("attained", Value::Bool(false))]), true);
        }
        let h = match hit {
            Some(h) => h,
            None => continue,
        };
        let act = |v: f64| -> Value {
            let mut a = match rep_to_action(&h) {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            let mut p = copy_map(a.get("params").unwrap_or(undef()));
            p.insert(fname.clone(), num(v));
            a.insert("params".into(), Value::Object(p));
            Value::Object(a)
        };
        let holds = |a: &Value| holds_level(decide_action(model, a));
        let top = t.last().copied().unwrap_or(f64::NEG_INFINITY);
        if c > top {
            if hi.is_finite() {
                let w = act(hi);
                let att = holds(&w);
                return (u(vec![("admitted", Value::Bool(true)), ("max", num(hi)), ("attained", Value::Bool(att)), ("witness", w)]), false);
            }
            return (u(vec![("admitted", Value::Bool(true)), ("max", num(INF)), ("attained", Value::Bool(false)), ("witness", act(HUGE))]), false);
        }
        if t.iter().any(|x| *x == c) {
            return (u(vec![("admitted", Value::Bool(true)), ("max", num(c)), ("attained", Value::Bool(true)), ("witness", act(c))]), false);
        }
        let nxt = t.iter().copied().find(|x| *x > c).unwrap_or(0.0);
        if own(o, "integer").as_bool() == Some(true) {
            let m = nxt.ceil() - 1.0;
            if m >= c {
                let w = act(m);
                if holds(&w) {
                    return (u(vec![("admitted", Value::Bool(true)), ("max", num(m)), ("attained", Value::Bool(true)), ("witness", w)]), false);
                }
            }
        }
        return (u(vec![("admitted", Value::Bool(true)), ("max", num(nxt)), ("attained", Value::Bool(false)), ("witness", act(c))]), false);
    }
    (u(vec![("admitted", Value::Bool(false)), ("max", num(0.0)), ("attained", Value::Bool(false))]), false)
}

fn universal(p: &Value, verb: &Value) -> bool {
    let pv = get(p, "verb");
    let mut verb_ok = strict_eq(pv, &s("*")) || strict_eq(pv, verb);
    if let (Some(l), false) = (pv.as_array(), verb_ok) {
        verb_ok = l.iter().any(|e| strict_eq(e, &s("*")) || strict_eq(e, verb));
    }
    let res = get(p, "resource");
    let where_ = get(p, "where");
    if where_.is_null() {
        fail("cannot read properties of null (reading 'length')");
    }
    let mut where_empty = is_undef(where_);
    if !where_empty {
        if let Some(l) = where_.as_array() {
            where_empty = l.is_empty();
        } else if let Some(t) = where_.as_str() {
            where_empty = t.is_empty();
        }
    }
    verb_ok && (is_undef(res) || strict_eq(res, &s("*"))) && where_empty
}

fn ceil_div(a: &Value, b: &Value) -> f64 {
    let q = to_number(a) / to_number(b);
    if q.is_infinite() || q.is_nan() {
        q
    } else {
        q.ceil()
    }
}

fn builtin_blast(verb: &Value) -> f64 {
    if let Some(v) = verb.as_str() {
        if let Some(r) = crate::catalog_risk::BUILTIN_CATALOG.iter().find(|r| r.0 == v) {
            return r.2;
        }
    }
    1.0
}

struct Limits {
    max_actions: f64,
    basis: Vec<Value>,
}

impl Limits {
    fn limit(&mut self, w: &Value, n: &Value, per_secs: &Value, why: String) {
        let mut k = INF;
        if !is_undef(w) {
            k = to_number(n) * ceil_div(w, per_secs);
        }
        if k < self.max_actions {
            self.max_actions = k;
            self.basis.push(s(&why));
        }
    }
}

fn window_bound(model: &Value, c: &Value, o: &Value, peak: &Value) -> Value {
    let w = own(o, "windowSecs");
    let default_field = s("amount");
    let path = format!("action.params.{}", js(nn(own(o, "amountField"), &default_field)));
    let per = if get(peak, "admitted").as_bool() == Some(true) { to_number(get(peak, "max")) } else { 0.0 };
    let mut lim = Limits { max_actions: INF, basis: vec![] };
    let mut not_applied: Vec<Value> = vec![];
    let mut caveats: Vec<Value> = req_list(get(model, "caveats")).clone();
    for m in req_list(get(model, "meets")) {
        caveats.extend(req_list(get(m, "caveats")).iter().cloned());
    }
    let invs: Vec<Value> = match own(c, "invariants").as_array() {
        Some(l) if is_obj(c) => l.clone(),
        _ => vec![],
    };
    for cv in &caveats {
        let (mx, ps) = (get(cv, "max"), get(cv, "per_secs"));
        if get(cv, "type").as_str() == Some("rate") && is_num(mx) && is_num(ps) && to_number(ps) > 0.0 {
            lim.limit(w, mx, ps, format!("rate caveat {}/{}s", num_str(to_number(mx)), num_str(to_number(ps))));
        }
    }
    for inv in &invs {
        if get(inv, "kind").as_str() != Some("rate") {
            continue;
        }
        if universal(get(inv, "when"), own(o, "verb")) {
            lim.limit(w, get(inv, "max"), get(inv, "window_secs"), format!("rate invariant {}", js(get(inv, "id"))));
        } else {
            not_applied.push(get(inv, "id").clone());
        }
    }
    let mut bnd: f64 = if per == 0.0 {
        0.0
    } else if lim.max_actions == INF {
        INF
    } else {
        per * lim.max_actions
    };
    if per.is_finite() && per > 0.0 {
        lim.basis.insert(0, s("per-action ceiling"));
    }
    for cv in &caveats {
        let l = get(cv, "limit");
        if get(cv, "type").as_str() != Some("budget_alloc") || !is_num(l) {
            continue;
        }
        let lim_f = to_number(l);
        let bm = own(o, "budgetModel");
        let kappa = own(o, "kappa");
        if bm.as_str() == Some("dollars") {
            if lim_f < bnd {
                bnd = lim_f;
                lim.basis.push(s(&format!("budget_alloc limit {}", num_str(lim_f))));
            }
        } else if bm.as_str() == Some("risk") && is_num(kappa) && to_number(kappa) > 0.0 {
            let r = own(o, "blastRadius");
            let rf = if is_undef(r) || r.is_null() { builtin_blast(own(o, "verb")) } else { to_number(r) };
            let cost = to_number(kappa) * jmin(1.0, jmax(0.0, rf));
            let n = if cost > 0.0 { (lim_f / cost).floor() } else { INF };
            if n < lim.max_actions {
                lim.max_actions = n;
                if n == 0.0 {
                    bnd = 0.0;
                } else if per.is_finite() && per > 0.0 {
                    bnd = per * n;
                }
                lim.basis.push(s(&format!("budget_alloc {} / cost {} = {} actions", num_str(lim_f), num_str(cost), num_str(n))));
            }
        } else {
            not_applied.push(s(&format!("budget_alloc {} (trust-budget units; pass budgetModel and kappa)", num_str(lim_f))));
        }
    }
    for inv in &invs {
        if get(inv, "kind").as_str() != Some("cap") {
            continue;
        }
        if !universal(get(inv, "when"), own(o, "verb")) || get(inv, "amount").as_str() != Some(path.as_str()) {
            not_applied.push(get(inv, "id").clone());
            continue;
        }
        let ws = get(inv, "window_secs");
        if !is_undef(ws) && is_undef(w) {
            continue; // a windowed cap says nothing about a lifetime total
        }
        let mut cap = to_number(get(inv, "max"));
        if !is_undef(ws) && !is_undef(w) {
            cap *= ceil_div(w, ws);
        }
        if cap < bnd {
            bnd = cap;
            lim.basis.push(s(&format!("cap invariant {}", js(get(inv, "id")))));
        }
    }
    let na: Vec<Value> = not_applied.into_iter().filter(|x| !is_undef(x)).collect();
    let mut out =
        u_map(vec![("maxActions", num(lim.max_actions)), ("bound", num(bnd)), ("basis", Value::Array(lim.basis.clone())), ("notApplied", Value::Array(na))]);
    if !is_undef(w) {
        out.insert("secs".into(), w.clone());
    }
    let pm = to_number(get(peak, "max"));
    let wit = own(peak, "witness");
    if !is_undef(wit) && get(peak, "admitted").as_bool() == Some(true) && !wit.is_null() && lim.max_actions.is_finite() && pm.is_finite() && pm > 0.0 {
        out.insert("sequence".into(), u(vec![("action", wit.clone()), ("repeat", num(lim.max_actions))]));
    }
    Value::Object(out)
}

fn approx_reason(overflow: bool, undecidable: &[Value]) -> String {
    if overflow {
        "representative grid exceeded the bound".to_string()
    } else {
        format!("over-approximated ({})", join(undecidable, "; "))
    }
}

/// The most that can ever leave under a policy: the largest single action, the largest autonomous action and the windowed total.
pub(crate) fn max_exposure(policy: &Value, given: &Value) -> Value {
    let mut o = copy_map(given);
    if is_undef(get(given, "budgetModel")) {
        let bm = get(policy, "budgetModel");
        if bm.as_str() == Some("dollars") || bm.as_str() == Some("risk") {
            o.insert("budgetModel".into(), bm.clone());
        }
    }
    if is_undef(get(given, "kappa")) {
        let rp = get(policy, "riskPolicy");
        let pk = if !is_undef(rp) && !rp.is_null() { get(rp, "kappa").clone() } else { undef_v() };
        if is_num(&pk) {
            o.insert("kappa".into(), pk);
        }
    }
    let ov = Value::Object(o);
    let c = own(&ov, "constitution").clone();
    let cv: Option<Value> = if !is_undef(&c) { Some(vetoes_from_constitution(&c)) } else { None };
    let base = to_model(policy);
    let mut model = base.clone();
    if let Some(cvv) = &cv {
        let mut vs: Vec<Value> = req_list(get(&base, "vetoes")).clone();
        vs.extend(req_list(get(cvv, "vetoes")).iter().cloned());
        if let Value::Object(m) = &mut model {
            m.insert("vetoes".into(), Value::Array(vs));
        }
    }
    let (admit, a_over) = peak_at(&model, &ov, "admit");
    let (auto, u_over) = peak_at(&model, &ov, "allow");
    let und = req_list(get(&model, "undecidable")).clone();
    let approximate = a_over || u_over || !und.is_empty();
    let ap = if a_over { unbounded_peak() } else { admit };
    let up = if u_over { unbounded_peak() } else { auto };
    let mut unmodeled: Vec<Value> = vec![];
    if let Some(cvv) = &cv {
        for um in req_list(get(cvv, "unmodeled")) {
            let k = get(um, "kind").as_str();
            if k != Some("cap") && k != Some("rate") {
                unmodeled.push(s(&format!("{}: {}", js(own(um, "id")), js(get(um, "reason")))));
            }
        }
    }
    let default_field = s("amount");
    let mut e = u_map(vec![
        ("verb", own(&ov, "verb").clone()),
        ("amountField", nn(own(&ov, "amountField"), &default_field).clone()),
        ("perAction", ap.clone()),
        ("autonomousPerAction", up.clone()),
        ("window", window_bound(&model, &c, &ov, &ap)),
        ("autonomousWindow", window_bound(&model, &c, &ov, &up)),
        ("unmodeled", Value::Array(unmodeled)),
    ]);
    if approximate {
        e.insert("approximate".into(), Value::Bool(true));
        let reason =
            if !a_over && !u_over { approx_reason(false, &und) } else { "representative grid exceeded the bound; exposure reported as unbounded".to_string() };
        e.insert("reason".into(), s(&reason));
    }
    Value::Object(e)
}

fn with_verbs(pr: &Probes, verbs: Vec<Value>) -> Probes {
    let mut c = pr.clone();
    c.verbs = verbs;
    c
}

/// The set of actions admitted only with a human: `{escalates, witnesses, approximate?, reason?}`.
pub(crate) fn escalation_surface(policy: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let opts = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let model = to_model(policy);
    let mut base = probes_for(std::slice::from_ref(&model), &Value::Null);
    let verb = get(opts, "verb");
    if !is_undef(verb) {
        base.verbs = vec![verb.clone()];
    }
    let eight = num(8.0);
    let lim = jmax(0.0, jmin(to_number(nn(get(opts, "limit"), &eight)), 1_073_741_824.0));
    let limit = if lim.is_nan() { 0 } else { lim as usize };
    let (hits, overflow) = collect(&base, &mut |r: &Rep| decide(&model, r) == "escalate", bound(opts), limit);
    let mut witnesses: Vec<Value> = vec![];
    for h in &hits {
        let a = rep_to_action(h);
        if decide_action(&model, &a) == "escalate" {
            witnesses.push(a);
        }
    }
    let und = req_list(get(&model, "undecidable"));
    let mut out = u_map(vec![("escalates", Value::Bool(!witnesses.is_empty())), ("witnesses", Value::Array(witnesses))]);
    if overflow || !und.is_empty() {
        out.insert("approximate".into(), Value::Bool(true));
        out.insert("reason".into(), s(&approx_reason(overflow, und)));
    }
    Value::Object(out)
}

/// The join of everything any holder of the leaf could do, with the remaining delegation depth.
pub(crate) fn delegation_envelope(chain_in: &Value, opts: &Value) -> Value {
    let chain = req_list(chain_in);
    let leaf_v: Value = chain.last().cloned().unwrap_or_else(undef_v);
    let init: Vec<Value> = if chain.is_empty() { vec![] } else { chain[..chain.len() - 1].to_vec() };
    let policy: Value = if is_obj(&leaf_v) {
        let extra = own(&leaf_v, "meet");
        let mut ex: Vec<Value> = vec![];
        if truthy(extra) {
            match extra.as_array() {
                Some(l) => ex = l.clone(),
                None => fail("meet is not iterable"),
            }
        }
        let mut p = copy_map(&leaf_v);
        let mut meet = init.clone();
        meet.extend(ex);
        p.insert("meet".into(), Value::Array(meet));
        Value::Object(p)
    } else if leaf_v.is_array() {
        u(vec![("meet", Value::Array(init.clone()))])
    } else {
        u(vec![("predicates", empty_arr())])
    };
    let model = to_model(&policy);
    let base = probes_for(std::slice::from_ref(&model), &Value::Null);
    let mx = bound(opts);
    let mut verbs: Vec<Value> = vec![];
    let mut any_verb = false;
    let mut overflow = false;
    for verb in &base.verbs {
        let (hits, ov) = collect(&with_verbs(&base, vec![verb.clone()]), &mut |r: &Rep| decide(&model, r) != "deny", mx, 1);
        if ov {
            overflow = true;
            break;
        }
        if hits.is_empty() {
            continue;
        }
        let hit = &hits[0];
        if verb.as_str().is_some_and(|t| t.starts_with('\u{0}')) {
            any_verb = true;
        } else {
            verbs.push(u(vec![("verb", verb.clone()), ("witness", rep_to_action(hit)), ("autonomous", Value::Bool(decide(&model, hit) == "allow"))]));
        }
    }
    let mut violations: Vec<Value> = vec![];
    for i in 0..chain.len().saturating_sub(1) {
        let a = to_model(&chain[i]);
        let b = to_model(&chain[i + 1]);
        let pr = probes_for(&[a.clone(), b.clone()], &Value::Null);
        let (hit, ov) = search(&pr, &mut |r: &Rep| decide(&b, r) != "deny" && decide(&a, r) == "deny", mx);
        if hit.is_some() || ov {
            violations.push(num((i + 1) as f64));
        }
    }
    let mut depths: Vec<f64> = vec![];
    for p in chain {
        if let Some(cvs) = obj(p).and_then(|m| m.get("caveats")).and_then(Value::as_array) {
            for c in cvs {
                if get(c, "type").as_str() == Some("delegation_depth") && is_num(get(c, "max")) {
                    depths.push(to_number(get(c, "max")));
                }
            }
        }
    }
    let used = jmax(0.0, chain.len() as f64 - 1.0);
    let mut depth = u_map(vec![("used", num(used))]);
    if !depths.is_empty() {
        let mut allowed = depths[0];
        for d in &depths[1..] {
            if *d < allowed {
                allowed = *d;
            }
        }
        depth.insert("allowed".into(), num(allowed));
        depth.insert("remaining".into(), num(jmax(0.0, allowed - used)));
    }
    let mut out = u_map(vec![
        ("violations", Value::Array(violations)),
        ("verbs", Value::Array(verbs)),
        ("anyVerb", Value::Bool(any_verb)),
        ("depth", Value::Object(depth)),
    ]);
    let und = req_list(get(&model, "undecidable"));
    if overflow || !und.is_empty() {
        out.insert("approximate".into(), Value::Bool(true));
        out.insert("reason".into(), s(&approx_reason(overflow, und)));
    }
    Value::Object(out)
}

fn is_widen(k: &str) -> bool {
    WIDEN.contains(&k)
}

fn sub(x: f64, y: f64) -> f64 {
    if x == y {
        0.0
    } else {
        x - y
    }
}

fn num_field(m: &Value, k: &str) -> f64 {
    to_number(get(m, k))
}

/// `diff(A, B)`: which actions move between allow / escalate / deny, with witnesses, and optionally how the max exposure moved.
pub(crate) fn diff_policies(a: &Value, b: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let o = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let ma = to_model(a);
    let mb = to_model(b);
    let pr = probes_for(&[ma.clone(), mb.clone()], &Value::Null);
    let four = num(4.0);
    let limit = to_number(nn(get(o, "limit"), &four));
    let mut shifts: HashMap<String, Vec<Value>> = HashMap::new();
    let mut kinds: Vec<String> = vec![];
    let mut counts: HashMap<String, f64> = HashMap::new();
    let (_, walk_over) = collect(
        &pr,
        &mut |rep: &Rep| {
            let (x, y) = (decide(&ma, rep), decide(&mb, rep));
            if x == y {
                return false;
            }
            let k = format!("{x}->{y}");
            let n = counts.get(&k).copied().unwrap_or(0.0);
            counts.insert(k.clone(), n + 1.0);
            if n < limit {
                if !shifts.contains_key(&k) {
                    kinds.push(k.clone());
                }
                shifts.entry(k).or_default().push(rep_to_action(rep));
            }
            false
        },
        bound(o),
        1,
    );
    let (mut widens, mut narrows) = (false, false);
    for k in &kinds {
        if is_widen(k) {
            widens = true;
        } else {
            narrows = true;
        }
    }
    let mut summary: Vec<Value> = vec![];
    let mut shifts_out = Map::new();
    for k in &kinds {
        let list = &shifts[k];
        let first = &list[0];
        let eo = empty_obj();
        let params = nn(own(first, "params"), &eo);
        summary.push(s(&format!("{k}: {}+ action(s), e.g. {} {} {}", list.len(), js(own(first, "verb")), js(own(first, "resource")), json_str(params))));
        shifts_out.insert(k.clone(), Value::Array(list.clone()));
    }
    let ua = req_list(get(&ma, "undecidable")).clone();
    let ub = req_list(get(&mb, "undecidable")).clone();
    let mut d = u_map(vec![
        ("equivalent", Value::Bool(kinds.is_empty() && !walk_over && ua.is_empty() && ub.is_empty())),
        ("shifts", Value::Object(shifts_out)),
        ("widens", Value::Bool(widens)),
        ("narrows", Value::Bool(narrows)),
    ]);
    let ex = get(o, "exposure");
    if !is_undef(ex) {
        let before = max_exposure(a, ex);
        let after = max_exposure(b, ex);
        let pa = sub(num_field(get(&after, "perAction"), "max"), num_field(get(&before, "perAction"), "max"));
        let au = sub(num_field(get(&after, "autonomousWindow"), "bound"), num_field(get(&before, "autonomousWindow"), "bound"));
        let dl = sub(num_field(get(&after, "window"), "bound"), num_field(get(&before, "window"), "bound"));
        let e = u(vec![("before", before.clone()), ("after", after.clone()), ("perActionDelta", num(pa)), ("autonomousDelta", num(au)), ("delta", num(dl))]);
        d.insert("exposure".into(), e);
        let worst = jmax(dl, jmax(pa, au));
        let best = jmin(dl, pa);
        let verb = js(get(ex, "verb"));
        if worst > 0.0 {
            summary.push(s(&format!("max exposure of {verb} rises by {}", num_str(worst))));
        } else if best < 0.0 {
            summary.push(s(&format!("max exposure of {verb} falls by {}", num_str(-best))));
        }
    }
    d.insert("summary".into(), Value::Array(summary));
    if walk_over || !ua.is_empty() || !ub.is_empty() {
        d.insert("approximate".into(), Value::Bool(true));
        let mut seen = OrdSet::default();
        for r in ua.iter().chain(ub.iter()) {
            seen.add(r.as_str().unwrap_or(""));
        }
        let reason = if walk_over { "representative grid exceeded the bound".to_string() } else { format!("over-approximated ({})", seen.keys.join("; ")) };
        d.insert("reason".into(), s(&reason));
    }
    Value::Object(d)
}

/// A CI gate over a diff: it fails when the change widens authority beyond what the reviewer allowed.
pub(crate) fn diff_gate(d: &Value, allow_in: &Value) -> Value {
    let empty = empty_obj();
    let allow = if allow_in.is_null() || is_undef(allow_in) { &empty } else { allow_in };
    let mut reasons: Vec<Value> = vec![];
    if get(d, "widens").as_bool() == Some(true) && get(allow, "widen").as_bool() != Some(true) {
        let summary = match get(d, "summary").as_array() {
            Some(l) => l,
            None => fail("d.summary is not iterable"),
        };
        let ws: Vec<String> = summary.iter().map(js).filter(|t| WIDEN.iter().any(|w| t.starts_with(w))).collect();
        reasons.push(s(&format!("widens authority: {}", ws.join("; "))));
    }
    let mut rise = 0.0;
    let ex = get(d, "exposure");
    if truthy(ex) {
        rise = jmax(to_number(get(ex, "delta")), jmax(to_number(get(ex, "perActionDelta")), to_number(get(ex, "autonomousDelta"))));
    }
    let zero = num(0.0);
    if rise > to_number(nn(get(allow, "maxExposureIncrease"), &zero)) {
        reasons.push(s(&format!("max exposure rises by {}", num_str(rise))));
    }
    if truthy(get(d, "approximate")) {
        let dflt = s("approximate");
        reasons.push(s(&format!("inconclusive: {}", js(nn(get(d, "reason"), &dflt)))));
    }
    u(vec![("ok", Value::Bool(reasons.is_empty())), ("reasons", Value::Array(reasons))])
}

/// Checks what an optional external solver returned: a witness is re-checked by the real evaluator (never trusted); an unsat claim
/// is returned labelled as solver-claimed.
pub(crate) fn find_with_backend(q: &Value, name: &Value, result: &Value) -> Value {
    let w = get(result, "witness");
    if !is_undef(w) {
        let ma = to_model(get(q, "a"));
        let qb = get(q, "b");
        let qv = get(q, "verb");
        let ok = if get(q, "kind").as_str() == Some("reachable") {
            decide_action(&ma, w) != "deny" && (is_undef(qv) || strict_eq(get(w, "verb"), qv))
        } else {
            !is_undef(qb) && ((decide_action(&ma, w) != "deny") != (decide_action(&to_model(qb), w) != "deny"))
        };
        return if ok { u(vec![("witness", w.clone())]) } else { u(vec![("rejected", Value::Bool(true))]) };
    }
    if get(result, "unsat").as_bool() == Some(true) {
        return u(vec![("claimedUnsat", u(vec![("by", name.clone()), ("proof", s("solver-claimed, not machine-checked"))]))]);
    }
    empty_obj()
}
