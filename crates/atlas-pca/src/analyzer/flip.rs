//! Minimal-change counterfactual search on a deny or escalate: "what is the smallest thing the agent can change to be allowed?" as a
//! typed patch it can apply, ordered by cost. The search proposes; the real decision verifies: every candidate is re-run through the
//! evaluator and only one that reaches the wanted decision is returned.

use super::enumerate::*;
use super::exposure::thresholds_of;
use super::js::*;
use super::residual::policy_digest_of;
use serde_json::{Map, Value};

fn rank_of(d: &str) -> f64 {
    match d {
        "deny" => 0.0,
        "escalate" => 1.0,
        "allow" => 2.0,
        _ => f64::NAN,
    }
}

struct Cand {
    repair: Value,
    cost: f64,
    decision: &'static str,
    action: Value,
}

impl Cand {
    fn to_json(&self) -> Value {
        u(vec![("repair", self.repair.clone()), ("cost", num(self.cost)), ("decision", s(self.decision)), ("action", self.action.clone())])
    }
}

/// `envelopeCaveatEvaluator` of one caveat at a context (a throw is false).
fn envelope_one(cv: &Value, ctx: &Value) -> bool {
    try_js(|| {
        if !(is_obj(cv) || cv.is_array()) || !(is_obj(ctx) || ctx.is_array()) {
            return false;
        }
        let now = match fin(get(ctx, "now")) {
            Some(n) => n,
            None => return false,
        };
        let c = get(cv, "type").as_str().unwrap_or("\u{0}");
        match c {
            "expires" => fin(get(cv, "at")).is_some_and(|at| now < at),
            "not_before" => fin(get(cv, "at")).is_some_and(|at| now >= at),
            "rate" => {
                let (max, per) = match (fin(get(cv, "max")), fin(get(cv, "per_secs"))) {
                    (Some(m), Some(p)) if p > 0.0 => (m, p),
                    _ => return false,
                };
                let times = match get(ctx, "recentActionTimes").as_array() {
                    Some(t) => t,
                    None => return false,
                };
                let lo = now - per * 1000.0;
                let n = times.iter().filter_map(fin).filter(|t| *t > lo && *t <= now).count();
                (n as f64) < max
            }
            "max_blast_radius" => match (fin(get(cv, "max")), fin(get(ctx, "blastRadius"))) {
                (Some(m), Some(b)) => b <= m,
                _ => false,
            },
            "reversibility_max" => match (get(cv, "class").as_str(), get(ctx, "reversibilityClass").as_str()) {
                (Some(l), Some(c)) => match (REV_ORDER.iter().position(|r| *r == l), REV_ORDER.iter().position(|r| *r == c)) {
                    (Some(l), Some(c)) => c <= l,
                    _ => false,
                },
                _ => false,
            },
            "delegation_depth" => match (fin(get(cv, "max")), fin(get(ctx, "delegationDepth"))) {
                (Some(m), Some(d)) => d <= m,
                _ => false,
            },
            "budget_alloc" => fin(get(cv, "limit")).is_some_and(|l| l >= 0.0),
            "intent_session" => crate::intent_session::intent_session_caveat_error(Some(cv)).is_none(),
            _ => false,
        }
    })
    .unwrap_or(false)
}

/// `evaluateCaveats(caveats, ctx).ok`.
fn caveats_ok(caveats: &Value, ctx: &Value) -> bool {
    match caveats.as_array() {
        Some(l) => l.iter().all(|c| envelope_one(c, ctx)),
        None => false,
    }
}

fn wait_time(caveats: &Value, ctx: &Value) -> Option<f64> {
    let mut at: Option<f64> = None;
    for c in req_list(caveats) {
        let ty = get(c, "type").as_str().unwrap_or("");
        let now = get(ctx, "now");
        if ty == "not_before" && is_num(get(c, "at")) && gt(get(c, "at"), now) {
            at = Some(jmax(at.unwrap_or(0.0), to_number(get(c, "at"))));
        }
        if ty == "rate" && is_num(get(c, "max")) && is_num(get(c, "per_secs")) {
            let span = to_number(get(c, "per_secs")) * 1000.0;
            let empty = empty_arr();
            let lo = num(to_number(now) - span);
            let mut recent: Vec<Value> = req_list(nn(get(ctx, "recentActionTimes"), &empty)).iter().filter(|t| gt(t, &lo)).cloned().collect();
            stable_sort_by_less(&mut recent, &|a, b| to_number(a) - to_number(b) < 0.0);
            let max = to_number(get(c, "max"));
            if recent.len() as f64 >= max {
                let idx = recent.len() as f64 - max;
                let last = if idx >= 0.0 && idx.fract() == 0.0 && (idx as usize) < recent.len() { to_number(&recent[idx as usize]) + span } else { f64::NAN };
                at = Some(jmax(at.unwrap_or(0.0), last));
            }
        }
    }
    at
}

/// Anything that bounds the total over several actions: a rate, a budget allocation.
fn meters(m: &Value) -> bool {
    let mut cs: Vec<Value> = req_list(get(m, "caveats")).clone();
    for x in req_list(get(m, "meets")) {
        cs.extend(req_list(get(x, "caveats")).iter().cloned());
    }
    cs.iter().any(|c| matches!(get(c, "type").as_str(), Some("rate") | Some("budget_alloc") | Some("max_blast_radius")))
}

fn set_path(o: &mut Map<String, Value>, path: &[&str], v: &Value) {
    let (k, rest) = match path.split_first() {
        Some(x) => x,
        None => return,
    };
    if rest.is_empty() {
        o.insert(k.to_string(), v.clone());
    } else {
        let empty = empty_obj();
        let cur = o.get(*k).cloned().unwrap_or_else(undef_v);
        let mut inner = spread(nn(&cur, &empty));
        set_path(&mut inner, rest, v);
        o.insert(k.to_string(), Value::Object(inner));
    }
}

/// An iterable value as a list (`...x` of an array, a string's characters; nullish is empty).
fn iter_of(v: &Value) -> Vec<Value> {
    if v.is_null() || is_undef(v) {
        return vec![];
    }
    match v {
        Value::Array(a) => a.clone(),
        Value::String(t) => t.chars().map(|c| s(&c.to_string())).collect(),
        _ => fail("value is not iterable"),
    }
}

fn dedupe_f64(xs: Vec<f64>) -> Vec<f64> {
    let mut out: Vec<f64> = vec![];
    for x in xs {
        if !out.iter().any(|y| *y == x || (x.is_nan() && y.is_nan())) {
            out.push(x);
        }
    }
    out
}

fn dedupe_str(xs: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn with_param(action: &Value, params: &Value, name: &str, v: Value) -> Value {
    let mut am = spread(action);
    let mut pm = spread(params);
    pm.insert(name.to_string(), v);
    am.insert("params".into(), Value::Object(pm));
    Value::Object(am)
}

enum Dim {
    Param(String),
    Resource,
}

struct DimV {
    dim: Dim,
    cost: f64,
    values: Vec<Value>,
}

fn dim_make(d: &Dim, a: &Value, v: &Value) -> Value {
    let mut am = spread(a);
    match d {
        Dim::Param(name) => {
            let empty = empty_obj();
            let mut pm = spread(nn(own(a, "params"), &empty));
            pm.insert(name.clone(), v.clone());
            am.insert("params".into(), Value::Object(pm));
        }
        Dim::Resource => {
            am.insert("resource".into(), v.clone());
        }
    }
    Value::Object(am)
}

fn dim_step(d: &Dim, params: &Value, action: &Value, v: &Value) -> Value {
    match d {
        Dim::Param(name) => u(vec![("kind", s("set_param")), ("param", s(name)), ("from", own(params, name).clone()), ("to", v.clone())]),
        Dim::Resource => u(vec![("kind", s("set_resource")), ("from", get(action, "resource").clone()), ("to", v.clone())]),
    }
}

/// Search for the smallest verified change that gets `action` to the wanted decision.
pub(crate) fn minimal_flip(policy: &Value, action: &Value, o: &Value) -> Value {
    let model = to_model(policy);
    let cctx = get(o, "caveatContext");
    let ok_caveats = is_undef(cctx) || caveats_ok(get(&model, "caveats"), cctx);
    let current: &'static str = if ok_caveats { decide_action(&model, action) } else { "deny" };
    let dflt = s("allow");
    let want = nn(get(o, "desired"), &dflt).clone();
    let want_rank = want.as_str().map_or(f64::NAN, rank_of);
    let mut res: Map<String, Value> = u_map(vec![("current", s(current)), ("repairs", empty_arr()), ("repairExists", Value::Bool(false))]);
    if !truthy(get(o, "holderAuthenticated")) {
        res.insert("refused".into(), s("counterfactuals are shown only to the authenticated holder"));
        return Value::Object(res);
    }
    let probe = get(o, "probe");
    if truthy(probe) {
        let now = get(probe, "now");
        // a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap)
        let fin = |v: &Value| jsnum(v).is_some_and(f64::is_finite);
        if !fin(now) || !fin(get(probe, "windowSecs")) || !req_list(get(probe, "history")).iter().all(fin) {
            res.insert("refused".into(), s("probe budget exhausted"));
            res.insert("probe".into(), u(vec![("history", get(probe, "history").clone())]));
            return Value::Object(res);
        }
        let lo = num(to_number(now) - to_number(get(probe, "windowSecs")) * 1000.0);
        let recent: Vec<Value> = req_list(get(probe, "history")).iter().filter(|t| gt(t, &lo)).cloned().collect();
        if !((recent.len() as f64) < to_number(get(probe, "limit"))) {
            res.insert("refused".into(), s("probe budget exhausted"));
            res.insert("probe".into(), u(vec![("history", Value::Array(recent))]));
            return Value::Object(res);
        }
        let mut h = recent;
        h.push(now.clone());
        res.insert("probe".into(), u(vec![("history", Value::Array(h))]));
    }
    let policy_digest = policy_digest_of(&model);
    if rank_of(current) >= want_rank {
        return Value::Object(res);
    }

    let schema = get(o, "schema");
    let shape: Option<Value> = if schema.is_null() || is_undef(schema) {
        None
    } else {
        let mut found: Option<Value> = None;
        for sh in req_list(schema) {
            if strict_eq(get(sh, "verb"), get(action, "verb")) {
                found = Some(sh.clone());
                break;
            }
        }
        found
    };
    let reaches = |a: &Value| -> Option<&'static str> {
        let d = decide_action(&model, a);
        if rank_of(d) >= want_rank {
            Some(d)
        } else {
            None
        }
    };
    let mut cands: Vec<Cand> = vec![];

    let pr = collect_probes(&u(vec![
        ("predicateSets", Value::Array(vec![Value::Array(probe_set(&model))])),
        ("varyReversibility", Value::Bool(rev_cap(&model).is_some())),
    ]));
    let params: Value = nn(get(action, "params"), &empty_obj()).clone();
    let names: Vec<String> = match get(o, "changeable") {
        c if !c.is_null() && !is_undef(c) => iter_of(c).iter().map(js).collect(),
        _ => match &shape {
            Some(sh) => match obj(get(sh, "params")) {
                Some(m) => keys(m),
                None => fail("Cannot convert undefined or null to object"),
            },
            None => match obj(&params) {
                Some(m) => keys(m),
                None => spread(&params).keys().cloned().collect(),
            },
        },
    };
    // `shape?.params[name]`
    let decl_of = |name: &str| -> Value {
        match &shape {
            Some(sh) => get(get(sh, "params"), name).clone(),
            None => undef_v(),
        }
    };

    // 1. wait: a time caveat that is not open yet, or a rate window that will reset
    if !ok_caveats && truthy(cctx) {
        let at = wait_time(get(&model, "caveats"), cctx);
        let d = decide_action(&model, action);
        if let Some(at) = at {
            let mut later = spread(cctx);
            later.insert("now".into(), num(at));
            if caveats_ok(get(&model, "caveats"), &Value::Object(later)) && rank_of(d) >= want_rank {
                cands.push(Cand {
                    repair: u(vec![("kind", s("wait_until")), ("at", num(at)), ("reason", s("a time or rate caveat opens then"))]),
                    cost: 1.0,
                    decision: d,
                    action: action.clone(),
                });
            }
        }
    }
    let finish = !ok_caveats; // nothing else helps while a caveat is closed

    // 2. one parameter changed: the nearest verified value, per parameter
    if !finish {
        for name in &names {
            let path = format!("action.params.{name}");
            let decl = decl_of(name);
            let cur = own(&params, name).clone();
            let field = pr.fields.iter().find(|f| f.path == path);
            let mut pool: Vec<Value> = vec![];
            if let Some(f) = field {
                pool.extend(f.values.iter().filter(|v| !is_absent(v)).cloned());
            }
            pool.extend(iter_of(oget(&decl, "values")));
            let dmin = oget(&decl, "min").clone();
            let dmax = oget(&decl, "max").clone();
            if !is_undef(&dmin) {
                pool.push(dmin.clone());
            }
            if !is_undef(&dmax) {
                pool.push(dmax.clone());
            }
            let nums: Vec<f64> = pool.iter().filter_map(fin).collect();
            let t: Vec<f64> = thresholds_of(&model, &path).iter().map(to_number).collect();
            let integer = oget(&decl, "type").as_str() == Some("integer") || fin(&cur).is_some_and(|c| c.fract() == 0.0);
            let ints: Vec<f64> = if integer { t.iter().flat_map(|x| [x - 1.0, x + 1.0]).collect() } else { vec![] };
            let mut all = nums.clone();
            all.extend(ints);
            let mut numeric: Vec<f64> =
                dedupe_f64(all).into_iter().filter(|v| (is_undef(&dmin) || *v >= to_number(&dmin)) && (is_undef(&dmax) || *v <= to_number(&dmax))).collect();
            let cn = if is_num(&cur) { to_number(&cur) } else { 0.0 };
            stable_sort_by_less(&mut numeric, &|a, b| {
                let d = (a - cn).abs() - (b - cn).abs();
                let c = if d != 0.0 && !d.is_nan() { d } else { a - b };
                c < 0.0
            });
            let strs: Vec<String> = dedupe_str(pool.iter().filter_map(|v| v.as_str()).filter(|t| !t.starts_with('\u{0}')).map(String::from).collect());
            let mut best: Option<Cand> = None;
            let candidates: Vec<Value> = numeric.iter().map(|x| num(*x)).chain(strs.iter().map(|x| s(x))).collect();
            for v in &candidates {
                if strict_eq(v, &cur) {
                    continue;
                }
                let a = with_param(action, &params, name, v.clone());
                if let Some(d) = reaches(&a) {
                    let extra = if is_num(v) && is_num(&cur) {
                        let (vn, cu) = (to_number(v), to_number(&cur));
                        jmin(1.0, (vn - cu).abs() / (cu.abs() + 1.0))
                    } else {
                        0.5
                    };
                    best = Some(Cand {
                        repair: u(vec![("kind", s("set_param")), ("param", s(name)), ("from", cur.clone()), ("to", v.clone())]),
                        cost: 2.0 + extra,
                        decision: d,
                        action: a,
                    });
                    break; // the pool is ordered nearest first
                }
            }
            if let Some(b) = best {
                cands.push(b);
            }
        }
    }

    // 2b. when no single edit works, the cheapest PAIR of edits (a parameter and the resource, or two parameters)
    if !finish && cands.is_empty() {
        let mut dims: Vec<DimV> = vec![];
        for name in &names {
            let path = format!("action.params.{name}");
            let field = pr.fields.iter().find(|f| f.path == path);
            let decl = decl_of(name);
            let mut vals: Vec<Value> = vec![];
            if let Some(f) = field {
                vals.extend(f.values.iter().cloned());
            }
            vals.extend(iter_of(oget(&decl, "values")));
            let cur = own(&params, name);
            let filtered: Vec<Value> = vals
                .into_iter()
                .filter(|v| match v {
                    Value::String(t) => !t.starts_with('\u{0}'),
                    other => !is_absent(other) && is_num(other),
                })
                .filter(|v| !strict_eq(v, cur))
                .collect();
            let mut uniq: Vec<Value> = vec![];
            for v in filtered {
                if !uniq.iter().any(|x| same_value_zero(x, &v)) {
                    uniq.push(v);
                }
            }
            uniq.truncate(6);
            dims.push(DimV { dim: Dim::Param(name.clone()), cost: 2.0, values: uniq });
        }
        let ar = get(action, "resource");
        let rvals: Vec<Value> = pr.resources.iter().filter(|x| !x.as_str().unwrap_or("").starts_with('\u{0}') && !strict_eq(x, ar)).take(6).cloned().collect();
        dims.push(DimV { dim: Dim::Resource, cost: 3.0, values: rvals });
        for i in 0..dims.len() {
            for j in (i + 1)..dims.len() {
                for x in &dims[i].values {
                    for y in &dims[j].values {
                        let a = dim_make(&dims[j].dim, &dim_make(&dims[i].dim, action, x), y);
                        if let Some(d) = reaches(&a) {
                            cands.push(Cand {
                                repair: u(vec![
                                    ("kind", s("combine")),
                                    ("steps", Value::Array(vec![dim_step(&dims[i].dim, &params, action, x), dim_step(&dims[j].dim, &params, action, y)])),
                                ]),
                                cost: dims[i].cost + dims[j].cost,
                                decision: d,
                                action: a,
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. another allowed resource
    if !finish {
        let ar = get(action, "resource");
        for r in pr.resources.iter().filter(|x| !x.as_str().unwrap_or("").starts_with('\u{0}') && !strict_eq(x, ar)) {
            let mut am = spread(action);
            am.insert("resource".into(), r.clone());
            let a = Value::Object(am);
            if let Some(d) = reaches(&a) {
                cands.push(Cand { repair: u(vec![("kind", s("set_resource")), ("from", ar.clone()), ("to", r.clone())]), cost: 3.0, decision: d, action: a });
            }
        }
    }

    // 4. a named fact that is missing: a subject or env field the policy reads
    if !finish {
        for f in pr.fields.iter().filter(|x| x.path.starts_with("subject.") || x.path.starts_with("env.")) {
            let segs: Vec<&str> = f.path.split('.').collect();
            let root = segs[0];
            let rest = &segs[1..];
            for v in f.values.iter().filter(|x| !is_absent(x)) {
                let empty = empty_obj();
                let mut inner = spread(nn(own(action, root), &empty));
                set_path(&mut inner, rest, v);
                let mut am = spread(action);
                am.insert(root.to_string(), Value::Object(inner));
                let a = Value::Object(am);
                let before = reaches(action);
                let d = reaches(&a);
                if let (Some(d), None) = (d, before) {
                    cands.push(Cand {
                        repair: u(vec![("kind", s("obtain_fact")), ("path", s(&f.path)), ("value", v.clone())]),
                        cost: 4.0,
                        decision: d,
                        action: a,
                    });
                    break;
                }
            }
        }
    }

    // 5. split (opt-in, and only when nothing meters the total)
    if get(o, "allowSplit").as_bool() == Some(true) && !meters(&model) {
        for name in &names {
            let cur = own(&params, name);
            if !is_num(cur) {
                continue;
            }
            let cur_n = to_number(cur);
            let flipped = cands.iter().find(|c| {
                own(&c.repair, "kind").as_str() == Some("set_param") && own(&c.repair, "param").as_str() == Some(name.as_str()) && is_num(own(&c.repair, "to"))
            });
            let part = match flipped {
                Some(c) => to_number(own(&c.repair, "to")),
                None => continue,
            };
            if part <= 0.0 || part >= cur_n {
                continue;
            }
            let n = (cur_n / part).ceil();
            if n > 8.0 {
                continue;
            }
            let nn_ = n as usize;
            let parts: Vec<Value> = (0..nn_)
                .map(|i| {
                    let mut m = Map::new();
                    m.insert(name.clone(), num(if i + 1 < nn_ { part } else { cur_n - part * (n - 1.0) }));
                    Value::Object(m)
                })
                .collect();
            let all_reach = parts.iter().all(|p| {
                let mut pm = spread(&params);
                for (k, v) in spread(p) {
                    pm.insert(k, v);
                }
                let mut am = spread(action);
                am.insert("params".into(), Value::Object(pm));
                reaches(&Value::Object(am)).is_some()
            });
            if all_reach {
                let want_s: &'static str = match want.as_str() {
                    Some("allow") => "allow",
                    Some("escalate") => "escalate",
                    _ => "deny",
                };
                cands.push(Cand {
                    repair: u(vec![("kind", s("split")), ("param", s(name)), ("parts", Value::Array(parts))]),
                    cost: 3.0 + n,
                    decision: want_s,
                    action: action.clone(),
                });
            }
        }
    }

    stable_sort_by_less(&mut cands, &|a, b| a.cost - b.cost < 0.0);
    let dflt_n = num(8.0);
    let mc = to_number(nn(get(o, "maxCandidates"), &dflt_n));
    let len = cands.len() as f64;
    let end = if mc.is_nan() {
        0.0
    } else {
        let t = mc.trunc();
        if t < 0.0 {
            jmax(len + t, 0.0)
        } else {
            jmin(t, len)
        }
    };
    cands.truncate(end as usize);
    let top = cands;
    res.insert("repairExists".into(), Value::Bool(!top.is_empty()));
    let dflt_r = s("critical");
    let redact = nn(get(o, "redact"), &dflt_r).clone();
    let mut redacted = false;
    let mut hide = |c: &Cand| -> Value {
        let kind = own(&c.repair, "kind").as_str().unwrap_or("");
        if redact.as_str() == Some("none") || kind != "set_param" {
            return c.to_json();
        }
        let param = own(&c.repair, "param").clone();
        let sens: Value = match &shape {
            Some(sh) => oget(get(get(sh, "params"), param.as_str().unwrap_or("")), "sensitivity").clone(),
            None => undef_v(),
        };
        if redact.as_str() == Some("critical") && sens.as_str() != Some("critical") {
            return c.to_json();
        }
        redacted = true;
        u(vec![
            ("repair", u(vec![("kind", s("set_param")), ("param", param), ("redacted", Value::Bool(true))])),
            ("cost", num(c.cost)),
            ("decision", s(c.decision)),
            ("action", Value::Object(spread(action))),
        ])
    };
    let mut repairs_out: Vec<Value> = vec![];
    let mut all_redacted = false;
    if redact.as_str() == Some("all") {
        all_redacted = true;
    } else {
        repairs_out = top.iter().map(&mut hide).collect();
    }
    let mut human_free: Option<Value> = None;
    if let Some(free) = top.iter().find(|c| c.decision == "allow" && own(&c.repair, "kind").as_str() != Some("split")) {
        if current == "escalate" {
            human_free = Some(hide(free));
        }
    }
    let human_ask: Option<Value> = if current == "escalate" || top.is_empty() {
        Some(u(vec![
            ("verb", get(action, "verb").clone()),
            ("resource", get(action, "resource").clone()),
            ("params", Value::Object(spread(&params))),
            ("kind", s(if current == "escalate" { "approval" } else { "access-request" })),
            ("policyDigest", s(&policy_digest)),
        ]))
    } else {
        None
    };
    res.insert("repairs".into(), Value::Array(repairs_out));
    if let Some(h) = human_free {
        res.insert("humanFree".into(), h);
    }
    if let Some(h) = human_ask {
        res.insert("humanAsk".into(), h);
    }
    if all_redacted || redacted {
        res.insert("redacted".into(), Value::Bool(true));
    }
    Value::Object(res)
}

fn same_value_zero(a: &Value, b: &Value) -> bool {
    match (jsnum(a), jsnum(b)) {
        (Some(x), Some(y)) => x == y || (x.is_nan() && y.is_nan()),
        _ => strict_eq(a, b) || (a.is_string() && a == b),
    }
}
