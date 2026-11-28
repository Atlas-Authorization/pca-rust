//! Boundary examples and signed GoalTests over the Goal IR and its reference semantics (`examples.ts`). An action is classified per
//! coordinate (verb, resource, relation bits, each parameter) against the literals of the policy; [`cells`] enumerates one
//! representative per decision cell. A case is `{act, rels}`: an action plus the relation facts it is decided under.
use super::*;
use crate::agent::KeyPair;
use crate::goal::digests::goal_digest;
use crate::goal::normalize::stable;
use crate::goal::refsem::ref_explain;
use crate::goal::sign::{sign_payload, verify_payload};
use serde_json::{json, Map};

pub const MAX_CELLS: f64 = 40_000.0;
const OTHER: &str = "\u{0}other";

pub fn empty_hist() -> Value {
    json!({"adms": [], "last": -1, "aggs": {}})
}
pub fn decision_of(d: i64) -> &'static str {
    match d {
        2 => "allow",
        1 => "escalate",
        _ => "deny",
    }
}
pub fn rank_of(d: &str) -> i64 {
    match d {
        "allow" => 0,
        "escalate" => 1,
        _ => 2,
    }
}
/// An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0).
pub fn mk_act(verb: &str, res: &str, params: Value) -> Value {
    json!({"verb": verb, "res": res, "params": params, "t": 0, "sess": "s", "prin": "p", "org": "o", "agent": "a", "depth": 0})
}
/// The reference decision of a goal for `{act, hist?, rels?}`: `{decision, witness, prohibited}`.
pub fn decide_case(gl: &Value, ont: &Value, c: &Value) -> Res<Value> {
    let rels = g(c, "rels");
    let ont2 = if crate::goal::js::truthy(c.get("rels")) {
        let mut m = ont.as_object().ok_or("ontology is not an object")?.clone();
        m.insert("rels".into(), rels.clone());
        Value::Object(m)
    } else {
        ont.clone()
    };
    let hist = match g(c, "hist") {
        Value::Null => empty_hist(),
        h => h.clone(),
    };
    let x = ref_explain(gl, &ont2, g(c, "act"), &hist)?;
    let d = x["d"].as_i64().ok_or("decision is not a number")?;
    Ok(json!({"decision": decision_of(d), "witness": x["witness"], "prohibited": x["prohibit"].as_i64().ok_or("prohibit is not a number")? < 2}))
}
/// The history of the admitted prefix of `acts` (an action the goal refuses is not recorded).
pub fn replay(gl: &Value, ont: &Value, acts: &[Value], rels: &Value) -> Res<Value> {
    let mut adms: Vec<Value> = vec![];
    let mut last = json!(-1);
    for act in acts {
        let h = json!({"adms": adms, "last": last, "aggs": {}});
        let v = decide_case(gl, ont, &json!({"act": act, "hist": h, "rels": rels}))?;
        if v["decision"] == "allow" && !v["witness"].is_null() {
            adms.push(json!({"gid": v["witness"], "act": act}));
            last = g(act, "t").clone();
        }
    }
    Ok(json!({"adms": adms, "last": last, "aggs": {}}))
}

fn qkey(q: &Value) -> String {
    let u = g(q, "u");
    if st(g(u, "k")) == "money" {
        format!("money:{}", js_s(g(u, "ccy")))
    } else {
        js_s(g(u, "k"))
    }
}
fn unit_of_key(key: &str) -> Value {
    match key.strip_prefix("money:") {
        Some(c) => json!({"k": "money", "ccy": c}),
        None => json!({"k": key}),
    }
}
fn dkey(v: &Value) -> Option<String> {
    (st(g(v, "k")) == "s").then(|| format!("s:{}", js_s(g(v, "s"))))
}

fn walk_cond(c: &Value, f: &mut dyn FnMut(&str, &Value)) {
    match st(g(c, "k")) {
        "cmp" => {
            let (l, r) = (g(c, "l"), g(c, "r"));
            let p = if st(g(l, "k")) == "param" {
                Some(st(g(l, "path")))
            } else if st(g(r, "k")) == "param" {
                Some(st(g(r, "path")))
            } else {
                None
            };
            let other = if st(g(l, "k")) == "param" { r } else { l };
            let p = match p {
                Some(p) if st(g(other, "k")) == "lit" => p,
                _ => return,
            };
            let v = g(other, "v");
            if st(g(v, "k")) == "set" {
                for i in arr(g(v, "items")) {
                    f(p, i);
                }
            } else {
                f(p, v);
            }
        }
        "and" | "or" => {
            walk_cond(g(c, "a"), f);
            walk_cond(g(c, "b"), f);
        }
        "not" => walk_cond(g(c, "c"), f),
        _ => {}
    }
}
fn parts(s: &Value) -> Vec<Value> {
    match st(g(s, "k")) {
        "all_of" => arr(g(s, "parts")).to_vec(),
        "any" => vec![],
        _ => vec![s.clone()],
    }
}

/// The literals of one or more goals, as the coordinates of the decision cells.
#[derive(Debug, Clone, Default)]
pub struct Space {
    pub verbs: Vec<String>,
    pub resources: Vec<String>,
    pub rels: Vec<(String, String)>,
    /// param -> (unit key -> sorted distinct numbers), in first-seen order
    pub q: Vec<(String, Vec<(String, Vec<Value>)>)>,
    /// param -> sorted distinct discrete literals (`s:<text>`), in first-seen order
    pub d: Vec<(String, Vec<String>)>,
}
impl Space {
    pub fn to_json(&self) -> Value {
        let mut q = Map::new();
        for (p, m) in &self.q {
            let mut mm = Map::new();
            for (k, v) in m {
                mm.insert(k.clone(), Value::Array(v.clone()));
            }
            q.insert(p.clone(), Value::Object(mm));
        }
        let mut d = Map::new();
        for (p, v) in &self.d {
            d.insert(p.clone(), sv(v.clone()));
        }
        json!({"verbs": self.verbs, "resources": self.resources, "rels": self.rels.iter().map(|(r, a)| json!({"rel": r, "anchor": a})).collect::<Vec<_>>(),
            "q": q, "d": d})
    }
    fn qg(&self, p: &str) -> Option<&Vec<(String, Vec<Value>)>> {
        self.q.iter().find(|(k, _)| k == p).map(|(_, v)| v)
    }
    fn dg(&self, p: &str) -> Option<&Vec<String>> {
        self.d.iter().find(|(k, _)| k == p).map(|(_, v)| v)
    }
}

fn sorted_str(mut v: Vec<String>) -> Vec<String> {
    v.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
    v.dedup();
    v
}

pub fn build_space(goals: &[Value], extra_verbs: &[String]) -> Res<Space> {
    let mut verbs: Vec<String> = extra_verbs.to_vec();
    let mut resources: Vec<String> = vec![];
    let mut rels: Vec<(String, String)> = vec![];
    let mut q: Vec<(String, Vec<(String, Vec<Value>)>)> = vec![];
    let mut d: Vec<(String, Vec<String>)> = vec![];
    fn lit(q: &mut Vec<(String, Vec<(String, Vec<Value>)>)>, d: &mut Vec<(String, Vec<String>)>, p: &str, v: &Value) {
        if st(g(v, "k")) == "q" {
            let key = qkey(g(v, "q"));
            let n = g(g(v, "q"), "n").clone();
            let mi = match q.iter().position(|(k, _)| k == p) {
                Some(i) => i,
                None => {
                    q.push((p.to_string(), vec![]));
                    q.len() - 1
                }
            };
            let m = &mut q[mi].1;
            let si = match m.iter().position(|(k, _)| *k == key) {
                Some(i) => i,
                None => {
                    m.push((key, vec![]));
                    m.len() - 1
                }
            };
            let s = &mut m[si].1;
            if !s.iter().any(|x| nm(x) == nm(&n) || (x.is_null() && n.is_null())) {
                s.push(n);
            }
        } else if let Some(k) = dkey(v) {
            let di = match d.iter().position(|(kk, _)| kk == p) {
                Some(i) => i,
                None => {
                    d.push((p.to_string(), vec![]));
                    d.len() - 1
                }
            };
            if !d[di].1.contains(&k) {
                d[di].1.push(k);
            }
        }
    }
    fn res(s: &Value, resources: &mut Vec<String>, rels: &mut Vec<(String, String)>) {
        for x in parts(s) {
            match st(g(&x, "k")) {
                "exact" => resources.push(js_s(g(&x, "id"))),
                "oneof" => resources.extend(arr(g(&x, "ids")).iter().map(js_s)),
                _ => {
                    let e = (js_s(g(&x, "rel")), js_s(g(&x, "anchor")));
                    if !rels.contains(&e) {
                        rels.push(e);
                    }
                }
            }
        }
    }
    for gl in goals {
        for gr in req_arr(g(gl, "grants"))? {
            verbs.push(js_s(g(gr, "verb")));
            res(g(gr, "res"), &mut resources, &mut rels);
            walk_cond(g(gr, "cond"), &mut |p, v| lit(&mut q, &mut d, p, v));
        }
        for p in req_arr(g(gl, "prohibits"))? {
            let t = g(p, "target");
            if st(g(t, "k")) == "verb" {
                verbs.push(js_s(g(t, "verb")));
            }
            res(g(p, "res"), &mut resources, &mut rels);
            walk_cond(g(p, "cond"), &mut |pp, v| lit(&mut q, &mut d, pp, v));
        }
        for c in req_arr(g(gl, "escalateOn"))? {
            walk_cond(c, &mut |p, v| lit(&mut q, &mut d, p, v));
        }
        for b in req_arr(g(gl, "bounds"))? {
            let v = g(b, "value");
            if st(g(b, "agg")) == "sum" && st(g(v, "k")) == "param" {
                lit(&mut q, &mut d, st(g(v, "path")), &json!({"k": "q", "q": g(b, "cap")}));
                // reps around the cap so witnesses carry the summed param
            }
        }
    }
    rels.sort_by(|a, b| crate::goal::js::u16cmp(&format!("{}{}", a.0, a.1), &format!("{}{}", b.0, b.1)));
    for (_, m) in q.iter_mut() {
        for (_, s) in m.iter_mut() {
            s.sort_by(|a, b| nm(a).partial_cmp(&nm(b)).unwrap_or(std::cmp::Ordering::Equal));
        }
    }
    for (_, s) in d.iter_mut() {
        s.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
    }
    Ok(Space { verbs: sorted_str_js(verbs), resources: sorted_str_js(resources), rels, q, d })
}
/// `[...new Set(xs)].sort()`.
fn sorted_str_js(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in v {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    sorted_str(out)
}

fn classify_lit(sp: &Space, p: &str, l: Option<&Value>) -> String {
    let l = match l {
        None => return "missing".into(),
        Some(l) => l,
    };
    if st(g(l, "k")) == "set" {
        return "missing".into();
    }
    let (groups, ds) = (sp.qg(p), sp.dg(p));
    if st(g(l, "k")) == "q" {
        let key = qkey(g(l, "q"));
        let grp = groups.and_then(|m| m.iter().find(|(k, _)| *k == key)).map(|(_, v)| v);
        let grp = match grp {
            None => return if groups.is_some() || ds.is_some() { "unit".into() } else { "any".into() },
            Some(x) => x,
        };
        let v = nm(g(g(l, "q"), "n"));
        if let Some(i) = grp.iter().position(|x| nm(x) == v) {
            return format!("{key}={i}");
        }
        let mut pos = 0;
        while pos < grp.len() && nm(&grp[pos]) < v {
            pos += 1;
        }
        return format!("{key}@{pos}"); // strictly between literal pos-1 and pos
    }
    let ds = match ds {
        None => return if groups.is_some() { "unit".into() } else { "any".into() },
        Some(x) => x,
    };
    match dkey(l) {
        Some(k) if ds.contains(&k) => k,
        _ => "other".into(),
    }
}
fn rel_bit(c: &Value, rel: &str, anchor: &str) -> i64 {
    for x in arr(g(c, "rels")) {
        if st(g(x, "rel")) == rel && st(g(x, "anchor")) == anchor {
            return i64::from(includes_v(arr(g(x, "members")), g(g(c, "act"), "res")));
        }
    }
    0
}
fn params_of(sp: &Space) -> Vec<String> {
    let mut v: Vec<String> = sp.q.iter().map(|x| x.0.clone()).collect();
    for (k, _) in &sp.d {
        if !v.contains(k) {
            v.push(k.clone());
        }
    }
    v.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
    v
}

/// The decision cell of a case under a space (canonical string; the unit of precedents).
pub fn cell_key(sp: &Space, c: &Value) -> Res<String> {
    let act = g(c, "act");
    let params = g(act, "params");
    let verb = st(g(act, "verb"));
    let rs = st(g(act, "res"));
    let mut p = Map::new();
    for name in params_of(sp) {
        p.insert(name.clone(), Value::String(classify_lit(sp, &name, params.get(&name))));
    }
    Ok(stable(&json!({
        "v": if sp.verbs.iter().any(|x| x == verb) { verb } else { "*" },
        "r": if sp.resources.iter().any(|x| x == rs) { rs } else { "*" },
        "l": sp.rels.iter().map(|(r, a)| rel_bit(c, r, a)).collect::<Vec<_>>(),
        "p": p})))
}

fn param_options(sp: &Space, p: &str) -> Vec<Option<Value>> {
    let mut out: Vec<Option<Value>> = vec![None];
    let mut seen: Vec<String> = vec![];
    let mut add = |v: Value, out: &mut Vec<Option<Value>>| {
        let k = stable(&v);
        if !seen.contains(&k) {
            seen.push(k);
            out.push(Some(v));
        }
    };
    for (key, vals) in sp.qg(p).into_iter().flatten() {
        let is_instant = key == "instant";
        for v in vals {
            let n = nm(v);
            for x in [n - 1.0, n, n + 1.0] {
                if x >= 0.0 || is_instant {
                    add(json!({"k": "q", "q": {"u": unit_of_key(key), "n": numv(x)}}), &mut out);
                }
            }
        }
        if key.starts_with("money:") {
            add(json!({"k": "q", "q": {"u": {"k": "money", "ccy": "ZZZ"}, "n": 0}}), &mut out);
            // unit mismatch -> Unknown
        }
    }
    for k in sp.dg(p).into_iter().flatten() {
        add(json!({"k": "s", "s": k.strip_prefix("s:").unwrap_or("")}), &mut out);
    }
    if sp.dg(p).is_some() {
        add(json!({"k": "s", "s": OTHER}), &mut out);
    }
    out
}

/// One representative per decision cell. `complete` is false when the grid exceeded [`MAX_CELLS`] (then it is a subset).
/// `{cases, complete}`.
pub fn cells(sp: &Space, verbs: Option<&[String]>) -> Res<Value> {
    let verbs: Vec<String> = match verbs {
        Some(v) => v.to_vec(),
        None => sp.verbs.iter().cloned().chain(["\u{0}other-verb".to_string()]).collect(),
    };
    let resources: Vec<String> = sp.resources.iter().cloned().chain(["\u{0}other-resource".to_string()]).collect();
    let params = params_of(sp);
    let p_opts: Vec<Vec<Option<Value>>> = params.iter().map(|p| param_options(sp, p)).collect();
    let rel_bits = sp.rels.len();
    let mut total = verbs.len() as f64 * resources.len() as f64 * 2f64.powi(rel_bits as i32);
    for o in &p_opts {
        total *= o.len() as f64;
    }
    let complete = total <= MAX_CELLS;
    let mut out: Vec<Value> = vec![];
    let mut seen: Vec<String> = vec![];
    let mut push = |c: Value, out: &mut Vec<Value>| -> Res<()> {
        let k = cell_key(sp, &c)?;
        if !seen.contains(&k) {
            seen.push(k);
            out.push(c);
        }
        Ok(())
    };
    let build = |verb: &str, resource: &str, bits: u64, choice: &[Option<Value>]| -> Value {
        let mut pr = Map::new();
        for (i, p) in params.iter().enumerate() {
            if let Some(Some(v)) = choice.get(i) {
                pr.insert(p.clone(), v.clone());
            }
        }
        let rels: Vec<Value> = sp
            .rels
            .iter()
            .enumerate()
            .map(|(i, (r, a))| json!({"rel": r, "anchor": a, "members": if bits & (1u64 << i) != 0 { vec![resource.to_string()] } else { vec![] }}))
            .collect();
        json!({"act": mk_act(verb, resource, Value::Object(pr)), "rels": rels})
    };
    if complete {
        for verb in &verbs {
            for res in &resources {
                for bits in 0..(1u64 << rel_bits) {
                    let mut idx = vec![0usize; params.len()];
                    loop {
                        let choice: Vec<Option<Value>> = idx.iter().enumerate().map(|(i, &j)| p_opts[i][j].clone()).collect();
                        push(build(verb.as_str(), res.as_str(), bits, &choice[..]), &mut out)?;
                        let mut k = 0;
                        while k < idx.len() {
                            idx[k] += 1;
                            if idx[k] != p_opts[k].len() {
                                break;
                            }
                            idx[k] = 0;
                            k += 1;
                        }
                        if k == idx.len() {
                            break;
                        }
                    }
                }
            }
        }
    } else {
        let base_choice = || -> Vec<Option<Value>> { p_opts.iter().map(|o| o[2usize.min(o.len() - 1)].clone()).collect() };
        for verb in &verbs {
            push(build(verb.as_str(), resources[0].as_str(), 0, &base_choice()[..]), &mut out)?;
            for res in &resources {
                for bits in 0..(1u64 << rel_bits) {
                    push(build(verb.as_str(), res.as_str(), bits, &base_choice()[..]), &mut out)?;
                }
            }
            for (i, o) in p_opts.iter().enumerate() {
                for l in o {
                    let mut ch = base_choice();
                    ch[i] = l.clone();
                    push(build(verb.as_str(), resources[0].as_str(), 0, &ch[..]), &mut out)?;
                }
            }
        }
    }
    Ok(json!({"cases": out, "complete": complete}))
}

fn magnitude(a: &Value) -> f64 {
    match g(a, "params").as_object() {
        Some(m) => m.values().map(|v| if st(g(v, "k")) == "q" { nm(g(g(v, "q"), "n")).abs() } else { 0.0 }).sum(),
        None => 0.0,
    }
}

/// The smallest-magnitude case the grant admits (a minimal Allow witness), or `None` if its Allow set is empty.
pub fn allow_witness(gl: &Value, gr: &Value, ont: &Value) -> Res<Option<Value>> {
    let sp = build_space(std::slice::from_ref(gl), &[])?;
    let mut best: Option<Value> = None;
    let vs = [js_s(g(gr, "verb"))];
    for c in cells(&sp, Some(&vs[..]))?["cases"].as_array().ok_or("cases")? {
        let v = decide_case(gl, ont, c)?;
        if v["decision"] == "allow" && seq_eq(&v["witness"], g(gr, "gid")) && best.as_ref().map_or(true, |b| magnitude(g(c, "act")) < magnitude(g(b, "act"))) {
            best = Some(c.clone());
        }
    }
    Ok(best)
}

fn example(gl: &Value, ont: &Value, kind: &str, why: &str, cs: &Value, hist: &Value) -> Res<Value> {
    let rels = g(cs, "rels");
    let digest = hc(&json!({"act": g(cs, "act"), "hist": hist, "rels": rels}))?;
    let decision = decide_case(gl, ont, &json!({"act": g(cs, "act"), "hist": hist, "rels": rels}))?["decision"].clone();
    Ok(json!({"id": format!("{kind}:{}", &digest[..12]), "kind": kind, "why": why, "act": g(cs, "act"), "hist": hist, "rels": rels, "decision": decision}))
}

/// The full example set: decision-cell representatives, cap sequences and unmentioned-dimension probes. `{examples, complete}`.
pub fn boundary_examples(gl: &Value, ont: &Value, extra: &[Value], verbs: &[String]) -> Res<Value> {
    let mut goals = vec![gl.clone()];
    goals.extend(extra.iter().cloned());
    let sp = build_space(&goals, verbs)?;
    let c = cells(&sp, None)?;
    let eh = empty_hist();
    let mut out: Vec<Value> = vec![];
    for cs in c["cases"].as_array().ok_or("cases")? {
        let v = decide_case(gl, ont, cs)?;
        let kind = if v["prohibited"] == true && v["decision"] == "deny" {
            "prohibit_trigger"
        } else if v["decision"] == "allow" {
            "member"
        } else {
            "boundary"
        };
        out.push(example(gl, ont, kind, &format!("cell {}", st(&v["decision"])), cs, &eh)?);
    }
    for gr in req_arr(g(gl, "grants"))? {
        if let Some(w) = allow_witness(gl, gr, ont)? {
            out.push(example(gl, ont, "allow_witness", &format!("minimal Allow witness of grant {}", js_s(g(gr, "gid"))), &w, &eh)?);
        }
    }
    for b in req_arr(g(gl, "bounds"))? {
        let sel = g(b, "sel");
        let gids: &[Value] = if st(g(sel, "k")) == "gids" { arr(g(sel, "gids")) } else { &[] };
        let gr = req_arr(g(gl, "grants"))?.iter().find(|x| includes_v(gids, g(x, "gid")));
        let w = match gr {
            Some(gr) => allow_witness(gl, gr, ont)?,
            None => None,
        };
        let w = match w {
            Some(w) => w,
            None => continue,
        };
        let cap_n = nm(g(g(b, "cap"), "n"));
        let per: f64 = if st(g(b, "agg")) == "count" {
            1.0
        } else {
            let val = g(b, "value");
            let v = if st(g(val, "k")) == "param" { g(g(g(&w, "act"), "params"), st(g(val, "path"))) } else { &NULL };
            if st(g(v, "k")) == "q" {
                nm(g(g(v, "q"), "n"))
            } else {
                0.0
            }
        };
        if st(g(b, "agg")) == "sum" && per <= 0.0 {
            continue;
        }
        let n = (cap_n / per).floor();
        if n > 60.0 {
            continue; // sequence too long to review; the aggregate theorem (not examples) covers it
        }
        let count = if n.is_finite() && n > 0.0 { n as usize } else { 0 };
        let acts: Vec<Value> = (0..count).map(|_| g(&w, "act").clone()).collect();
        let h = replay(gl, ont, &acts, g(&w, "rels"))?;
        let why = format!("reach the {} cap with {} action(s), then one more", js_s(g(b, "bid")), crate::intent_v2::js_number_string(n));
        out.push(example(gl, ont, "cap_sequence", &why, &w, &h)?);
    }
    for gr in req_arr(g(gl, "grants"))? {
        let w = match allow_witness(gl, gr, ont)? {
            Some(w) => w,
            None => continue,
        };
        let act = g(&w, "act");
        for (p, l) in g(act, "params").as_object().into_iter().flatten() {
            if st(g(l, "k")) == "q" && st(g(g(g(l, "q"), "u"), "k")) == "money" {
                let mut q = g(l, "q").as_object().cloned().unwrap_or_default();
                q.insert("n".into(), json!(1_000_000_000));
                let mut params = g(act, "params").as_object().cloned().unwrap_or_default();
                params.insert(p.clone(), json!({"k": "q", "q": q}));
                let mut a2 = act.as_object().cloned().unwrap_or_default();
                a2.insert("params".into(), Value::Object(params));
                out.push(example(gl, ont, "probe", &format!("extreme {p}"), &json!({"act": a2, "rels": g(&w, "rels")}), &eh)?);
            }
        }
        let nothing: Vec<Value> = arr(g(&w, "rels"))
            .iter()
            .map(|r| {
                let mut m = r.as_object().cloned().unwrap_or_default();
                m.insert("members".into(), json!([]));
                Value::Object(m)
            })
            .collect();
        let mut a3 = act.as_object().cloned().unwrap_or_default();
        a3.insert("res".into(), json!("\u{0}other-resource"));
        out.push(example(gl, ont, "probe", "other resource", &json!({"act": a3, "rels": nothing}), &eh)?);
        out.push(example(gl, ont, "probe", "other customer/anchor", &json!({"act": act, "rels": nothing}), &eh)?);
    }
    let mut seen: Vec<String> = vec![];
    let mut res: Vec<Value> = vec![];
    for e in out {
        let id = st(&e["id"]).to_string();
        if !seen.contains(&id) {
            seen.push(id);
            res.push(e);
        }
    }
    Ok(json!({"examples": res, "complete": c["complete"]}))
}

/// Cap examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable.
pub fn review_set(examples: &[Value], cap: usize) -> Vec<Value> {
    let w = |k: &str| match k {
        "probe" => 0,
        "cap_sequence" => 1,
        "allow_witness" => 2,
        "prohibit_trigger" => 3,
        "member" => 4,
        _ => 5,
    };
    let mut v = examples.to_vec();
    v.sort_by(|a, b| {
        rank_of(st(g(a, "decision")))
            .cmp(&rank_of(st(g(b, "decision"))))
            .then(w(st(g(a, "kind"))).cmp(&w(st(g(b, "kind")))))
            .then_with(|| crate::goal::js::u16cmp(st(g(a, "id")), st(g(b, "id"))))
    });
    v.truncate(cap);
    v
}

pub fn expected_decision(a: &str) -> &'static str {
    match a {
        "allow" => "allow",
        "deny" => "deny",
        _ => "escalate",
    }
}
/// Order-independent digest of a test list.
pub fn tests_digest(tests: &[Value]) -> Res<String> {
    let mut v = tests.to_vec();
    v.sort_by(|a, b| crate::goal::js::u16cmp(st(g(a, "id")), st(g(b, "id"))));
    hc(&json!({"d": "atlas-pca/goal-tests/v1", "tests": v}))
}
/// `confirmed`: `[{example, answer}]`.
pub fn make_goal_tests(gl: &Value, confirmed: &[Value]) -> Res<Value> {
    let tests: Vec<Value> = confirmed
        .iter()
        .map(|c| {
            let e = g(c, "example");
            let mut m = Map::new();
            m.insert("id".into(), g(e, "id").clone());
            m.insert("act".into(), g(e, "act").clone());
            m.insert("hist".into(), g(e, "hist").clone());
            if let Some(r) = e.get("rels") {
                m.insert("rels".into(), r.clone());
            }
            m.insert("answer".into(), g(c, "answer").clone());
            Value::Object(m)
        })
        .collect();
    Ok(json!({"goal_digest": goal_digest(gl)?, "ontology_digest": g(gl, "ontDigest"), "tests": tests, "tests_digest": tests_digest(&tests)?}))
}
pub fn sign_goal_tests(set: &Value, secret: &KeyPair) -> Res<Value> {
    sign_payload("goal-tests", set, secret)
}
/// Recompile check: any recompile must reproduce every confirmed test or the policy is refused. `decide_fn(test) -> decision`.
pub fn check_goal_tests(s: &Value, pins: &[Value], decide_fn: &dyn Fn(&Value) -> Res<String>) -> Res<Value> {
    if !verify_payload(s, "goal-tests", pins) {
        return Ok(json!({"ok": false, "reason": "signature", "failures": []}));
    }
    let pl = g(s, "payload");
    let tests = req_arr(g(pl, "tests"))?;
    if tests_digest(tests)? != st(g(pl, "tests_digest")) {
        return Ok(json!({"ok": false, "reason": "tests_digest", "failures": []}));
    }
    let mut failures: Vec<Value> = vec![];
    for t in tests {
        let got = decide_fn(t)?;
        let want = expected_decision(st(g(t, "answer")));
        if got != want {
            failures.push(json!({"id": g(t, "id"), "expected": want, "got": got}));
        }
    }
    Ok(if failures.is_empty() { json!({"ok": true, "failures": failures}) } else { json!({"ok": false, "reason": "test_regression", "failures": failures}) })
}
/// The pin: the policy version cannot silently change under a signed test set.
pub fn sign_pin(p: &Value, secret: &KeyPair) -> Res<Value> {
    sign_payload("policy-pin", p, secret)
}
/// `cur`: `{goal, policy_digest, tests}`.
pub fn check_pin(pin: &Value, pins: &[Value], cur: &Value) -> Res<Value> {
    if !verify_payload(pin, "policy-pin", pins) {
        return Ok(json!({"ok": false, "reason": "signature"}));
    }
    let p = g(pin, "payload");
    let (goal, tests) = (g(cur, "goal"), g(cur, "tests"));
    let bad = |r: &str| Ok(json!({"ok": false, "reason": r}));
    if !seq_eq(g(p, "goal_digest"), &Value::String(goal_digest(goal)?)) {
        return bad("goal changed under the pin");
    }
    if !seq_eq(g(p, "policy_digest"), g(cur, "policy_digest")) {
        return bad("policy changed under the pin");
    }
    if !seq_eq(g(p, "tests_digest"), g(tests, "tests_digest")) || !seq_eq(g(p, "tests_digest"), &Value::String(tests_digest(req_arr(g(tests, "tests"))?)?)) {
        return bad("tests changed under the pin");
    }
    if !seq_eq(g(p, "ontology_digest"), g(goal, "ontDigest")) {
        return bad("ontology changed under the pin");
    }
    Ok(json!({"ok": true}))
}
