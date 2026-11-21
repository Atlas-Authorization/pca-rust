//! N-version interpretation: the enforced policy is the semantic meet of the readings (`nversion.ts`). Allow(meet gs) a implies
//! Allow(g) a for every g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named
//! `x&y&z`), resources intersect through `all_of`, conditions conjoin; a bound of one reading counts the actions admitted by the
//! merged grants derived from the grants that bound selected.
use super::disambiguate::{disagreement_mass, questions, QOpts};
use super::*;
use crate::goal::normalize::{canonicalize_goal, stable};
use serde_json::{json, Map};

fn parts_of(s: &Value) -> Vec<Value> {
    match st(g(s, "k")) {
        "all_of" => arr(g(s, "parts")).to_vec(),
        "any" => vec![],
        _ => vec![s.clone()],
    }
}
fn intersect(a: &Value, b: &Value) -> Value {
    if st(g(a, "k")) == "any" {
        return b.clone();
    }
    if st(g(b, "k")) == "any" {
        return a.clone();
    }
    // `new Map(parts.map(p => [stable(p), p]))`: the first position of a key, the last value
    let mut uniq: Vec<(String, Value)> = vec![];
    for p in parts_of(a).into_iter().chain(parts_of(b)) {
        let k = stable(&p);
        match uniq.iter_mut().find(|(kk, _)| *kk == k) {
            Some(e) => e.1 = p,
            None => uniq.push((k, p)),
        }
    }
    if uniq.len() == 1 {
        uniq.remove(0).1
    } else {
        json!({"k": "all_of", "parts": uniq.into_iter().map(|x| x.1).collect::<Vec<_>>()})
    }
}
fn conj(a: &Value, b: &Value) -> Value {
    if st(g(a, "k")) == "true" {
        b.clone()
    } else if st(g(b, "k")) == "true" {
        a.clone()
    } else {
        json!({"k": "and", "a": a, "b": b})
    }
}

/// A merged grant and, per reading, the gid of the grant it was derived from.
struct Tracked {
    g: Value,
    from: Vec<Value>,
}
fn cross(a: &[Tracked], b: &[Tracked]) -> Vec<Tracked> {
    let mut out = vec![];
    for x in a {
        for y in b {
            if seq_eq(g(&x.g, "verb"), g(&y.g, "verb")) {
                let gid = format!("{}&{}", js_s(g(&x.g, "gid")), js_s(g(&y.g, "gid")));
                out.push(Tracked {
                    g: json!({"gid": gid, "verb": g(&x.g, "verb"), "res": intersect(g(&x.g, "res"), g(&y.g, "res")), "cond": conj(g(&x.g, "cond"), g(&y.g, "cond"))}),
                    from: x.from.iter().chain(y.from.iter()).cloned().collect(),
                });
            }
        }
    }
    out
}
fn track(gs: &[Value]) -> Vec<Tracked> {
    gs.iter().map(|x| Tracked { g: x.clone(), from: vec![g(x, "gid").clone()] }).collect()
}

/// Cross product on equal verbs, resource intersection, conjoined conditions.
pub fn meet_grants(a: &[Value], b: &[Value]) -> Vec<Value> {
    cross(&track(a), &track(b)).into_iter().map(|t| t.g).collect()
}

fn sorted_vals(mut v: Vec<Value>) -> Vec<Value> {
    v.sort_by(|a, b| crate::goal::js::u16cmp(&js_s(a), &js_s(b)));
    v
}

/// The semantic meet of readings that share principal, ontology and text.
pub fn meet(goals: &[Value]) -> Res<Value> {
    if goals.is_empty() {
        return Err("meet: no goals".into());
    }
    let first = &goals[0];
    for gl in goals {
        if !seq_eq(g(gl, "principal"), g(first, "principal"))
            || !seq_eq(g(gl, "ontDigest"), g(first, "ontDigest"))
            || !seq_eq(g(gl, "nlDigest"), g(first, "nlDigest"))
        {
            return Err("meet: readings must share principal, ontology and text".into());
        }
    }
    if goals.len() == 1 {
        return Ok(first.clone());
    }
    let mut tracked = track(arr(g(first, "grants")));
    for gl in &goals[1..] {
        tracked = cross(&tracked, &track(arr(g(gl, "grants"))));
    }
    let derived =
        |i: usize, gids: &Value| -> Vec<Value> { tracked.iter().filter(|t| includes_v(arr(gids), &t.from[i])).map(|t| g(&t.g, "gid").clone()).collect() };
    let grants: Vec<Value> = tracked.iter().map(|t| t.g.clone()).collect();

    let mut prohibits: Vec<Value> = vec![];
    let mut pseen: Vec<(String, Value)> = vec![];
    for (i, gl) in goals.iter().enumerate() {
        for p in req_arr(g(gl, "prohibits"))? {
            let mut body = p.as_object().cloned().unwrap_or_default();
            body.insert("pid".into(), json!(""));
            let body = stable(&Value::Object(body));
            if pseen.iter().any(|(k, _)| *k == body) {
                continue;
            }
            let taken = pseen.iter().any(|(_, v)| seq_eq(v, g(p, "pid")));
            pseen.push((body, g(p, "pid").clone()));
            if taken {
                let mut m = p.as_object().cloned().unwrap_or_default();
                m.insert("pid".into(), json!(format!("{}#{i}", js_s(g(p, "pid")))));
                prohibits.push(Value::Object(m));
            } else {
                prohibits.push(p.clone());
            }
        }
    }
    let mut bounds: Vec<Value> = vec![];
    let mut bseen: Vec<(String, usize)> = vec![];
    for (i, gl) in goals.iter().enumerate() {
        for b in req_arr(g(gl, "bounds"))? {
            let bsel = g(b, "sel");
            let sel = if st(g(bsel, "k")) == "gids" { json!({"k": "gids", "gids": sorted_vals(derived(i, g(bsel, "gids")))}) } else { bsel.clone() };
            if st(g(&sel, "k")) == "gids" && arr(g(&sel, "gids")).is_empty() {
                continue; // no merged grant derives from the selected grants: nothing to count
            }
            let cap = g(b, "cap");
            let key = stable(
                &json!({"sel": sel, "agg": g(b, "agg"), "value": g(b, "value"), "key": g(b, "key"), "window": g(b, "window"), "scope": g(b, "scope"), "unit": g(cap, "u")}),
            );
            if let Some((_, idx)) = bseen.iter().find(|(k, _)| *k == key) {
                // the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
                let prev = &mut bounds[*idx];
                if nm(g(cap, "n")) < nm(g(g(prev, "cap"), "n")) {
                    prev["cap"] = cap.clone();
                }
                if st(g(b, "onExceed")) == "deny" {
                    prev["onExceed"] = json!("deny");
                }
                continue;
            }
            let bid = if bounds.iter().any(|x| seq_eq(g(x, "bid"), g(b, "bid"))) { json!(format!("{}#{i}", js_s(g(b, "bid")))) } else { g(b, "bid").clone() };
            let mut nb = b.as_object().cloned().unwrap_or_default();
            nb.insert("sel".into(), sel);
            nb.insert("bid".into(), bid);
            bounds.push(Value::Object(nb));
            bseen.push((key, bounds.len() - 1));
        }
    }
    let mut esc: Vec<(String, Value)> = vec![];
    for gl in goals {
        for c in req_arr(g(gl, "escalateOn"))? {
            let k = stable(c);
            match esc.iter_mut().find(|(kk, _)| *kk == k) {
                Some(e) => e.1 = c.clone(),
                None => esc.push((k, c.clone())),
            }
        }
    }
    let idle: Vec<&Value> = goals.iter().map(|x| g(g(x, "validity"), "maxIdle")).filter(|x| nm(x) > 0.0).collect();
    let touch: Vec<Value> = tracked
        .iter()
        .filter(|t| goals.iter().enumerate().all(|(i, gl)| includes_v(arr(g(g(gl, "deleg"), "mayTouch")), &t.from[i])))
        .map(|t| g(&t.g, "gid").clone())
        .collect();
    let ack: Vec<Value> = tracked
        .iter()
        .filter(|t| {
            st(g(g(&t.g, "res"), "k")) == "any"
                && goals.iter().enumerate().all(|(i, gl)| {
                    let x = arr(g(gl, "grants")).iter().find(|x| seq_eq(g(x, "gid"), &t.from[i]));
                    x.map_or(true, |x| st(g(g(x, "res"), "k")) != "any") || includes_v(arr(g(gl, "wildcardAck")), &t.from[i])
                })
        })
        .map(|t| g(&t.g, "gid").clone())
        .collect();
    let mut holes: Vec<(Value, Value)> = vec![];
    for (i, gl) in goals.iter().enumerate() {
        for h in req_arr(g(gl, "holes"))? {
            let prev = holes.iter().find(|(k, _)| seq_eq(k, g(h, "hid"))).map(|(_, v)| v.clone());
            let mut aff: Vec<Value> = prev.as_ref().map(|p| arr(g(p, "affects")).to_vec()).unwrap_or_default();
            aff.extend(derived(i, g(h, "affects")));
            let affects = sorted_vals(uniq_v(&aff));
            let gl_h = g(h, "global");
            let global = if crate::goal::js::truthy(Some(gl_h)) {
                gl_h.clone()
            } else {
                match prev.as_ref().map(|p| g(p, "global")) {
                    Some(v) if !v.is_null() => v.clone(),
                    _ => json!(false),
                }
            };
            let mut nh = h.as_object().cloned().unwrap_or_default();
            nh.insert("affects".into(), Value::Array(affects));
            nh.insert("global".into(), global);
            let nh = Value::Object(nh);
            match holes.iter_mut().find(|(k, _)| seq_eq(k, g(h, "hid"))) {
                Some(e) => e.1 = nh,
                None => holes.push((g(h, "hid").clone(), nh)),
            }
        }
    }
    let mut srcs: Vec<Value> = vec![];
    for gl in goals {
        srcs.extend(req_arr(g(gl, "sources"))?.iter().cloned());
    }
    let vs: Vec<&Value> = goals.iter().map(|x| g(x, "validity")).collect();
    let (mut nb_v, mut na_v) = (g(vs[0], "notBefore"), g(vs[0], "notAfter"));
    for v in &vs[1..] {
        if nm(g(v, "notBefore")) > nm(nb_v) {
            nb_v = g(v, "notBefore");
        }
        if nm(g(v, "notAfter")) < nm(na_v) {
            na_v = g(v, "notAfter");
        }
    }
    let max_idle = idle.iter().copied().fold(None::<&Value>, |acc, x| match acc {
        Some(a) if nm(a) <= nm(x) => Some(a),
        _ => Some(x),
    });
    let max_depth = goals.iter().map(|x| g(g(x, "deleg"), "maxDepth")).fold(None::<&Value>, |acc, x| match acc {
        Some(a) if nm(a) <= nm(x) => Some(a),
        _ => Some(x),
    });
    let mut m: Map<String, Value> = first.as_object().cloned().unwrap_or_default();
    m.insert("grants".into(), Value::Array(grants));
    m.insert("prohibits".into(), Value::Array(prohibits));
    m.insert("bounds".into(), Value::Array(bounds));
    m.insert("escalateOn".into(), Value::Array(esc.into_iter().map(|x| x.1).collect()));
    m.insert("sources".into(), Value::Array(uniq_v(&srcs)));
    m.insert("validity".into(), json!({"notBefore": nb_v, "notAfter": na_v, "maxIdle": max_idle.cloned().unwrap_or(json!(0))}));
    m.insert("deleg".into(), json!({"maxDepth": max_depth.cloned().unwrap_or(Value::Null), "narrowOnly": true, "mayTouch": touch}));
    m.insert("holes".into(), Value::Array(holes.into_iter().map(|x| x.1).collect()));
    m.insert("wildcardAck".into(), Value::Array(ack));
    canonicalize_goal(&Value::Object(m))
}

/// Panel requirements: k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families.
pub fn check_panel(readings: &[Value]) -> Vec<Value> {
    let mut out = vec![];
    if readings.len() < 3 {
        out.push(json!({"code": "too_few", "msg": "need at least 3 interpreters"}));
    }
    if !readings.iter().any(|r| crate::goal::js::truthy(Some(g(r, "deterministic")))) {
        out.push(json!({"code": "no_deterministic", "msg": "need at least one deterministic template interpreter"}));
    }
    let fams: Vec<Value> = readings.iter().filter(|r| !crate::goal::js::truthy(Some(g(r, "deterministic")))).map(|r| g(r, "family").clone()).collect();
    if uniq_v(&fams).len() < 2 {
        out.push(json!({"code": "no_family_diversity", "msg": "need at least two distinct model families"}));
    }
    out
}

/// `{merged, panelIssues, disagreementHoles, mass, signable}`: auto-signable only when the panel is valid and no hole remains.
pub fn n_version(readings: &[Value], opts: &QOpts, mass_threshold: Option<f64>) -> Res<Value> {
    let merged = meet(&readings.iter().map(|r| g(r, "goal").clone()).collect::<Vec<_>>())?;
    let panel_issues = check_panel(readings);
    let verb_sets: Vec<Vec<String>> = readings.iter().map(|r| arr(g(g(r, "goal"), "grants")).iter().map(|x| js_s(g(x, "verb"))).collect()).collect();
    let mut all_verbs: Vec<String> = vec![];
    for s in &verb_sets {
        for v in s {
            if !all_verbs.contains(v) {
                all_verbs.push(v.clone());
            }
        }
    }
    all_verbs.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
    let mut holes: Vec<Value> = vec![];
    for v in &all_verbs {
        if verb_sets.iter().any(|s| !s.contains(v)) {
            holes.push(json!({"hid": format!("nv:verb:{v}"), "q": format!("Only some readings allow \"{v}\". Should it be allowed at all?"), "domain": [], "affects": [], "global": false}));
        }
    }
    let mass = disagreement_mass(readings, opts.ont)?;
    if mass > mass_threshold.unwrap_or(0.0) {
        let q = questions(readings, opts)?;
        let text = q.first().map_or("The readings disagree.".to_string(), |x| st(g(x, "text")).to_string());
        holes.push(json!({"hid": "nv:split", "q": text, "domain": [], "affects": [], "global": true}));
    }
    let all: Vec<Value> = arr(g(&merged, "holes")).iter().cloned().chain(holes.iter().cloned()).collect();
    // `new Map(all.map(h => [h.hid, h]))`: the first position of a hid, the last hole
    let mut by: Vec<(Value, Value)> = vec![];
    for h in &all {
        match by.iter_mut().find(|(k, _)| seq_eq(k, g(h, "hid"))) {
            Some(e) => e.1 = h.clone(),
            None => by.push((g(h, "hid").clone(), h.clone())),
        }
    }
    let mut m = merged.as_object().cloned().unwrap_or_default();
    m.insert("holes".into(), Value::Array(by.into_iter().map(|x| x.1).collect()));
    Ok(json!({"merged": canonicalize_goal(&Value::Object(m))?, "panelIssues": panel_issues, "disagreementHoles": holes, "mass": mass,
        "signable": panel_issues.is_empty() && all.is_empty()}))
}
