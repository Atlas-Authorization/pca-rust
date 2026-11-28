//! Trait selectors and role-addressed parameters for the Goal IR (`selectors.ts`). A selector goal ("SelGoal") names a verb or a
//! trait class in its grants, prohibitions and bounds, and may name a parameter by ROLE; it is lowered against the PINNED catalog to
//! an ordinary goal (one grant per verb). Fail-closed rules: a grant verb with no unique parameter of a named role is dropped from
//! the grant (reported); a prohibition whose role term is unresolved for a verb applies to that verb unconditionally; a bound whose
//! role value cannot be resolved for every selected verb is a type error; an allow selector is positive (no `none_of`, at least
//! one trait); an unconfirmed verb carries `pca.unreviewed`: a class ALLOW never covers it, a class prohibition or bound over a
//! trait selector ALWAYS covers it; an unknown trait id is a type error. `compile_sel_goal` takes the core compiler as a parameter.
use super::*;
use crate::actions::{closure, core_registry, effective, Registry};
use crate::actions_kit::data::{core_pack_defs, domain_roles, domain_verb_bindings};
use crate::goal::card::{q as jq, render_card};
use crate::goal::js::key_order;
use serde_json::{json, Map};

pub const UNREVIEWED: &str = "pca.unreviewed";

fn by_verb(a: &Value, b: &Value) -> std::cmp::Ordering {
    crate::goal::js::u16cmp(st(g(a, "verb")), st(g(b, "verb")))
}
fn known_of(reg: &Registry) -> Value {
    let mut ids: Vec<String> = reg.traits.keys().cloned().collect();
    ids.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
    sv(ids)
}

/// The catalog of a pack of defs (verb ids and parameter paths are the defs' own): `{known, verbs}`.
pub fn sel_catalog_of_defs(defs: &[Value]) -> Res<Value> {
    let reg = core_registry();
    let mut verbs: Vec<Value> = vec![];
    for d in defs {
        let params = g(d, "params").as_object().cloned().unwrap_or_default();
        let mut names: Vec<&String> = params.keys().collect();
        names.sort_by(|a, b| crate::goal::js::u16cmp(a, b));
        let mut roles = Map::new();
        for name in names {
            if let Some(r) = params[name.as_str()].get("role").and_then(Value::as_str) {
                let e = roles.entry(r.to_string()).or_insert_with(|| json!([]));
                e.as_array_mut().ok_or("roles")?.push(json!(name));
            }
        }
        let eff = effective(d, &reg, None).map_err(|e| e.to_string())?;
        verbs.push(json!({"verb": g(d, "verb"), "traits": eff.closure, "roles": roles}));
    }
    verbs.sort_by(by_verb);
    Ok(json!({"known": known_of(&reg), "verbs": verbs}))
}

/// The catalog of one domain ontology: the NL short ids and NL parameter names, with the traits of the defs behind them.
pub fn sel_catalog_of_domain(domain: &str) -> Res<Value> {
    let reg = core_registry();
    let roles = domain_roles(domain)?;
    let all = domain_verb_bindings();
    let bs = all.get(domain).and_then(Value::as_array).ok_or_else(|| format!("unknown domain '{domain}'"))?;
    let defs = core_pack_defs();
    let mut verbs: Vec<Value> = vec![];
    for b in bs {
        let d = defs.iter().find(|x| seq_eq(g(x, "verb"), g(b, "verb"))).ok_or("domain binding names an unknown def")?;
        let eff = effective(d, &reg, None).map_err(|e| e.to_string())?;
        verbs.push(json!({"verb": g(b, "id"), "traits": eff.closure, "roles": roles.get(st(g(b, "id"))).cloned().unwrap_or(json!({}))}));
    }
    verbs.sort_by(by_verb);
    Ok(json!({"known": known_of(&reg), "verbs": verbs}))
}

/// Digest of the catalog (what `SelGoal.catDigest` must equal).
pub fn sel_catalog_digest(c: &Value) -> Res<String> {
    hc(&json!({"d": "atlas-pca/goal-sel-catalog/v1", "catalog": c}))
}
pub fn sel_goal_digest(gl: &Value) -> Res<String> {
    hc(&json!({"d": "atlas-pca/goal-ir-sel/v1", "goal": gl}))
}

// ---- G-A4: the verbs of a Class selector ------------------------------------------------------------------------------------------

fn has_all(ts: &Value, req: &Value) -> bool {
    arr(req).iter().all(|t| includes_v(arr(ts), t))
}
fn has_none(ts: &Value, ex: &Value) -> bool {
    arr(ex).iter().all(|t| !includes_v(arr(ts), t))
}
/// The verbs of the catalog, in catalog order, whose trait closure contains every `all_of` trait and none of the `none_of` traits.
pub fn class_verbs(cat: &Value, all_of: &Value, none_of: &Value) -> Vec<Value> {
    arr(g(cat, "verbs")).iter().filter(|v| has_all(g(v, "traits"), all_of) && has_none(g(v, "traits"), none_of)).map(|v| g(v, "verb").clone()).collect()
}
/// The verbs a class ALLOW covers: the class, minus every unconfirmed verb.
pub fn allow_class_verbs(cat: &Value, all_of: &Value, none_of: &Value) -> Vec<Value> {
    let mut n = arr(none_of).to_vec();
    n.push(json!(UNREVIEWED));
    class_verbs(cat, all_of, &Value::Array(n))
}
/// The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says.
pub fn float_class_verbs(cat: &Value, all_of: &Value, none_of: &Value) -> Vec<Value> {
    arr(g(cat, "verbs"))
        .iter()
        .filter(|v| includes_v(arr(g(v, "traits")), &json!(UNREVIEWED)) || (has_all(g(v, "traits"), all_of) && has_none(g(v, "traits"), none_of)))
        .map(|v| g(v, "verb").clone())
        .collect()
}

// ---- role resolution ----------------------------------------------------------------------------------------------------------------

fn decl_of<'a>(ont: &'a Value, verb: &Value) -> Option<&'a Value> {
    arr(g(ont, "verbs")).iter().find(|v| seq_eq(g(v, "verb"), verb))
}
fn info_of<'a>(cat: &'a Value, verb: &Value) -> Option<&'a Value> {
    arr(g(cat, "verbs")).iter().find(|v| seq_eq(g(v, "verb"), verb))
}
/// The one parameter of `verb` carrying `role`, with its declared type (`{path, ty}`); none, several or undeclared: `None`.
pub fn resolve_role(ont: &Value, cat: &Value, verb: &Value, role: &Value) -> Option<Value> {
    let (info, decl) = (info_of(cat, verb)?, decl_of(ont, verb)?);
    let paths = role.as_str().and_then(|r| g(info, "roles").get(r)).map(|p| arr(p).to_vec()).unwrap_or_default();
    if paths.len() != 1 {
        return None;
    }
    let p = arr(g(decl, "params")).iter().find(|x| seq_eq(g(x, "path"), &paths[0]))?;
    Some(json!({"path": g(p, "path"), "ty": g(p, "ty")}))
}
fn resolve_term(ont: &Value, cat: &Value, verb: &Value, t: &Value) -> Option<Value> {
    match st(g(t, "k")) {
        "param" => Some(json!({"k": "param", "path": g(t, "path"), "ty": g(t, "ty")})),
        "lit" => Some(json!({"k": "lit", "v": g(t, "v")})),
        "hist" => Some(json!({"k": "hist", "bid": g(t, "bid"), "u": g(t, "u")})),
        "role" => resolve_role(ont, cat, verb, g(t, "role")).map(|r| json!({"k": "param", "path": r["path"], "ty": r["ty"]})),
        _ => None,
    }
}
/// `None` as soon as one role term is unresolved for the verb.
fn resolve_cond(ont: &Value, cat: &Value, verb: &Value, c: &Value) -> Option<Value> {
    match st(g(c, "k")) {
        "true" => Some(json!({"k": "true"})),
        "cmp" => {
            let (l, r) = (resolve_term(ont, cat, verb, g(c, "l"))?, resolve_term(ont, cat, verb, g(c, "r"))?);
            Some(json!({"k": "cmp", "op": g(c, "op"), "l": l, "r": r}))
        }
        k @ ("and" | "or") => {
            let (a, b) = (resolve_cond(ont, cat, verb, g(c, "a"))?, resolve_cond(ont, cat, verb, g(c, "b"))?);
            Some(json!({"k": k, "a": a, "b": b}))
        }
        "not" => Some(json!({"k": "not", "c": resolve_cond(ont, cat, verb, g(c, "c"))?})),
        _ => None,
    }
}

// ---- the expansion --------------------------------------------------------------------------------------------------------------------

/// An expanded grant and the gid of the selector grant it came from.
struct Exp {
    src: Value,
    g: Value,
}
fn grant_verbs(cat: &Value, s: &Value) -> Vec<Value> {
    if st(g(s, "k")) == "verb" {
        vec![g(s, "verb").clone()]
    } else {
        allow_class_verbs(cat, g(s, "all_of"), g(s, "none_of"))
    }
}
fn expand_grants(ont: &Value, cat: &Value, gs: &Value, report: &mut Vec<Value>) -> Res<Vec<Exp>> {
    let mut out = vec![];
    for gr in req_arr(gs)? {
        let sel = g(gr, "sel");
        let verbs = grant_verbs(cat, sel);
        let mut dropped: Vec<Value> = vec![];
        for v in &verbs {
            match resolve_cond(ont, cat, v, g(gr, "cond")) {
                None => dropped.push(json!({"verb": v, "reason": "role_unresolved"})),
                Some(c) => {
                    let gid = if st(g(sel, "k")) == "class" { json!(format!("{}.{}", js_s(g(gr, "gid")), js_s(v))) } else { g(gr, "gid").clone() };
                    out.push(Exp { src: g(gr, "gid").clone(), g: json!({"gid": gid, "verb": v, "res": g(gr, "res"), "cond": c}) });
                }
            }
        }
        report.push(json!({"gid": g(gr, "gid"), "verbs": verbs, "dropped": dropped}));
    }
    Ok(out)
}
fn proh_verbs(ont: &Value, cat: &Value, t: &Value) -> Vec<Value> {
    match st(g(t, "k")) {
        "verb" => vec![g(t, "verb").clone()],
        "effect" => arr(g(ont, "verbs")).iter().filter(|v| seq_eq(g(v, "cls"), g(t, "cls"))).map(|v| g(v, "verb").clone()).collect(),
        _ => float_class_verbs(cat, g(t, "all_of"), g(t, "none_of")),
    }
}
fn expand_prohibits(ont: &Value, cat: &Value, ps: &Value, report: &mut Vec<Value>) -> Res<Vec<Value>> {
    let mut out = vec![];
    for p in req_arr(ps)? {
        let target = g(p, "target");
        let verbs = proh_verbs(ont, cat, target);
        let mut unconditional: Vec<Value> = vec![];
        for v in &verbs {
            let c = resolve_cond(ont, cat, v, g(p, "cond"));
            if c.is_none() {
                unconditional.push(v.clone());
            }
            let pid = if st(g(target, "k")) == "verb" { g(p, "pid").clone() } else { json!(format!("{}.{}", js_s(g(p, "pid")), js_s(v))) };
            out.push(json!({"pid": pid, "target": {"k": "verb", "verb": v}, "res": g(p, "res"), "cond": c.unwrap_or(json!({"k": "true"}))}));
        }
        report.push(json!({"pid": g(p, "pid"), "verbs": verbs, "unconditional": unconditional}));
    }
    Ok(out)
}
fn ids_of(es: &[Exp], srcs: &Value) -> Vec<Value> {
    es.iter().filter(|e| includes_v(arr(srcs), &e.src)).map(|e| g(&e.g, "gid").clone()).collect()
}
fn gids_of_verbs(es: &[Exp], vs: &[Value]) -> Vec<Value> {
    es.iter().filter(|e| includes_v(vs, g(&e.g, "verb"))).map(|e| g(&e.g, "gid").clone()).collect()
}
fn verbs_of_gids(es: &[Exp], gids: &[Value]) -> Vec<Value> {
    es.iter().filter(|e| includes_v(gids, g(&e.g, "gid"))).map(|e| g(&e.g, "verb").clone()).collect()
}
fn bound_role_verbs(ont: &Value, cat: &Value, es: &[Exp], s: &Value) -> Vec<Value> {
    match st(g(s, "k")) {
        "gids" => verbs_of_gids(es, &ids_of(es, g(s, "gids"))),
        "effect" => arr(g(ont, "verbs")).iter().filter(|v| seq_eq(g(v, "cls"), g(s, "cls"))).map(|v| g(v, "verb").clone()).collect(),
        _ => verbs_of_gids(es, &gids_of_verbs(es, &float_class_verbs(cat, g(s, "all_of"), g(s, "none_of")))),
    }
}
/// One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the
/// type is one. `(term, how)`.
fn bound_value(ont: &Value, cat: &Value, vs: &[Value], t: &Value) -> Option<(Value, &'static str)> {
    match st(g(t, "k")) {
        "param" => Some((json!({"k": "param", "path": g(t, "path"), "ty": g(t, "ty")}), "literal")),
        "lit" => Some((json!({"k": "lit", "v": g(t, "v")}), "literal")),
        "hist" => Some((json!({"k": "hist", "bid": g(t, "bid"), "u": g(t, "u")}), "literal")),
        "role" => {
            let mut rs: Vec<Value> = vec![];
            for v in vs {
                rs.push(resolve_role(ont, cat, v, g(t, "role"))?);
            }
            if rs.is_empty() {
                return None;
            }
            let same = |a: &Value, b: &Value| jstr(a) == jstr(b);
            if rs.iter().all(|r| seq_eq(&r["path"], &rs[0]["path"]) && same(&r["ty"], &rs[0]["ty"])) {
                return Some((json!({"k": "param", "path": rs[0]["path"], "ty": rs[0]["ty"]}), "shared_path"));
            }
            if rs.iter().all(|r| same(&r["ty"], &rs[0]["ty"])) {
                return Some((json!({"k": "param", "path": format!("@{}", js_s(g(t, "role"))), "ty": rs[0]["ty"]}), "role_key"));
            }
            None
        }
        _ => None,
    }
}
fn expand_bounds(ont: &Value, cat: &Value, es: &[Exp], bs: &Value, report: &mut Vec<Value>) -> Res<Vec<Value>> {
    let mut out = vec![];
    for b in req_arr(bs)? {
        let bsel = g(b, "sel");
        let (term, how) = match bound_value(ont, cat, &bound_role_verbs(ont, cat, es, bsel), g(b, "value")) {
            Some(x) => x,
            None => continue, // a type error (sel_reasons), never reached when the goal is well typed
        };
        let mk = |sel: Value| {
            json!({"bid": g(b, "bid"), "sel": sel, "agg": g(b, "agg"), "value": term, "key": g(b, "key"), "window": g(b, "window"),
            "scope": g(b, "scope"), "cap": g(b, "cap"), "onExceed": g(b, "onExceed")})
        };
        let gids: Vec<Value> = match st(g(bsel, "k")) {
            "gids" => ids_of(es, g(bsel, "gids")),
            "effect" => {
                out.push(mk(json!({"k": "effect", "cls": g(bsel, "cls")})));
                report.push(json!({"bid": g(b, "bid"), "gids": [], "dropped": false, "value": how}));
                continue;
            }
            _ => gids_of_verbs(es, &float_class_verbs(cat, g(bsel, "all_of"), g(bsel, "none_of"))),
        };
        if gids.is_empty() {
            report.push(json!({"bid": g(b, "bid"), "gids": [], "dropped": true, "value": how}));
            continue;
        }
        out.push(mk(json!({"k": "gids", "gids": gids})));
        report.push(json!({"bid": g(b, "bid"), "gids": gids, "dropped": false, "value": how}));
    }
    Ok(out)
}

/// Lower a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is [`sel_reasons`] + the core
/// typechecker. `{goal, report}`.
pub fn expand_sel_goal(sg: &Value, ont: &Value, cat: &Value) -> Res<Value> {
    let (mut rg, mut rp, mut rb) = (vec![], vec![], vec![]);
    let es = expand_grants(ont, cat, g(sg, "grants"), &mut rg)?;
    let prohibits = expand_prohibits(ont, cat, g(sg, "prohibits"), &mut rp)?;
    let bounds = expand_bounds(ont, cat, &es, g(sg, "bounds"), &mut rb)?;
    let mut deleg = g(sg, "deleg").as_object().cloned().ok_or("Cannot read properties of undefined (reading 'mayTouch')")?;
    deleg.insert("mayTouch".into(), Value::Array(ids_of(&es, g(g(sg, "deleg"), "mayTouch"))));
    let mut holes: Vec<Value> = vec![];
    for h in req_arr(g(sg, "holes"))? {
        let mut m = h.as_object().cloned().unwrap_or_default();
        m.insert("affects".into(), Value::Array(ids_of(&es, g(h, "affects"))));
        holes.push(Value::Object(m));
    }
    let goal = json!({"v": 1, "principal": g(sg, "principal"), "ontDigest": g(sg, "ontDigest"), "nlDigest": g(sg, "nlDigest"), "sources": g(sg, "sources"),
        "grants": es.iter().map(|e| e.g.clone()).collect::<Vec<_>>(), "prohibits": prohibits, "bounds": bounds, "validity": g(sg, "validity"), "deleg": deleg,
        "escalateOn": g(sg, "escalateOn"), "wildcardAck": ids_of(&es, g(sg, "wildcardAck")), "holes": holes});
    Ok(json!({"goal": goal, "report": {"grants": rg, "prohibits": rp, "bounds": rb}}))
}

// ---- typing of the selector layer -------------------------------------------------------------------------------------------------------

fn all_known(known: &Value, ids: &Value) -> bool {
    arr(ids).iter().all(|i| i.as_str().is_some_and(|s| !s.is_empty()) && includes_v(arr(known), i))
}
fn grant_sel_ok(cat: &Value, gr: &Value) -> bool {
    let s = g(gr, "sel");
    st(g(s, "k")) == "verb" || (!arr(g(s, "all_of")).is_empty() && arr(g(s, "none_of")).is_empty() && all_known(g(cat, "known"), g(s, "all_of")))
}
fn proh_sel_ok(cat: &Value, p: &Value) -> bool {
    let t = g(p, "target");
    st(g(t, "k")) != "trait" || (all_known(g(cat, "known"), g(t, "all_of")) && all_known(g(cat, "known"), g(t, "none_of")))
}
fn bound_sel_ok(cat: &Value, gs: &Value, b: &Value) -> bool {
    let s = g(b, "sel");
    match st(g(s, "k")) {
        "gids" => arr(g(s, "gids")).iter().all(|i| arr(gs).iter().any(|x| seq_eq(g(x, "gid"), i))),
        "effect" => true,
        _ => all_known(g(cat, "known"), g(s, "all_of")) && all_known(g(cat, "known"), g(s, "none_of")),
    }
}
fn sel_id_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The type reasons of the selector layer, preceded by the wire checks (`catalog_digest_mismatch`, `bad_id`). `[]` = well typed here.
pub fn sel_reasons(sg: &Value, ont: &Value, cat: &Value) -> Res<Vec<String>> {
    let mut out: Vec<String> = vec![];
    if !seq_eq(g(sg, "catDigest"), &Value::String(sel_catalog_digest(cat)?)) {
        out.push("catalog_digest_mismatch".into());
    }
    let mut ids: Vec<&Value> = vec![];
    ids.extend(req_arr(g(sg, "grants"))?.iter().map(|x| g(x, "gid")));
    ids.extend(req_arr(g(sg, "prohibits"))?.iter().map(|x| g(x, "pid")));
    ids.extend(req_arr(g(sg, "bounds"))?.iter().map(|x| g(x, "bid")));
    if !ids.iter().all(|i| sel_id_ok(&js_s(i))) {
        out.push("bad_id".into());
    }
    if !req_arr(g(cat, "verbs"))?.iter().all(|v| decl_of(ont, g(v, "verb")).is_some()) {
        out.push("catalog_mismatch".into());
    }
    if !arr(g(sg, "grants")).iter().all(|x| grant_sel_ok(cat, x)) {
        out.push("bad_grant_selector".into());
    }
    if !arr(g(sg, "prohibits")).iter().all(|p| proh_sel_ok(cat, p)) {
        out.push("bad_prohibit_selector".into());
    }
    if !arr(g(sg, "bounds")).iter().all(|b| bound_sel_ok(cat, g(sg, "grants"), b)) {
        out.push("bad_bound_selector".into());
    }
    let es = expand_grants(ont, cat, g(sg, "grants"), &mut vec![])?;
    if !arr(g(sg, "bounds")).iter().all(|b| bound_value(ont, cat, &bound_role_verbs(ont, cat, &es, g(b, "sel")), g(b, "value")).is_some()) {
        out.push("unresolved_role_bound".into());
    }
    Ok(out)
}

/// CompileX: selector reasons first (fail closed), then expansion and the core compiler (`compile`, required once the selector layer
/// passes). `{ok: true, policy, goal, report}` or `{ok: false, reasons}`.
pub fn compile_sel_goal(sg: &Value, ont: &Value, cat: &Value, compile: Option<&dyn Fn(&Value, &Value) -> Res<Value>>) -> Res<Value> {
    let rs = sel_reasons(sg, ont, cat)?;
    if !rs.is_empty() {
        return Ok(json!({"ok": false, "reasons": rs}));
    }
    let x = expand_sel_goal(sg, ont, cat)?;
    let f = compile.ok_or("compile_sel_goal needs a core compiler")?;
    let c = f(g(&x, "goal"), ont)?;
    if c["ok"] == true {
        Ok(json!({"ok": true, "policy": c["policy"], "goal": x["goal"], "report": x["report"]}))
    } else {
        Ok(json!({"ok": false, "reasons": c["reasons"]}))
    }
}

// ---- acts -----------------------------------------------------------------------------------------------------------------------------------

/// Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
/// supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value).
pub fn with_role_params(act: &Value, cat: &Value) -> Res<Value> {
    let mut params = Map::new();
    for (k, v) in g(act, "params").as_object().ok_or("Cannot convert undefined or null to object")? {
        if !k.starts_with('@') {
            params.insert(k.clone(), v.clone());
        }
    }
    if let Some(info) = info_of(cat, g(act, "verb")) {
        for (role, paths) in g(info, "roles").as_object().into_iter().flatten() {
            if let [p] = arr(paths) {
                if let Some(v) = p.as_str().and_then(|s| params.get(s)).cloned() {
                    params.insert(format!("@{role}"), v);
                }
            }
        }
    }
    let mut m = act.as_object().cloned().unwrap_or_default();
    m.insert("params".into(), Value::Object(params));
    Ok(Value::Object(m))
}

// ---- the policy card ----------------------------------------------------------------------------------------------------------------

fn selector_text(all_: &Value, none: &Value, reg: &Registry) -> String {
    let phrase = |i: &Value| -> String {
        match i.as_str().and_then(|s| reg.traits.get(s)) {
            Some(t) => t.card_phrase.clone(),
            None => js_s(i),
        }
    };
    let a = if !arr(all_).is_empty() {
        format!("every action that {}", arr(all_).iter().map(phrase).collect::<Vec<_>>().join(" and "))
    } else {
        "every action".to_string()
    };
    if !arr(none).is_empty() {
        format!("{a}, except those that {}", arr(none).iter().map(phrase).collect::<Vec<_>>().join(" or "))
    } else {
        a
    }
}
fn jqv(v: &Value) -> String {
    jq(Some(v))
}
fn jq_list(xs: &Value) -> String {
    arr(xs).iter().map(jqv).collect::<Vec<_>>().join(", ")
}

/// The card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with the verbs the
/// pinned catalog gives it, then the card of the expansion (the exact clauses that run). `{lines, warnings}`.
pub fn render_sel_card(sg: &Value, ont: &Value, cat: &Value) -> Res<Value> {
    let reg = core_registry();
    let x = expand_sel_goal(sg, ont, cat)?;
    let (goal, report) = (&x["goal"], &x["report"]);
    let mut lines: Vec<String> = vec![];
    let mut warnings: Vec<String> = vec![];
    for (i, gr) in arr(g(sg, "grants")).iter().enumerate() {
        let r = &report["grants"][i];
        let s = g(gr, "sel");
        if st(g(s, "k")) == "class" {
            lines.push(format!(
                "ALLOW {}: {} [{} verb(s) in the pinned catalog: {}]",
                jqv(g(gr, "gid")),
                selector_text(g(s, "all_of"), &json!([]), &reg),
                arr(&r["verbs"]).len(),
                jq_list(&r["verbs"])
            ));
        }
        for d in arr(&r["dropped"]) {
            warnings.push(format!(
                "grant {} does not cover {}: it has no unique parameter for a role the condition names",
                jqv(g(gr, "gid")),
                jqv(g(d, "verb"))
            ));
        }
    }
    for (i, p) in arr(g(sg, "prohibits")).iter().enumerate() {
        let r = &report["prohibits"][i];
        let t = g(p, "target");
        if st(g(t, "k")) == "trait" {
            lines.push(format!(
                "NEVER {}: {}, today {} verb(s) [{}]; it also covers every verb added to the catalog later",
                jqv(g(p, "pid")),
                selector_text(g(t, "all_of"), g(t, "none_of"), &reg),
                arr(&r["verbs"]).len(),
                jq_list(&r["verbs"])
            ));
        }
        for v in arr(&r["unconditional"]) {
            warnings.push(format!(
                "prohibition {} applies to {} without its condition: the verb has no unique parameter for a role the condition names",
                jqv(g(p, "pid")),
                jqv(v)
            ));
        }
    }
    for (i, b) in arr(g(sg, "bounds")).iter().enumerate() {
        let r = arr(&report["bounds"]).get(i);
        let s = g(b, "sel");
        if let Some(r) = r {
            if st(g(s, "k")) == "trait" {
                lines.push(format!(
                    "LIMIT {}: over {} ({} grant(s))",
                    jqv(g(b, "bid")),
                    selector_text(g(s, "all_of"), g(s, "none_of"), &reg),
                    arr(&r["gids"]).len()
                ));
            }
            if r["dropped"] == true {
                warnings.push(format!("limit {} selects no grant and bounds nothing", jqv(g(b, "bid"))));
            }
            if r["value"] == "role_key" {
                warnings.push(format!("limit {} sums a role the verbs carry on different parameters: the action must supply the role key", jqv(g(b, "bid"))));
            }
        }
    }
    let core = render_card(goal)?;
    lines.extend(strs(arr(&core["lines"])));
    warnings.extend(strs(arr(&core["warnings"])));
    Ok(json!({"lines": lines, "warnings": warnings}))
}

/// The closure of a trait id list under the core registry (a selector written with a parent trait covers the children by `implies`).
pub fn trait_closure(ids: &[String]) -> Res<Vec<String>> {
    closure(&core_registry(), ids).map_err(|e| e.to_string())
}

// ---- the carrier form ----------------------------------------------------------------------------------------------------------------

const ROLE_MARK: &str = "\u{1}role:";

fn carry_term(t: &Value) -> Value {
    match st(g(t, "k")) {
        "role" => json!({"k": "param", "path": format!("{ROLE_MARK}{}", js_s(g(t, "role"))), "ty": {"k": "s"}}),
        "param" => json!({"k": "param", "path": g(t, "path"), "ty": g(t, "ty")}),
        "lit" => json!({"k": "lit", "v": g(t, "v")}),
        _ => json!({"k": "hist", "bid": g(t, "bid"), "u": g(t, "u")}),
    }
}
fn carry_cond(c: &Value) -> Value {
    match st(g(c, "k")) {
        "true" => json!({"k": "true"}),
        "cmp" => json!({"k": "cmp", "op": g(c, "op"), "l": carry_term(g(c, "l")), "r": carry_term(g(c, "r"))}),
        k @ ("and" | "or") => json!({"k": k, "a": carry_cond(g(c, "a")), "b": carry_cond(g(c, "b"))}),
        _ => json!({"k": "not", "c": carry_cond(g(c, "c"))}),
    }
}
fn sel2(all_: &Value, none: &Value) -> String {
    let j = |x: &Value| arr(x).iter().map(js_s).collect::<Vec<_>>().join("\u{2}");
    format!("{}\u{1}{}", j(all_), j(none))
}

/// An ordinary Goal's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the extracted
/// model decodes it with its existing Goal decoder.
pub fn sel_carrier(sg: &Value) -> Res<Value> {
    let mut grants = vec![];
    for gr in req_arr(g(sg, "grants"))? {
        let s = g(gr, "sel");
        let verb = if st(g(s, "k")) == "verb" { format!("V\u{1}{}", js_s(g(s, "verb"))) } else { format!("C\u{1}{}", sel2(g(s, "all_of"), g(s, "none_of"))) };
        grants.push(json!({"gid": g(gr, "gid"), "verb": verb, "res": g(gr, "res"), "cond": carry_cond(g(gr, "cond"))}));
    }
    let mut prohibits = vec![];
    for p in req_arr(g(sg, "prohibits"))? {
        let t = g(p, "target");
        let verb = match st(g(t, "k")) {
            "verb" => format!("V\u{1}{}", js_s(g(t, "verb"))),
            "effect" => format!("E\u{1}{}", js_s(g(t, "cls"))),
            _ => format!("T\u{1}{}", sel2(g(t, "all_of"), g(t, "none_of"))),
        };
        prohibits.push(json!({"pid": g(p, "pid"), "res": g(p, "res"), "cond": carry_cond(g(p, "cond")), "target": {"k": "verb", "verb": verb}}));
    }
    let mut bounds = vec![];
    for b in req_arr(g(sg, "bounds"))? {
        let s = g(b, "sel");
        let sel = match st(g(s, "k")) {
            "gids" => json!({"k": "gids", "gids": g(s, "gids")}),
            "effect" => json!({"k": "effect", "cls": g(s, "cls")}),
            _ => json!({"k": "effect", "cls": format!("T\u{1}{}", sel2(g(s, "all_of"), g(s, "none_of")))}),
        };
        bounds.push(json!({"bid": g(b, "bid"), "key": g(b, "key"), "window": g(b, "window"), "scope": g(b, "scope"), "cap": g(b, "cap"),
            "onExceed": g(b, "onExceed"), "agg": g(b, "agg"), "value": carry_term(g(b, "value")), "sel": sel}));
    }
    Ok(json!({"v": 1, "principal": g(sg, "principal"), "ontDigest": g(sg, "ontDigest"), "nlDigest": g(sg, "nlDigest"), "sources": g(sg, "sources"),
        "grants": grants, "prohibits": prohibits, "bounds": bounds, "validity": g(sg, "validity"), "deleg": g(sg, "deleg"),
        "escalateOn": g(sg, "escalateOn"), "wildcardAck": g(sg, "wildcardAck"), "holes": g(sg, "holes")}))
}

/// The catalog tape the extracted model reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*, as
/// `[tag, value]` tokens (`"i"` an integer, `"s"` a string).
pub fn encode_sel_catalog(c: &Value) -> Res<Value> {
    fn strs_t(xs: &Value, out: &mut Vec<Value>) -> Res<()> {
        let a = req_arr(xs)?;
        out.push(json!(["i", a.len()]));
        for x in a {
            out.push(json!(["s", x]));
        }
        Ok(())
    }
    let mut out: Vec<Value> = vec![];
    strs_t(g(c, "known"), &mut out)?;
    let verbs = req_arr(g(c, "verbs"))?;
    out.push(json!(["i", verbs.len()]));
    for v in verbs {
        out.push(json!(["s", g(v, "verb")]));
        strs_t(g(v, "traits"), &mut out)?;
        let roles = g(v, "roles").as_object().ok_or("Cannot convert undefined or null to object")?;
        out.push(json!(["i", roles.len()]));
        for k in key_order(roles) {
            out.push(json!(["s", k]));
            strs_t(&roles[k.as_str()], &mut out)?;
        }
    }
    Ok(Value::Array(out))
}
