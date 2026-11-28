//! An independent, hand-written reading of the goal semantics `D_G` (`refsem.ts`), used to cross-check a compiled policy. It is NOT
//! the trusted decision function (the kernel is). Decisions are 0 deny, 1 escalate, 2 allow; condition truth is 0 false, 1 unknown,
//! 2 true. Goals, ontologies, actions and histories are JSON trees read with the reference's property semantics.
use super::js::*;
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::collections::HashSet;

type Res<T> = Result<T, String>;

fn b2t(b: bool) -> i64 {
    if b {
        2
    } else {
        0
    }
}
/// JavaScript `Number(x)` for a JSON-derived value.
fn to_number(x: U) -> f64 {
    match x {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => *b as i64 as f64,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = js_trim(s);
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(Value::Array(a)) => match a.len() {
            0 => 0.0,
            1 => to_number(Some(&a[0])),
            _ => f64::NAN,
        },
        Some(Value::Object(_)) => f64::NAN,
    }
}
/// `a < b` with the language's coercions (two strings compare by UTF-16 code units; otherwise numerically, NaN is false).
fn js_lt(a: U, b: U) -> bool {
    if let (Some(Value::String(x)), Some(Value::String(y))) = (a, b) {
        return u16cmp(x, y) == Ordering::Less;
    }
    to_number(a) < to_number(b)
}
fn js_gt(a: U, b: U) -> bool {
    js_lt(b, a)
}
fn num(x: f64) -> Value {
    json!(x)
}
/// `JSON.stringify(a) === JSON.stringify(b)` (an absent unit equals only an absent unit).
fn same_unit(a: U, b: U) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => crate::js_stringify(x) == crate::js_stringify(y),
        _ => false,
    }
}
fn has_own(o: U, k: U) -> Res<bool> {
    match o {
        None | Some(Value::Null) => Err("Cannot convert undefined or null to object".into()),
        Some(Value::Object(m)) => Ok(matches!(k, Some(Value::String(s)) if m.contains_key(s.as_str()))),
        _ => Ok(false),
    }
}
fn val(t: U, a: U, h: U) -> Res<Option<Value>> {
    let k = jget(t, "k")?;
    if is_str(k, "param") {
        let params = jget(a, "params")?;
        let path = jget(t, "path")?;
        return Ok(if has_own(params, path)? { own(params, &js_str(path))?.cloned() } else { None });
    }
    if is_str(k, "lit") {
        return Ok(jget(t, "v")?.cloned());
    }
    let aggs = jget(h, "aggs")?;
    let bid = jget(t, "bid")?;
    Ok(if has_own(aggs, bid)? { Some(json!({"k": "q", "q": own(aggs, &js_str(bid))?.cloned().unwrap_or(Value::Null)})) } else { None })
}
fn eq(x: U, y: U) -> Res<i64> {
    let (xk, yk) = (jget(x, "k")?, jget(y, "k")?);
    if is_str(xk, "q") && is_str(yk, "q") {
        let (xq, yq) = (jget(x, "q")?, jget(y, "q")?);
        return Ok(if same_unit(jget(xq, "u")?, jget(yq, "u")?) { b2t(strict_eq(jget(xq, "n")?, jget(yq, "n")?)) } else { 1 });
    }
    if is_str(xk, "s") && is_str(yk, "s") {
        return Ok(b2t(strict_eq(jget(x, "s")?, jget(y, "s")?)));
    }
    Ok(1)
}
fn lt(x: U, y: U) -> Res<i64> {
    if is_str(jget(x, "k")?, "q") && is_str(jget(y, "k")?, "q") {
        let (xq, yq) = (jget(x, "q")?, jget(y, "q")?);
        if same_unit(jget(xq, "u")?, jget(yq, "u")?) {
            return Ok(b2t(js_lt(jget(xq, "n")?, jget(yq, "n")?)));
        }
    }
    Ok(1)
}
fn in_set(x: U, y: U) -> Res<i64> {
    if !is_str(jget(y, "k")?, "set") {
        return Ok(1);
    }
    let mut acc = 0;
    for it in seq(jget(y, "items")?)?.iter() {
        acc = acc.max(eq(x, Some(it))?);
    }
    Ok(acc)
}
fn cmp(op: U, x: U, y: U) -> Res<i64> {
    if !truthy(x) || !truthy(y) {
        return Ok(1);
    }
    let is = |s: &str| is_str(op, s);
    Ok(if is("eq") {
        eq(x, y)?
    } else if is("ne") {
        2 - eq(x, y)?
    } else if is("lt") {
        lt(x, y)?
    } else if is("gte") {
        2 - lt(x, y)?
    } else if is("gt") {
        lt(y, x)?
    } else if is("lte") {
        2 - lt(y, x)?
    } else if is("in") {
        in_set(x, y)?
    } else {
        2 - in_set(x, y)?
    })
}
fn eval_c(c: U, a: U, h: U) -> Res<i64> {
    let k = jget(c, "k")?;
    if is_str(k, "true") {
        Ok(2)
    } else if is_str(k, "cmp") {
        let (l, r) = (val(jget(c, "l")?, a, h)?, val(jget(c, "r")?, a, h)?);
        cmp(jget(c, "op")?, l.as_ref(), r.as_ref())
    } else if is_str(k, "and") {
        Ok(eval_c(jget(c, "a")?, a, h)?.min(eval_c(jget(c, "b")?, a, h)?))
    } else if is_str(k, "or") {
        Ok(eval_c(jget(c, "a")?, a, h)?.max(eval_c(jget(c, "b")?, a, h)?))
    } else if is_str(k, "not") {
        Ok(2 - eval_c(jget(c, "c")?, a, h)?)
    } else {
        Err("unknown condition".into()) // the reference yields NaN here; refuse instead
    }
}
fn res_ok(s: U, ont: U, r: U) -> Res<bool> {
    let k = jget(s, "k")?;
    if is_str(k, "any") {
        Ok(true)
    } else if is_str(k, "exact") {
        Ok(strict_eq(r, jget(s, "id")?))
    } else if is_str(k, "oneof") {
        super::card::includes_checked(jget(s, "ids")?, r)
    } else if is_str(k, "related") {
        let (rel, anchor) = (jget(s, "rel")?, jget(s, "anchor")?);
        for x in seq(jget(ont, "rels")?)?.iter() {
            if strict_eq(jget(Some(x), "rel")?, rel) && strict_eq(jget(Some(x), "anchor")?, anchor) {
                return match jget(Some(x), "members")? {
                    None | Some(Value::Null) => Ok(false),
                    m => super::card::includes_checked(m, r),
                };
            }
        }
        Ok(false)
    } else if is_str(k, "all_of") {
        for p in seq(jget(s, "parts")?)?.iter() {
            if !res_ok(Some(p), ont, r)? {
                return Ok(false);
            }
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
fn verbs_of<'a>(ont: U<'a>, cls: U) -> Res<Vec<U<'a>>> {
    let mut out = Vec::new();
    for v in seq_members(jget(ont, "verbs")?)?.into_iter() {
        if strict_eq(jget(Some(v), "cls")?, cls) {
            out.push(jget(Some(v), "verb")?);
        }
    }
    Ok(out)
}
fn in_list(xs: &[U], x: U) -> bool {
    xs.iter().any(|e| strict_eq(*e, x))
}
fn in_scope(sc: U, a: U, x: U) -> Res<bool> {
    let k = jget(sc, "k")?;
    Ok(if is_str(k, "session") {
        strict_eq(jget(a, "sess")?, jget(x, "sess")?)
    } else if is_str(k, "principal") {
        strict_eq(jget(a, "prin")?, jget(x, "prin")?)
    } else if is_str(k, "org") {
        strict_eq(jget(a, "org")?, jget(x, "org")?)
    } else if is_str(k, "fleet") {
        let ag = jget(sc, "agents")?;
        super::card::includes_checked(ag, jget(a, "agent")?)? && super::card::includes_checked(ag, jget(x, "agent")?)?
    } else {
        false
    })
}
fn in_win(w: U, a: U, x: U) -> Res<bool> {
    let k = jget(w, "k")?;
    if is_str(k, "task") || is_str(k, "lifetime") {
        return Ok(true);
    }
    let (at, xt) = (jget(a, "t")?, jget(x, "t")?);
    if is_str(k, "sliding") {
        let lim = num(to_number(at) - to_number(jget(w, "ms")?));
        return Ok(js_gt(xt, Some(&lim)) && to_number(xt) <= to_number(at));
    }
    if is_str(k, "period") {
        let ms = jget(w, "ms")?;
        if !js_gt(ms, Some(&json!(0))) {
            return Ok(false);
        }
        let (m, t0) = (to_number(ms), to_number(jget(w, "t0")?));
        return Ok(((to_number(at) - t0) / m).floor() == ((to_number(xt) - t0) / m).floor());
    }
    Ok(false)
}

/// `{d, witness, prohibit}`: the decision, the first grant (goal order) whose own decision is Allow (null unless d = 2), and the
/// meet over the prohibitions alone (0 one fires, 1 one is unknown, 2 none applies).
pub fn ref_explain(g: &Value, ont: &Value, a: &Value, h: &Value) -> Res<Value> {
    let (g, ont, a, h) = (Some(g), Some(ont), Some(a), Some(h));
    let mut d: i64 = 2;
    let mut prohibit: i64 = 2;
    let mut witness: Option<Value> = None;
    let v = jget(g, "validity")?;
    let t = jget(a, "t")?;
    let deleg = jget(g, "deleg")?;
    let last = jget(h, "last")?;
    let depth = jget(a, "depth")?;
    let zero = json!(0);
    if js_lt(t, jget(v, "notBefore")?) || js_gt(t, jget(v, "notAfter")?) {
        d = 0;
    } else if js_gt(jget(v, "maxIdle")?, Some(&zero)) && to_number(last) >= 0.0 && js_gt(Some(&num(to_number(t) - to_number(last))), jget(v, "maxIdle")?) {
        d = 0;
    } else if js_lt(depth, Some(&zero)) || js_gt(depth, jget(deleg, "maxDepth")?) {
        d = 0;
    }
    for p in seq(jget(g, "prohibits")?)?.iter() {
        let tg = jget(Some(p), "target")?;
        let verbs: Vec<U> = if is_str(jget(tg, "k")?, "verb") { vec![jget(tg, "verb")?] } else { verbs_of(ont, jget(tg, "cls")?)? };
        let a_verb = jget(a, "verb")?;
        let m = b2t(in_list(&verbs, a_verb)).min(b2t(res_ok(jget(Some(p), "res")?, ont, jget(a, "res")?)?).min(eval_c(jget(Some(p), "cond")?, a, h)?));
        let pd = if m == 2 {
            0
        } else if m == 1 {
            1
        } else {
            2
        };
        d = d.min(pd);
        prohibit = prohibit.min(pd);
    }
    for c in seq(jget(g, "escalateOn")?)?.iter() {
        d = d.min(if eval_c(Some(c), a, h)? == 0 { 2 } else { 1 });
    }
    let mut best: i64 = 0;
    for gr in seq(jget(g, "grants")?)?.iter() {
        let gr_s = Some(gr);
        let gid = jget(gr_s, "gid")?;
        let verb_ok = strict_eq(jget(a, "verb")?, jget(gr_s, "verb")?)
            && (strict_eq(depth, Some(&zero)) || super::card::includes_checked(jget(deleg, "mayTouch")?, gid)?);
        let m = b2t(verb_ok).min(b2t(res_ok(jget(gr_s, "res")?, ont, jget(a, "res")?)?).min(eval_c(jget(gr_s, "cond")?, a, h)?));
        let mut gd = m;
        for b in seq(jget(g, "bounds")?)?.iter() {
            let bv = Some(b);
            let sel = jget(bv, "sel")?;
            let sel_k = jget(sel, "k")?;
            let gids_v = if is_str(sel_k, "gids") { jget(sel, "gids")? } else { None };
            let gid_list = if is_str(sel_k, "gids") { Some(seq(gids_v)?) } else { None };
            let gids: Vec<U> = gid_list.as_ref().map_or_else(Vec::new, |l| l.iter().map(Some).collect());
            let verbs: Vec<U> = if is_str(sel_k, "effect") { verbs_of(ont, jget(sel, "cls")?)? } else { vec![] };
            if !(in_list(&gids, gid) || in_list(&verbs, jget(a, "verb")?)) {
                continue;
            }
            let mut items: Vec<U> = Vec::new();
            for x in seq_members(jget(h, "adms")?)?.into_iter() {
                let xa = jget(Some(x), "act")?;
                if (in_list(&gids, jget(Some(x), "gid")?) || in_list(&verbs, jget(xa, "verb")?))
                    && in_scope(jget(bv, "scope")?, a, xa)?
                    && in_win(jget(bv, "window")?, a, xa)?
                {
                    items.push(xa);
                }
            }
            items.push(a);
            let cap = jget(bv, "cap")?;
            let agg = jget(bv, "agg")?;
            let cap_n = jget(cap, "n")?;
            let ex: i64 = if is_str(agg, "count") {
                b2t(js_gt(Some(&json!(items.len())), cap_n))
            } else if is_str(agg, "sum") || is_str(agg, "max") {
                let mut xs: Vec<f64> = Vec::new();
                let mut ok = true;
                for it in &items {
                    let value = val(jget(bv, "value")?, *it, h)?;
                    let vv = value.as_ref();
                    if !truthy(vv) || !is_str(jget(vv, "k")?, "q") || !same_unit(jget(jget(vv, "q")?, "u")?, jget(cap, "u")?) {
                        ok = false;
                        break;
                    }
                    xs.push(to_number(jget(jget(vv, "q")?, "n")?));
                }
                if !ok {
                    1
                } else if is_str(agg, "sum") {
                    b2t(js_gt(Some(&num(xs.iter().sum::<f64>())), cap_n))
                } else if xs.is_empty() {
                    1
                } else {
                    let mx = if xs.iter().any(|x| x.is_nan()) { f64::NAN } else { xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max) };
                    b2t(js_gt(Some(&num(mx)), cap_n))
                }
            } else {
                let key = jget(bv, "key")?;
                let mut ks: HashSet<String> = HashSet::new();
                let mut ok = true;
                for it in &items {
                    let ip = jget(*it, "params")?;
                    if !has_own(ip, key)? {
                        ok = false;
                        break;
                    }
                    ks.insert(q_json(own(ip, &js_str(key))?));
                }
                if ok {
                    b2t(js_gt(Some(&json!(ks.len())), cap_n))
                } else {
                    1
                }
            };
            let imposed = if ex == 2 {
                if is_str(jget(bv, "onExceed")?, "deny") {
                    0
                } else {
                    1
                }
            } else if ex == 1 {
                1
            } else {
                2
            };
            gd = gd.min(imposed);
        }
        if gd == 2 && witness.is_none() {
            witness = gid.cloned();
        }
        best = best.max(gd);
    }
    d = d.min(best);
    Ok(json!({"d": d, "witness": if d == 2 { witness.unwrap_or(Value::Null) } else { Value::Null }, "prohibit": prohibit}))
}
fn q_json(x: U) -> String {
    x.map(crate::js_stringify).unwrap_or_else(|| "undefined".into())
}
/// The reference decision: 0 deny, 1 escalate, 2 allow.
pub fn ref_decide(g: &Value, ont: &Value, a: &Value, h: &Value) -> Res<i64> {
    Ok(ref_explain(g, ont, a, h)?["d"].as_i64().unwrap_or(0))
}
