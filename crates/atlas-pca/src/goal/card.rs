//! The human-readable PolicyCard text (`card.ts`): a fixed phrase table over the IR, every clause with its exact numbers. The
//! lossless guarantee (G-T10) is on the token tape; this text is a pure function of the same goal and prints every field the tape
//! carries. Goals are JSON trees; a member of an absent or null value is a refusal, as the reference's property read throws.
use super::js::*;
use serde_json::{json, Value};

type Res<T> = Result<T, String>;

/// `JSON.stringify(x)` interpolated into a template (`undefined` for an absent member).
pub fn q(x: U) -> String {
    match x {
        None => "undefined".into(),
        Some(v) => crate::js_stringify(v),
    }
}
fn list_q(xs: U) -> Res<String> {
    Ok(seq(xs)?.iter().map(|x| q(Some(x))).collect::<Vec<_>>().join(", "))
}
pub fn unit(u: U) -> Res<String> {
    let k = jget(u, "k")?;
    Ok(if is_str(k, "money") { format!("{} minor units", js_str(jget(u, "ccy")?)) } else { js_str(k) })
}
pub fn quantity(x: U) -> Res<String> {
    let n = js_str(jget(x, "n")?);
    Ok(format!("{n} {}", unit(jget(x, "u")?)?))
}
pub fn value(v: U) -> Res<String> {
    let k = jget(v, "k")?;
    if is_str(k, "q") {
        quantity(jget(v, "q")?)
    } else if is_str(k, "s") {
        Ok(q(jget(v, "s")?))
    } else {
        let items: Res<Vec<String>> = seq(jget(v, "items")?)?.iter().map(|i| value(Some(i))).collect();
        Ok(format!("{{{}}}", items?.join(", ")))
    }
}
pub fn term(t: U) -> Res<String> {
    let k = jget(t, "k")?;
    if is_str(k, "param") {
        let path = q(jget(t, "path")?);
        let ty = jget(t, "ty")?;
        let tys = if is_str(jget(ty, "k")?, "q") { unit(jget(ty, "u")?)? } else { "text".to_string() };
        Ok(format!("param {path} ({tys})"))
    } else if is_str(k, "lit") {
        value(jget(t, "v")?)
    } else {
        Ok(format!("running total of bound {} ({})", q(jget(t, "bid")?), unit(jget(t, "u")?)?))
    }
}
fn op_word(op: U) -> String {
    let w = match op {
        Some(Value::String(s)) => match s.as_str() {
            "eq" => "=",
            "ne" => "!=",
            "lt" => "<",
            "lte" => "<=",
            "gt" => ">",
            "gte" => ">=",
            "in" => "is one of",
            "nin" => "is none of",
            _ => "undefined",
        },
        _ => "undefined",
    };
    w.to_string()
}
/// A condition as text; an unknown discriminant renders as `undefined` (the reference switch has no default).
pub fn cond(c: U) -> Res<String> {
    let k = jget(c, "k")?;
    if is_str(k, "true") {
        Ok("always".into())
    } else if is_str(k, "cmp") {
        let l = term(jget(c, "l")?)?;
        let o = op_word(jget(c, "op")?);
        Ok(format!("{l} {o} {}", term(jget(c, "r")?)?))
    } else if is_str(k, "and") {
        Ok(format!("({}) AND ({})", cond(jget(c, "a")?)?, cond(jget(c, "b")?)?))
    } else if is_str(k, "or") {
        Ok(format!("({}) OR ({})", cond(jget(c, "a")?)?, cond(jget(c, "b")?)?))
    } else if is_str(k, "not") {
        Ok(format!("NOT ({})", cond(jget(c, "c")?)?))
    } else {
        Ok("undefined".into())
    }
}
pub fn res(s: U) -> Res<String> {
    let k = jget(s, "k")?;
    if is_str(k, "exact") {
        Ok(format!("exactly {}", q(jget(s, "id")?)))
    } else if is_str(k, "oneof") {
        Ok(format!("one of [{}]", list_q(jget(s, "ids")?)?))
    } else if is_str(k, "related") {
        Ok(format!("{} of {}", js_str(jget(s, "rel")?), q(jget(s, "anchor")?)))
    } else if is_str(k, "all_of") {
        let parts: Res<Vec<String>> = seq(jget(s, "parts")?)?.iter().map(|p| res(Some(p))).collect();
        Ok(format!("ALL OF ({})", parts?.join(" AND ")))
    } else {
        Ok(format!("ANY RESOURCE (reason: {})", q(jget(s, "reason")?)))
    }
}
pub fn win(w: U) -> Res<String> {
    let k = jget(w, "k")?;
    Ok(if is_str(k, "task") {
        "per task".into()
    } else if is_str(k, "lifetime") {
        "over the lifetime".into()
    } else if is_str(k, "sliding") {
        format!("in any {} ms window", js_str(jget(w, "ms")?))
    } else {
        format!("per {} ms period starting at {}", js_str(jget(w, "ms")?), js_str(jget(w, "t0")?))
    })
}
pub fn scope(s: U) -> Res<String> {
    let k = jget(s, "k")?;
    if is_str(k, "fleet") {
        Ok(format!("fleet [{}]", list_q(jget(s, "agents")?)?))
    } else {
        Ok(js_str(k))
    }
}
pub fn grant_line(x: U) -> Res<String> {
    Ok(format!("ALLOW {}: verb {} on {} when {}", q(jget(x, "gid")?), q(jget(x, "verb")?), res(jget(x, "res")?)?, cond(jget(x, "cond")?)?))
}
pub fn prohibit_line(x: U) -> Res<String> {
    let t = jget(x, "target")?;
    let tgt =
        if is_str(jget(t, "k")?, "verb") { format!("verb {}", q(jget(t, "verb")?)) } else { format!("every verb of effect class {}", q(jget(t, "cls")?)) };
    Ok(format!("NEVER {}: {tgt} on {} when {}", q(jget(x, "pid")?), res(jget(x, "res")?)?, cond(jget(x, "cond")?)?))
}
pub fn bound_line(b: U) -> Res<String> {
    let sel = jget(b, "sel")?;
    let over =
        if is_str(jget(sel, "k")?, "gids") { format!("grants [{}]", list_q(jget(sel, "gids")?)?) } else { format!("effect class {}", q(jget(sel, "cls")?)) };
    let agg = jget(b, "agg")?;
    let mid = if is_str(agg, "count") {
        String::new()
    } else if is_str(agg, "distinct") {
        format!(" of {}", q(jget(b, "key")?))
    } else {
        format!(" of {}", term(jget(b, "value")?)?)
    };
    let exc = if is_str(jget(b, "onExceed")?, "deny") { "deny" } else { "ask the principal" };
    Ok(format!(
        "LIMIT {}: {}{mid} over {over}, {}, scope {}, at most {}; beyond that: {exc}",
        q(jget(b, "bid")?),
        js_str(agg),
        win(jget(b, "window")?)?,
        scope(jget(b, "scope")?)?,
        quantity(jget(b, "cap")?)?
    ))
}
/// `x > 0` with the reference's coercion (an absent value is false).
fn positive(x: U) -> bool {
    match x {
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f > 0.0),
        Some(Value::String(s)) => js_trim(s).parse::<f64>().is_ok_and(|f| f > 0.0),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}
pub fn validity_line(v: U) -> Res<String> {
    let mi = jget(v, "maxIdle")?;
    let idle = if positive(mi) { format!("{} ms", js_str(mi)) } else { "none".to_string() };
    Ok(format!("VALID from {} to {}; idle limit {idle}", js_str(jget(v, "notBefore")?), js_str(jget(v, "notAfter")?)))
}
pub fn delegation_line(d: U) -> Res<String> {
    Ok(format!(
        "DELEGATION depth at most {}, narrow only {}, delegates may use grants [{}]",
        js_str(jget(d, "maxDepth")?),
        js_str(jget(d, "narrowOnly")?),
        list_q(jget(d, "mayTouch")?)?
    ))
}
pub fn escalate_line(c: U) -> Res<String> {
    Ok(format!("ASK THE PRINCIPAL when {}", cond(c)?))
}
pub fn hole_line(h: U) -> Res<String> {
    let aff = if truthy(jget(h, "global")?) { "everything".to_string() } else { format!("[{}]", list_q(jget(h, "affects")?)?) };
    Ok(format!("UNRESOLVED {}: {} options [{}] affects {aff}", q(jget(h, "hid")?), q(jget(h, "q")?), list_q(jget(h, "domain")?)?))
}
/// One line per clause, in the goal's canonical order: `{lines, warnings}`. `warnings` lists what the principal must look at twice.
pub fn render_card(g: &Value) -> Res<Value> {
    let g = Some(g);
    let mut lines: Vec<String> = vec![format!(
        "Goal v{} for principal {}; ontology {}; request text digest {}",
        js_str(jget(g, "v")?),
        q(jget(g, "principal")?),
        q(jget(g, "ontDigest")?),
        q(jget(g, "nlDigest")?)
    )];
    let mut warnings: Vec<String> = Vec::new();
    for s in seq(jget(g, "sources")?)?.iter() {
        lines.push(format!("Source {}", q(Some(s))));
    }
    for x in seq(jget(g, "grants")?)?.iter() {
        lines.push(grant_line(Some(x))?);
        if is_str(jget(jget(Some(x), "res")?, "k")?, "any") {
            let ack = includes_checked(jget(g, "wildcardAck")?, jget(Some(x), "gid")?)?;
            warnings.push(format!(
                "grant {} applies to every resource{}",
                q(jget(Some(x), "gid")?),
                if ack { " (acknowledged)" } else { " (NOT acknowledged)" }
            ));
        }
    }
    for x in seq(jget(g, "prohibits")?)?.iter() {
        lines.push(prohibit_line(Some(x))?);
    }
    for b in seq(jget(g, "bounds")?)?.iter() {
        lines.push(bound_line(Some(b))?);
    }
    lines.push(validity_line(jget(g, "validity")?)?);
    lines.push(delegation_line(jget(g, "deleg")?)?);
    for c in seq(jget(g, "escalateOn")?)?.iter() {
        lines.push(escalate_line(Some(c))?);
    }
    for a in seq(jget(g, "wildcardAck")?)?.iter() {
        lines.push(format!("Wildcard acknowledged for {}", q(Some(a))));
    }
    let holes = seq(jget(g, "holes")?)?;
    for h in holes.iter() {
        lines.push(hole_line(Some(h))?);
    }
    if !holes.is_empty() {
        warnings.push("this goal has unresolved questions and cannot be signed".into());
    }
    Ok(json!({"lines": lines, "warnings": warnings}))
}
/// `xs.includes(x)`: an array or string; any other receiver throws.
pub fn includes_checked(xs: U, x: U) -> Res<bool> {
    match xs {
        Some(Value::Array(_)) | Some(Value::String(_)) => Ok(includes(xs, x)),
        _ => Err("includes is not a function".into()),
    }
}
