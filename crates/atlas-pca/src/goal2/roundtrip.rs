//! Round-trip checks (`roundtrip.ts`): the lossless card tape, semantic widening mutations and the explainer + comparator detector,
//! measured by mutation and tighten-only (it can only escalate). An explainer is `lines -> text`; a comparator is
//! `(goal text, explanation) -> {equivalent, reason?}`; either may fail (an `Err`).
use super::interpret::extract_candidates;
use super::*;
use crate::goal::card::render_card;
use crate::goal::codec::{decode_goal, encode_goal};
use crate::goal::normalize::{canonicalize_goal, stable};
use serde_json::json;

pub const MUTATION_KINDS: [&str; 6] = ["widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant"];

pub type Explainer<'a> = &'a dyn Fn(&[String]) -> Res<String>;
pub type Comparator<'a> = &'a dyn Fn(&str, &str) -> Res<Value>;

/// decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape.
pub fn card_round_trips(gl: &Value) -> Res<bool> {
    Ok(stable(&decode_goal(&encode_goal(gl)?)?) == stable(gl))
}

/// The explainer sees ONLY the compiled card lines, never the goal text or the model's reasoning. `"ok"` or `"escalate"`.
pub fn round_trip(goal: &Value, goal_text: &str, explainer: Explainer, comparator: Comparator) -> &'static str {
    let run = || -> Res<bool> {
        let card = render_card(goal)?;
        let lines = strs(arr(&card["lines"]));
        let e = explainer(&lines)?;
        Ok(crate::goal::js::truthy(comparator(goal_text, &e)?.get("equivalent")))
    };
    match run() {
        Ok(true) => "ok",
        _ => "escalate",
    }
}

/// Offline reference explainer: the card lines themselves.
pub fn deterministic_explainer(lines: &[String]) -> Res<String> {
    Ok(lines.join("\n"))
}

/// `(\d+) ([A-Z]{3}) minor units` over a text: `(ccy, number)`.
fn card_amounts(s: &str) -> Vec<(String, f64)> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let tail = b" minor units";
        if b.get(j) == Some(&b' ') && j + 4 < b.len() && b[j + 1..j + 4].iter().all(|c| c.is_ascii_uppercase()) && b[j + 4..].starts_with(tail) {
            out.push((s[j + 1..j + 4].to_string(), s[i..j].parse::<f64>().unwrap_or(f64::INFINITY)));
            i = j + 4 + tail.len();
        } else {
            i = j;
        }
    }
    out
}
/// Offline reference comparator: the card lines judged lexically (ids, amounts). `{equivalent, reason?}`.
pub fn lexical_comparator(o: &Value, text: &str, explanation: &str) -> Res<Value> {
    let a = extract_candidates(text, o, None)?;
    let b = extract_candidates(explanation, o, None)?;
    let b_amounts = card_amounts(explanation);
    let ids = |x: &[String]| -> String {
        let mut u: Vec<String> = vec![];
        for s in x {
            if !u.contains(s) {
                u.push(s.clone());
            }
        }
        u.sort_by(|p, q| crate::goal::js::u16cmp(p, q));
        u.join(",")
    };
    if ids(&a.ids) != ids(&b.ids) {
        return Ok(json!({"equivalent": false, "reason": "ids differ"}));
    }
    // every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
    let wrote: Vec<String> = a.amounts.iter().map(|m| format!("{}{}", m.ccy, js_s(&m.minor))).collect();
    for (ccy, minor) in &b_amounts {
        let n = crate::intent_v2::js_number_string(*minor);
        if !wrote.contains(&format!("{ccy}{n}")) {
            return Ok(json!({"equivalent": false, "reason": format!("amount {ccy} {n} not stated by the principal")}));
        }
    }
    if !a.amounts.is_empty() && b_amounts.is_empty() {
        return Ok(json!({"equivalent": false, "reason": "no amount in the policy"}));
    }
    Ok(json!({"equivalent": true}))
}

fn scale(x: &Value, f: f64) -> Value {
    let k = st(g(g(x, "u"), "k"));
    if k == "money" || k == "count" {
        let mut m = x.as_object().cloned().unwrap_or_default();
        m.insert("n".into(), numv(nm(g(x, "n")) * f));
        Value::Object(m)
    } else {
        x.clone()
    }
}
fn map_lits(c: &Value, f: f64) -> Value {
    match st(g(c, "k")) {
        "cmp" => {
            let r = g(c, "r");
            let hit = st(g(r, "k")) == "lit" && st(g(g(r, "v"), "k")) == "q" && (st(g(c, "op")) == "lte" || st(g(c, "op")) == "lt");
            let mut m = c.as_object().cloned().unwrap_or_default();
            m.insert("r".into(), if hit { json!({"k": "lit", "v": {"k": "q", "q": scale(g(g(r, "v"), "q"), f)}}) } else { r.clone() });
            Value::Object(m)
        }
        "and" | "or" => {
            let mut m = c.as_object().cloned().unwrap_or_default();
            m.insert("a".into(), map_lits(g(c, "a"), f));
            m.insert("b".into(), map_lits(g(c, "b"), f));
            Value::Object(m)
        }
        _ => c.clone(),
    }
}

/// Semantic mutations that WIDEN the policy (or leave it equal); `None` when the goal has nothing to mutate.
pub fn mutate_goal(gl: &Value, kind: &str, ontology: &Value) -> Res<Option<Value>> {
    let mut x = gl.clone();
    match kind {
        "widen_cap" => {
            let b0 = match x["bounds"].get_mut(0) {
                Some(b) => b,
                None => return Ok(None),
            };
            let cap = scale(g(b0, "cap"), 10.0);
            b0["cap"] = cap;
            Ok(Some(x))
        }
        "widen_where" => {
            let idx = arr(g(&x, "grants")).iter().position(|y| jstr(&map_lits(g(y, "cond"), 10.0)) != jstr(g(y, "cond")));
            match idx {
                None => Ok(None),
                Some(i) => {
                    let c = map_lits(&x["grants"][i]["cond"].clone(), 10.0);
                    x["grants"][i]["cond"] = c;
                    Ok(Some(x))
                }
            }
        }
        "drop_prohibit" | "drop_bound" => {
            let f = if kind == "drop_prohibit" { "prohibits" } else { "bounds" };
            if arr(g(&x, f)).is_empty() {
                return Ok(None);
            }
            x[f].as_array_mut().ok_or("array")?.pop();
            Ok(Some(x))
        }
        "swap_resource" => {
            let idx = arr(g(&x, "grants")).iter().position(|y| st(g(g(y, "res"), "k")) == "exact");
            match idx {
                None => Ok(None),
                Some(i) => {
                    let id = format!("{}9", js_s(&x["grants"][i]["res"]["id"]));
                    x["grants"][i]["res"] = json!({"k": "exact", "id": id});
                    Ok(Some(x))
                }
            }
        }
        "add_grant" => {
            let have: Vec<Value> = arr(g(&x, "grants")).iter().map(|y| g(y, "verb").clone()).collect();
            let v = req_arr(g(ontology, "verbs"))?.iter().find(|y| {
                st(g(y, "effect")) != "read"
                    && !includes_v(&have, g(y, "id"))
                    && !arr(g(&x, "prohibits")).iter().any(|p| st(g(g(p, "target"), "k")) == "verb" && seq_eq(g(g(p, "target"), "verb"), g(y, "id")))
            });
            let v = match v {
                None => return Ok(None),
                Some(v) => g(v, "id").clone(),
            };
            x["grants"]
                .as_array_mut()
                .ok_or("grants")?
                .push(json!({"gid": "injected", "verb": v, "res": {"k": "any", "reason": "injected"}, "cond": {"k": "true"}}));
            x["wildcardAck"].as_array_mut().ok_or("wildcardAck")?.push(json!("injected"));
            Ok(Some(canonicalize_goal(&x)?))
        }
        _ => Ok(None),
    }
}

/// Fraction of semantic widenings the explainer + comparator pair flags (they can only escalate; this is a measured detector).
/// `cases`: `[{goal, text}]`.
pub fn measure_detection(cases: &[Value], ontology: &Value, explainer: Explainer, comparator: Comparator) -> Res<Vec<Value>> {
    let mut out = vec![];
    for kind in MUTATION_KINDS {
        let (mut applied, mut detected) = (0usize, 0usize);
        for c in cases {
            let m = match mutate_goal(g(c, "goal"), kind, ontology)? {
                Some(m) => m,
                None => continue,
            };
            applied += 1;
            if round_trip(&m, st(g(c, "text")), explainer, comparator) == "escalate" {
                detected += 1;
            }
        }
        out.push(json!({"kind": kind, "applied": applied, "detected": detected, "rate": if applied > 0 { numv(detected as f64 / applied as f64) } else { json!(0) }}));
    }
    Ok(out)
}
