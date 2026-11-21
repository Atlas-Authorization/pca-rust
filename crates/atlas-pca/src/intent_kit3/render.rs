//! Deterministic plain-language rendering of grants, caveats, questions and actions, the back-translation claim diff, and the
//! boundary witnesses (`render.ts`, `witnesses.ts`). Every sentence is a fixed template over the grant's own data. Uses the built-in
//! action catalogue (descriptions below) and the analyzer's admission oracle. Omega / verb spaces are plain JSON.
//!
//! shortcut: only the built-in catalogue is supported (no caller-supplied catalogue argument).
use super::slots::slots_to_policy;
use super::{js_str, member, to_number};
use crate::grants::u16key;
use crate::wallet_omega::{cell_rep, cell_stats, decode_cell, num_cells, verb_cell_count};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};

pub use crate::wallet_omega::label_of;

/// The one-line description of each built-in catalogue verb.
pub const BUILTIN_DESCRIPTIONS: [(&str, &str); 21] = [
    ("stripe.charge", "Charge a customer. Refundable in practice, but a charge is treated as final."),
    ("stripe.refund", "Returns money for a charge to the customer."),
    ("stripe.payout", "Moves funds from a Stripe balance to a bank account."),
    ("stripe.create_customer", "Creates a customer record."),
    ("gmail.send", "Sends an email to people outside your organisation."),
    ("gmail.draft", "Saves an email draft without sending it."),
    ("gmail.delete", "Permanently deletes a message."),
    ("github.read", "Reads files from a repository."),
    ("github.create_pr", "Opens a pull request, which is visible to everyone with access to the repository."),
    ("github.comment", "Posts a comment, visible to everyone with access to the repository."),
    ("github.merge_pr", "Merges a pull request, which can trigger deploys and other downstream effects."),
    ("github.delete_repo", "Deletes a repository and everything in it."),
    ("slack.post_message", "Posts a message that members of the channel can read."),
    ("slack.read", "Reads the message history of a channel."),
    ("calendar.create_event", "Creates an event and sends invitations to its attendees."),
    ("calendar.delete_event", "Deletes a calendar event."),
    ("files.read", "Reads files."),
    ("files.write", "Writes or overwrites files."),
    ("files.delete", "Deletes files."),
    ("http.get", "Fetches a URL."),
    ("http.post", "Posts a body to a URL."),
];

/// `(description, reversibility)` of a catalogued verb.
fn cat_get(verb: &str) -> Option<(&'static str, &'static str)> {
    let d = BUILTIN_DESCRIPTIONS.iter().find(|(v, _)| *v == verb)?.1;
    let r = crate::catalog_risk::BUILTIN_CATALOG.iter().find(|r| r.0 == verb)?.1;
    Some((d, r))
}

fn dash1(s: &str) -> String {
    s.replacen('_', "-", 1)
}

fn desc(d: &str) -> &str {
    d.strip_suffix('.').unwrap_or(d)
}

fn lower_first(s: &str) -> String {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}') => format!("{}{}", c.to_lowercase(), cs.as_str()),
        _ => s.to_string(),
    }
}

fn fmt(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => format!("\"{s}\""),
        Some(Value::Array(a)) => a.iter().map(|x| fmt(Some(x))).collect::<Vec<_>>().join(", "),
        o => js_str(o),
    }
}

/// `x.map(...)` over an array member: absent / null is empty, any other non-array throws.
fn arr<'a>(x: Option<&'a Value>) -> Result<&'a [Value], String> {
    match x {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err("x.map is not a function".into()),
    }
}

fn is_leaf(c: &Value) -> bool {
    c.is_object() && !crate::predicates::is_group_condition(c) && c.get("field").is_some_and(Value::is_string)
}

pub fn render_condition(c: &Value) -> Result<String, String> {
    let unread = || "an unreadable condition (not understood)".to_string();
    if !c.is_object() {
        return Ok(unread());
    }
    if crate::predicates::is_group_condition(c) {
        if c.get("all_of").is_some() {
            let parts: Result<Vec<String>, String> = arr(c.get("all_of"))?.iter().map(|x| render_condition(x).map(|s| format!("({s})"))).collect();
            return Ok(format!("all of: {}", parts?.join(" and ")));
        }
        if c.get("any_of").is_some() {
            let parts: Result<Vec<String>, String> = arr(c.get("any_of"))?.iter().map(|x| render_condition(x).map(|s| format!("({s})"))).collect();
            return Ok(format!("either {}", parts?.join(" or ")));
        }
        return Ok(format!("it is not the case that {}", render_condition(c.get("not").unwrap_or(&crate::wallet_omega::NULL))?));
    }
    if !is_leaf(c) {
        return Ok(unread());
    }
    let l = format!("the {}", label_of(c["field"].as_str().unwrap_or("")));
    let v = match c.get("ref") {
        Some(r) => format!("the {}", label_of(r.as_str().ok_or("path.split is not a function")?)),
        None => fmt(c.get("value")),
    };
    let op = c.get("op");
    if let Some(o) = op.and_then(Value::as_str) {
        let t = match o {
            "eq" => Some("is"),
            "ne" => Some("is not"),
            "in" => Some("is one of"),
            "nin" => Some("is none of"),
            "lt" => Some("is less than"),
            "lte" => Some("is at most"),
            "gt" => Some("is more than"),
            "gte" => Some("is at least"),
            "prefix" => Some("starts with"),
            "like" => Some("matches the pattern"),
            "matches" => Some("matches the regular expression"),
            "is_a" => Some("is of type"),
            "member_of" => Some("belongs to"),
            _ => None,
        };
        if let Some(t) = t {
            return Ok(format!("{l} {t} {v}"));
        }
        if o == "exists" {
            return Ok(if c.get("value") == Some(&Value::Bool(false)) { format!("{l} is absent") } else { format!("{l} is present") });
        }
    }
    Ok(format!("{l} has an unrecognised test \"{}\" (not understood)", js_str(op)))
}

fn render_resource(r: Option<&Value>) -> String {
    match r {
        None => "on any resource".into(),
        Some(Value::String(s)) if s == "*" => "on any resource".into(),
        Some(Value::String(s)) => {
            if let Some(re) = s.strip_prefix("re:") {
                format!("on resources matching the regular expression \"{re}\"")
            } else if let Some(p) = s.strip_suffix('*') {
                format!("on resources under \"{p}\"")
            } else {
                format!("only on resource \"{s}\"")
            }
        }
        Some(_) => "on an unreadable resource matcher (not understood)".into(),
    }
}

fn render_verb(v: Option<&Value>) -> String {
    let one = |x: &str| -> String {
        if x == "*" {
            return "ANY action of any connector".into();
        }
        match cat_get(x) {
            Some((d, r)) => format!("{} [{x}, {}]", lower_first(desc(d)), dash1(r)),
            None => format!("\"{x}\" [uncatalogued: treated as irreversible]"),
        }
    };
    match v {
        Some(Value::Array(a)) => a.iter().map(|x| one(&js_str(Some(x)))).collect::<Vec<_>>().join("; or "),
        o => one(&js_str(o)),
    }
}

/// `new Date(Number(t)).toISOString()`; an invalid time throws.
fn iso(t: Option<&Value>) -> Result<String, String> {
    let x = to_number(t);
    if x.is_nan() || x.abs() > 8.64e15 {
        return Err("Invalid time value".into());
    }
    let ms = x.trunc() as i64;
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    let ys = if (0..=9999).contains(&y) { format!("{y:04}") } else { format!("{}{:06}", if y > 0 { "+" } else { "-" }, y.abs()) };
    let (h, r) = (rem / 3_600_000, rem % 3_600_000);
    let (mi, r) = (r / 60_000, r % 60_000);
    Ok(format!("{ys}-{m:02}-{d:02}T{h:02}:{mi:02}:{:02}.{:03}Z", r / 1000, r % 1000))
}

pub fn render_caveat(c: &Value) -> Result<String, String> {
    let g = |k: &str| c.as_object().and_then(|m| m.get(k));
    let t = g("type");
    Ok(match t.and_then(Value::as_str) {
        Some("expires") => format!("The grant expires at {}.", iso(g("at"))?),
        Some("not_before") => format!("The grant is not valid before {}.", iso(g("at"))?),
        Some("rate") => format!("At most {} actions in any {} seconds.", js_str(g("max")), js_str(g("per_secs"))),
        Some("max_blast_radius") => format!("No action whose blast radius exceeds {} (on a 0\u{2013}1 scale).", js_str(g("max"))),
        Some("reversibility_max") => format!("Nothing more severe than \"{}\" (reversible < rate-limited < irreversible).", dash1(&js_str(g("class")))),
        Some("delegation_depth") => format!("It may be re-delegated at most {} level(s) deep.", js_str(g("max"))),
        Some("budget_alloc") => format!("A trust-budget allocation of {} is carried for sub-delegation.", js_str(g("limit"))),
        _ => format!("An unrecognised constraint of type \"{}\" (NOT UNDERSTOOD: do not rely on this grant until it is explained).", js_str(t)),
    })
}

fn norm_list<'a>(p: &'a Value, k: &str) -> &'a [Value] {
    match p.get(k) {
        Some(Value::Array(a)) => a,
        _ => &[],
    }
}

pub fn render_grant(policy: &Value) -> Result<String, String> {
    let (preds, caveats) = (norm_list(policy, "predicates"), norm_list(policy, "caveats"));
    if preds.is_empty() {
        return Ok("This grant allows nothing.".into());
    }
    let mut lines = vec!["The agent may do the following, and nothing else:".to_string()];
    for (i, p) in preds.iter().enumerate() {
        let w = member(p, "where")?;
        let conds: Vec<String> = arr(w)?.iter().map(render_condition).collect::<Result<_, _>>()?;
        let only = if conds.is_empty() { String::new() } else { format!(", only when {}", conds.join(", and ")) };
        lines.push(format!("{}. {}, {}{}.", i + 1, render_verb(member(p, "verb")?), render_resource(member(p, "resource")?), only));
    }
    if !caveats.is_empty() {
        lines.push("Limits that apply to everything above:".into());
        for c in caveats {
            lines.push(format!("- {}", render_caveat(c)?));
        }
    }
    Ok(lines.join("\n"))
}

fn arr_of(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn s_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn dim_count(d: &Value) -> usize {
    if s_of(&d["kind"]) == "num" {
        num_cells(d).len()
    } else {
        arr_of(&d["values"]).len()
    }
}

fn render_dim_cell(d: &Value, i: usize) -> Result<String, String> {
    let l = label_of(s_of(&d["path"]));
    if s_of(&d["kind"]) == "num" {
        let c = *num_cells(d).get(i).ok_or("cell index out of range")?;
        if c.0 == c.1 {
            return Ok(format!("{l} exactly {}", c.0));
        }
        return Ok(format!("any {l} from {} to {} (e.g. {})", c.0, c.1, if i > 0 { c.0 } else { c.1 }));
    }
    let v = arr_of(&d["values"]).get(i).ok_or("cell index out of range")?;
    let val = s_of(&v["value"]);
    Ok(match s_of(&v["kind"]) {
        "exact" => format!("{l} \"{val}\""),
        "prefix" => format!("a {l} under \"{val}\" (not otherwise named)"),
        _ => format!("a {l} not named anywhere in the grant or your request"),
    })
}

pub fn render_question(vs: &Value, cell: &[usize]) -> Result<String, String> {
    let verb = s_of(&vs["verb"]);
    let what = match cat_get(verb) {
        Some((d, _)) => format!("{} [{verb}]", desc(d)),
        None => format!("perform \"{verb}\""),
    };
    let mut parts = vec![];
    for (k, d) in arr_of(&vs["dims"]).iter().enumerate() {
        parts.push(render_dim_cell(d, *cell.get(k).ok_or("cell index out of range")?)?);
    }
    Ok(format!("Should the agent be allowed to: {what}{}?", if parts.is_empty() { String::new() } else { format!(", with {}", parts.join(", ")) }))
}

pub fn render_action(vs: &Value, values: &Value) -> Result<String, String> {
    let verb = s_of(&vs["verb"]);
    let what = match cat_get(verb) {
        Some((d, _)) => format!("{} [{verb}, {}]", desc(d), dash1(&js_str(vs.get("reversibility")))),
        None => format!("perform \"{verb}\" [uncatalogued: treated as irreversible]"),
    };
    let m = values.as_object().ok_or("Cannot convert undefined or null to object")?;
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by_key(|k| u16key(k));
    let parts: Vec<String> = keys
        .iter()
        .map(|k| {
            let v = &m[k.as_str()];
            format!("{} {}", label_of(k), if let Value::String(s) = v { format!("\"{s}\"") } else { js_str(Some(v)) })
        })
        .collect();
    Ok(format!("The agent wants to: {what}{}.", if parts.is_empty() { String::new() } else { format!(", with {}", parts.join(", ")) }))
}

// ---- admission oracle ----------------------------------------------------------------------------------------------------------

fn set_path(root: &mut Map<String, Value>, segs: &[&str], value: Value) {
    let mut cur = root;
    for k in &segs[..segs.len() - 1] {
        if !cur.get(*k).is_some_and(Value::is_object) {
            cur.insert((*k).to_string(), json!({}));
        }
        cur = cur.get_mut(*k).and_then(Value::as_object_mut).expect("object");
    }
    cur.insert(segs[segs.len() - 1].to_string(), value);
}

/// The outcome as the analyzer's concrete action.
pub fn outcome_to_action(vs: &Value, o: &Value) -> Value {
    let (mut params, mut env, mut subject) = (Map::new(), Map::new(), Map::new());
    let mut resource = "resource:any".to_string();
    if let Some(vals) = o.get("values").and_then(Value::as_object) {
        for (path, value) in vals {
            let segs: Vec<&str> = path.split('.').collect();
            if path == "action.resource" {
                resource = js_str(Some(value));
            } else if segs[0] == "action" && segs.len() > 2 && segs[1] == "params" {
                set_path(&mut params, &segs[2..], value.clone());
            } else if segs[0] == "env" && segs.len() > 1 {
                set_path(&mut env, &segs[1..], value.clone());
            } else if segs[0] == "subject" && segs.len() > 1 {
                set_path(&mut subject, &segs[1..], value.clone());
            }
        }
    }
    let mut a = Map::new();
    a.insert("verb".into(), o["verb"].clone());
    a.insert("resource".into(), json!(resource));
    a.insert("params".into(), Value::Object(params));
    if let Some(r) = vs.get("reversibility") {
        a.insert("reversibilityClass".into(), r.clone());
    }
    if !env.is_empty() {
        a.insert("env".into(), Value::Object(env));
    }
    if !subject.is_empty() {
        a.insert("subject".into(), Value::Object(subject));
    }
    Value::Object(a)
}

/// A compiled admission oracle for one policy.
pub struct Admitter {
    model: Value,
}

impl Admitter {
    pub fn new(policy: &Value) -> Result<Admitter, String> {
        Ok(Admitter { model: crate::analyzer::to_model(policy)? })
    }
    pub fn admits(&self, vs: &Value, o: &Value) -> Result<bool, String> {
        Ok(crate::analyzer::decide_action_model(&self.model, &outcome_to_action(vs, o))? != "deny")
    }
}

// ---- back-translation diff ------------------------------------------------------------------------------------------------------

/// The claim IR of a policy over the outcome space: verb by verb, dimension by dimension.
pub fn claims_of(policy: &Value, omega: &Value) -> Result<Value, String> {
    let a = Admitter::new(policy)?;
    let mut out = vec![];
    for vs in arr_of(&omega["verbs"]) {
        let n = verb_cell_count(vs);
        let mut acc: Vec<Vec<usize>> = vec![];
        for c in 0..n {
            let idx = decode_cell(vs, c);
            if a.admits(vs, &cell_rep(vs, &idx))? {
                acc.push(idx);
            }
        }
        let dims_v = arr_of(&vs["dims"]);
        let proj: Vec<BTreeSet<usize>> = (0..dims_v.len()).map(|k| acc.iter().map(|x| x[k]).collect()).collect();
        let box_count: usize = proj.iter().map(BTreeSet::len).product();
        let mut dims = vec![];
        for (k, d) in dims_v.iter().enumerate() {
            let s = &proj[k];
            let total = dim_count(d);
            let ids: Vec<usize> = s.iter().copied().collect();
            if s_of(&d["kind"]) == "num" {
                let cells = num_cells(d);
                let mut dc = json!({ "path": d["path"], "any": s.len() == total });
                if let (Some(f), Some(l)) = (ids.first(), ids.last()) {
                    dc["range"] = json!([cells[*f].0, cells[*l].1]);
                }
                dims.push(dc);
            } else {
                let vals = arr_of(&d["values"]);
                let names: Vec<Value> = ids
                    .iter()
                    .map(|&i| {
                        json!(if s_of(&vals[i]["kind"]) == "prefix" { format!("{}*", s_of(&vals[i]["value"])) } else { s_of(&vals[i]["value"]).to_string() })
                    })
                    .collect();
                dims.push(json!({ "path": d["path"], "any": s.len() == total, "values": names }));
            }
        }
        out.push(json!({ "verb": vs["verb"], "allowed": !acc.is_empty(), "boxShaped": acc.len() == box_count, "dims": dims }));
    }
    Ok(Value::Array(out))
}

fn dim_text(c: &Value) -> String {
    if !c.is_object() {
        return "anything".into();
    }
    if c["any"] == json!(true) {
        return "any value".into();
    }
    if let Some(r) = c.get("range").and_then(Value::as_array) {
        return format!("{} to {}", js_str(r.first()), js_str(r.get(1)));
    }
    match c.get("values").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => v.iter().map(|x| s_of(x).to_string()).collect::<Vec<_>>().join(", "),
        _ => "nothing".into(),
    }
}

struct Words {
    extra: Box<dyn Fn(&str) -> String>,
    missing: Box<dyn Fn(&str) -> String>,
    shape: Box<dyn Fn(&str) -> String>,
    dim: Box<dyn Fn(&str, &str, &str, &str) -> String>,
}

fn f64_of(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn diff_claims(g: &Value, s: &Value, w: &Words) -> Result<Value, String> {
    let mut out = vec![];
    for (i, gc) in arr_of(g).iter().enumerate() {
        let sc = s.get(i).ok_or("claim lists differ in length")?;
        let (ga, sa) = (gc["allowed"] == json!(true), sc["allowed"] == json!(true));
        let verb = s_of(&gc["verb"]);
        if ga && !sa {
            out.push(json!({ "verb": verb, "kind": "extra-verb", "text": (w.extra)(verb) }));
            continue;
        }
        if !ga && sa {
            out.push(json!({ "verb": verb, "kind": "missing-verb", "text": (w.missing)(verb) }));
            continue;
        }
        if !ga {
            continue;
        }
        if gc["boxShaped"] != sc["boxShaped"] {
            out.push(json!({ "verb": verb, "kind": "shape", "text": (w.shape)(verb) }));
        }
        for (k, gd) in arr_of(&gc["dims"]).iter().enumerate() {
            let sd = arr_of(&sc["dims"]).get(k).ok_or("claim lists differ in length")?;
            if gd == sd {
                continue;
            }
            let mut kind = "different";
            if let (Some(gr), Some(sr)) = (gd.get("range").and_then(Value::as_array), sd.get("range").and_then(Value::as_array)) {
                let (g0, g1, s0, s1) = (f64_of(&gr[0]), f64_of(&gr[1]), f64_of(&sr[0]), f64_of(&sr[1]));
                kind = if g0 <= s0 && g1 >= s1 {
                    "looser"
                } else if g0 >= s0 && g1 <= s1 {
                    "tighter"
                } else {
                    "different"
                };
            } else if let (Some(gv), Some(sv)) = (gd.get("values").and_then(Value::as_array), sd.get("values").and_then(Value::as_array)) {
                kind = if sv.iter().all(|v| gv.contains(v)) {
                    "looser"
                } else if gv.iter().all(|v| sv.contains(v)) {
                    "tighter"
                } else {
                    "different"
                };
            } else if gd["any"] == json!(true) && sd["any"] != json!(true) {
                kind = "looser";
            }
            let path = s_of(&gd["path"]);
            out.push(json!({ "verb": verb, "kind": kind, "path": path, "text": (w.dim)(verb, path, &dim_text(gd), &dim_text(sd)) }));
        }
    }
    Ok(Value::Array(out))
}

/// Render the grant and the intent slots into the same claim IR and list every difference.
pub fn back_translation_diff(grant: &Value, slots: &Value, omega: &Value) -> Result<Value, String> {
    let w = Words {
        extra: Box::new(|v| format!("The grant allows {v}, which your request did not mention.")),
        missing: Box::new(|v| format!("Your request mentions {v}, but the grant does not allow it.")),
        shape: Box::new(|v| format!("The grant's rule for {v} is a combination of cases that your request did not describe.")),
        dim: Box::new(|v, p, a, b| format!("For {v}, the grant allows {} {a}; your request said {b}.", label_of(p))),
    };
    diff_claims(&claims_of(grant, omega)?, &claims_of(&slots_to_policy(slots)?, omega)?, &w)
}

/// The same claim diff between two grants (two readings).
pub fn claim_diff(a: &Value, b: &Value, omega: &Value, names: Option<(&str, &str)>) -> Result<Value, String> {
    let (n0, n1) = names.unwrap_or(("the first reading", "the second reading"));
    let (n0, n1) = (n0.to_string(), n1.to_string());
    let (e0, e1) = (n0.clone(), n1.clone());
    let (m0, m1) = (n0.clone(), n1.clone());
    let (s0, s1) = (n0.clone(), n1.clone());
    let w = Words {
        extra: Box::new(move |v| format!("{e0} allows {v}; {e1} does not.")),
        missing: Box::new(move |v| format!("{m1} allows {v}; {m0} does not.")),
        shape: Box::new(move |v| format!("{s0} and {s1} describe {v} with differently shaped rules.")),
        dim: Box::new(move |v, p, x, y| format!("For {v}, {n0} allows {} {x}; {n1} allows {y}.", label_of(p))),
    };
    diff_claims(&claims_of(a, omega)?, &claims_of(b, omega)?, &w)
}

// ---- witnesses ------------------------------------------------------------------------------------------------------------------

fn encode_cell(vs: &Value, idx: &[usize]) -> usize {
    arr_of(&vs["dims"]).iter().enumerate().fold(0usize, |flat, (i, d)| flat * dim_count(d) + idx[i])
}

struct Pusher {
    seen: HashSet<String>,
    out: Vec<Value>,
}

impl Pusher {
    fn push(&mut self, vs: &Value, kind: &str, idx: &[usize], allows: bool, facet: String) -> Result<(), String> {
        let key = format!("{}|{}", s_of(&vs["verb"]), idx.iter().map(usize::to_string).collect::<Vec<_>>().join(","));
        if !self.seen.insert(key) {
            return Ok(());
        }
        self.out.push(json!({ "kind": kind, "side": if allows { "inside" } else { "outside" }, "verb": vs["verb"], "cell": idx,
            "outcome": cell_rep(vs, idx), "grantAllows": allows, "facet": facet, "question": render_question(vs, idx)? }));
        Ok(())
    }
}

/// Boundary, verb and unconstrained witness actions to ask the principal about.
pub fn boundary_witnesses(grant: &Value, omega: &Value) -> Result<Value, String> {
    let g = Admitter::new(grant)?;
    let mut p = Pusher { seen: HashSet::new(), out: vec![] };
    for vs in arr_of(&omega["verbs"]) {
        let verb = s_of(&vs["verb"]);
        let n = verb_cell_count(vs);
        let mut acc = vec![false; n];
        let mut mass = vec![0.0f64; n];
        let (mut typical, mut typical_out): (Option<usize>, Option<usize>) = (None, None);
        for c in 0..n {
            let idx = decode_cell(vs, c);
            acc[c] = g.admits(vs, &cell_rep(vs, &idx))?;
            mass[c] = cell_stats(vs, &idx).mass;
            if acc[c] && typical.map_or(true, |t| mass[c] > mass[t]) {
                typical = Some(c);
            }
            if typical_out.map_or(true, |t| mass[c] > mass[t]) {
                typical_out = Some(c);
            }
        }
        let Some(typical) = typical else {
            let idx = decode_cell(vs, typical_out.ok_or("verb space without cells")?);
            p.push(vs, "verb", &idx, false, format!("{verb}|verb"))?;
            continue;
        };
        let base = decode_cell(vs, typical);
        p.push(vs, "verb", &base, true, format!("{verb}|verb"))?;
        let dims = arr_of(&vs["dims"]);
        // facet -> (inside cell, outside cell, score)
        let mut best: HashMap<String, (Vec<usize>, Vec<usize>, f64)> = HashMap::new();
        for c in 0..n {
            if !acc[c] {
                continue;
            }
            let idx = decode_cell(vs, c);
            for (k, d) in dims.iter().enumerate() {
                let nk = dim_count(d);
                let is_num = s_of(&d["kind"]) == "num";
                let neigh: Vec<usize> = if is_num {
                    [idx[k].wrapping_sub(1), idx[k] + 1].into_iter().filter(|&x| x < nk).collect()
                } else {
                    (0..nk).filter(|&x| x != idx[k]).collect()
                };
                for x in neigh {
                    let mut j = idx.clone();
                    j[k] = x;
                    if acc[encode_cell(vs, &j)] {
                        continue;
                    }
                    let path = s_of(&d["path"]);
                    let facet = if is_num { format!("{verb}|{path}|{}~{}", x.min(idx[k]), x.max(idx[k])) } else { format!("{verb}|{path}|{x}") };
                    let shared = idx.iter().enumerate().filter(|(t, v)| *t != k && **v == base[*t]).count();
                    let score = shared as f64 * 10.0 + mass[c];
                    if best.get(&facet).map_or(true, |prev| score > prev.2) {
                        best.insert(facet, (idx.clone(), j, score));
                    }
                }
            }
        }
        let mut facets: Vec<&String> = best.keys().collect();
        facets.sort_by_key(|f| u16key(f));
        for f in facets {
            let b = &best[f];
            p.push(vs, "boundary", &b.0, true, f.clone())?;
            p.push(vs, "boundary", &b.1, false, f.clone())?;
        }
        for (k, d) in dims.iter().enumerate() {
            let nk = dim_count(d);
            if nk < 2 {
                continue;
            }
            let mut depends = false;
            'outer: for c in 0..n {
                let idx = decode_cell(vs, c);
                for x in 0..nk {
                    let mut j = idx.clone();
                    j[k] = x;
                    if acc[encode_cell(vs, &j)] != acc[c] {
                        depends = true;
                        break 'outer;
                    }
                }
            }
            if depends {
                continue;
            }
            let mut j = base.clone();
            if s_of(&d["kind"]) == "num" {
                j[k] = nk - 1;
            } else {
                j[k] = arr_of(&d["values"]).iter().position(|v| s_of(&v["kind"]) == "other").ok_or("categorical dimension without an other cell")?;
            }
            p.push(vs, "unconstrained", &j, true, format!("{verb}|{}|unconstrained", s_of(&d["path"])))?;
        }
    }
    Ok(Value::Array(p.out))
}

/// Ask an oracle (the principal) about each witness; a mismatch is where grant and intent disagree.
pub fn check_witnesses(witnesses: &[Value], oracle: &dyn Fn(&Value) -> bool) -> Value {
    let mism: Vec<Value> = witnesses.iter().filter(|w| oracle(w) != (w["grantAllows"] == json!(true))).cloned().collect();
    json!({ "questions": witnesses.len(), "mismatches": mism })
}
