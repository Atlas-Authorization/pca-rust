//! Authoring forms of an ActionDef (native port of `author.ts` of the reference): the param and resource shorthands, the entry
//! expansion, the document loader over an already parsed value and the typed builder. One action has one digest whichever way it
//! was written; every expanded def is checked by `validate_def`.
//! The text loader (`load_actions_text`, with source positions) is in `actions_kit_ops::yaml`. The business-rules block of an action
//! (`rules:`) is validated by the rules port, so the loader here takes that check as a parameter ([`load_actions_value_with`]);
//! [`load_actions_value`] has none and refuses
//! an action that carries `rules` rather than accept it unchecked.

use serde_json::{json, Map, Value};

use super::{arr, get, js_trim, opt};
use crate::actions::{json_profile_error, validate_def, ACTION_DEF_KIND};
use crate::intent_v2::js_value_string;

pub const MAX_AUTHOR_BYTES: usize = 1 << 20;
pub const IDEMPOTENCY_PARAM: &str = "idempotency_key";
/// Effects whose repeat is not harmless: an absent idempotency declaration gets a key parameter.
pub const AUTO_IDEMPOTENT_EFFECTS: [&str; 5] = ["send", "pay", "create", "provision", "publish"];
const PROVENANCE_LEVELS: [&str; 3] = ["first_party", "tool", "agent"];
const RESOURCE_SCOPES: [&str; 4] = ["one", "set", "tenant", "global"];
const BLAST_RADII: [&str; 4] = ["one", "bounded", "tenant", "global"];
const ID_CLASSES: [&str; 6] = ["digits", "hex", "alnum", "slug", "uuid", "any_safe"];
const ENTRY_KEYS: [&str; 22] = [
    "v",
    "kind",
    "verb",
    "aliases",
    "title",
    "description",
    "effects",
    "resource",
    "params",
    "reversibility",
    "blast",
    "side_effects",
    "idempotency",
    "context",
    "traits",
    "audience",
    "compensates",
    "bindings",
    "examples",
    "review",
    "source",
    "since",
];
const FILE_KEYS: [&str; 3] = ["ns", "since", "actions"];

/// The business-rules check of the loader: `(def, rules) -> Some(error)`.
pub type RulesCheck<'a> = &'a dyn Fn(&Value, &Value) -> Option<String>;

fn bad_shorthand<T>(m: String) -> Result<T, String> {
    Err(m)
}

// ---- param shorthands ---------------------------------------------------------------------------------------------------------

type Named = Vec<(String, String)>;

fn split_args(s: &str) -> (Vec<String>, Named) {
    let (mut pos, mut named): (Vec<String>, Named) = (vec![], vec![]);
    for raw in s.split(',') {
        let a = js_trim(raw);
        if a.is_empty() {
            continue;
        }
        match a.find('=') {
            Some(eq) if eq > 0 => {
                let (k, v) = (js_trim(&a[..eq]).to_string(), js_trim(&a[eq + 1..]).to_string());
                match named.iter_mut().find(|(n, _)| *n == k) {
                    Some(slot) => slot.1 = v,
                    None => named.push((k, v)),
                }
            }
            _ => pos.push(a.to_string()),
        }
    }
    (pos, named)
}

fn named_get<'a>(n: &'a Named, k: &str) -> Option<&'a str> {
    n.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

/// `/^-?\d{1,15}$/` then `Number(s)`.
fn int_arg(s: Option<&str>, what: &str) -> Result<Option<i64>, String> {
    let Some(s) = s else { return Ok(None) };
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || digits.len() > 15 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return bad_shorthand(format!("{what} must be an integer, got '{s}'"));
    }
    Ok(Some(s.parse::<i64>().map_err(|_| format!("{what} must be an integer, got '{s}'"))?))
}

fn only(pos: &[String], named: &Named, n: usize, names: &[&str], shorthand: &str) -> Result<(), String> {
    if pos.len() > n {
        return bad_shorthand(format!("'{shorthand}' takes at most {n} positional argument(s)"));
    }
    for (k, _) in named {
        if !names.contains(&k.as_str()) {
            return bad_shorthand(format!("'{shorthand}' has no option '{k}'"));
        }
    }
    Ok(())
}

fn list_arg(s: &str, shorthand: &str) -> Result<Vec<String>, String> {
    let xs: Vec<String> = s.split('|').map(|x| js_trim(x).to_string()).collect();
    if xs.iter().any(|x| x.is_empty()) {
        return bad_shorthand(format!("'{shorthand}' needs values separated by |"));
    }
    Ok(xs)
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}

/// `^([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\((.*)\))?(\?)?$` over the trimmed source: (name, inner, optional).
fn split_shorthand(s: &str) -> Option<(&str, Option<&str>, bool)> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i].is_ascii_lowercase() || b[i] == b'_') {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    if i < b.len() && b[i] == b':' {
        let mut j = i + 1;
        let seg = |mut j: usize| {
            let st = j;
            while j < b.len() && is_name_char(b[j]) {
                j += 1;
            }
            (j > st).then_some(j)
        };
        if let Some(e) = seg(j) {
            j = e;
            for _ in 0..3 {
                if j < b.len() && b[j] == b'.' {
                    match seg(j + 1) {
                        Some(e) => j = e,
                        None => break,
                    }
                } else {
                    break;
                }
            }
            i = j;
        }
    }
    let (name, rest) = s.split_at(i);
    let line_term = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
    match rest {
        "" => Some((name, None, false)),
        "?" => Some((name, None, true)),
        _ if rest.starts_with('(') => {
            let (inner, optional) = if let Some(r) = rest.strip_suffix(")?") {
                (r, true)
            } else if let Some(r) = rest.strip_suffix(')') {
                (r, false)
            } else {
                return None;
            };
            let inner = inner.strip_prefix('(')?;
            (!inner.contains(line_term)).then_some((name, Some(inner), optional))
        }
        _ => None,
    }
}

/// Expand one param shorthand. Forms: email phone url uuid ccy country secret bool date datetime duration text(N) string(N)
/// message(N) int(MIN..MAX) count(MAX) money(CCY|@param, max=N, min=N, exp=N, provenance=first_party|tool|agent) id:&lt;type&gt;
/// enum(a|b) set(a|b) array(items, max=N, min=N). A trailing `?` makes the param optional.
pub fn parse_param_shorthand(src: &str) -> Result<Value, String> {
    let Some((name, inner, optional)) = split_shorthand(js_trim(src)) else {
        return bad_shorthand(format!("unknown param shorthand '{src}'"));
    };
    let (pos, named) = split_args(inner.unwrap_or(""));
    let bare = || -> Result<(), String> {
        if inner.is_some() {
            bad_shorthand(format!("'{name}' takes no arguments"))
        } else {
            Ok(())
        }
    };
    let mut p = match name {
        "email" => {
            bare()?;
            json!({"type": "string", "role": "contact.email", "format": "email", "tags": ["pii"], "max_len": 254})
        }
        "phone" => {
            bare()?;
            json!({"type": "string", "role": "contact.phone", "format": "phone_e164", "tags": ["pii"], "max_len": 16})
        }
        "url" => {
            bare()?;
            json!({"type": "string", "role": "url.target", "format": "url", "max_len": 2048})
        }
        "uuid" => {
            bare()?;
            json!({"type": "string", "format": "uuid", "max_len": 36})
        }
        "ccy" => {
            bare()?;
            json!({"type": "string", "role": "money.currency", "format": "iso_currency", "max_len": 3})
        }
        "country" => {
            bare()?;
            json!({"type": "string", "format": "iso_country", "max_len": 2})
        }
        "secret" => {
            bare()?;
            json!({"type": "string", "role": "credential.secret", "tags": ["secret"], "max_len": 512})
        }
        "bool" => {
            bare()?;
            json!({"type": "boolean"})
        }
        "date" => {
            bare()?;
            json!({"type": "date"})
        }
        "datetime" => {
            bare()?;
            json!({"type": "datetime"})
        }
        "duration" => {
            only(&pos, &named, 1, &[], "duration")?;
            match int_arg(pos.first().map(String::as_str), "duration max (ms)")? {
                Some(mx) => json!({"type": "duration", "min": 0, "max": mx}),
                None => json!({"type": "duration"}),
            }
        }
        "text" | "string" => {
            only(&pos, &named, 1, &[], name)?;
            match int_arg(pos.first().map(String::as_str), &format!("{name} length"))? {
                Some(n) => json!({"type": "string", "max_len": n}),
                None => json!({"type": "string"}),
            }
        }
        "message" => {
            only(&pos, &named, 1, &[], "message")?;
            let ml = int_arg(pos.first().map(String::as_str), "message length")?.unwrap_or(1024);
            json!({"type": "string", "role": "text.message", "tags": ["free_text_outbound"], "max_len": ml})
        }
        "int" => {
            only(&pos, &named, 1, &[], "int")?;
            match pos.first() {
                None => json!({"type": "integer"}),
                Some(r) => {
                    let range = r.split_once("..").and_then(|(a, b)| Some((int_arg(Some(a), "").ok()??, int_arg(Some(b), "").ok()??)));
                    match range {
                        Some((lo, hi)) => json!({"type": "integer", "min": lo, "max": hi}),
                        None => return bad_shorthand("int takes MIN..MAX, for example int(0..100)".into()),
                    }
                }
            }
        }
        "count" => {
            only(&pos, &named, 1, &[], "count")?;
            let mx = int_arg(pos.first().map(String::as_str), "count max")?;
            let mut m = Map::new();
            m.insert("type".into(), json!("integer"));
            m.insert("role".into(), json!("count.limit"));
            m.insert("min".into(), json!(1));
            if let Some(mx) = mx {
                m.insert("max".into(), json!(mx));
            }
            m.insert("unit".into(), json!({"kind": "count"}));
            Value::Object(m)
        }
        "money" => {
            only(&pos, &named, 1, &["max", "min", "exp", "provenance"], "money")?;
            let Some(c) = pos.first() else { return bad_shorthand("money needs a currency: money(USD) or money(@currency_param)".into()) };
            let ccy = match c.strip_prefix('@') {
                Some(f) => json!({ "from": f }),
                None => json!(c),
            };
            let mx = int_arg(named_get(&named, "max"), "money max")?;
            let prov = named_get(&named, "provenance").unwrap_or("first_party");
            if !PROVENANCE_LEVELS.contains(&prov) {
                return bad_shorthand(format!("money provenance must be one of {}", PROVENANCE_LEVELS.join(", ")));
            }
            let mn = int_arg(named_get(&named, "min"), "money min")?.unwrap_or(1);
            let ex = int_arg(named_get(&named, "exp"), "money exp")?.unwrap_or(2);
            let mut m = Map::new();
            m.insert("type".into(), json!("integer"));
            m.insert("role".into(), json!("money.amount"));
            m.insert("min".into(), json!(mn));
            if let Some(mx) = mx {
                m.insert("max".into(), json!(mx));
            }
            m.insert("unit".into(), json!({"kind": "money", "ccy": ccy, "exp": ex}));
            m.insert("provenance_min".into(), json!(prov));
            Value::Object(m)
        }
        "enum" | "set" => {
            let Some(inner) = inner else { return bad_shorthand(format!("{name} needs values: {name}(a|b|c)")) };
            let ty = if name == "enum" { "string" } else { "set" };
            let values = list_arg(inner, name)?;
            json!({"type": ty, "values": values})
        }
        "array" => {
            only(&pos, &named, 1, &["max", "min"], "array")?;
            let items = pos.first().map(String::as_str);
            if items != Some("string") && items != Some("integer") {
                return bad_shorthand("array(items): items is string or integer".into());
            }
            let mx = int_arg(named_get(&named, "max"), "array max")?;
            let mn = int_arg(named_get(&named, "min"), "array min")?;
            let mut m = Map::new();
            m.insert("type".into(), json!("array"));
            m.insert("items".into(), json!(items));
            if let Some(mn) = mn {
                m.insert("min_items".into(), json!(mn));
            }
            if let Some(mx) = mx {
                m.insert("max_items".into(), json!(mx));
            }
            Value::Object(m)
        }
        _ => match name.strip_prefix("id:") {
            Some(t) => {
                bare()?;
                json!({"type": "string", "role": format!("id.{t}"), "max_len": 64})
            }
            None => return bad_shorthand(format!("unknown param shorthand '{name}'")),
        },
    };
    if optional {
        p["required"] = json!(false);
    }
    Ok(p)
}

// ---- resource shorthand ---------------------------------------------------------------------------------------------------------

/// `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.
/// A prefix pattern is scope one (class alnum, length 8..32 after the prefix); `*` is scope set; a bare type is tenant.
pub fn parse_resource_shorthand(src: &str) -> Result<Value, String> {
    let mut s = js_trim(src);
    let mut scope: Option<&str> = None;
    if let Some(at) = s.rfind('@') {
        let name = &s[at + 1..];
        if !name.is_empty() && name.bytes().all(|c| c.is_ascii_lowercase()) {
            if !RESOURCE_SCOPES.contains(&name) {
                return bad_shorthand(format!("unknown resource scope '@{name}'"));
            }
            scope = Some(name);
            s = &s[..at];
        }
    }
    let Some(colon) = s.find(':') else { return Ok(json!({"type": s, "id": "*", "scope": scope.unwrap_or("tenant")})) };
    let (typ, idsrc) = (&s[..colon], &s[colon + 1..]);
    if idsrc == "*" {
        return Ok(json!({"type": typ, "id": "*", "scope": scope.unwrap_or("set")}));
    }
    let Some(star) = idsrc.find('*') else { return Ok(json!({"type": typ, "id": {"exact": idsrc}, "scope": scope.unwrap_or("one")})) };
    let (prefix, rest) = (&idsrc[..star], &idsrc[star + 1..]);
    let (mut cls, mut len) = ("alnum".to_string(), [8i64, 32]);
    if !rest.is_empty() {
        let fail = || bad_shorthand(format!("resource id '{idsrc}': expected prefix*{{class,min..max}}"));
        let Some(body) = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')) else { return fail() };
        let Some((c, nums)) = body.split_once(',') else { return fail() };
        let Some((lo, hi)) = nums.split_once("..") else { return fail() };
        let n = |x: &str| (!x.is_empty() && x.len() <= 3 && x.bytes().all(|b| b.is_ascii_digit())).then(|| x.parse::<i64>().ok()).flatten();
        let class_ok = !c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        match (class_ok && ID_CLASSES.contains(&c), n(lo), n(hi)) {
            (true, Some(a), Some(b)) => {
                cls = c.to_string();
                len = [a, b];
            }
            _ => return fail(),
        }
    }
    Ok(json!({"type": typ, "id": {"prefix": prefix, "class": cls, "len": len}, "scope": scope.unwrap_or("one")}))
}

// ---- action expansion -----------------------------------------------------------------------------------------------------------

/// The title an action gets when it names none: the action word and its nouns, `acme.invoice.send` -> `Send invoice`.
pub fn default_title(verb: &str) -> String {
    let seg: Vec<&str> = verb.split('.').skip(1).collect();
    let act = seg.last().copied().unwrap_or(verb);
    let mut parts = vec![act];
    if seg.len() > 1 {
        parts.extend(&seg[..seg.len() - 1]);
    }
    let t = parts.join(" ").replace('_', " ");
    let mut cs = t.chars();
    cs.next().map_or(String::new(), |f| f.to_uppercase().collect::<String>() + cs.as_str())
}

fn as_list(v: &Value) -> Value {
    if v.is_string() {
        json!([v])
    } else {
        v.clone()
    }
}

fn is_one(v: &Value) -> bool {
    v.as_f64() == Some(1.0)
}

/// Expand one authoring entry (shorthands or full def members) to `{def, notes}`. Errs `bad_action` / `bad_shorthand`.
pub fn expand_action(entry: &Value, since: Option<&str>) -> Result<Value, String> {
    let Some(e) = entry.as_object() else { return Err("an action must be an object".into()) };
    if let Some(k) = e.keys().find(|k| !ENTRY_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown member '{k}'"));
    }
    if e.get("v").is_some_and(|v| !is_one(v)) {
        return Err("unsupported def version".into());
    }
    if e.get("kind").is_some_and(|k| k.as_str() != Some(ACTION_DEF_KIND)) {
        return Err(format!("kind must be '{ACTION_DEF_KIND}'"));
    }
    let Some(verb) = e.get("verb").and_then(Value::as_str) else { return Err("verb is required".into()) };
    if e.contains_key("kind") {
        // the full form is taken exactly as written: no shorthands, no defaults, validate_def decides
        let mut full = Map::new();
        full.insert("v".into(), json!(1));
        for (k, x) in e {
            full.insert(k.clone(), x.clone());
        }
        let full = Value::Object(full);
        if let Some(je) = json_profile_error(&full, 0) {
            return Err(format!("not strict JSON: {je}"));
        }
        return Ok(json!({"def": full, "notes": []}));
    }
    let mut notes = Vec::new();
    let mut out = Map::new();
    out.insert("v".into(), json!(1));
    out.insert("kind".into(), json!(ACTION_DEF_KIND));
    out.insert("verb".into(), json!(verb));
    if let Some(a) = e.get("aliases") {
        out.insert("aliases".into(), as_list(a));
    }
    out.insert("title".into(), opt(entry, "title").cloned().unwrap_or_else(|| json!(default_title(verb))));
    if let Some(d) = e.get("description") {
        out.insert("description".into(), d.clone());
    }
    if let Some(x) = e.get("effects") {
        out.insert("effects".into(), as_list(x));
    }
    if let Some(res) = e.get("resource") {
        out.insert(
            "resource".into(),
            match res.as_str() {
                Some(s) => parse_resource_shorthand(s)?,
                None => res.clone(),
            },
        );
    }
    // the reference keeps an absent `effects` / `resource` as an undefined member, which the strict JSON profile then refuses
    if !out.contains_key("effects") || !out.contains_key("resource") {
        return Err("not strict JSON: only JSON values are allowed".into());
    }
    let mut params = Map::new();
    if let Some(p) = e.get("params") {
        let Some(pm) = p.as_object() else { return Err("params must be an object".into()) };
        for (k, v) in pm {
            params.insert(
                k.clone(),
                match v.as_str() {
                    Some(s) => parse_param_shorthand(s)?,
                    None => v.clone(),
                },
            );
        }
    }
    if let Some(r) = e.get("reversibility") {
        out.insert("reversibility".into(), r.clone());
    }
    if let Some(b) = e.get("blast") {
        out.insert(
            "blast".into(),
            match b.as_str() {
                Some(s) => json!({ "radius": s }),
                None => b.clone(),
            },
        );
        if let Some(s) = b.as_str().filter(|s| !BLAST_RADII.contains(s)) {
            return Err(format!("unknown blast radius '{s}'"));
        }
    }
    if let Some(s) = e.get("side_effects") {
        out.insert("side_effects".into(), s.clone());
    }
    let effects: Vec<Value> = out.get("effects").map(|x| arr(x).to_vec()).unwrap_or_default();
    let mut idem: Option<Value> = e.get("idempotency").map(|i| match i.as_str() {
        Some("key_param") => json!({"mode": "key_param", "param": IDEMPOTENCY_PARAM}),
        Some(m) => json!({ "mode": m }),
        None => i.clone(),
    });
    if idem.is_none() && effects.iter().any(|x| x.as_str().is_some_and(|s| AUTO_IDEMPOTENT_EFFECTS.contains(&s))) {
        idem = Some(json!({"mode": "key_param", "param": IDEMPOTENCY_PARAM}));
        notes.push(json!({"verb": verb, "message": format!("{IDEMPOTENCY_PARAM} auto-added")}));
    }
    if let Some(i) = &idem {
        if i.get("mode").and_then(Value::as_str) == Some("key_param")
            && i.get("param").and_then(Value::as_str) == Some(IDEMPOTENCY_PARAM)
            && !params.contains_key(IDEMPOTENCY_PARAM)
        {
            params.insert(IDEMPOTENCY_PARAM.into(), json!({"type": "string", "max_len": 64}));
        }
    }
    if let Some(i) = idem {
        out.insert("idempotency".into(), i);
    }
    out.insert("params".into(), Value::Object(params));
    for k in ["context", "traits"] {
        if let Some(x) = e.get(k) {
            out.insert(k.into(), as_list(x));
        }
    }
    for k in ["audience", "compensates", "bindings", "examples", "source"] {
        if let Some(x) = e.get(k) {
            out.insert(k.into(), x.clone());
        }
    }
    out.insert("review".into(), opt(entry, "review").cloned().unwrap_or_else(|| json!({"state": "authored"})));
    if let Some(sn) = opt(entry, "since").cloned().or_else(|| since.map(|s| json!(s))) {
        out.insert("since".into(), sn);
    }
    let out = Value::Object(out);
    if let Some(je) = json_profile_error(&out, 0) {
        return Err(format!("not strict JSON: {je}"));
    }
    Ok(json!({"def": out, "notes": notes}))
}

// ---- the document loader ----------------------------------------------------------------------------------------------------------

fn has_proto_key(v: &Value, depth: usize) -> bool {
    if depth > 40 || !(v.is_object() || v.is_array()) {
        return depth > 40;
    }
    match v {
        Value::Array(a) => a.iter().any(|x| has_proto_key(x, depth + 1)),
        Value::Object(m) => m.iter().any(|(k, x)| k == "__proto__" || has_proto_key(x, depth + 1)),
        _ => false,
    }
}

fn ns_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| is_name_char(*c))
}

/// [`load_actions_value_with`] with no rules check: an action that carries `rules` is refused (never accepted unchecked).
pub fn load_actions_value(doc: &Value) -> Value {
    load_actions_value_with(doc, &|_, _| Some("a rules block cannot be checked: use load_actions_value_with".to_string()))
}

/// Expand an already parsed document (`{ns, since?, actions: [...]}`, or one raw def) to `{defs, notes, errors, locs, rules[, ns]}`.
/// Never errs.
pub fn load_actions_value_with(doc: &Value, rules_check: RulesCheck) -> Value {
    let mut ns: Option<String> = None;
    let mut defs: Vec<Value> = Vec::new();
    let mut notes: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();
    let mut rules = Map::new();
    let finish = |ns: &Option<String>, defs: Vec<Value>, notes: Vec<Value>, errors: Vec<Value>, rules: Map<String, Value>| {
        let mut o = Map::new();
        if let Some(n) = ns {
            o.insert("ns".into(), json!(n));
        }
        o.insert("defs".into(), Value::Array(defs));
        o.insert("notes".into(), Value::Array(notes));
        o.insert("errors".into(), Value::Array(errors));
        o.insert("locs".into(), json!({}));
        o.insert("rules".into(), Value::Object(rules));
        Value::Object(o)
    };
    let fail = |ns: &Option<String>, m: String| finish(ns, vec![], vec![], vec![json!({ "message": m })], Map::new());
    if has_proto_key(doc, 0) {
        return fail(&ns, "the document contains a '__proto__' member or nests deeper than 40".into());
    }
    let Some(d) = doc.as_object() else { return fail(&ns, "the document must be an object".into()) };
    let mut since: Option<String> = None;
    let entries: Vec<Value> = if d.get("kind").and_then(Value::as_str) == Some(ACTION_DEF_KIND) {
        vec![doc.clone()]
    } else {
        if let Some(k) = d.keys().find(|k| !FILE_KEYS.contains(&k.as_str())) {
            return fail(&ns, format!("unknown top-level member '{k}' (expected ns, since, actions)"));
        }
        match d.get("ns").and_then(Value::as_str) {
            Some(n) if ns_ok(n) => ns = Some(n.to_string()),
            _ => return fail(&ns, "ns must be a lowercase identifier".into()),
        }
        match d.get("since") {
            Some(Value::String(s)) => since = Some(s.clone()),
            Some(_) => return fail(&ns, "since must be a string".into()),
            None => {}
        }
        match d.get("actions").and_then(Value::as_array) {
            Some(a) => a.clone(),
            None => return fail(&ns, "actions must be a list".into()),
        }
    };
    for (index, e) in entries.iter().enumerate() {
        let verb = e.get("verb").and_then(Value::as_str);
        let mut err = |m: String| {
            let mut x = Map::new();
            x.insert("index".into(), json!(index));
            if let Some(v) = verb.filter(|v| !v.is_empty()) {
                x.insert("verb".into(), json!(v));
            }
            x.insert("message".into(), json!(m));
            errors.push(Value::Object(x));
        };
        let (entry, entry_rules) = match e.as_object() {
            Some(m) if m.contains_key("rules") => {
                let mut rest = m.clone();
                let r = rest.remove("rules");
                (Value::Object(rest), r)
            }
            _ => (e.clone(), None),
        };
        let ex = match expand_action(&entry, since.as_deref()) {
            Ok(x) => x,
            Err(m) => {
                err(m);
                continue;
            }
        };
        let def = ex["def"].clone();
        if let Some(bad) = validate_def(&def) {
            err(bad);
            continue;
        }
        if let Some(r) = entry_rules {
            if let Some(re) = rules_check(&def, &r) {
                err(re);
                continue;
            }
            rules.insert(js_value_string(get(&def, "verb")), r);
        }
        notes.extend(arr(&ex["notes"]).iter().cloned());
        defs.push(def);
    }
    finish(&ns, defs, notes, errors, rules)
}

/// The typed constructor over the JSON form: the same expansion as the loader (so the same digest); errs on a malformed spec.
pub fn action(verb: &str, spec: &Value) -> Result<Value, String> {
    let mut entry = Map::new();
    entry.insert("verb".into(), json!(verb));
    for (k, v) in spec.as_object().into_iter().flatten() {
        entry.insert(k.clone(), v.clone());
    }
    let def = expand_action(&Value::Object(entry), None)?["def"].clone();
    match validate_def(&def) {
        Some(bad) => Err(format!("{verb}: {bad}")),
        None => Ok(def),
    }
}

// ---- the typed builder --------------------------------------------------------------------------------------------------------------

fn with_extra(p: Value, x: Option<&Value>) -> Value {
    let mut p = p;
    if let (Some(m), Some(xm)) = (p.as_object_mut(), x.and_then(Value::as_object)) {
        for (k, v) in xm {
            m.insert(k.clone(), v.clone());
        }
    }
    p
}

/// `P.<name>(...args)`: the same param the matching shorthand expands to. `args` are the positional arguments as JSON, a missing
/// or null one is `undefined`; the last optional one adds or overrides members. Names: email phone url uuid ccy country secret
/// bool date datetime duration message text int count money id enum set array optional.
pub fn builder(name: &str, args: &[Value]) -> Result<Value, String> {
    let a = |i: usize| args.get(i).filter(|v| !v.is_null());
    let n = |i: usize| a(i).map(js_value_string);
    let sh = |s: String, x: Option<&Value>| -> Result<Value, String> { Ok(with_extra(parse_param_shorthand(&s)?, x)) };
    match name {
        "email" | "phone" | "url" | "uuid" | "ccy" | "country" | "secret" | "bool" | "date" | "datetime" => sh(name.to_string(), a(0)),
        "duration" | "message" | "text" | "count" => sh(n(0).map_or(name.to_string(), |m| format!("{name}({m})")), a(1)),
        "int" => sh(
            match (n(0), n(1)) {
                (Some(lo), Some(hi)) => format!("int({lo}..{hi})"),
                _ => "int".to_string(),
            },
            a(2),
        ),
        "money" => {
            let ccy = a(0).ok_or("money needs a currency")?;
            let c = match ccy.as_str() {
                Some(s) => s.to_string(),
                None => format!("@{}", js_value_string(get(ccy, "from"))),
            };
            let o = a(1);
            let mut opts = String::new();
            for k in ["max", "min", "exp"] {
                if let Some(v) = o.and_then(|o| opt(o, k)) {
                    opts.push_str(&format!(", {k}={}", js_value_string(v)));
                }
            }
            sh(format!("money({c}{opts})"), a(2))
        }
        "id" => sh(format!("id:{}", n(0).unwrap_or_default()), a(1)),
        "enum" | "set" => {
            let vals = a(0).map(|v| arr(v).iter().map(js_value_string).collect::<Vec<_>>().join("|")).unwrap_or_default();
            sh(format!("{name}({vals})"), a(1))
        }
        "array" => {
            let items = n(0).unwrap_or_default();
            sh(
                match n(1) {
                    Some(m) => format!("array({items}, max={m})"),
                    None => format!("array({items})"),
                },
                a(2),
            )
        }
        "optional" => {
            let mut d = a(0).cloned().ok_or("optional needs a param")?;
            if let Some(m) = d.as_object_mut() {
                m.insert("required".into(), json!(false));
            }
            Ok(d)
        }
        _ => Err(format!("unknown builder '{name}'")),
    }
}
