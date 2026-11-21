//! The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render from the
//! wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a closed-enum
//! reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured clarification request
//! with max-information cell selection. A port of the reference (@atlasauth/pca-wallet), part 2; part 1 is [`crate::wallet`].
//!
//! Values are plain JSON (the reference's member names). A missing member is the reference's `undefined`; a reference refusal that is a
//! verdict is a `Value`, a thrown Error is an `Err(String)`.
//!
//! API: [`clean_text`], [`last4`], [`format_number`], [`render_card`], [`card_digest`], [`card_digest_matches`], [`card_text`],
//! [`partial_error`], [`normalize_typed`], [`expected_typed`], [`parse_clarify_request`], [`information_gain`], [`plan_clarification`]
//! ([`PlanInput`], [`ClarifyView`]).
//!
//! shortcut: a custom harm model is not supported (the default model of the outcome space is used); a cut inside a surrogate pair of
//! [`clean_text`] yields U+10FFFF where the reference holds a lone surrogate (a Rust string cannot).
use crate::intent_v2::{js_number_string, js_value_string};
use crate::wallet::{
    bin_ent, cat_label, cell_key, cell_of_action, flat_index, friction_rank, is_obj, reason_labels, resolve_coords, worst_provenance, BoxResult,
};
use crate::wallet::{CARD_DOMAIN, CLARIFY_REASONS, MAX_CANDIDATES};
use crate::wallet_omega::{cell_stats, is_int, js_entries, label_of, num, num_cells, truthy, u16len, NULL};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

const MAX_VALUES: usize = 64;
const MAX_STRING: usize = 256;
const LONE: char = '\u{10FFFF}';

/// The one-line description of each built-in catalogue verb (what a card says the action does).
const BUILTIN_DESCRIPTIONS: [(&str, &str); 21] = [
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

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}

fn g<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

fn js_str(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_value_string)
}

fn s_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// JavaScript `\s` and `String.prototype.trim` whitespace.
fn is_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn is_ctrl(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// `JSON.parse(JSON.stringify(v))`: `-0` becomes `0`.
fn plain(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(plain).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), plain(x))).collect::<Map<String, Value>>()),
        Value::Number(_) if num(v) == Some(0.0) => json!(0),
        _ => v.clone(),
    }
}

/// Strict equality of two JSON members as the reference's `===` (numbers by value; an object or array equals nothing).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(_)), Some(Value::Number(_))) => num(a.unwrap()) == num(b.unwrap()),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

// ---- text helpers ------------------------------------------------------------------------------------------------------------------

/// Strip control characters, collapse whitespace, cap length (UTF-16 units) for a string.
pub fn clean_str(s: &str, mx: usize) -> String {
    let mut t = String::new();
    let mut in_ws = false;
    for c in s.chars() {
        let c = if is_ctrl(c) { ' ' } else { c };
        if is_ws(c) {
            if !in_ws {
                t.push(' ');
                in_ws = true;
            }
        } else {
            t.push(c);
            in_ws = false;
        }
    }
    let t = t.trim_matches(' ');
    if u16len(t) <= mx {
        return t.to_string();
    }
    let units: Vec<u16> = t.encode_utf16().take(mx.saturating_sub(1)).collect();
    let mut out = String::new();
    for r in char::decode_utf16(units) {
        out.push(r.unwrap_or(LONE));
    }
    out.push('\u{2026}');
    out
}

/// `cleanText(s, max)`: a value that is no string is the reference's `s.replace is not a function`.
pub fn clean_text(s: &Value, mx: usize) -> Result<String, String> {
    s.as_str().map(|x| clean_str(x, mx)).ok_or_else(|| "s.replace is not a function".to_string())
}

fn clean_opt(s: Option<&Value>, mx: usize) -> Result<String, String> {
    clean_text(s.unwrap_or(&NULL), mx)
}

/// The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name).
pub fn last4(s: &str) -> String {
    let t: Vec<char> = s.chars().filter(char::is_ascii_alphanumeric).collect();
    t[t.len().saturating_sub(4)..].iter().collect::<String>().to_uppercase()
}

fn group_digits(s: &str) -> String {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return s.to_string();
    }
    let n = s.len();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (n - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// JavaScript `ToNumber` of a JSON value (`None` is `undefined`).
fn to_number(v: Option<&Value>) -> f64 {
    static NUM: OnceLock<Regex> = OnceLock::new();
    let Some(v) = v else { return f64::NAN };
    match v {
        Value::Null | Value::Bool(false) => 0.0,
        Value::Bool(true) => 1.0,
        Value::Number(_) => num(v).unwrap_or(f64::NAN),
        Value::String(s) => str_to_number(s, re(&NUM, r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")),
        Value::Array(_) => str_to_number(&js_value_string(v), re(&NUM, r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")),
        Value::Object(_) => f64::NAN,
    }
}

fn str_to_number(s: &str, number: &Regex) -> f64 {
    let t = s.trim_matches(is_ws);
    match t {
        "" => 0.0,
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ if number.is_match(t) => t.parse::<f64>().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

fn is_money(unit: Option<&Value>) -> bool {
    unit.and_then(|u| g(u, "kind")).and_then(Value::as_str) == Some("money")
}

fn currency_symbol(unit: &Value) -> String {
    let cur = g(unit, "currency");
    match cur.and_then(Value::as_str) {
        Some("USD") => "$".into(),
        Some("EUR") => "\u{20ac}".into(),
        Some("GBP") => "\u{a3}".into(),
        Some("JPY") => "\u{a5}".into(),
        _ => format!("{} ", js_str(cur)),
    }
}

/// Clamp of a money unit's exponent to 0..6 (`NaN` stays `NaN`, the way the reference computes with it).
fn exponent(unit: &Value) -> f64 {
    let e = to_number(g(unit, "exponent"));
    if e.is_nan() {
        f64::NAN
    } else {
        e.floor().min(6.0).max(0.0)
    }
}

/// Thousands grouping with commas, independent of any locale data (cards render identically anywhere).
pub fn format_number(x: f64, unit: Option<&Value>) -> String {
    let neg = if x < 0.0 { "-" } else { "" };
    let a = x.trunc().abs();
    if is_money(unit) {
        let u = unit.unwrap_or(&NULL);
        let e = exponent(u);
        let sym = currency_symbol(u);
        if e.is_nan() {
            return format!("{neg}{sym}NaN");
        }
        let div = 10f64.powi(e as i32);
        let whole = group_digits(&js_number_string((a / div).floor()));
        let frac = if e > 0.0 {
            let r = js_number_string(a % div);
            format!(".{}{}", "0".repeat((e as usize).saturating_sub(r.len())), r)
        } else {
            String::new()
        };
        return format!("{neg}{sym}{whole}{frac}");
    }
    format!("{neg}{}", group_digits(&js_number_string(a)))
}

fn dim_label(path: &str) -> String {
    static ACC: OnceLock<Regex> = OnceLock::new();
    static WORLD: OnceLock<Regex> = OnceLock::new();
    static MON: OnceLock<Regex> = OnceLock::new();
    let spaced = |s: &str| s.replace(['_', '.'], " ");
    if let Some(c) = re(&ACC, r"^env\.acc\.([A-Za-z0-9_.-]+)\.post$").captures(path) {
        return format!("{} (running total for this task)", spaced(&c[1]));
    }
    if let Some(c) = re(&WORLD, r"^env\.world\.([A-Za-z0-9_.-]+)$").captures(path) {
        return format!("{} (from a signed fact)", spaced(&c[1]));
    }
    if let Some(c) = re(&MON, r"^env\.mon\.([A-Za-z0-9_.-]+)\.state$").captures(path) {
        return format!("state of {}", spaced(&c[1]));
    }
    label_of(path)
}

fn is_prov_path(p: &str) -> bool {
    p.starts_with("env.prov.")
}

fn num_fact(d: &Value, ids: &[usize], unit: Option<&Value>, action_value: Option<&Value>) -> String {
    let cells = num_cells(d);
    let (lo, hi) = (cells[ids[0]].0 as f64, cells[ids[ids.len() - 1]].1 as f64);
    let (dlo, dhi) = (num(&d["lo"]).unwrap_or(f64::NAN), num(&d["hi"]).unwrap_or(f64::NAN));
    let range = if lo == hi {
        format!("exactly {}", format_number(lo, unit))
    } else if lo == dlo && hi == dhi {
        "any value".to_string()
    } else if hi == dhi {
        format!("{} or more", format_number(lo, unit))
    } else if lo == dlo {
        format!("up to {}", format_number(hi, unit))
    } else {
        format!("{} \u{2013} {}", format_number(lo, unit), format_number(hi, unit))
    };
    match action_value.and_then(num) {
        Some(x) if x.is_finite() => format!("{range} (this action: {})", format_number(x, unit)),
        _ => range,
    }
}

fn cat_value_text(d: &Value, i: usize) -> String {
    let v = &d["values"][i];
    match s_of(&v["kind"]) {
        "exact" => format!("\"{}\"", clean_str(s_of(&v["value"]), 64)),
        "prefix" => format!("anything starting with \"{}\"", clean_str(s_of(&v["value"]), 64)),
        _ => "a value not named in your request".to_string(),
    }
}

fn cat_fact(d: &Value, ids: &[usize], action_value: Option<&Value>) -> String {
    let parts: Vec<String> = ids.iter().map(|i| cat_value_text(d, *i)).collect();
    let set = if parts.len() == 1 {
        parts[0].clone()
    } else {
        format!("{} or {}", parts[..parts.len().saturating_sub(1)].join(", "), parts.last().map_or("undefined", String::as_str))
    };
    let Some(av) = action_value.and_then(Value::as_str) else { return set };
    let named = d["values"].as_array().is_some_and(|vs| vs.iter().any(|v| s_of(&v["kind"]) == "exact" && s_of(&v["value"]) == av));
    let shown = if named { format!("\"{}\"", clean_str(av, 64)) } else { format!("a value ending in \"{}\"", last4(av)) };
    format!("{set} (this action: {shown})")
}

fn banner_for(path: &str, levels: Vec<String>) -> Result<Option<String>, String> {
    let w = worst_provenance(&Value::Array(levels.into_iter().map(Value::String).collect()))?;
    let label = dim_label(path);
    Ok(match w {
        "web" => Some(format!("This {label} was suggested by content on a web page, not by you.")),
        "tool" => Some(format!("This {label} came from a tool result, not from you.")),
        "agent" => Some(format!("This {label} was chosen by your agent, not taken from your request or from the site.")),
        _ => None,
    })
}

fn prov_levels(d: &Value, ids: &[usize]) -> Vec<String> {
    ids.iter().flat_map(|i| cat_label(d, *i).split(['|', ',']).map(String::from).collect::<Vec<_>>()).collect()
}

/// `action.values[path]`: a missing or null `values` throws, a non-object has no members.
fn vget<'a>(values: Option<&'a Value>, path: &str) -> Result<Option<&'a Value>, String> {
    match values {
        None | Some(Value::Null) => Err("Cannot read properties of undefined".into()),
        Some(v) => Ok(v.as_object().and_then(|m| m.get(path))),
    }
}

fn dims_of(vs: &Value) -> &[Value] {
    vs["dims"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn typed_target(vs: &Value, action: Option<&Value>, units: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(action) = action.filter(|a| truthy(a)) else { return Ok(None) };
    let values = g(action, "values");
    let dims: Vec<&Value> = dims_of(vs).iter().filter(|d| !is_prov_path(s_of(&d["path"]))).collect();
    let mut nums: Vec<&Value> = vec![];
    for d in &dims {
        if s_of(&d["kind"]) == "num" && vget(values, s_of(&d["path"]))?.is_some_and(Value::is_number) {
            nums.push(*d);
        }
    }
    let unit_of = |d: &Value| units.and_then(|u| g(u, s_of(&d["path"])));
    let money = nums.iter().copied().find(|d| is_money(unit_of(*d)));
    if let Some(pick) = money.or_else(|| nums.first().copied()) {
        let path = s_of(&pick["path"]);
        return Ok(Some(json!({ "path": path, "mode": "number", "prompt": format!("To allow it, type the {} of this action shown above.", dim_label(path)) })));
    }
    for d in &dims {
        if s_of(&d["kind"]) == "cat" && vget(values, s_of(&d["path"]))?.and_then(Value::as_str).is_some_and(|v| last4(v).len() == 4) {
            let path = s_of(&d["path"]);
            return Ok(Some(
                json!({ "path": path, "mode": "last4", "prompt": format!("To allow it, type the last 4 letters or digits of the {}.", dim_label(path)) }),
            ));
        }
    }
    Ok(None)
}

fn answers_of(friction: Option<&Value>) -> Option<Value> {
    let key = match friction {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Array(a)) if a.len() == 1 => a[0].as_str()?, // a property key: a one-element array of a tier name selects that tier too
        _ => return None,
    };
    let yes = match key {
        "tap" => "Yes",
        "hold" => "Press and hold to allow",
        "typed" => "Yes, type the value to confirm",
        "device" => "Yes, confirm with your security key",
        _ => return None,
    };
    Some(json!([{ "id": "no", "label": "No" }, { "id": "partly", "label": "Partly\u{2026}" }, { "id": "yes", "label": yes }]))
}

fn lower_first(s: &str) -> String {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}') && (c as u32) <= 0xffff => format!("{}{}", c.to_lowercase(), cs.as_str()),
        _ => s.to_string(),
    }
}

fn catalog_description(inp: &Value, verb: &str) -> Option<String> {
    match g(inp, "catalog") {
        None | Some(Value::Null) => BUILTIN_DESCRIPTIONS.iter().find(|(v, _)| *v == verb).map(|(_, d)| d.to_string()),
        Some(Value::Array(specs)) => specs
            .iter()
            .rev()
            .find(|s| g(s, "verb").and_then(Value::as_str) == Some(verb))
            .and_then(|s| g(s, "description"))
            .and_then(Value::as_str)
            .map(String::from),
        Some(_) => None,
    }
}

/// Render the trusted question card: `{ok: true, card}` or `{ok: false, reason}`. `inp` carries omega, verb, coords, site, statementText,
/// reversibility, units, action, friction, kind, reason, locale and an optional catalog (an array of `{verb, description}`).
pub fn render_card(inp: &Value) -> Result<Value, String> {
    let refuse = |r: String| Ok(json!({ "ok": false, "reason": r }));
    let loc = g(inp, "locale").filter(|l| !l.is_null());
    if loc.is_some_and(|l| l.as_str() != Some("en")) {
        return refuse(format!("unsupported locale {}", js_str(g(inp, "locale"))));
    }
    let kind = g(inp, "kind");
    let reason = g(inp, "reason");
    let clarification = kind.and_then(Value::as_str) == Some("clarification");
    if clarification && reason.is_none() {
        return refuse("a clarification card needs a reason".into());
    }
    if reason.is_some_and(|r| !r.as_str().is_some_and(|s| CLARIFY_REASONS.contains(&s))) {
        return refuse("unknown clarification reason".into());
    }
    let verb_v = g(inp, "verb");
    let Some(verb) = verb_v.and_then(Value::as_str) else {
        return refuse(format!("verb {} is not in the wallet's outcome space", js_str(verb_v)));
    };
    let omega = g(inp, "omega").ok_or("Cannot read properties of undefined (reading 'verbs')")?;
    let (vs, box_) = match resolve_coords(omega, verb, g(inp, "coords").unwrap_or(&NULL))? {
        BoxResult::Ok { vs, box_ } => (vs, box_),
        BoxResult::Refused(r) => return refuse(r),
    };
    let action = g(inp, "action");
    if action.is_some_and(truthy) && !strict_eq(action.and_then(|a| g(a, "verb")), verb_v) {
        return refuse("the action is for another verb".into());
    }
    let site = g(inp, "site").ok_or("Cannot read properties of undefined (reading 'name')")?;
    let mut site_name = clean_opt(g(site, "name"), 64)?;
    if site_name.is_empty() {
        site_name = clean_opt(g(site, "origin"), 64)?;
    }
    let said = match g(inp, "statementText") {
        Some(s) => clean_text(s, 280)?,
        None => String::new(),
    };
    let header = if clarification {
        if said.is_empty() {
            "Your agent needs a decision".to_string()
        } else {
            format!("Your agent needs a decision for your request \"{said}\"")
        }
    } else if said.is_empty() {
        format!("{site_name} asks for your confirmation")
    } else {
        format!("{site_name} asks on behalf of your request \"{said}\"")
    };
    let what = match catalog_description(inp, verb) {
        Some(d) => lower_first(d.strip_suffix('.').unwrap_or(&d)),
        None => format!("the action \"{}\" on {site_name}", clean_str(verb, 64)),
    };
    let rev = g(inp, "reversibility").filter(|r| !r.is_null()).unwrap_or(&vs["reversibility"]);
    let rev_text = match rev.as_str() {
        Some("reversible") => "that can be undone",
        Some("rate_limited") => "that is rate-limited",
        Some("irreversible") => "that cannot be undone",
        _ => "undefined",
    };
    let sentence = format!("Allow {what}, {rev_text}, with:");
    let units = g(inp, "units");
    let (mut facts, mut banners, mut partial) = (vec![], vec![], vec![]);
    for (k, d) in dims_of(vs).iter().enumerate() {
        let ids = &box_[k];
        let path = s_of(&d["path"]);
        if is_prov_path(path) {
            if s_of(&d["kind"]) != "cat" {
                continue;
            }
            if let Some(b) = banner_for(&path["env.prov.".len()..], prov_levels(d, ids))? {
                banners.push(Value::String(b));
            }
            continue;
        }
        let av = match action.filter(|a| !a.is_null()) {
            Some(a) => vget(g(a, "values"), path)?,
            None => None,
        };
        let unit = units.filter(|u| u.is_object()).and_then(|u| g(u, path));
        if s_of(&d["kind"]) == "num" {
            facts.push(json!({ "key": path, "label": dim_label(path), "text": num_fact(d, ids, unit, av) }));
            let cells = num_cells(d);
            partial.push(json!({ "path": path, "kind": "num", "lo": cells[ids[0]].0, "hi": cells[ids[ids.len() - 1]].1 }));
        } else {
            facts.push(json!({ "key": path, "label": dim_label(path), "text": cat_fact(d, ids, av) }));
            let options: Vec<Value> = ids.iter().filter(|i| s_of(&d["values"][**i]["kind"]) == "exact").map(|i| d["values"][*i]["value"].clone()).collect();
            if options.len() > 1 {
                partial.push(json!({ "path": path, "kind": "cat", "options": options }));
            }
        }
    }
    let friction = g(inp, "friction");
    let typed = if friction_rank(friction.unwrap_or(&NULL)) >= friction_rank(&json!("typed")) { typed_target(vs, action, units)? } else { None };
    let mut body = Map::new();
    body.insert("v".into(), json!(2));
    body.insert("verb".into(), json!(verb));
    body.insert("coords".into(), plain(g(inp, "coords").unwrap_or(&NULL)));
    body.insert("locale".into(), json!("en"));
    let origin = clean_opt(g(site, "origin"), 256)?;
    body.insert("site".into(), json!({ "origin": origin, "name": site_name }));
    body.insert("header".into(), json!(header));
    if let Some(k) = kind {
        body.insert("kind".into(), k.clone());
    }
    if let Some(r) = reason {
        body.insert("reason_label".into(), reason_labels()[s_of(r)].clone());
    }
    body.insert("sentence".into(), json!(sentence));
    body.insert("facts".into(), Value::Array(facts));
    body.insert("banners".into(), Value::Array(banners));
    if let Some(f) = friction {
        body.insert("friction".into(), f.clone());
    }
    if let Some(a) = answers_of(friction) {
        body.insert("answers".into(), a);
    }
    if let Some(t) = typed {
        body.insert("typed".into(), t);
    }
    body.insert("partial".into(), Value::Array(partial));
    let body = Value::Object(body);
    let digest = card_digest(&body)?;
    let mut card = body;
    card["rendered_digest"] = json!(digest);
    Ok(json!({ "ok": true, "card": card }))
}

/// The content address of a card body (everything but `rendered_digest`).
pub fn card_digest(body: &Value) -> Result<String, String> {
    crate::hash_canonical_strict(&json!({ "d": CARD_DOMAIN, "c": plain(body) })).ok_or_else(|| "canonicalize: value outside the strict profile".to_string())
}

/// Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed.
pub fn card_digest_matches(card: &Value) -> Result<bool, String> {
    let m = card.as_object().ok_or("Cannot destructure a value that is not an object")?;
    let mut body = m.clone();
    body.remove("rendered_digest");
    let d = card_digest(&Value::Object(body))?;
    Ok(m.get("rendered_digest").and_then(Value::as_str) == Some(d.as_str()))
}

/// The plain text of a card, line by line (what a screen reader or a text channel shows).
pub fn card_text(card: &Value) -> Result<String, String> {
    let arr = |k: &str| g(card, k).and_then(Value::as_array).ok_or_else(|| format!("Cannot read properties of undefined (reading '{k}')"));
    let mut lines = vec![js_str(g(card, "header"))];
    if g(card, "reason_label").is_some_and(truthy) {
        lines.push(js_str(g(card, "reason_label")));
    }
    lines.push(js_str(g(card, "sentence")));
    for f in arr("facts")? {
        lines.push(format!("- {}: {}", js_str(g(f, "label")), js_str(g(f, "text"))));
    }
    lines.extend(arr("banners")?.iter().map(js_value_string));
    if let Some(t) = g(card, "typed").filter(|t| truthy(t)) {
        lines.push(js_str(g(t, "prompt")));
    }
    lines.push(arr("answers")?.iter().map(|a| format!("[{}]", js_str(g(a, "label")))).collect::<Vec<_>>().join(" "));
    Ok(lines.join("\n"))
}

// ---- responses -------------------------------------------------------------------------------------------------------------------

/// Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only (`None` when it is valid).
pub fn partial_error(card: &Value, p: &Value) -> Result<Option<String>, String> {
    let slots = g(card, "partial").and_then(Value::as_array).ok_or("Cannot read properties of undefined (reading 'find')")?;
    let pm = p.as_object().ok_or("Cannot read properties of undefined (reading 'path')")?;
    let Some(slot) = slots.iter().find(|s| strict_eq(g(s, "path"), pm.get("path"))) else {
        return Ok(Some(format!("the card has no field {}", js_str(pm.get("path")))));
    };
    if s_of(&slot["kind"]) == "num" {
        let (lo, hi) = (num(&slot["lo"]).unwrap_or(f64::NAN), num(&slot["hi"]).unwrap_or(f64::NAN));
        let in_range = |x: &Value| num(x).is_some_and(|f| f.is_finite() && f.fract() == 0.0 && !(f == 0.0 && f.is_sign_negative()) && f >= lo && f <= hi);
        if let Some(v) = pm.get("upTo") {
            let ok = in_range(v) && num(v).is_some_and(|f| f < hi);
            return Ok((!ok).then(|| format!("upTo must be an integer in [{}, {}]", js_number_string(lo), js_number_string(hi - 1.0))));
        }
        if let Some(v) = pm.get("from") {
            let ok = in_range(v) && num(v).is_some_and(|f| f > lo);
            return Ok((!ok).then(|| format!("from must be an integer in [{}, {}]", js_number_string(lo + 1.0), js_number_string(hi))));
        }
        if let Some(v) = pm.get("except") {
            let ok = v.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(in_range));
            return Ok((!ok).then(|| format!("except values must be integers in [{}, {}]", js_number_string(lo), js_number_string(hi))));
        }
        return Ok(Some("a numeric partly answer needs upTo, from or except".into()));
    }
    let Some(nf) = pm.get("notFor") else { return Ok(Some("a categorical partly answer needs notFor".into())) };
    let nf = nf.as_array().ok_or("object is not iterable")?;
    let mut vals: Vec<&Value> = vec![];
    for v in nf {
        if !vals.iter().any(|x| strict_eq(Some(*x), Some(v))) {
            vals.push(v);
        }
    }
    let options = slot["options"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if vals.is_empty() || !vals.iter().all(|v| options.iter().any(|o| strict_eq(Some(o), Some(*v)))) {
        return Ok(Some("notFor must name values shown on the card".into()));
    }
    if vals.len() == options.len() {
        return Ok(Some("excluding every value is a \"No\"".into()));
    }
    Ok(None)
}

/// Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money). `mode` is "number" or "last4".
pub fn normalize_typed(input: &str, mode: &str, unit: Option<&Value>) -> Option<String> {
    static HEAD: OnceLock<Regex> = OnceLock::new();
    static NUMBER: OnceLock<Regex> = OnceLock::new();
    if mode == "last4" {
        let t: String = input.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_uppercase();
        return (t.len() == 4).then_some(t);
    }
    let stripped: String = input.chars().filter(|c| !(is_ws(*c) || matches!(c, ',' | '$' | '\u{20ac}' | '\u{a3}' | '\u{a5}'))).collect();
    let t = re(&HEAD, r"^[A-Za-z]{3}").replace(&stripped, "").to_string();
    let m = re(&NUMBER, r"^(-?)([0-9]+)(?:\.([0-9]+))?$").captures(&t)?;
    let e = if is_money(unit) {
        let x = exponent(unit.unwrap_or(&NULL));
        if x.is_nan() {
            return None; // the reference's BigInt(NaN) throws
        }
        x as usize
    } else {
        0
    };
    let frac = m.get(3).map_or("", |f| f.as_str());
    if frac.len() > e {
        return None;
    }
    let digits = format!("{}{}{}", &m[2], frac, "0".repeat(e - frac.len()));
    let minor = digits.trim_start_matches('0');
    let minor = if minor.is_empty() { "0" } else { minor };
    Some(format!("{}{}", if &m[1] == "-" && minor != "0" { "-" } else { "" }, minor))
}

/// The normalized value the human must type for this card and action (what a site or auditor recomputes).
pub fn expected_typed(card: &Value, action: &Value) -> Result<Option<String>, String> {
    let Some(t) = g(card, "typed").filter(|t| truthy(t)) else { return Ok(None) };
    let v = vget(g(action, "values"), s_of(&t["path"]))?;
    if s_of(&t["mode"]) == "last4" {
        return Ok(v.and_then(Value::as_str).filter(|s| last4(s).len() == 4).map(last4));
    }
    Ok(v.filter(|x| is_int(x)).and_then(num).map(js_number_string))
}

// ---- agent-initiated clarification -----------------------------------------------------------------------------------------------

/// Strict parse of a clarification body: `{ok: true, request: {candidates, reason}}` or `{ok: false, error}`.
pub fn parse_clarify_request(body: &Value) -> Value {
    static PATH: OnceLock<Regex> = OnceLock::new();
    let bad = |e: String| json!({ "ok": false, "error": e });
    if !is_obj(body) {
        return bad("body must be an object".into());
    }
    let m = body.as_object().expect("object");
    for k in crate::missing_context::js_keys(m) {
        if k != "candidates" && k != "reason" {
            return bad(format!("unknown member \"{k}\" (clarifications carry no text)"));
        }
    }
    let reason = m.get("reason").and_then(Value::as_str).filter(|r| CLARIFY_REASONS.contains(r));
    let Some(reason) = reason else { return bad(format!("reason must be one of {}", CLARIFY_REASONS.join(", "))) };
    let cands = m.get("candidates").and_then(Value::as_array).filter(|c| !c.is_empty() && c.len() as i64 <= MAX_CANDIDATES);
    let Some(cands) = cands else { return bad(format!("candidates must be 1..{MAX_CANDIDATES} structured actions")) };
    let mut out: Vec<Value> = vec![];
    for (i, c) in cands.iter().enumerate() {
        let Some(cm) = c.as_object().filter(|_| is_obj(c)) else { return bad(format!("candidates[{i}] must be an object")) };
        for k in crate::missing_context::js_keys(cm) {
            if k != "verb" && k != "values" {
                return bad(format!("candidates[{i}] has an unknown member \"{k}\""));
            }
        }
        let verb = cm.get("verb").and_then(Value::as_str).filter(|v| u16len(v) != 0 && u16len(v) <= 128);
        let Some(verb) = verb else { return bad(format!("candidates[{i}].verb must be a non-empty string")) };
        let Some(values) = cm.get("values").filter(|v| is_obj(v)) else { return bad(format!("candidates[{i}].values must be an object")) };
        let entries = match js_entries(values) {
            Ok(e) => e,
            Err(e) => return bad(e),
        };
        if entries.len() > MAX_VALUES {
            return bad(format!("candidates[{i}] has too many values"));
        }
        let mut vals = Map::new();
        for (p, v) in entries {
            if !re(&PATH, r"^(?i-u:[a-z][a-z0-9_]*(\.[a-z0-9_]+)*)$").is_match(&p) {
                return bad(format!("candidates[{i}] has a malformed path"));
            }
            if !(p == "action.resource" || p.starts_with("action.params.")) {
                return bad(format!("candidates[{i}].values may only name action.params.* or action.resource"));
            }
            if v.is_number() {
                if !is_int(&v) {
                    return bad(format!("candidates[{i}].values.{p} must be a safe integer"));
                }
            } else if !v.as_str().is_some_and(|s| u16len(s) <= MAX_STRING) {
                return bad(format!("candidates[{i}].values.{p} must be a string (\u{2264} {MAX_STRING}) or an integer"));
            }
            vals.insert(p, v);
        }
        out.push(json!({ "verb": verb, "values": vals }));
    }
    json!({ "ok": true, "request": { "candidates": out, "reason": reason } })
}

/// Expected information gain of asking a cell with acceptance `p` under asymmetric noise (bits).
pub fn information_gain(p: f64, eta_pos: f64, eta_neg: f64) -> f64 {
    let py = p * (1.0 - eta_neg) + (1.0 - p) * eta_pos;
    bin_ent(py) - (p * bin_ent(eta_neg) + (1.0 - p) * bin_ent(eta_pos))
}

/// What the planner reads of the principal's grant: acceptance, veto and ceiling, by verb and cell index.
pub struct ClarifyView<'a> {
    pub p: &'a dyn Fn(&str, &[usize]) -> f64,
    pub vetoed: &'a dyn Fn(&str, &[usize]) -> bool,
    pub outside_ceiling: &'a dyn Fn(&str, &[usize]) -> bool,
}

pub struct PlanInput<'a> {
    pub omega: &'a Value,
    pub view: ClarifyView<'a>,
    pub candidates: &'a [Value],
    /// Lifts a candidate (`{verb, values}`) onto the outcome space's dimensions (default: as given).
    pub lift: Option<&'a dyn Fn(&Value) -> Result<Value, String>>,
    /// `verb|i,j,..` keys already asked.
    pub asked: &'a HashSet<String>,
    pub eta_pos: f64,
    pub eta_neg: f64,
}

struct Best {
    index: usize,
    verb: String,
    idx: Vec<usize>,
    p: f64,
    ig: f64,
    weight: f64,
    flat: usize,
}

/// Dry-run verdicts for each candidate and the one cell worth asking, if any: `{verdicts, ask?}` (no `ask` member when nothing is worth asking).
pub fn plan_clarification(i: &PlanInput) -> Result<Value, String> {
    let mut verdicts: Vec<Value> = vec![];
    let mut best: Option<Best> = None;
    let mut seen: HashSet<String> = HashSet::new();
    for (index, cand) in i.candidates.iter().enumerate() {
        let lifted = match i.lift {
            Some(l) => l(cand)?,
            None => cand.clone(),
        };
        let v = |verdict: &str| json!({ "index": index, "verdict": verdict });
        let Some((vs, idx)) = cell_of_action(i.omega, &lifted)? else {
            verdicts.push(v("outside"));
            continue;
        };
        let verb = s_of(&vs["verb"]);
        if (i.view.outside_ceiling)(verb, &idx) || (i.view.vetoed)(verb, &idx) {
            verdicts.push(v("denied"));
            continue;
        }
        let p = (i.view.p)(verb, &idx);
        if p <= 0.0 {
            verdicts.push(v("denied"));
            continue;
        }
        if p >= 1.0 {
            verdicts.push(v("admitted"));
            continue;
        }
        let key = cell_key(verb, &idx);
        if i.asked.contains(&key) {
            verdicts.push(v("asked"));
            continue;
        }
        verdicts.push(v("uncertain"));
        if !seen.insert(key) {
            continue;
        }
        let ig = information_gain(p, i.eta_pos, i.eta_neg);
        let s = cell_stats(vs, &idx);
        let c2 = Best { index, verb: verb.to_string(), idx: idx.clone(), p, ig, weight: s.mass * s.harm, flat: flat_index(vs, &idx) };
        let better = match &best {
            None => true,
            Some(b) => c2.ig > b.ig + 1e-12 || ((c2.ig - b.ig).abs() <= 1e-12 && (c2.weight > b.weight || (c2.weight == b.weight && c2.flat < b.flat))),
        };
        if better {
            best = Some(c2);
        }
    }
    let mut out = Map::new();
    out.insert("verdicts".into(), Value::Array(verdicts));
    // `ask` is always a member: the question, or null when nothing is worth asking
    out.insert("ask".into(), best.map_or(Value::Null, |b| json!({ "index": b.index, "verb": b.verb, "idx": b.idx, "p": b.p, "ig": b.ig })));
    Ok(Value::Object(out))
}
