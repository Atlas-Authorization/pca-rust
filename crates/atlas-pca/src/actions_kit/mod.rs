//! Action-definition kit, authoring and derivation side (native port of the reference `pca-actions` author, build, compat, builtin,
//! derive, explain, effective, idpattern, diff, defdiff and evolve modules). Everything is JSON-valued: a def, a pack or a record
//! is a `serde_json::Value`, an error is the reference's message. Importers, lint, rules, templates, pack, hosted, undo and review
//! live in the sibling modules of the other ports.
//!
//! This file holds what the sub-modules share: JavaScript string helpers, resource id patterns (`id_matches`,
//! `id_pattern_contains`) and the confirmation-verifier form of T(d) / eff(d) (`effective_with`, `prules_violations`).
//! A confirmation verifier is the caller's `Fn(&def) -> bool`; absent means nothing is confirmed (maximally dangerous).

use serde_json::{json, Value};
use std::cmp::Ordering;

use crate::actions::{closure, decl_profile, floor_of, hint_traits, join, leq, normalize, top_traits, ActionKitError, Profile, Registry, PARAM_RULE_IDS};

pub mod author;
pub mod build;
pub mod compat;
pub mod data;
pub mod derive;
pub mod diff;
pub mod evolve;

/// The caller's confirmation verifier (the reference's `attestationVerified`). `None`: nothing is confirmed.
pub type Verifier<'a> = Option<&'a dyn Fn(&Value) -> bool>;

static NULL: Value = Value::Null;

// ---- small shared helpers -----------------------------------------------------------------------------------------------------

/// `o[k]`, JSON null when absent or `o` is not an object.
pub(crate) fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&NULL)
}

/// `o[k]` with absent and null both `None` (the reference's `?? undefined` reads).
pub(crate) fn opt<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| !x.is_null())
}

pub(crate) fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

pub(crate) fn strs(v: &Value) -> Vec<String> {
    arr(v).iter().filter_map(|x| x.as_str().map(String::from)).collect()
}

pub(crate) fn vstrs(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|x| Value::String(x.clone())).collect())
}

pub(crate) fn u16cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// An `f64` as the JSON number the reference prints: an integer when it is one.
pub(crate) fn num_value(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9007199254740992.0 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// `Number.isSafeInteger` of a JSON number.
pub(crate) fn safe_int(v: &Value) -> Option<i64> {
    let n = v.as_number()?;
    if let Some(i) = n.as_i64() {
        return (i.abs() <= 9007199254740991).then_some(i);
    }
    let f = n.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9007199254740991.0).then_some(f as i64)
}

/// A reference error message (its `.message`).
pub(crate) fn ke<T>(r: Result<T, ActionKitError>) -> Result<T, String> {
    r.map_err(|e| e.message)
}

/// ECMAScript `String.prototype.trim` whitespace (note U+FEFF is in, U+0085 is out).
pub(crate) fn is_js_ws(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

pub(crate) fn rev_rank(r: &str) -> i32 {
    match r {
        "reversible" => 0,
        "rate_limited" => 1,
        _ => 2,
    }
}

// ---- resource id patterns -------------------------------------------------------------------------------------------------------

const ALNUM: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn class_chars(c: &str) -> Option<String> {
    Some(match c {
        "digits" => "0123456789".to_string(),
        "hex" => "0123456789abcdef".to_string(),
        "alnum" => ALNUM.to_string(),
        "slug" => "0123456789abcdefghijklmnopqrstuvwxyz-_".to_string(),
        "uuid" => "0123456789abcdef-".to_string(),
        "any_safe" => format!("{ALNUM}._-:/"),
        _ => return None,
    })
}

fn in_class(s: &str, c: &str) -> bool {
    class_chars(c).is_some_and(|cs| s.chars().all(|ch| cs.contains(ch)))
}

fn class_subset(a: &str, b: &str) -> bool {
    match (class_chars(a), class_chars(b)) {
        (Some(x), Some(y)) => x.chars().all(|ch| y.contains(ch)),
        _ => false,
    }
}

fn uuid_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(c) })
}

fn len_pair(p: &Value) -> (i64, i64) {
    let l = arr(get(p, "len"));
    (l.first().and_then(Value::as_i64).unwrap_or(0), l.get(1).and_then(Value::as_i64).unwrap_or(0))
}

/// Does `id` (the id part of a resource, without the type) match the pattern? A non-string id never matches.
pub fn id_matches(p: &Value, id: &Value) -> bool {
    let Some(id) = id.as_str() else { return false };
    if p.as_str() == Some("*") {
        let n = id.encode_utf16().count();
        return n > 0 && n <= 128 && in_class(id, "any_safe");
    }
    if !p.is_object() {
        return false;
    }
    if let Some(e) = p.get("exact") {
        return e.as_str() == Some(id);
    }
    let prefix = get(p, "prefix").as_str().unwrap_or("");
    if !id.starts_with(prefix) {
        return false;
    }
    let rest = &id[prefix.len()..];
    let (lo, hi) = len_pair(p);
    let n = rest.encode_utf16().count() as i64;
    if n < lo || n > hi {
        return false;
    }
    let cls = get(p, "class").as_str().unwrap_or("");
    if cls == "uuid" {
        return uuid_ok(rest);
    }
    in_class(rest, cls)
}

/// Is every id matched by `inner` also matched by `outer`? Sound; an exact id never contains a pattern.
pub fn id_pattern_contains(outer: &Value, inner: &Value) -> bool {
    if outer.as_str() == Some("*") {
        return true;
    }
    if inner.as_str() == Some("*") {
        return false;
    }
    if let Some(e) = outer.get("exact") {
        return inner.is_object() && inner.get("exact") == Some(e);
    }
    if let Some(e) = inner.get("exact") {
        return id_matches(outer, e);
    }
    let (op, ip) = (get(outer, "prefix").as_str().unwrap_or(""), get(inner, "prefix").as_str().unwrap_or(""));
    if !ip.starts_with(op) {
        return false;
    }
    let r = &ip[op.len()..];
    let (oc, ic) = (get(outer, "class").as_str().unwrap_or(""), get(inner, "class").as_str().unwrap_or(""));
    if !in_class(r, oc) {
        return false;
    }
    if oc == "uuid" {
        return ic == "uuid" && r.is_empty();
    }
    if !class_subset(ic, oc) {
        return false;
    }
    let rl = r.encode_utf16().count() as i64;
    let ((olo, ohi), (ilo, ihi)) = (len_pair(outer), len_pair(inner));
    rl + ilo >= olo && rl + ihi <= ohi
}

// ---- T(d) / eff(d) with a caller-supplied confirmation verifier ------------------------------------------------------------------

/// One view of the effective profile: a trait set, its closure, the floor of the closure and decl joined with it.
#[derive(Debug, Clone)]
pub struct EffView {
    pub traits: Vec<String>,
    pub closure: Vec<String>,
    pub floor: Profile,
    pub eff: Profile,
}

impl EffView {
    pub fn to_value(&self) -> Value {
        json!({"traits": self.traits, "closure": self.closure, "floor": self.floor.to_value(), "eff": self.eff.to_value()})
    }
}

/// `effective_with`: the main view (the top of the registry unless confirmed), the hint view (as written) and the clamps.
#[derive(Debug, Clone)]
pub struct EffWith {
    pub confirmed: bool,
    pub main: EffView,
    pub decl: Profile,
    pub hint: EffView,
    pub clamps: Vec<Value>,
}

impl EffWith {
    pub fn to_value(&self) -> Value {
        json!({
            "traits": self.main.traits, "closure": self.main.closure, "floor": self.main.floor.to_value(), "eff": self.main.eff.to_value(),
            "confirmed": self.confirmed, "decl": self.decl.to_value(), "hint": self.hint.to_value(), "clamps": self.clamps,
        })
    }
}

/// True iff the caller's verifier says the def carries a valid signed review. Absent: never.
pub fn is_confirmed(d: &Value, v: Verifier) -> bool {
    v.is_some_and(|f| f(d))
}

fn view(reg: &Registry, decl: &Profile, traits: Vec<String>) -> Result<EffView, String> {
    let floor = ke(floor_of(reg, &traits))?;
    let cl = ke(closure(reg, &traits))?;
    Ok(EffView { traits, closure: cl, eff: join(decl, &floor), floor })
}

pub fn effective_with(d: &Value, reg: &Registry, v: Verifier) -> Result<EffWith, String> {
    let decl = decl_profile(d);
    let hint = view(reg, &decl, hint_traits(d))?;
    let confirmed = is_confirmed(d, v);
    let main = if confirmed { hint.clone() } else { view(reg, &decl, top_traits(reg))? };
    let mut clamps = Vec::new();
    if d.get("reversibility").is_some() && rev_rank(&decl.rev) < rev_rank(&hint.floor.rev) {
        clamps.push(json!({"field": "rev", "declared": decl.rev, "floor": hint.floor.rev}));
    }
    if d.get("blast").is_some() && decl.blast_ppm < hint.floor.blast_ppm {
        clamps.push(json!({"field": "blast_ppm", "declared": decl.blast_ppm, "floor": hint.floor.blast_ppm}));
    }
    Ok(EffWith { confirmed, main, decl, hint, clamps })
}

/// The hint profile after adding trait `t` to the declared traits (never lower). Analysis only.
pub fn eff_with_trait(d: &Value, t: &str, reg: &Registry) -> Result<Profile, String> {
    let mut d2 = d.clone();
    let mut ts = arr(get(d, "traits")).to_vec();
    ts.push(Value::String(t.to_string()));
    d2["traits"] = Value::Array(ts);
    Ok(effective_with(&d2, reg, None)?.hint.eff)
}

pub fn profile_eq(p: &Profile, q: &Profile) -> bool {
    leq(p, q) && leq(q, p)
}

/// Structural param rules (among `ids`) the def violates. A def violating a rule its traits require is not loadable.
pub fn prules_violations(d: &Value, ids: &[String]) -> Vec<String> {
    let n = normalize(d);
    let ps: Vec<&Value> = n["params"].as_object().map(|m| m.values().collect()).unwrap_or_default();
    let with_role =
        |pred: &dyn Fn(&str) -> bool| -> Vec<&Value> { ps.iter().copied().filter(|p| p.get("role").and_then(Value::as_str).is_some_and(pred)).collect() };
    let money_ok = |p: &Value| -> bool {
        let u = get(p, "unit");
        if u.get("kind").and_then(Value::as_str) != Some("money") {
            return false;
        }
        let ccy = get(u, "ccy");
        if ccy.is_string() {
            return true;
        }
        let c = ccy.get("from").and_then(Value::as_str).and_then(|f| n["params"].get(f));
        c.is_some_and(|c| c.get("role").and_then(Value::as_str) == Some("money.currency") && c.get("format").and_then(Value::as_str) == Some("iso_currency"))
    };
    let effects = strs(&n["effects"]);
    let mut bad = Vec::new();
    for rid in ids {
        let ok = match rid.as_str() {
            "money_has_currency" => with_role(&|r| r == "money.amount" || r == "money.fee").into_iter().all(|p| money_ok(p)),
            "money_amount_bounded" => with_role(&|r| r == "money.amount")
                .into_iter()
                .all(|p| p["type"].as_str() == Some("integer") && p.get("min").is_some() && p.get("max").is_some()),
            "id_not_wildcard" => !(n["resource"]["id"].as_str() == Some("*") && n["resource"]["scope"].as_str() == Some("one")),
            "recipient_param_declared" => {
                n.get("audience").and_then(Value::as_str) == Some("resource") || !with_role(&|r| r == "party.payee" || r.starts_with("contact.")).is_empty()
            }
            "array_bounded" => ps.iter().filter(|p| p["type"].as_str() == Some("array")).all(|p| opt(p, "max_items").is_some()),
            "export_bounded" => {
                n["resource"]["scope"].as_str() == Some("one") || with_role(&|r| r == "count.limit").into_iter().any(|p| p.get("max").is_some())
            }
            "secret_not_logged" => with_role(&|r| r.starts_with("credential.")).into_iter().all(|p| strs(get(p, "tags")).iter().any(|t| t == "secret")),
            "pay_has_idempotency" => !effects.iter().any(|e| e == "pay") || n["idempotency"]["mode"].as_str() != Some("none"),
            _ => true,
        };
        if !ok {
            bad.push(rid.clone());
        }
    }
    bad
}

/// The structural rules the registry lists in order, for callers that want them all.
pub fn all_prule_ids() -> Vec<String> {
    PARAM_RULE_IDS.iter().map(|s| s.to_string()).collect()
}

/// Rules the effective profile requires but the def does not satisfy (the load-time check).
pub fn required_prules_violated(d: &Value, eff: &Profile) -> Vec<String> {
    prules_violations(d, &eff.prules)
}
